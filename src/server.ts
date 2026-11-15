/**
 * server.ts — HTTP server: POST /agent (signed tasks + preflight), GET /health.
 *
 * Request flow for POST /agent:
 *   1. Read the RAW body (1 MB cap) — HMAC is computed over these exact bytes.
 *   2. Verify x-agent-games-signature BEFORE parsing JSON. Mismatch -> 401, no processing.
 *   3. Parse + validate the envelope. Malformed -> signed REJECT / INVALID_TASK.
 *   4. Preflight -> signed {"ok":true,"protocolVersion":"v1"}.
 *   5. Task -> deterministic decide() (steps 1–7). If a step 1–7 rejection wins,
 *      generate a decision=0 proof when the reason is circuit-attested and
 *      respond. If all of 1–7 pass, confirm proof_tx on-chain (step 8);
 *      unconfirmed -> signed REJECT / PROOF_NOT_FOUND (fail closed).
 *   6. APPROVE -> generate the decision=1 proof, submit to Kurier with a
 *      SHORT budget from the remaining handler time (max ~10s), respond with
 *      the local proof + public_signals (+ proofReference = Kurier job id),
 *      then continue polling Kurier in the background until Finalized.
 *   7. Record proof_tx in the seen-set ONLY after the APPROVE response is sent.
 *
 * Hard cap: the whole handler is raced against a 50s deadline (platform
 * deadline is 60s). On cap expiry the handler responds REJECT /
 * PROOF_GENERATION_FAILED rather than timing out (-2 either way, but a
 * response keeps the decision auditable and avoids a platform-side timeout).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decide, type DecisionResult } from "./decide.js";
import { parseEnvelope, EnvelopeError, type TaskEnvelope } from "./envelope.js";
import { signBody, verifySignature, SIGNATURE_HEADER } from "./hmac.js";
import { log } from "./logger.js";
import { Prover, type GeneratedProof } from "./prover.js";
import { KurierClient } from "./kurier.js";
import { confirmProofTx } from "./zkverify.js";
import { SeenSet } from "./seen.js";
import type { Config } from "./config.js";

const HANDLER_CAP_MS = 50_000;
const KURIER_SHORT_POLL_MAX_MS = 10_000;
const KURIER_BACKGROUND_POLL_MS = 5 * 60_000;
const MAX_BODY_BYTES = 1_000_000;

export interface GatekeeperResponse {
  decision: "APPROVE" | "REJECT";
  reason_code: string;
  proof?: unknown;
  public_signals?: string[];
  proof_tx?: string;
  proofReference?: string | null;
}

export class GatekeeperServer {
  private readonly config: Config;
  private readonly prover: Prover;
  private readonly seen: SeenSet;
  private readonly kurier: KurierClient;
  private inFlight = 0;

  constructor(config: Config) {
    this.config = config;
    this.prover = new Prover(config.wasmPath, config.zkeyPath, config.vkPath);
    this.seen = new SeenSet(config.dataDir);
    this.kurier = new KurierClient(config.kurierApiUrl, config.kurierApiKey);
    if (!this.kurier.enabled) {
      log("warn", "KURIER_API_KEY not set — proofs will NOT be submitted to zkVerify (local proof only)");
    }
    if (!config.subscanApiKey) {
      log(
        "warn",
        "SUBSCAN_API_KEY not set — proof_tx cannot be confirmed on-chain; otherwise-valid tasks will be REJECTED with PROOF_NOT_FOUND (fail closed). See README.",
      );
    }
  }

  /** Read the raw request body with a size cap. */
  private readBody(req: IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(new Error("body exceeds 1MB cap"));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }

  /** Send a JSON body signed over its raw bytes. */
  private sendSigned(res: ServerResponse, status: number, payload: unknown): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, {
      "Content-Type": "application/json",
      [SIGNATURE_HEADER]: signBody(this.config.hmacSecret, body),
    });
    res.end(body);
  }

  private sendUnsigned(res: ServerResponse, status: number, payload: unknown): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(body);
  }

  /** Core task handling (no HTTP concerns). Returns the response payload. */
  private async handleTask(task: TaskEnvelope, deadlineMs: number): Promise<GatekeeperResponse> {
    const started = Date.now();
    const input = task.input;

    // Steps 1–7 (timestamp, VK, threshold, recipient, amount, expiry, reuse).
    // proofTxConfirmed is passed as true here: the on-chain check (step 8) is
    // only reached when steps 1–7 all pass — first failure wins.
    const early = decide(task, {
      canonicalVkHash: this.config.gatekeeperVkHash,
      proofTxSeen: this.seen.has(input.proof_tx),
      proofTxConfirmed: true,
      now: new Date(),
    });
    if (early.decision === "REJECT") {
      return this.finishReject(task, early, started);
    }

    // Step 8: on-chain confirmation of proof_tx (fail closed).
    const confirmation = await confirmProofTx(input.proof_tx, {
      kurierApiUrl: this.config.kurierApiUrl,
      kurierApiKey: this.config.kurierApiKey,
      subscanApiKey: this.config.subscanApiKey,
    });
    if (!confirmation.confirmed) {
      log("warn", "proof_tx NOT confirmed on-chain — rejecting (fail closed)", {
        task_id: task.task_id,
        proof_tx_prefix: input.proof_tx.slice(0, 10),
        source: confirmation.source,
        detail: confirmation.detail,
      });
      return this.finishReject(
        task,
        { decision: "REJECT", reason_code: "PROOF_NOT_FOUND", provable: false, circuitDecision: 0 },
        started,
      );
    }

    // Step 9: APPROVE — generate the decision=1 proof.
    let generated: GeneratedProof;
    try {
      generated = await this.prover.prove(task, 1);
    } catch (err) {
      log("error", "proof generation failed on APPROVE path", { task_id: task.task_id, error: String(err).slice(0, 200) });
      return this.finishReject(
        task,
        { decision: "REJECT", reason_code: "PROOF_GENERATION_FAILED", provable: false, circuitDecision: 0 },
        started,
      );
    }

    // Kurier: submit + short poll within the remaining handler budget.
    let proofReference: string | null = null;
    if (this.kurier.enabled) {
      try {
        const remaining = deadlineMs - Date.now();
        const submit = await this.kurier.submitProof(generated.proof, generated.publicSignals, this.config.gatekeeperVkHash);
        proofReference = submit.jobId;
        if (submit.jobId) {
          const pollBudget = Math.max(0, Math.min(KURIER_SHORT_POLL_MAX_MS, remaining - 2_000));
          const shortStatus = await this.kurier.pollJob(submit.jobId, pollBudget);
          log("info", "kurier short poll done", { task_id: task.task_id, job_id: submit.jobId, status: shortStatus });
          if (shortStatus !== "Finalized" && shortStatus !== "Failed") {
            // Background continuation: never blocks the response.
            void this.kurier
              .pollJob(submit.jobId, KURIER_BACKGROUND_POLL_MS)
              .then((finalStatus) => {
                log("info", "kurier background poll finished", {
                  task_id: task.task_id,
                  job_id: submit.jobId,
                  status: finalStatus,
                });
              })
              .catch((err) => log("warn", "kurier background poll error", { task_id: task.task_id, error: String(err).slice(0, 120) }));
          }
        }
      } catch (err) {
        // Kurier failures must NEVER turn an approve into a timeout: the
        // local proof is what the platform re-verifies. Log and continue.
        log("warn", "kurier submit/poll failed — responding with local proof only", {
          task_id: task.task_id,
          error: String(err).slice(0, 200),
        });
      }
    }

    const response: GatekeeperResponse = {
      decision: "APPROVE",
      reason_code: "VALID_CONDITION",
      proof: generated.proof,
      public_signals: generated.publicSignals,
      proof_tx: input.proof_tx,
      proofReference,
    };
    log("info", "task APPROVED", {
      task_id: task.task_id,
      ms: Date.now() - started,
      kurier_job_id: proofReference,
      prove_ms: generated.proveMs,
    });
    return response;
  }

  /** Build a REJECT response, generating a decision=0 proof when attestable. */
  private async finishReject(task: TaskEnvelope, result: DecisionResult, started: number): Promise<GatekeeperResponse> {
    const base: GatekeeperResponse = {
      decision: "REJECT",
      reason_code: result.reason_code,
      proof_tx: task.input.proof_tx,
    };
    if (!result.provable) {
      log("info", "task REJECTED (no proof — non-circuit reason)", {
        task_id: task.task_id,
        reason_code: result.reason_code,
        ms: Date.now() - started,
      });
      return base;
    }
    try {
      const generated = await this.prover.prove(task, 0);
      log("info", "task REJECTED (with decision=0 proof)", {
        task_id: task.task_id,
        reason_code: result.reason_code,
        ms: Date.now() - started,
        prove_ms: generated.proveMs,
      });
      return { ...base, proof: generated.proof, public_signals: generated.publicSignals };
    } catch (err) {
      // Proof generation failed for a reject: keep the decision engine's
      // reason_code (it identifies the trap) and respond without a proof.
      // This happens when the circuit cannot attest the decision — e.g. a
      // VK_SUBSTITUTION where proof_vk == registered_vk but neither equals
      // the canonical hash: in-circuit all checks pass, so a decision=0
      // proof cannot exist. The decision stands; only the proof is missing.
      log("error", "proof generation failed on REJECT path — responding without proof", {
        task_id: task.task_id,
        reason_code: result.reason_code,
        error: String(err).slice(0, 200),
      });
      return base;
    }
  }

  private async handleAgent(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = Date.now();
    const deadlineMs = started + HANDLER_CAP_MS;
    this.inFlight++;
    try {
      let raw: Buffer;
      try {
        raw = await this.readBody(req);
      } catch (err) {
        this.sendUnsigned(res, 413, { error: "body too large or unreadable" });
        return;
      }

      // HMAC verification BEFORE any parsing.
      const signature = req.headers[SIGNATURE_HEADER] as string | undefined;
      if (!verifySignature(this.config.hmacSecret, raw, signature)) {
        log("warn", "HMAC verification failed — 401, no processing", { sig_prefix: (signature ?? "").slice(0, 8) });
        this.sendUnsigned(res, 401, { error: "invalid signature" });
        return;
      }

      let envelope;
      try {
        envelope = parseEnvelope(raw);
      } catch (err) {
        const message = err instanceof EnvelopeError ? err.message : "invalid envelope";
        log("warn", "envelope rejected", { error: message });
        this.sendSigned(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });
        return;
      }

      if (envelope.type === "agent-games.preflight.v1") {
        if (this.config.agentId && envelope.agent_id !== this.config.agentId) {
          log("warn", "preflight agent_id mismatch", { agent_id: envelope.agent_id });
          this.sendSigned(res, 200, { ok: false, protocolVersion: "v1", error: "agent_id mismatch" });
          return;
        }
        log("info", "preflight OK", { agent_id: envelope.agent_id, nonce: envelope.nonce });
        this.sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
        return;
      }

      // Task with a 50s hard cap: race the handler against the deadline.
      const task = envelope;
      const handler = this.handleTask(task, deadlineMs);
      const cap = new Promise<GatekeeperResponse>((resolve) =>
        setTimeout(
          () => resolve({ decision: "REJECT", reason_code: "PROOF_GENERATION_FAILED", proof_tx: task.input.proof_tx }),
          Math.max(0, deadlineMs - Date.now()),
        ),
      );
      const response = await Promise.race([handler, cap]);
      this.sendSigned(res, 200, response);

      // Record proof_tx ONLY after a successful APPROVE response was sent.
      if (response.decision === "APPROVE" && response.reason_code === "VALID_CONDITION") {
        this.seen.record(task.input.proof_tx, {
          task_id: task.task_id,
          decided_at: new Date().toISOString(),
          kurier_job_id: response.proofReference ?? null,
          kurier_status: null,
        });
      }
      log("debug", "task response sent", { task_id: task.task_id, ms: Date.now() - started });
    } catch (err) {
      log("error", "unhandled error in /agent handler", { error: String(err).slice(0, 300) });
      if (!res.headersSent) {
        this.sendSigned(res, 200, { decision: "REJECT", reason_code: "PROOF_GENERATION_FAILED" });
      }
    } finally {
      this.inFlight--;
    }
  }

  private handleHealth(_req: IncomingMessage, res: ServerResponse): void {
    this.sendUnsigned(res, 200, {
      ok: true,
      service: "proof-gatekeeper",
      version: "1.0.0",
      uptime_s: Math.floor(process.uptime()),
      seen_entries: this.seen.size,
      kurier_enabled: this.kurier.enabled,
      subscan_configured: this.config.subscanApiKey !== null,
      vk_hash_prefix: this.config.gatekeeperVkHash.slice(0, 10),
      in_flight: this.inFlight,
    });
  }

  listen(): void {
    const server = createServer((req, res) => {
      const url = req.url ?? "/";
      if (req.method === "GET" && url === "/health") {
        this.handleHealth(req, res);
        return;
      }
      if (req.method === "POST" && url === "/agent") {
        void this.handleAgent(req, res);
        return;
      }
      this.sendUnsigned(res, 404, { error: "not found" });
    });
    server.listen(this.config.port, () => {
      log("info", "proof-gatekeeper listening", {
        port: this.config.port,
        kurier_enabled: this.kurier.enabled,
        subscan_configured: this.config.subscanApiKey !== null,
        seen_entries: this.seen.size,
      });
    });
    const shutdown = () => {
      log("info", "shutting down");
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 5_000).unref();
    };
    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);
  }
}
