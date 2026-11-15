/**
 * kurier.ts — Kurier REST client (docs.zkverify.io quickstart + "Verifying
 * proofs with Kurier"; API base https://api.kurier.xyz/api/v1, testnet
 * https://api-testnet.kurier.xyz/api/v1; Swagger at /docs).
 *
 * Endpoints used:
 *  - POST /register-vk/{apiKey}   {proofType:"groth16", proofOptions:{library:"snarkjs", curve:"bn128"}, vk: <vk json>}
 *    -> returns the registered vk hash. One-time step; the gatekeeper vk is
 *      already registered by the platform, so the service submits with
 *      vkRegistered:true and does NOT call register-vk on the hot path.
 *      registerVk() is provided for manual one-time use.
 *  - POST /submit-proof/{apiKey}  {proofType:"groth16", vkRegistered:true,
 *      proofOptions:{library:"snarkjs", curve:"bn128"},
 *      proofData:{proof, publicSignals, vk: <registered vkHash>}}
 *    -> {jobId, ...} (shape parsed defensively).
 *  - GET  /job-status/{apiKey}/{jobId} -> {status: "Submitted" |
 *    "IncludedInBlock" | "Finalized" | "Failed" | ..., ...} (shape parsed
 *    defensively — the status field has been seen as `status` and nested
 *    under `data.status` across doc versions).
 *
 * TIMING RULE (hard): the platform's 60s response deadline is absolute.
 * The response carries the LOCALLY generated proof; Kurier is never on the
 * critical path. submitProof + pollJob are called with a SHORT budget taken
 * from the remaining handler time (max ~10s); the handler responds with the
 * local proof + the Kurier job id (as proofReference) when available, and
 * polling continues in the background until Finalized (or a 5-minute cap).
 * A task is only marked "confirmed" when a job reaches Finalized.
 */
import { log } from "./logger.js";

export type KurierJobStatus = "Submitted" | "IncludedInBlock" | "Finalized" | "Failed" | "Unknown";

export interface KurierSubmitResult {
  jobId: string | null;
  statusUrl: string | null;
  raw: unknown;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function readStatus(body: unknown): KurierJobStatus {
  if (typeof body === "object" && body !== null) {
    const obj = body as Record<string, unknown>;
    const candidates = [obj.status, (obj.data as Record<string, unknown> | undefined)?.status, obj.state];
    for (const c of candidates) {
      if (typeof c === "string" && ["Submitted", "IncludedInBlock", "Finalized", "Failed"].includes(c)) {
        return c as KurierJobStatus;
      }
    }
  }
  return "Unknown";
}

function readJobId(body: unknown): string | null {
  if (typeof body === "object" && body !== null) {
    const obj = body as Record<string, unknown>;
    for (const key of ["jobId", "job_id", "id"]) {
      if (typeof obj[key] === "string" && (obj[key] as string).length > 0) return obj[key] as string;
    }
    const data = obj.data as Record<string, unknown> | undefined;
    if (data) {
      for (const key of ["jobId", "job_id", "id"]) {
        if (typeof data[key] === "string" && (data[key] as string).length > 0) return data[key] as string;
      }
    }
  }
  return null;
}

export class KurierClient {
  private readonly apiUrl: string;
  private readonly apiKey: string | null;

  constructor(apiUrl: string, apiKey: string | null) {
    this.apiUrl = apiUrl;
    this.apiKey = apiKey;
  }

  get enabled(): boolean {
    return this.apiKey !== null && this.apiKey.length > 0;
  }

  /** One-time VK registration. Not called on the hot path. */
  async registerVk(vk: unknown, timeoutMs = 30_000): Promise<string | null> {
    if (!this.enabled) throw new Error("KURIER_API_KEY is not set");
    const res = await fetchWithTimeout(`${this.apiUrl}/register-vk/${this.apiKey}`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ proofType: "groth16", proofOptions: { library: "snarkjs", curve: "bn128" }, vk }),
    }, timeoutMs);
    const body: unknown = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`register-vk failed: HTTP ${res.status} ${JSON.stringify(body)?.slice(0, 300)}`);
    const obj = body as Record<string, unknown>;
    const hash = (obj.vkHash as string) ?? ((obj.data as Record<string, unknown> | undefined)?.vkHash as string) ?? null;
    log("info", "kurier vk registered", { vk_hash_prefix: typeof hash === "string" ? hash.slice(0, 10) : null });
    return typeof hash === "string" ? hash : null;
  }

  /** Submit a proof for verification. Returns the job id (if any). */
  async submitProof(proof: unknown, publicSignals: string[], vkHash: string, timeoutMs = 15_000): Promise<KurierSubmitResult> {
    if (!this.enabled) throw new Error("KURIER_API_KEY is not set");
    const res = await fetchWithTimeout(`${this.apiUrl}/submit-proof/${this.apiKey}`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
      }),
    }, timeoutMs);
    const body: unknown = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`submit-proof failed: HTTP ${res.status} ${JSON.stringify(body)?.slice(0, 300)}`);
    const jobId = readJobId(body);
    const statusUrl = jobId ? `${this.apiUrl}/job-status/${this.apiKey}/${jobId}` : null;
    log("info", "kurier proof submitted", { job_id: jobId });
    return { jobId, statusUrl, raw: body };
  }

  /** Poll one job until it reaches a terminal state or the budget is spent. */
  async pollJob(jobId: string, budgetMs: number, intervalMs = 2_000): Promise<KurierJobStatus> {
    if (!this.enabled) return "Unknown";
    const deadline = Date.now() + budgetMs;
    let last: KurierJobStatus = "Unknown";
    while (Date.now() < deadline) {
      try {
        const res = await fetchWithTimeout(
          `${this.apiUrl}/job-status/${this.apiKey}/${jobId}`,
          { method: "GET" },
          Math.min(10_000, Math.max(1_000, deadline - Date.now())),
        );
        const body: unknown = await res.json().catch(() => null);
        if (res.ok) {
          last = readStatus(body);
          log("debug", "kurier job status", { job_id: jobId, status: last });
          if (last === "Finalized" || last === "Failed") return last;
        } else {
          log("warn", "kurier job-status non-OK", { job_id: jobId, http_status: res.status });
        }
      } catch (err) {
        log("warn", "kurier job-status error", { job_id: jobId, error: String(err).slice(0, 120) });
      }
      const wait = Math.min(intervalMs, Math.max(0, deadline - Date.now()));
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }
    return last;
  }
}
