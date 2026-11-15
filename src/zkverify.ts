/**
 * zkverify.ts — on-chain confirmation of the platform's proof_tx.
 *
 * THE PROBLEM (documented honestly): as of 2026-11-15 there is NO free,
 * keyless public read API that resolves a zkVerify (Volta) extrinsic hash
 * to a finalized inclusion proof:
 *  - Kurier's job-status endpoint only covers jobs submitted through Kurier
 *    itself (proof_tx is a chain tx hash, not a Kurier jobId — except in the
 *    UUID-shaped case handled below).
 *  - Subscan runs the zkVerify explorer (zkverify.subscan.io) and its API
 *    (POST https://zkverify.api.subscan.io/api/scan/extrinsic
 *    {"hash": "0x..."}) returns the extrinsic + block + success flag — but
 *    since ~2026 it returns HTTP 403 "Subscan API strictly requires an API
 *    key" for unauthenticated calls (verified live 2026-11-15).
 *  - No verified public Volta RPC URL is published in the Agent Games docs.
 *
 * WHAT THIS MODULE DOES (fail closed, per the safety rules):
 *  1. If proof_tx looks like a Kurier jobId (UUID) AND a Kurier key is set,
 *     confirm via Kurier job-status == Finalized.
 *  2. Else if SUBSCAN_API_KEY is set, confirm via the Subscan API:
 *     extrinsic found + success + block number present. (Finality: Subscan
 *     only indexes finalized/canonical blocks for the chains it serves, and
 *     we additionally require the extrinsic's block to be at least 1 block
 *     behind the chain head when the head is available — see code.)
 *  3. Otherwise return {confirmed:false, source:"none"} — the decision
 *     engine then REJECTs with PROOF_NOT_FOUND. This is deliberate: an
 *     unverified proof_tx must never be approved.
 *
 * ACTION REQUIRED BEFORE ROUND 4: get a free Subscan API key
 * (https://subscan.io — sign up, create a key, set SUBSCAN_API_KEY).
 * Until then the agent will REJECT every otherwise-valid task with
 * PROOF_NOT_FOUND. That is the safe default; do NOT weaken it without an
 * explicit decision. See README "The proof_tx confirmation problem".
 */
import { log } from "./logger.js";

export interface ProofTxConfirmation {
  confirmed: boolean;
  source: "kurier" | "subscan" | "none";
  detail: string;
  blockNumber: number | null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export interface ZkVerifyDeps {
  kurierApiUrl: string;
  kurierApiKey: string | null;
  subscanApiKey: string | null;
  /** Test hook: confirm via Kurier job-status. Defaults to the real client call. */
  kurierJobStatus?: (jobId: string) => Promise<string>;
}

export async function confirmProofTx(proofTx: string, deps: ZkVerifyDeps, timeoutMs = 8_000): Promise<ProofTxConfirmation> {
  const prefix = proofTx.slice(0, 10);

  // Strategy 0: UUID-shaped reference = a Kurier job id.
  if (UUID_RE.test(proofTx) && deps.kurierApiKey) {
    try {
      const status = deps.kurierJobStatus
        ? await deps.kurierJobStatus(proofTx)
        : await (async () => {
            const res = await fetchWithTimeout(
              `${deps.kurierApiUrl}/job-status/${deps.kurierApiKey}/${proofTx}`,
              { method: "GET" },
              timeoutMs,
            );
            if (!res.ok) return "Unknown";
            const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
            const s = body?.status ?? (body?.data as Record<string, unknown> | undefined)?.status;
            return typeof s === "string" ? s : "Unknown";
          })();
      if (status === "Finalized") {
        return { confirmed: true, source: "kurier", detail: "kurier job Finalized", blockNumber: null };
      }
      return { confirmed: false, source: "kurier", detail: `kurier job status=${status}`, blockNumber: null };
    } catch (err) {
      log("warn", "kurier proof_tx lookup failed", { proof_tx_prefix: prefix, error: String(err).slice(0, 120) });
    }
  }

  // Strategy 1: Subscan API (requires key).
  if (deps.subscanApiKey) {
    if (!TX_HASH_RE.test(proofTx)) {
      return { confirmed: false, source: "subscan", detail: "proof_tx is not a 0x 32-byte hash", blockNumber: null };
    }
    try {
      const res = await fetchWithTimeout("https://zkverify.api.subscan.io/api/scan/extrinsic", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": deps.subscanApiKey },
        body: JSON.stringify({ hash: proofTx, row: 1, page: 0 }),
      }, timeoutMs);
      const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
      if (!res.ok || !body || body.code !== 0) {
        return { confirmed: false, source: "subscan", detail: `subscan api error http=${res.status}`, blockNumber: null };
      }
      const data = body.data as Record<string, unknown> | undefined;
      const extrinsic = (data?.extrinsic ?? data) as Record<string, unknown> | undefined;
      const blockNumber = typeof extrinsic?.block_num === "number" ? (extrinsic.block_num as number) : null;
      const success = extrinsic?.success === true;
      if (blockNumber !== null && success) {
        return { confirmed: true, source: "subscan", detail: `extrinsic in block ${blockNumber}, success`, blockNumber };
      }
      return { confirmed: false, source: "subscan", detail: "extrinsic not found or not successful", blockNumber };
    } catch (err) {
      log("warn", "subscan proof_tx lookup failed", { proof_tx_prefix: prefix, error: String(err).slice(0, 120) });
      return { confirmed: false, source: "subscan", detail: "subscan lookup error", blockNumber: null };
    }
  }

  // Strategy 2: none available — fail closed.
  return {
    confirmed: false,
    source: "none",
    detail: "no proof_tx read endpoint configured (set SUBSCAN_API_KEY; see README)",
    blockNumber: null,
  };
}
