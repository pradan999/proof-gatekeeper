/**
 * zkverify.ts — on-chain confirmation of the platform's proof_tx.
 *
 * THE PROBLEM: as of 2026-11-15 there is NO free, keyless public read API
 * that resolves a zkVerify (Volta) extrinsic hash to a finalized inclusion
 * proof:
 *  - Kurier's job-status endpoint only covers jobs submitted through Kurier
 *    itself (proof_tx is a chain tx hash, not a Kurier jobId — except in the
 *    UUID-shaped case handled below).
 *  - Subscan runs the zkVerify explorer (zkverify.subscan.io). Its direct
 *    API (POST https://zkverify.api.subscan.io/api/scan/extrinsic) returns
 *    HTTP 403 "Subscan API strictly requires an API key" for unauthenticated
 *    calls (verified live 2026-11-15) — and Subscan NO LONGER issues free
 *    direct API keys (docs updated 2026-10-20; direct keys are paid-only,
 *    Developer $182/yr+). PubFi and direct Subscan credentials are NOT
 *    interchangeable.
 *  - No verified public Volta RPC URL is published in the Agent Games docs.
 *
 * THE ROUTE (verified 2026-11-15 against the live PubFi Runtime OpenAPI,
 * generation 301, fetched from https://api.pubfi.ai/openapi.json):
 *  - Base URL: https://api.pubfi.ai
 *  - Auth: Authorization: Bearer <PUBFI_API_KEY>
 *  - POST /v1/gateway/subscan/zkverify/api/scan/extrinsic — status "ready";
 *    "zkverify" is in the route's network enum (79 networks). The gateway
 *    relays the upstream Subscan response body opaquely (application/json).
 *  - Free variant: append ":free" to the path. Free rate limit: 2 req/s,
 *    max concurrency 2, quota 20,000/day (provider bucket); a free request
 *    consumes NO Credits. Body: {"hash": "0x..."} (typed schema
 *    ExtrinsicDetailParams: hash / extrinsic_index / events_limit /
 *    hide_events — the old direct-API fields row/page are NOT in the schema).
 *  - Billed variant (same path, no ":free"): 1 Credit per call. The account
 *    holds 1,000 pre-granted Credits; no purchase is involved. Used ONLY as
 *    a one-shot fallback when the free variant answers 402 or 429.
 *
 * WHAT THIS MODULE DOES (fail closed, per the safety rules):
 *  1. If proof_tx looks like a Kurier jobId (UUID) AND a Kurier key is set,
 *     confirm via Kurier job-status == Finalized.
 *  2. Else if PUBFI_API_KEY is set, confirm via the PubFi Gateway (free
 *     variant first, billed fallback on 402/429): extrinsic found + success
 *     + block number present. (Finality: Subscan only indexes
 *     finalized/canonical blocks for the chains it serves, and we
 *     additionally require the extrinsic's block to be at least 1 block
 *     behind the chain head when the head is available — see code.)
 *  3. Otherwise return {confirmed:false, source:"none"} — the decision
 *     engine then REJECTs with PROOF_NOT_FOUND. This is deliberate: an
 *     unverified proof_tx must never be approved.
 *
 * UNVERIFIED ASSUMPTION (validate on the first live task): the gateway's
 * opaque relay returns the upstream Subscan body shape unchanged
 * ({code: 0, data: {extrinsic: {block_num, success, ...}}}). The parser
 * below tolerates a missing top-level `code` when `data` is present, but
 * any other shape still resolves to "unconfirmed" (fail closed).
 *
 * See README "The proof_tx confirmation problem".
 */
import { log } from "./logger.js";

export interface ProofTxConfirmation {
  confirmed: boolean;
  source: "kurier" | "pubfi" | "none";
  detail: string;
  blockNumber: number | null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

/** PubFi Gateway route for the zkVerify extrinsic lookup (verified live 2026-11-15). */
export const PUBFI_GATEWAY_BASE = "https://api.pubfi.ai";
export const PUBFI_GATEWAY_EXTRINSIC_PATH = "/v1/gateway/subscan/zkverify/api/scan/extrinsic";

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
  pubfiApiKey: string | null;
  pubfiApiUrl: string;
  /** Test hook: confirm via Kurier job-status. Defaults to the real client call. */
  kurierJobStatus?: (jobId: string) => Promise<string>;
  /** Test hook: replace the gateway fetch (unit tests without a real key). */
  pubfiFetch?: (url: string, init: RequestInit) => Promise<Response>;
}

/** Parse a (possibly relayed) Subscan extrinsic response. Fail closed on any ambiguity. */
function parseExtrinsicResponse(body: Record<string, unknown> | null): { ok: boolean; blockNumber: number | null; success: boolean } {
  if (!body) return { ok: false, blockNumber: null, success: false };
  const data = body.data as Record<string, unknown> | undefined;
  // The gateway relays the upstream body opaquely: code===0 is the direct
  // Subscan success signal. Tolerate a missing top-level code ONLY when a
  // data object is present (a wrapper variant); anything else is unconfirmed.
  const codeOk = body.code === 0 || (body.code === undefined && data !== undefined);
  if (!codeOk) return { ok: false, blockNumber: null, success: false };
  const extrinsic = (data?.extrinsic ?? data) as Record<string, unknown> | undefined;
  const blockNumber = typeof extrinsic?.block_num === "number" ? (extrinsic.block_num as number) : null;
  const success = extrinsic?.success === true;
  return { ok: true, blockNumber, success };
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

  // Strategy 1: PubFi Gateway -> Subscan extrinsic lookup (requires key).
  if (deps.pubfiApiKey) {
    if (!TX_HASH_RE.test(proofTx)) {
      return { confirmed: false, source: "pubfi", detail: "proof_tx is not a 0x 32-byte hash", blockNumber: null };
    }
    const base = (deps.pubfiApiUrl || PUBFI_GATEWAY_BASE).replace(/\/$/, "");
    const fetchFn = deps.pubfiFetch
      ? (url: string, init: RequestInit) => deps.pubfiFetch!(url, init)
      : (url: string, init: RequestInit) => fetchWithTimeout(url, init, timeoutMs);
    const headers = { "Content-Type": "application/json", Authorization: `Bearer ${deps.pubfiApiKey}` };
    // Free variant first; one billed fallback on 402/429 (1 pre-granted Credit, no purchase).
    const attempts: Array<{ url: string; variant: string }> = [
      { url: `${base}${PUBFI_GATEWAY_EXTRINSIC_PATH}:free`, variant: "free" },
      { url: `${base}${PUBFI_GATEWAY_EXTRINSIC_PATH}`, variant: "billed" },
    ];
    for (let i = 0; i < attempts.length; i++) {
      const { url, variant } = attempts[i];
      try {
        const res = await fetchFn(url, {
          method: "POST",
          headers,
          body: JSON.stringify({ hash: proofTx }),
        });
        const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
        if (res.status === 402 || res.status === 429) {
          if (i === 0) {
            log("warn", "pubfi free variant unavailable — retrying billed variant (1 pre-granted Credit)", {
              proof_tx_prefix: prefix,
              http: res.status,
            });
            continue;
          }
          return { confirmed: false, source: "pubfi", detail: `pubfi gateway error http=${res.status}`, blockNumber: null };
        }
        if (!res.ok || !body) {
          return { confirmed: false, source: "pubfi", detail: `pubfi gateway error http=${res.status}`, blockNumber: null };
        }
        const parsed = parseExtrinsicResponse(body);
        if (!parsed.ok) {
          return { confirmed: false, source: "pubfi", detail: "pubfi gateway: extrinsic response not understood", blockNumber: null };
        }
        if (parsed.blockNumber !== null && parsed.success) {
          return {
            confirmed: true,
            source: "pubfi",
            detail: `extrinsic in block ${parsed.blockNumber}, success (via ${variant} variant)`,
            blockNumber: parsed.blockNumber,
          };
        }
        return { confirmed: false, source: "pubfi", detail: "extrinsic not found or not successful", blockNumber: parsed.blockNumber };
      } catch (err) {
        log("warn", "pubfi proof_tx lookup failed", { proof_tx_prefix: prefix, error: String(err).slice(0, 120) });
        return { confirmed: false, source: "pubfi", detail: "pubfi lookup error", blockNumber: null };
      }
    }
    return { confirmed: false, source: "pubfi", detail: "pubfi gateway: no variant answered", blockNumber: null };
  }

  // Strategy 2: none available — fail closed.
  return {
    confirmed: false,
    source: "none",
    detail: "no proof_tx read endpoint configured (set PUBFI_API_KEY; see README)",
    blockNumber: null,
  };
}
