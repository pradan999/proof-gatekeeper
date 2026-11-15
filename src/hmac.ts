/**
 * hmac.ts — HMAC-SHA256 verification + signing for Agent Games envelopes.
 *
 * The platform signs the RAW request body; we verify BEFORE parsing JSON.
 * Responses are signed over the RAW response body with the same secret.
 * Signature header: `x-agent-games-signature`, hex-encoded (lowercase).
 * NEVER log a secret or a full signature value.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Compute hex HMAC-SHA256 of `body` with `secret`. */
export function signBody(secret: string, body: Buffer): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Verify a hex `signature` against the raw `body`.
 * Uses a timing-safe comparison; length mismatch fails closed.
 * Accepts upper/lowercase hex (normalised before compare).
 */
export function verifySignature(secret: string, body: Buffer, signature: string | undefined | null): boolean {
  if (!signature || typeof signature !== "string") return false;
  const expected = signBody(secret, body);
  const provided = signature.trim().toLowerCase();
  if (provided.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(provided, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}
