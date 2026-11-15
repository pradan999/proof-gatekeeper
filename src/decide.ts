/**
 * decide.ts — the DETERMINISTIC decision engine. No LLM, no heuristics,
 * no randomness. Checks run in a fixed order; the first failure wins.
 *
 * Order (matches the /build Security checklist + the event trap table):
 *   1. INVALID_TIMESTAMP      issued_at unparseable / stale (>10 min old) /
 *                               issued in the future (>5 min) / now past deadline_at
 *   2. VK_SUBSTITUTION        proof_vk != registered_vk, or registered_vk !=
 *                               the canonical gatekeeper vkHash
 *   3. THRESHOLD_MISMATCH     public_balance < minimum
 *   4. RECIPIENT_MISMATCH     recipient != condition_recipient (case-insensitive)
 *   5. AMOUNT_OVERFLOW        amount > max_transfer
 *   6. EXPIRED_CONDITION      current_block >= expiry_block
 *   7. PROOF_REUSED           proof_tx already in the local seen-set
 *   8. PROOF_NOT_FOUND        proof_tx cannot be confirmed finalized on zkVerify
 *   9. VALID_CONDITION        everything passes -> APPROVE
 *
 * INVALID_TIMESTAMP and PROOF_NOT_FOUND are EXTENSION codes (not in the
 * platform's published trap table); they are documented as such in the README.
 *
 * Proof attachment rule (see prover.ts + README "Which responses carry a proof"):
 * the circuit can only attest decisions that follow from its own checks, so a
 * proof is generated for APPROVE (decision=1) and for REJECTs caused by an
 * in-circuit check (decision=0). Rejections caused by OUT-OF-CIRCUIT reasons
 * (INVALID_TIMESTAMP, PROOF_NOT_FOUND) and PROOF_REUSED carry no proof.
 */
import type { TaskEnvelope } from "./envelope.js";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "EXPIRED_CONDITION"
  | "PROOF_REUSED"
  | "PROOF_NOT_FOUND"
  | "INVALID_TIMESTAMP"
  | "PROOF_GENERATION_FAILED";

export type Decision = "APPROVE" | "REJECT";

export interface DecisionResult {
  decision: Decision;
  reason_code: ReasonCode;
  /** True when this decision can be attested by the gatekeeper circuit. */
  provable: boolean;
  /** The decision value fed to the circuit: 1 = approve, 0 = reject. */
  circuitDecision: 0 | 1;
}

/** Reasons that are NOT attested by the circuit (no proof can be generated). */
export const NON_CIRCUIT_REASONS: ReadonlySet<ReasonCode> = new Set([
  "INVALID_TIMESTAMP",
  "PROOF_NOT_FOUND",
  "PROOF_REUSED",
  "PROOF_GENERATION_FAILED",
]);

const MAX_ISSUED_AGE_MS = 10 * 60 * 1000; // 10 minutes
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000; // 5 minutes

export interface DecideContext {
  /** Canonical gatekeeper vkHash (lowercase 0x hex). */
  canonicalVkHash: string;
  /** True when proof_tx is already in the local seen-set. */
  proofTxSeen: boolean;
  /** Outcome of the on-chain proof_tx confirmation (step 8). */
  proofTxConfirmed: boolean;
  /** Server time at decision time (injectable for tests). */
  now: Date;
}

export function decide(task: TaskEnvelope, ctx: DecideContext): DecisionResult {
  const input = task.input;

  // 1. Timestamp validity.
  const issuedAt = Date.parse(task.issued_at);
  const deadlineAt = Date.parse(task.deadline_at);
  if (Number.isNaN(issuedAt) || Number.isNaN(deadlineAt)) {
    return { decision: "REJECT", reason_code: "INVALID_TIMESTAMP", provable: false, circuitDecision: 0 };
  }
  const nowMs = ctx.now.getTime();
  if (issuedAt < nowMs - MAX_ISSUED_AGE_MS || issuedAt > nowMs + MAX_FUTURE_SKEW_MS || nowMs > deadlineAt) {
    return { decision: "REJECT", reason_code: "INVALID_TIMESTAMP", provable: false, circuitDecision: 0 };
  }

  // 2. VK substitution — both the proof's vk and the registered vk must equal
  //    the canonical gatekeeper vkHash.
  if (input.proof_vk !== input.registered_vk || input.registered_vk !== ctx.canonicalVkHash) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true, circuitDecision: 0 };
  }

  // 3. Threshold.
  if (input.public_balance < input.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true, circuitDecision: 0 };
  }

  // 4. Recipient.
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true, circuitDecision: 0 };
  }

  // 5. Amount cap.
  if (input.amount > input.max_transfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true, circuitDecision: 0 };
  }

  // 6. Expiry.
  if (input.current_block >= input.expiry_block) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true, circuitDecision: 0 };
  }

  // 7. Reuse (local seen-set).
  if (ctx.proofTxSeen) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false, circuitDecision: 0 };
  }

  // 8. On-chain confirmation of proof_tx (fail closed).
  if (!ctx.proofTxConfirmed) {
    return { decision: "REJECT", reason_code: "PROOF_NOT_FOUND", provable: false, circuitDecision: 0 };
  }

  // 9. All checks pass.
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true, circuitDecision: 1 };
}
