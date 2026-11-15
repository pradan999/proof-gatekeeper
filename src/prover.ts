/**
 * prover.ts — local Groth16 proof generation with snarkjs.
 *
 * CIRCUIT INPUTS (discovered from the artifacts, see circuits/INPUTS.md —
 * the platform does NOT publish signal names; these were recovered by
 * brute-forcing the wasm's FNV-1a signal-name hash table and verified by
 * successful fullProve + local groth16.verify):
 *
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt          (13 inputs, all scalar)
 *
 * Semantics verified by experiment (2026-11-15, see circuits/INPUTS.md):
 *  - public_signals[0]  = Poseidon-style commitment over the inputs
 *  - public_signals[1]  = registeredVkHash (as a field element, hash mod p)
 *  - public_signals[2]  = proofVkHash
 *  - public_signals[3..10] = minimum, publicBalance, expiryBlock,
 *    currentBlock, recipient, conditionRecipient, amount, maxTransfer
 *  - public_signals[11] = decision (1 = approve, 0 = reject)
 *  - public_signals[12] = taskId
 *  - salt is the ONLY private input (never appears in public signals).
 *  - The circuit asserts decision == AND(all in-circuit checks). A
 *    decision=1 proof with any failing check FAILS witness generation
 *    (GatekeeperEvaluation_79 line 102); a decision=0 proof with all
 *    checks passing fails the same way. Only consistent decisions prove.
 *
 * Encodings (field elements are reduced mod the BN128 scalar field by
 * snarkjs; we reduce explicitly for clarity):
 *  - vk hashes: full 32-byte hash as a BigInt, reduced mod p. (A 256-bit
 *    value cannot fit in one field element unreduced; mod-p reduction is
 *    the only sane encoding, and the platform must do the same when it
 *    checks public_signals[1..2] against the task.)
 *  - recipient / condition_recipient: 20-byte address as a BigInt.
 *  - taskId: keccak256(task_id) as a BigInt, reduced mod p. ASSUMPTION —
 *    the platform's canonical string->field encoding is not published.
 *    keccak256 is the Ethereum-standard choice; if a practice task shows
 *    the platform expects a different encoding, change TASK_ID_ENCODING
 *    in one place (see encodeTaskId below) and re-run the harness.
 *  - salt: fresh crypto-random 128-bit value per proof (private input;
 *    binds the proof to this attempt and randomises the commitment).
 *
 * Proof generation is fast (~0.4–1s measured locally on this VM) and is
 * always locally re-verified against circuits/vk.json before the proof is
 * returned. Any failure -> the caller rejects with PROOF_GENERATION_FAILED
 * (never approve without a proof).
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import * as snarkjs from "snarkjs";
// js-sha3 is a CommonJS module — load it via createRequire.
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { keccak256 } = require("js-sha3") as { keccak256: (data: string) => string };
import type { TaskEnvelope } from "./envelope.js";
import { log } from "./logger.js";

export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** The 13 circuit input signal names, in declaration order. */
export const CIRCUIT_INPUTS = [
  "registeredVkHash",
  "proofVkHash",
  "minimum",
  "publicBalance",
  "expiryBlock",
  "currentBlock",
  "recipient",
  "conditionRecipient",
  "amount",
  "maxTransfer",
  "decision",
  "taskId",
  "salt",
] as const;

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
  /** Milliseconds spent inside fullProve. */
  proveMs: number;
}

export class Prover {
  private readonly wasmPath: string;
  private readonly zkeyPath: string;
  private readonly vk: unknown;

  constructor(wasmPath: string, zkeyPath: string, vkPath: string) {
    this.wasmPath = wasmPath;
    this.zkeyPath = zkeyPath;
    this.vk = JSON.parse(readFileSync(vkPath, "utf8"));
  }

  /** keccak256(task_id) reduced mod p. See the encoding note above. */
  static encodeTaskId(taskId: string): string {
    return (BigInt("0x" + keccak256(taskId)) % FIELD_MODULUS).toString();
  }

  static encodeVkHash(hex: string): string {
    return (BigInt(hex) % FIELD_MODULUS).toString();
  }

  static encodeAddress(hex: string): string {
    return BigInt(hex).toString();
  }

  /** Build the circuit input object for a task + a circuit decision (0/1). */
  static buildInput(task: TaskEnvelope, circuitDecision: 0 | 1): Record<string, string> {
    const input = task.input;
    const salt = (BigInt("0x" + randomBytes(16).toString("hex")) % FIELD_MODULUS).toString();
    return {
      registeredVkHash: Prover.encodeVkHash(input.registered_vk),
      proofVkHash: Prover.encodeVkHash(input.proof_vk),
      minimum: input.minimum.toString(),
      publicBalance: input.public_balance.toString(),
      expiryBlock: input.expiry_block.toString(),
      currentBlock: input.current_block.toString(),
      recipient: Prover.encodeAddress(input.recipient),
      conditionRecipient: Prover.encodeAddress(input.condition_recipient),
      amount: input.amount.toString(),
      maxTransfer: input.max_transfer.toString(),
      decision: String(circuitDecision),
      taskId: Prover.encodeTaskId(task.task_id),
      salt,
    };
  }

  /**
   * Generate + locally verify a proof for a task. Throws on any failure.
   * The caller converts a throw into REJECT / PROOF_GENERATION_FAILED.
   */
  async prove(task: TaskEnvelope, circuitDecision: 0 | 1, proveTimeoutMs = 20_000): Promise<GeneratedProof> {
    const input = Prover.buildInput(task, circuitDecision);
    const t0 = Date.now();
    const provePromise = (async () => {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, this.wasmPath, this.zkeyPath);
      const ok = await snarkjs.groth16.verify(this.vk, publicSignals, proof);
      if (!ok) throw new Error("local groth16.verify failed for the generated proof");
      return { proof, publicSignals: publicSignals as string[], proveMs: Date.now() - t0 };
    })();
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`proof generation timed out after ${proveTimeoutMs}ms`)), proveTimeoutMs),
    );
    const result = await Promise.race([provePromise, timeout]);
    log("info", "proof generated + locally verified", {
      task_id: task.task_id,
      decision: circuitDecision,
      prove_ms: result.proveMs,
      public_signals: result.publicSignals.length,
    });
    return result;
  }
}
