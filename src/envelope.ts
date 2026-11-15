/**
 * envelope.ts — parsing + validation of inbound Agent Games envelopes.
 *
 * Two envelope types:
 *  - preflight: {"type":"agent-games.preflight.v1","agent_id":"agt_...","issued_at":"...","nonce":"..."}
 *  - task:      {"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_...","mode":"competition",
 *                "issued_at":"...","deadline_at":"...","input":{...}}
 *
 * Numbers in `input` may arrive as JSON numbers OR decimal strings (the
 * platform's own sample page uses numbers for block heights, strings for
 * amounts). All numeric fields are normalised to BigInt here.
 */
import { log } from "./logger.js";

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: bigint;
  public_balance: bigint;
  expiry_block: bigint;
  current_block: bigint;
  recipient: string;
  condition_recipient: string;
  amount: bigint;
  max_transfer: bigint;
  proof_tx: string;
}

export interface TaskEnvelope {
  type: "agent-games.proof-gatekeeper.v1";
  task_id: string;
  mode: string;
  issued_at: string;
  deadline_at: string;
  input: GatekeeperInput;
}

export interface PreflightEnvelope {
  type: "agent-games.preflight.v1";
  agent_id: string;
  issued_at: string;
  nonce: string;
}

export type Envelope = TaskEnvelope | PreflightEnvelope;

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

function asBigInt(value: unknown, field: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) throw new EnvelopeError(`input.${field} must be a non-negative integer`);
    return BigInt(value);
  }
  if (typeof value === "string" && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value.trim())) {
    try {
      return BigInt(value.trim());
    } catch {
      throw new EnvelopeError(`input.${field} is not a valid integer: ${field}`);
    }
  }
  throw new EnvelopeError(`input.${field} must be an integer or decimal/hex string`);
}

function asHexString(value: unknown, field: string, bytes: number): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value.trim())) {
    throw new EnvelopeError(`input.${field} must be a 0x hex string`);
  }
  const v = value.trim().toLowerCase();
  if (bytes > 0 && v.length !== 2 + bytes * 2) {
    throw new EnvelopeError(`input.${field} must be ${bytes} bytes (0x + ${bytes * 2} hex chars)`);
  }
  return v;
}

function asAddress(value: unknown, field: string): string {
  return asHexString(value, field, 20);
}

function asNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new EnvelopeError(`${field} must be a non-empty string`);
  return value.trim();
}

/** Parse a raw body into a validated envelope. Throws EnvelopeError on any problem. */
export function parseEnvelope(raw: Buffer): Envelope {
  let json: unknown;
  try {
    json = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new EnvelopeError("body is not valid JSON");
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new EnvelopeError("body must be a JSON object");
  }
  const obj = json as Record<string, unknown>;

  if (obj.type === "agent-games.preflight.v1") {
    return {
      type: "agent-games.preflight.v1",
      agent_id: asNonEmptyString(obj.agent_id, "agent_id"),
      issued_at: asNonEmptyString(obj.issued_at, "issued_at"),
      nonce: asNonEmptyString(obj.nonce, "nonce"),
    };
  }

  if (obj.type !== "agent-games.proof-gatekeeper.v1") {
    throw new EnvelopeError(`unsupported envelope type: ${String(obj.type)}`);
  }
  if (typeof obj.input !== "object" || obj.input === null || Array.isArray(obj.input)) {
    throw new EnvelopeError("input must be an object");
  }
  const input = obj.input as Record<string, unknown>;
  const task: TaskEnvelope = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: asNonEmptyString(obj.task_id, "task_id"),
    mode: typeof obj.mode === "string" ? obj.mode : "competition",
    issued_at: asNonEmptyString(obj.issued_at, "issued_at"),
    deadline_at: asNonEmptyString(obj.deadline_at, "deadline_at"),
    input: {
      registered_vk: asHexString(input.registered_vk, "registered_vk", 32),
      proof_vk: asHexString(input.proof_vk, "proof_vk", 32),
      minimum: asBigInt(input.minimum, "minimum"),
      public_balance: asBigInt(input.public_balance, "public_balance"),
      expiry_block: asBigInt(input.expiry_block, "expiry_block"),
      current_block: asBigInt(input.current_block, "current_block"),
      recipient: asAddress(input.recipient, "recipient"),
      condition_recipient: asAddress(input.condition_recipient, "condition_recipient"),
      amount: asBigInt(input.amount, "amount"),
      max_transfer: asBigInt(input.max_transfer, "max_transfer"),
      proof_tx: asHexString(input.proof_tx, "proof_tx", 32),
    },
  };
  log("debug", "envelope parsed", { task_id: task.task_id, proof_tx_prefix: task.input.proof_tx.slice(0, 10) });
  return task;
}
