/**
 * seen.ts — persistent seen-set of approved proof_tx values.
 *
 * A proof_tx is recorded ONLY after a successful APPROVE response has been
 * sent (recording before responding risks double-counting on a platform
 * retry). Writes are atomic (temp file + rename) so a crash cannot corrupt
 * the set. File: <dataDir>/seen.json — gitignored, never committed.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { log } from "./logger.js";

export interface SeenEntry {
  task_id: string;
  decided_at: string;
  kurier_job_id: string | null;
  kurier_status: string | null;
}

export class SeenSet {
  private readonly path: string;
  private readonly map = new Map<string, SeenEntry>();

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.path = join(dataDir, "seen.json");
    if (existsSync(this.path)) {
      try {
        const raw = JSON.parse(readFileSync(this.path, "utf8")) as Record<string, SeenEntry>;
        for (const [k, v] of Object.entries(raw)) this.map.set(k.toLowerCase(), v);
        log("info", "seen-set loaded", { entries: this.map.size });
      } catch (err) {
        log("error", "seen-set corrupt, starting empty (old file kept as .corrupt)", { path: this.path });
        try {
          renameSync(this.path, this.path + ".corrupt");
        } catch {
          /* best effort */
        }
      }
    }
  }

  has(proofTx: string): boolean {
    return this.map.has(proofTx.toLowerCase());
  }

  get size(): number {
    return this.map.size;
  }

  /** Record an approved proof_tx. Atomic write. */
  record(proofTx: string, entry: SeenEntry): void {
    this.map.set(proofTx.toLowerCase(), entry);
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.map), null, 2) + "\n", "utf8");
    renameSync(tmp, this.path);
    log("info", "proof_tx recorded in seen-set", { proof_tx_prefix: proofTx.slice(0, 10), entries: this.map.size });
  }
}
