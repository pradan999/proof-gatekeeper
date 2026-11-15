/**
 * logger.ts — structured JSON logs to stdout. NEVER log secrets, full HMAC
 * values, API keys, or full request/response bodies. Only truncated,
 * non-sensitive identifiers (task_id, first 10 chars of a tx hash).
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
const MIN_LEVEL: LogLevel = (process.env.LOG_LEVEL as LogLevel) || "info";

export function log(level: LogLevel, msg: string, fields: Record<string, unknown> = {}): void {
  if (LEVELS[level] < LEVELS[MIN_LEVEL]) return;
  const entry = { ts: new Date().toISOString(), level, msg, ...fields };
  process.stdout.write(JSON.stringify(entry) + "\n");
}
