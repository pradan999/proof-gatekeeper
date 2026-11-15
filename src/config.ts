/**
 * config.ts — environment loading. Fail fast on missing/placeholder secrets.
 *
 * Secrets are read from process.env only (never from files, never hardcoded).
 * A local `.env` file is supported for development via a tiny parser below —
 * production deployments (Railway) should use real environment variables.
 */
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PLACEHOLDERS = new Set(["", "change-me", "changeme", "placeholder", "xxx", "your-secret-here", "test", "demo"]);

/** Minimal .env parser (KEY=VALUE lines, no expansion, no quotes handling beyond stripping). */
export function loadDotEnv(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "..", ".env"), join(process.cwd(), ".env")];
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (!(key in process.env)) process.env[key] = value;
    }
    return;
  }
}

export interface Config {
  hmacSecret: string;
  kurierApiKey: string | null;
  pubfiApiKey: string | null;
  agentId: string | null;
  port: number;
  /** Canonical gatekeeper verification-key hash (registered on zkVerify mainnet). */
  gatekeeperVkHash: string;
  kurierApiUrl: string;
  pubfiApiUrl: string;
  wasmPath: string;
  zkeyPath: string;
  vkPath: string;
  dataDir: string;
}

function requiredSecret(name: string): string {
  const value = (process.env[name] ?? "").trim();
  if (PLACEHOLDERS.has(value.toLowerCase())) {
    throw new Error(
      `Missing or placeholder secret: ${name}. Set it in the environment (or .env for local dev). ` +
        `The service refuses to start without a real HMAC secret.`,
    );
  }
  return value;
}

function optionalSecret(name: string): string | null {
  const value = (process.env[name] ?? "").trim();
  return PLACEHOLDERS.has(value.toLowerCase()) ? null : value;
}

export function loadConfig(): Config {
  loadDotEnv();
  const here = dirname(fileURLToPath(import.meta.url));
  const root = join(here, "..");
  return {
    hmacSecret: requiredSecret("AGENT_GAMES_HMAC_SECRET"),
    kurierApiKey: optionalSecret("KURIER_API_KEY"),
    pubfiApiKey: optionalSecret("PUBFI_API_KEY"),
    agentId: optionalSecret("AGENT_GAMES_AGENT_ID"),
    port: Number(process.env.PORT ?? "3000") || 3000,
    gatekeeperVkHash: (process.env.GATEKEEPER_VK_HASH ??
      "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0").toLowerCase(),
    kurierApiUrl: (process.env.KURIER_API_URL ?? "https://api.kurier.xyz/api/v1").replace(/\/$/, ""),
    pubfiApiUrl: (process.env.PUBFI_API_URL ?? "https://api.pubfi.ai").replace(/\/$/, ""),
    wasmPath: join(root, "circuits", "gatekeeper.wasm"),
    zkeyPath: join(root, "circuits", "gatekeeper_final.zkey"),
    vkPath: join(root, "circuits", "vk.json"),
    dataDir: join(root, "data"),
  };
}
