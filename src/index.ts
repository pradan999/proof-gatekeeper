/**
 * index.ts — bootstrap. Loads config (fail fast on missing HMAC secret),
 * constructs the server (fail fast on missing circuit artifacts), listens.
 */
import { loadConfig } from "./config.js";
import { GatekeeperServer } from "./server.js";
import { log } from "./logger.js";

try {
  const config = loadConfig();
  const server = new GatekeeperServer(config);
  server.listen();
} catch (err) {
  log("error", "startup failed", { error: String(err).slice(0, 500) });
  process.exit(1);
}
