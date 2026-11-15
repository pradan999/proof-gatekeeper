/**
 * harness.mjs — local test harness for the Proof Gatekeeper agent.
 *
 * Usage: npm run build && npm test
 *
 * Spawns the compiled server on a test port with a test HMAC secret, replays
 * the fixtures in test/fixtures/, and prints PASS/FAIL per case. Also runs a
 * direct-layer test of the APPROVE path (decide + Prover), which the HTTP
 * layer cannot reach without a PubFi API key (fail-closed PROOF_NOT_FOUND),
 * plus mocked PubFi Gateway tests for confirmProofTx (no real key, no
 * network calls to PubFi/Subscan/Kurier).
 *
 * The harness never touches production secrets: test secret only, no Kurier
 * key, no Subscan key. It seeds data/seen.json with the reused proof_tx
 * before starting the server (restored afterwards).
 */
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 3101;
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = "test-harness-secret-do-not-use-in-prod";
const REUSED_TX = "0xa8000000000000000000000000000000000000000000000000000000000000aa";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

function hmacHex(secret, body) {
  return createHmac("sha256", secret).update(body).digest("hex");
}

async function postAgent(rawBody, secret = TEST_SECRET) {
  const t0 = Date.now();
  const res = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-agent-games-signature": hmacHex(secret, rawBody) },
    body: rawBody,
  });
  const rawRes = Buffer.from(await res.arrayBuffer());
  const ms = Date.now() - t0;
  return { status: res.status, rawRes, ms, sig: res.headers.get("x-agent-games-signature") };
}

function verifyResponseSig(rawRes, sig) {
  return sig !== null && hmacHex(TEST_SECRET, rawRes) === sig.toLowerCase();
}

function buildTaskEnvelope(fixture, stale = false) {
  const now = Date.now();
  const issued = new Date(now - (stale ? 3600_000 : 30_000)).toISOString();
  const deadline = new Date(now + (stale ? -3500_000 : 120_000)).toISOString();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: fixture.task_id,
    mode: "competition",
    issued_at: issued,
    deadline_at: deadline,
    input: fixture.input,
  };
}

async function waitHealth(timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function main() {
  if (!fs.existsSync(path.join(ROOT, "dist", "index.js"))) {
    console.error("dist/index.js missing — run `npm run build` first.");
    process.exit(2);
  }

  // Seed the seen-set with the reused proof_tx (restore afterwards).
  const dataDir = path.join(ROOT, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const seenPath = path.join(dataDir, "seen.json");
  const seenBackup = fs.existsSync(seenPath) ? fs.readFileSync(seenPath, "utf8") : null;
  fs.writeFileSync(
    seenPath,
    JSON.stringify({ [REUSED_TX]: { task_id: "gk_seed_reused", decided_at: new Date().toISOString(), kurier_job_id: null, kurier_status: null } }, null, 2),
  );

  const env = {
    ...process.env,
    AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
    KURIER_API_KEY: "",
    PUBFI_API_KEY: "",
    PORT: String(PORT),
    LOG_LEVEL: "error",
  };
  const server = spawn("node", [path.join(ROOT, "dist", "index.js")], { env, stdio: ["ignore", "pipe", "pipe"] });
  server.stdout.on("data", () => {});
  server.stderr.on("data", (d) => process.stderr.write(d));
  let exitCode = 0;

  try {
    if (!(await waitHealth())) {
      check("server starts + /health responds", false, "no health response in 15s");
      throw new Error("server did not start");
    }
    check("server starts + /health responds", true);

    // --- preflight ---
    const pre = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "fixtures", "preflight.json"), "utf8"));
    const preRaw = Buffer.from(JSON.stringify({ type: pre.type, agent_id: pre.agent_id, issued_at: new Date().toISOString(), nonce: pre.nonce }));
    const preRes = await postAgent(preRaw);
    const preJson = JSON.parse(preRes.rawRes.toString("utf8"));
    check(
      "preflight -> {ok:true, protocolVersion:v1} + valid response signature",
      preRes.status === 200 && preJson.ok === true && preJson.protocolVersion === "v1" && verifyResponseSig(preRes.rawRes, preRes.sig),
      `status=${preRes.status} body=${preRes.rawRes.toString("utf8").slice(0, 120)}`,
    );

    // --- bad HMAC ---
    const validFixture = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "fixtures", "valid.json"), "utf8"));
    const badHmac = await postAgent(Buffer.from(JSON.stringify(buildTaskEnvelope(validFixture))), "wrong-secret");
    check("bad HMAC -> 401, no processing", badHmac.status === 401, `status=${badHmac.status}`);

    // --- malformed JSON (signed) ---
    const malformed = await postAgent(Buffer.from("{not json"));
    const malJson = JSON.parse(malformed.rawRes.toString("utf8"));
    check(
      "malformed JSON -> signed REJECT INVALID_TASK",
      malformed.status === 200 && malJson.decision === "REJECT" && malJson.reason_code === "INVALID_TASK" && verifyResponseSig(malformed.rawRes, malformed.sig),
      `status=${malformed.status} body=${malformed.rawRes.toString("utf8").slice(0, 120)}`,
    );

    // --- fixture replays (HTTP layer) ---
    const vk = JSON.parse(fs.readFileSync(path.join(ROOT, "circuits", "vk.json"), "utf8"));
    const fixtureFiles = ["valid", "vk_substitution", "vk_substitution_canonical", "threshold", "recipient", "amount", "expired", "reused", "stale"];
    for (const name of fixtureFiles) {
      const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, "test", "fixtures", `${name}.json`), "utf8"));
      const env2 = buildTaskEnvelope(fixture, fixture.stale_timestamps === true);
      const r = await postAgent(Buffer.from(JSON.stringify(env2)));
      let body;
      try {
        body = JSON.parse(r.rawRes.toString("utf8"));
      } catch {
        check(`fixture ${name}`, false, `unparseable response: ${r.rawRes.toString("utf8").slice(0, 120)}`);
        continue;
      }
      const exp = fixture.expected;
      let ok = r.status === 200 && body.decision === exp.decision && body.reason_code === exp.reason_code && verifyResponseSig(r.rawRes, r.sig);
      let detail = `${body.decision}/${body.reason_code} in ${r.ms}ms`;
      if (exp.proof_expected) {
        const hasProof = body.proof !== undefined && Array.isArray(body.public_signals) && body.public_signals.length === 13;
        let proofOk = false;
        if (hasProof) {
          proofOk = await snarkjs.groth16.verify(vk, body.public_signals, body.proof);
          detail += `, proof verifies locally=${proofOk}, decision_signal=${body.public_signals[11]}`;
          if (body.public_signals[11] !== "0") proofOk = false;
        }
        ok = ok && hasProof && proofOk;
      } else {
        ok = ok && body.proof === undefined && body.public_signals === undefined;
        detail += ", no proof attached (as expected)";
      }
      check(`fixture ${name} -> ${exp.decision}/${exp.reason_code}`, ok, detail);
    }

    // --- direct layer: APPROVE path (decide + Prover) ---
    const { decide } = await import(path.join(ROOT, "dist", "decide.js"));
    const { Prover } = await import(path.join(ROOT, "dist", "prover.js"));
    const { parseEnvelope } = await import(path.join(ROOT, "dist", "envelope.js"));
    const task = parseEnvelope(Buffer.from(JSON.stringify(buildTaskEnvelope(validFixture))));
    const d = decide(task, {
      canonicalVkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proofTxSeen: false,
      proofTxConfirmed: true,
      now: new Date(),
    });
    check("direct decide() valid task -> APPROVE/VALID_CONDITION", d.decision === "APPROVE" && d.reason_code === "VALID_CONDITION", JSON.stringify(d));

    const prover = new Prover(
      path.join(ROOT, "circuits", "gatekeeper.wasm"),
      path.join(ROOT, "circuits", "gatekeeper_final.zkey"),
      path.join(ROOT, "circuits", "vk.json"),
    );
    const t0 = Date.now();
    const generated = await prover.prove(task, 1);
    const proveMs = Date.now() - t0;
    const localOk = await snarkjs.groth16.verify(vk, generated.publicSignals, generated.proof);
    check(
      "direct prover: decision=1 proof verifies locally",
      localOk && generated.publicSignals.length === 13 && generated.publicSignals[11] === "1",
      `proveMs=${generated.proveMs} (wall ${proveMs}ms), public_signals=${generated.publicSignals.length}`,
    );
    const enc1 = Prover.encodeTaskId("gk_24_9d1");
    const enc2 = Prover.encodeTaskId("gk_24_9d1");
    check("taskId encoding is deterministic (keccak256 mod p)", enc1 === enc2, `encoded=${enc1.slice(0, 24)}...`);

    // --- direct layer: PubFi Gateway confirmProofTx (mocked fetch, no real key) ---
    const { confirmProofTx } = await import(path.join(ROOT, "dist", "zkverify.js"));
    const TX = "0x" + "ab".repeat(32);
    const baseDeps = {
      kurierApiUrl: "https://api.kurier.xyz/api/v1",
      kurierApiKey: null,
      pubfiApiKey: "test-pubfi-key",
      pubfiApiUrl: "https://api.pubfi.ai",
    };
    const okBody = { code: 0, data: { extrinsic: { block_num: 1234567, success: true } } };
    // (a) free variant success — exact URL + Bearer auth asserted.
    {
      const seen = [];
      const mockFetch = async (url, init) => {
        seen.push({ url, auth: init.headers.Authorization, body: JSON.parse(init.body) });
        return new Response(JSON.stringify(okBody), { status: 200, headers: { "Content-Type": "application/json" } });
      };
      const r = await confirmProofTx(TX, { ...baseDeps, pubfiFetch: mockFetch });
      check(
        "pubfi gateway: free variant confirms a successful extrinsic",
        r.confirmed === true && r.source === "pubfi" && r.blockNumber === 1234567 &&
          seen.length === 1 &&
          seen[0].url === "https://api.pubfi.ai/v1/gateway/subscan/zkverify/api/scan/extrinsic:free" &&
          seen[0].auth === "Bearer test-pubfi-key" && seen[0].body.hash === TX,
        `confirmed=${r.confirmed} source=${r.source} block=${r.blockNumber} calls=${seen.length}`,
      );
    }
    // (b) free variant 402 -> one billed fallback, same Bearer auth.
    {
      const seen = [];
      const mockFetch = async (url) => {
        seen.push(url);
        if (url.endsWith(":free")) return new Response(JSON.stringify({ message: "free variant unavailable" }), { status: 402 });
        return new Response(JSON.stringify(okBody), { status: 200, headers: { "Content-Type": "application/json" } });
      };
      const r = await confirmProofTx(TX, { ...baseDeps, pubfiFetch: mockFetch });
      check(
        "pubfi gateway: 402 on free variant falls back once to billed variant",
        r.confirmed === true && r.source === "pubfi" && seen.length === 2 &&
          seen[1] === "https://api.pubfi.ai/v1/gateway/subscan/zkverify/api/scan/extrinsic",
        `confirmed=${r.confirmed} calls=${seen.length}`,
      );
    }
    // (c) extrinsic not found -> unconfirmed (fail closed).
    {
      const mockFetch = async () =>
        new Response(JSON.stringify({ code: 0, data: null }), { status: 200, headers: { "Content-Type": "application/json" } });
      const r = await confirmProofTx(TX, { ...baseDeps, pubfiFetch: mockFetch });
      check("pubfi gateway: missing extrinsic -> unconfirmed", r.confirmed === false && r.source === "pubfi", `detail=${r.detail}`);
    }
    // (d) no key -> source "none" (fail closed).
    {
      const r = await confirmProofTx(TX, { ...baseDeps, pubfiApiKey: null });
      check("pubfi gateway: no key -> unconfirmed, source none", r.confirmed === false && r.source === "none", `detail=${r.detail}`);
    }
  } catch (err) {
    console.error("harness error:", err);
    exitCode = 1;
  } finally {
    server.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    if (seenBackup !== null) fs.writeFileSync(seenPath, seenBackup);
    else if (fs.existsSync(seenPath)) fs.unlinkSync(seenPath);
  }

  const passed = results.filter((r) => r.ok).length;
  console.log(`\n${passed}/${results.length} checks passed.`);
  if (passed !== results.length) exitCode = 1;
  process.exit(exitCode);
}

main();
