# Proof Gatekeeper — zkVerify Agent Games

A production-ready HTTPS agent for the **Proof Gatekeeper** track of the
zkVerify Agent Games. It receives signed task envelopes, makes a
**deterministic** APPROVE/REJECT decision (no LLM anywhere in the decision
path), generates a local Groth16 proof with snarkjs, submits it to zkVerify
via Kurier, and returns a signed response — all inside the platform's 60s
deadline. Any timeout, error, or uncertainty resolves to REJECT (fail closed).

- Competition: 8 daily rounds, 13–21 Nov 2026, 16:00–02:00 IST (17:30–03:30 WIB), 8 tasks/round, cumulative.
- Scoring: +12 correct decision · −6 wrong approve · −3 wrong reject ·
  −2 timeout · −2 missing/invalid proof · reliability bonus +0–5.
- Round 3 is live now (15 Nov); rounds 4–8 run 16–20 Nov.

## What was verified while building this (2026-11-15)

- **All 13 circuit input signal names were recovered from the artifacts**
  (the platform does not publish them). See `circuits/INPUTS.md` for the
  full method, the hash-table extraction, and the per-check semantics
  experiments. The circuit asserts `decision == AND(all checks)`; a
  decision=1 proof with any failing check (and a decision=0 proof with all
  checks passing) fails witness generation — the circuit is a real referee.
- **Proof generation: ~0.4–0.5 s per proof** (first proof in a fresh process
  ~1.1 s, wasm load included). Measured locally, snarkjs 0.7.5, Node 24.
- **Harness: 20/20 checks pass** (`npm test`).
- **Kurier endpoints confirmed from docs.zkverify.io**: `POST
  /register-vk/{key}`, `POST /submit-proof/{key}`, `GET
  /job-status/{key}/{jobId}` at `https://api.kurier.xyz/api/v1`.

## File structure

```
package.json / tsconfig.json / railway.json
.env.example            # blank values only — copy to .env locally
.gitignore              # .env, node_modules, dist, data
circuits/
  gatekeeper.wasm       # 1,755,820 bytes, sha256 be00aefe…92764f
  gatekeeper_final.zkey # 309,750 bytes, sha256 adfe95a4…af80d
  vk.json               # exported verification key (groth16/bn128, nPublic=13)
  INPUTS.md             # how the 13 input signals were discovered + semantics
  # NOTE: the wasm/zkey are binary and NOT committed — `npm start` runs
  # scripts/fetch-circuits.mjs first, which downloads + verifies them
  # from https://agentgames.zkverify.io/circuits/ when missing.
src/
  config.ts   env loading, fail-fast on missing/placeholder HMAC secret
  hmac.ts     HMAC-SHA256 verify/sign (timing-safe)
  envelope.ts task/preflight parsing + validation (numbers or strings)
  decide.ts   deterministic engine + reason codes (first failure wins)
  seen.ts     persistent proof_tx seen-set (atomic writes, data/seen.json)
  prover.ts   snarkjs fullProve + local verify; input encodings (INPUT_MAP)
  kurier.ts   Kurier submit + poll to Finalized (short poll + background)
  zkverify.ts on-chain proof_tx confirmation (see below)
  server.ts   HTTP server: POST /agent, GET /health, 50s handler cap
  logger.ts   structured JSON logs (never secrets / full bodies)
  index.ts    bootstrap
test/
  harness.mjs           # replays fixtures against a live server + direct layer
  fixtures/             # preflight, valid, 6 traps, reused, stale
```

## Setup

```sh
npm install
cp .env.example .env   # then fill in the secrets (see below)
npm run build
npm start              # listens on $PORT (default 3000)
```

Test: `npm run build && npm test` (20 checks; uses a throwaway test secret,
no real keys, no network calls to Kurier/PubFi/Subscan — the gateway path
is tested with a mocked fetch).

## Environment variables

| variable | required | notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | **yes** | From the dashboard ("Rotate Secret"). Service refuses to start without a real value. |
| `KURIER_API_KEY` | yes, for scoring | Kurier mainnet key (https://kurier.xyz). Without it, proofs are generated locally but never submitted (no Finalized confirmation). |
| `PUBFI_API_KEY` | **yes, for approvals** | See "The proof_tx confirmation problem" — without it every valid task is rejected. |
| `AGENT_GAMES_AGENT_ID` | no | `agt_...`; if set, preflights with another id are rejected. |
| `PORT` | no | default 3000. |
| `GATEKEEPER_VK_HASH` | no | default is the canonical mainnet hash `0x6b79c6…`. |
| `KURIER_API_URL` | no | default `https://api.kurier.xyz/api/v1` (testnet: `https://api-testnet.kurier.xyz/api/v1`). |
| `PUBFI_API_URL` | no | default `https://api.pubfi.ai`. |

Secrets come from the environment only. Never hardcode or commit them;
`.env` is gitignored. Nothing secret is ever logged (only truncated
non-sensitive prefixes, e.g. first 10 chars of a tx hash).

## How it works

### Request flow (`POST /agent`)

1. Read the raw body (1 MB cap). Verify `x-agent-games-signature`
   (HMAC-SHA256 over the raw bytes) **before parsing JSON** → 401 on mismatch.
2. Parse the envelope. Malformed → signed `REJECT / INVALID_TASK`.
3. Preflight (`agent-games.preflight.v1`) → signed
   `{"ok":true,"protocolVersion":"v1"}`.
4. Task: deterministic checks in order (first failure wins):
   `INVALID_TIMESTAMP` → `VK_SUBSTITUTION` → `THRESHOLD_MISMATCH` →
   `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` → `EXPIRED_CONDITION` →
   `PROOF_REUSED` → `PROOF_NOT_FOUND` → `VALID_CONDITION`.
5. On-chain `proof_tx` confirmation (step 8) — fail closed; see below.
6. APPROVE: generate the decision=1 Groth16 proof locally (~0.5 s),
   submit to Kurier, poll with a short budget from the remaining handler
   time (max ~10 s), respond with the local proof + `public_signals` (+
   `proofReference` = Kurier job id). Polling continues in the background
   until Finalized (5 min cap); the task is only "confirmed" then.
7. `proof_tx` is recorded in the seen-set **only after** the APPROVE
   response is sent (atomic write to `data/seen.json`).
8. Whole handler is capped at **50 s** (platform deadline is 60 s). On cap
   expiry the handler responds `REJECT / PROOF_GENERATION_FAILED` instead
   of timing out. Kurier slowness can never cause a timeout.

### Which responses carry a proof?

The circuit can only attest decisions that follow from its own checks, so:

| response | proof attached? |
|---|---|
| APPROVE (`VALID_CONDITION`) | yes — decision=1 proof |
| REJECT for an in-circuit trap (`VK_SUBSTITUTION` where the two vk hashes differ, `THRESHOLD_MISMATCH`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, `EXPIRED_CONDITION`) | yes — decision=0 proof (locally verified) |
| REJECT `VK_SUBSTITUTION` where `proof_vk == registered_vk != canonical` | **no** — in-circuit all checks pass, so a decision=0 proof cannot exist. Reason code is preserved; only the proof is missing. |
| REJECT `INVALID_TIMESTAMP`, `PROOF_NOT_FOUND`, `PROOF_REUSED` | no — out-of-circuit reasons (or the trap definition). |
| `PROOF_GENERATION_FAILED` | no. |

Every generated proof is re-verified locally against `circuits/vk.json`
before it is returned.

### Decision inputs to the circuit

`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
taskId, salt` — see `circuits/INPUTS.md`. Encodings: vk hashes and
addresses as BigInts reduced mod the BN128 field; `taskId` as
`keccak256(task_id)` reduced mod p (**assumption** — the platform's
canonical string→field encoding is unpublished; it is one line in
`src/prover.ts` if a practice task shows otherwise); `salt` is a fresh
random 128-bit private input per proof.

## The proof_tx confirmation problem — READ THIS BEFORE ROUND 4

Step 8 of the decision requires confirming the platform's `proof_tx` is
finalized on zkVerify. As of 2026-11-15 there is **no free, keyless public
read API** for this:

- Kurier's `job-status` only covers jobs submitted through Kurier itself
  (`proof_tx` is a chain tx hash, not a Kurier job id — except the
  UUID-shaped case, which this service does check via Kurier).
- Subscan runs the zkVerify explorer and its direct API
  (`POST https://zkverify.api.subscan.io/api/scan/extrinsic`,
  `{"hash": "0x..."}`) returns the extrinsic + block + success flag — but
  it now returns **HTTP 403 "Subscan API strictly requires an API key"**
  for unauthenticated calls (verified live 2026-11-15), and Subscan **no
  longer issues free direct API keys** (docs updated 2026-10-20; direct
  keys are paid-only, Developer $182/yr+).
- No public Volta RPC URL is published in the Agent Games docs.

The official free route is the **PubFi Gateway** (Subscan tutorial,
https://support.subscan.io/doc-360177): create a PubFi account, create a
PubFi API key, and call an eligible Subscan route through the gateway.
PubFi and direct Subscan credentials are **not** interchangeable. The
route this service uses was verified against the live PubFi Runtime
OpenAPI (generation 301, 2026-11-15):

- `POST https://api.pubfi.ai/v1/gateway/subscan/zkverify/api/scan/extrinsic`
  (+ `:free` suffix for the free variant), `Authorization: Bearer
  <PUBFI_API_KEY>`, body `{"hash": "0x..."}`. Free variant: 2 req/s, max
  concurrency 2, quota 20,000/day, consumes no Credits. Billed variant: 1
  Credit per call — used only as a one-shot fallback if the free variant
  answers 402/429 (the account holds 1,000 pre-granted Credits; no
  purchase is involved).

This service therefore confirms `proof_tx` via the PubFi Gateway **only
when `PUBFI_API_KEY` is set**, and otherwise returns "unconfirmed" — which
makes the engine **REJECT every otherwise-valid task with
`PROOF_NOT_FOUND`**. That is deliberate and fail-closed: an unverified
proof_tx must never be approved (−6 for a wrong approve beats −3 for a
wrong reject, and an unconfirmed approve is exactly the trap this track
punishes).

**Action required:** create a PubFi API key (sign up at
https://pubfi.ai, Dashboard → API keys; the complete secret is shown
only once — store it in a secret manager immediately) and set
`PUBFI_API_KEY`. Until then, approvals cannot happen. Do not weaken this
check without an explicit decision — the alternative (approve on an
unverified `proof_tx`) is how this track is lost.

**One unverified assumption:** the gateway relays the upstream Subscan
body opaquely, so the parser expects the direct-Subscan shape
(`{code: 0, data: {extrinsic: {block_num, success}}}`). If the first live
task shows a different shape, the lookup fails closed (PROOF_NOT_FOUND)
and the parser is a one-line fix in `src/zkverify.ts`
(`parseExtrinsicResponse`).

## Deploy to Railway

1. Push this directory to a GitHub repo (no secrets — `.env` is gitignored;
   `data/` is gitignored too).
2. In Railway: New Project → Deploy from GitHub repo → the `railway.json`
   here selects the Node provider; Nixpacks runs `npm run build` then
   `npm start`. Set `PORT` from Railway's `$PORT` (it is injected
   automatically; the service reads `process.env.PORT`).
3. In the service Variables tab, set `AGENT_GAMES_HMAC_SECRET`,
   `KURIER_API_KEY`, `PUBFI_API_KEY` (no other secrets needed).
4. Generate a public domain; `GET /health` must return `{"ok":true,...}`.
   The endpoint to register is `https://<your-domain>/agent` (HTTPS only).

## Dashboard registration (manual steps)

1. In the Agent Games dashboard, register the endpoint
   `https://<your-domain>/agent` for the Proof Gatekeeper event.
2. **Rotate Secret** in the dashboard; copy the value into
   `AGENT_GAMES_HMAC_SECRET` (Railway variables, then redeploy).
3. The platform sends a signed preflight; the service answers
   `{"ok":true,"protocolVersion":"v1"}` signed. Preflight must pass before
   the agent is marked active.
4. Run at least one **practice task** (unscored) from the dashboard and
   confirm: decision + reason_code are right, the proof verifies, and the
   Kurier job reaches Finalized. If the platform rejects the proof, check
   first the `taskId` encoding (`src/prover.ts`, `Prover.encodeTaskId`) and
   second the Kurier `curve`/`vk` fields — those are the two unpublished
   assumptions in this build.
5. One agent per owner in this event; entries lock while a round is open.

## Monitoring

- Logs are structured JSON on stdout (Railway captures them). Each task
  logs `task_id`, `decision`, `reason_code`, `prove_ms`, and the Kurier
  job id when present. No secrets, HMAC values, or full bodies are logged.
- `GET /health` reports `seen_entries`, `kurier_enabled`,
  `pubfi_configured`, and `in_flight`.
- Watch for: `PROOF_NOT_FOUND` on every valid task (= missing PubFi
  key), Kurier `Failed` jobs (= check `curve`/`vk` fields), and any
  `PROOF_GENERATION_FAILED` (= check the circuit artifacts are intact).

## Known limitations / assumptions

- `taskId` encoding is `keccak256(task_id) mod p` — unpublished by the
  platform; validate on the first practice task (one-line change).
- Response signature encoding is lowercase hex HMAC-SHA256 (the platform's
  documented header is `x-agent-games-signature`; hex is the standard
  encoding — validate on preflight).
- The `public_signals[0]` commitment's exact Poseidon preimage was not
  reproduced (three orderings tried). It does not need to be: the Groth16
  proof guarantees its consistency and the platform re-verifies the proof.
- `snarkjs` leaves the Node process alive after use in one-shot scripts
  (a lingering handle); the harness calls `process.exit(0)` explicitly.
  The long-running server is unaffected.
- Expected stderr noise: a failed decision=0 prove attempt (the
  canonical-VK-substitution case) prints `Error in template
  GatekeeperEvaluation_79 line: 102` from the wasm — that is the circuit
  correctly refusing an unattestable decision, not a crash.
