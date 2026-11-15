# Gatekeeper circuit — input signals (DISCOVERED, not published)

**Status: RESOLVED.** The platform does not publish the gatekeeper circuit's
input signal names anywhere on /build, /events/proof-gatekeeper, or
/api/circuit-info. They were recovered from the artifacts themselves on
2026-11-15 and verified end-to-end (see "Verification" below).

## Artifacts

| file | bytes | sha256 |
|---|---|---|
| `gatekeeper.wasm` | 1,755,820 | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | 309,750 | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `vk.json` (exported) | — | protocol groth16, curve bn128, **nPublic = 13** |

Source: https://agentgames.zkverify.io/circuits/gatekeeper.wasm and
.../gatekeeper_final.zkey (downloaded 2026-11-15). Registered vkHash on
zkVerify mainnet (from /api/circuit-info):
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

## How the names were found

Circom 2.x witness-calculator wasm files map signal names to positions by
FNV-1a-64 hash. `getInputSignalSize(hMSB, hLSB)` returns the signal size
(>= 1) iff the name exists, 0 otherwise. Method:

1. `strings` on the wasm found no names (they are not stored as text).
2. `wasm2wat` showed the map is a 256-slot open-addressing hash table at
   memory offset 2032 (16 bytes/entry: i64 hash, i32 signal offset, i32 size).
3. Reading that table live from the instantiated wasm gave exactly **13
   entries** (offsets 2–14, all scalar size 1).
4. Brute-forcing candidate names against the table (FNV-1a-64) matched 11
   immediately; the last two fell to a combinatorial sweep
   (`registeredVkHash`, `proofVkHash`).

## The 13 inputs (declaration order = signal offset)

| # | signal | offset | meaning |
|---|---|---|---|
| 1 | `registeredVkHash` | 2 | vk hash registered for the condition (32-byte hash as a field element, mod p) |
| 2 | `proofVkHash` | 3 | vk hash the proof was verified against |
| 3 | `minimum` | 4 | required minimum balance |
| 4 | `publicBalance` | 5 | balance disclosed in the proof |
| 5 | `expiryBlock` | 6 | condition expiry block height |
| 6 | `currentBlock` | 7 | current block height |
| 7 | `recipient` | 8 | payment recipient (20-byte address as a field element) |
| 8 | `conditionRecipient` | 9 | recipient on the payment condition |
| 9 | `amount` | 10 | requested transfer amount |
| 10 | `maxTransfer` | 11 | single-transfer cap |
| 11 | `decision` | 12 | 1 = approve, 0 = reject |
| 12 | `taskId` | 13 | task identifier, as a field element (see encoding note) |
| 13 | `salt` | 14 | **private input** — fresh random value per proof |

## Public signals (13, as returned by snarkjs)

- `[0]` — commitment over the inputs (Poseidon-style; exact preimage
  construction not reproduced — the proof itself guarantees consistency,
  and the platform re-verifies the Groth16 proof, so reproducing it is not
  required. Three orderings tried and rejected: 13 inputs in order, 12
  public inputs, salt-first + 12.)
- `[1]` — `registeredVkHash` (reduced mod p)
- `[2]` — `proofVkHash` (reduced mod p)
- `[3..10]` — minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer
- `[11]` — decision
- `[12]` — taskId

`salt` never appears in the public signals: it is the only private input.

## Verified circuit semantics (all by experiment, 2026-11-15)

The circuit asserts `decision == AND(all checks)` in template
`GatekeeperEvaluation_79`, line 102. Each row was tested with
`snarkjs.groth16.fullProve`:

| case | result |
|---|---|
| all checks pass, decision=1 | proof OK, local `groth16.verify` true |
| all checks pass, decision=0 | FAIL (assert line 102) |
| balance < minimum, decision=1 | FAIL (assert line 102) |
| balance < minimum, decision=0 | proof OK, public_signals[11] = 0 |
| vk hashes differ, decision=1 | FAIL (assert line 102) |
| vk hashes differ, decision=0 | proof OK |
| recipient mismatch, decision=1 | FAIL; decision=0 OK |
| amount > maxTransfer, decision=1 | FAIL |
| currentBlock >= expiryBlock, decision=1 | FAIL; decision=0 OK |
| same inputs, different salt | proof OK (fresh commitment) |

Proof generation: **~0.4–1.0 s per proof** on this VM (measured across
~15 runs; snarkjs 0.7.5, Node 24).

## Encoding notes (assumptions, not platform-published)

- **vk hashes**: the full 32-byte hash as a BigInt reduced mod the BN128
  scalar field p. A 256-bit value cannot fit in one field element
  unreduced; mod-p reduction is the only sane encoding, and the platform
  must do the same when checking public_signals[1..2].
- **addresses**: 20-byte value as a BigInt (fits in the field).
- **taskId**: `keccak256(task_id)` as a BigInt reduced mod p. The task id
  is a string like `gk_24_9d1`; the platform's canonical string->field
  encoding is NOT published. keccak256 is the Ethereum-standard choice.
  If a practice task shows the platform expects a different encoding, it
  is a one-line change in `src/prover.ts` (`Prover.encodeTaskId`).
- **salt**: fresh `crypto.randomBytes(16)` per proof. The platform cannot
  check it (private); it binds the proof to this attempt.

## Reproducing the discovery

```sh
# 1. export the verification key (nPublic = 13)
npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/vk.json
# 2. probe candidate names against the wasm hash table (see git history /
#    the probe scripts used during discovery — the table is at memory
#    offset 2032, 256 slots x 16 bytes, index = hash & 0xFF)
# 3. fullProve with the 13 names above, then groth16.verify against vk.json
```
