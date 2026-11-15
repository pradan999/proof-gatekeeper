// Downloads the gatekeeper circuit artifacts from the official Agent Games CDN
// when they are missing or fail their checksum. The wasm/zkey are binary, so
// they are NOT committed to the repo — Railway (or any deploy) fetches them
// on start via the `prestart` script. Idempotent; safe to run on every start.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ARTIFACTS = [
  {
    name: 'gatekeeper.wasm',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm',
    sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  },
  {
    name: 'gatekeeper_final.zkey',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey',
    sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
  },
];

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'circuits');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

for (const a of ARTIFACTS) {
  const path = join(dir, a.name);
  if (existsSync(path)) {
    const buf = await readFile(path);
    if (sha256(buf) === a.sha256) {
      console.log(`circuits: ${a.name} OK (cached)`);
      continue;
    }
    console.log(`circuits: ${a.name} checksum mismatch, re-downloading`);
  }
  console.log(`circuits: downloading ${a.name} ...`);
  const res = await fetch(a.url);
  if (!res.ok) throw new Error(`download failed: ${a.url} HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (sha256(buf) !== a.sha256) {
    throw new Error(`checksum mismatch after download: ${a.name}`);
  }
  mkdirSync(dir, { recursive: true });
  await writeFile(path, buf);
  console.log(`circuits: ${a.name} downloaded + verified`);
}
console.log('circuits: ready');
