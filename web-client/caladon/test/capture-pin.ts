import { CaladonClient, tdxMeasurements, fromHex } from '../src/index.js';
import { randomBytes } from '../src/envelope.js';
import { wasmBytes } from './support.js';
const GW = process.env.CALADON_GATEWAY_BASE ?? 'https://gw.caladon.ai';
async function main() {
  const c = new CaladonClient({ shimBase: `${GW}/v1`, wasmInput: await wasmBytes(), attestationPolicy: 'observe' });
  await c.init();
  c.unlockSeed(randomBytes(32));
  await c.onboard();
  const ephPriv = randomBytes(32);
  const ephPub = (c as any).wasm.x25519_public(ephPriv);
  const ev = await c.getAttestation(ephPub);
  const info = ev.info ?? {};
  if (info.compose_hash == null || info.app_id == null) throw new Error('evidence missing info.compose_hash/app_id');
  const m = tdxMeasurements(fromHex((ev.intel_quote ?? ev.quote) as string));
  console.log(JSON.stringify({ measurements: [m.aggregate], compose_hashes: [info.compose_hash], workload_ids: [info.app_id] }));
}
main().catch((e) => { console.error('CAPTURE-FAIL', e?.message || e); process.exit(1); });
