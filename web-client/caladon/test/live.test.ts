/**
 * LIVE integration test — drives the full confidential round-trip through the protocol SDK against
 * the real gateway (gw.caladon.ai), mirroring infra/cvm/gate1_client.py:
 *
 *   onboard (idempotent) → GET /v1/attestation?challenge=SHA256(eph_pub)
 *     → verify_quote_sync (collateral via the committed FMSPC fixture)  [FAIL-CLOSED]
 *     → POST /v1/session (sealed WMK)  → POST /v1/chat (sealed prompt → opened sealed deltas)
 *
 * It SELF-ONBOARDS a FRESH random seed: now that caladon-core exports `ed25519_public`, the SDK
 * builds the real proof-of-possession body (account_id + raw Ed25519 pub + KEM pub) signed by the
 * Authorization header, so a never-before-seen seed registers itself against the live gateway
 * (mirroring gate1_client.py onboard()). It talks DIRECTLY to the gateway (shimBase = `${GW}/v1`)
 * since the shim is a verbatim relay; a shim-fronted run is identical with shimBase = `/api/caladon`.
 *
 * The pinned measurement/compose/app_id are DISCOVERED from the live evidence at test time
 * (docs/security/measurements.md notes rtmr2/app_id/compose churn per redeploy; the crypto root of
 * trust — quote→Intel root, TCB UpToDate, challenge binding — is what the verdict truly asserts).
 *
 * Gated on CALADON_LIVE=1 (network + a possible multi-minute RedPill cold-start). Run:
 *   CALADON_LIVE=1 npm test     (or: npm run test:live)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { CaladonClient, tdxMeasurements, fromHex } from '../src/index.js';
import { randomBytes } from '../src/envelope.js';
import { wasmBytes, fixtureCollateral, pinnedSet } from './support.js';

const LIVE = process.env.CALADON_LIVE === '1';
const GW = process.env.CALADON_GATEWAY_BASE ?? 'https://gw.caladon.ai';
// A FRESH, never-before-seen random seed — exercises true self-onboarding (PoP) end to end.
const TEST_SEED = randomBytes(32);
const PROMPT = 'Reply with exactly: CALADON LIVE OK';

const d = LIVE ? describe : describe.skip;

d('live confidential round-trip (gw.caladon.ai)', () => {
  let discoveredPin: ReturnType<typeof pinnedSet>;

  beforeAll(async () => {
    // Phase 0: discover the CURRENT live measurement/compose/app_id (robust to redeploys).
    const disc = new CaladonClient({
      shimBase: `${GW}/v1`,
      wasmInput: await wasmBytes(),
      attestationPolicy: 'observe',
    });
    await disc.init();
    disc.unlockSeed(TEST_SEED);
    // Self-onboard the FRESH seed (PoP) before the signed attestation GET.
    const onboardStatus = await disc.onboard();
    expect([200, 201, 409]).toContain(onboardStatus);
    const ephPriv = (await import('../src/envelope.js')).randomBytes(32);
    const ephPub = (disc as unknown as { wasm: { x25519_public(b: Uint8Array): Uint8Array } }).wasm.x25519_public(ephPriv);
    const ev = await disc.getAttestation(ephPub);
    const quote = fromHex(ev.intel_quote ?? ev.quote!);
    const m = tdxMeasurements(quote);
    discoveredPin = {
      measurements: [m.aggregate],
      compose_hashes: [ev.info!.compose_hash!],
      workload_ids: [ev.info!.app_id!],
    };
    // sanity: the challenge we sent is bound into the quote's report_data.
    expect(m.reportDataChallenge).toBe(
      (disc as unknown as { wasm: { challenge_hex(b: Uint8Array): string } }).wasm.challenge_hex(ephPub),
    );
  }, 120_000);

  it('verifies attestation fail-closed and recovers a real sealed reply', async () => {
    const client = new CaladonClient({
      shimBase: `${GW}/v1`,
      wasmInput: await wasmBytes(),
      attestationPolicy: 'strict', // refuse to send unless the verdict is ok
      collateralProvider: () => fixtureCollateral(),
      pinned: discoveredPin,
    });

    const { handshake, chat } = await client.roundtrip(TEST_SEED, PROMPT);

    // --- attestation keystone ---
    expect(handshake.evidence.regime).toBe('tdx-onchain');
    expect(handshake.evidence.session_pub).toBeTruthy();
    expect(handshake.verdict).not.toBeNull();
    expect(handshake.verdict!.ok).toBe(true);
    expect(handshake.verdict!.reason).toBe('ok');
    expect(handshake.verdict!.measurement_matched).toBe(true);

    // --- sealed §6 session ---
    expect(handshake.sessionKey.length).toBe(32);

    // --- recovered attested-inference reply (opened under SK) ---
    expect(chat.reply.length).toBeGreaterThan(0);
    expect(chat.reply).toContain('CALADON LIVE OK');
    expect(chat.rawBytes).toBeGreaterThan(0);

    // eslint-disable-next-line no-console
    console.log(`\n  ── recovered attested-inference reply ──\n  ${chat.reply.trim().replace(/\n/g, '\n  ')}\n`);
  });

  it('fails closed when the pinned measurement does not match (no TOFU)', async () => {
    const badClient = new CaladonClient({
      shimBase: `${GW}/v1`,
      wasmInput: await wasmBytes(),
      attestationPolicy: 'strict',
      collateralProvider: () => fixtureCollateral(),
      // A pin that cannot match the live measurement → MEASUREMENT_UNPINNED, refuse to proceed.
      pinned: pinnedSet('deadbeef'.repeat(8), '0'.repeat(40)),
    });
    await expect(badClient.handshake(TEST_SEED)).rejects.toThrow(/attestation failed|MEASUREMENT_UNPINNED/);
  });
});
