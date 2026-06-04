/**
 * Offline unit tests — no network. Validate the byte/base64/hex helpers, the envelope wire
 * (de)serialization, the WASM crypto primitives (argon2id → account_id, seal/open round-trip,
 * x25519/session-key, attestation verdict against the committed live quote + fixture collateral).
 *
 * These pin the SDK's interop bytes WITHOUT reaching the gateway, so `npm test` is green in CI;
 * the live gateway round-trip is the separate CALADON_LIVE=1 suite (live.test.ts).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  loadCaladonWasm,
  type CaladonWasm,
  CaladonClient,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  utf8,
  fromUtf8,
  toWireEnvelope,
  fromWireEnvelope,
  tdxMeasurements,
  deriveWrappingKey,
  wrapSeed,
  unwrapSeed,
} from '../src/index.js';
import { wasmBytes, fixtureCollateral } from './support.js';

const here = dirname(fileURLToPath(import.meta.url));

let wasm: CaladonWasm;
beforeAll(async () => {
  wasm = await loadCaladonWasm(await wasmBytes());
});

describe('bytes helpers', () => {
  it('base64 round-trips', () => {
    const b = new Uint8Array([0, 1, 2, 250, 251, 255]);
    expect(fromBase64(toBase64(b))).toEqual(b);
  });
  it('hex round-trips (incl 0x prefix)', () => {
    const b = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(toHex(b)).toBe('deadbeef');
    expect(fromHex('0xdeadbeef')).toEqual(b);
  });
  it('utf8 round-trips', () => {
    expect(fromUtf8(utf8('héllo ✨'))).toBe('héllo ✨');
  });
});

describe('WASM identity', () => {
  it('argon2id (reference params) → the gate1 key-bound account_id', () => {
    // Same seed + reference params as gate1_client.py; account_id must be deterministic.
    const seed = new Uint8Array(32).fill(0x07);
    const root = wasm.argon2id(seed, utf8('swifty/v1'), 3, 64 * 1024 * 1024);
    expect(root.length).toBe(32);
    const acct = wasm.account_id(root);
    // The live gateway recognises this account (driven by the same seed) — stable value.
    expect(acct).toBe('62ln5YjoYx1ktrIQIxksS8kjpSZxGEhp6jAqPkPAcVQ');
  });

  it('authorization_header is a Swifty header signed over the canonical path', () => {
    const seed = new Uint8Array(32).fill(0x07);
    const root = wasm.argon2id(seed, utf8('swifty/v1'), 3, 64 * 1024 * 1024);
    const acct = wasm.account_id(root);
    const hdr = wasm.authorization_header(root, acct, 1_780_000_000n, 'GET', '/v1/whoami');
    expect(hdr).toMatch(/^Swifty acct=.+ ts=1780000000 sig=.+/);
    expect(hdr).toContain(`acct=${acct}`);
  });
});

describe('sealed channel (self round-trip under a derived SK)', () => {
  it('derive_session_key + seal_chat/open_chat round-trips the plaintext', () => {
    // Two parties: derive the SAME SK (client + "cvm") and confirm seal/open interoperate.
    const aPriv = new Uint8Array(32).fill(0x11);
    const bPriv = new Uint8Array(32).fill(0x22);
    const aPub = wasm.x25519_public(aPriv);
    const bPub = wasm.x25519_public(bPriv);
    const skA = wasm.derive_session_key(aPriv, bPub, aPub, bPub);
    const skB = wasm.derive_session_key(bPriv, aPub, aPub, bPub);
    expect(toHex(skA)).toBe(toHex(skB));

    const acct = 'acct-test';
    const sealed = wasm.seal_chat(skA, utf8('the quick brown fox'), acct, 1n);
    const opened = wasm.open_chat(skB, sealed, acct, 1n);
    expect(fromUtf8(opened)).toBe('the quick brown fox');
  });

  it('wire envelope round-trips through toWireEnvelope/fromWireEnvelope', async () => {
    const sk = new Uint8Array(32).fill(0x33);
    const acct = 'acct-test';
    const sealed = wasm.seal_chat(sk, utf8('hello wire'), acct, 1n);
    const env = await toWireEnvelope(sealed, acct, 'chat', 1, 'chat');
    expect(env.alg).toBe('xchacha20poly1305');
    expect(env.v).toBe(1);
    const back = fromWireEnvelope(env);
    expect(fromUtf8(wasm.open_chat(sk, back, acct, 1n))).toBe('hello wire');
  });

  it('open_chat fails closed on a tampered ciphertext', () => {
    const sk = new Uint8Array(32).fill(0x44);
    const acct = 'acct-test';
    const sealed = wasm.seal_chat(sk, utf8('secret'), acct, 1n);
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 0x01; // flip a tag byte
    expect(() => wasm.open_chat(sk, sealed, acct, 1n)).toThrow();
  });
});

describe('attestation verify (offline, committed live quote + fixture collateral)', () => {
  const QUOTE_HEX_PATH = resolve(here, 'intel_quote.hex');
  // The fixture collateral validity window is 2026-06-03 .. 2026-07-03; pin `now` inside it.
  const NOW_SECS = 1_780_533_902n;
  const CHALLENGE_HEX = 'a49d15e53c99ece49b4bbd54e4b92ba9eec3449a01ba148ab9683ac6b42dce24';
  const APP_ID = '64111f5c9442480b82b865f30e4085035a5e790b';
  const COMPOSE_HASH = 'd95a0706c94055db38c3d26de7933f2c66a3b8c0da0a2b73bd3f85a0c1b0c90c';
  // KEYSTONE binding: the quote now also binds report_data[32:64] == SHA-256(cvm_session_pub).
  // SESSION_PUB is the raw 32-byte gateway X25519 session pub whose SHA-256 the committed
  // intel_quote.hex carries in report_data[32:64]. It MUST be recaptured together with the quote
  // (the verify phase recaptures both from the live gateway built with the new GetQuote binding —
  // see capture-pin.ts). The committed quote predates the binding ([32:64] is currently zeroed), so
  // until the fixture is regenerated SESSION_PUB stays a placeholder and these vectors expect a
  // BINDING_MISMATCH on the session half rather than ok=true.
  const SESSION_PUB = new Uint8Array(32);

  let quote: Uint8Array;
  let collateralJson: string;
  beforeAll(async () => {
    quote = fromHex((await readFile(QUOTE_HEX_PATH, 'utf8')).trim());
    collateralJson = JSON.stringify(await fixtureCollateral());
  });

  it('the committed live quote parses to the documented measurement prefix', () => {
    const m = tdxMeasurements(quote);
    expect(m.mrTd).toBe('f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077');
    expect(m.rtmr0).toBe('68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96');
    expect(m.reportDataChallenge).toBe(CHALLENGE_HEX);
    expect(m.aggregate.length).toBe(4 * 48 * 2);
  });

  it('verify_quote_sync returns ok=true for the matching pin (the keystone, offline)', () => {
    const m = tdxMeasurements(quote);
    const pinned = JSON.stringify({
      measurements: [m.aggregate],
      compose_hashes: [COMPOSE_HASH],
      workload_ids: [APP_ID],
    });
    const v = wasm.verify_quote_sync(quote, collateralJson, JSON.stringify({ compose_hash: COMPOSE_HASH, app_id: APP_ID }), NOW_SECS, CHALLENGE_HEX, SESSION_PUB, pinned) as {
      ok: boolean;
      reason: string;
      measurement_matched: boolean;
    };
    expect(v).toEqual({ ok: true, reason: 'ok', measurement_matched: true });
  });

  it('fails closed (BINDING_MISMATCH) when the challenge does not match report_data', () => {
    const m = tdxMeasurements(quote);
    const pinned = JSON.stringify({ measurements: [m.aggregate], compose_hashes: [COMPOSE_HASH], workload_ids: [APP_ID] });
    const wrongChallenge = 'b'.repeat(64);
    const v = wasm.verify_quote_sync(quote, collateralJson, JSON.stringify({ compose_hash: COMPOSE_HASH, app_id: APP_ID }), NOW_SECS, wrongChallenge, SESSION_PUB, pinned) as { ok: boolean; reason: string };
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('BINDING_MISMATCH');
  });

  it('fails closed (MEASUREMENT_UNPINNED) for an unpinned measurement', () => {
    const pinned = JSON.stringify({ measurements: ['00'.repeat(192)], compose_hashes: [COMPOSE_HASH], workload_ids: [APP_ID] });
    const v = wasm.verify_quote_sync(quote, collateralJson, JSON.stringify({ compose_hash: COMPOSE_HASH, app_id: APP_ID }), NOW_SECS, CHALLENGE_HEX, SESSION_PUB, pinned) as { ok: boolean; reason: string };
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('MEASUREMENT_UNPINNED');
  });
});

describe('passkey-PRF seed custody (wrap/unwrap + wrapping key, offline)', () => {
  // The wrapping key is a deterministic HKDF(prf32); the AEAD nonce is random, so the wrapped blob
  // differs per call but always unwraps to the original seed under the same PRF.
  const PRF = new Uint8Array(32).fill(0x5a);
  const SEED = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);

  it('deriveWrappingKey is deterministic in prf32 and 32 bytes', () => {
    const k1 = deriveWrappingKey(wasm, PRF);
    const k2 = deriveWrappingKey(wasm, PRF);
    expect(k1.length).toBe(32);
    expect(toHex(k1)).toBe(toHex(k2));
    // A different PRF yields a different key.
    const kOther = deriveWrappingKey(wasm, new Uint8Array(32).fill(0x01));
    expect(toHex(kOther)).not.toBe(toHex(k1));
  });

  it('wrap/unwrap round-trips the 32-byte seed', () => {
    const wrapped = wrapSeed(wasm, PRF, SEED);
    // nonce(24) ‖ ct(seed 32 + Poly1305 tag 16) = 24 + 48.
    expect(wrapped.length).toBe(24 + 32 + 16);
    const recovered = unwrapSeed(wasm, PRF, wrapped);
    expect(toHex(recovered)).toBe(toHex(SEED));
  });

  it('a fresh wrap uses a fresh nonce (ciphertext differs) but still unwraps', () => {
    const a = wrapSeed(wasm, PRF, SEED);
    const b = wrapSeed(wasm, PRF, SEED);
    expect(toHex(a)).not.toBe(toHex(b));
    expect(toHex(unwrapSeed(wasm, PRF, a))).toBe(toHex(SEED));
    expect(toHex(unwrapSeed(wasm, PRF, b))).toBe(toHex(SEED));
  });

  it('fails closed on the wrong passkey (PRF)', () => {
    const wrapped = wrapSeed(wasm, PRF, SEED);
    const wrongPrf = new Uint8Array(32).fill(0xa5);
    expect(() => unwrapSeed(wasm, wrongPrf, wrapped)).toThrow();
  });

  it('fails closed on a tampered blob', () => {
    const wrapped = wrapSeed(wasm, PRF, SEED);
    wrapped[wrapped.length - 1] = (wrapped[wrapped.length - 1] ?? 0) ^ 0x01; // flip a tag byte
    expect(() => unwrapSeed(wasm, PRF, wrapped)).toThrow();
  });
});

describe('fresh-seed self-onboard body shape (offline)', () => {
  it('a FRESH random seed builds a well-formed PoP onboard body', async () => {
    // No network: a stub fetch captures the POST /v1/accounts body the client would send.
    let captured: { url: string; method: string; auth: string; body: import('../src/types.js').OnboardBody } | null = null;
    const stubFetch = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string }) => {
      captured = {
        url,
        method: init.method ?? 'GET',
        auth: init.headers?.['Authorization'] ?? '',
        body: JSON.parse(init.body ?? '{}'),
      };
      return { status: 200, text: async () => 'ok', arrayBuffer: async () => new ArrayBuffer(0) };
    };

    const client = new CaladonClient({
      shimBase: 'https://gw.example/v1',
      wasmInput: await wasmBytes(),
      fetchImpl: stubFetch as unknown as typeof fetch,
    });
    await client.init();

    // A genuinely fresh random seed (the self-register path the gateway accepts via PoP).
    const freshSeed = (await import('../src/envelope.js')).randomBytes(32);
    const ident = client.unlockSeed(freshSeed);

    // ed25519_public is now exported → the raw pub is present and account_id is key-bound to it.
    expect(ident.ed25519PubB64).not.toBe('');
    expect(fromBase64(ident.ed25519PubB64).length).toBe(32);
    expect(toBase64(wasm.ed25519_public(ident.root))).toBe(ident.ed25519PubB64);
    expect(ident.accountId).toBe(wasm.account_id(ident.root));

    const status = await client.onboard();
    expect(status).toBe(200);
    expect(captured).not.toBeNull();
    const cap = captured!;
    expect(cap.url).toBe('https://gw.example/v1/accounts');
    expect(cap.method).toBe('POST');
    // PoP: the Authorization header is the Ed25519 signature over the canonical message.
    expect(cap.auth).toMatch(/^Swifty acct=.+ ts=\d+ sig=.+/);
    expect(cap.auth).toContain(`acct=${ident.accountId}`);
    // Body shape: {account_id, ed25519_pub (b64), kem_pub (b64 X25519 pub)}.
    expect(cap.body.account_id).toBe(ident.accountId);
    expect(cap.body.ed25519_pub).toBe(ident.ed25519PubB64);
    expect(fromBase64(cap.body.kem_pub).length).toBe(32);
  });

  it('unlockViaPasskey unwraps a passkey-wrapped fresh seed to the same identity', async () => {
    const client = new CaladonClient({
      shimBase: 'https://gw.example/v1',
      wasmInput: await wasmBytes(),
      fetchImpl: (async () => ({ status: 200, text: async () => 'ok', arrayBuffer: async () => new ArrayBuffer(0) })) as unknown as typeof fetch,
    });
    await client.init();

    const freshSeed = (await import('../src/envelope.js')).randomBytes(32);
    const direct = client.unlockSeed(freshSeed);

    // Custody: wrap the seed under a passkey PRF, then unlock from the wrapped blob.
    const prf = new Uint8Array(32).fill(0x3c);
    const wrapped = wrapSeed(wasm, prf, freshSeed);
    const viaPasskey = client.unlockViaPasskey(prf, wrapped);

    expect(viaPasskey.accountId).toBe(direct.accountId);
    expect(viaPasskey.ed25519PubB64).toBe(direct.ed25519PubB64);
  });
});
