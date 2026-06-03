/**
 * Envelope wire (de)serialization + AAD derivation, bridging the WASM `nonce ‖ ct` buffers to the
 * gateway's `{v, alg, kid, nonce, aad, ct}` base64 JSON (identity-envelope.md §4). The WASM seals
 * with a random nonce and returns `nonce ‖ ct`; the on-wire `aad` field is base64(SHA-256(
 * "{account_id}\n{purpose}\n{v}")) — the gateway/CVM re-derive and check it on open, and the WASM
 * `open_*` re-derive it internally too, so `aad` is carried for the wire contract but never trusted.
 */

import { ALG, NONCE_LEN } from './constants.js';
import { fromBase64, toBase64, concatBytes, utf8 } from './bytes.js';
import type { Envelope } from './types.js';

let subtleCrypto: SubtleCrypto | undefined;

/** Resolve WebCrypto SubtleCrypto in both browser and Node (>=18 exposes globalThis.crypto). */
function subtle(): SubtleCrypto {
  if (subtleCrypto) return subtleCrypto;
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('WebCrypto subtle unavailable (need Node >=18 or a browser)');
  subtleCrypto = c.subtle;
  return subtleCrypto;
}

/** Cryptographically secure random bytes (browser + Node). */
export function randomBytes(n: number): Uint8Array {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.getRandomValues) throw new Error('crypto.getRandomValues unavailable');
  const out = new Uint8Array(n);
  c.getRandomValues(out);
  return out;
}

/** SHA-256, async (WebCrypto). */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await subtle().digest('SHA-256', data as unknown as BufferSource);
  return new Uint8Array(buf);
}

/** The envelope AAD = SHA-256("{account_id}\n{purpose}\n{v}") (matches envelope.rs::aad). */
export async function aad(accountId: string, purpose: string, v: number): Promise<Uint8Array> {
  return sha256(utf8(`${accountId}\n${purpose}\n${v}`));
}

/**
 * Build the on-wire `Envelope` from the WASM seal output (`nonce ‖ ct`). `kid`/`purpose` are the
 * same string for our two purposes ("chat", "wmk-delivery"); `v` is the envelope version.
 */
export async function toWireEnvelope(
  nonceCt: Uint8Array,
  accountId: string,
  purpose: string,
  v: number,
  kid: string,
): Promise<Envelope> {
  if (nonceCt.length < NONCE_LEN) throw new Error('sealed payload shorter than the nonce');
  const nonce = nonceCt.subarray(0, NONCE_LEN);
  const ct = nonceCt.subarray(NONCE_LEN);
  return {
    v,
    alg: ALG,
    kid,
    nonce: toBase64(nonce),
    aad: toBase64(await aad(accountId, purpose, v)),
    ct: toBase64(ct),
  };
}

/** Recover the WASM `open_*` input (`nonce ‖ ct`) from a wire `Envelope`. */
export function fromWireEnvelope(env: Envelope): Uint8Array {
  return concatBytes(fromBase64(env.nonce), fromBase64(env.ct));
}
