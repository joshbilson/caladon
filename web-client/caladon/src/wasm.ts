/**
 * caladon-core WASM loader — the single place the SDK touches the wasm-bindgen module.
 *
 * The generated glue (`../wasm/caladon_core.js`) is a `--target web` module: its default export
 * is an async `init(input)` that instantiates the `.wasm`. In a browser the SDK passes a URL
 * (fetched same-origin); under Node (the integration test) there is no fetch-by-URL for a local
 * file, so we read the `.wasm` bytes off disk and hand them in. Either way we then have the typed
 * exports (argon2id, account_id, ed25519_public, authorization_header, challenge_hex,
 * x25519_public, derive_session_key, seal_wmk, seal_chat, open_chat, verify_quote_sync, wmk,
 * open_wmk, and the passkey-PRF custody trio passkey_{derive_wrapping_key,wrap_seed,unwrap_seed}).
 *
 * READ-ONLY consumer of caladon-core: this imports the built artifact; it never edits the crate.
 */

import init, * as wasmExports from '../wasm/caladon_core.js';

/** The subset of caladon-core exports the protocol SDK uses (see SURGERY.md §D table). */
export interface CaladonWasm {
  /** Argon2id(seed, salt, opslimit, memlimit_bytes) -> 32-byte root. */
  argon2id(seed: Uint8Array, salt: Uint8Array, opslimit: number, memlimitBytes: number): Uint8Array;
  /** Zero-PII, key-bound routing account_id (B2-bis) from the root. */
  account_id(root: Uint8Array): string;
  /** Raw 32-byte Ed25519 public key from the root — the onboarding PoP key (POST /v1/accounts). */
  ed25519_public(root: Uint8Array): Uint8Array;
  /** Working-memory key from the root (delivered into the CVM over the §6 session channel). */
  wmk(root: Uint8Array): Uint8Array;
  /** `Authorization: Swifty acct=.. ts=.. sig=..` signed with the seed-derived Ed25519 key. */
  authorization_header(root: Uint8Array, accountId: string, ts: bigint, method: string, path: string): string;
  /** Lowercase-hex SHA-256(eph_pub) — the attestation channel binding. */
  challenge_hex(ephPub: Uint8Array): string;
  /** X25519 public key for a 32-byte private scalar. */
  x25519_public(privateBytes: Uint8Array): Uint8Array;
  /** SK = HKDF(X25519(my_priv, their_pub), info = label ‖ client_pub ‖ cvm_pub). */
  derive_session_key(myPrivate: Uint8Array, theirPublic: Uint8Array, clientPub: Uint8Array, cvmPub: Uint8Array): Uint8Array;
  /** Seal the WMK to SK (purpose "wmk-delivery"). Returns `nonce ‖ ct`. */
  seal_wmk(sessionKey: Uint8Array, wmk: Uint8Array, accountId: string, v: bigint): Uint8Array;
  /** Open a sealed WMK under SK. `nonce_ct` is `nonce ‖ ct`. */
  open_wmk(sessionKey: Uint8Array, nonceCt: Uint8Array, accountId: string, v: bigint): Uint8Array;
  /** Seal a live-turn payload to SK (purpose "chat"). Returns `nonce ‖ ct`. */
  seal_chat(sessionKey: Uint8Array, plaintext: Uint8Array, accountId: string, v: bigint): Uint8Array;
  /** Open a sealed live-turn payload under SK. `nonce_ct` is `nonce ‖ ct`. */
  open_chat(sessionKey: Uint8Array, nonceCt: Uint8Array, accountId: string, v: bigint): Uint8Array;
  /** Fail-closed TDX verdict. Collateral is JS-fetched and passed in. */
  verify_quote_sync(
    quoteBytes: Uint8Array,
    collateralJson: string,
    infoJson: string,
    nowSecs: bigint,
    expectedChallengeHex: string,
    pinnedJson: string,
  ): unknown;
  /** Passkey-PRF custody: wrapping key = HKDF-SHA256(prf32, "caladon/passkey-wrapping/v1"). */
  passkey_derive_wrapping_key(prf32: Uint8Array): Uint8Array;
  /** Seal the 32-byte seed under the passkey-derived key. Returns `nonce ‖ ct`. */
  passkey_wrap_seed(prf32: Uint8Array, seed: Uint8Array): Uint8Array;
  /** Open a wrapped seed. `wrapped` is `nonce ‖ ct`. Fails closed on a wrong PRF / tamper. */
  passkey_unwrap_seed(prf32: Uint8Array, wrapped: Uint8Array): Uint8Array;
}

let loaded: CaladonWasm | null = null;

/** Input the wasm-bindgen `init` accepts: a URL/Response (browser) or the raw bytes (Node). */
export type WasmInput = string | URL | Response | BufferSource | WebAssembly.Module;

/**
 * Initialise the WASM module once and return the typed exports.
 *
 * - Browser: pass `wasmUrl` (e.g. a Vite `?url` import or `/caladon/caladon_core_bg.wasm`).
 * - Node: pass the `.wasm` bytes (an `ArrayBuffer`/`Uint8Array`); the test reads the file and
 *   passes them in (there is no same-origin fetch for a local path under Node).
 * Idempotent: subsequent calls return the already-initialised module.
 */
export async function loadCaladonWasm(input?: WasmInput): Promise<CaladonWasm> {
  if (loaded) return loaded;
  // wasm-bindgen 0.2's web target now prefers `init({ module_or_path })`; passing the value
  // directly still works (with a deprecation note we suppress by using the object form when we
  // have an explicit input).
  if (input === undefined) {
    await init();
  } else {
    await init({ module_or_path: input });
  }
  loaded = wasmExports as unknown as CaladonWasm;
  return loaded;
}

/** Reset the singleton (tests only). */
export function __resetWasmForTests(): void {
  loaded = null;
}
