/* tslint:disable */
/* eslint-disable */

/**
 * Zero-PII routing account_id (key-bound, B2-bis), from the root.
 */
export function account_id(root: Uint8Array): string;

/**
 * Argon2id(seed, salt) → 32-byte root. `memlimit_bytes` is libsodium-style bytes (m_cost = /1024).
 * Pass `SwiftyCrypto.{ops,mem}LimitProduction` equivalents (t=3, m=256MiB) in production.
 */
export function argon2id(seed: Uint8Array, salt: Uint8Array, opslimit: number, memlimit_bytes: number): Uint8Array;

/**
 * Build the `Authorization: Swifty acct=.. ts=.. sig=..` header for a request, signing with the
 * seed-derived Ed25519 key. Every signed gateway call uses this (the web client cannot reach the
 * gateway without it). Fails closed on a malformed account_id.
 */
export function authorization_header(root: Uint8Array, account_id: string, ts: bigint, method: string, path: string): string;

/**
 * Lowercase-hex SHA-256(eph_pub) — the channel binding the verifier checks at §4.6.
 */
export function challenge_hex(eph_pub: Uint8Array): string;

/**
 * SK = HKDF(X25519(my_private, their_public), info = label ‖ client_pub ‖ cvm_pub).
 * Fails closed on a low-order/identity peer key.
 */
export function derive_session_key(my_private: Uint8Array, their_public: Uint8Array, client_pub: Uint8Array, cvm_pub: Uint8Array): Uint8Array;

/**
 * The device-local encrypted store key (32 bytes) for the client's SQLite/SQLCipher store
 * (history + RAG + FTS) — Batch-1 client foundation. Derived from the root; NEVER leaves the
 * device. Single source of truth (the native client uses the UniFFI export of the same kdf fn),
 * so the key is byte-identical and never re-implemented in JS/Swift (avoids an HKDF salt drift).
 */
export function device_store_key(root: Uint8Array): Uint8Array;

/**
 * Raw Ed25519 public key (32 bytes) for gateway onboarding proof-of-possession (POST /v1/accounts):
 * the gateway checks the PoP signature + that account_id == key-bound(pub). Lets the web client
 * self-onboard a fresh identity (account_id alone is one-way, so the raw pub must be exported).
 */
export function ed25519_public(root: Uint8Array): Uint8Array;

/**
 * Open a sealed live-turn payload under SK. `nonce_ct` is `nonce ‖ ct`. Fails closed on tamper.
 */
export function open_chat(session_key: Uint8Array, nonce_ct: Uint8Array, account_id: string, v: bigint): Uint8Array;

/**
 * CVM opens a sealed WMK. `nonce_ct` is `nonce ‖ ct`. Fails closed on tamper.
 */
export function open_wmk(session_key: Uint8Array, nonce_ct: Uint8Array, account_id: string, v: bigint): Uint8Array;

/**
 * Pad to a fixed bucket so the wire length reveals only the bucket, not the exact plaintext size.
 */
export function pad(plaintext: Uint8Array): Uint8Array;

/**
 * Wrapping key = HKDF-SHA256(ikm = prf32, info = "caladon/passkey-wrapping/v1") → 32 bytes.
 * Deterministic in `prf32`. Throws on a non-32-byte PRF.
 */
export function passkey_derive_wrapping_key(prf32: Uint8Array): Uint8Array;

/**
 * Open (unwrap) the sealed seed. `wrapped` is `nonce ‖ ct`. Fails closed (throws) on a wrong
 * passkey/PRF or a tampered blob.
 */
export function passkey_unwrap_seed(prf32: Uint8Array, wrapped: Uint8Array): Uint8Array;

/**
 * Seal (wrap) the 32-byte seed under the passkey-derived wrapping key. Random 24-byte nonce.
 * Returns `nonce ‖ ct` (24-byte nonce prefix) so JS handles one buffer.
 */
export function passkey_wrap_seed(prf32: Uint8Array, seed: Uint8Array): Uint8Array;

/**
 * Seal a live-turn payload (prompt / response delta) to SK (purpose "chat"). Random nonce.
 * Returns `nonce ‖ ct`.
 */
export function seal_chat(session_key: Uint8Array, plaintext: Uint8Array, account_id: string, v: bigint): Uint8Array;

/**
 * Client seals the WMK to SK for delivery into the CVM (purpose "wmk-delivery"). Random nonce.
 * Returns `nonce ‖ ct` (24-byte nonce prefix) so JS handles one buffer.
 */
export function seal_wmk(session_key: Uint8Array, wmk: Uint8Array, account_id: string, v: bigint): Uint8Array;

/**
 * Decode a recovery string back to the 32-byte seed. Fails closed (throws) on a bad
 * checksum/length/character.
 */
export function seed_decode(text: string): Uint8Array;

/**
 * Encode a 32-byte seed to the grouped Crockford-base32 + checksum recovery string.
 */
export function seed_encode(seed: Uint8Array): string;

/**
 * Recover the exact plaintext from a padded buffer. Fails closed (throws) on a malformed buffer.
 */
export function unpad(padded: Uint8Array): Uint8Array;

/**
 * Verify a TDX quote, returning the `Verdict` as a JS value (`{ ok, reason, measurement_matched }`).
 *
 * `pinned_json` is `{ "measurements": [...], "compose_hashes": [...], "workload_ids": [...] }`
 * (the client-shipped pin list; no TOFU). `collateral_json` is the PCS collateral JSON the JS
 * host fetched. `expected_challenge_hex` is lowercase-hex SHA-256(eph_pub) (the §4.6 client
 * binding); `expected_session_pub` is the RAW 32-byte CVM X25519 session pubkey (the JS host
 * base64-decodes `ev.session_pub`) — §4.6b checks report_data[32:64] == SHA-256(session_pub) so a
 * relay cannot substitute its own session key. Never throws on a verification FAILURE — it returns
 * a failing `Verdict` so the caller can branch on the specific reason; it only throws if
 * `pinned_json` is unparseable.
 */
export function verify_quote_sync(quote_bytes: Uint8Array, collateral_json: string, info_json: string, now_secs: bigint, expected_challenge_hex: string, expected_session_pub: Uint8Array, pinned_json: string): any;

/**
 * The working-memory key (delivered into the CVM over the §6 session channel), from the root.
 */
export function wmk(root: Uint8Array): Uint8Array;

/**
 * X25519 public key for a 32-byte private scalar (RFC 7748 clamped base-point multiply).
 */
export function x25519_public(private_bytes: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly account_id: (a: number, b: number) => [number, number];
    readonly argon2id: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly authorization_header: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly challenge_hex: (a: number, b: number) => [number, number];
    readonly derive_session_key: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly device_store_key: (a: number, b: number) => [number, number];
    readonly ed25519_public: (a: number, b: number) => [number, number];
    readonly open_chat: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number, number];
    readonly open_wmk: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number, number];
    readonly pad: (a: number, b: number) => [number, number, number, number];
    readonly passkey_derive_wrapping_key: (a: number, b: number) => [number, number, number, number];
    readonly passkey_unwrap_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly passkey_wrap_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly seal_chat: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number, number];
    readonly seal_wmk: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number, number];
    readonly seed_decode: (a: number, b: number) => [number, number, number, number];
    readonly seed_encode: (a: number, b: number) => [number, number, number, number];
    readonly unpad: (a: number, b: number) => [number, number, number, number];
    readonly verify_quote_sync: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number];
    readonly wmk: (a: number, b: number) => [number, number];
    readonly x25519_public: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
