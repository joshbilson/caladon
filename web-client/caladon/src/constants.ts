/**
 * Protocol constants — byte-identical to caladon-core + swifty_crypto. Changing any of these
 * breaks interop with the gateway/CVM (they are not knobs).
 */

/** AEAD algorithm tag on every envelope (envelope.rs::ALG). */
export const ALG = 'xchacha20poly1305' as const;

/** XChaCha20-Poly1305-IETF nonce length (envelope.rs::NONCE_LEN). */
export const NONCE_LEN = 24;

/** Envelope version used for chat + WMK delivery (gate1_client.py uses v=1). */
export const ENVELOPE_V = 1;

/** Purpose tags (session.rs::{CHAT_PURPOSE, WMK_DELIVERY_PURPOSE}). */
export const CHAT_PURPOSE = 'chat' as const;
export const WMK_PURPOSE = 'wmk-delivery' as const;

/** Default app-domain Argon2id salt (gate1_client.py SALT = b"swifty/v1"). */
export const DEFAULT_SALT = 'swifty/v1';

/**
 * Argon2id parameters. The §10 PRODUCTION baseline is t=3, m=256MiB (kdf.rs
 * ARGON2ID_*_PRODUCTION). The Python reference round-trip client (gate1_client.py) onboards with
 * the FUNCTION DEFAULTS (t=3, m=64MiB), so to derive the SAME account_id as a Python-onboarded
 * identity the SDK must match those. Both are exposed; the test pins the reference (64MiB) so it
 * recovers the same key-bound account_id the live gateway already knows.
 */
export const ARGON2ID_OPSLIMIT_REFERENCE = 3;
export const ARGON2ID_MEMLIMIT_REFERENCE = 64 * 1024 * 1024;
export const ARGON2ID_OPSLIMIT_PRODUCTION = 3;
export const ARGON2ID_MEMLIMIT_PRODUCTION = 256 * 1024 * 1024;

/** Default same-origin shim base (browser). The integration test overrides this. */
export const DEFAULT_SHIM_BASE = '/api/caladon';

/** Default PCS-collateral proxy prefix on the shim (server.ts /pcs-collateral/*). */
export const DEFAULT_PCS_COLLATERAL_BASE = '/pcs-collateral';

/** The live gateway (DNS now wired — gw.caladon.ai serves the dstack CVM TLS). */
export const LIVE_GATEWAY_BASE = 'https://gw.caladon.ai';
