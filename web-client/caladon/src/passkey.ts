/**
 * Passkey-PRF seed custody (Confer pattern; caladon-core/src/passkey.rs).
 *
 * A WebAuthn credential with the `prf` extension yields a 32-byte secret (`prf32`) that never
 * persists — it is re-evaluated on demand from the authenticator (Touch ID / a security key) for a
 * fixed app salt. From `prf32` we derive a wrapping key (HKDF-SHA256, domain-separated) in WASM and
 * seal / open the 32-byte account seed under it (XChaCha20-Poly1305). This makes a passkey the easy
 * hardware-backed custody for the seed, alongside the Mullvad-style seed codec (sovereign recovery).
 *
 * Two layers, split so Node/vitest can unit-test the crypto without WebAuthn:
 *
 *   1. CRYPTO (this module's `wrapSeed` / `unwrapSeed` / `deriveWrappingKey`) — pure WASM, runs
 *      anywhere (Node, browser). These are what the offline tests exercise against the wasm exports.
 *   2. BROWSER GLUE (`BrowserPasskeyCustody`) — `navigator.credentials.create/get` with
 *      `{ extensions: { prf: { eval: { first: salt } } } }`. Implements the {@link PasskeyCustody}
 *      interface so a browser app wires real WebAuthn while tests inject a stub. Node has no
 *      `navigator.credentials`, so this layer is documented + interface-gated, never run under vitest.
 */

import type { CaladonWasm } from './wasm.js';

// -------------------------------------------------------------------------------------------
// Crypto layer (pure WASM — isomorphic, unit-testable)
// -------------------------------------------------------------------------------------------

/** Wrapping key = HKDF-SHA256(prf32, info="caladon/passkey-wrapping/v1") → 32 bytes (deterministic). */
export function deriveWrappingKey(wasm: CaladonWasm, prf32: Uint8Array): Uint8Array {
  return wasm.passkey_derive_wrapping_key(prf32);
}

/** Seal the 32-byte seed under the passkey-derived key (random nonce). Returns `nonce ‖ ct`. */
export function wrapSeed(wasm: CaladonWasm, prf32: Uint8Array, seed: Uint8Array): Uint8Array {
  return wasm.passkey_wrap_seed(prf32, seed);
}

/** Open a wrapped seed. `wrapped` is `nonce ‖ ct`. Fails closed (throws) on a wrong PRF / tamper. */
export function unwrapSeed(wasm: CaladonWasm, prf32: Uint8Array, wrapped: Uint8Array): Uint8Array {
  return wasm.passkey_unwrap_seed(prf32, wrapped);
}

// -------------------------------------------------------------------------------------------
// Browser glue layer (WebAuthn PRF — documented, interface-gated)
// -------------------------------------------------------------------------------------------

/**
 * The custody interface the browser implements (or a test stubs). `register` provisions a fresh
 * passkey and returns its credential id; `get` re-evaluates the PRF for an existing credential. Both
 * return the 32-byte `prf32` for the SAME `salt`, so:
 *   register → prf32 → wrapSeed(seed) → persist the wrapped blob (NOT the seed);
 *   later     get → prf32 → unwrapSeed(blob) → seed.
 * The seed and prf32 live only in memory; only the wrapped blob (+ credentialId) are stored.
 */
export interface PasskeyCustody {
  /** Create a new passkey credential and evaluate its PRF for `salt`. */
  register(opts: PasskeyRegisterOptions): Promise<PasskeyResult>;
  /** Evaluate the PRF of an existing credential (by id) for `salt`. */
  get(opts: PasskeyGetOptions): Promise<PasskeyResult>;
}

export interface PasskeyResult {
  /** The 32-byte WebAuthn PRF evaluation (HKDF ikm for the wrapping key). */
  prf32: Uint8Array;
  /** The credential id (store this so a later `get` can target the same passkey). */
  credentialId: Uint8Array;
}

export interface PasskeyRegisterOptions {
  /** RP id (the registrable domain, e.g. "caladon.ai"). */
  rpId: string;
  rpName: string;
  /** A stable opaque user handle (≤ 64 bytes); NOT PII for an account-number identity. */
  userId: Uint8Array;
  userName: string;
  userDisplayName?: string;
  /** The fixed PRF salt for this app (domain-separates the derived secret). Default below. */
  salt?: Uint8Array;
  /** Cryptographically random challenge (the create() ceremony challenge). */
  challenge: Uint8Array;
}

export interface PasskeyGetOptions {
  rpId: string;
  /** Restrict to the credential(s) provisioned at register time. */
  allowCredentialIds: Uint8Array[];
  salt?: Uint8Array;
  challenge: Uint8Array;
}

/** The default app PRF salt — domain-separates the seed-wrapping secret from any other PRF use. */
export const DEFAULT_PRF_SALT: Uint8Array = new TextEncoder().encode('caladon/passkey-prf/v1');

/**
 * Minimal `navigator.credentials` surface this glue needs (so the SDK type-checks without DOM-lib's
 * full WebAuthn types and so a test can inject a stub). The shapes mirror the spec subset we use.
 */
export interface CredentialsContainerLike {
  create(opts: { publicKey: PublicKeyCreateLike }): Promise<PublicKeyCredentialLike | null>;
  get(opts: { publicKey: PublicKeyRequestLike }): Promise<PublicKeyCredentialLike | null>;
}

/** A byte buffer the WebAuthn ceremony accepts (we hand it `Uint8Array`s; the spec coerces). */
type Bytes = Uint8Array | ArrayBuffer;
interface PrfInputs {
  prf: { eval: { first: Bytes } };
}
interface PrfOutputs {
  prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } };
}
interface PublicKeyCreateLike {
  challenge: Bytes;
  rp: { id: string; name: string };
  user: { id: Bytes; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection?: { residentKey?: string; userVerification?: string };
  extensions?: PrfInputs;
}
interface PublicKeyRequestLike {
  challenge: Bytes;
  rpId: string;
  allowCredentials?: { type: 'public-key'; id: Bytes }[];
  userVerification?: string;
  extensions?: PrfInputs;
}
interface PublicKeyCredentialLike {
  rawId: ArrayBuffer;
  getClientExtensionResults(): PrfOutputs;
}

/**
 * The browser-side {@link PasskeyCustody} over `navigator.credentials` + the WebAuthn PRF extension.
 * Construct with `new BrowserPasskeyCustody()` in a browser (defaults to `navigator.credentials`),
 * or pass a `CredentialsContainerLike` to inject a stub. Node has no `navigator.credentials`, so
 * this runs only in a real browser — the crypto layer above is what the unit tests cover.
 *
 * Spec note: ES256 (-7) + RS256 (-257) cover the common authenticators; we request `prf` with a
 * fixed `first` salt and read `getClientExtensionResults().prf.results.first` as the 32-byte secret.
 * Some authenticators return PRF only on a subsequent assertion (`get`), not at `create`; callers
 * that get an empty `prf32` from `register` should follow with `get` to obtain it.
 */
export class BrowserPasskeyCustody implements PasskeyCustody {
  private readonly creds: CredentialsContainerLike;

  constructor(creds?: CredentialsContainerLike) {
    const c =
      creds ??
      (globalThis as { navigator?: { credentials?: CredentialsContainerLike } }).navigator
        ?.credentials;
    if (!c) {
      throw new Error('no navigator.credentials (WebAuthn unavailable — pass a CredentialsContainerLike)');
    }
    this.creds = c;
  }

  async register(opts: PasskeyRegisterOptions): Promise<PasskeyResult> {
    const salt = opts.salt ?? DEFAULT_PRF_SALT;
    const cred = await this.creds.create({
      publicKey: {
        challenge: opts.challenge,
        rp: { id: opts.rpId, name: opts.rpName },
        user: { id: opts.userId, name: opts.userName, displayName: opts.userDisplayName ?? opts.userName },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    return toResult(cred);
  }

  async get(opts: PasskeyGetOptions): Promise<PasskeyResult> {
    const salt = opts.salt ?? DEFAULT_PRF_SALT;
    const cred = await this.creds.get({
      publicKey: {
        challenge: opts.challenge,
        rpId: opts.rpId,
        allowCredentials: opts.allowCredentialIds.map((id) => ({ type: 'public-key', id })),
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    return toResult(cred);
  }
}

function toResult(cred: PublicKeyCredentialLike | null): PasskeyResult {
  if (!cred) throw new Error('WebAuthn ceremony returned no credential');
  const ext = cred.getClientExtensionResults();
  const first = ext.prf?.results?.first;
  if (!first) {
    throw new Error('passkey PRF result missing (authenticator does not support the prf extension)');
  }
  const prf32 = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
  if (prf32.length !== 32) throw new Error(`passkey PRF is ${prf32.length} bytes, expected 32`);
  return { prf32: prf32.slice(), credentialId: new Uint8Array(cred.rawId.slice(0)) };
}
