/**
 * CaladonClient — the TypeScript bridge from a seed-derived identity → caladon-core WASM → the live
 * gateway protocol, through the stateless shim (SURGERY.md §D, the "INJECT" layer).
 *
 * The full fail-closed handshake (SURGERY.md §D3, mirrors infra/cvm/gate1_client.py):
 *   1. unlock seed → derive identity (account_id + Ed25519 signer) in WASM.
 *   2. onboard: POST /v1/accounts (idempotent) with the key-bound account_id + KEM pub.
 *   3. GET /v1/attestation?challenge=SHA256(eph_pub) → evidence (TDX quote + cvm session_pub).
 *   4. verify_quote_sync (collateral JS-fetched via /pcs-collateral) — FAIL CLOSED on any non-ok
 *      verdict (no TOFU). Refuse to seal/send if the verdict is not ok (configurable: a dev tier
 *      may downgrade attestation to a warning, but the default is strict).
 *   5. derive SK against the attested session_pub → seal WMK → POST /v1/session.
 *   6. per turn: seal_chat(prompt) → POST /v1/chat → open each sealed token/reasoning delta.
 *
 * The browser is the ONLY place plaintext or a key exists; the shim + gateway route opaque
 * envelopes. Identity is seed-derived; the seed itself may be held under passkey-PRF custody
 * (src/passkey.ts wraps the WebAuthn-PRF derived key around the seed) or transcribed via the
 * Mullvad-style seed codec. `unlockViaPasskey(prf32, wrappedSeed)` unwraps then derives identity.
 */

import {
  ARGON2ID_MEMLIMIT_REFERENCE,
  ARGON2ID_OPSLIMIT_REFERENCE,
  CHAT_PURPOSE,
  DEFAULT_PCS_COLLATERAL_BASE,
  DEFAULT_SALT,
  DEFAULT_SHIM_BASE,
  ENVELOPE_V,
  WMK_PURPOSE,
} from './constants.js';
import { fromBase64, fromHex, fromUtf8, toBase64, utf8 } from './bytes.js';
import { fromWireEnvelope, randomBytes, toWireEnvelope } from './envelope.js';
import { fetchCollateralFromPcs, type FetchLike } from './collateral.js';
import { loadCaladonWasm, type CaladonWasm, type WasmInput } from './wasm.js';
import type {
  AttestationEvidence,
  ChatBody,
  ChatDelta,
  Identity,
  OnboardBody,
  PinnedSet,
  QuoteCollateralV3,
  SessionBody,
  Verdict,
} from './types.js';

export interface CaladonClientConfig {
  /** Shim base for /v1/* relays (browser default: same-origin /api/caladon). */
  shimBase?: string;
  /** Shim base for the PCS-collateral proxy (default /pcs-collateral). */
  pcsCollateralBase?: string;
  /** fetch implementation (default: globalThis.fetch). */
  fetchImpl?: FetchLike;
  /** WASM init input (browser: URL; Node: the .wasm bytes). Omit to use the bundler default. */
  wasmInput?: WasmInput;
  /** Argon2id opslimit. Default = reference (t=3) so the derived account_id matches a
   * Python/gate1-onboarded identity. Pass the production memlimit for real users. */
  argon2idOpslimit?: number;
  argon2idMemlimitBytes?: number;
  /** App-domain Argon2id salt (default "swifty/v1"). */
  salt?: string;
  /** The pinned measurement set (docs/security/measurements.md). REQUIRED for strict attestation. */
  pinned?: PinnedSet;
  /**
   * Attestation policy. 'strict' (default) refuses to proceed unless verify_quote_sync returns
   * ok=true. 'observe' verifies + reports but does not block (dev/diagnostic only — NEVER a
   * hosted-tier default). 'skip' bypasses verification entirely (plaintext-debug round-trips only).
   */
  attestationPolicy?: 'strict' | 'observe' | 'skip';
  /** Optional override that supplies collateral instead of the live PCS fetch (e.g. a pinned
   * fixture for known hardware, or an offline test). Receives the quote bytes. */
  collateralProvider?: (quote: Uint8Array) => Promise<QuoteCollateralV3> | QuoteCollateralV3;
  /** Clock source (seconds) for the attestation `now`. Default Date.now()/1000. */
  nowSecs?: () => number;
}

export interface HandshakeResult {
  identity: Identity;
  evidence: AttestationEvidence;
  verdict: Verdict | null;
  /** The derived session key (held in memory only). */
  sessionKey: Uint8Array;
}

export interface ChatResult {
  /** Concatenated decrypted `token` deltas — the model reply. */
  reply: string;
  /** Concatenated decrypted `reasoning` deltas (if any). */
  reasoning: string;
  /** Each opened delta in order. */
  deltas: ChatDelta[];
  /** Raw SSE bytes (for the leak assertion). */
  rawBytes: number;
}

export class CaladonError extends Error {}
export class AttestationFailedError extends CaladonError {
  constructor(public readonly verdict: Verdict) {
    super(`attestation failed: ${verdict.reason}`);
    this.name = 'AttestationFailedError';
  }
}

export class CaladonClient {
  private wasm!: CaladonWasm;
  private readonly cfg: Required<
    Omit<CaladonClientConfig, 'wasmInput' | 'pinned' | 'collateralProvider'>
  > & Pick<CaladonClientConfig, 'wasmInput' | 'pinned' | 'collateralProvider'>;

  // Session state (in memory only).
  private identity: Identity | null = null;
  private sessionKey: Uint8Array | null = null;

  constructor(config: CaladonClientConfig = {}) {
    const fetchImpl =
      config.fetchImpl ?? ((globalThis as { fetch?: FetchLike }).fetch as FetchLike | undefined);
    if (!fetchImpl) throw new CaladonError('no fetch implementation (pass fetchImpl)');
    this.cfg = {
      shimBase: config.shimBase ?? DEFAULT_SHIM_BASE,
      pcsCollateralBase: config.pcsCollateralBase ?? DEFAULT_PCS_COLLATERAL_BASE,
      fetchImpl,
      argon2idOpslimit: config.argon2idOpslimit ?? ARGON2ID_OPSLIMIT_REFERENCE,
      argon2idMemlimitBytes: config.argon2idMemlimitBytes ?? ARGON2ID_MEMLIMIT_REFERENCE,
      salt: config.salt ?? DEFAULT_SALT,
      attestationPolicy: config.attestationPolicy ?? 'strict',
      nowSecs: config.nowSecs ?? (() => Math.floor(Date.now() / 1000)),
      wasmInput: config.wasmInput,
      pinned: config.pinned,
      collateralProvider: config.collateralProvider,
    };
  }

  /** Initialise the WASM module (idempotent). Call once before use. */
  async init(): Promise<void> {
    if (!this.wasm) this.wasm = await loadCaladonWasm(this.cfg.wasmInput);
  }

  // -------------------------------------------------------------------------------------------
  // Identity
  // -------------------------------------------------------------------------------------------

  /**
   * Derive the seed identity (Argon2id root → key-bound account_id + Ed25519 public). The seed
   * must be a high-entropy 32-byte secret (a Mullvad-style account number / restored seed); it
   * never leaves memory. Holds the identity for subsequent signed calls.
   */
  unlockSeed(seed: Uint8Array): Identity {
    const root = this.wasm.argon2id(
      seed,
      utf8(this.cfg.salt),
      this.cfg.argon2idOpslimit,
      this.cfg.argon2idMemlimitBytes,
    );
    const accountId = this.wasm.account_id(root);
    // The onboarding body (POST /v1/accounts) needs the RAW Ed25519 public key — account_id is
    // sha256(domain‖pub), one-way, so the pub can't be recovered from it. caladon-core now exports
    // `ed25519_public(root)`, so the SDK derives the raw pub directly and a FRESH random seed can
    // self-register (the gateway checks PoP + that account_id == key-bound(pub)). See onboard().
    const ed25519PubB64 = toBase64(this.wasm.ed25519_public(root));
    const identity: Identity = { root, accountId, ed25519PubB64 };
    this.identity = identity;
    return identity;
  }

  /**
   * Unlock the seed-derived identity from a passkey-PRF-wrapped seed (Confer custody): unwrap the
   * seed under the WebAuthn-PRF-derived wrapping key in WASM, then derive the identity as usual.
   * `prf32` is the 32-byte WebAuthn PRF evaluation (e.g. from {@link PasskeyCustody.get}); it and
   * the recovered seed never leave memory. Fails closed (throws) on a wrong passkey / tampered blob.
   */
  unlockViaPasskey(prf32: Uint8Array, wrappedSeed: Uint8Array): Identity {
    const seed = this.wasm.passkey_unwrap_seed(prf32, wrappedSeed);
    return this.unlockSeed(seed);
  }

  // -------------------------------------------------------------------------------------------
  // Signed transport
  // -------------------------------------------------------------------------------------------

  private requireIdentity(): Identity {
    if (!this.identity) throw new CaladonError('no identity (call unlockSeed first)');
    return this.identity;
  }

  /** The signing path matches gateway canonical: sign the PATH WITHOUT the query string. */
  private authHeader(method: string, fullPath: string): string {
    const ident = this.requireIdentity();
    const signPath = fullPath.split('?', 1)[0]!;
    const ts = BigInt(this.cfg.nowSecs());
    return this.wasm.authorization_header(ident.root, ident.accountId, ts, method, signPath);
  }

  private async signedFetch(
    method: 'GET' | 'POST',
    relayName: string,
    query: string,
    body?: unknown,
    isStream = false,
  ): Promise<{ status: number; text(): Promise<string>; arrayBuffer(): Promise<ArrayBuffer> }> {
    const gatewayPath = `/v1/${relayName}`;
    const url = `${this.cfg.shimBase}/${relayName}${query}`;
    const headers: Record<string, string> = {
      Authorization: this.authHeader(method, gatewayPath + query),
    };
    const init: { method: string; headers: Record<string, string>; body?: string } = { method, headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    if (isStream) headers['Accept'] = 'text/event-stream';
    const r = await this.cfg.fetchImpl(url, init);
    return r;
  }

  // -------------------------------------------------------------------------------------------
  // 2. Onboard
  // -------------------------------------------------------------------------------------------

  /**
   * Self-onboard: POST /v1/accounts (idempotent) with the real proof-of-possession body
   * `{account_id, ed25519_pub (b64 of ed25519_public(root)), kem_pub (b64 X25519)}`, signed by the
   * Authorization header (Ed25519 over the canonical message). Mirrors infra/cvm/gate1_client.py
   * `onboard()`. Because the raw Ed25519 pub is now exported, a FRESH random seed registers itself:
   * the gateway checks the PoP signature and that account_id == key-bound(pub). Returns the HTTP
   * status (200 on first onboard; the gateway is idempotent so a re-onboard of a known account is
   * also accepted). THROWS if the WASM has no `ed25519_public` (the onboarding body would be
   * unsigned-for / rejected — fail closed rather than POST a body the gateway will refuse).
   */
  async onboard(): Promise<number> {
    const ident = this.requireIdentity();
    if (!ident.ed25519PubB64) {
      throw new CaladonError('identity has no ed25519_pub — cannot build the onboarding PoP body');
    }
    const kemPriv = randomBytes(32);
    const kemPub = this.wasm.x25519_public(kemPriv);
    const onboardBody: OnboardBody = {
      account_id: ident.accountId,
      ed25519_pub: ident.ed25519PubB64,
      kem_pub: toBase64(kemPub),
    };
    const r = await this.signedFetch('POST', 'accounts', '', onboardBody);
    return r.status;
  }

  // -------------------------------------------------------------------------------------------
  // 3 + 4. Attestation
  // -------------------------------------------------------------------------------------------

  /** GET /v1/attestation?challenge=SHA256(eph_pub) → evidence. */
  async getAttestation(ephPub: Uint8Array): Promise<AttestationEvidence> {
    const challenge = this.wasm.challenge_hex(ephPub);
    const r = await this.signedFetch('GET', 'attestation', `?challenge=${challenge}`);
    const txt = await r.text();
    if (r.status !== 200) throw new CaladonError(`GET /v1/attestation -> ${r.status}: ${txt.slice(0, 200)}`);
    const ev = JSON.parse(txt) as AttestationEvidence;
    if (ev.challenge !== challenge) {
      throw new CaladonError('attestation challenge not bound (evidence stale/replayed)');
    }
    return ev;
  }

  /**
   * Fail-closed attestation verify (SURGERY.md §D3.2). Fetches collateral (JS), runs
   * verify_quote_sync in WASM, and applies the policy. Returns the verdict (null if policy=skip).
   * THROWS AttestationFailedError under 'strict' on any non-ok verdict.
   */
  async verifyAttestation(ev: AttestationEvidence, ephPub: Uint8Array): Promise<Verdict | null> {
    if (this.cfg.attestationPolicy === 'skip') return null;

    const quoteHex = ev.intel_quote ?? ev.quote;
    if (!quoteHex) throw new CaladonError('no intel_quote in evidence — cannot verify');
    const quote = fromHex(quoteHex);

    const collateral: QuoteCollateralV3 = this.cfg.collateralProvider
      ? await this.cfg.collateralProvider(quote)
      : await fetchCollateralFromPcs(quote, {
          pcsCollateralBase: this.cfg.pcsCollateralBase,
          fetchImpl: this.cfg.fetchImpl,
        });

    if (!this.cfg.pinned) {
      throw new CaladonError('no pinned set configured (docs/security/measurements.md) — refusing (no TOFU)');
    }
    const challengeHex = this.wasm.challenge_hex(ephPub);
    const infoJson = JSON.stringify(ev.info ?? {});
    const verdict = this.wasm.verify_quote_sync(
      quote,
      JSON.stringify(collateral),
      infoJson,
      BigInt(this.cfg.nowSecs()),
      challengeHex,
      JSON.stringify(this.cfg.pinned),
    ) as Verdict;

    if (this.cfg.attestationPolicy === 'strict' && !verdict.ok) {
      throw new AttestationFailedError(verdict);
    }
    return verdict;
  }

  // -------------------------------------------------------------------------------------------
  // 5. Session — derive SK against the attested session_pub, seal + deliver the WMK.
  // -------------------------------------------------------------------------------------------

  /** Derive SK against the CVM session_pub, seal the WMK, POST /v1/session. Returns SK. */
  async establishSession(ev: AttestationEvidence, ephPriv: Uint8Array, ephPub: Uint8Array): Promise<Uint8Array> {
    const ident = this.requireIdentity();
    if (!ev.session_pub) throw new CaladonError('evidence carries no session_pub — cannot derive SK (§6)');
    const cvmPub = fromBase64(ev.session_pub);

    const sk = this.wasm.derive_session_key(ephPriv, cvmPub, ephPub, cvmPub);
    const wmk = this.wasm.wmk(ident.root);
    const sealedWmk = this.wasm.seal_wmk(sk, wmk, ident.accountId, BigInt(ENVELOPE_V));
    const body: SessionBody = {
      client_eph_pub: toBase64(ephPub),
      sealed_wmk: await toWireEnvelope(sealedWmk, ident.accountId, WMK_PURPOSE, ENVELOPE_V, WMK_PURPOSE),
    };
    const r = await this.signedFetch('POST', 'session', '', body);
    const txt = await r.text();
    if (r.status !== 200) throw new CaladonError(`POST /v1/session -> ${r.status}: ${txt.slice(0, 200)}`);
    this.sessionKey = sk;
    return sk;
  }

  // -------------------------------------------------------------------------------------------
  // 6. Chat — seal the prompt, POST /v1/chat, open the sealed deltas.
  // -------------------------------------------------------------------------------------------

  /** Seal `prompt` under SK, POST /v1/chat, recover the decrypted reply. */
  async chat(prompt: string, model?: string): Promise<ChatResult> {
    const ident = this.requireIdentity();
    if (!this.sessionKey) throw new CaladonError('no session key (call establishSession first)');
    const sk = this.sessionKey;

    const sealed = this.wasm.seal_chat(sk, utf8(prompt), ident.accountId, BigInt(ENVELOPE_V));
    const body: ChatBody = {
      envelope: await toWireEnvelope(sealed, ident.accountId, CHAT_PURPOSE, ENVELOPE_V, CHAT_PURPOSE),
    };
    if (model) body.model = model;

    const r = await this.signedFetch('POST', 'chat', '', body, true);
    const sseText = await r.text();
    if (r.status !== 200) throw new CaladonError(`POST /v1/chat -> ${r.status}: ${sseText.slice(0, 300)}`);

    // Fail-closed proof: the plaintext prompt must NOT appear on the wire.
    if (sseText.includes(prompt)) throw new CaladonError('LEAK: plaintext prompt appeared in the response stream');

    const deltas = this.openDeltas(sseText, sk, ident.accountId);
    const reply = deltas.filter((d) => d.event === 'token').map((d) => d.text).join('');
    const reasoning = deltas.filter((d) => d.event === 'reasoning').map((d) => d.text).join('');
    return { reply, reasoning, deltas, rawBytes: utf8(sseText).length };
  }

  /** Open each sealed token/reasoning delta under SK → recovered plaintext (mirrors gate1 `_open_deltas`). */
  private openDeltas(sseText: string, sk: Uint8Array, accountId: string): ChatDelta[] {
    const out: ChatDelta[] = [];
    let lastEvent = '';
    for (const rawLine of sseText.split(/\r?\n/)) {
      const line = rawLine;
      if (line.startsWith('event:')) {
        lastEvent = line.slice('event:'.length).trim();
      } else if (line.startsWith('data:') && (lastEvent === 'token' || lastEvent === 'reasoning')) {
        const obj = JSON.parse(line.slice('data:'.length).trim()) as { envelope: import('./types.js').Envelope };
        const nonceCt = fromWireEnvelope(obj.envelope);
        const pt = this.wasm.open_chat(sk, nonceCt, accountId, BigInt(obj.envelope.v));
        out.push({ event: lastEvent, text: fromUtf8(pt) });
      }
    }
    return out;
  }

  // -------------------------------------------------------------------------------------------
  // Orchestration — the full fail-closed round-trip in one call.
  // -------------------------------------------------------------------------------------------

  /**
   * Run the entire handshake (onboard → attest → verify → session) and return the session state.
   * Generates a fresh ephemeral X25519 keypair, binds it into the attestation challenge, verifies
   * fail-closed, then delivers the WMK over SK.
   */
  async handshake(seed: Uint8Array): Promise<HandshakeResult> {
    await this.init();
    const identity = this.unlockSeed(seed);
    await this.onboard();

    const ephPriv = randomBytes(32);
    const ephPub = this.wasm.x25519_public(ephPriv);

    const evidence = await this.getAttestation(ephPub);
    const verdict = await this.verifyAttestation(evidence, ephPub);
    const sessionKey = await this.establishSession(evidence, ephPriv, ephPub);
    return { identity, evidence, verdict, sessionKey };
  }

  /** Convenience: handshake then a single chat turn. */
  async roundtrip(seed: Uint8Array, prompt: string, model?: string): Promise<{ handshake: HandshakeResult; chat: ChatResult }> {
    const handshake = await this.handshake(seed);
    const chat = await this.chat(prompt, model);
    return { handshake, chat };
  }
}
