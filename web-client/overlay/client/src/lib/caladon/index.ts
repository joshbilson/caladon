/**
 * Caladon client integration (SURGERY.md §D — the INJECT layer).
 *
 * This is the ONLY place the LibreChat fork touches crypto. It wraps `@caladon/protocol`
 * (the committable, tested SDK at web-client/caladon/) which in turn is the sole consumer of
 * the `caladon-core` WASM. AuthContext owns the unlocked seed + this module's singleton; useSSE
 * and createPayload reach the seal/open/sign surface through here — no raw key ever escapes.
 *
 * Trust model (SURGERY.md §0): the browser is the only place plaintext or a key exists. The shim
 * (web-client/shim) and the gateway route opaque envelopes; this module seals before send and
 * opens after receive. The fail-closed attestation gate (§D3.2) lives in CaladonClient.handshake.
 */

import {
  CaladonClient,
  CaladonError,
  AttestationFailedError,
  loadCaladonWasm,
  fromWireEnvelope,
  toWireEnvelope,
} from '@caladon/protocol';
import type {
  CaladonClientConfig,
  CaladonWasm,
  Envelope,
  HandshakeResult,
  Identity,
  PinnedSet,
} from '@caladon/protocol';

import wasmUrl from '@caladon/protocol/wasm/caladon_core_bg.wasm?url';

export { CaladonError, AttestationFailedError };
export type { Identity, HandshakeResult };

const ENVELOPE_V = 1;
const CHAT_PURPOSE = 'chat';

/**
 * Pinned measurement set (docs/security/measurements.md). REQUIRED for strict attestation —
 * the SDK refuses to proceed without it (no TOFU). Sourced at build/deploy time; an empty set
 * forces a build-config decision rather than silently weakening the gate. The deploy pass injects
 * the real values via VITE_CALADON_PINNED (JSON) so they are not hard-coded here.
 */
function readPinned(): PinnedSet | undefined {
  const raw = import.meta.env?.VITE_CALADON_PINNED as string | undefined;
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as PinnedSet;
  } catch {
    return undefined;
  }
}

/**
 * Attestation policy (SURGERY.md §D3.2). Default 'strict' — fail-closed. A dev build may set
 * VITE_CALADON_ATTESTATION=skip|observe for plaintext-debug round-trips ONLY; never a hosted
 * default. Plumbed through so the gate is a deploy decision, not a code edit.
 *
 * CS-2/ATT-3 production guard: a build-time env var must NEVER be able to silently fail-open
 * attestation in a hosted/production build — that would deliver WMK + prompts to an unverified
 * gateway. So in a PROD build we REFUSE to honor any non-'strict' policy and HARD-FAIL at client
 * init (throw), rather than quietly weakening the gate. 'observe'/'skip' are permitted ONLY in a
 * DEV build, or behind the explicit VITE_CALADON_ALLOW_INSECURE=1 escape hatch (loudly warned).
 */
function readPolicy(): CaladonClientConfig['attestationPolicy'] {
  const raw = import.meta.env?.VITE_CALADON_ATTESTATION as string | undefined;
  if (raw !== 'skip' && raw !== 'observe' && raw !== 'strict') return 'strict';
  if (raw === 'strict') return raw;

  // Non-strict ('observe'/'skip') requested. Only allow it in a dev build or behind the explicit
  // escape hatch; otherwise refuse loudly so an insecure policy can never reach a hosted build.
  const allowInsecure = (import.meta.env?.VITE_CALADON_ALLOW_INSECURE as string | undefined) === '1';
  if (import.meta.env?.DEV || allowInsecure) {
    console.warn(
      `[caladon] INSECURE attestation policy '${raw}' — the fail-closed gate is DISABLED. ` +
        'WMK + prompts may be delivered to an UNVERIFIED gateway. NEVER ship this in production.',
    );
    return raw;
  }
  throw new CaladonError(
    `refusing insecure attestation policy '${raw}' in a production build: only 'strict' is ` +
      'permitted (set VITE_CALADON_ALLOW_INSECURE=1 to override, dev only)',
  );
}

let client: CaladonClient | null = null;
let wasm: CaladonWasm | null = null;
let identity: Identity | null = null;
let handshakeResult: HandshakeResult | null = null;

/** The single shared client. Same-origin shim base; pinned set + policy from build env. */
export function getCaladonClient(): CaladonClient {
  if (!client) {
    client = new CaladonClient({
      shimBase: (import.meta.env?.VITE_CALADON_SHIM_BASE as string) || '/api/caladon',
      pcsCollateralBase: '/pcs-collateral',
      wasmInput: wasmUrl,
      pinned: readPinned(),
      attestationPolicy: readPolicy(),
    });
  }
  return client;
}

/** Initialise the WASM (idempotent). Returns the low-level export surface for streaming seal/open. */
export async function getWasm(): Promise<CaladonWasm> {
  if (!wasm) {
    wasm = await loadCaladonWasm(wasmUrl);
  }
  return wasm;
}

/**
 * The full fail-closed handshake (SURGERY.md §D3): unlock seed → onboard → attest →
 * verify (fail-closed) → derive SK → deliver WMK. Holds the resulting identity + session so
 * subsequent chat turns reuse the established session key. THROWS AttestationFailedError on a
 * non-ok verdict under strict policy — the caller MUST surface this and refuse to chat.
 */
export async function caladonUnlock(seed: Uint8Array): Promise<HandshakeResult> {
  const c = getCaladonClient();
  const result = await c.handshake(seed);
  identity = result.identity;
  handshakeResult = result;
  return result;
}

export function caladonIdentity(): Identity | null {
  return identity;
}

export function isUnlocked(): boolean {
  return identity != null && handshakeResult != null;
}

export function caladonLock(): void {
  identity = null;
  handshakeResult = null;
  // Note: the SDK holds the session key in memory inside the client instance; drop the instance.
  client = null;
}

/**
 * Per-request signed Authorization header (SURGERY.md §A3). Mirrors the gateway canonical signer:
 * sign the PATH WITHOUT the query string. `gatewayPath` is the upstream `/v1/...` path the shim
 * relays to (the shim forwards this header verbatim; the gateway verifies it).
 */
export async function signRequest(method: 'GET' | 'POST', gatewayPath: string): Promise<string> {
  if (!identity) throw new CaladonError('no identity (unlock seed first)');
  const w = await getWasm();
  const signPath = gatewayPath.split('?', 1)[0]!;
  const ts = BigInt(Math.floor(Date.now() / 1000));
  return w.authorization_header(identity.root, identity.accountId, ts, method, signPath);
}

/** The session key established by the handshake (held in the SDK; mirrored here for streaming). */
function requireSession(): { sk: Uint8Array; accountId: string } {
  if (!handshakeResult || !identity) throw new CaladonError('no session (unlock seed first)');
  return { sk: handshakeResult.sessionKey, accountId: identity.accountId };
}

/**
 * Seal a chat prompt for `POST /v1/chat` (SURGERY.md §D, createPayload call site). Returns the
 * on-wire envelope JSON the body carries: `{ envelope, model }`. The plaintext never leaves here.
 */
export async function sealChat(
  prompt: string,
  model?: string,
  opts?: { tools?: boolean; toolsYolo?: boolean },
): Promise<{ envelope: Envelope; model?: string; tools?: boolean; tools_yolo?: boolean }> {
  const { sk, accountId } = requireSession();
  const w = await getWasm();
  const sealed = w.seal_chat(sk, new TextEncoder().encode(prompt), accountId, BigInt(ENVELOPE_V));
  const envelope = await toWire(sealed, accountId);
  const body: { envelope: Envelope; model?: string; tools?: boolean; tools_yolo?: boolean } = { envelope };
  if (model) {
    body.model = model;
  }
  // In-CVM tool loop (MCP). Only attach the flags when on, so a normal turn's wire body is unchanged.
  if (opts?.tools) {
    body.tools = true;
    if (opts.toolsYolo) {
      body.tools_yolo = true;
    }
  }
  return body;
}

/**
 * Open a single sealed SSE delta (SURGERY.md §D, useSSE token/reasoning handlers). Each
 * `token`/`reasoning` event's `e.data` is `{ envelope }`; this recovers the plaintext delta to
 * feed the existing messageHandler/contentHandler unchanged.
 */
export async function openDelta(wireEnvelope: Envelope): Promise<string> {
  const { sk, accountId } = requireSession();
  const w = await getWasm();
  const nonceCt = fromWireEnvelope(wireEnvelope);
  const pt = w.open_chat(sk, nonceCt, accountId, BigInt(wireEnvelope.v));
  return new TextDecoder().decode(pt);
}

/** Build the on-wire envelope JSON (base64 fields + AAD) for a `nonce‖ct` seal output. */
async function toWire(nonceCt: Uint8Array, accountId: string): Promise<Envelope> {
  return toWireEnvelope(nonceCt, accountId, CHAT_PURPOSE, ENVELOPE_V, CHAT_PURPOSE);
}
