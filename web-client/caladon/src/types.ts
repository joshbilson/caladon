/**
 * Wire + protocol types for the Caladon gateway (contracts/gateway-api.md + identity-envelope.md).
 * These are the JSON shapes the SDK puts on / takes off the wire via the shim.
 */

/** The on-wire sealed envelope (identity-envelope.md §4). All byte fields are base64. */
export interface Envelope {
  /** Envelope version (matches the AAD's `v`). */
  v: number;
  /** AEAD algorithm — always "xchacha20poly1305". */
  alg: 'xchacha20poly1305';
  /** Key id / purpose tag (e.g. "chat", "wmk-delivery"). */
  kid: string;
  /** base64(24-byte XChaCha20 nonce). */
  nonce: string;
  /** base64(SHA-256("{account_id}\n{purpose}\n{v}")) — the 32-byte AEAD AAD. */
  aad: string;
  /** base64(ciphertext ‖ Poly1305 tag). */
  ct: string;
}

/** `POST /v1/accounts` body — onboarding (idempotent). */
export interface OnboardBody {
  account_id: string;
  /** base64(Ed25519 public key). */
  ed25519_pub: string;
  /** base64(X25519 KEM public key). */
  kem_pub: string;
}

/** `GET /v1/attestation?challenge=…` evidence bundle (attestation-evidence.md §1 / §2.1). */
export interface AttestationEvidence {
  regime: 'tdx-onchain' | 'sev-sigstore' | 'none';
  /** lowercase-hex SHA-256(eph_pub); must equal the challenge we sent. */
  challenge: string;
  /** TDX v4 quote, hex (may be prefixed `0x`). Present in `tdx-onchain`. */
  intel_quote?: string;
  /** alias some gateways use. */
  quote?: string;
  /** dstack RTMR3 event log JSON (string). */
  event_log?: string;
  /** dstack CVM identity (POST /Info) — the client pins compose_hash + app_id. */
  info?: {
    compose_hash?: string;
    app_id?: string;
    instance_id?: string;
    device_id?: string;
    app_name?: string;
    no_log?: boolean;
  };
  /** base64(CVM X25519 session public key) — the §6 channel peer key. */
  session_pub?: string;
}

/** `POST /v1/session` body — WMK delivery into the CVM over SK (identity-envelope.md §6). */
export interface SessionBody {
  /** base64(client ephemeral X25519 public key). */
  client_eph_pub: string;
  /** The WMK sealed to SK. */
  sealed_wmk: Envelope;
}

/** `POST /v1/chat` body — the sealed prompt (model is honoured only if attested). */
export interface ChatBody {
  envelope: Envelope;
  model?: string;
}

/** dcap-qvl `QuoteCollateralV3` JSON (the shape `verify_quote_sync` consumes). */
export interface QuoteCollateralV3 {
  pck_crl_issuer_chain: string;
  /** hex string OR byte array — caladon-core/dcap-qvl accept hex (see fetchCollateral). */
  root_ca_crl: string | number[];
  pck_crl: string | number[];
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: string | number[];
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: string | number[];
  pck_certificate_chain?: string;
}

/** The client-shipped pinned set (docs/security/measurements.md). NO TOFU. */
export interface PinnedSet {
  /** lowercase-hex aggregate mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2. */
  measurements: string[];
  compose_hashes: string[];
  workload_ids: string[];
}

/** The fail-closed verdict `verify_quote_sync` returns (attestation/verdict.rs serde shape). */
export interface Verdict {
  ok: boolean;
  /** wire code: "ok" | "QUOTE_SIG_INVALID" | "TCB_OUT_OF_DATE" | … (A7 table). */
  reason: string;
  measurement_matched: boolean;
}

/** A recovered, decrypted SSE delta. */
export interface ChatDelta {
  event: 'token' | 'reasoning';
  text: string;
}

/** Seed-derived identity (held only in memory; the seed never leaves the device). */
export interface Identity {
  /** 32-byte Argon2id root. */
  root: Uint8Array;
  /** key-bound routing id. */
  accountId: string;
  /** base64(Ed25519 public). */
  ed25519PubB64: string;
}
