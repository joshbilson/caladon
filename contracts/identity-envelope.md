# Contract: Identity & Encryption Envelope  (`/contracts/identity-envelope.md`)

**Status:** FROZEN — **AMENDED at Gate 0 (2026-06-02, Josh-approved).** The Gate-0
resolutions in the `docs/security/` notes (§"Gate-0 resolutions")
are APPROVED and **supersede any conflicting clause below** — notably: the transcript
ratchet is **multi-device** (per-device sub-ratchet, Sesame-style; supports iOS+macOS
sync from one seed); identity/routing must be **multi-tenant** (public scale from day 1);
and the §3/§4 crypto specifics are pinned (named hash + length-prefixed `aad`,
`account_id` length, static-salt rationale, CSPRNG nonces). Sprint-2 builds against
contract-as-amended. Further changes require maintainer + project-lead sign-off.
**Owners:** A (crypto/identity, primary), B (gateway routes by account id), C (CVM
decrypts working memory under WMK), D (iOS generation/storage), H (tests).
**Pairs with:** `/contracts/attestation.md` (the WMK only travels over a verified channel).

Established primitives only — **no custom crypto** (charter rule). All algorithms
named below are the chosen primitives; do not substitute without sign-off.

---

## 1. Primitives
- **Seed→key KDF:** Argon2id (memory-hard; params in §10, versioned).
- **Sub-key derivation:** HKDF-SHA-256 with domain-separation labels.
- **AEAD:** XChaCha20-Poly1305 (192-bit nonce, misuse-resistant nonce space).
- **Asymmetric:** X25519 (ECDH session keys), Ed25519 (signatures where needed).
- **Transcript ratchet:** symmetric KDF-chain (libsignal-style) — chain key
  advanced per entry, prior chain keys discarded on the advancing device.

---

## 2. The seed (root secret)
- **Generation:** on-device only, `SecRandomCopyBytes`, **256 bits** entropy.
- **Encoding (human-transcribable, Mullvad-style):** group the 256 bits as a fixed
  digit/word format with a checksum; this is the *only* thing the user must keep.
- **Storage on device:** wrapped in the **Secure Enclave**, stored in Keychain
  (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no iCloud, **excluded from
  backups**). Plaintext seed never persisted outside the Secure Enclave boundary.
- The seed is **identity + encryption root in one** (this is why Sign in with Apple
  cannot be used — it yields no user-held key).

---

## 3. Derivations (all via HKDF from the Argon2id output, distinct labels)
```
ARGON2ID(seed, salt="swifty/v1") = root
ed25519      = Ed25519(HKDF(root, "swifty/gateway-auth/v1"))  # gateway-auth signing key
account_id   = urlsafe_b64_nopad(SHA-256("swifty/account/v1" || ed25519_pub))  # AMENDED B2-bis
             #   ^ key-BOUND (so the gateway verifies ownership at onboarding); still a
             #     function of root only, non-reversible, zero PII. Supersedes the prior
             #     `HKDF(root,"swifty/account-id/v1")`. See the contract-review notes.
WMK          = HKDF(root, "swifty/working-mem/v1")   # working-memory data key
transcript_root = HKDF(root, "swifty/transcript/v1") # ratchet seed
metadata_key = HKDF(root, "swifty/metadata/v1")      # for padding/index encryption
```
- `account_id` is a routing identifier only; it must not be reversible to `root`
  and must carry no identity signal (no email/name/handle derived in).
- Per-tier scoping (Phase 4, B7) — the coding tier is an INDEPENDENT key tree; the coding
  CVM receives ONLY `coding_root` (never `root`/`WMK`/`transcript_root`):
```
coding_root            = HKDF(root, "swifty/coding/v1")
coding_WMK             = HKDF(coding_root, "swifty/coding/working-mem/v1")
coding_transcript_root = HKDF(coding_root, "swifty/coding/transcript/v1")
```
  Distinct leaf labels (not the personal ones) keep the label→key mapping bijective. HKDF
  one-wayness means `coding_root` cannot recover `root`, so a coding-CVM compromise can't
  reach personal keys. Impl: `swifty_crypto.derive_coding_root`/`coding_wmk`/`coding_transcript_root`.

---

## 4. Encryption envelope (what the server stores — opaque blobs only)
```
envelope = {
  v:        uint,           # envelope version (crypto-agility)
  alg:      "xchacha20poly1305",
  kid:      string,         # which sub-key/ratchet step
  nonce:    bytes[24],
  aad:      H(account_id || purpose || v),   # binds blob to user+purpose+version
  ct:       bytes           # AEAD ciphertext+tag
}
```
- Server (gateway + at-rest store) sees **only** `envelope` blobs + `account_id`
  for routing. It has **no key** and **no decryption capability**. The gateway is a
  ciphertext router (see attestation contract / STATUS plaintext-exposure map).

---

## 5. The forward-secrecy split (Signal-grade where possible; honest where not)
Two stores, two regimes — because an AI **must re-read its memory**, so it cannot
be fully forward-secret like a messenger.

### 5.1 Transcript — forward-secret, device-side ratchet
- Append-only raw log, rarely re-read.
- **Chat transcript:** the **client** holds the ratchet; encrypts each entry,
  advances the chain, **discards the prior chain key on-device**; hands the CVM only
  ciphertext. The CVM never holds chat-transcript keys. → real FS vs server
  compromise and device-at-rest.
- **Coding-tier transcript:** generated unattended *inside* the coding CVM, so that
  CVM transiently holds its (coding-scoped) ratchet keys. Weaker; it's the coding
  tier (already "attested, not E2E").

### 5.2 Working memory — seed-recoverable, NOT forward-secret (by necessity)
- Letta's living state, re-read every turn. Encrypted under `WMK`. Must stay
  decryptable, so it cannot be forward-secret.
- Decrypted **inside the attested CVM** using `WMK` (see §6).

> **Honest claim for vetting:** "Forward secrecy on the conversation transcript;
> working memory is seed-recoverable and therefore not forward-secret, because an
> agent must re-read its memory." Never claim whole-store FS.

---

## 6. WMK delivery into the CVM (the asymmetry, made explicit)
1. Client completes the attestation handshake (`attestation.md §3–4`) → session key
   `SK`, bound to the verified CVM.
2. Client sends `WMK` to the CVM **only over the SK channel, only after §4 passes**.
3. CVM holds `WMK` in **TEE RAM for the session**, uses it to decrypt/re-encrypt
   working memory, and **discards it on session end**. Never written to disk in the
   clear; never leaves the TEE.
- This is the one point a user-held key enters a remote machine. It is gated by
  attestation and confined to TEE RAM — but it is the reason the system is
  "attested-confidential", not "E2E". Document in `/docs/security/`.

---

## 7. Two-user isolation
- Josh and Blake each have independent seeds → independent `{account_id, WMK,
  transcript_root, ...}`. **No shared key material.**
- Gateway maps `account_id → that user's Agent CVM + Letta agent`.
- Cross-user read is cryptographically impossible (distinct keys) **and**
  routing-isolated (distinct CVMs/agents). H tests both layers.

---

## 8. Recovery
### 8.1 Default: no recovery
Lose the seed → data unrecoverable. Stated plainly at generation time; the backup
step (§2 encoding) is the mitigation.

### 8.2 Optional: SVR-style PIN recovery (Phase 2, opt-in)
- Seed wrapped under a key derived from a user PIN, stored in an **enclave-backed
  recovery service the server cannot read**, with **rate-limited PIN attempts** and
  destroy-after-N.
- **Honest tradeoff (resolve 3↔5 together):** recovering the seed re-derives
  `transcript_root`, so **seed recovery can reconstruct the transcript** — i.e. the
  transcript's forward secrecy holds against device/server compromise but **not
  against seed compromise**, by design, because recoverability requires it. Document
  this interaction explicitly; it is the price of recovery.

---

## 9. Metadata minimization (the sealed-sender analog)
Even with perfect content encryption, the relay sees timing/size/frequency.
- **Padding:** pad every `ct` to fixed size buckets.
- **Batching:** batch/store-and-forward where latency allows.
- **Decoupled identity:** `account_id` carries zero PII (§3); no email/phone/Apple ID.
- **Disclosed non-goal:** traffic-analysis resistance is partial; state it in vetting
  docs rather than imply it's solved.

---

## 10. Versioning & crypto-agility
- `v` in every envelope; Argon2id params recorded per `v`; HKDF labels carry `/vN`.
- Upgrade path: new `v` re-encrypts lazily on next write; readers support `v-1`.
- Param baseline (tune on-device, record actual): Argon2id `m=256MiB, t=3, p=1`.

---

## 11. Threat coverage table (put in vetting docs)
| Adversary capability | Transcript | Working memory |
|---|---|---|
| Server / operator (at rest) | ✅ ciphertext only | ✅ ciphertext only |
| Device theft (locked) | ✅ Secure-Enclave wrapped | ✅ |
| TEE break (CVM) during session | ⚠️ chat: no keys present; coding: scoped keys exposed | ⚠️ WMK in TEE RAM exposed |
| Seed compromise | ❌ transcript reconstructable | ❌ readable |
| Network MITM | ✅ (TLS + attestation binding) | ✅ |

---

## 12. Test obligations (H)
- KDF determinism + domain separation (no cross-label key reuse).
- Account-id non-reversibility; zero-PII check.
- Envelope AAD tamper → AEAD fails closed.
- Transcript ratchet: prior-key discard verified; server-blob-only verified.
- WMK never written to disk in clear; discarded on session end (CVM memory probe).
- Two-user: cross-account decrypt impossible; cross-CVM routing blocked.
- SVR: rate-limit + destroy-after-N enforced; server cannot read the wrapped seed.
