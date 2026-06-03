# Caladon — Threat Model

**Status:** Phase-0 / Sprint-1 foundational doc. This is the acceptance bar that
all later work is measured against (BUILD-PLAN Gate 0).
**Owner:** the team (Security / Audit / Docs).
**Derived from (do not contradict):** `the internal status notes` §"🔒 Threat model, claims, and
plaintext-exposure inventory"; `internal handover notes` §5–6;
`contracts/attestation.md` §5–9; `contracts/identity-envelope.md` §5–6, §9, §11;
`internal architecture notes` §10.

> **Read the claims discipline first** (`docs/security/claims-register.md`). The
> wording of every positive privacy statement is itself an acceptance criterion:
> getting it wrong fails the independent security review before any code is read.

---

## 0. One-line characterization

Caladon is **attested confidential computing**, **not** end-to-end encryption.
Plaintext exists **only** on the user's device and inside a hardware TEE whose
attestation the iOS client verifies, fail-closed, before any data is sent.
Everywhere else — gateway, at-rest store, network — sees ciphertext only.

The approved positive claim (use **verbatim** wherever a positive claim is made):

> *"All inference and agent memory run inside hardware TEEs whose attestation the
> app verifies before any data is sent. The operator cannot read your data unless
> the TEE hardware or its attestation is compromised. Per-user data is encrypted
> under a key derived from a secret only you hold."*

---

## 1. Assets (what we protect)

| Asset | What it is | Where it legitimately exists in plaintext |
|---|---|---|
| **Seed** | 256-bit root secret; identity + encryption root in one (`identity-envelope.md §2`) | Device Secure Enclave only; never persisted outside it; never sent to any server |
| **WMK** (working-memory key) | `HKDF(root, "swifty/working-mem/v1")`; decrypts Letta's living state | Device; **and transiently in Agent-CVM TEE RAM during a session** (the honest asymmetry, §4 below) |
| **Transcript** | Append-only chat/coding log | Device (chat: client-side ratchet); coding transcript generated in-CVM |
| **Working memory** | Letta's re-read-every-turn agent state | Device; decrypted inside the Agent CVM under WMK |
| **`account_id`** | `HKDF(root, "swifty/account-id/v1")`; routing identifier, zero PII, non-reversible | Gateway sees it (for routing only); carries no identity signal |
| **Metadata** | Timing, request/response sizes, frequency, active hours, model choice | Visible to the relay/network even with perfect content confidentiality (§6) |

---

## 2. Trust boundary

```
        TRUSTED                                  UNTRUSTED (ciphertext only)
┌───────────────────────┐    verified channel   ┌──────────────────────────────┐
│  iOS device           │  ───── SK / §4 ─────▶  │  Gateway (ciphertext router) │
│  - seed (Secure Encl.)│                        │  At-rest store (envelopes)   │
│  - WMK derivation     │                        │  Network / relay             │
│  - attestation verifier│                       └──────────────────────────────┘
└───────────────────────┘                                      │
        │  WMK only over §4-verified channel                   │ routes by account_id
        ▼                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  ATTESTED TEE BOUNDARY (plaintext allowed here, and only here, off-device)     │
│  - Agent CVM (Phala dstack, Intel TDX): Letta + Postgres + embeddings          │
│      WMK held in TEE RAM for the session, discarded on session end             │
│  - Inference enclave (Phala/Redpill: Intel TDX + NVIDIA H100 CC): the model    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Rule:** plaintext exists ONLY (a) on the user's device and (b) inside an attested
TEE the client has verified. The gateway, the at-rest store, and the network must
never hold plaintext or any decryption key. See
`docs/security/plaintext-exposure-map.md` for the per-point build requirements.

The client's trust root is **the silicon vendors + the on-chain registry**, never
Phala's word and never the operator (`attestation.md §5`).

---

## 3. Adversary model — capability per adversary

| Adversary | Assumed capability | Outcome under the design | Residual / caveat |
|---|---|---|---|
| **Host / operator** (Netcup today; Phala host under target) | Full control of the host OS, disk, RAM outside the TEE, gateway process, at-rest store | Sees only `envelope` ciphertext + `account_id`; **no key, no decryption capability** (`identity-envelope.md §4`). Cannot read inside the attested TEE under sound-hardware assumptions | Sees metadata (§6); a binary swap is caught by measurement pinning (§3 last row) |
| **Inference provider** (Phala/Redpill, or Tinfoil/NEAR fallback) | Runs the model host; can attempt to log or inspect | Receipt must carry `x-phala-no-log == true`; receipt re-verified per response (`attestation.md §4.9`); prefer transparency-log / BYO-weights builds | Trust in the provider's attestation that the expected build runs; mitigated by client verification + multi-provider abstraction |
| **Network MITM** | Intercept, modify, replay traffic; present self-signed certs | Channel binding (`attestation.md §3`): `report_data == SHA-256(eph_pub)` binds the attested enclave to *this* session. A captured quote cannot be replayed onto a malicious proxy. Self-signed cert → abort | TLS terminates **inside** the attested boundary (dstack-gateway cert carries its TDX quote), not at a plain proxy |
| **Device theft (locked)** | Physical possession of a locked device | Seed wrapped in Secure Enclave, Keychain `…WhenUnlockedThisDeviceOnly`, no iCloud, excluded from backups (`identity-envelope.md §2, §11`) | An **unlocked** stolen device is out of scope (attacker has the user's session) |
| **Seed compromise** | Attacker obtains the user's seed | **Full compromise of that user's data.** Transcript reconstructable (seed re-derives `transcript_root`), working memory readable (`identity-envelope.md §11`). No recovery-without-seed-leak tradeoff is free (§8/SVR) | This is the explicit cost of seed-recoverable working memory + optional recovery; static seed = **no forward secrecy** against seed leak. Documented, not hidden |
| **Malicious server-binary swap** | Operator silently replaces the CVM/inference workload with a logging variant | A swapped workload produces an **unpinned measurement**; the client refuses to send. No TOFU, no accept-new (`attestation.md §6`). Mid-session swap caught by per-response receipt re-check (`attestation.md §4.9`) | Only as strong as "pinned measurement == audited source" (§5) and reproducible builds (Phase 5, `reproducible-builds.md`) |

---

## 4. The defensible claim, scoped per tier

The positive claim in §0 is the **whole-system** statement. Per tier:

- **Chat / personal tier — strongest story.** Letta-in-CVM: the WMK is derived
  on-device and released into the Agent CVM **only over the §4-verified channel**,
  held in TEE RAM, discarded on session end. The **chat transcript ratchet lives
  client-side** — the CVM never holds chat-transcript keys (`identity-envelope.md
  §5.1, §6`). Strongest key custody short of device-only inference.
- **Coding tier — "attested confidential", NEVER "E2E".** Letta + Ralph/multi-agent
  loops run unattended inside a **separate** Phala CVM with **per-tier scoped keys**
  (coding-project data only — never the personal WMK/transcript_root,
  `identity-envelope.md §3`). Because the loops are unattended, prompt assembly and
  the coding transcript ratchet happen **inside** the CVM, which therefore
  transiently holds the (coding-scoped) keys. This is weaker than the chat tier and
  must always be scoped as "attested", never ride under a whole-system E2E label
  (`MASTER-HANDOVER §5`; `architecture-handoff §10`).

**The honest asymmetry (state in every vetting doc):** the chat-tier key is
device-derived but **enters a remote attested TEE** (the WMK); the coding-tier key
is **released into a remote attested CVM**. Neither tier is device-only inference.
The only architecture that earns the literal "the server cannot read it" claim is
on-device inference, which the project consciously rejected (it sacrifices the 35B
brain) — see `the internal status notes` and `MASTER-HANDOVER §5`.

---

## 5. Residual trust — what we MUST trust (cannot be eliminated)

A reviewer will demand this list. Under the design, security reduces to trusting:

1. **Silicon correctness:** Intel TDX + NVIDIA CC hardware behaves as specified
   (isolation, measured boot, quote generation are sound).
2. **Attestation roots:** Intel DCAP/PCS roots and the NVIDIA CC root are authentic
   and uncompromised; the on-chain DstackApp registry has integrity
   (`attestation.md §5, §9`).
3. **Pinned measurement == audited source:** the `{mrtd, rtmr[*], compose_hash,
   app_id}` tuple the client pins corresponds to the public, audited source — i.e.
   reproducible builds actually reproduce (`attestation.md §6`,
   `reproducible-builds.md`).
4. **dstack KMS key-release:** the dstack KMS releases the CVM's app-key only after
   the CVM's own attestation passes; the operator never holds it (`attestation.md §7`).

If any of these breaks, the operator-cannot-read guarantee may not hold. This is
exactly why the claim is conditional ("...unless the TEE hardware or its
attestation is compromised") and not absolute.

---

## 6. Explicit non-goals (out of scope — disclose, do not let them be "caught")

- **Traffic / metadata analysis — partial mitigation only.** Even with perfect
  content confidentiality, the relay/network sees timing, request/response sizes,
  frequency, active hours, and model choice (`identity-envelope.md §9`). Mitigated
  (not solved) by fixed-size payload padding, batching/store-and-forward, and an
  `account_id` fully decoupled from identity. **Metadata is data**; we disclose
  traffic-analysis resistance as partial, never imply it is solved
  (`MASTER-HANDOVER §5`, `the internal status notes`).
- **TEE side-channel / fault attacks — acknowledged break class.** TEEs have a real
  history of side-channel and fault-injection breaks (`the internal status notes`; `attestation.md
  §9`). The design is strong, not "impossible to leak". We do not defend against a
  novel hardware break; we bound it (the claim is explicitly conditional on sound
  hardware).
- **The working-memory-in-TEE asymmetry.** Working memory **must** be re-read every
  turn, so it cannot be forward-secret and the WMK must enter the TEE
  (`identity-envelope.md §5.2, §6`). A TEE break *during a session* exposes the WMK
  in TEE RAM and (coding tier) the scoped ratchet keys (`identity-envelope.md §11`).
- **Seed compromise.** A leaked seed reconstructs the transcript and reads working
  memory (§3; `identity-envelope.md §8.2, §11`). No recovery path removes this;
  optional SVR recovery deliberately *re-introduces* it (recoverability requires it).
- **Unlocked / compromised device, malicious OS, jailbreak.** Plaintext exists on
  device by necessity; an attacker with an unlocked device or device-level code
  execution is outside the model.
- **Generative-UI client-side exfil** is **in** scope and a HARD GATE (see §8); not
  a non-goal — listed here only to disambiguate.

---

## 7. Threat-coverage table (reproduced + expanded from `identity-envelope.md §11`)

Original two-column table, expanded with the additional adversaries from §3 and a
"covered by" column citing the control.

| Adversary capability | Transcript | Working memory | `account_id` / metadata | Covered by |
|---|---|---|---|---|
| **Server / operator (at rest)** | ✅ ciphertext only | ✅ ciphertext only | ⚠️ `account_id` visible (routing, zero-PII); metadata visible | Encryption envelope (`id-env §4`); ciphertext-router gateway |
| **Network MITM** | ✅ (TLS + attestation binding) | ✅ | ⚠️ sizes/timing visible | Channel binding (`attestation §3`); TLS-in-CVM |
| **Device theft (locked)** | ✅ Secure-Enclave wrapped | ✅ Secure-Enclave wrapped | ✅ seed not extractable | Keychain `…WhenUnlockedThisDeviceOnly`, no-iCloud, no-backup (`id-env §2`) |
| **Inference provider** | ✅ ciphertext to it; receipt-gated | ✅ never sent raw to it | ⚠️ model choice / token volume visible | `x-phala-no-log`; per-response receipt re-check (`attestation §4.9`) |
| **Malicious binary swap** | ✅ refuses to send to unpinned build | ✅ same | n/a | Measurement pinning, no-TOFU (`attestation §6`); receipt re-check |
| **TEE break (CVM) during session** | ⚠️ chat: no transcript keys present; coding: scoped ratchet keys exposed | ⚠️ WMK in TEE RAM exposed | ⚠️ exposed | Bounded by claim conditionality; acknowledged non-goal (§6) |
| **Seed compromise** | ❌ transcript reconstructable | ❌ readable | ❌ derivable | None — explicit residual (§6); price of recoverable working memory |

Legend: ✅ protected · ⚠️ partial / disclosed limitation · ❌ not protected (by design).

---

## 8. Mandatory in-scope controls (keystones — failure makes the claim false)

These are not hardening; they are the boundary:

- **Fail-closed attestation** (`attestation.md §4`): the client runs the full
  verification algorithm and **sends nothing** on any ✗. No fallback to an
  unverified path.
- **Measurement pinning, no TOFU** (`attestation.md §6`): pinned set updates only
  via a signed client app update.
- **Channel binding** (`attestation.md §3`): session key bound to the attested
  enclave so a valid quote can't be proxied to a bad enclave.
- **Ciphertext-only off-device** (plaintext-exposure map rows 1–3): gateway, Letta
  at rest, and embeddings must never see plaintext on a trusted host.
- **Fail-closed no-logging** of prompts/responses everywhere (row 5).
- **Generative-UI WKWebView hard sandbox (HARD GATE):** model-emitted HTML/SVG is
  attacker-influenced; render with CSP denying all origins, **no JS bridge to
  native, no Keychain access, strict tag allowlist** — otherwise it can exfiltrate
  decrypted on-device data, bypassing all server-side TEE work
  (`the internal status notes`; BUILD-PLAN Phase 3).

---

## 9. Cross-references

- Claims discipline & forbidden/approved strings: `docs/security/claims-register.md`
- Per-point plaintext build requirements: `docs/security/plaintext-exposure-map.md`
- Pinned-measurement registry: `docs/security/measurements.md`
- Reproducible-build plan: `docs/security/reproducible-builds.md`
- Attestation interface (FROZEN): `contracts/attestation.md`
- Identity / encryption envelope (FROZEN): `contracts/identity-envelope.md`
- Live state & decisions: `the internal status notes`; locked decisions: `internal handover notes`
