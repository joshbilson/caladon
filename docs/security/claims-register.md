# Caladon — Claims Register (canonical privacy-claims source of truth)

**Status:** Phase-0 / Sprint-1 foundational doc. The **#1 acceptance criterion**:
getting a claim's wording wrong fails the independent security review on its own,
before any code is examined (`the internal status notes`; `MASTER-HANDOVER §5`).
**Owner:** the team. **Enforcement:** a CI claims-lint (owned by **the team**, in
`tests/leak/` — referenced here, **not** implemented here) greps every PR, string,
and doc against this register.

> **The system is *attested confidential computing*, NOT end-to-end encryption.**
> The coding tier is "attested", never "E2E". See `docs/security/threat-model.md`.

---

## 1. FORBIDDEN phrases (CI fails on any occurrence outside the allowlist)

Exact strings, **lowercase**, so the linter greps **case-insensitively**. These are
false for any system that computes the model on a remote machine, including a TEE.

```
client-side e2e
client-side end-to-end
end-to-end encrypted
zero-knowledge
zero knowledge
no possibility of leaks
we can't read your data
we cannot read your data
impossible to leak
```

Why each is false / forbidden:
- **`client-side e2e` / `client-side end-to-end` / `end-to-end encrypted`** — the
  key is released into a remote enclave so the model can run; this is attested
  confidential computing, not E2E. Never apply "E2E" to the whole system, and
  **never** to the coding tier.
- **`zero-knowledge` / `zero knowledge`** — we are not a ZK system; the operator is
  *attested-not-to-read*, conditional on sound hardware + correct attestation +
  audited enclave code.
- **`no possibility of leaks` / `impossible to leak`** — TEEs have a real
  side-channel/fault break history (`attestation.md §9`); strong, not absolute.
- **`we can't read your data` / `we cannot read your data`** (unqualified) — only
  defensible *with* the conditional ("...unless the TEE hardware or its attestation
  is compromised"). The unqualified form is forbidden; use the approved claim in §2.

> **Adjacent traps (reviewer judgement, not literal-grep):** "trustless", "fully
> private", "no one can ever see your data", calling the **coding tier** "E2E" or
> "end-to-end", or describing the **current built state** as "confidential" (it is
> trusted-host v0). These won't all be caught by the literal lint — G screens for
> them in the per-phase claims pass.

---

## 2. APPROVED claim strings

### 2.1 The defensible claim (use VERBATIM where a positive claim is needed)

> *"All inference and agent memory run inside hardware TEEs whose attestation the
> app verifies before any data is sent. The operator cannot read your data unless
> the TEE hardware or its attestation is compromised. Per-user data is encrypted
> under a key derived from a secret only you hold."*

### 2.2 Per-tier variants

- **Chat / personal tier (strongest):**
  > *"Your chat runs inside a hardware TEE whose attestation the app verifies
  > before sending anything. Your working-memory key is derived on your device from
  > a secret only you hold and is released into the verified enclave for the session
  > only. Your conversation transcript is forward-secret and its keys never leave
  > your device."*

- **Coding tier (attested, NEVER "E2E"):**
  > *"The coding agent runs inside a separate hardware TEE with attestation the app
  > verifies. It receives a key scoped to coding-project data only — never your
  > personal data. This tier is **attested confidential**, not end-to-end
  > encrypted: the key is held in the remote enclave's memory while the loops run."*

### 2.3 Required honest disclosures (state alongside positive claims)

- **Asymmetry:** "the working-memory key enters a remote attested TEE; it is not
  device-only — this is why the system is attested-confidential, not E2E"
  (`identity-envelope.md §6`).
- **Forward-secrecy split:** "forward secrecy on the conversation transcript;
  working memory is seed-recoverable and therefore not forward-secret, because an
  agent must re-read its memory" (`identity-envelope.md §5`).
- **Metadata:** "traffic-analysis resistance is partial; timing, sizes, and
  frequency are visible to the relay" (`identity-envelope.md §9`).
- **Residual trust:** "security relies on Intel TDX + NVIDIA CC silicon, the
  DCAP/PCS + NVIDIA roots, the on-chain registry, and pinned-measurement ==
  audited-source" (`attestation.md §9`, `threat-model.md §5`).
- **Current state:** label M1a/M1b "trusted-host v0", not confidential, until the
  CVM migration lands and the client verifies attestation (`the internal status notes`).

---

## 3. Usage rule

- Every PR, user-facing string, marketing line, and doc is checked against this
  register. A positive privacy claim must be one of the §2 approved strings (or a
  clearly-equivalent qualified variant approved by G in the per-phase claims pass).
- The CI **claims-lint** (the team, `tests/leak/`) enforces §1 mechanically and
  flags new positive-claim strings for G review. G runs a manual claims-discipline
  pass every phase, with a hard gate at Phase 5 (`MASTER-HANDOVER §7`,
  BUILD-PLAN Risk #6, Phase 5).

---

## 4. Linter allowlist (for the team's claims-lint design)

**Problem:** the forbidden phrases in §1 legitimately appear in docs that describe
what we **do NOT** claim (this register, the threat model, READMEs, status, and
handover docs). A naive grep would flag those as violations (false positives).

**Solution:** the claims-lint must **exclude (allowlist) the following paths** —
files whose job is to enumerate or refute the forbidden phrases:

```
docs/security/claims-register.md      # this file (defines the forbidden list)
docs/security/threat-model.md         # quotes forbidden phrases to refute them
docs/security/plaintext-exposure-map.md
docs/security/reproducible-builds.md
docs/security/measurements.md
README.md                             # documents what we do NOT claim
the internal status notes                             # threat-model section quotes the forbidden list
internal handover notes        # §5 quotes the forbidden list
internal architecture notes   # legacy file; see note below
the internal build plan       # §1 quotes the forbidden list
```

Lint design guidance for H:
- Match **case-insensitively** against the exact §1 strings.
- Apply the lint to **all other** tracked text/markdown/source/UI-string files; the
  allowlist above is the only exemption set.
- Keep the forbidden list and the allowlist **sourced from this file** (or a machine
  shape derived from it) so the register stays the single source of truth — don't
  hard-code a second copy in the test.
- The lint is **advisory in Phase 0** (docs still being written) and a **hard gate
  by Phase 5**.

> **legacy file that itself overclaims**: its line 2 / §1 call Caladon
> "end-to-end-encrypted" and "zero-trust", and §3 (Tier 1) describes pure
> device-side orchestration. These contradict the locked attested-confidential model
> (`MASTER-HANDOVER §5`) and the locked Letta-in-CVM decision (`MASTER-HANDOVER §3`,
> BUILD-PLAN §0). It is allowlisted above **only so CI doesn't break today**, but it
> needs a claims-discipline rewrite (G, Phase 5 / `the internal status notes` "update the design
> spec"). Flag at Gate 0. The frozen contracts are constraint-clean — fix the legacy
> doc to them, not vice-versa.

---

## 5. Cross-references

- `docs/security/threat-model.md` — adversaries, residual trust, non-goals.
- `docs/security/plaintext-exposure-map.md` — where plaintext exists + controls.
- `contracts/attestation.md §9` — residual trust & non-goals.
- `contracts/identity-envelope.md §5, §6, §9, §11` — FS split, WMK asymmetry,
  metadata, threat coverage.
- `tests/leak/` (the team) — the CI claims-lint implementation.
