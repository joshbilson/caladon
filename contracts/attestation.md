# Contract: Attestation  (`/contracts/attestation.md`)

**Status:** FROZEN — **AMENDED at Gate 0 (2026-06-02, Josh-approved).** The Gate-0
resolutions in the `docs/security/` notes (§"Gate-0 resolutions")
are APPROVED and **supersede any conflicting clause below** — notably: attestation is
**multi-regime** (TDX/on-chain **and** SEV-SNP/Sigstore adapters, A1); the per-response
receipt is a separate `GET /v1/attestation/report?model&nonce` returning
`intel_quote`+`nvidia_payload`+`info{compose_hash,app_id,…}`+`signing_address`, **not**
the `x-phala-*` headers in §2.2 (A2); the NVIDIA GPU-CC path is in scope (A3);
`report_data` carries the 32-byte client challenge (A5); §4's fail-closed rule applies to
**attested (operator≠user) connections** — self-host tier T0 opts out per
`docs/deployment-tiers.md`. Sprint-2 builds against contract-as-amended. Further changes
require maintainer + project-lead sign-off.
**Owners (build against this):** C (CVM/Infra emits), D (iOS client verifies), E (inference), H (tests).
**Pairs with:** `/contracts/identity-envelope.md` (key flow intersects here).

This contract defines the trust boundary: exactly what evidence each attested
component emits, and exactly what the iOS client checks **before any plaintext
leaves the phone**. If the client cannot complete §4 successfully, it **must not
send** — fail-closed, no exceptions, no fallback to an unverified path.

---

## 1. Scope: two attested components
A chat turn touches **two** enclaves; both are attested, both are verified.

1. **Agent CVM** — Phala dstack Confidential VM (Intel TDX) running Letta +
   Postgres + embeddings. Holds the user's working-memory key *transiently in TEE
   RAM* during a session (see `identity-envelope.md §6`). This is the component the
   client establishes its session with.
2. **Inference enclave** — Phala/Redpill (Intel TDX + NVIDIA H100 CC) running the
   model. The Agent CVM calls it; its attestation is verified by the CVM **and**
   re-checked by the client via the per-response receipt (§5).

The coding tier (Phase 4) uses a **separate** Agent CVM with scoped keys; identical
contract, different app-id and measurement.

---

## 2. Evidence each component emits
### 2.1 Agent CVM (per session, on handshake)
- `tdx_quote` — Intel TDX quote: `mrtd` + `rtmr[0..3]`, signed, chaining to Intel
  DCAP/PCS roots.
- `compose_hash` — dstack compose hash identifying the exact workload image.
- `app_id` — dstack application id.
- `dstack_cert` — the CVM's X.509 cert whose key **is** the channel endpoint; the
  quote's `report_data` binds this session (see §3).
- `event_log` — RTMR event log for measurement reconstruction.
- `registry_ref` — on-chain DstackApp registry entry for `compose_hash`.

### 2.2 Inference enclave (per response)
Phala unified receipt headers on every model response:
- `x-phala-receipt-sig` — signature chaining to the TDX root + on-chain entry.
- `x-phala-compose-hash` — the inference workload's build hash.
- `x-phala-app-id` — expected inference app id (model slug bound).
- `x-phala-no-log` — must be `true`.

> Format is provider-uniform (TDX+H100 or SEV+B-series produce the same receipt
> shape), so one verifier covers all inference backends and any Tinfoil/NEAR
> fallback adapter must emit an equivalent receipt or it is rejected.

---

## 3. Channel binding (prevents relay of a valid quote)
1. Client generates an ephemeral X25519 keypair `(eph_pub, eph_priv)` per session.
2. Client sends `challenge = SHA-256(eph_pub)` as the attestation nonce.
3. CVM returns a quote whose `report_data` **contains `challenge`**.
4. Client derives the session key `SK = X25519(eph_priv, cvm_key_from_cert)` and
   verifies `report_data == SHA-256(eph_pub)`.

This binds the attested enclave to *this* channel. A quote captured from a genuine
enclave cannot be replayed to authenticate a malicious proxy, because the proxy
cannot produce a quote over the client's fresh `eph_pub`.

---

## 4. Client verification algorithm (FAIL-CLOSED)
Run **before** transmitting the working-memory key or any prompt. Any ✗ → abort,
surface a clear "could not verify the server is genuine" error, send nothing.

1. **Quote signature → vendor root.** Verify `tdx_quote` chains to Intel DCAP/PCS
   roots. ✗ if broken/expired.
2. **TCB status.** Quote TCB is up-to-date and **not revoked**. ✗ on `OutOfDate`/
   `Revoked` (configurable allow-list of `SWHardeningNeeded` only, documented).
3. **Measurement pinning.** `mrtd` + `rtmr[*]` ∈ the **pinned known-good set**
   shipped in this client build (see §6). ✗ if not present. **No TOFU. No
   accept-new.**
4. **Compose hash.** `compose_hash` == the value the pinned measurement maps to
   **and** matches `registry_ref` on-chain. ✗ on mismatch.
5. **App id.** `app_id` == expected Agent-CVM id for this tier. ✗ on mismatch.
6. **Channel binding.** `report_data` == `SHA-256(eph_pub)` (§3). ✗ on mismatch.
7. **No-log posture.** Workload declares no-logging (verified via measured config
   / receipt). ✗ if absent.
8. Only if 1–7 pass: derive `SK`, open the channel, proceed to send (per
   `identity-envelope.md`). 

### Per-response (every model reply)
9. Verify `x-phala-receipt-sig` chains to the TDX root + on-chain entry; confirm
   `x-phala-compose-hash`/`x-phala-app-id` match the **pinned inference build** and
   the requested model slug; confirm `x-phala-no-log == true`. ✗ → drop the
   response, mark the session untrusted, stop. This catches a mid-session swap.

---

## 5. Trust chain summary
```
Intel DCAP/PCS root ─┐
NVIDIA CC root ──────┼─► Agent CVM quote (client verifies, §4.1–8)
on-chain registry ───┘        │
                              ├─► CVM verifies inference enclave before sending prompt
                              └─► client re-verifies inference receipt per response (§4.9)
```
The client's trust root is **the silicon vendors + the on-chain registry**, never
Phala's word and never the operator.

---

## 6. Measurement pinning & update policy
- The client ships a **pinned set** of allowed `{mrtd, rtmr[*], compose_hash,
  app_id}` tuples for both enclaves.
- Each tuple maps to a **reproducible build** (see Phase 5): a reviewer rebuilds the
  enclave image from public source and confirms the measurement equals the pinned
  value. The mapping table lives in `/docs/security/measurements.md`.
- **Updating the pinned set happens only via a signed client app update.** Never
  accept a new measurement at runtime. This closes the "operator swaps the binary"
  hole — a swapped workload produces an unpinned measurement and the client refuses.

---

## 7. Key-release interaction (cross-ref `identity-envelope.md`)
Two distinct keys — do not conflate:
- **dstack KMS app-key:** released to the CVM by dstack KMS *only after the CVM's
  own attestation passes*; encrypts the CVM's local disk state (defense in depth).
  The operator never holds it.
- **User working-memory key (WMK):** derived from the user's seed on-device; sent
  into the CVM **over the §4-verified channel only**, held in TEE RAM for the
  session, discarded on session end. This is the honest asymmetry — the user's key
  enters a remote (attested) TEE. Document it; never call it "E2E".

---

## 8. Failure modes (all → fail-closed, send nothing)
Invalid/expired quote · TCB out-of-date or revoked · measurement not in pinned set
· compose-hash ≠ registry · unexpected app-id · channel-binding mismatch · missing
no-log · missing/invalid response receipt · network MITM (binding catches it).
Each surfaces a distinct diagnostic code to the user; none degrades to an
unverified send.

---

## 9. Residual trust & explicit non-goals (state in vetting docs)
**Trusted:** Intel TDX + NVIDIA CC silicon correctness; DCAP/PCS + NVIDIA roots;
the on-chain registry integrity; that the pinned measurement = audited source.
**NOT covered by attestation:** traffic/metadata analysis (see
`identity-envelope.md §9`); TEE side-channel/fault attacks (acknowledge the
historical class); the working-memory-in-TEE asymmetry; anything after plaintext
legitimately exists inside a verified enclave. Attestation makes the operator
*unable to read* under sound-hardware assumptions; it is **not** "no possibility of
leaks".

---

## 10. Test obligations (H)
- Tamper each field (quote sig, measurement, compose-hash, app-id, report_data,
  receipt) → assert the client **refuses to send**.
- Replay a genuine quote against a fresh `eph_pub` → assert binding failure.
- Mid-session compose-hash change → assert response dropped + session marked
  untrusted.
- Network MITM with a self-signed cert → assert abort.
- "Happy path" → assert plaintext is transmitted **only** after all checks pass.
