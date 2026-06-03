# Contract: Attestation Evidence (multi-regime)  (`/contracts/attestation-evidence.md`)

**Status:** FROZEN for Phase 1 (2026-06-02). Changes require maintainer + project-lead sign-off.
**Owners:** D (client verifier, primary — KEYSTONE), C (CVM emits), E (inference receipts), H (tests).
**Pairs with:** `attestation.md` (the fail-closed algorithm §4; this file makes A1/A2/A3/A5
concrete from the Sprint-1 spike). Realises the **regime-agnostic evidence interface**.

The verifier consumes a **regime-tagged evidence bundle** and dispatches to a regime
adapter. `attestation.md §4`'s fail-closed checks are identical in spirit across regimes;
each maps to regime-specific evidence. Two adapters in Phase 1.

## 1. Common envelope (both regimes)
```
evidence = {
  regime:        "tdx-onchain" | "sev-sigstore",
  challenge:     bytes32,        # SHA-256(eph_pub), bound into the quote/report (att.md §3,§A5)
  measurement:   { ... },        # regime-specific (below), compared to the PINNED set (measurements.md)
  workload_id:   string,         # app_id (tdx) / repo+digest (sev) — expected per tier
  signing_key:   bytes,          # in-TEE key that signs responses (per-response binding)
  raw:           { ... }         # regime-specific raw artifacts for full verification
}
verdict = { ok: bool, reason: CODE, regime, measurement_matched: bool }
```
`reason` ∈ the A7 code table: `QUOTE_SIG_INVALID, TCB_OUT_OF_DATE, MEASUREMENT_UNPINNED,
COMPOSE_MISMATCH, APPID_MISMATCH, BINDING_MISMATCH, NO_LOG_ABSENT, RECEIPT_INVALID,
COLLATERAL_STALE, REGIME_UNSUPPORTED`.

## 2. Regime adapters
### 2.1 `tdx-onchain` (Phala) — verified shape from the spike (`infra/spikes/phala-smoke/`)
`raw = { intel_quote (TDX v4, ~5KB), nvidia_payload (GPU-CC), info{compose_hash, app_id,
app_cert, mr_aggregated, tcb_info, event_log, os_image_hash, key_provider_info},
signing_address, signing_public_key }`.
Verify: (a) `intel_quote` → Intel **DCAP/PCS** root, TCB up-to-date; (b) `nvidia_payload`
→ **NVIDIA** root (GPU-CC); (c) `mrtd`/`rtmr[0..3]` (from quote+`event_log`) + `compose_hash`
+ `app_id` ∈ pinned set AND `compose_hash` matches the **on-chain DstackApp registry**;
(d) `challenge` == quote `report_data[0:32]` (§A5); (e) no-log posture in measured config.
Library: **`Phala-Network/dcap-qvl-swift`** (MIT) for the TDX quote core; dstack/registry
+ NVIDIA-root + event-log glue is BUILT (`docs/oss-reuse-map.md`).

### 2.2 `sev-sigstore` (Tinfoil)
`raw = { sev_snp_report, sigstore_bundle, tls_pubkey, measured_config }`.
Verify: (a) SEV-SNP report → **AMD** root; (b) measurement → **Sigstore transparency-log**
inclusion + the published GitHub-built image digest ∈ pinned set; (c) `tls_pubkey` ==
attested key (cert pinning); (d) `challenge` bound in report. Library: **`tinfoilsh/tinfoil-swift`**
(AGPL-3.0; a referenced optional adapter, NOT bundled — see NOTICE).

## 3. Per-response receipt (every model reply; `gateway-api.md §3` `event: receipt`)
A response is bound to the attested enclave by an **in-TEE signature** over the response
bytes using `signing_key` (tdx: `signing_address` ECDSA; sev: attested key). The client
re-verifies each receipt: signature valid + signer == the handshake-attested key + (tdx)
the per-model attestation report (`GET /v1/attestation/report?model&nonce`) is fresh
(<5 min) and its `compose_hash`/`app_id` ∈ the pinned **inference** set. ✗ → drop response,
mark session untrusted, stop (catches mid-session swap). **Phase-1 task:** pin exactly what
the signature signs over (full body + request binding).

## 4. Pinning & policy
- The pinned `{measurement, workload_id}` set per regime + tier lives in
  `docs/security/measurements.md`. **No runtime TOFU / accept-new** (`attestation.md §6`).
- Interim **dev-pinning** allowed (flagged not-yet-reproducible) until Phase 5.
- **Deployment-tier policy:** `require-attestation` is mandatory for any hosted (T1,
  operator≠user) connection; self-host T0 may set `trusted-self-host` (regime `none`).

## 5. Test obligations (H) — extend `tests/attestation/`
- Per regime: tamper each field (quote/report sig, measurement, compose/digest,
  workload_id, challenge, receipt) → assert `ok=false` with the correct `reason` code.
- Replay a genuine bundle vs a fresh `challenge` → `BINDING_MISMATCH`.
- Mid-session compose/digest change → response dropped + session untrusted.
- Unknown regime → `REGIME_UNSUPPORTED` (fail-closed). Deterministic fixtures per §C4.
