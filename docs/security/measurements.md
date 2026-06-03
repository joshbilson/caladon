<!-- GENERATED FILE — do not edit by hand.
     Source of truth: infra/transparency/measurements.source.json
     Regenerate:      python3 infra/transparency/gen-measurements.py
     Verified in CI:  tests/transparency/test_measurements_generated.py -->

# Caladon — Pinned-Measurement Registry

**Status:** SEEDED (chat Agent CVM, dev-pinned) — schema + policy defined; the first real **dev-pinned** tuple is recorded from the live `caladon-gw` v1 gateway CVM (2026-06-03, §2.1). Remaining tuples are seeded as those enclave images are produced; all graduate to reproducible at Phase 5.
**Owner:** the team (registry/doc) with **C** (CVM measurements) and **E** (inference measurements); **D** consumes the pinned set; **H** tests pinning fail-closed.
**Referenced by:** `contracts/attestation.md §6` ("The mapping table lives in `/docs/security/measurements.md`").

> This is the **mapping table** the iOS client pins. The client ships a pinned set
> of allowed `{mrtd, rtmr[*], compose_hash, app_id}` tuples for both enclaves; each
> tuple maps to a reproducible build a reviewer can rebuild from public source and
> confirm the measurement matches (`attestation.md §6`, `reproducible-builds.md`).

---

## 1. Registry schema

| Column | Meaning |
|---|---|
| `tier` | `chat` \| `coding` |
| `component` | `Agent CVM` \| `Inference enclave` |
| `mrtd` | Intel TDX measurement of the TD (boot measurement) |
| `rtmr[0..3]` | Runtime measurement registers (extend the boot chain) |
| `compose_hash` | dstack compose hash identifying the exact workload image |
| `app_id` | dstack application id (inference: model slug bound) |
| `reproducible-build-ref` | Pointer to the build recipe / artifact that reproduces this measurement (`reproducible-builds.md`) |
| `source-ref` | Git ref / tag of the public source that the build was produced from |

---

## 2. Pinned set

### 2.1 Agent CVM (Phala dstack, Intel TDX)

**chat / gateway-v1 (direct attested inference, no Letta) — `caladon-gw`, dstack 0.5.x, `tdx.small`.**
Captured live 2026-06-03 from the running CVM (`infra/spikes/gw-v1-live/cvm-attestation.json`). Compose: `infra/cvm/dstack-compose.gw-v1.yml`. **dev-pinned / not-yet-reproducible** (image is pinned by tag `:gw-v1`, not digest — digest-pin is a follow-up; Phase-5 reproducible-build ref TBD).

| field | value |
|---|---|
| tier / component | `chat` / Agent CVM (gateway v1, + dstack-ingress for gw.caladon.ai) |
| mrtd | `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077` |
| rtmr0 | `68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96` |
| rtmr1 | `07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c` |
| rtmr2 | `a2a58c9a959a4fa44bd6da0c97a2270c051faf12084cfe91ae900e4fdff6cdd4f69a82005e04ee920f231497894d677f` |
| rtmr3 | `3e88269c02243b7ac42343576f1623f719e11f24e5d374ef0c918681e11fe09211c1e3192103ab64b5b0ebfeffe5cc74` |
| compose_hash | `47bae9194b7c52ed006f6af0e31a9e8eccdf2a9785985e820b632e4a41c5cc17` |
| os-image-hash | `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9` (mrtd/rtmr0 unchanged dev→prod ⇒ same base) |
| app_id | `6643c22f716a1a48eab209feda535db501659175` |
| OS image | **production (`--no-dev-os`)** — root SSH break-glass REFUSED (verified: ssh → "Connection closed", not connectable). Apple-PCC req #3 (no privileged runtime access). |
| domain | `gw.caladon.ai` (LE cert provisioned in-CVM via dstack-ingress DNS-01; CAA-locked to this TEE) |
| reproducible-build-ref | _dev-pinned / not-yet-reproducible_ |
| source-ref | `main` @ deploy (image `ghcr.io/joshbilson/caladon-gateway:gw-v1` digest `sha256:ae613a90…`, compose `dstack-compose.gw-v1.yml`) |

> Confirmed across THREE deploys (incl. the `--no-dev-os` production redeploy): **`mrtd` + `rtmr0..2`
> are stable** (`f06dfda6…` / `68102e7b…` / `07e6f51a…` / `a2a58c9a…`) — stable EVEN across the
> dev→production OS image; **`app_id` + `rtmr3` change per deploy** (…→6643c22f, …→3e88269c);
> `compose_hash` (`47bae919`) is stable while the compose file is unchanged. **Pinning policy:** pin
> `mrtd` + `rtmr0..2` + `compose_hash` + `os-image-hash`; treat `app_id`/`rtmr3` as per-instance
> (advisory). The `--no-dev-os` redeploy added the no-SSH property without changing the stable four.

> ⚠ **rtmr3 + app_id are deploy-specific.** dstack derives `app_id` per deployment (not purely
> from compose_hash), and rtmr3 binds the app-id/compose-hash/instance-id event log — so a
> **redeploy changes app_id + rtmr3** even with an identical compose. `mrtd`/`rtmr0..2` +
> `compose_hash` + `os-image-hash` are the stable identity; pin those and treat app_id/rtmr3 as
> per-instance. (This also drives the gw.caladon.ai custom-domain churn noted in the internal status notes.)

**chat / full-backbone Agent CVM (Letta + Postgres + embeddings) — `infra/cvm/dstack-compose.yml`**:

| tier | component | mrtd | rtmr[0..3] | compose_hash | app_id | reproducible-build-ref | source-ref |
|---|---|---|---|---|---|---|---|
| chat | Agent CVM (full) | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ |
| coding | Agent CVM | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ |

### 2.2 Inference enclave (Phala/Redpill: Intel TDX + NVIDIA H100 CC; Tinfoil/NEAR fallback)

| tier | component | mrtd | rtmr[0..3] | compose_hash | app_id | reproducible-build-ref | source-ref |
|---|---|---|---|---|---|---|---|
| chat | Inference enclave | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ |
| coding | Inference enclave | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ | _(empty)_ |

> The coding tier uses a **separate** Agent CVM with **scoped keys** — identical
> contract, **different `app_id` and measurement** (`attestation.md §1`). Fallback
> inference adapters (Tinfoil/NEAR) must emit an equivalent receipt and have their
> own pinned tuple, or they are rejected (`attestation.md §2.2`).

---

## 3. Interim pinning policy (until reproducible builds exist — Phase 5)

Reproducible builds do not exist until Phase 5. Until then:

- **Dev builds are measured and recorded here**, each row explicitly flagged
  **`dev-pinned / not-yet-reproducible`** in the `reproducible-build-ref` column.
  This documents provenance honestly: the measurement is real, but it has not yet
  been independently reproducible from public source.
- **Runtime NEVER accepts an unpinned measurement.** No TOFU. No accept-new. A
  measurement not present in this pinned set → the client **refuses to send**
  (`attestation.md §4.3, §6`; fail-closed per `attestation.md §8`).
- **The pinned set updates ONLY via a signed client app update** — never at runtime,
  never via a server-pushed list. This is what closes the "operator swaps the
  binary" hole: a swapped workload produces an unpinned measurement and the client
  refuses (`attestation.md §6`).
- **Phase-5 graduation:** when reproducible builds land, each `dev-pinned` row is
  replaced by a reproducible tuple whose `reproducible-build-ref` points to a recipe
  a reviewer can rebuild from `source-ref` and confirm the measurement matches
  (`reproducible-builds.md`).

> The interim flag is a **provenance label, not a relaxation** of fail-closed
> behavior. A `dev-pinned` measurement is still pinned; an *unpinned* measurement is
> still always refused.

---

## 4. Transparency log (Apple-PCC req #5 + Confer)

Each pinned tuple above + its reproducible-build hashes are published as a
**signed, append-only Sigstore Rekor entry** so the registry is publicly
auditable and tamper-evident: a stranger can fetch the entry, verify the
signature, and confirm an **inclusion proof** against the log's signed tree
head — establishing that this exact measurement set was published and has not
been silently changed. Tooling + procedure: `infra/transparency/` (`publish.sh`,
`verify.sh`, `README.md`). The log is the *transparency* leg; the *non-targetability*
leg (Apple-PCC req #4 — the client cannot be steered to a specific compromised
node) is designed in `docs/security/non-targetability.md`.

---

## 5. Cross-references

- `contracts/attestation.md §4, §6, §8` — verification algorithm, pinning policy,
  failure modes.
- `docs/security/reproducible-builds.md` — how a row graduates from `dev-pinned` to
  reproducible.
- `docs/security/non-targetability.md` — Apple-PCC req #4 design (OHTTP relay / IP
  hiding / single-use credentials).
- `infra/transparency/` — Sigstore Rekor publish/verify tooling for this registry.
- `docs/security/threat-model.md §3, §5` — malicious-binary-swap adversary;
  "pinned == audited source" as residual trust.
