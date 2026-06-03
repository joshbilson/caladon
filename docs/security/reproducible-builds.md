# Caladon — Reproducible Builds Plan (SKELETON)

**Status:** SKELETON — Phase-5 work (`MASTER-HANDOVER §7`, BUILD-PLAN Phase 5).
This file states the *plan and procedure*; the recipes/tooling are built in
Phase 5. **Owner:** the team (with **C** for enclave images, **D** for the iOS
client). Risk #2 in the register (BUILD-PLAN §6 / `MASTER-HANDOVER §8`).
**Referenced by:** `contracts/attestation.md §6`; `docs/security/measurements.md §3`.

> **Why this is load-bearing:** the security claim reduces to "**pinned measurement
> == audited public source**" (`threat-model.md §5`). Reproducible builds are what
> make that statement *checkable by a stranger* rather than taken on faith. Until
> they exist, measurements are `dev-pinned / not-yet-reproducible`
> (`measurements.md §3`). Done = "a stranger can rebuild the client + enclave from
> public source and confirm the hashes match what the client pins"
> (`MASTER-HANDOVER §11`).

---

## 1. Two reproducibility targets

### 1.1 Enclave images (Agent CVM + Inference enclave)
- **What is measured:** the dstack workload → `{mrtd, rtmr[0..3], compose_hash,
  app_id}` (the tuple pinned in `measurements.md`).
- **Goal:** a reviewer rebuilds the enclave image from public source and confirms
  the resulting measurement **equals the pinned value**. This is the Tinfoil /
  Sigstore-transparency-log bar (`the internal status notes`; `architecture-handoff §3`).
- **Scope:** both the Agent CVM (Letta + Postgres + embeddings) and, where the
  build is ours (BYO-weights GPU TEE), the inference workload. For hosted inference
  slugs we cannot rebuild, prefer a provider with a **transparency log**
  (Tinfoil/Sigstore) over an unrebuildable slug (`the internal status notes` row 4).

### 1.2 iOS client
- **What is measured:** the app binary / build artifact a reviewer compares against
  a build produced from public source.
- **Goal:** a reviewer rebuilds the client from public source and confirms the
  artifact matches the published build — establishing that the pinned-measurement
  set and the attestation verifier are exactly what the source says.

---

## 2. Rebuild-and-confirm procedure (skeleton)

For each pinned tuple in `measurements.md`:

1. **Publish** the exact source ref (`source-ref`) and a deterministic build recipe
   (`reproducible-build-ref`): pinned toolchain, pinned base images, pinned
   dependency hashes, no embedded timestamps/build-host entropy.
2. **Reviewer rebuilds** from `source-ref` using the published recipe in a clean
   environment.
3. **Reviewer derives the measurement** from the rebuilt artifact (enclave: derive
   `mrtd`/`rtmr[*]`/`compose_hash`; client: hash the artifact).
4. **Reviewer confirms** the derived measurement **==** the value pinned in the
   client build (cross-checked against the on-chain registry for the enclave,
   `attestation.md §4.4`).
5. **On match:** the `dev-pinned` flag is removed and the row graduates to a
   reproducible tuple (`measurements.md §3`).

---

## 3. The App-Store re-sign gap (the reproducible sideload is the vetting artifact)

- The App Store **re-signs / re-encrypts** the binary, breaking bit-for-bit
  verification of the App-Store build against a from-source rebuild
  (`architecture-handoff §6`; BUILD-PLAN Risk #2; `MASTER-HANDOVER §8`).
- **Therefore the reproducible *sideload* build is the load-bearing vetting
  artifact** — that is what a reviewer verifies against source. The App Store
  channel exists for low-friction distribution ("Data Not Collected", no telemetry)
  but is **not** the verification path.
- Distribution is therefore **dual-channel** (post-MVP): App Store **plus** a
  reproducible sideload/self-build path; published hashes are the keystone of the
  vetting story (`architecture-handoff §6`).

---

## 4. Open items / to fill in at Phase 5

- Exact deterministic build recipe per target (toolchain pins, base-image digests,
  dependency lockfiles, source-date-epoch handling).
- The publication channel for hashes + recipes (audit-readiness package).
- How fallback inference providers (Tinfoil/NEAR) prove their build provenance to
  the same bar (transparency log vs. our-rebuild).
- Tooling to derive `mrtd`/`rtmr[*]` from a rebuilt dstack image for reviewer use.

---

## 4b. Tooling (Phase-5 — built)

The deterministic build recipes the §4 plan calls for now exist, under
**`infra/reproducible/`** (see its `README.md` for the full procedure):

- **`build-caladon-core-wasm.sh`** — reproducibly builds the web trust-core
  `caladon_core_bg.wasm` (sealed-channel crypto + dcap-qvl verifier). Pins: toolchain via
  `caladon-core/rust-toolchain.toml` (`rustup`, fail-closed on mismatch), `--locked`
  Cargo.lock, `SOURCE_DATE_EPOCH=0`, `--remap-path-prefix`, and `wasm-opt` **skipped**
  (binaryen is not version-pinned). **Verified reproducible** 2026-06-03 (`9c4fb7e`): two
  clean builds → identical
  `sha256:78dcb312ff39477d51d87a4d113bb27001ec5bd842cbf02c6831956c005ccf79` (1,184,853 B).
- **`build-gateway-image.sh`** — reproducibly builds `ghcr.io/joshbilson/caladon-gateway`. Pins
  the base by **digest not tag** (`python@sha256:866411c1…`, linux/amd64),
  `SOURCE_DATE_EPOCH=0` + buildx `rewrite-timestamp`, fixed `--platform linux/amd64`,
  `--provenance=false --sbom=false`, OCI-tar output (no push), and emits the image **manifest
  digest** + a **DIGEST-PIN NOTE** instructing the deployer to replace the mutable
  `:gw-v1` tag in `infra/cvm/dstack-compose.gw-v1.yml` with `@sha256:<digest>` and re-derive
  `compose_hash`. Dry-run verified; full build is a documented `DRY_RUN=1` path when buildx is
  busy.
- **Remaining for fully-reproducible gateway:** the image installs Python deps from
  range-specifiers in `gateway/pyproject.toml` (no hash-locked requirements) → must ship a
  fully-pinned hashed lock and `FROM`-by-digest in `gateway/Dockerfile` (owned by the gateway
  author). Tracked as §4 open-item.
- **Transparency-log feed:** each script prints a one-line feed entry
  (`{source-ref, recipe, artifact-hash}`) and writes a record to
  `infra/reproducible/out/*.sha256`; path to Sigstore/Rekor `cosign` signing + the on-chain
  registry cross-check is documented in `infra/reproducible/README.md §4`.

---

## 5. Cross-references

- `infra/reproducible/` — the **tooling** (§4b): the two build scripts + procedure README.
- `docs/security/measurements.md` — the pinned tuples these builds must reproduce.
- `contracts/attestation.md §6` — "each tuple maps to a reproducible build".
- `docs/security/threat-model.md §5` — "pinned == audited source" residual trust;
  §3 malicious-binary-swap adversary.
- `MASTER-HANDOVER §7, §8, §11`; BUILD-PLAN Phase 5, Risk #2.
