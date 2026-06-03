# Reproducible builds — tooling

> **The load-bearing claim.** Caladon's whole security story reduces to one sentence
> (`docs/security/threat-model.md §5`): **"the pinned measurement == the audited public
> source."** That is only *checkable by a stranger* if the stranger can rebuild the exact
> artifacts and get the exact hashes the client/CVM pin. This directory is the tooling that
> makes that possible. Until these hashes are independently reproduced, every row in
> `docs/security/measurements.md` is honestly flagged `dev-pinned / not-yet-reproducible`.

This is the **tooling** side of `docs/security/reproducible-builds.md` (which states the
plan/policy). Two scripts, two artifacts:

| script | artifact | who measures it |
|---|---|---|
| `build-gateway-image.sh` | `ghcr.io/joshbilson/caladon-gateway` OCI image | dstack → `compose_hash` / `app_id` of the Agent CVM (`measurements.md §2.1`) |
| `build-caladon-core-wasm.sh` | `caladon_core_bg.wasm` (web trust-core) | the web client hashes the wasm it loads (sealed-channel crypto + dcap-qvl verifier) |

Both write their records to `out/` (git-ignored except the `.sha256` / `.SHA256SUMS` records,
which are the published hashes).

---

## 1. caladon-core WASM

```bash
infra/reproducible/build-caladon-core-wasm.sh
# → caladon-core/pkg/caladon_core_bg.wasm
# → infra/reproducible/out/caladon-core-wasm.sha256        (full record)
# → infra/reproducible/out/caladon-core-wasm.SHA256SUMS    (sha256sum -c friendly)
```

**Determinism levers** (why two strangers' builds agree byte-for-byte):

1. **Pinned toolchain.** The canonical pin is `caladon-core/rust-toolchain.toml`
   (`channel = "1.96.0"`); the script enforces it via `rustup` and **fails closed (exit 3)**
   if the active rustc disagrees. Override for a candidate bump with `RUST_TOOLCHAIN=…`.
2. **Pinned deps.** `caladon-core/Cargo.lock` is committed on purpose
   (`caladon-core/.gitignore` keeps it tracked) and the build runs `--locked` — a stranger
   builds the *exact* dependency graph or the build fails.
3. **No timestamps.** `SOURCE_DATE_EPOCH=0`, `TZ=UTC`, `LC_ALL=C`.
4. **No host paths.** `--remap-path-prefix` strips `$CARGO_HOME`, the crate dir, and `$HOME`
   from any path embedded in panic/debug strings, so the build host can't leak into the bytes.
5. **`--no-opt` (wasm-opt skipped).** wasm-pack's optional `wasm-opt` (binaryen) pass is
   **not** version-pinned and its output varies between binaryen releases — so we ship the
   raw `wasm-bindgen` output. This makes the artifact bigger (~1.18 MB vs ~0.95 MB optimized)
   but **deterministic**. See *"wasm-opt"* below if a size-optimized reproducible build is
   wanted.

**Verified reproducible (2026-06-03, `9c4fb7e`):** two consecutive clean builds produced the
identical hash:

```
sha256: 78dcb312ff39477d51d87a4d113bb27001ec5bd842cbf02c6831956c005ccf79
bytes:  1184853   (rust 1.96.0, wasm-pack 0.15.0, --no-opt, --features wasm)
```

> ### wasm-opt
> To ship a size-optimized *and* reproducible wasm, pin binaryen by version (e.g. vendor a
> `wasm-opt` binary by sha256 and run a fixed pass list `-Oz` with no
> `--zero-filled-memory`/date-dependent flags) as a **separate, separately-pinned** step
> after this script, and record *that* tool's hash next to the artifact. Until that pin
> exists, `--no-opt` is the honest reproducible artifact.

---

## 2. Gateway image

```bash
# Reviewer path (build → deterministic OCI tar → digest; does NOT push):
infra/reproducible/build-gateway-image.sh
# Dry-run the plan + show the resolved/pinned base digest, no build:
DRY_RUN=1 infra/reproducible/build-gateway-image.sh
# → infra/reproducible/out/caladon-gateway.oci.tar   (git-ignored)
# → infra/reproducible/out/gateway-image.sha256     (record: oci-tar sha + image manifest digest)
```

**Determinism levers:**

1. **Base pinned by DIGEST, not tag.** `gateway/Dockerfile` says `FROM python:3.12-slim` — a
   *mutable* tag. The script rewrites that to the **linux/amd64 manifest digest** into a
   throwaway `out/Dockerfile.pinned` and builds from that. Recorded pin (resolved 2026-06-03
   via `docker buildx imagetools inspect python:3.12-slim`):
   - linux/amd64: `python@sha256:866411c135b507754efdf2fda51484be4d3d7d5173ed53cd083106132e710904`
   - (index/multi-arch: `sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203`)
   Override with `BASE_DIGEST=sha256:…`. The script also re-resolves the live tag and **warns
   if it drifted** from the pin (the build still uses the pin).
   **Canonical fix:** commit the digest pin directly in `gateway/Dockerfile`
   (`FROM python@sha256:866411…`) so the source itself is pinned — owned by the gateway author.
2. **`SOURCE_DATE_EPOCH=0`** + `--output type=oci,…,rewrite-timestamp=true` — buildkit rewrites
   layer mtimes and the image-config `created` field to the epoch.
3. **Fixed `--platform linux/amd64`** — dstack CVMs are amd64; building arm64 changes every
   layer (and crash-loops the container, see `infra/cvm/publish-gateway.sh`). On an arm64 host
   this cross-builds via the bundled QEMU in the `docker-container` buildx driver.
4. **`--provenance=false --sbom=false`** — buildkit otherwise bakes a build-host attestation
   manifest (timestamps + host) into the OCI index, which breaks a byte-equal digest.
5. **OCI tar output, not push.** A reviewer re-hashes the local OCI tar and reads the image
   **manifest digest** out of its `index.json` *without* a registry round-trip (push can
   re-compress / re-add attestations).

> **Reproducibility caveat (honest):** the gateway image installs Python deps via
> `pip install .` from `gateway/pyproject.toml`, which uses **range specifiers** (`fastapi>=…`)
> and **no hash-locked requirements**. Two builds on different days can therefore resolve
> *different* wheel versions → different layers → different digest. To make the image fully
> reproducible, the gateway must ship a **fully pinned, hashed** lock (e.g. `uv export
> --frozen --no-emit-project -o requirements.lock` with `--require-hashes`, then
> `pip install --require-hashes -r requirements.lock`) and the Dockerfile must install from
> that lock. That pin is owned by the gateway author (out of this directory's scope); this
> script is correct the moment that lock + the `FROM`-digest land. This is the same
> open-item as `reproducible-builds.md §4`.

### The digest-pin output (the point of the gateway script)

After a real build the script emits the **image manifest digest** and a **DIGEST-PIN NOTE**:
the dstack compose (`infra/cvm/dstack-compose.gw-v1.yml`) currently pins the gateway by the
mutable tag

```yaml
image: ${GATEWAY_IMAGE:-ghcr.io/joshbilson/caladon-gateway:gw-v1}
```

— which a reviewer **cannot** tie to a specific build. Replace it with the digest:

```yaml
image: ghcr.io/joshbilson/caladon-gateway@sha256:<manifest-digest>
```

then re-derive `compose_hash` and re-pin `measurements.md §2.1`. That digest pin is what
closes the "operator swaps the binary" hole (`threat-model.md §3`, `measurements.md §3`): a
swapped image → different digest → different `compose_hash` → the client refuses (fail-closed).

---

## 3. Rebuild-and-confirm procedure (what a stranger does)

For each pinned tuple in `docs/security/measurements.md`:

1. **Check out** the published `source-ref` (git tag/commit recorded in the measurement row
   and in each `out/*.sha256` record).
2. **Run the matching script** in a clean checkout (the pinned toolchain / base digest make
   the build host irrelevant).
3. **Compare the artifact hash** the script prints against the published hash:
   - wasm: `sha256sum -c infra/reproducible/out/caladon-core-wasm.SHA256SUMS`
   - gateway: compare the emitted **image manifest digest** to the `@sha256:…` the dstack
     compose pins (and that the CVM's `compose_hash`/`app_id` in `measurements.md` was derived
     from).
4. **On match**, the measurement row graduates from `dev-pinned / not-yet-reproducible` to a
   reproducible tuple (`measurements.md §3`, `reproducible-builds.md §2`).

---

## 4. How the hashes feed the transparency log

The end-state (`docs/private-ai-architecture-decision.md`: *"GAP — build an append-only PUBLIC
transparency log of measurements + publish images"*; the Tinfoil/Sigstore bar in
`reproducible-builds.md §1.1`) is an **append-only, publicly auditable** record binding:

```
{ source-ref, build-recipe (this script + its pins), artifact-sha256 / image-digest, measurement }
```

Each script prints a one-line **transparency-log feed** entry, e.g.:

```
78dcb312…  caladon_core_bg.wasm  (source-ref 9c4fb7e, toolchain 1.96.0)
sha256:<digest>  ghcr.io/joshbilson/caladon-gateway  (source-ref …, base python@sha256:866411…)
```

Feed path (in order of increasing strength):

1. **Now (provenance ledger):** append the `out/*.sha256` records to the audit-readiness
   package and reference them from the `reproducible-build-ref` column in `measurements.md`.
   This is a *checkable* claim: anyone reruns the script and diffs the hash.
2. **Image provenance (Sigstore/Rekor):** when the image is published
   (`infra/cvm/publish-gateway.sh`), sign the **digest** with `cosign sign` and record the
   Rekor inclusion entry — the same transparency-log bar Tinfoil meets for its enclave images.
   Reviewers verify with `cosign verify` against the published identity.
3. **On-chain measurement registry:** the derived `compose_hash`/`app_id` for the CVM are
   cross-checked against the on-chain registry the client also checks
   (`contracts/attestation.md §4.4`), so the published build hash, the signed image digest,
   and the on-chain measurement all agree — independently, by three parties.

Until (2)/(3) are wired, (1) (the committed `out/*.sha256` records + `source-ref`) is the
honest, already-checkable transparency artifact.

---

## 5. Cross-references

- `docs/security/reproducible-builds.md` — the plan/policy (this dir is its **tooling** section).
- `docs/security/measurements.md` — the pinned tuples these builds must reproduce; the
  `reproducible-build-ref` column points back here.
- `contracts/attestation.md §4, §6` — verification algorithm + pinning policy (fail-closed).
- `infra/cvm/dstack-compose.gw-v1.yml` — where the gateway image digest gets pinned.
- `infra/cvm/publish-gateway.sh` — the publish (push) path; this dir is the **reviewer/rebuild** path.
