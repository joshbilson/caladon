# Measurement Transparency Log (Apple-PCC req #5 + Confer)

This directory makes Caladon's **pinned-measurement registry** publicly auditable
and tamper-evident by publishing it to a **Sigstore Rekor** append-only
transparency log, and by **generating** `docs/security/measurements.md` from a
single source of truth so the published values cannot drift or be hand-edited
undetectably.

> **Why this is load-bearing.** The whole security claim reduces to "the client
> only ever talks to a workload whose measurement is in the pinned set, and that
> pinned set == audited public source" (`docs/security/threat-model.md §5`,
> `contracts/attestation.md §6`). Transparency (Apple-PCC requirement #5) is the
> property that *a stranger* can confirm the published measurement set is exactly
> what the source says and has not been silently swapped. The companion
> **non-targetability** property (Apple-PCC requirement #4) is designed in
> `docs/security/non-targetability.md`.

---

## What's here

| File | Role |
|---|---|
| `measurements.source.json` | **Source of truth.** The real pinned tuple (measurements.md §2.1: `mrtd`/`rtmr0..3`/`compose_hash`/`os-image-hash`/`app_id`) + reproducible-build hashes + provenance. Edit THIS, never the doc. |
| `gen-measurements.py` | Generates `docs/security/measurements.md` from the source. `--check` exits non-zero if the committed doc is stale. |
| `build-record.py` | Emits the deterministic **canonical record** (the JSON blob published to Rekor) from the same source. `--sha256` prints its digest. |
| `docker-compose.yml` | A local Sigstore Rekor stack (Rekor + Trillian log-server/signer + MySQL + Redis). LOCAL DEV ONLY. |
| `publish.sh` | Build canonical record → sign (EC P-256 / x509) → POST a `rekord` entry to Rekor → save a receipt. |
| `verify.sh` | Fetch the entry → verify its **inclusion proof** against the log's **signed tree head** → confirm the logged artifact hash == the locally re-derived record (the doc↔log binding). Fail-closed. |
| `rekor_api.py` | Pure-stdlib Rekor REST client used by `REKOR_MODE=api` (no `rekor-cli` binary needed). |
| `sample/rekor-entry.sample.json` | A real entry + signed tree head captured during the dry-run (ephemeral keys; evidence, not a production attestation). |

The anti-drift test lives at `tests/transparency/test_measurements_generated.py`
and runs in CI: **if the committed `measurements.md` ≠ `render(source)`, CI is red.**

---

## The generated-doc workflow (anti-drift)

```bash
# 1. Edit the source of truth (NOT the doc):
$EDITOR infra/transparency/measurements.source.json

# 2. Regenerate the doc:
python3 infra/transparency/gen-measurements.py

# 3. CI / pre-commit check (exits 1 if stale):
python3 infra/transparency/gen-measurements.py --check
```

`docs/security/measurements.md` carries a `<!-- GENERATED FILE -->` header so a
human reader knows not to hand-edit it. The committed doc keeps the **current real
values** captured live from `caladon-gw` on 2026-06-03.

---

## Publish + verify against the local log

### 1. Bring up Rekor

```bash
docker compose -f infra/transparency/docker-compose.yml up -d
# wait until the log answers:
curl -s http://localhost:3000/api/v1/log
```

On Apple Silicon the images run under amd64 emulation; the compose sets no
`platform`, so export `DOCKER_DEFAULT_PLATFORM=linux/amd64` if your daemon does
not auto-emulate.

### 2. Publish the pinned measurements

```bash
# Canonical path (rekor-cli in a container):
./infra/transparency/publish.sh

# REST fallback (no rekor-cli — recommended on arm64; see Troubleshooting):
REKOR_MODE=api ./infra/transparency/publish.sh
```

This builds the canonical record, signs it with an EC P-256 key (auto-generated
into `keys/` on first run, git-ignored), posts a `rekord` entry, and prints the
`logIndex` + saves a receipt under `receipts/`.

### 3. Verify the inclusion proof

```bash
./infra/transparency/verify.sh <logIndex>
# or REST fallback:
REKOR_MODE=api ./infra/transparency/verify.sh
```

`verify.sh` (a) verifies the **Merkle inclusion proof** recomputes to the log's
**signed tree-head rootHash** — proving the entry is in the append-only log and
the log has not been forked under it — and (b) confirms the **logged artifact hash
equals the record re-derived from this repo's source** — proving the entry is
*this* pinned-measurement set, not some other blob. Any mismatch exits non-zero
(fail-closed).

### 4. Tear down

```bash
docker compose -f infra/transparency/docker-compose.yml down -v
```

---

## Dry-run result (this machine, 2026-06-03)

A full live publish+verify round-trip was executed against the local stack:

- **Publish:** canonical record `sha256=431658e1…` signed (EC P-256 / x509) and
  posted → `logIndex=0`.
- **Tree growth:** a second distinct leaf published → `treeSize=2`, so the
  measurement entry's inclusion proof has a sibling hash.
- **Verify:** the leaf + sibling recompute (RFC-6962) to
  `rootHash=c9a2fba9…`, which **equals the signed tree-head rootHash** the log
  signs; and the **logged artifact hash == the local source's record sha256**.
- **Fail-closed negative test:** tampering `measurements.source.json` changes the
  record sha, the entry is not found in the log, and `verify.sh` exits non-zero.

Captured in `sample/rekor-entry.sample.json` (the entry + signed tree head).

> `rekor-cli` itself could not be built on this arm64 host (the amd64 distroless
> image has no shell/`rekor-cli` binary, and a `go install` under qemu segfaulted),
> so the live round-trip used `REKOR_MODE=api`. The `rekor-cli` path in the scripts
> is the canonical one for amd64 CI/servers and is exercised the same way.

---

## Production notes (not this round)

- **Independently operated log.** Local Rekor uses an ephemeral `--signer=memory`
  key — fine for dev, useless as evidence. Production publishes to a Rekor that is
  *operated separately* from the thing it attests (the Sigstore public-good
  instance, or an independently-run log), so the operator cannot both swap a
  workload and rewrite its log entry.
- **Signing key = the release key.** The canonical record must be signed by the
  same offline key that signs the client app update (the pinned set only changes
  via a signed app update — `measurements.md §3`). The client can then check the
  log entry's signature chains to that key.
- **Client-side check.** A hardened client verifies, at pin-update time, that each
  measurement it pins appears in the transparency log with a valid inclusion proof
  — closing "the published doc says X but the app pins Y".
- **Reproducible-build hashes.** Once Phase-5 reproducible builds land
  (`docs/security/reproducible-builds.md`), their artifact hashes populate
  `reproducible_build_hashes` in the source and ride along in the same signed
  entry, so source→hash→measurement is one auditable chain.

---

## Troubleshooting

- **`rekor-cli upload failed` on Apple Silicon / arm64.** `rekor-cli` is not
  published as a runnable public container and a Go cross-build under qemu is
  unreliable. Use `REKOR_MODE=api` — same operation over the REST API, pure
  stdlib.
- **`panic: dial tcp …:6379`** in the rekor-server logs → Redis isn't up. The
  compose includes it with a healthcheck; `docker compose up -d` brings it first.
- **MySQL `unhealthy`** → the trillian db image is MySQL 8.x; the healthcheck uses
  `mysqladmin ping` (the older `/etc/init.d/mysql status` probe does not exist in
  this image).
- **`host.docker.internal` not resolving on Linux** → the scripts pass
  `--add-host host.docker.internal:host-gateway`; on older Docker, run rekor-cli
  on the compose network instead.

---

## Cross-references

- `docs/security/measurements.md` — the generated pinned registry (this is its source).
- `docs/security/non-targetability.md` — Apple-PCC req #4 (OHTTP relay / IP hiding / single-use creds).
- `docs/security/reproducible-builds.md` — how a `dev-pinned` row graduates to reproducible.
- `contracts/attestation.md §4, §6, §8` — verification, pinning policy, fail-closed.
- `tests/transparency/test_measurements_generated.py` — the anti-drift enforcement.
