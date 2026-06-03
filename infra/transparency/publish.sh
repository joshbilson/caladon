#!/usr/bin/env bash
# Publish the pinned CVM measurements + reproducible-build hashes to the Sigstore
# Rekor transparency log as a SIGNED, append-only entry (Apple-PCC req #5 + Confer).
#
# What it does:
#   1. Builds the canonical measurement RECORD from the source of truth
#      (infra/transparency/measurements.source.json) — the same source the doc is
#      generated from, so the published record and docs/security/measurements.md
#      cannot disagree.
#   2. Signs the record with a minisign/ed25519-style key (generated on first run
#      and kept in ./keys/ unless you pass your own).
#   3. Posts {artifact=record, signature, public-key} to Rekor as a `rekord` entry.
#   4. Prints the resulting logIndex + UUID and saves a receipt under ./receipts/.
#
# rekor-cli runs INSIDE a container (no host install required).
#
#   ./infra/transparency/publish.sh                 # local Rekor (compose), ephemeral key
#   REKOR_URL=https://rekor.sigstore.dev ./publish.sh   # public-good instance
#   SIGNING_KEY=/path/to/ec.key ./publish.sh         # bring your own EC P-256 key
#
# rekor-cli is the canonical client. On hosts where it is unavailable (e.g. arm64
# dev boxes — rekor-cli ships as an amd64-only distroless image and a Go
# cross-build under qemu is unreliable), set REKOR_MODE=api to use the bundled
# pure-stdlib REST client (rekor_api.py) instead. It performs the same operation.
#
#   REKOR_MODE=api ./infra/transparency/publish.sh
#
# Exit non-zero on any failure (fail-closed: a publish that did not land must not
# look like success).
set -euo pipefail

REKOR_MODE="${REKOR_MODE:-cli}"   # cli | api

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

REKOR_URL="${REKOR_URL:-http://localhost:3000}"
REKOR_CLI_IMAGE="${REKOR_CLI_IMAGE:-gcr.io/projectsigstore/rekor-cli:latest}"
KEYS_DIR="$HERE/keys"
RECEIPTS_DIR="$HERE/receipts"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$KEYS_DIR" "$RECEIPTS_DIR"

log() { printf '\033[1;36m[publish]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[publish] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required (rekor-cli runs in a container)"
command -v python3 >/dev/null 2>&1 || die "python3 is required (build-record.py)"
command -v openssl >/dev/null 2>&1 || die "openssl is required (sign the record)"

# ── 1. canonical record ───────────────────────────────────────────────────────
RECORD="$WORK_DIR/measurements.record.json"
python3 "$HERE/build-record.py" > "$RECORD"
RECORD_SHA="$(python3 "$HERE/build-record.py" --sha256)"
log "canonical record sha256 = $RECORD_SHA"

# ── 2. signing key (EC P-256) + self-signed x509 cert ─────────────────────────
# rekord entries accept pki-format x509; we sign sha256-ECDSA and attach a
# self-signed cert as the public key (the same shape `--pki-format=x509` expects).
if [[ -n "${SIGNING_KEY:-}" ]]; then
  PRIV_KEY="$SIGNING_KEY"
  [[ -f "$PRIV_KEY" ]] || die "SIGNING_KEY=$PRIV_KEY not found"
else
  PRIV_KEY="$KEYS_DIR/measurements-signer.ec.key"
  if [[ ! -f "$PRIV_KEY" ]]; then
    log "no signing key found — generating an ephemeral EC P-256 key at $PRIV_KEY"
    log "  (LOCAL DEV ONLY; a real publish uses an offline release key tied to the app-update signer)"
    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV_KEY" >/dev/null 2>&1
  fi
fi
CERT="$WORK_DIR/signer.crt"
openssl req -new -x509 -key "$PRIV_KEY" -out "$CERT" -days 365 \
  -subj "/CN=caladon-measurements-signer" >/dev/null 2>&1

# ── 3. sign the record (sha256-ECDSA) ──────────────────────────────────────────
SIG="$WORK_DIR/measurements.record.sig"
openssl dgst -sha256 -sign "$PRIV_KEY" -out "$SIG" "$RECORD"
log "signed record (sha256-ECDSA) + self-signed x509 cert"

# ── 4. post to Rekor ───────────────────────────────────────────────────────────
log "posting to Rekor at $REKOR_URL (mode=$REKOR_MODE)"
LOG_INDEX=""
ENTRY_URL=""

if [[ "$REKOR_MODE" == "api" ]]; then
  PUB_OUT="$WORK_DIR/pub.out"
  set +e
  python3 "$HERE/rekor_api.py" publish \
    --rekor-url "$REKOR_URL" \
    --record "$RECORD" --cert "$CERT" --sig "$SIG" >"$PUB_OUT" 2>&1
  RC=$?
  set -e
  cat "$PUB_OUT"
  [[ $RC -eq 0 ]] || die "REST publish failed (rc=$RC). Is the log up? See README.md §Troubleshooting."
  LOG_INDEX="$(grep -Eo 'logIndex=[0-9]+' "$PUB_OUT" | grep -Eo '[0-9]+' | head -1 || true)"
else
  DOCKER_NET=()
  if [[ "$REKOR_URL" == http://localhost:* || "$REKOR_URL" == http://127.0.0.1:* ]]; then
    # Talk to the compose Rekor on the host. host.docker.internal works on Docker
    # Desktop (macOS/Windows); on Linux --add-host host-gateway covers it.
    REKOR_URL_INCONTAINER="${REKOR_URL/localhost/host.docker.internal}"
    REKOR_URL_INCONTAINER="${REKOR_URL_INCONTAINER/127.0.0.1/host.docker.internal}"
    DOCKER_NET=(--add-host host.docker.internal:host-gateway)
  else
    REKOR_URL_INCONTAINER="$REKOR_URL"
  fi
  UPLOAD_OUT="$WORK_DIR/upload.out"
  set +e
  docker run --rm "${DOCKER_NET[@]}" \
    -v "$WORK_DIR:/work:ro" \
    "$REKOR_CLI_IMAGE" \
    upload \
    --rekor_server "$REKOR_URL_INCONTAINER" \
    --type rekord \
    --artifact /work/measurements.record.json \
    --signature /work/measurements.record.sig \
    --pki-format=x509 \
    --public-key /work/signer.crt \
    >"$UPLOAD_OUT" 2>&1
  RC=$?
  set -e
  cat "$UPLOAD_OUT"
  [[ $RC -eq 0 ]] || die "rekor-cli upload failed (rc=$RC). Is the log up? Try REKOR_MODE=api. See README.md §Troubleshooting."
  # Rekor prints "Created entry at index N" or, on a duplicate, the existing URL.
  ENTRY_URL="$(grep -Eo 'http[s]?://[^ ]+/api/v1/log/entries/[a-f0-9]+' "$UPLOAD_OUT" | head -1 || true)"
  LOG_INDEX="$(grep -Eo 'index [0-9]+' "$UPLOAD_OUT" | grep -Eo '[0-9]+' | head -1 || true)"
fi

RECEIPT="$RECEIPTS_DIR/measurements-$(date -u +%Y%m%dT%H%M%SZ).receipt.json"
python3 - "$RECEIPT" "$RECORD_SHA" "${LOG_INDEX:-}" "$ENTRY_URL" "$REKOR_URL" <<'PY'
import json, sys
receipt_path, record_sha, log_index, entry_url, rekor_url = sys.argv[1:6]
json.dump({
    "record_sha256": record_sha,
    "rekor_url": rekor_url,
    "log_index": int(log_index) if log_index else None,
    "entry_url": entry_url or None,
    "record_type": "ai.caladon.measurements/v1",
    "note": "Verify with: ./infra/transparency/verify.sh "
            + (log_index or "<logIndex>"),
}, open(receipt_path, "w"), indent=2)
print(receipt_path)
PY
log "receipt saved → ${RECEIPT/#$REPO_ROOT\//}"
[[ -n "$LOG_INDEX" ]] && log "PUBLISHED: logIndex=$LOG_INDEX  (verify: ./infra/transparency/verify.sh $LOG_INDEX)"
log "done."
