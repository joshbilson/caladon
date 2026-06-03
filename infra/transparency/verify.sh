#!/usr/bin/env bash
# Verify a published measurement entry in the Sigstore Rekor transparency log:
# fetch it and check its INCLUSION PROOF against the log's signed tree head
# (Apple-PCC req #5 + Confer — the registry is publicly auditable + tamper-evident).
#
# What it does:
#   1. Fetches the entry by logIndex (or UUID) from Rekor.
#   2. Verifies the inclusion proof + the signed-entry-timestamp (`rekor-cli verify`
#      checks the Merkle inclusion proof against the log's signed tree head — i.e.
#      proves the entry really is in the append-only log and the log has not been
#      forked/rewritten under it).
#   3. Re-derives the canonical record from the local source of truth and confirms
#      its sha256 matches the entry's logged artifact hash — i.e. the entry in the
#      log is THIS repo's pinned-measurement set, not some other blob.
#
# rekor-cli runs INSIDE a container (no host install required).
#
#   ./infra/transparency/verify.sh <logIndex>
#   ./infra/transparency/verify.sh --uuid <entryUUID>
#   REKOR_URL=https://rekor.sigstore.dev ./verify.sh <logIndex>
#   REKOR_MODE=api ./infra/transparency/verify.sh   # REST fallback (no rekor-cli)
#
# rekor-cli is the canonical client. On hosts without it, REKOR_MODE=api uses the
# bundled pure-stdlib REST verifier (rekor_api.py) which recomputes the RFC-6962
# inclusion proof up to the signed tree head — same property, no binary needed.
#
# Exit non-zero if the proof fails OR the logged record does not match the local
# source (fail-closed).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REKOR_URL="${REKOR_URL:-http://localhost:3000}"
REKOR_CLI_IMAGE="${REKOR_CLI_IMAGE:-gcr.io/projectsigstore/rekor-cli:latest}"
REKOR_MODE="${REKOR_MODE:-cli}"   # cli | api
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

log() { printf '\033[1;36m[verify]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[verify] OK:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[verify] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is required (build-record.py)"

# ── REST fallback mode (no rekor-cli / docker) ─────────────────────────────────
if [[ "$REKOR_MODE" == "api" ]]; then
  RECORD="$WORK_DIR/measurements.record.json"
  python3 "$HERE/build-record.py" > "$RECORD"
  log "verifying via REST at $REKOR_URL"
  if [[ "${1:-}" == "--uuid" && -n "${2:-}" ]]; then
    python3 "$HERE/rekor_api.py" verify --rekor-url "$REKOR_URL" --record "$RECORD" --uuid "$2" \
      || die "REST verification failed (fail-closed)."
  else
    python3 "$HERE/rekor_api.py" verify --rekor-url "$REKOR_URL" --record "$RECORD" \
      || die "REST verification failed (fail-closed)."
  fi
  ok "transparency verification complete — pinned measurements are in the append-only log and match this repo."
  exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker is required for rekor-cli mode (or set REKOR_MODE=api)"

SELECTOR=()
case "${1:-}" in
  "")        die "usage: verify.sh <logIndex> | --uuid <entryUUID>" ;;
  --uuid)    [[ -n "${2:-}" ]] || die "--uuid needs a value"; SELECTOR=(--uuid "$2") ;;
  *)         SELECTOR=(--log-index "$1") ;;
esac

DOCKER_NET=()
if [[ "$REKOR_URL" == http://localhost:* || "$REKOR_URL" == http://127.0.0.1:* ]]; then
  REKOR_URL_INCONTAINER="${REKOR_URL/localhost/host.docker.internal}"
  REKOR_URL_INCONTAINER="${REKOR_URL_INCONTAINER/127.0.0.1/host.docker.internal}"
  DOCKER_NET=(--add-host host.docker.internal:host-gateway)
else
  REKOR_URL_INCONTAINER="$REKOR_URL"
fi

# ── 1+2. fetch + verify inclusion proof ────────────────────────────────────────
log "verifying inclusion proof at $REKOR_URL for ${SELECTOR[*]}"
VERIFY_OUT="$WORK_DIR/verify.out"
set +e
docker run --rm "${DOCKER_NET[@]}" "$REKOR_CLI_IMAGE" \
  verify --rekor_server "$REKOR_URL_INCONTAINER" "${SELECTOR[@]}" \
  >"$VERIFY_OUT" 2>&1
RC=$?
set -e
cat "$VERIFY_OUT"
[[ $RC -eq 0 ]] || die "inclusion-proof verification failed (rc=$RC)."
grep -qiE 'inclusion proof.*(verified|valid)|Index:' "$VERIFY_OUT" \
  || die "rekor-cli did not report a verified inclusion proof."
ok "inclusion proof verified against the signed tree head."

# ── 3. confirm the logged record is THIS repo's measurement set ────────────────
GET_OUT="$WORK_DIR/get.out"
docker run --rm "${DOCKER_NET[@]}" "$REKOR_CLI_IMAGE" \
  get --rekor_server "$REKOR_URL_INCONTAINER" "${SELECTOR[@]}" --format json \
  >"$GET_OUT" 2>/dev/null || die "rekor-cli get failed"

LOCAL_SHA="$(python3 "$HERE/build-record.py" --sha256)"
log "local source record sha256 = $LOCAL_SHA"

# Rekor stores the artifact hash in the rekord entry body (hashedrekord/rekord
# `data.hash.value`). Pull every sha256-looking hex from the entry and require a match.
if grep -qi "$LOCAL_SHA" "$GET_OUT"; then
  ok "logged entry's artifact hash matches the local pinned-measurement record."
else
  die "logged record does NOT match local source ($LOCAL_SHA). The published measurement set differs from this repo — investigate before trusting either."
fi

ok "transparency verification complete — pinned measurements are in the append-only log and match this repo."
