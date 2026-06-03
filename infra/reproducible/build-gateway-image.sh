#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────────────────
# build-gateway-image.sh — REPRODUCIBLE build of ghcr.io/joshbilson/caladon-gateway.
#
# Load-bearing claim (docs/security/reproducible-builds.md §1.1, threat-model.md §3/§5):
#   The gateway is the ciphertext router that runs INSIDE the attested CVM. Its image is the
#   workload measured into the dstack compose_hash / app_id pinned in measurements.md. A
#   stranger MUST be able to: check out `source-ref`, run THIS script, get the SAME image
#   sha256, and then confirm THAT digest is what the dstack compose pins — closing the
#   "operator swaps the binary" hole (measurements.md §3).
#
# Determinism levers:
#   1. PINNED BASE BY DIGEST — FROM python:3.12-slim is pinned to its linux/amd64 manifest
#      DIGEST (not the moving :3.12-slim tag). Passed in as a build-arg / Dockerfile override.
#   2. SOURCE_DATE_EPOCH=0   — buildkit rewrites layer timestamps to the epoch (needs
#      buildx/buildkit, which honors SOURCE_DATE_EPOCH for the image config + layer mtimes).
#   3. FIXED PLATFORM        — --platform linux/amd64 (dstack CVMs are amd64; building arm64
#      would change every layer and crash-loop the container, see publish-gateway.sh).
#   4. --provenance=false --sbom=false — no build-host attestation manifest baked into the
#      index (those embed timestamps/host and break a byte-equal index digest).
#   5. --output type=oci so the artifact is a deterministic OCI tar a reviewer can re-hash
#      WITHOUT pushing (the registry may re-compress / add attestations on push).
#
# This does NOT push by default (reviewers rebuild + compare; publishing is publish-gateway.sh).
#
# Usage:
#   infra/reproducible/build-gateway-image.sh            # build → OCI tar → digest
#   DRY_RUN=1 infra/reproducible/build-gateway-image.sh  # print the plan + resolved digest, no build
#   BASE_DIGEST=sha256:... infra/reproducible/build-gateway-image.sh   # override pinned base
#   PUSH=1 TAG=gw-v1 ...                                 # also push (needs docker login; CI/publish path)
#
# Exit: 0 ok · 2 prereq missing · 3 base-digest unresolved · 4 build failed
# ──────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GATEWAY_CTX="$REPO_ROOT/gateway"
OUT_DIR="$SCRIPT_DIR/out"

IMAGE_REF="${IMAGE_REF:-ghcr.io/joshbilson/caladon-gateway}"
TAG="${TAG:-gw-v1}"
PLATFORM="${PLATFORM:-linux/amd64}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export SOURCE_DATE_EPOCH

# ── 1. Pinned base image DIGEST (NOT the tag) ───────────────────────────────────────────
# Recorded pin for python:3.12-slim linux/amd64 (resolved 2026-06-03 via
#   docker buildx imagetools inspect python:3.12-slim).
# index (multi-arch): sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
# Re-resolve + re-pin whenever the base is intentionally bumped (README §"base bump").
BASE_NAME="python:3.12-slim"
BASE_DIGEST="${BASE_DIGEST:-sha256:866411c135b507754efdf2fda51484be4d3d7d5173ed53cd083106132e710904}"
BASE_PINNED="${BASE_NAME%%:*}@${BASE_DIGEST}"   # python@sha256:866411...

command -v docker >/dev/null 2>&1 || { echo "❌ docker not found"; exit 2; }
docker buildx version >/dev/null 2>&1 || { echo "❌ docker buildx not available (need buildkit for SOURCE_DATE_EPOCH)"; exit 2; }
[ -f "$GATEWAY_CTX/Dockerfile" ] || { echo "❌ gateway/Dockerfile not found at $GATEWAY_CTX"; exit 4; }

# Optionally re-resolve the live digest of the tag and WARN if it drifted from the pin
# (informational — the build still uses the PINNED digest).
LIVE_AMD64=""
if [ -z "${SKIP_DIGEST_CHECK:-}" ]; then
  LIVE_AMD64="$(docker buildx imagetools inspect "$BASE_NAME" 2>/dev/null \
    | awk '/Platform:[[:space:]]*linux\/amd64/{found=1} found&&/Name:/{print $2; exit}' \
    | sed -E 's/.*@(sha256:[0-9a-f]+)/\1/')" || true
  if [ -n "$LIVE_AMD64" ] && [ "$LIVE_AMD64" != "$BASE_DIGEST" ]; then
    echo "⚠ base tag '$BASE_NAME' currently resolves to $LIVE_AMD64"
    echo "  but this recipe is PINNED to                $BASE_DIGEST"
    echo "  (expected if upstream moved the tag; the build uses the PINNED digest, not the tag)"
  fi
fi

mkdir -p "$OUT_DIR"
OCI_TAR="$OUT_DIR/caladon-gateway.oci.tar"
LOCAL_TAG="$IMAGE_REF:$TAG"

echo "── gateway reproducible build plan ─────────────────────────────────────────"
echo "  context:            $GATEWAY_CTX"
echo "  image:              $LOCAL_TAG"
echo "  platform:           $PLATFORM"
echo "  base (PINNED):      $BASE_PINNED"
[ -n "$LIVE_AMD64" ] && echo "  base (live tag now): $LIVE_AMD64"
echo "  SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
echo "  output:             OCI tar → $OCI_TAR"
echo "────────────────────────────────────────────────────────────────────────────"

# The Dockerfile uses `FROM python:3.12-slim`. To pin WITHOUT editing the committed Dockerfile,
# rewrite that FROM to the digest-pinned ref into a throwaway Dockerfile in OUT_DIR. (The
# canonical fix is to commit the digest pin in gateway/Dockerfile — see the emitted note.)
PINNED_DOCKERFILE="$OUT_DIR/Dockerfile.pinned"
sed -E "s#^FROM[[:space:]]+python:3\.12-slim.*#FROM ${BASE_PINNED}#" "$GATEWAY_CTX/Dockerfile" > "$PINNED_DOCKERFILE"
if ! grep -q "^FROM ${BASE_PINNED}\$" "$PINNED_DOCKERFILE"; then
  echo "❌ failed to pin FROM line — check gateway/Dockerfile base ($BASE_NAME)"; exit 3
fi
echo "  pinned Dockerfile:  $PINNED_DOCKERFILE (FROM → $BASE_PINNED)"

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
SRC_REF="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

emit_pin_note() {
  local digest_line="$1"
  SHA_FILE="$OUT_DIR/gateway-image.sha256"
  {
    echo "# caladon-gateway reproducible-build record"
    echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
    echo "image-ref:          $LOCAL_TAG"
    echo "platform:           $PLATFORM"
    echo "base-image-pinned:  $BASE_PINNED"
    echo "oci-tar-sha256:     ${TAR_SHA:-n/a}"
    echo "image-manifest:     ${digest_line}"
    echo "SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
    echo "source-ref:         $SRC_REF"
  } > "$SHA_FILE"
  echo ""
  echo "──────────────────────────────────────────────────────────────────────────"
  echo " DIGEST-PIN NOTE (action for the deployer):"
  echo "   The dstack compose currently pins the gateway image by TAG:"
  echo "       infra/cvm/dstack-compose.gw-v1.yml →"
  echo "       image: \${GATEWAY_IMAGE:-$IMAGE_REF:$TAG}"
  echo "   A tag is MUTABLE → a reviewer cannot prove the running workload == this build."
  echo "   PIN BY DIGEST instead, e.g.:"
  echo "       image: $IMAGE_REF@${digest_line}"
  echo "   Then re-derive compose_hash and re-pin measurements.md §2.1."
  echo "   Record written: ${SHA_FILE}"
  echo "──────────────────────────────────────────────────────────────────────────"
}

if [ -n "${DRY_RUN:-}" ]; then
  echo ""
  echo "DRY_RUN=1 → not building. Would run:"
  echo "  SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH docker buildx build \\"
  echo "    --builder swifty-repro --platform $PLATFORM \\"
  echo "    --provenance=false --sbom=false \\"
  echo "    --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \\"
  echo "    -f $PINNED_DOCKERFILE -t $LOCAL_TAG \\"
  echo "    --output type=oci,dest=$OCI_TAR,rewrite-timestamp=true \\"
  echo "    $GATEWAY_CTX"
  echo ""
  echo "Then the OCI tar is hashed and the image config digest extracted; see the emitted note below."
  emit_pin_note "(dry-run; image digest not computed)"
  exit 0
fi

# Dedicated reproducible builder (docker-container driver = buildkit, honors SOURCE_DATE_EPOCH).
docker buildx inspect swifty-repro >/dev/null 2>&1 \
  || docker buildx create --name swifty-repro --driver docker-container >/dev/null

echo "▶ building (this cross-builds amd64 via QEMU on arm64 hosts) …"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" docker buildx build \
  --builder swifty-repro \
  --platform "$PLATFORM" \
  --provenance=false --sbom=false \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  -f "$PINNED_DOCKERFILE" \
  -t "$LOCAL_TAG" \
  --output "type=oci,dest=$OCI_TAR,rewrite-timestamp=true" \
  "$GATEWAY_CTX" \
  || { echo "❌ buildx build failed"; exit 4; }

[ -f "$OCI_TAR" ] || { echo "❌ OCI tar not produced"; exit 4; }

TAR_SHA="$(sha "$OCI_TAR")"

# The reproducible identity is the OCI image MANIFEST digest (index → manifest). Extract it
# from the OCI layout: index.json points at the manifest digest the registry will serve.
MANIFEST_DIGEST=""
if command -v tar >/dev/null 2>&1; then
  TMPX="$(mktemp -d)"
  tar -xf "$OCI_TAR" -C "$TMPX" index.json 2>/dev/null || true
  if [ -f "$TMPX/index.json" ]; then
    # First manifest digest in the OCI index (single-platform build → one entry).
    MANIFEST_DIGEST="$(grep -o 'sha256:[0-9a-f]\{64\}' "$TMPX/index.json" | head -1)"
  fi
  rm -rf "$TMPX"
fi

# Optional push (publish path — NOT the reviewer path).
if [ -n "${PUSH:-}" ]; then
  echo "▶ PUSH=1 → loading + pushing $LOCAL_TAG (requires docker login to $IMAGE_REF) …"
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" docker buildx build \
    --builder swifty-repro --platform "$PLATFORM" \
    --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    -f "$PINNED_DOCKERFILE" -t "$LOCAL_TAG" --push "$GATEWAY_CTX" \
    || { echo "❌ push failed"; exit 4; }
fi

echo ""
echo "✅ gateway image built reproducibly (OCI tar)"
echo "   oci-tar sha256:   $TAR_SHA"
echo "   image manifest:   ${MANIFEST_DIGEST:-<extract failed; inspect $OCI_TAR/index.json>}"
emit_pin_note "${MANIFEST_DIGEST:-unknown}"
echo ""
echo "Feed to the transparency log (README §4):"
echo "   ${MANIFEST_DIGEST:-unknown}  $IMAGE_REF  (source-ref $SRC_REF, base $BASE_PINNED)"
