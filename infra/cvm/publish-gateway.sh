#!/usr/bin/env bash
# Publish the gateway image to a registry so `phala deploy` can pull it (dstack cannot
# build from source). Prints the GATEWAY_IMAGE to feed gate1.sh.
#
# ┌─ BLOCKER B-REGISTRY ───────────────────────────────────────────────────────────────┐
# │ Needs a registry credential the unattended loop does NOT have:                       │
# │   • a GitHub PAT with `write:packages` (the `gh` CLI token lacks this scope), OR      │
# │   • a Docker Hub access token.                                                        │
# │ The gateway image carries NO secrets (config is all runtime env), so the package can  │
# │ be PUBLIC — dstack then pulls it with no registry creds in the CVM.                   │
# │ Fix (≈30s, human): add a PAT to op://$OP_VAULT/GitHub/credential (write:packages),  │
# │ or `docker login` with a Docker Hub token, then set REGISTRY/OWNER below.             │
# └──────────────────────────────────────────────────────────────────────────────────────┘
#
# Usage:  ./publish-gateway.sh            # ghcr.io/<gh-user>/caladon-gateway:gate1
#         REGISTRY=docker.io OWNER=me ./publish-gateway.sh
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root (build context = gateway/)

REGISTRY="${REGISTRY:-ghcr.io}"
OWNER="${OWNER:-$(gh api user --jq .login 2>/dev/null || echo CHANGE_ME)}"
TAG="${TAG:-gate1}"
IMAGE="$REGISTRY/$OWNER/caladon-gateway:$TAG"

# dstack CVMs are linux/amd64 — MUST build for that platform or the container crash-loops
# with "exec format error" (this dev machine is arm64 via colima). buildx + the
# docker-container driver bundle QEMU for the cross-build.
PLATFORM="${PLATFORM:-linux/amd64}"

echo "Logging in to $REGISTRY …"
case "$REGISTRY" in
  ghcr.io)
    # Classic PAT w/ write:packages (op://$OP_VAULT/GitHub/classic_pat) is the reliable
    # ghcr credential; fall back to the fine-grained `pat`, then the gh token.
    TOKEN="$(op read 'op://$OP_VAULT/GitHub/classic_pat' 2>/dev/null \
             || op read 'op://$OP_VAULT/GitHub/pat' 2>/dev/null \
             || gh auth token 2>/dev/null)"
    [ -n "$TOKEN" ] || { echo "❌ B-REGISTRY: no token (need a PAT w/ write:packages)"; exit 2; }
    echo "$TOKEN" | docker login ghcr.io -u "$OWNER" --password-stdin ;;
  *) echo "Run 'docker login $REGISTRY' first (Docker Hub token)";;
esac

# Ensure a cross-capable builder exists (idempotent).
docker buildx inspect swiftyx >/dev/null 2>&1 || docker buildx create --name swiftyx --driver docker-container >/dev/null 2>&1
echo "Building ($PLATFORM) + pushing $IMAGE …"
docker buildx build --builder swiftyx --platform "$PLATFORM" -t "$IMAGE" --push gateway/ \
  || { echo "❌ buildx build/push failed"; exit 2; }

echo "✅ published ($PLATFORM). Now run:  GATEWAY_IMAGE=$IMAGE ./infra/cvm/gate1.sh  (or gate1-smoke.sh)"
