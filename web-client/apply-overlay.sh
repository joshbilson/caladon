#!/usr/bin/env bash
# Apply the Caladon surgery overlay onto a fresh vendored LibreChat clone.
#
# The vendored LibreChat tree (web-client/librechat/) is git-ignored and never committed (see
# web-client/SURGERY.md "Vendored upstream"). The SURGERY edits, however, ARE committed — as an
# OVERLAY at web-client/overlay/<same-relative-path>. This script materialises a working tree by:
#   1. cloning the PINNED upstream commit into web-client/librechat/ (if not already present), and
#   2. copying every overlay file over the matching upstream path.
#
# Idempotent: re-running re-copies the overlay (it will not re-clone if librechat/ already exists).
#
# Usage:  ./web-client/apply-overlay.sh
#         ./web-client/apply-overlay.sh --force-clone   # wipe + re-clone librechat/ first
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBRECHAT_DIR="${SCRIPT_DIR}/librechat"
OVERLAY_DIR="${SCRIPT_DIR}/overlay"

# Pinned upstream — keep in sync with web-client/SURGERY.md + web-client/setup.sh.
LIBRECHAT_REPO="https://github.com/danny-avila/LibreChat"
LIBRECHAT_COMMIT="d680763db3e5ec8e100c824a9b8f6189ab0081cd"  # v0.8.6, 2026-06-02

echo "==> Caladon overlay apply"
echo "    overlay:   ${OVERLAY_DIR}"
echo "    work tree: ${LIBRECHAT_DIR}"

if [ "${1:-}" = "--force-clone" ]; then
  echo "==> --force-clone: removing existing work tree"
  rm -rf "${LIBRECHAT_DIR}"
fi

# 1. Clone the pinned upstream (full clone so we can checkout the exact commit).
if [ -d "${LIBRECHAT_DIR}/.git" ]; then
  echo "==> LibreChat already present (skipping clone)"
  echo "    HEAD: $(git -C "${LIBRECHAT_DIR}" rev-parse --short HEAD)"
else
  echo "==> Cloning LibreChat and checking out the pinned commit ${LIBRECHAT_COMMIT}"
  git clone "${LIBRECHAT_REPO}" "${LIBRECHAT_DIR}"
  if ! git -C "${LIBRECHAT_DIR}" checkout --quiet "${LIBRECHAT_COMMIT}" 2>/dev/null; then
    echo "    WARNING: pinned commit ${LIBRECHAT_COMMIT} not found (upstream history rewritten?)."
    echo "             Staying on the default branch HEAD: $(git -C "${LIBRECHAT_DIR}" rev-parse --short HEAD)"
    echo "             Surgery line numbers in SURGERY.md may have drifted — re-verify."
  fi
fi

# 2. Copy the overlay over the upstream tree, preserving relative paths.
if [ ! -d "${OVERLAY_DIR}" ]; then
  echo "ERROR: overlay dir ${OVERLAY_DIR} not found" >&2
  exit 1
fi

echo "==> Applying overlay files:"
COUNT=0
while IFS= read -r -d '' src; do
  rel="${src#"${OVERLAY_DIR}/"}"
  dest="${LIBRECHAT_DIR}/${rel}"
  mkdir -p "$(dirname "${dest}")"
  cp "${src}" "${dest}"
  echo "    + ${rel}"
  COUNT=$((COUNT + 1))
done < <(find "${OVERLAY_DIR}" -type f -print0)
echo "==> Applied ${COUNT} overlay file(s)."

cat <<'EOF'

==> Done. Next:
  - Install deps (monorepo root):  cd web-client/librechat && npm install
  - Build the shared packages:      npm run build:data-provider && npm run build:data-schemas \
                                       && npm run build:api && npm run build:client-package
  - Build the SPA:                  cd client && npm run build
  - Dev server (proxies the shim):  CALADON_SHIM_URL=http://localhost:8787 npm run dev   # client/
  - Run the shim alongside:         cd web-client/shim && npm run dev

The Caladon SDK is aliased from web-client/caladon (@caladon/protocol) by client/vite.config.ts +
client/tsconfig.json. Build the wasm binary first if missing: cd web-client/caladon && npm run build:wasm.
EOF
