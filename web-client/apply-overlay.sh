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
    # FAIL CLOSED. The pin is load-bearing for the trust model: upstream `main` ships a different
    # chat/SSE flow that BYPASSES the sealed surgery, and the measured SPA must be built from the
    # exact audited commit. Silently falling back to HEAD would produce an unaudited, unpinned bundle.
    echo "ERROR: pinned LibreChat commit ${LIBRECHAT_COMMIT} could not be checked out" >&2
    echo "       (upstream history rewritten or network/clone issue). Refusing to build from an" >&2
    echo "       unpinned tree — the measured SPA must come from the exact pinned commit. Aborting." >&2
    rm -rf "${LIBRECHAT_DIR}"
    exit 1
  fi
  # Belt-and-braces: assert we landed on the exact pin.
  ACTUAL_HEAD="$(git -C "${LIBRECHAT_DIR}" rev-parse HEAD)"
  if [ "${ACTUAL_HEAD}" != "${LIBRECHAT_COMMIT}" ]; then
    echo "ERROR: LibreChat HEAD ${ACTUAL_HEAD} != pinned ${LIBRECHAT_COMMIT}. Aborting." >&2
    rm -rf "${LIBRECHAT_DIR}"
    exit 1
  fi
fi

# 2. Copy the overlay over the upstream tree, preserving relative paths.
#
# The copy is generic: EVERY file under overlay/ is copied onto the matching librechat/ path, so
# adding a new overlay file (e.g. the G2 seed-unlock UI:
#   client/src/components/Auth/CaladonUnlock.tsx  — the seed-unlock screen (create/restore identity)
#   client/src/routes/index.tsx                   — route override: /login renders <CaladonUnlock/>
# ) needs no edit here — just drop it in overlay/ and re-run. (List kept in sync with SURGERY.md.)
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
