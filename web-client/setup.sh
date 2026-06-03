#!/usr/bin/env bash
# Caladon web client setup — fetch the vendored LibreChat upstream and install the shim.
#
# The LibreChat tree is NOT committed to this repo (it's in .gitignore: `web-client/librechat/`).
# Run this once after cloning swifty to materialize it locally. Re-running is idempotent.
#
# Usage:  ./web-client/setup.sh
set -euo pipefail

# Resolve this script's dir so it works from any CWD (agent threads reset CWD between calls).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBRECHAT_DIR="${SCRIPT_DIR}/librechat"
SHIM_DIR="${SCRIPT_DIR}/shim"

# Pinned upstream (keep in sync with web-client/SURGERY.md "Vendored upstream").
LIBRECHAT_REPO="https://github.com/danny-avila/LibreChat"
LIBRECHAT_COMMIT="d680763db3e5ec8e100c824a9b8f6189ab0081cd"  # v0.8.6, 2026-06-02

echo "==> Caladon web-client setup"
echo "    script dir: ${SCRIPT_DIR}"

# 1. Vendored LibreChat (shallow clone; not committed).
if [ -d "${LIBRECHAT_DIR}/.git" ]; then
  echo "==> LibreChat already cloned at ${LIBRECHAT_DIR} (skipping)"
  echo "    HEAD: $(git -C "${LIBRECHAT_DIR}" rev-parse --short HEAD)"
else
  echo "==> Cloning LibreChat (shallow) into ${LIBRECHAT_DIR}"
  git clone --depth 1 "${LIBRECHAT_REPO}" "${LIBRECHAT_DIR}"
  HEAD="$(git -C "${LIBRECHAT_DIR}" rev-parse HEAD)"
  if [ "${HEAD}" != "${LIBRECHAT_COMMIT}" ]; then
    echo "    NOTE: upstream main is now ${HEAD}, not the pinned ${LIBRECHAT_COMMIT}."
    echo "          Surgery line numbers in SURGERY.md are pinned to the latter; re-verify after drift."
  fi
fi

# 2. The shim (committed). Install its deps + sanity-check.
if command -v npm >/dev/null 2>&1; then
  echo "==> Installing shim deps (${SHIM_DIR})"
  ( cd "${SHIM_DIR}" && npm install )
  echo "==> Typechecking the shim"
  ( cd "${SHIM_DIR}" && npm run typecheck )
else
  echo "==> npm not found — skipping shim install (install Node 20+ then: cd shim && npm install)"
fi

cat <<'EOF'

==> Done.

Next:
  - Read  web-client/SURGERY.md   (the file-level surgery map for the LibreChat fork)
  - Shim: cd web-client/shim && npm run dev      (stateless proxy on :8787)
          cd web-client/shim && npm run smoke     (plaintext-first round-trip vs the live gateway)

The vendored web-client/librechat/ tree is git-ignored and never committed.
EOF
