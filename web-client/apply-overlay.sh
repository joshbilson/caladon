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

# 3. Merge the Caladon device-store + RAG dependencies INTO librechat/client/package.json BEFORE the
#    build's `npm install`, rather than bolting them on afterwards.
#
#    Why merge (not an overlay package.json, not a post-hoc `npm install --no-save`):
#      - The client's package.json lives in the CLONED (not-overlaid) librechat tree. Shipping an
#        overlay package.json would CLOBBER librechat's ~200 deps. So we patch the real file in place.
#      - A merge BEFORE `npm install` lets npm's normal resolver hoist/dedupe these and pull their
#        transitive deps (e.g. onnxruntime-web under @huggingface/transformers, the OPFS worker that
#        ships inside @evolu/sqlite-wasm). A post-hoc `--no-save` install is fragile across hoisting.
#      - Idempotent: the node one-liner only ADDS a dep if it is not already pinned, so re-running
#        (or an upstream that later vendors one of these) is a no-op and never downgrades.
#
#    The four runtime deps (LOCKED design):
#      @evolu/sqlite-wasm  — official @sqlite.org/sqlite-wasm + SQLite3MultipleCiphers (SQLCipher key,
#                            FTS5, OPFS via worker) — the encrypted on-device store.
#      @huggingface/transformers — on-device MiniLM embeddings (webgpu→wasm), model served same-origin.
#      pdfjs-dist + mammoth — in-browser PDF/DOCX parsing for RAG ingest (files never uploaded).
CLIENT_PKG="${LIBRECHAT_DIR}/client/package.json"
if [ ! -f "${CLIENT_PKG}" ]; then
  echo "ERROR: ${CLIENT_PKG} not found — cannot merge Caladon deps. Aborting." >&2
  exit 1
fi
echo "==> Merging Caladon device-store + RAG deps into client/package.json"
node -e '
  const fs = require("fs");
  const p = process.argv[1];
  const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
  pkg.dependencies = pkg.dependencies || {};
  // Pinned ranges — keep in sync with web-client/SURGERY.md + the StoreProxy/RAG modules.
  const add = {
    "@evolu/sqlite-wasm": "^2",
    "@huggingface/transformers": "^4",
    "pdfjs-dist": "^6",
    "mammoth": "^1",
  };
  let changed = 0;
  for (const [name, range] of Object.entries(add)) {
    if (!pkg.dependencies[name] && !(pkg.devDependencies && pkg.devDependencies[name])) {
      pkg.dependencies[name] = range;
      changed++;
      console.log("    + " + name + "@" + range);
    } else {
      console.log("    = " + name + " (already present, left as-is)");
    }
  }
  if (changed > 0) fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + "\n");
  console.log("==> client/package.json: " + changed + " dep(s) added.");
' "${CLIENT_PKG}"

# 4. Fetch the RAG embedding model into client/public/models/ so it is served SAME-ORIGIN from
#    /models/ (env.allowRemoteModels=false in embed.worker.ts: the library will NEVER reach
#    huggingface.co at runtime). Best-effort: a build without network still proceeds — the embed
#    worker then logs and RAG retrieval is skipped (fail-open), it never blocks chat. Idempotent:
#    skipped if the model dir already exists.
MODEL_DIR="${LIBRECHAT_DIR}/client/public/models/Xenova/all-MiniLM-L6-v2"
if [ -d "${MODEL_DIR}" ]; then
  echo "==> RAG model already present (skipping download): ${MODEL_DIR}"
else
  echo "==> Fetching RAG model Xenova/all-MiniLM-L6-v2 → client/public/models/ (best-effort)"
  CALADON_MODEL_BASE="https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main"
  # The minimal file set @huggingface/transformers loads for feature-extraction (quantized ONNX).
  CALADON_MODEL_FILES=(
    "config.json"
    "tokenizer.json"
    "tokenizer_config.json"
    "onnx/model_quantized.onnx"
  )
  if command -v curl >/dev/null 2>&1; then
    set +e
    DL_OK=1
    for f in "${CALADON_MODEL_FILES[@]}"; do
      dest="${MODEL_DIR}/${f}"
      mkdir -p "$(dirname "${dest}")"
      if ! curl -fsSL "${CALADON_MODEL_BASE}/${f}" -o "${dest}"; then
        echo "    ! failed to fetch ${f} (RAG will fall back to skip until the model is present)" >&2
        DL_OK=0
      else
        echo "    + ${f}"
      fi
    done
    set -e
    if [ "${DL_OK}" -ne 1 ]; then
      echo "==> RAG model fetch incomplete — leaving partial dir; re-run with network to complete." >&2
    else
      echo "==> RAG model fetched."
    fi
  else
    echo "    ! curl not found — skipping model fetch. Place the model at ${MODEL_DIR} manually." >&2
  fi
fi

cat <<'EOF'

==> Done. Next:
  - Install deps (monorepo root):  cd web-client/librechat && npm install
        (the Caladon device-store + RAG deps were just merged into client/package.json, so this
         single install resolves them with everything else — no extra install step needed.)
  - Build the shared packages:      npm run build:data-provider && npm run build:data-schemas \
                                       && npm run build:api && npm run build:client-package
  - Build the SPA:                  cd client && npm run build
        (the RAG model was fetched to client/public/models/ above so it is served same-origin
         from /models/; the store/embed workers bundle automatically via import.meta.url.)
  - Dev server (proxies the shim):  CALADON_SHIM_URL=http://localhost:8787 npm run dev   # client/
  - Run the shim alongside:         cd web-client/shim && npm run dev

The Caladon SDK is aliased from web-client/caladon (@caladon/protocol) by client/vite.config.ts +
client/tsconfig.json. Build the wasm binary first if missing: cd web-client/caladon && npm run build:wasm.
EOF
