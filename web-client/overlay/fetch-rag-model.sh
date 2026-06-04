#!/usr/bin/env bash
# Caladon RAG — fetch the on-device embedding model (MANUAL one-time step).
#
# The RAG retrieval/ingest pipeline embeds text ENTIRELY on-device with
# Xenova/all-MiniLM-L6-v2 (384-dim) via @huggingface/transformers. For the trust model to hold,
# the model is served SAME-ORIGIN from /models/ and the library is configured with
# env.allowRemoteModels=false — so the browser NEVER fetches model bytes from huggingface.co at
# runtime. This script downloads those bytes ONCE into the client's public/ tree so Vite serves
# them with the rest of the bundle.
#
# WHY MANUAL: the ONNX weights are ~22 MB; we don't commit-by-default from the build agent. Run
# this locally, verify the files, then COMMIT them (they are part of the audited, measured SPA).
#
#   Usage:   web-client/overlay/fetch-rag-model.sh
#   Output:  web-client/overlay/client/public/models/Xenova/all-MiniLM-L6-v2/
#
# After running, the directory layout transformers.js expects (env.localModelPath="/models/") is:
#   /models/Xenova/all-MiniLM-L6-v2/config.json
#   /models/Xenova/all-MiniLM-L6-v2/tokenizer.json
#   /models/Xenova/all-MiniLM-L6-v2/tokenizer_config.json
#   /models/Xenova/all-MiniLM-L6-v2/onnx/model_quantized.onnx   (the quantized weights we load)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_REPO="Xenova/all-MiniLM-L6-v2"
HF_BASE="https://huggingface.co/${MODEL_REPO}/resolve/main"
DEST="${SCRIPT_DIR}/client/public/models/${MODEL_REPO}"

# Files transformers.js needs for a feature-extraction pipeline. We pull BOTH the quantized and the
# full-precision ONNX so either dtype works; quantized is the default the worker loads (smaller).
ROOT_FILES=(
  "config.json"
  "tokenizer.json"
  "tokenizer_config.json"
  "special_tokens_map.json"
  "vocab.txt"
)
ONNX_FILES=(
  "onnx/model_quantized.onnx"
  "onnx/model.onnx"
)

echo "==> Fetching ${MODEL_REPO} into:"
echo "    ${DEST}"
mkdir -p "${DEST}/onnx"

fetch() {
  local rel="$1"
  local url="${HF_BASE}/${rel}"
  local out="${DEST}/${rel}"
  mkdir -p "$(dirname "${out}")"
  echo "    + ${rel}"
  # -L follow redirects, -f fail on HTTP error, --retry for flaky CDN, -C - resume partials.
  if ! curl -fL --retry 3 -C - -o "${out}" "${url}"; then
    echo "ERROR: failed to download ${url}" >&2
    return 1
  fi
}

MISSING_OPTIONAL=0
for f in "${ROOT_FILES[@]}"; do
  fetch "${f}" || { echo "ERROR: required file ${f} missing" >&2; exit 1; }
done
for f in "${ONNX_FILES[@]}"; do
  # The full-precision model.onnx may not exist for every revision; treat it as best-effort and
  # only hard-require the quantized weights the worker defaults to.
  if ! fetch "${f}"; then
    if [ "${f}" = "onnx/model_quantized.onnx" ]; then
      echo "ERROR: required quantized weights ${f} missing" >&2
      exit 1
    fi
    echo "    (optional ${f} unavailable — skipping)"
    MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
  fi
done

echo "==> Done. Verify the tree, then COMMIT it (it is part of the measured SPA):"
echo "    git add web-client/overlay/client/public/models/${MODEL_REPO}"
du -sh "${DEST}" 2>/dev/null || true
echo
echo "Reminder: the SPA loads this SAME-ORIGIN (env.allowRemoteModels=false). If these files are"
echo "missing at runtime, embedding fails closed (no remote fetch) and RAG is silently skipped."
