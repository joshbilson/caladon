#!/usr/bin/env bash
set -euo pipefail

HF_REPO="hf.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive"
QUANT="Q4_K_M"
ALIAS="qwen3.6-35b-a3b"

echo "[*] Pulling ${HF_REPO}:${QUANT} (this downloads ~21 GB)"
ollama pull "${HF_REPO}:${QUANT}"

echo "[*] Tagging as ${ALIAS}"
ollama cp "${HF_REPO}:${QUANT}" "${ALIAS}"

echo "[*] Pulling a dedicated embedding model for Letta archival memory"
ollama pull nomic-embed-text

echo "[*] Installed models:"
ollama list

echo "[*] Smoke test (non-thinking, short):"
curl -fsS http://127.0.0.1:11434/api/generate -d "{
  \"model\": \"${ALIAS}\",
  \"prompt\": \"Reply with exactly the word: ready\",
  \"stream\": false,
  \"options\": {\"num_predict\": 5}
}" | sed 's/.*"response":"\([^"]*\)".*/response=\1/'
