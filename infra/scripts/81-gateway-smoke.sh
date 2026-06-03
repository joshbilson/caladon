#!/usr/bin/env bash
set -euo pipefail
# End-to-end check against the tailnet HTTPS URL. Pass the URL + a device token.
URL="${1:?usage: 81-gateway-smoke.sh <https-url> <device-token>}"
TOK="${2:?missing device token}"

echo "[*] health"; curl -s "${URL}/health"; echo
echo "[*] whoami"; curl -s "${URL}/v1/whoami" -H "Authorization: Bearer ${TOK}"; echo
echo "[*] chat (SSE; first lines)"
curl -sN -X POST "${URL}/v1/chat" -H "Authorization: Bearer ${TOK}" \
  -H "Content-Type: application/json" -d '{"text":"Say hi in 5 words."}' | head -20
