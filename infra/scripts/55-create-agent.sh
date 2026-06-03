#!/usr/bin/env bash
set -euo pipefail

# Run ON the VPS. Creates the 'swifty' Letta agent bound to the local chat model
# (via llama.cpp) and the local Ollama embedding model. Requires that
# 52-register-provider.sh has been run first.

source ~/caladon-infra/.env
BASE="http://127.0.0.1:8283"
AUTH="Authorization: Bearer ${LETTA_SERVER_PASSWORD}"
CHAT_HANDLE="openai-proxy/qwen3.6-35b-a3b"      # from the local-openai BYOK provider
EMBED_HANDLE="ollama/nomic-embed-text:latest"   # from the Ollama provider

echo "[*] Creating agent 'swifty'"
AGENT=$(curl -s -X POST "${BASE}/v1/agents/" -H "${AUTH}" -H "Content-Type: application/json" -d "{
  \"name\": \"swifty\",
  \"model\": \"${CHAT_HANDLE}\",
  \"embedding\": \"${EMBED_HANDLE}\",
  \"memory_blocks\": [
    {\"label\": \"persona\", \"value\": \"I am Swifty, a private personal assistant. I am concise and helpful.\"},
    {\"label\": \"human\", \"value\": \"The user is the owner of this self-hosted assistant.\"}
  ]
}")
AGENT_ID=$(echo "$AGENT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo "AGENT_ID=${AGENT_ID}"
[ -z "$AGENT_ID" ] && { echo "CREATE FAILED:"; echo "$AGENT" | head -c 600; exit 1; }
echo "${AGENT_ID}" > ~/caladon-infra/agent_id.txt

echo "[*] Test message (runs local Qwen via llama-server; allow time on CPU)"
curl -s -X POST "${BASE}/v1/agents/${AGENT_ID}/messages" -H "${AUTH}" -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Say hello in one short sentence and tell me what you are."}]}' \
  | python3 -c "import sys,json
d=json.load(sys.stdin); msgs=d.get('messages',d) if isinstance(d,dict) else d
for m in msgs:
    t=m.get('message_type') or m.get('role')
    if t=='assistant_message': print('ASSISTANT:', (m.get('content') or '')[:300])"
echo "=== If you see an assistant reply above, the local brain works end-to-end. ==="
