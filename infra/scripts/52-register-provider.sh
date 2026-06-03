#!/usr/bin/env bash
set -euo pipefail

# Register the local chat model with Letta as an OpenAI-compatible BYOK provider
# pointing at the llama.cpp llama-server.
#
# Why "openai" and not "vllm": Letta's vllm provider parser requires a
# 'max_model_len' field in /v1/models which llama.cpp does not emit (KeyError).
# The openai provider type parses llama-server's /v1/models cleanly. The
# resulting model handle is 'openai-proxy/qwen3.6-35b-a3b'.

source ~/caladon-infra/.env
BASE="http://127.0.0.1:8283"
AUTH="Authorization: Bearer ${LETTA_SERVER_PASSWORD}"

EXISTS=$(curl -s "$BASE/v1/providers/" -H "$AUTH" \
  | python3 -c "import sys,json; print(any(p.get('name')=='local-openai' for p in json.load(sys.stdin)))" 2>/dev/null || echo False)

if [ "$EXISTS" = "True" ]; then
  echo "provider 'local-openai' already registered"
else
  curl -s -X POST "$BASE/v1/providers/" -H "$AUTH" -H "Content-Type: application/json" \
    -d '{"name":"local-openai","provider_type":"openai","api_key":"dummy","base_url":"http://host.docker.internal:8080/v1"}' >/dev/null
  echo "registered provider 'local-openai' -> llama-server"
fi

echo "[*] restarting letta to sync provider models"
docker compose -f ~/caladon-infra/docker-compose.yml restart letta >/dev/null 2>&1
for i in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/health/")" = "200" ] && break; sleep 4
done

echo "[*] chat model handle now available:"
curl -s "$BASE/v1/models/" -H "$AUTH" \
  | python3 -c "import sys,json
for m in json.load(sys.stdin):
    if 'qwen' in (m.get('handle') or '').lower(): print('  -', m['handle'])"
