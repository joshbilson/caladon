#!/usr/bin/env bash
set -euo pipefail

# Serve Qwen3.6-35B-A3B (qwen35moe) via upstream llama.cpp's llama-server.
# Ollama cannot load this architecture; llama.cpp can. Ollama is kept only for
# embeddings (nomic-embed-text). The GGUF is reused from Ollama's blob store
# (no second 21 GB download) via a symlink.

LLAMA_DIR="$HOME/llamacpp/llama-b9464"
MODEL_LINK="$HOME/models/qwen3.6-35b-a3b.gguf"
OLLAMA_BLOB="/usr/share/ollama/.ollama/models/blobs/sha256-bbef58c37ce88820be9d98b6437f1cf4bac890c947bd55fc7b68e22098574231"

echo "[*] Ensuring model symlink"
mkdir -p "$HOME/models"
ln -sf "$OLLAMA_BLOB" "$MODEL_LINK"

echo "[*] Stopping any manually-launched llama-server (specific pattern, not this script)"
pkill -f 'llama-b9464/llama-server' 2>/dev/null || true
sleep 1

echo "[*] Installing runtime libs (idempotent)"
sudo apt-get install -y libgomp1 libcurl4 >/dev/null 2>&1 || true

# Allow Docker containers (e.g. Letta) to reach this service via the bridge
# gateway. Scoped to the private Docker range only; public stays blocked by
# ufw default-deny (no public allow rule for 8080).
echo "[*] ufw: allow docker subnet -> host:8080"
sudo ufw allow from 172.16.0.0/12 to any port 8080 proto tcp >/dev/null 2>&1 || true

echo "[*] Writing systemd unit (localhost:8080, OpenAI-compatible)"
sudo tee /etc/systemd/system/llama-server.service > /dev/null <<EOF
[Unit]
Description=llama.cpp server (Qwen3.6-35B-A3B) for Swifty
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$LLAMA_DIR
Environment=LD_LIBRARY_PATH=$LLAMA_DIR
ExecStart=$LLAMA_DIR/llama-server -m $MODEL_LINK --alias qwen3.6-35b-a3b --host 0.0.0.0 --port 8080 -c 32768 -t 20 --jinja
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now llama-server
echo "[*] Waiting for health..."
until curl -fsS http://127.0.0.1:8080/health 2>/dev/null | grep -q ok; do sleep 4; done
echo "llama-server: $(curl -fsS http://127.0.0.1:8080/health)"
