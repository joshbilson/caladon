#!/usr/bin/env bash
set -euo pipefail

if command -v ollama >/dev/null 2>&1; then
  echo "Ollama already installed: $(ollama --version)"
else
  curl -fsSL https://ollama.com/install.sh | sh
fi

# Ensure Ollama listens so Docker containers (Letta) can reach it via
# host.docker.internal. Bind to 0.0.0.0 but rely on ufw (only tailscale0 + ssh
# open) to keep it private. Threads tuned to physical-ish core count.
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_KEEP_ALIVE=30m"
EOF

sudo systemctl daemon-reload
sudo systemctl restart ollama
sleep 2

# Allow Docker containers (Letta) to reach Ollama via the bridge gateway.
# Scoped to the private Docker range; public stays blocked by ufw default-deny.
sudo ufw allow from 172.16.0.0/12 to any port 11434 proto tcp >/dev/null 2>&1 || true

curl -fsS http://127.0.0.1:11434/api/version
echo
echo "Ollama running."
