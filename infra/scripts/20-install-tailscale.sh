#!/usr/bin/env bash
set -euo pipefail

if command -v tailscale >/dev/null 2>&1; then
  echo "Tailscale already installed: $(tailscale version | head -1)"
else
  curl -fsSL https://tailscale.com/install.sh | sh
fi

echo "Bringing Tailscale up. This prints an auth URL — open it in a browser to log in."
echo "Using --ssh so you can also reach the box via Tailscale SSH as a fallback."
sudo tailscale up --ssh

echo "Tailnet IPv4 for this host:"
tailscale ip -4
