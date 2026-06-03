#!/usr/bin/env bash
set -euo pipefail

# Expose the localhost-bound gateway (127.0.0.1:8088) as HTTPS on the tailnet
# only. Requires HTTPS + MagicDNS enabled in the Tailscale admin console.
# Produces a URL like https://<host>.<tailnet>.ts.net with a valid cert — so
# iOS App Transport Security is satisfied and nothing is exposed publicly.

echo "[*] Enabling Tailscale Serve (HTTPS -> 127.0.0.1:8088)"
sudo tailscale serve --bg --https=443 http://127.0.0.1:8088

echo "[*] Serve status:"
sudo tailscale serve status

echo "[*] Your gateway HTTPS URL (give this to the iOS app):"
echo "https://$(tailscale status --json | python3 -c 'import sys,json;print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
