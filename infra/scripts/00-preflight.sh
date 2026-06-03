#!/usr/bin/env bash
set -euo pipefail

echo "=== Swifty preflight ==="

echo "[*] Whoami / sudo:"
whoami
sudo -n true 2>/dev/null && echo "sudo: OK (passwordless)" || echo "sudo: will prompt for password"

echo "[*] OS:"
. /etc/os-release && echo "$PRETTY_NAME"

echo "[*] RAM (need >= 24G free for Q4 model + Letta):"
free -h | awk '/Mem:/ {print "total="$2" available="$7}'

echo "[*] Disk free on / (need >= 40G for model + images):"
df -h / | awk 'NR==2 {print $4" free"}'

echo "[*] SSH authorized_keys present (so key login keeps working after hardening):"
if [ -s "$HOME/.ssh/authorized_keys" ]; then
  echo "authorized_keys: OK ($(wc -l < "$HOME/.ssh/authorized_keys") key(s))"
else
  echo "authorized_keys: MISSING — DO NOT run hardening until a key is installed"
  exit 1
fi

echo
echo ">>> MANUAL CHECK REQUIRED before running 30-harden.sh:"
echo ">>> 1. Confirm you have provider web-console (VNC/serial) access as a fallback."
echo ">>> 2. Open a SECOND ssh session and keep it open during hardening."
echo "=== preflight complete ==="
