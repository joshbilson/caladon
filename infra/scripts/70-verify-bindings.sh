#!/usr/bin/env bash
set -euo pipefail

# Verifies the network exposure model for M1a:
#   - Postgres (5432) and Letta (8283): docker-published to 127.0.0.1 ONLY.
#   - llama-server (8080) and Ollama (11434): bound 0.0.0.0 so the Letta
#     container can reach them via the docker bridge, but protected by ufw
#     (no public allow rule; only the private docker range + tailnet permitted).
# Public internet reaches NOTHING here except SSH; everything else is for the
# gateway over Tailscale (M1b).

echo "[*] Listening sockets of interest:"
ss -tlnp 2>/dev/null | awk 'NR==1 || /:5432|:8283|:8080|:11434/'

FAIL=0
# Postgres + Letta must be 127.0.0.1 only (never 0.0.0.0)
for p in 5432 8283; do
  if ss -tln | grep -qE "0\.0\.0\.0:${p}|\[::\]:${p}"; then echo "FAIL: port ${p} exposed on all interfaces"; FAIL=1; fi
done

echo "[*] ufw status (expect: default deny in; OpenSSH + tailscale0 allowed; 8080/11434 only from 172.16.0.0/12):"
sudo ufw status verbose | sed -n '1,30p'

# There must be NO 'Anywhere' allow rule for the LLM ports (only docker subnet).
for p in 8080 11434; do
  if sudo ufw status | grep -E "^${p}(/tcp)?\s" | grep -qi "Anywhere"; then
    echo "FAIL: ufw allows ${p} from Anywhere (should be 172.16.0.0/12 only)"; FAIL=1
  fi
done

echo "[*] Confirm public default-deny is active:"
sudo ufw status verbose | grep -qi "deny (incoming)" && echo "  default deny incoming: OK" || { echo "  FAIL: default incoming not deny"; FAIL=1; }

[ "$FAIL" -eq 0 ] && echo "=== Binding verification PASSED ===" || { echo "=== FAILED ==="; exit 1; }
