#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing ufw + fail2ban + unattended-upgrades"
sudo apt-get update
sudo apt-get install -y ufw fail2ban unattended-upgrades

echo "[*] Firewall: default deny incoming, allow outgoing, allow OpenSSH"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
# Allow Tailscale interface fully (intra-tailnet traffic)
sudo ufw allow in on tailscale0
sudo ufw --force enable
sudo ufw status verbose

echo "[*] SSH hardening — verifying key auth is present BEFORE disabling passwords"
if ! grep -q '.' "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  echo "ABORT: no authorized_keys; refusing to disable password auth."
  exit 1
fi

SSHD_DROPIN=/etc/ssh/sshd_config.d/99-swifty-hardening.conf
sudo tee "$SSHD_DROPIN" > /dev/null <<'EOF'
PasswordAuthentication no
PermitRootLogin no
KbdInteractiveAuthentication no
EOF

echo "[*] Validating sshd config"
sudo sshd -t
echo "[*] Reloading sshd (existing sessions stay alive)"
sudo systemctl reload ssh

echo "[*] Enabling unattended security upgrades"
echo 'APT::Periodic::Update-Package-Lists "1";'  | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";'    | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades

echo "=== Hardening applied. In a NEW terminal, verify: ssh $VPS_USER@$VPS_HOST 'echo ok' ==="
