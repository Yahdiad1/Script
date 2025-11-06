#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer + Interactive Color Menu
# Features:
#  - Debian 10..12 support
#  - SSH / Dropbear / Stunnel4 / Nginx
#  - Xray (install-release.sh official)
#  - SlowDNS (purwasasmito)
#  - UDP-Custom (akunssh binary)
#  - Menu (command: menu) with color UI
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

# ------- Configuration (edit only if you know what you do) -------
ADMIN_USER="yhds"
ADMIN_PASS="yhds"
UDP_CUSTOM_PORT=7300
SLOWDNS_UDP_PORT=5300
XRAY_PORT=443
XRAY_WS_PATH="/vless"
TIMEZONE="Asia/Jakarta"
REPO_ROOT="https://raw.githubusercontent.com/Yahdiad1/pgetunnel/main"
# ------------------------------------------------------------------

# Colors
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
MAGENTA='\e[1;35m'
CYAN='\e[1;36m'
NC='\e[0m'

echoinfo(){ echo -e "${CYAN}[INFO]${NC} $*"; }
echowarn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
echoerr(){ echo -e "${RED}[ERR]${NC} $*"; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
  echoerr "This script must be run as root."
  exit 1
fi

# Check virtualization
if command -v systemd-detect-virt >/dev/null 2>&1; then
  if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echoerr "OpenVZ is not supported."
    exit 1
  fi
fi

# Basic environment
export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# Ensure apt works
echoinfo "Updating package lists..."
apt update -y >/dev/null 2>&1 || { echoerr "apt update failed"; }

# Install base packages
echoinfo "Installing required packages..."
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat >/dev/null 2>&1 || true

# Kernel headers best-effort
KVER=$(uname -r)
if ! dpkg -s linux-headers-"$KVER" >/dev/null 2>&1; then
  echoinfo "Installing linux-headers (best-effort)..."
  apt install -y linux-headers-"$KVER" >/dev/null 2>&1 || echowarn "linux-headers install failed (not fatal)."
fi

# ---------------- Domain selection ----------------
clear
echo -e "${MAGENTA}========================================${NC}"
echo -e "${BLUE}        SETUP: DOMAIN CONFIGURATION      ${NC}"
echo -e "${MAGENTA}========================================${NC}"
echo "1) Use your own domain"
echo "2) Create random domain (local fake domain for config)"
read -rp "Choose 1 or 2 [default 2]: " choice_domain
choice_domain=${choice_domain:-2}

if [ "$choice_domain" = "1" ]; then
  read -rp "Enter your domain (example: vpn.example.com): " INPUT_DOMAIN
  DOMAIN="$INPUT_DOMAIN"
else
  RAND=$(tr -dc 'a-z0-9' </dev/urandom | head -c6)
  DOMAIN="vpn-${RAND}.local"
fi

echo "$DOMAIN" > /root/domain
echoinfo "Domain set to: ${GREEN}$DOMAIN${NC}"

# ---------------- Create admin user ----------------
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  echoinfo "Creating admin user: $ADMIN_USER"
  useradd -m -s /bin/bash "$ADMIN_USER" || true
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1 || true
  usermod -aG sudo "$ADMIN_USER" >/dev/null 2>&1 || true
else
  echoinfo "Admin user $ADMIN_USER already exists, skipping creation."
fi

# ---------------- Setup services ----------------
echoinfo "Installing and starting base services (nginx, dropbear, stunnel4)..."
apt install -y nginx dropbear stunnel4 >/dev/null 2>&1 || true

# Dropbear config
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 2>/dev/null || true
# Configure extra ports: 109 & 143
grep -q "DROPBEAR_PORT=109" /etc/default/dropbear || sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/' /etc/default/dropbear || true
if ! grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear 2>/dev/null; then
  echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
fi
systemctl enable dropbear
systemctl restart dropbear

# stunnel basic enable
systemctl enable stunnel4
systemctl restart stunnel4 || true

# nginx enable
systemctl enable nginx
systemctl restart nginx || true

echoinfo "Base services configured."

# ---------------- UDP-Custom (akunssh) ----------------
echoinfo "Installing UDP-Custom (akunssh)..."
cd /root || true
# Try to download prebuilt binary from official GitHub release (linux amd64)
UDP_BIN_URL="https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64"
if wget -q --tries=3 --timeout=15 -O /root/udp-custom "$UDP_BIN_URL"; then
  chmod +x /root/udp-custom
  cat > /etc/systemd/system/udp-custom.service <<'EOF'
[Unit]
Description=UDP-Custom (akunssh) service
After=network.target

[Service]
Type=simple
ExecStart=/root/udp-custom server -p 7300 -mode auto
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable udp-custom
  systemctl start udp-custom
  echoinfo "UDP-Custom installed and started on port ${UDP_CUSTOM_PORT}."
else
  echoerr "Failed to download UDP-Custom binary. UDP service not started."
fi

# ---------------- Xray install ----------------
echoinfo "Installing Xray (official installer)..."
# Use official Xray install script
if curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh; then
  bash /tmp/xray-install.sh >/dev/null 2>&1 || echowarn "Xray installer returned nonzero (check logs)."
else
  echowarn "Failed to fetch Xray installer script."
fi

# Create a minimal Xray config (VLESS over WS)
mkdir -p /etc/xray
XRAY_UUID="11111111-2222-3333-4444-555555555555"   # default client id (change later)
cat > /etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${XRAY_UUID}", "flow":"", "level":0, "email":"user@local" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "${XRAY_WS_PATH}" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
# Enable and restart xray service if available
if systemctl list-unit-files | grep -q xray; then
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  echoinfo "Xray service configured (port ${XRAY_PORT}, ws path ${XRAY_WS_PATH})."
else
  echowarn "Xray service unit not found — check install logs."
fi

# ---------------- SlowDNS ----------------
echoinfo "Installing SlowDNS (purwasasmito)..."
cd /root || true
if [ ! -d /root/slowdns ]; then
  if git clone https://github.com/purwasasmito/slowdns.git /root/slowdns >/dev/null 2>&1; then
    cd /root/slowdns
    # Build server
    if go build -o slowdns server.go >/dev/null 2>&1; then
      mv slowdns /usr/local/bin/slowdns || true
      # systemd unit
      cat > /etc/systemd/system/slowdns.service <<'EOF'
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -udp 5300 -tcp 443 -name ns1.local
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable slowdns
      systemctl start slowdns
      echoinfo "SlowDNS installed and started (udp ${SLOWDNS_UDP_PORT})."
    else
      echowarn "Failed to build SlowDNS from source."
    fi
  else
    echowarn "Failed to clone SlowDNS repository."
  fi
else
  echoinfo "SlowDNS already present; skipping clone."
fi

# --------------- Helper functions for menu ---------------
menu_add_user(){
  read -rp "Username: " _u
  read -rp "Password: " -s _p; echo; read -rp "Confirm Password: " -s _p2; echo
  if [ "$_p" != "$_p2" ]; then
    echoerr "Passwords do not match."
    return
  fi
  if id "$_u" >/dev/null 2>&1; then
    echowarn "User exists."
    return
  fi
  useradd -m -s /bin/bash "$_u" || { echoerr "Failed to add user."; return; }
  echo -e "${_p}\n${_p}" | passwd "$_u" >/dev/null 2>&1 || true
  chage -M 30 "$_u" >/dev/null 2>&1 || true
  echoinfo "User $_u created (default expiry 30 days)."
}

menu_del_user(){
  read -rp "Username to delete: " _u
  if ! id "$_u" >/dev/null 2>&1; then
    echowarn "User not found."
    return
  fi
  userdel -r "$_u" >/dev/null 2>&1 || { echoerr "Failed to delete user."; return; }
  echoinfo "User $_u deleted."
}

menu_renew_user(){
  read -rp "Username to extend (days): " _u
  read -rp "Extra days (number): " _d
  if ! id "$_u" >/dev/null 2>&1; then
    echowarn "User not found."
    return
  fi
  # get current expiry in epoch (if chage info available)
  cur_exp=$(chage -l "$_u" 2>/dev/null | grep "Account expires" | cut -d: -f2- | xargs || echo "never")
  if [ "$cur_exp" = "never" ] || [ -z "$cur_exp" ]; then
    # set expiry from today
    newdate=$(date -d "+${_d} days" +"%Y-%m-%d")
  else
    # parse current expiry to date and add days
    newdate=$(date -d "${cur_exp} + ${_d} days" +"%Y-%m-%d" 2>/dev/null || date -d "+${_d} days" +"%Y-%m-%d")
  fi
  chage -E "$(date -d "$newdate" +%Y-%m-%d)" "$_u" >/dev/null 2>&1 || true
  echoinfo "User $_u expiry extended to $newdate"
}

menu_list_users(){
  echo -e "${MAGENTA}Local users (home dirs):${NC}"
  awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | xargs -n1 -I{} bash -c 'u="{}"; echo -n "- $u"; chage -l $u | grep "Account expires" | sed "s/^/ ---> /";'
}

menu_restart_services(){
  echo -e "${YELLOW}Restarting common services...${NC}"
  for s in nginx dropbear stunnel4 xray slowdns udp-custom; do
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then
      echoinfo "Restarting $s"
      systemctl restart "$s" >/dev/null 2>&1 || echowarn "Failed to restart $s (or service not present)."
    fi
  done
  echoinfo "Done."
}

menu_info(){
  echo -e "${CYAN}========= SERVER INFO =========${NC}"
  echo -e "Domain  : $(cat /root/domain 2>/dev/null || echo '-')"
  echo -e "IP      : $(curl -sS ipv4.icanhazip.com || echo '-')"
  echo -e "CPU     : $(nproc) cores"
  echo -e "Memory  : $(free -h | awk '/Mem:/ {print $3\"/\"$2}')"
  echo -e "Uptime  : $(uptime -p)"
  echo -e "Time    : $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "Services:"
  for s in nginx dropbear stunnel4 xray slowdns udp-custom; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      echo -e "  ${GREEN}$s: running${NC}"
    else
      echo -e "  ${RED}$s: not running${NC}"
    fi
  done
  echo -e "${CYAN}===============================${NC}"
}

menu_view_logs(){
  echo -e "${YELLOW}Available logs (if present):${NC}"
  ls -1 /root | grep -E "log|install|xray|slow" || echo "- none"
  echo
  read -rp "Enter filename under /root to view (or ENTER to cancel): " LOGF
  if [ -n "$LOGF" ] && [ -f "/root/$LOGF" ]; then
    less "/root/$LOGF"
  fi
}

# ------------ Save small menu script into /usr/local/bin/menu ------------
cat > /usr/local/bin/menu <<'BASHMENU'
#!/usr/bin/env bash
# Simple color menu wrapper that calls functions inside /etc/yhds-menu
if [ ! -f /etc/yhds-menu ]; then
  echo "Menu not installed or corrupted. Please run install script again."
  exit 1
fi
# shellcheck source=/etc/yhds-menu
source /etc/yhds-menu
_main_menu
BASHMENU
chmod +x /usr/local/bin/menu

# ------------ Persist menu functions to source file /etc/yhds-menu ------------
cat > /etc/yhds-menu <<'BASHFUNC'
#!/usr/bin/env bash
# YHDS menu functions (sourced by /usr/local/bin/menu)
GREEN='\e[1;32m'; RED='\e[1;31m'; YELLOW='\e[1;33m'; CYAN='\e[1;36m'; MAGENTA='\e[1;35m'; NC='\e[0m'

# import helpers from system if available
_main_menu(){
  while true; do
    clear
    echo -e "${MAGENTA}================================================${NC}"
    echo -e "${CYAN}   YHDS SERVER MANAGEMENT MENU (colorful)${NC}"
    echo -e "${MAGENTA}================================================${NC}"
    echo -e "${GREEN}1) Add user${NC}         ${YELLOW}5) Restart services${NC}"
    echo -e "${GREEN}2) Delete user${NC}      ${YELLOW}6) Server info${NC}"
    echo -e "${GREEN}3) Renew user expiry${NC} ${YELLOW}7) View logs${NC}"
    echo -e "${GREEN}4) List users${NC}       ${RED}0) Exit${NC}"
    echo -e "${MAGENTA}================================================${NC}"
    read -rp "Select [0-7]: " opt
    case "$opt" in
      1) menu_add_user;;
      2) menu_del_user;;
      3) menu_renew_user;;
      4) menu_list_users;;
      5) menu_restart_services;;
      6) menu_info;;
      7) menu_view_logs;;
      0) exit 0;;
      *) echo -e "${RED}Invalid option${NC}"; sleep 1;;
    esac
    echo -e "\nPress ENTER to continue..."
    read -r _
  done
}

# Define wrappers that call original functions defined in /etc/profile.d/yhds_helpers.sh
menu_add_user(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_add_user "$@"'; }
menu_del_user(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_del_user "$@"'; }
menu_renew_user(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_renew_user "$@"'; }
menu_list_users(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_list_users "$@"'; }
menu_restart_services(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_restart_services "$@"'; }
menu_info(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_info "$@"'; }
menu_view_logs(){ bash -c '. /etc/profile.d/yhds_helpers.sh; menu_view_logs "$@"'; }

BASHFUNC

# ------------ Persist helper functions to /etc/profile.d/yhds_helpers.sh ------------
cat > /etc/profile.d/yhds_helpers.sh <<'BASHHELP'
#!/usr/bin/env bash
# Helper functions used by menu (actual implementations)

menu_add_user(){
  read -rp "Username: " _u
  read -rp "Password: " -s _p; echo
  read -rp "Confirm Password: " -s _p2; echo
  if [ "$_p" != "$_p2" ]; then
    echo "Passwords do not match."; return
  fi
  if id "$_u" >/dev/null 2>&1; then
    echo "User exists."; return
  fi
  useradd -m -s /bin/bash "$_u"
  echo -e "${_p}\n${_p}" | passwd "$_u" >/dev/null 2>&1 || true
  chage -M 30 "$_u" >/dev/null 2>&1 || true
  echo "User $_u created (expiry default 30 days)."
}

menu_del_user(){
  read -rp "Username to delete: " _u
  if ! id "$_u" >/dev/null 2>&1; then
    echo "User not found."; return
  fi
  userdel -r "$_u" >/dev/null 2>&1 || echo "Failed to delete user."
  echo "User $_u deleted."
}

menu_renew_user(){
  read -rp "Username to extend: " _u
  read -rp "Extra days (number): " _d
  if ! id "$_u" >/dev/null 2>&1; then
    echo "User not found."; return
  fi
  # compute new expiry
  cur=$(chage -l "$_u" | grep "Account expires" | cut -d: -f2- | xargs)
  if [ -z "$cur" ] || [ "$cur" = "never" ]; then
    new=$(date -d "+${_d} days" +"%Y-%m-%d")
  else
    new=$(date -d "${cur} + ${_d} days" +"%Y-%m-%d" 2>/dev/null || date -d "+${_d} days" +"%Y-%m-%d")
  fi
  chage -E "$new" "$_u" || true
  echo "User $_u expiry set to $new"
}

menu_list_users(){
  awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | xargs -n1 -I{} bash -c 'u="{}"; echo -n "- $u"; chage -l $u | grep "Account expires" | sed "s/^/ ---> /";'
}

menu_restart_services(){
  for s in nginx dropbear stunnel4 xray slowdns udp-custom; do
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then
      systemctl restart "$s" >/dev/null 2>&1 || echo "$s restart failed"
      echo "$s restarted"
    else
      echo "$s not enabled/present"
    fi
  done
}

menu_info(){
  echo "Domain: $(cat /root/domain 2>/dev/null || echo '-')"
  echo "IP    : $(curl -sS ipv4.icanhazip.com || echo '-')"
  echo "Uptime: $(uptime -p)"
  echo "Mem   : $(free -h | awk '/Mem:/ {print $3\"/\"$2}')"
  for s in nginx dropbear stunnel4 xray slowdns udp-custom; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      echo "$s: running"
    else
      echo "$s: not running"
    fi
  done
}

menu_view_logs(){
  ls -1 /root | grep -E "log|install|xray|slow" || echo "- none"
  read -rp "File in /root to view (ENTER to cancel): " f
  [ -n "$f" -a -f "/root/$f" ] && less "/root/$f"
}
BASHHELP

chmod +x /usr/local/bin/menu
chmod +x /etc/profile.d/yhds_helpers.sh
chmod +x /etc/yhds-menu

# ------------- Create a simple banner/alias so users know how to open menu -------------
cat > /etc/update-motd.d/99-yhds <<'EOM'
#!/bin/sh
printf "\n\x1b[36mYHDS Installer\x1b[0m - type \x1b[33mmenu\x1b[0m to open management panel\n\n"
EOM
chmod +x /etc/update-motd.d/99-yhds

# ------------- Write a short install summary -------------
cat > /root/install-summary.txt <<EOF
YHDS Installer Summary
======================
Domain: $(cat /root/domain 2>/dev/null || echo "-")
IP: $(curl -sS ipv4.icanhazip.com || echo "-")
Admin user: ${ADMIN_USER}
Admin pass: ${ADMIN_PASS}
UDP-Custom port: ${UDP_CUSTOM_PORT}
Xray port: ${XRAY_PORT} (ws path ${XRAY_WS_PATH})
SlowDNS UDP: ${SLOWDNS_UDP_PORT}
Menu: run 'menu'
EOF

echoinfo "Installation finished. Summary saved to /root/install-summary.txt"
cat /root/install-summary.txt

echoinfo "Please reboot the server to finalize (recommended):"
echo -e "  ${YELLOW}reboot${NC}"

# End of installer
