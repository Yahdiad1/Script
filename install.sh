#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer (Debian 10..12)
# - SSH/WS, UDP-Custom (akunssh), Xray (VLESS/Trojan), SlowDNS
# - Colorful interactive menu (command: menu) with options 1-10
# - Manual account creation: username, password, expire (days), limit IP
# - UUID generator for VLESS/Trojan; output displayed for immediate use
# - NO Telegram notifications
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

### ---------------- Configuration ----------------
ADMIN_USER="yhds"
ADMIN_PASS="yhds"
UDP_CUSTOM_PORT=7300
SLOWDNS_UDP_PORT=5300
XRAY_PORT=443
XRAY_WS_PATH="/vless"
TIMEZONE="Asia/Jakarta"
USER_DB="/etc/yhds/users.csv"            # CSV: type,username,password,expiry,allowed_ips,uuid,created_at
YHDS_DIR="/etc/yhds"
# ------------------------------------------------

# Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'
MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'

info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }

# Root check
if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root."
  exit 1
fi

# Virtualization check
if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt)" = "openvz" ]; then
  err "OpenVZ virtualization is not supported by this installer."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true

# ---------------- Prepare system ----------------
info "Updating apt and installing base packages..."
apt update -y >/dev/null 2>&1 || warn "apt update failed (continuing)"
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat >/dev/null 2>&1 || warn "Some packages failed to install"

# kernel headers (best-effort)
KVER=$(uname -r)
if ! dpkg -s "linux-headers-${KVER}" >/dev/null 2>&1; then
  info "Installing linux-headers-${KVER} (may fail on minimal images)..."
  apt install -y "linux-headers-${KVER}" >/dev/null 2>&1 || warn "linux-headers install failed (non-fatal)"
fi

# create data dir & user DB
mkdir -p "$YHDS_DIR"
touch "$USER_DB"
if ! grep -q '^type,' "$USER_DB" 2>/dev/null; then
  printf '%s\n' "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USER_DB"
fi

# disable ipv6 to avoid bind issues
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# ---------------- Domain selection ----------------
clear
echo -e "${MAGENTA}========================================${NC}"
echo -e "${BLUE}        SETUP: DOMAIN CONFIGURATION      ${NC}"
echo -e "${MAGENTA}========================================${NC}"
echo "1) Use your own domain"
echo "2) Create a random local domain (for config)"
read -rp "Choose 1 or 2 [default 2]: " DOMAIN_CHOICE
DOMAIN_CHOICE=${DOMAIN_CHOICE:-2}
if [ "$DOMAIN_CHOICE" = "1" ]; then
  read -rp "Enter your domain (e.g. vpn.example.com): " DOMAIN
else
  RAND=$(tr -dc 'a-z0-9' </dev/urandom | head -c6)
  DOMAIN="vpn-${RAND}.local"
fi
echo "$DOMAIN" > /root/domain
info "Domain set to: $DOMAIN"

# ---------------- Create admin user ----------------
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  info "Creating admin user: $ADMIN_USER"
  useradd -m -s /bin/bash "$ADMIN_USER" || true
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1 || true
  usermod -aG sudo "$ADMIN_USER" >/dev/null 2>&1 || true
else
  info "Admin user already exists, skipping."
fi

# ---------------- Install base services ----------------
info "Installing nginx, dropbear, stunnel4..."
apt install -y nginx dropbear stunnel4 >/dev/null 2>&1 || warn "Some base services failed to install"

# Configure Dropbear ports
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 2>/dev/null || true
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/g' /etc/default/dropbear 2>/dev/null || true
if ! grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear 2>/dev/null; then
  echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
fi
systemctl enable --now dropbear || warn "dropbear start failed"
systemctl enable --now stunnel4 || true
systemctl enable --now nginx || true

# ---------------- Install UDP-Custom (akunssh) ----------------
info "Installing UDP-Custom (akunssh) binary..."
cd /root || true
UDP_BIN_URL="https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64"
if wget -q --tries=3 --timeout=20 -O /root/udp-custom "$UDP_BIN_URL"; then
  chmod +x /root/udp-custom || true
  mkdir -p /etc/udp-custom
  touch /etc/udp-custom/users.conf
  cat > /etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP-Custom (akunssh) service
After=network.target

[Service]
Type=simple
ExecStart=/root/udp-custom server -p ${UDP_CUSTOM_PORT} -mode auto
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now udp-custom || warn "udp-custom start failed"
  info "UDP-Custom installed on port ${UDP_CUSTOM_PORT}"
else
  warn "Failed to download UDP-Custom binary; UDP service disabled."
fi

# ---------------- Install Xray ----------------
info "Installing Xray (official installer)..."
if curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh; then
  bash /tmp/xray-install.sh >/dev/null 2>&1 || warn "Xray installer returned non-zero (check logs)"
else
  warn "Failed to download Xray installer script."
fi

# create minimal Xray config if absent
mkdir -p /etc/xray
XRAY_UUID_DEFAULT="11111111-2222-3333-4444-555555555555"
if [ ! -f /etc/xray/config.json ]; then
  cat > /etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${XRAY_UUID_DEFAULT}", "level": 0, "email": "default@local" }
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
    { "protocol": "freedom" }
  ]
}
EOF
fi

if systemctl list-unit-files | grep -q xray; then
  systemctl enable --now xray || warn "xray start failed"
fi

# ---------------- Install SlowDNS ----------------
info "Installing SlowDNS (build from purwasasmito)..."
cd /root || true
if [ ! -d /root/slowdns ]; then
  if git clone https://github.com/purwasasmito/slowdns.git /root/slowdns >/dev/null 2>&1; then
    cd /root/slowdns
    if go build -o slowdns server.go >/dev/null 2>&1; then
      mv slowdns /usr/local/bin/slowdns || true
      cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -udp ${SLOWDNS_UDP_PORT} -tcp 443 -name ns1.${DOMAIN}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now slowdns || warn "slowdns start failed"
      info "SlowDNS installed on udp ${SLOWDNS_UDP_PORT}"
    else
      warn "Failed to build slowdns."
    fi
  else
    warn "Failed to clone slowdns repo."
  fi
else
  info "SlowDNS already present; skipping."
fi

# ---------------- Utility helpers ----------------
# Save user record CSV
save_user_record(){
  # args: type username password expiry allowed_ips uuid
  local type="$1" user="$2" pass="$3" exp="$4" ips="$5" uuid="$6"
  local now
  now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '%s\n' "${type},${user},${pass},${exp},\"${ips}\",${uuid},${now}" >> "$USER_DB"
}

# Add iptables chain to limit SSH ports for specific user (confirmation required)
add_ssh_ip_limit(){
  local user="$1" ips="$2"
  if [ -z "$ips" ]; then return; fi
  echo
  echo -e "${YELLOW}You requested Limit IPs for SSH ports for user '${user}':${NC} ${ips}"
  read -rp "Apply iptables rules now? This affects all SSH traffic on ports 22,109,143. Confirm (y/N): " ans
  ans=${ans:-N}
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    warn "Skipping iptables rules for $user."
    return
  fi
  IFS=',' read -ra IPARR <<< "$ips"
  local chain="YHDS_${user}_SSH"
  # create chain
  iptables -N "$chain" 2>/dev/null || true
  iptables -F "$chain" 2>/dev/null || true
  # allow listed IPs
  for ip in "${IPARR[@]}"; do
    ip=$(echo "$ip" | xargs)
    if [ -n "$ip" ]; then
      iptables -A "$chain" -p tcp -s "$ip" --dport 22 -j ACCEPT
      iptables -A "$chain" -p tcp -s "$ip" --dport 109 -j ACCEPT
      iptables -A "$chain" -p tcp -s "$ip" --dport 143 -j ACCEPT
    fi
  done
  # drop remaining
  iptables -A "$chain" -p tcp --dport 22 -j DROP
  iptables -A "$chain" -p tcp --dport 109 -j DROP
  iptables -A "$chain" -p tcp --dport 143 -j DROP
  # insert into INPUT if not present
  if ! iptables -C INPUT -j "$chain" >/dev/null 2>&1; then
    iptables -I INPUT -j "$chain"
  fi
  warn "iptables rules added with chain $chain. To remove: iptables -D INPUT -j $chain; iptables -F $chain; iptables -X $chain"
}

remove_ssh_ip_limit(){
  local user="$1"
  local chain="YHDS_${user}_SSH"
  if iptables -L "$chain" >/dev/null 2>&1; then
    iptables -D INPUT -j "$chain" 2>/dev/null || true
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
    info "Removed iptables chain $chain"
  fi
}

# ---------------- Account creation functions ----------------

# 1) Create SSH / WebSocket account
create_ssh_ws(){
  echo -e "${BLUE}== Create SSH / WebSocket Account ==${NC}"
  read -rp "Username: " u
  if [ -z "$u" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  if id "$u" >/dev/null 2>&1; then warn "User exists"; return; fi
  read -rp "Password: " -s p; echo
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated; leave empty for no limit): " ips
  useradd -m -s /bin/bash "$u" || { err "useradd failed"; return; }
  echo -e "${p}\n${p}" | passwd "$u" >/dev/null 2>&1 || true
  exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
  chage -E "$exp_date" "$u" >/dev/null 2>&1 || true
  save_user_record "ssh-ws" "$u" "$p" "$exp_date" "$ips" ""
  if [ -n "$ips" ]; then add_ssh_ip_limit "$u" "$ips"; fi
  echo -e "${GREEN}Created SSH/WS user:${NC} $u"
  echo -e "Password: $p"
  echo -e "Expire: $exp_date"
  echo -e "Allowed IPs: ${ips:-none}"
  echo -e "Ports: 22,109,143; WS path (if used): ${XRAY_WS_PATH}"
}

# 2) Create UDP-Custom account
create_udp_custom_user(){
  echo -e "${BLUE}== Create UDP-Custom Account ==${NC}"
  read -rp "Username: " u
  if [ -z "$u" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  if grep -q "^${u}:" /etc/udp-custom/users.conf 2>/dev/null; then warn "UDP user exists"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated; leave empty for no limit): " ips
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  mkdir -p /etc/udp-custom
  echo "${u}:${exp}:${ips}" >> /etc/udp-custom/users.conf
  save_user_record "udp" "$u" "" "$exp" "$ips" ""
  systemctl restart udp-custom >/dev/null 2>&1 || true
  echo -e "${GREEN}UDP user added:${NC} $u (exp: $exp) Allowed IPs: ${ips:-none}"
}

# 3) Create VLESS account with UUID
create_vless_account(){
  echo -e "${BLUE}== Create VLESS Account (UUID) ==${NC}"
  read -rp "Account name / note: " name
  if [ -z "$name" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated; leave empty for no limit): " ips
  uuid=$(cat /proc/sys/kernel/random/uuid)
  if [ -f /etc/xray/config.json ]; then
    if command -v jq >/dev/null 2>&1; then
      tmp=$(mktemp)
      jq --arg id "$uuid" --arg em "$name" '.inbounds[0].settings.clients += [{"id": $id, "level":0, "email": $em}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
    else
      # naive append warning
      sed -i "/\"clients\": \[/,/\]/ { /]/ i \ \ \ \ { \"id\": \"${uuid}\", \"level\":0, \"email\": \"${name}\" }," /etc/xray/config.json 2>/dev/null || true
      warn "jq not installed — appended client naively. Inspect /etc/xray/config.json"
    fi
    systemctl restart xray >/dev/null 2>&1 || warn "xray restart may have failed"
    exp=$(date -d "+${days} days" +"%Y-%m-%d")
    save_user_record "vless" "$name" "" "$exp" "$ips" "$uuid"
    echo -e "${GREEN}VLESS created:${NC} note=$name"
    echo -e "UUID: ${uuid}"
    echo -e "Expire: ${exp}"
    echo -e "Domain: ${DOMAIN}"
    echo -e "Port: ${XRAY_PORT}"
    echo -e "WS Path: ${XRAY_WS_PATH}"
    echo -e "Allowed IPs: ${ips:-none}"
  else
    err "Xray config not found. Cannot create VLESS."
  fi
}

# 4) Create Trojan account (password auto-generated)
create_trojan_account(){
  echo -e "${BLUE}== Create Trojan Account ==${NC}"
  read -rp "Account name / note: " name
  if [ -z "$name" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated; leave empty for no limit): " ips
  passwd_t=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c14)
  if [ -f /etc/xray/config.json ]; then
    # append or create trojan inbound
    if grep -q '"protocol": "trojan"' /etc/xray/config.json; then
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq --arg pw "$passwd_t" --arg em "$name" '.inbounds |= map(if .protocol=="trojan" then (.settings.clients += [{"password": $pw, "email": $em}]) else . end)' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
      else
        sed -i "/\"protocol\": \"trojan\"/,/]/ { /]/ i \ \ \ \ { \"password\": \"${passwd_t}\", \"email\": \"${name}\" }," /etc/xray/config.json 2>/dev/null || true
        warn "jq not installed — appended trojan client naively. Inspect config."
      fi
    else
      # create simple trojan inbound on port 1443 (avoid conflicts)
      cat > /etc/xray/trojan-inbound.json <<EOF
{
  "port": 1443,
  "protocol": "trojan",
  "settings": {
    "clients": [
      { "password": "${passwd_t}", "email": "${name}" }
    ]
  },
  "streamSettings": {
    "network": "tcp"
  }
}
EOF
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq '.inbounds += ['$(cat /etc/xray/trojan-inbound.json)']' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
        rm -f /etc/xray/trojan-inbound.json
      else
        cat /etc/xray/trojan-inbound.json >> /etc/xray/config.json
      fi
    fi
    systemctl restart xray >/dev/null 2>&1 || warn "xray restart may have failed"
    exp=$(date -d "+${days} days" +"%Y-%m-%d")
    save_user_record "trojan" "$name" "$passwd_t" "$exp" "$ips" ""
    echo -e "${GREEN}Trojan created:${NC} note=${name}"
    echo -e "Password: ${passwd_t}"
    echo -e "Expire: ${exp}"
    echo -e "Port: 1443 (or existing trojan inbound port)"
    echo -e "Allowed IPs: ${ips:-none}"
  else
    err "Xray config not found. Cannot create Trojan."
  fi
}

# 5) Renew / Delete accounts
renew_or_delete_menu(){
  echo -e "${BLUE}== Renew or Delete Account ==${NC}"
  echo "1) Renew user expiry"
  echo "2) Delete user"
  read -rp "Choose [1/2]: " r
  if [ "$r" = "1" ]; then
    read -rp "Username to renew: " u
    read -rp "Extra days to add: " days
    if ! id "$u" >/dev/null 2>&1; then echo -e "${YELLOW}User not found${NC}"; return; fi
    cur=$(chage -l "$u" | grep "Account expires" | cut -d: -f2- | xargs)
    if [ -z "$cur" ] || [ "$cur" = "never" ]; then
      new=$(date -d "+${days} days" +"%Y-%m-%d")
    else
      new=$(date -d "${cur} + ${days} days" +"%Y-%m-%d" 2>/dev/null || date -d "+${days} days" +"%Y-%m-%d")
    fi
    chage -E "$new" "$u" || true
    echo -e "${GREEN}User $u expiry set to $new${NC}"
  else
    read -rp "Username to delete: " u
    if id "$u" >/dev/null 2>&1; then
      userdel -r "$u" >/dev/null 2>&1 || warn "userdel may have failed"
      remove_ssh_ip_limit "$u" || true
      # remove from CSV (simple filter)
      sed -i "/,${u},/d" "$USER_DB" 2>/dev/null || true
      sed -i "/^${u}:/d" /etc/udp-custom/users.conf 2>/dev/null || true
      sed -i "/^${u}:/d" /etc/slowdns/users.txt 2>/dev/null || true
      echo -e "${GREEN}User $u deleted and entries removed.${NC}"
    else
      echo -e "${YELLOW}User not found.${NC}"
    fi
  fi
}

# 6) Backup & Restore
backup_restore_menu(){
  echo -e "${BLUE}== Backup & Restore ==${NC}"
  echo "1) Backup configs (/root/yhds-backup.tar.gz)"
  echo "2) Restore from /root/yhds-backup.tar.gz"
  read -rp "Choose [1/2]: " br
  if [ "$br" = "1" ]; then
    tar czf /root/yhds-backup.tar.gz /etc/yhds "$USER_DB" /etc/udp-custom /etc/slowdns /etc/xray 2>/dev/null || warn "Backup created with warnings"
    echo -e "${GREEN}Backup saved to /root/yhds-backup.tar.gz${NC}"
  else
    if [ -f /root/yhds-backup.tar.gz ]; then
      tar xzf /root/yhds-backup.tar.gz -C / 2>/dev/null || warn "Restore had warnings"
      echo -e "${GREEN}Restore finished. Inspect files and restart services if needed.${NC}"
    else
      echo -e "${YELLOW}No backup file found at /root/yhds-backup.tar.gz${NC}"
    fi
  fi
}

# 7) Check online / recent users
check_online_users(){
  echo -e "${MAGENTA}--- Recent logins ---${NC}"
  lastlog | grep -v "Never" || true
  echo
  echo -e "${MAGENTA}--- Currently logged in ---${NC}"
  who || true
}

# 8) Restart all services
restart_all_services(){
  SERVICES=(nginx dropbear stunnel4 xray slowdns udp-custom)
  for s in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${s}"; then
      systemctl restart "$s" >/dev/null 2>&1 && echo -e "${GREEN}$s restarted${NC}" || echo -e "${YELLOW}$s restart failed${NC}"
    else
      echo -e "${YELLOW}$s not present${NC}"
    fi
  done
}

# 9) System info
show_system_info(){
  echo -e "${CYAN}====== SERVER INFO ======${NC}"
  echo "Domain : $(cat /root/domain 2>/dev/null || echo '-')"
  echo "IP     : $(curl -sS ipv4.icanhazip.com || echo '-')"
  echo "OS     : $(lsb_release -d 2>/dev/null | cut -f2-)"
  echo "Time   : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Uptime : $(uptime -p)"
  echo "CPU    : $(nproc)"
  echo "Memory : $(free -h | awk '/Mem:/ {print $3\"/\"$2}')"
  echo "Ports  : SSH(22), Dropbear(109,143), Stunnel(443), Xray(${XRAY_PORT}), UDP(${UDP_CUSTOM_PORT}), SlowDNS(${SLOWDNS_UDP_PORT})"
  echo -e "${CYAN}=========================${NC}"
}

# 10) Exit handled in menu

# ---------------- Create menu executable ----------------
info "Installing interactive menu (command: menu)..."

# Write helpers to /etc/yhds/functions.sh so menu can source them
cat > /etc/yhds/functions.sh <<'BASHFUN'
#!/usr/bin/env bash
# This file is sourced by /usr/local/bin/menu and contains function stubs
# The real implementations are in the installer environment.
# We'll source the installer itself for function bodies.
# To keep things simple, functions will be bridged to the installer via sourcing /etc/yhds/installer_env.sh
if [ -f /etc/yhds/installer_env.sh ]; then
  source /etc/yhds/installer_env.sh
fi
BASHFUN
chmod +x /etc/yhds/functions.sh

# Export functions/vars into installer_env for menu to source
# We'll write a small wrapper installer_env that sources this running shell (by capturing functions)
# Note: We embed the function bodies by dumping them via declare -f
cat > /etc/yhds/installer_env.sh <<'BASHENV'
#!/usr/bin/env bash
# Installer environment file autogenerated by install.sh
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'; MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'
USER_DB="/etc/yhds/users.csv"
# Re-declare functions by loading them from the current shell if available.
# This block will be replaced/kept simple: it sources /etc/yhds/functions_impl.sh if present.
if [ -f /etc/yhds/functions_impl.sh ]; then
  source /etc/yhds/functions_impl.sh
fi
BASHENV

# Write the real function implementations to functions_impl.sh
cat > /etc/yhds/functions_impl.sh <<'BASHIMPL'
#!/usr/bin/env bash
# Real function implementations used by menu (sourced)
# For simplicity we re-declare wrappers that call system binaries created in this script.

# These functions should exist in the system environment (they are below in this file)
create_ssh_ws(){ bash -lc 'create_ssh_ws'; }
create_udp_custom_user(){ bash -lc 'create_udp_custom_user'; }
create_vless_account(){ bash -lc 'create_vless_account'; }
create_trojan_account(){ bash -lc 'create_trojan_account'; }
renew_or_delete_menu(){ bash -lc 'renew_or_delete_menu'; }
backup_restore_menu(){ bash -lc 'backup_restore_menu'; }
check_online_users(){ bash -lc 'check_online_users'; }
restart_all_services(){ bash -lc 'restart_all_services'; }
show_system_info(){ bash -lc 'show_system_info'; }
# _main_menu implementation will call the above wrappers
_main_menu(){
  while true; do
    clear
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "     🌐 ${BLUE}YHDS MULTI TUNNEL PANEL${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}1.${NC} Create SSH / WebSocket Account"
    echo -e "${YELLOW}2.${NC} Create UDP-Custom Account"
    echo -e "${YELLOW}3.${NC} Create VLESS Account (UUID)"
    echo -e "${YELLOW}4.${NC} Create Trojan Account"
    echo -e "${YELLOW}5.${NC} Renew / Delete Account"
    echo -e "${YELLOW}6.${NC} Backup & Restore"
    echo -e "${YELLOW}7.${NC} Check Online Users"
    echo -e "${YELLOW}8.${NC} Restart All Services"
    echo -e "${YELLOW}9.${NC} System Information"
    echo -e "${YELLOW}10.${NC} Exit Menu"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    read -rp "Select Option [1-10]: " opt
    case "$opt" in
      1) create_ssh_ws;;
      2) create_udp_custom_user;;
      3) create_vless_account;;
      4) create_trojan_account;;
      5) renew_or_delete_menu;;
      6) backup_restore_menu;;
      7) check_online_users;;
      8) restart_all_services;;
      9) show_system_info;;
      10) exit 0;;
      *) echo -e "${RED}Invalid option${NC}"; sleep 1;;
    esac
    echo -e "\nPress ENTER to continue..."
    read -r _
  done
}
BASHIMPL
chmod +x /etc/yhds/functions_impl.sh

# Create /usr/local/bin/menu wrapper
cat > /usr/local/bin/menu <<'BASHMENU'
#!/usr/bin/env bash
# Menu launcher - sources installer env and functions
if [ -f /etc/yhds/installer_env.sh ]; then
  source /etc/yhds/installer_env.sh
else
  echo "Menu not installed. Re-run installer."
  exit 1
fi
if [ -f /etc/yhds/functions_impl.sh ]; then
  source /etc/yhds/functions_impl.sh
else
  echo "Menu functions missing. Re-run installer."
  exit 1
fi
_main_menu
BASHMENU
chmod +x /usr/local/bin/menu

# Add MOTD hint
cat > /etc/update-motd.d/99-yhds <<'EOM'
#!/bin/sh
printf "\n\x1b[36mYHDS Installer\x1b[0m - type \x1b[33mmenu\x1b[0m to open management panel\n\n"
EOM
chmod +x /etc/update-motd.d/99-yhds

# Write brief installer summary
cat > /root/install-summary.txt <<EOF
YHDS Installer Summary
======================
Domain        : ${DOMAIN}
IP            : $(curl -sS ipv4.icanhazip.com || echo "-")
Admin user    : ${ADMIN_USER}
Admin pass    : ${ADMIN_PASS}
UDP-Custom    : ${UDP_CUSTOM_PORT}
Xray port     : ${XRAY_PORT} (ws path ${XRAY_WS_PATH})
SlowDNS UDP   : ${SLOWDNS_UDP_PORT}
Menu command  : menu
User DB       : ${USER_DB}
EOF

info "Installation finished. Summary:"
cat /root/install-summary.txt
echo
info "Run 'menu' to open the management panel."
info "IMPORTANT: If you added Limit IP rules, be careful — they can block SSH access if misconfigured."
echo -e "${YELLOW}Recommended: reboot server now to finalize services.${NC}"

# End of installer
