#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer + Colorful Menu (1-10)
# Manual create: username, password, expire (days), limit IP
# - Debian 10..12
# - Features: SSH/WS, UDP-Custom, VLESS (UUID), Trojan (UUID), SlowDNS
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

# ---------------- Configuration ----------------
ADMIN_USER="yhds"
ADMIN_PASS="yhds"
UDP_CUSTOM_PORT=7300
SLOWDNS_UDP_PORT=5300
XRAY_PORT=443
XRAY_WS_PATH="/vless"
TIMEZONE="Asia/Jakarta"
USERS_CSV="/etc/yhds/users.csv"
# ------------------------------------------------

# Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'
MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'

info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
warnc(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }

# Ensure root
if [ "$(id -u)" -ne 0 ]; then
  err "Run as root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true

# create storage
mkdir -p /etc/yhds
touch "$USERS_CSV"
# ensure header if empty
if ! grep -q "^type," "$USERS_CSV" 2>/dev/null; then
  echo "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USERS_CSV"
fi

# helper: save account record
save_user_record(){
  # args: type username password expiry allowed_ips uuid
  local type="$1" user="$2" pass="$3" exp="$4" ips="$5" uuid="$6"
  local now
  now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "${type},${user},${pass},${exp},\"${ips}\",${uuid},${now}" >> "$USERS_CSV"
}

# helper: add iptables allow for SSH ports for specific username (WARNING: global effect)
add_ssh_ip_limit(){
  # args: username,comma-separated-ips
  local user="$1" ips="$2"
  if [ -z "$ips" ]; then return; fi
  # parse ips
  IFS=',' read -ra IPARR <<< "$ips"
  # create unique chain for this user
  local chain="YHDS_${user}_SSH"
  iptables -N "$chain" 2>/dev/null || true
  # flush existing
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
  # drop other sources for these ports (comment includes username)
  iptables -A "$chain" -p tcp --dport 22 -j DROP
  iptables -A "$chain" -p tcp --dport 109 -j DROP
  iptables -A "$chain" -p tcp --dport 143 -j DROP
  # insert chain into INPUT if not present
  if ! iptables -C INPUT -j "$chain" >/dev/null 2>&1; then
    iptables -I INPUT -j "$chain"
  fi
  warnc "iptables rules added for SSH ports restricted to [$ips] (chain: $chain). This affects all users on those ports."
}

# helper: remove ip limit chain
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

# ---------------- Create functions ----------------

create_ssh_ws(){
  echo -e "${BLUE}== Create SSH / WebSocket Account ==${NC}"
  read -rp "Username: " u
  if [ -z "$u" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Password: " -s p; echo
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated, leave empty for no limit): " ips
  if id "$u" >/dev/null 2>&1; then
    warnc "User already exists."
    return
  fi
  useradd -m -s /bin/bash "$u" || { err "useradd failed"; return; }
  echo -e "${p}\n${p}" | passwd "$u" >/dev/null 2>&1 || true
  expire_date=$(date -d "+${days} days" +"%Y-%m-%d")
  chage -E "$expire_date" "$u" >/dev/null 2>&1 || true
  # save record
  save_user_record "ssh-ws" "$u" "$p" "$expire_date" "$ips" ""
  # add ip limit if specified
  if [ -n "$ips" ]; then
    add_ssh_ip_limit "$u" "$ips"
  fi
  echo -e "${GREEN}SSH/WS user created:${NC} $u"
  echo -e "Password: $p"
  echo -e "Expire: $expire_date"
  echo -e "Allowed IPs: ${ips:-none}"
  echo -e "SSH Ports: 22,109,143"
  echo -e "If you use websocket tunneling, use path: ${XRAY_WS_PATH}"
}

create_udp_custom_user(){
  echo -e "${BLUE}== Create UDP-Custom Account ==${NC}"
  read -rp "Username: " u
  if [ -z "$u" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated, leave empty for no limit): " ips
  # ensure users file
  mkdir -p /etc/udp-custom
  touch /etc/udp-custom/users.conf
  if grep -q "^${u}:" /etc/udp-custom/users.conf 2>/dev/null; then
    warnc "UDP user already exists."
    return
  fi
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  echo "${u}:${exp}:${ips}" >> /etc/udp-custom/users.conf
  save_user_record "udp" "$u" "" "$exp" "$ips" ""
  systemctl restart udp-custom >/dev/null 2>&1 || true
  echo -e "${GREEN}UDP-Custom user added:${NC} $u (exp: $exp) Allowed IPs: ${ips:-none}"
}

create_vless_account(){
  echo -e "${BLUE}== Create VLESS Account ==${NC}"
  read -rp "Account name / note: " name
  if [ -z "$name" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated, leave empty for no limit): " ips
  uuid=$(cat /proc/sys/kernel/random/uuid)
  # add to xray config via jq if available
  if [ -f /etc/xray/config.json ]; then
    if command -v jq >/dev/null 2>&1; then
      tmp=$(mktemp)
      jq --arg id "$uuid" --arg em "$name" '.inbounds[0].settings.clients += [{"id": $id, "level":0, "email": $em}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
    else
      # naive append (best-effort); warn user to verify
      sed -i "/\"clients\": \[/,/\]/ { /]/ i \ \ \ \ { \"id\": \"${uuid}\", \"level\":0, \"email\": \"${name}\" }," /etc/xray/config.json 2>/dev/null || true
      warnc "jq not installed — appended client naively. Please inspect /etc/xray/config.json"
    fi
    systemctl restart xray >/dev/null 2>&1 || warnc "xray restart may have failed"
    exp=$(date -d "+${days} days" +"%Y-%m-%d")
    save_user_record "vless" "$name" "" "$exp" "$ips" "$uuid"
    echo -e "${GREEN}VLESS created:${NC} note=$name"
    echo -e "UUID: ${uuid}"
    echo -e "Expire: ${exp}"
    echo -e "Domain: $(cat /root/domain 2>/dev/null || echo '-')"
    echo -e "Port: ${XRAY_PORT}"
    echo -e "WS path: ${XRAY_WS_PATH}"
    echo -e "Allowed IPs: ${ips:-none}"
  else
    err "Xray config not found. Cannot create VLESS."
  fi
}

create_trojan_account(){
  echo -e "${BLUE}== Create Trojan Account ==${NC}"
  read -rp "Account name / note: " name
  if [ -z "$name" ]; then echo -e "${YELLOW}Canceled${NC}"; return; fi
  read -rp "Expire in days (default 7): " days
  days=${days:-7}
  read -rp "Limit IPs (comma separated, leave empty for no limit): " ips
  passwd_t=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c12)
  if [ -f /etc/xray/config.json ]; then
    # If trojan inbound exists, append; else create trojan inbound on port 1443
    if grep -q '"protocol": "trojan"' /etc/xray/config.json; then
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq --arg pw "$passwd_t" --arg em "$name" '.inbounds |= map(if .protocol=="trojan" then (.settings.clients += [{"password": $pw, "email": $em}]) else . end)' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
      else
        sed -i "/\"protocol\": \"trojan\"/,/]/ { /]/ i \ \ \ \ { \"password\": \"${passwd_t}\", \"email\": \"${name}\" }," /etc/xray/config.json 2>/dev/null || true
        warnc "jq not installed — appended trojan client naively. Inspect config."
      fi
    else
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
    systemctl restart xray >/dev/null 2>&1 || warnc "xray restart may have failed"
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
      userdel -r "$u" >/dev/null 2>&1 || warnc "userdel may have failed"
      remove_ssh_ip_limit "$u" || true
      sed -i "/^ssh-ws,${u},/d" "$USERS_CSV" 2>/dev/null || true
      sed -i "/^udp,${u},/d" /etc/udp-custom/users.conf 2>/dev/null || true
      sed -i "/^vless,${u},/d" "$USERS_CSV" 2>/dev/null || true
      echo -e "${GREEN}User $u deleted and related entries removed.${NC}"
    else
      echo -e "${YELLOW}User not found.${NC}"
    fi
  fi
}

backup_restore_menu(){
  echo -e "${BLUE}== Backup & Restore ==${NC}"
  echo "1) Backup /etc/yhds/users.csv and configs to /root/yhds-backup.tar.gz"
  echo "2) Restore from /root/yhds-backup.tar.gz"
  read -rp "Choose [1/2]: " br
  if [ "$br" = "1" ]; then
    tar czf /root/yhds-backup.tar.gz /etc/yhds "$USERS_CSV" /etc/udp-custom /etc/slowdns /etc/xray 2>/dev/null || warnc "Backup created with warnings."
    echo -e "${GREEN}Backup saved to /root/yhds-backup.tar.gz${NC}"
  else
    if [ -f /root/yhds-backup.tar.gz ]; then
      tar xzf /root/yhds-backup.tar.gz -C / 2>/dev/null || warnc "Restore had warnings."
      echo -e "${GREEN}Restore finished. Please inspect files.${NC}"
    else
      echo -e "${YELLOW}No backup file found at /root/yhds-backup.tar.gz${NC}"
    fi
  fi
}

check_online_users(){
  echo -e "${MAGENTA}--- Recent logins ---${NC}"
  lastlog | grep -v "Never" || true
  echo
  echo -e "${MAGENTA}--- Currently logged in ---${NC}"
  who || true
}

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

show_system_info(){
  echo -e "${CYAN}====== SERVER INFO ======${NC}"
  echo "Domain : $(cat /root/domain 2>/dev/null || echo '-')"
  echo "IP     : $(curl -sS ipv4.icanhazip.com || echo '-')"
  echo "OS     : $(lsb_release -d 2>/dev/null | cut -f2-)"
  echo "Uptime : $(uptime -p)"
  echo "CPU    : $(nproc)"
  echo "Memory : $(free -h | awk '/Mem:/ {print $3\"/\"$2}')"
  echo "Ports  : SSH(22), Dropbear(109,143), Stunnel(443), Xray(${XRAY_PORT}), UDP(${UDP_CUSTOM_PORT}), SlowDNS(${SLOWDNS_UDP_PORT})"
  echo -e "${CYAN}=========================${NC}"
}

# ---------------- Build menu executable (/usr/local/bin/menu) ----------------
cat > /usr/local/bin/menu <<'BASHMENU'
#!/usr/bin/env bash
# lightweight wrapper that sources helpers in this installer file's environment
SCRIPT="/etc/yhds/installer_env.sh"
if [ -f "$SCRIPT" ]; then
  source "$SCRIPT"
  _main_menu
else
  echo "Menu not installed. Run installer again."
  exit 1
fi
BASHMENU
chmod +x /usr/local/bin/menu

# ---------------- Persist environment and functions to /etc/yhds/installer_env.sh ----------------
cat > /etc/yhds/installer_env.sh <<'BASHENV'
#!/usr/bin/env bash
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'; MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'
USERS_CSV="/etc/yhds/users.csv"
XRAY_PORT='"${XRAY_PORT}"'
create_ssh_ws(){ '"$(declare -f create_ssh_ws)"'; }
create_udp_custom_user(){ '"$(declare -f create_udp_custom_user)"'; }
create_vless_account(){ '"$(declare -f create_vless_account)"'; }
create_trojan_account(){ '"$(declare -f create_trojan_account)"'; }
renew_or_delete_menu(){ '"$(declare -f renew_or_delete_menu)"'; }
backup_restore_menu(){ '"$(declare -f backup_restore_menu)"'; }
check_online_users(){ '"$(declare -f check_online_users)"'; }
restart_all_services(){ '"$(declare -f restart_all_services)"'; }
show_system_info(){ '"$(declare -f show_system_info)"'; }
_main_menu(){ '"$(declare -f _main_menu 2>/dev/null || true)"' || true; }
# Provide inline _main_menu implementation (colorful 1-10)
_main_menu(){
  while true; do
    clear
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "     🌐 ${BLUE}YHDS MULTI TUNNEL PANEL${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}1.${NC} Create SSH / WebSocket Account"
    echo -e "${YELLOW}2.${NC} Create UDP-Custom Account"
    echo -e "${YELLOW}3.${NC} Create VLESS Account (UUID)"
    echo -e "${YELLOW}4.${NC} Create Trojan Account (passgen)"
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
BASHENV

chmod +x /etc/yhds/installer_env.sh

# ------------- motd hint -------------
cat > /etc/update-motd.d/99-yhds <<'EOM'
#!/bin/sh
printf "\n\x1b[36mYHDS Installer\x1b[0m - type \x1b[33mmenu\x1b[0m to open management panel\n\n"
EOM
chmod +x /etc/update-motd.d/99-yhds

# ------------- final message -------------
info "Menu installed. Run 'menu' to open the panel."
info "All account records saved in $USERS_CSV"
echo -e "${YELLOW}Note:${NC} If you used Limit IPs, iptables rules were created that affect SSH ports globally. Use with care."
echo -e "${GREEN}Installer finished. Recommended: reboot server now.${NC}"
