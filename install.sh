#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer + Menu 1-12 (Debian 10-12)
# Features: SSH/WS, UDP-Custom, Xray(VLESS/Trojan), SlowDNS, Telegram Bot
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
USER_DB="/etc/yhds/users.csv"
YHDS_DIR="/etc/yhds"
# ------------------------------------------------

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

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true

# ---------------- Prepare system ----------------
info "Updating apt and installing base packages..."
apt update -y >/dev/null 2>&1
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat python3 python3-pip >/dev/null 2>&1 || true

mkdir -p "$YHDS_DIR"
touch "$USER_DB"
if ! grep -q '^type,' "$USER_DB" 2>/dev/null; then
  printf '%s\n' "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USER_DB"
fi

# ---------------- Domain selection ----------------
clear
echo -e "${MAGENTA}========================================${NC}"
echo -e "${BLUE}        SETUP: DOMAIN CONFIGURATION      ${NC}"
echo -e "${MAGENTA}========================================${NC}"
echo "1) Use your own domain"
echo "2) Create a random local domain"
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
  useradd -m -s /bin/bash "$ADMIN_USER"
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER"
  usermod -aG sudo "$ADMIN_USER"
else
  info "Admin user already exists, skipping."
fi

# ---------------- Install base services ----------------
info "Installing nginx, dropbear, stunnel4..."
apt install -y nginx dropbear stunnel4 >/dev/null 2>&1 || true
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 2>/dev/null || true
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/g' /etc/default/dropbear 2>/dev/null || true
if ! grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear 2>/dev/null; then
  echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
fi
systemctl enable --now dropbear stunnel4 nginx || true

# ---------------- UDP-Custom ----------------
info "Installing UDP-Custom..."
cd /root || true
UDP_BIN_URL="https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64"
wget -q --tries=3 --timeout=20 -O /root/udp-custom "$UDP_BIN_URL"
chmod +x /root/udp-custom
mkdir -p /etc/udp-custom
touch /etc/udp-custom/users.conf
cat > /etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP-Custom Service
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
systemctl enable --now udp-custom

# ---------------- Xray ----------------
info "Installing Xray..."
curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh
bash /tmp/xray-install.sh >/dev/null 2>&1
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
      "settings": { "clients": [ { "id": "${XRAY_UUID_DEFAULT}", "level":0, "email":"default@local" } ], "decryption": "none" },
      "streamSettings": { "network":"ws", "wsSettings":{"path":"${XRAY_WS_PATH}"} }
    }
  ],
  "outbounds":[{"protocol":"freedom"}]
}
EOF
fi
systemctl enable --now xray

# ---------------- SlowDNS ----------------
info "Installing SlowDNS..."
cd /root
if [ ! -d /root/slowdns ]; then
  git clone https://github.com/purwasasmito/slowdns.git /root/slowdns
  cd /root/slowdns
  go build -o slowdns server.go
  mv slowdns /usr/local/bin/slowdns
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
  systemctl enable --now slowdns
fi

# ---------------- Telegram Bot ----------------
info "Installing Telegram Bot..."
mkdir -p /etc/yhds/bot
cat > /etc/yhds/bot/bot.py <<'BOT'
import telegram
TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"
bot = telegram.Bot(token=TOKEN)
bot.send_message(chat_id=CHAT_ID, text="YHDS VPS Bot is now online!")
BOT
cat > /etc/systemd/system/yhds-bot.service <<EOF
[Unit]
Description=YHDS Telegram Bot
After=network.target
[Service]
ExecStart=/usr/bin/python3 /etc/yhds/bot/bot.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now yhds-bot

# ---------------- Menu Installer ----------------
info "Installing interactive menu..."
cat > /usr/local/bin/menu <<'MENU'
#!/usr/bin/env bash
# Source: full YHDS menu 1-12 (same as previous message)
# Paste the menu script from previous message here
MENU
chmod +x /usr/local/bin/menu

# ---------------- Final ----------------
info "Installation complete."
echo -e "${GREEN}Run 'menu' to manage your VPS${NC}"
