#!/bin/bash
# ==============================================
#  CLEAN AUTO INSTALL SCRIPT (SSH/XRAY/SLOWDNS)
#  Versi: 2025-11 - Clean by GPT-5 for Yhd
# ==============================================

set -euo pipefail
IFS=$'\n\t'

echo -e "\e[1;36m[*]\e[0m Menyiapkan sistem..."

# Pastikan root
if [ "$(id -u)" -ne 0 ]; then
  echo -e "\e[1;31m[ERROR]\e[0m Jalankan sebagai root!"
  exit 1
fi

# Nonaktifkan IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

# Zona waktu & dependensi
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
apt update -y >/dev/null 2>&1
apt install -y wget curl jq git lsb-release ca-certificates >/dev/null 2>&1

# Mirror fallback
SOURCE1="https://raw.githubusercontent.com/Yahdiad1/pgetunnel/main"
SOURCE2="https://ghp.ci/https://raw.githubusercontent.com/Yahdiad1/pgetunnel/main"
SOURCE3="https://raw.fastgit.org/Yahdiad1/pgetunnel/main"

download() {
  local FILE="$1"
  for SRC in "$SOURCE1" "$SOURCE2" "$SOURCE3"; do
    echo -e "\e[1;33m[INFO]\e[0m Coba unduh: $SRC/$FILE"
    if wget -q -O "$FILE" "$SRC/$FILE"; then
      echo -e "\e[1;32m[SUKSES]\e[0m $FILE diunduh dari $SRC"
      return 0
    fi
  done
  echo -e "\e[1;31m[GAGAL]\e[0m Tidak bisa unduh $FILE dari semua sumber!"
  return 1
}

# Direktori penting
mkdir -p /etc/xray /etc/v2ray /var/lib/SIJA /home/script

# Domain otomatis
echo -e "\e[1;33m[INFO]\e[0m Mengatur domain acak..."
if download "cf"; then
  chmod +x cf && bash cf || true
fi
DOMAIN=$(cat /root/domain 2>/dev/null || echo "random-domain.test")
echo "$DOMAIN" | tee /etc/xray/domain /etc/xray/scdomain /etc/v2ray/domain /etc/v2ray/scdomain >/dev/null
echo "IP=$DOMAIN" > /var/lib/SIJA/ipvps.conf

# Buat user admin default
if ! id -u adminvpn >/dev/null 2>&1; then
  useradd -r -M -d /home/script -s /bin/bash adminvpn
  echo -e "adminvpn\nadminvpn" | passwd adminvpn >/dev/null 2>&1
  usermod -aG sudo adminvpn
fi

# Info VPS
MYIP=$(curl -sS ipv4.icanhazip.com || echo "-")
CITY=$(curl -s ipinfo.io/city 2>/dev/null || echo "-")
ISP=$(curl -s ipinfo.io/org 2>/dev/null | cut -d ' ' -f 2-10 || echo "-")
TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo -e "\n\e[1;32m[INFO]\e[0m Domain: $DOMAIN"
echo -e "\e[1;32m[INFO]\e[0m IP VPS: $MYIP"
echo -e "\e[1;32m[INFO]\e[0m ISP   : $ISP"
echo -e "\e[1;32m[INFO]\e[0m Lokasi: $CITY"
echo -e "\e[1;32m[INFO]\e[0m Waktu : $TIME\n"

# Jalankan semua modul utama
run_script() {
  local NAME="$1"
  local FILE="$(basename "$NAME")"
  if download "$NAME"; then
    chmod +x "$FILE" && bash "$FILE" || echo "[WARN] $FILE gagal dijalankan"
    rm -f "$FILE"
  fi
}

run_script "tools.sh"
run_script "ssh/ssh-vpn.sh"
run_script "backup/set-br.sh"
run_script "xray/ins-xray.sh"
run_script "sshws/insshws.sh"
run_script "slow.sh"

# Hapus sisa file
rm -f cf >/dev/null 2>&1

# Log hasil
cat > /root/install-summary.txt <<EOF
======================================
   INSTALASI VPN SELESAI
======================================
Domain : $DOMAIN
IP VPS : $MYIP
ISP    : $ISP
Kota   : $CITY
Waktu  : $TIME
User   : adminvpn
Pass   : adminvpn
======================================
EOF

cat /root/install-summary.txt
echo -e "\n\e[1;32m[SUKSES]\e[0m Instalasi selesai! Silakan reboot VPS."
