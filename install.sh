#!/bin/bash

# ==========================================
# MEOW ENGINE - AUTO INSTALLER SCRIPT
# ==========================================

# Warna Terminal
RED='\033[0;31m'
LIME='\033[1;92m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================${NC}"
echo -e "${LIME}   INITIALIZING MEOW ENGINE AUTO-INSTALLER...${NC}"
echo -e "${CYAN}====================================================${NC}\n"

# 1. Pastikan script tidak dijalankan sebagai root (karena instalasi Go harus di user space)
if [ "$EUID" -eq 0 ]; then
  echo -e "${RED}[!] Jangan jalankan script ini menggunakan sudo su / root!${NC}"
  echo -e "    Jalankan sebagai user biasa (nanti script akan meminta password sudo untuk apt)."
  exit 1
fi

echo -e "${LIME}[+] Update Sistem & Install Paket Dasar...${NC}"
sudo apt update -y
sudo apt install -y python3 python3-pip golang git curl wget unzip hydra jq

# Export path Golang sementara agar bisa dipakai langsung di script ini
export PATH=$PATH:/usr/local/go/bin:~/go/bin

echo -e "\n${LIME}[+] Menginstal Tools dari ProjectDiscovery (Golang)...${NC}"
echo -e "    - Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo -e "    - Naabu..."
# Butuh libpcap untuk Naabu
sudo apt install -y libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo -e "    - HTTPX..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo -e "    - Katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
echo -e "    - Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo -e "\n${LIME}[+] Menginstal FFUF...${NC}"
go install -v github.com/ffuf/ffuf/v2@latest

echo -e "\n${LIME}[+] Menginstal Dependensi Python & Arjun...${NC}"
# Menggunakan --break-system-packages jika kamu pakai Kali/Ubuntu terbaru (PEP 668)
pip3 install requests arjun python-dotenv --break-system-packages || pip3 install requests arjun python-dotenv

echo -e "\n${LIME}[+] Menyiapkan Wordlists untuk Fuzzing...${NC}"
mkdir -p ~/wordlists
if [ ! -f ~/wordlists/dirs.txt ]; then
    echo -e "    Mengunduh SecLists (raft-small-directories)..."
    wget -q https://raw.githubusercontent.com/ariphx/MeowScanner/refs/heads/main/dirs.txt -O ~/wordlists/dirs.txt
else
    echo -e "    Wordlist sudah ada, melewati..."
fi

echo -e "\n${LIME}[+] Mengunduh Template Nuclei Terbaru...${NC}"
~/go/bin/nuclei -update-templates

# Memastikan path Golang ada di .bashrc atau .zshrc
BASHRC_FILE="$HOME/.bashrc"
ZSHRC_FILE="$HOME/.zshrc"

if ! grep -q 'export PATH=$PATH:~/go/bin' "$BASHRC_FILE"; then
    echo 'export PATH=$PATH:~/go/bin' >> "$BASHRC_FILE"
fi

if [ -f "$ZSHRC_FILE" ] && ! grep -q 'export PATH=$PATH:~/go/bin' "$ZSHRC_FILE"; then
    echo 'export PATH=$PATH:~/go/bin' >> "$ZSHRC_FILE"
fi

echo -e "\n${CYAN}====================================================${NC}"
echo -e "${LIME}   INSTALASI SELESAI KOMANDAN! 🔥${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "Penting: Silakan jalankan perintah ini sekarang agar path Go terbaca:"
echo -e "${RED}source ~/.bashrc${NC}  (atau source ~/.zshrc jika pakai zsh)"
echo -e "Setelah itu, MeowEngine siap ditembakkan!"
