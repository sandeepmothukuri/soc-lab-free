#!/usr/bin/env bash
# =============================================================================
# setup-host.sh — Prepare host machine for SOC Lab
# Run on your HOST (not inside a VM)
# Tested on: Ubuntu 22.04 / Debian 11 / Kali Linux
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# --- Check root ---
[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

info "=== SOC Lab Host Setup ==="
info "Installing dependencies..."

apt-get update -qq

# VirtualBox
if ! command -v VBoxManage &>/dev/null; then
    info "Installing VirtualBox..."
    apt-get install -y virtualbox virtualbox-ext-pack
else
    info "VirtualBox already installed: $(VBoxManage --version)"
fi

# Vagrant (for Metasploitable3)
if ! command -v vagrant &>/dev/null; then
    info "Installing Vagrant..."
    wget -O /tmp/vagrant.deb https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1-1_amd64.deb
    dpkg -i /tmp/vagrant.deb
    rm /tmp/vagrant.deb
else
    info "Vagrant already installed: $(vagrant --version)"
fi

# Python3 + pip (for integration scripts)
apt-get install -y python3 python3-pip python3-venv

# Python packages for integration scripts
pip3 install --break-system-packages requests paramiko python-gvm jinja2 2>/dev/null || \
pip3 install requests paramiko python-gvm jinja2

# jq for JSON parsing in scripts
apt-get install -y jq curl wget git net-tools nmap

# Git LFS (for large VM files if needed)
apt-get install -y git-lfs
git lfs install

info "=== Host Setup Complete ==="
info "Next step: Run ./scripts/network-setup.sh"
