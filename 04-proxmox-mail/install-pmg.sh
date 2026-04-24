#!/usr/bin/env bash
# =============================================================================
# install-pmg.sh — Install Proxmox Mail Gateway on Debian 12
# Target: 192.168.10.30
# Replaces: Mimecast
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

PMG_HOST="192.168.10.30"
PMG_HOSTNAME="pmg.soc.lab"
ADMIN_EMAIL="soc-admin@soc.lab"

step "1/6 — System Preparation"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl wget gnupg2 apt-transport-https ca-certificates \
    postfix postfix-pcre libsasl2-modules rsyslog net-tools

# Set hostname
hostnamectl set-hostname "$PMG_HOSTNAME"
echo "$PMG_HOST $PMG_HOSTNAME pmg" >> /etc/hosts

step "2/6 — Add Proxmox Repository"
# Proxmox Mail Gateway on Debian
wget -qO /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg \
    http://download.proxmox.com/debian/proxmox-release-bookworm.gpg

echo "deb [arch=amd64] http://download.proxmox.com/debian/pmg bookworm pmg-no-subscription" \
    > /etc/apt/sources.list.d/pmg.list

apt-get update -qq

step "3/6 — Install Proxmox Mail Gateway"
apt-get install -y proxmox-mailgateway

step "4/6 — Install ClamAV + SpamAssassin"
apt-get install -y \
    clamav clamav-daemon clamav-freshclam \
    spamassassin spamc \
    amavisd-new \
    razor pyzor

# Configure ClamAV
cat > /etc/clamav/clamd.conf << CLAMCONF
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666
TCPSocket 3310
TCPAddr 127.0.0.1
User clamav
ScanMail true
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 15
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads 12
MaxConnectionQueueLength 15
LogSyslog false
LogRotate true
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly false
SelfCheck 3600
Foreground false
Debug false
ScanPE true
MaxEmbeddedPE 10M
ScanOLE2 true
ScanPDF true
ScanHTML true
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
ScanSWF true
ScanELF true
DetectELF true
AlertBrokenExecutables false
AlertEncrypted false
AlertEncryptedArchive false
AlertEncryptedDoc false
AlertOLE2Macros true
AlertPhishingSSLMismatch false
AlertPhishingCloak false
CLAMCONF

# Update ClamAV database
info "Updating ClamAV database..."
freshclam || warn "ClamAV update failed (will retry on startup)"

systemctl enable --now clamav-daemon clamav-freshclam

step "5/6 — Configure SpamAssassin"
cat > /etc/spamassassin/local.cf << SACONF
# SpamAssassin Config — SOC Lab
required_score          5.0
use_bayes               1
bayes_auto_learn        1
bayes_auto_learn_threshold_nonspam  0.1
bayes_auto_learn_threshold_spam     12.0

# DKIM, SPF, DMARC
use_dkim_verifier       1
check_dkim_signature    1

# Whitelist/Blacklist
whitelist_from          *@soc.lab
blacklist_from          *.ru *.cn *.xyz

# Network checks
use_razor2              1
use_pyzor               1
use_dcc                 0

# Score adjustments
score RAZOR2_CHECK           2.0
score PYZOR_CHECK            2.0
score DKIM_INVALID           3.0
score SPF_FAIL               3.0
score SPF_SOFTFAIL           1.0
score DMARC_FAIL             3.0
score URIBL_BLACK            5.0
score URIBL_RED              3.0

# Phishing detection
score FREEMAIL_FORGED_FROMDOMAIN  3.0
score FREEMAIL_FROM               0.5
score FROM_EXCESS_BASE64          2.0
SACONF

systemctl enable --now spamassassin

step "6/6 — Configure Rsyslog → Wazuh"
cat >> /etc/rsyslog.d/50-soc-wazuh.conf << RSYSLOG
# Forward mail logs to Wazuh SIEM
:programname, isequal, "postfix" @192.168.10.10:514
:programname, isequal, "pmg" @192.168.10.10:514
:programname, isequal, "pmgpolicy" @192.168.10.10:514
:programname, isequal, "clamav" @192.168.10.10:514
:programname, isequal, "spamd" @192.168.10.10:514
RSYSLOG

systemctl restart rsyslog

# Start PMG services
systemctl enable --now pmgproxy pmgdaemon pmgmirror

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Proxmox Mail Gateway Installed!                     ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  WebUI:   https://192.168.10.30:8006                 ║${NC}"
echo -e "${GREEN}║  Login:   root / (your root password)                ║${NC}"
echo -e "${GREEN}║  SMTP:    192.168.10.30:25                           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next: Configure relay domain in WebUI               ║${NC}"
echo -e "${GREEN}║  Mail Proxy → Default → Relay Domains: soc.lab      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
