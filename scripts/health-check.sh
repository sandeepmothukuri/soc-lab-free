#!/usr/bin/env bash
# =============================================================================
# health-check.sh — Verify all SOC Lab services are running
# Run from the management network (any VM on 192.168.10.0/24)
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
OK()   { echo -e "  ${GREEN}[OK]${NC}   $*"; }
FAIL() { echo -e "  ${RED}[FAIL]${NC} $*"; FAILURES=$((FAILURES+1)); }
INFO() { echo -e "  ${BLUE}[INFO]${NC} $*"; }

FAILURES=0

check_port() {
    local host=$1 port=$2 label=$3
    if timeout 3 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
        OK "$label (${host}:${port})"
    else
        FAIL "$label (${host}:${port}) — unreachable"
    fi
}

check_http() {
    local url=$1 label=$2 expected_code=${3:-200}
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)
    if [[ "$code" == "$expected_code" || "$code" == "301" || "$code" == "302" ]]; then
        OK "$label → HTTP $code"
    else
        FAIL "$label → HTTP $code (expected $expected_code)"
    fi
}

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      SOC Lab Health Check                    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── pfSense ─────────────────────────────────────────
echo -e "${YELLOW}[1] pfSense Firewall (192.168.10.1)${NC}"
check_port  192.168.10.1 443  "pfSense WebGUI (HTTPS)"
check_port  192.168.10.1 22   "pfSense SSH"
check_http  "https://192.168.10.1" "pfSense WebGUI" 200

# ── Wazuh SIEM ─────────────────────────────────────
echo ""
echo -e "${YELLOW}[2] Wazuh SIEM (192.168.10.10)${NC}"
check_port  192.168.10.10 1514 "Wazuh Agent Port (UDP/TCP)"
check_port  192.168.10.10 1515 "Wazuh Agent Enrollment"
check_port  192.168.10.10 55000 "Wazuh API"
check_http  "https://192.168.10.10:443" "Wazuh Dashboard" 200

# Check Wazuh service (if running on this host)
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    OK "wazuh-manager systemd service"
    AGENTS=$(curl -sk -u admin:SecurePass123 "https://192.168.10.10:55000/agents?status=active" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('total_affected_items',0))" 2>/dev/null || echo "?")
    INFO "Active Wazuh agents: ${AGENTS}"
else
    INFO "wazuh-manager not on this host (remote check only)"
fi

# ── OpenVAS ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3] OpenVAS/Greenbone (192.168.10.20)${NC}"
check_port  192.168.10.20 9390 "GVM/OpenVAS GMP port"
check_port  192.168.10.20 9392 "Greenbone Security Assistant (GSA)"
check_http  "https://192.168.10.20:9392" "Greenbone Web UI" 200

# ── Proxmox Mail Gateway ────────────────────────────
echo ""
echo -e "${YELLOW}[4] Proxmox Mail Gateway (192.168.10.30)${NC}"
check_port  192.168.10.30 25   "SMTP"
check_port  192.168.10.30 8006 "PMG WebUI"
check_http  "https://192.168.10.30:8006" "PMG Dashboard" 200

# ── Target VMs ──────────────────────────────────────
echo ""
echo -e "${YELLOW}[5] Target VMs${NC}"
check_port  192.168.30.10 22  "Ubuntu Target SSH"
check_port  192.168.30.20 22  "Metasploitable3 SSH"
check_port  192.168.30.30 3389 "Windows Target RDP"

# ── Kali Attacker ───────────────────────────────────
echo ""
echo -e "${YELLOW}[6] Kali Attacker${NC}"
check_port  192.168.20.10 22  "Kali SSH"

# ── Summary ─────────────────────────────────────────
echo ""
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All services healthy! Lab is ready.${NC}"
else
    echo -e "${RED}${FAILURES} service(s) failed. Check the items above.${NC}"
    exit 1
fi
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
