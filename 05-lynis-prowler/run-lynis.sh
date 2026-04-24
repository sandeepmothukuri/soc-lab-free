#!/usr/bin/env bash
# =============================================================================
# run-lynis.sh — Full CIS audit via Lynis + report generation
# Run on each target VM you want to audit
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }

HOSTNAME=$(hostname)
DATE=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/var/log/lynis-reports"
REPORT_FILE="${REPORT_DIR}/${HOSTNAME}-${DATE}"
WAZUH_SERVER="${WAZUH_SERVER:-192.168.10.10}"

mkdir -p "$REPORT_DIR"

step "Installing Lynis (latest)"
if ! command -v lynis &>/dev/null; then
    if [[ -d /opt/lynis ]]; then
        ln -sf /opt/lynis/lynis /usr/local/bin/lynis
    else
        cd /opt
        git clone --depth=1 https://github.com/CISOfy/lynis.git
        ln -sf /opt/lynis/lynis /usr/local/bin/lynis
        info "Lynis installed from source"
    fi
fi

LYNIS_VER=$(lynis --version 2>/dev/null | head -1)
info "Using: $LYNIS_VER"

step "Running Full System Audit"
info "This takes 3-5 minutes..."

lynis audit system \
    --quiet \
    --report-file "${REPORT_FILE}.dat" \
    --log-file "${REPORT_FILE}.log" \
    --no-colors \
    2>&1 | tee "${REPORT_FILE}-output.txt"

step "Parsing Results"
# Extract key metrics from report
HARDENING_IDX=$(grep '^hardening_index=' "${REPORT_FILE}.dat" | cut -d= -f2 || echo "0")
WARNINGS=$(grep '^warning\[\]=' "${REPORT_FILE}.dat" | wc -l)
SUGGESTIONS=$(grep '^suggestion\[\]=' "${REPORT_FILE}.dat" | wc -l)
TESTS_DONE=$(grep '^tests_executed=' "${REPORT_FILE}.dat" | cut -d= -f2 || echo "0")
OS_NAME=$(grep '^os=' "${REPORT_FILE}.dat" | cut -d= -f2 || echo "unknown")

# Generate Markdown summary report
cat > "${REPORT_FILE}-summary.md" << SUMMARY
# Lynis Audit Report
**Host:** ${HOSTNAME}
**Date:** $(date)
**OS:** ${OS_NAME}

## Score
**Hardening Index: ${HARDENING_IDX}/100**

| Metric | Count |
|---|---|
| Tests Executed | ${TESTS_DONE} |
| Warnings | ${WARNINGS} |
| Suggestions | ${SUGGESTIONS} |

## Warnings (Fix These First)
$(grep '^warning\[\]=' "${REPORT_FILE}.dat" | cut -d= -f2 | sed 's/|/\t/g' | awk '{print "- **"$1"** — "$2}')

## Top Suggestions
$(grep '^suggestion\[\]=' "${REPORT_FILE}.dat" | head -20 | cut -d= -f2 | sed 's/|/\t/g' | awk '{print "- "$1" — "$2}')

## Compliance
$(grep '^compliance_' "${REPORT_FILE}.dat" | sed 's/compliance_//;s/=/ → /')

## Files
- Full log: ${REPORT_FILE}.log
- Raw data: ${REPORT_FILE}.dat
SUMMARY

info "Report saved to ${REPORT_FILE}-summary.md"

step "Sending Results to Wazuh SIEM"
# Send summary to Wazuh via syslog UDP
python3 -c "
import socket, json, datetime

alert = {
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'source': 'lynis',
    'hostname': '${HOSTNAME}',
    'hardening_index': ${HARDENING_IDX},
    'warnings': ${WARNINGS},
    'suggestions': ${SUGGESTIONS},
    'tests_executed': ${TESTS_DONE}
}

msg = 'lynis: ' + json.dumps(alert)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode(), ('${WAZUH_SERVER}', 514))
    print('Sent to Wazuh at ${WAZUH_SERVER}:514')
except Exception as e:
    print(f'Warning: Could not send to Wazuh: {e}')
" 2>/dev/null || true

step "Summary"
echo ""
echo "  Host:            ${HOSTNAME}"
echo "  Hardening Index: ${HARDENING_IDX}/100"
echo "  Warnings:        ${WARNINGS}"
echo "  Suggestions:     ${SUGGESTIONS}"
echo ""
echo "  Report: ${REPORT_FILE}-summary.md"
echo ""

if [[ $HARDENING_IDX -lt 50 ]]; then
    echo -e "${YELLOW}Score below 50 — run configs/cis-harden.sh to apply CIS Level 1 hardening${NC}"
elif [[ $HARDENING_IDX -lt 70 ]]; then
    echo -e "${YELLOW}Score below 70 — review warnings above and apply fixes${NC}"
else
    echo -e "${GREEN}Good score! Address remaining warnings to reach 80+${NC}"
fi
