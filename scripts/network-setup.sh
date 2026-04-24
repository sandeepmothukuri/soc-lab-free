#!/usr/bin/env bash
# =============================================================================
# network-setup.sh — Create VirtualBox host-only networks for SOC Lab
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

command -v VBoxManage &>/dev/null || { echo "VirtualBox not found. Run setup-host.sh first."; exit 1; }

# Network definitions
declare -A NETS=(
    ["vboxnet0"]="192.168.10.1"
    ["vboxnet1"]="192.168.20.1"
    ["vboxnet2"]="192.168.30.1"
)
declare -A LABELS=(
    ["vboxnet0"]="Management (SIEM/Tools)"
    ["vboxnet1"]="Attacker (Kali)"
    ["vboxnet2"]="Target (Vulnerable VMs)"
)

# List existing networks
EXISTING=$(VBoxManage list hostonlyifs | grep -oP '(?<=Name:)\s+\S+' | tr -d ' ')

for iface in vboxnet0 vboxnet1 vboxnet2; do
    ip="${NETS[$iface]}"
    label="${LABELS[$iface]}"

    if echo "$EXISTING" | grep -q "^${iface}$"; then
        warn "Interface $iface already exists — reconfiguring..."
    else
        info "Creating $iface ($label)..."
        VBoxManage hostonlyif create
    fi

    VBoxManage hostonlyif ipconfig "$iface" --ip "$ip" --netmask 255.255.255.0

    # Remove DHCP server if exists
    VBoxManage dhcpserver remove --netname "HostInterfaceNetworking-${iface}" 2>/dev/null || true

    info "  $iface → $ip/24 [${label}] ✓"
done

echo ""
info "=== Network Summary ==="
VBoxManage list hostonlyifs | grep -E "Name:|IPAddress:|NetworkMask:|Status:"

echo ""
info "Networks created. Next steps:"
echo "  1. Build pfSense VM first (docs/vm-build-guide.md)"
echo "  2. Assign vboxnet0/1/2 adapters to each VM as documented"
echo "  3. Boot pfSense and configure LAN/WAN/OPT1 interfaces"
