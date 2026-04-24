# Network Setup Guide — VirtualBox Configuration

## Overview

This lab uses three isolated networks in VirtualBox:

| Network | Subnet | Purpose |
|---|---|---|
| Management (vboxnet0) | 192.168.10.0/24 | Security tools, SIEM, scanners |
| Attacker (vboxnet1) | 192.168.20.0/24 | Kali Linux, red team ops |
| Target (vboxnet2) | 192.168.30.0/24 | Vulnerable VMs, monitored hosts |

---

## Step 1 — Create Host-Only Networks in VirtualBox

### Via GUI

1. Open VirtualBox → **File → Host Network Manager**
2. Click **Create** three times
3. Configure each:

**vboxnet0 — Management**
- IPv4: `192.168.10.1`
- Mask: `255.255.255.0`
- DHCP: **Disabled** (we use static IPs)

**vboxnet1 — Attacker**
- IPv4: `192.168.20.1`
- Mask: `255.255.255.0`
- DHCP: **Disabled**

**vboxnet2 — Target**
- IPv4: `192.168.30.1`
- Mask: `255.255.255.0`
- DHCP: **Disabled**

### Via CLI (faster)

```bash
# Create the three networks
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.10.1 --netmask 255.255.255.0

VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet1 --ip 192.168.20.1 --netmask 255.255.255.0

VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet2 --ip 192.168.30.1 --netmask 255.255.255.0

# Disable DHCP on all
VBoxManage dhcpserver remove --netname HostInterfaceNetworking-vboxnet0 2>/dev/null
VBoxManage dhcpserver remove --netname HostInterfaceNetworking-vboxnet1 2>/dev/null
VBoxManage dhcpserver remove --netname HostInterfaceNetworking-vboxnet2 2>/dev/null
```

---

## Step 2 — Assign Networks to VMs

Each VM gets the appropriate adapter(s):

### pfSense (Router/Firewall) — 3 adapters
```
Adapter 1: NAT (WAN — internet access)
Adapter 2: Host-Only vboxnet0 (LAN — Management)
Adapter 3: Host-Only vboxnet2 (OPT1 — Target)
```

### Wazuh Server
```
Adapter 1: Host-Only vboxnet0 (Management)
IP: 192.168.10.10/24
GW: 192.168.10.1 (pfSense)
```

### OpenVAS
```
Adapter 1: Host-Only vboxnet0 (Management)
IP: 192.168.10.20/24
GW: 192.168.10.1
```

### Proxmox Mail Gateway
```
Adapter 1: Host-Only vboxnet0 (Management)
IP: 192.168.10.30/24
GW: 192.168.10.1
```

### Ubuntu Target + Kali Target
```
Adapter 1: Host-Only vboxnet2 (Target network)
IP: 192.168.30.10/24
GW: 192.168.30.1 (pfSense OPT1 interface)
```

### Metasploitable3
```
Adapter 1: Host-Only vboxnet2
IP: 192.168.30.20/24
```

### Kali Linux (Attacker)
```
Adapter 1: NAT (internet for tools)
Adapter 2: Host-Only vboxnet1 (Attacker network)
Adapter 3: Host-Only vboxnet2 (Can reach targets)
```

---

## Step 3 — Configure Static IPs on Ubuntu/Debian VMs

Edit `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 192.168.10.10/24   # Change per VM
      routes:
        - to: default
          via: 192.168.10.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

Apply:
```bash
sudo netplan apply
```

---

## Step 4 — Test Connectivity

From Wazuh server (192.168.10.10):
```bash
# Can reach pfSense
ping -c 2 192.168.10.1

# Can reach OpenVAS
ping -c 2 192.168.10.20

# Can reach targets (via pfSense routing)
ping -c 2 192.168.30.10

# Can reach internet (via pfSense NAT)
ping -c 2 8.8.8.8
```

---

## pfSense Routing Rules

After pfSense is installed, add these firewall rules:

1. **LAN → any**: Allow all (for lab purposes)
2. **OPT1 → LAN**: Allow from 192.168.30.0/24 to 192.168.10.0/24
3. **LAN → OPT1**: Allow from 192.168.10.0/24 to 192.168.30.0/24
4. **LAN → WAN**: Allow with NAT masquerade

These rules let your SIEM, scanner, and email gateway reach and monitor the target VMs.
