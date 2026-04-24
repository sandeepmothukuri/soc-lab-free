# VM Build Guide — Step-by-Step

## VM 1 — pfSense Firewall (Deploy First)

**Download:** https://www.pfsense.org/download/ (pfSense CE 2.7.x, AMD64, DVD ISO)

### VirtualBox Config
```
Name: pfSense-FW
Type: BSD → FreeBSD (64-bit)
RAM: 1024 MB
Disk: 20 GB (VDI, Dynamically allocated)
Adapter 1: NAT
Adapter 2: Host-Only vboxnet0
Adapter 3: Host-Only vboxnet2
```

### pfSense First-Boot Configuration
1. Boot from ISO → Accept default install
2. At VLAN setup → **No**
3. WAN interface → `em0` (NAT adapter)
4. LAN interface → `em1` (vboxnet0)
5. OPT1 interface → `em2` (vboxnet2)
6. After install, set LAN IP: `192.168.10.1/24`
7. Access WebGUI from host: `https://192.168.10.1` (admin/pfsense)

---

## VM 2 — Wazuh SIEM Server

**Download:** Ubuntu Server 22.04 LTS — https://ubuntu.com/download/server

### VirtualBox Config
```
Name: Wazuh-SIEM
RAM: 4096 MB (4 GB minimum)
Disk: 50 GB
Adapter 1: Host-Only vboxnet0
```

### Post-Install Setup
```bash
# Set hostname
sudo hostnamectl set-hostname wazuh-server

# Set static IP (edit /etc/netplan/00-installer-config.yaml)
# IP: 192.168.10.10/24, GW: 192.168.10.1

# Update
sudo apt update && sudo apt upgrade -y
```

Then run: `sudo ./02-wazuh-siem/install-wazuh-server.sh`

---

## VM 3 — OpenVAS/Greenbone Scanner

**Download:** Kali Linux (includes OpenVAS) OR Ubuntu 22.04 for manual install

### VirtualBox Config
```
Name: OpenVAS-Scanner
RAM: 4096 MB
Disk: 50 GB
Adapter 1: Host-Only vboxnet0
```

### Post-Install Setup
```bash
sudo hostnamectl set-hostname openvas-scanner
# IP: 192.168.10.20/24, GW: 192.168.10.1
```

Then run: `sudo ./01-openvas/install-openvas.sh`

---

## VM 4 — Proxmox Mail Gateway

**Download:** https://www.proxmox.com/en/downloads/proxmox-mail-gateway
(Use Proxmox Mail Gateway ISO)

### VirtualBox Config
```
Name: PMG-Mail
RAM: 2048 MB
Disk: 30 GB
Adapter 1: Host-Only vboxnet0
```

### Post-Install
- IP: `192.168.10.30/24`
- Gateway: `192.168.10.1`
- Access WebUI: `https://192.168.10.30:8006`
- Default creds: `root` / (set during install)

---

## VM 5 — Ubuntu 22.04 Target (Linux Target)

```
Name: Ubuntu-Target
RAM: 2048 MB
Disk: 30 GB
Adapter 1: Host-Only vboxnet2
IP: 192.168.30.10/24, GW: 192.168.30.1
```

**Install Wazuh agent after Wazuh server is running:**
```bash
sudo ./02-wazuh-siem/install-wazuh-agent.sh 192.168.10.10
```

---

## VM 6 — Metasploitable3 (Intentionally Vulnerable Linux Target)

**Download & Build:**
```bash
# On your HOST machine (requires Vagrant + Packer)
git clone https://github.com/rapid7/metasploitable3.git
cd metasploitable3
./build.sh ubuntu1404
vagrant up ub1404
```

Or import the pre-built OVA if available.

```
Name: Metasploitable3
RAM: 2048 MB
Adapter 1: Host-Only vboxnet2
IP: 192.168.30.20/24
```

**Credentials:** `vagrant:vagrant`

---

## VM 7 — Windows Server 2019 (Windows Target)

**Download:** https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
(180-day free eval)

```
Name: WinServer-Target
RAM: 4096 MB
Disk: 60 GB
Adapter 1: Host-Only vboxnet2
IP: 192.168.30.30/24, GW: 192.168.30.1
```

**Post-Install PowerShell:**
```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.30.30 -PrefixLength 24 -DefaultGateway 192.168.30.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8

# Enable WinRM for remote management
Enable-PSRemoting -Force
winrm quickconfig -y
```

Install Wazuh agent from: `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi`

---

## VM 8 — Kali Linux (Attacker)

**Download:** https://www.kali.org/get-kali/#kali-virtual-machines
(Pre-built VirtualBox image — no install needed)

```
Name: Kali-Attacker
RAM: 2048 MB
Adapter 1: NAT
Adapter 2: Host-Only vboxnet1
Adapter 3: Host-Only vboxnet2
```

**Default creds:** `kali:kali`

---

## Build Order

```
1. pfSense       ← Must be first (provides routing for all others)
2. Wazuh Server  ← Core SIEM, agents register to this
3. OpenVAS       ← Needs network access to targets
4. Proxmox Mail  ← Independent, can be done any time
5. Ubuntu Target ← Install Wazuh agent pointing to step 2
6. Metasploitable← Independent target VM
7. Win Server    ← Install Wazuh agent pointing to step 2
8. Kali Linux    ← Last (attacker, used for testing)
```
