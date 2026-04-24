# 🛡️ Free SOC Lab — Real-Time Hands-On Project

> **100% Free | Production-Grade | Local VM-Based | GitHub-Ready**

A fully functional Security Operations Center (SOC) lab built entirely with **open-source and free tools**, mapped 1:1 to enterprise-grade paid security platforms. Designed for advanced security practitioners who want real hands-on experience.

---

## 🗺️ Tool Mapping — Paid vs Free

| Enterprise Tool | Free Alternative | Category |
|---|---|---|
| **Nessus** | [Greenbone/OpenVAS](#01-openvas--greenbone) | Vulnerability Scanner |
| **Tenable.sc** | [Greenbone Security Manager](#01-openvas--greenbone) | Vuln Management Console |
| **Splunk** | [Wazuh + OpenSearch/Kibana](#02-wazuh-siem) | SIEM / XDR / Log Management |
| **Netskope** | [pfSense + Squid + mitmproxy](#03-pfsense--network-security) | CASB / Network Inspection |
| **Mimecast** | [Proxmox Mail Gateway + ClamAV](#04-proxmox-mail-gateway) | Email Security |
| **Guardstack** | [Lynis + Prowler](#05-lynis--prowler) | Security Posture / Hardening |

---

## 🏗️ Lab Architecture

```
                        ┌─────────────────────────────────────┐
                        │         SOC ANALYST WORKSTATION      │
                        │    (Kali Linux / Ubuntu Desktop)     │
                        │  Wazuh Dashboard | OpenVAS | Kibana  │
                        └─────────────┬───────────────────────┘
                                      │
                        ┌─────────────▼───────────────────────┐
                        │         pfSense FIREWALL             │
                        │   CASB | IDS/IPS | Traffic Inspect   │
                        │      (Replaces Netskope)             │
                        └──┬──────────────────────────────┬───┘
                           │                              │
          ┌────────────────▼──────┐       ┌──────────────▼────────────┐
          │   MANAGEMENT VLAN     │       │      TARGET VLAN           │
          │   192.168.10.0/24     │       │    192.168.30.0/24         │
          │                       │       │                            │
          │  ┌─────────────────┐  │       │  ┌─────────────────────┐  │
          │  │  Wazuh Server   │  │       │  │  Ubuntu 22.04 Target │  │
          │  │  (SIEM/XDR)     │  │       │  │  + Wazuh Agent       │  │
          │  │  192.168.10.10  │  │       │  │  192.168.30.10       │  │
          │  └─────────────────┘  │       │  └─────────────────────┘  │
          │                       │       │                            │
          │  ┌─────────────────┐  │       │  ┌─────────────────────┐  │
          │  │  OpenVAS/       │  │       │  │  Metasploitable3     │  │
          │  │  Greenbone      │  │       │  │  (Vuln Target)       │  │
          │  │  192.168.10.20  │  │       │  │  192.168.30.20       │  │
          │  └─────────────────┘  │       │  └─────────────────────┘  │
          │                       │       │                            │
          │  ┌─────────────────┐  │       │  ┌─────────────────────┐  │
          │  │  Proxmox Mail   │  │       │  │  Windows Server 2019 │  │
          │  │  Gateway        │  │       │  │  + Wazuh Agent       │  │
          │  │  192.168.10.30  │  │       │  │  192.168.30.30       │  │
          │  └─────────────────┘  │       │  └─────────────────────┘  │
          └───────────────────────┘       └────────────────────────────┘
                                                       │
                        ┌──────────────────────────────▼────────────────┐
                        │             ATTACKER VLAN                      │
                        │           192.168.20.0/24                      │
                        │  ┌──────────────────────────────────────────┐  │
                        │  │  Kali Linux (Attack Machine)             │  │
                        │  │  192.168.20.10                           │  │
                        │  └──────────────────────────────────────────┘  │
                        └────────────────────────────────────────────────┘
```

---

## 🖥️ VM Requirements

| VM | OS | RAM | Disk | IP | Role |
|---|---|---|---|---|---|
| pfSense | pfSense CE 2.7 | 1 GB | 20 GB | 192.168.10.1 | Firewall/Router |
| Wazuh Server | Ubuntu 22.04 LTS | 4 GB | 50 GB | 192.168.10.10 | SIEM/XDR |
| OpenVAS | Kali/Ubuntu 22.04 | 4 GB | 50 GB | 192.168.10.20 | Vuln Scanner |
| Proxmox Mail GW | Debian 11 | 2 GB | 30 GB | 192.168.10.30 | Email Security |
| Ubuntu Target | Ubuntu 22.04 LTS | 2 GB | 30 GB | 192.168.30.10 | Linux Target |
| Metasploitable3 | Ubuntu 14.04 | 2 GB | 30 GB | 192.168.30.20 | Vuln Target |
| Windows Target | Windows Server 2019 | 4 GB | 60 GB | 192.168.30.30 | Windows Target |
| Kali Linux | Kali 2024 | 2 GB | 40 GB | 192.168.20.10 | Attacker |

**Total minimum host RAM: 21 GB | Recommended: 32 GB**

---

## 📁 Repository Structure

```
soc-lab-free/
├── README.md                          # This file
├── docs/
│   ├── network-setup.md               # VirtualBox network config
│   ├── vm-build-guide.md              # VM creation step-by-step
│   └── tool-comparison.md             # Paid vs Free feature mapping
├── scripts/
│   ├── setup-host.sh                  # Host machine pre-reqs
│   ├── network-setup.sh               # VirtualBox network automation
│   └── health-check.sh                # Verify all services are running
├── 01-openvas/                        # Replaces Nessus + Tenable.sc
│   ├── README.md
│   ├── install-openvas.sh
│   ├── configs/
│   │   ├── scan-config-full.xml
│   │   ├── scan-config-quick.xml
│   │   └── targets.xml
│   └── reports/
│       └── report-template.md
├── 02-wazuh-siem/                     # Replaces Splunk
│   ├── README.md
│   ├── install-wazuh-server.sh
│   ├── install-wazuh-agent.sh
│   ├── configs/
│   │   ├── ossec.conf
│   │   └── filebeat.yml
│   ├── rules/
│   │   ├── local_rules.xml
│   │   └── soc_custom_rules.xml
│   └── dashboards/
│       └── soc-overview.ndjson
├── 03-pfsense-network/                # Replaces Netskope
│   ├── README.md
│   ├── configs/
│   │   ├── pfsense-config.xml
│   │   └── squid.conf
│   ├── rules/
│   │   └── firewall-rules.md
│   └── squid/
│       ├── squid.conf
│       └── ssl-bump.conf
├── 04-proxmox-mail/                   # Replaces Mimecast
│   ├── README.md
│   ├── install-pmg.sh
│   ├── configs/
│   │   ├── pmg.conf
│   │   └── spam-filter.conf
│   └── clamav/
│       └── clamd.conf
├── 05-lynis-prowler/                  # Replaces Guardstack
│   ├── README.md
│   ├── run-lynis.sh
│   ├── run-prowler.sh
│   ├── configs/
│   │   └── lynis.cfg
│   └── reports/
│       └── hardening-checklist.md
├── 06-integrations/                   # Cross-tool automation
│   ├── README.md
│   ├── scripts/
│   │   ├── openvas-to-wazuh.py
│   │   ├── alert-correlator.py
│   │   └── auto-response.sh
│   ├── rules/
│   │   └── correlation-rules.xml
│   └── playbooks/
│       ├── incident-response.md
│       └── threat-hunting.md
└── .github/
    └── workflows/
        └── lab-validation.yml
```

---

## 🚀 Quick Start (Step-by-Step)

### Step 1 — Prepare Your Host Machine

```bash
# Clone this repo
git clone https://github.com/YOUR_USERNAME/soc-lab-free.git
cd soc-lab-free

# Run host setup (installs VirtualBox, dependencies)
chmod +x scripts/setup-host.sh
sudo ./scripts/setup-host.sh
```

### Step 2 — Build the Network

```bash
# Create VirtualBox host-only networks
chmod +x scripts/network-setup.sh
./scripts/network-setup.sh
```

### Step 3 — Deploy in Order

```bash
# 1. pfSense Firewall first (gateway for all VMs)
cd 03-pfsense-network && cat README.md

# 2. Wazuh SIEM (core of the SOC)
cd ../02-wazuh-siem && sudo ./install-wazuh-server.sh

# 3. OpenVAS Vulnerability Scanner
cd ../01-openvas && sudo ./install-openvas.sh

# 4. Proxmox Mail Gateway
cd ../04-proxmox-mail && sudo ./install-pmg.sh

# 5. Lynis + Prowler on all targets
cd ../05-lynis-prowler && sudo ./run-lynis.sh

# 6. Wire up integrations
cd ../06-integrations && python3 scripts/openvas-to-wazuh.py
```

### Step 4 — Verify Everything Is Running

```bash
chmod +x scripts/health-check.sh
./scripts/health-check.sh
```

---

## 🎯 Hands-On Lab Exercises

Each module has its own exercises. Here's the full SOC workflow:

| # | Exercise | Tools Used | MITRE ATT&CK |
|---|---|---|---|
| 1 | Initial Recon & Asset Discovery | OpenVAS | TA0043 Reconnaissance |
| 2 | Vulnerability Scan & Prioritization | OpenVAS + Wazuh | TA0007 Discovery |
| 3 | Phishing Email Detection | PMG + ClamAV | T1566 Phishing |
| 4 | Lateral Movement Detection | Wazuh Rules | T1021 Remote Services |
| 5 | Privilege Escalation Alerting | Wazuh + Lynis | T1068 Exploitation |
| 6 | Network Anomaly Detection | pfSense + Snort | T1046 Network Scan |
| 7 | CASB Policy Enforcement | Squid + pfSense | T1537 Data Exfil |
| 8 | Incident Response Automation | Integration Scripts | All phases |

---

## 📚 Documentation

- [Network Setup Guide](docs/network-setup.md)
- [VM Build Guide](docs/vm-build-guide.md)
- [Paid vs Free Tool Comparison](docs/tool-comparison.md)

---

## 🔗 Resources

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Greenbone Community Docs](https://greenbone.github.io/docs/)
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [Proxmox Mail Gateway Docs](https://pmg.proxmox.com/pmg-docs/)
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

*Built for advanced SOC practitioners. All tools are 100% free and open source.*
