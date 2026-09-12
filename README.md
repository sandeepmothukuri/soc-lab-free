# 🛡️ Free SOC Lab — Real-Time Hands-On Project
![100% Free](https://img.shields.io/badge/Cost-100%25%20Free-brightgreen)

[![CI](https://github.com/sandeepmothukuri/soc-lab-free/actions/workflows/lab-validation.yml/badge.svg)](https://github.com/sandeepmothukuri/soc-lab-free/actions) [![Website](https://img.shields.io/badge/Website-cybertechnology.in-blue)](https://cybertechnology.in) [![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

> **100% Free | Production-Grade | Local VM-Based | GitHub-Ready**

A fully functional Security Operations Center (SOC) lab built entirely with **open-source and free tools**, mapped to enterprise security capabilities and designed for hands-on security practitioners.

---

## 🗺️ Tool Mapping — Paid vs Free

| Enterprise Tool | Free Alternative | Category |
|---|---|---|
| **Nessus** | Greenbone/OpenVAS | Vulnerability Scanner |
| **Tenable.sc** | Greenbone Security Manager | Vulnerability Management |
| **Splunk** | Wazuh + OpenSearch/Kibana | SIEM / XDR / Log Management |
| **Netskope** | pfSense + Squid + mitmproxy | CASB / Network Inspection |
| **Mimecast** | Proxmox Mail Gateway + ClamAV | Email Security |
| **Guardstack** | Lynis + Prowler | Security Posture / Hardening |

---

## 🏗️ Lab Architecture

The lab separates management, target and attacker workloads with pfSense providing network control and Wazuh/OpenVAS providing monitoring and vulnerability management.

---

## 🖥️ VM Requirements

| VM | OS | RAM | Disk | Role |
|---|---|---:|---:|---|
| pfSense | pfSense CE | 1 GB | 20 GB | Firewall / Router |
| Wazuh Server | Ubuntu 22.04 LTS | 4 GB | 50 GB | SIEM / XDR |
| OpenVAS | Kali/Ubuntu | 4 GB | 50 GB | Vulnerability Scanner |
| Proxmox Mail GW | Debian | 2 GB | 30 GB | Email Security |
| Ubuntu Target | Ubuntu 22.04 LTS | 2 GB | 30 GB | Linux Target |
| Windows Target | Windows Server | 4 GB | 60 GB | Windows Target |
| Kali Linux | Kali | 2 GB | 40 GB | Attacker |

---

## 📁 Repository Structure

The repository contains installation scripts, configuration files, detection rules, integrations, playbooks and validation workflows for the lab environment.

---

## 🚀 Quick Start

```bash
git clone https://github.com/sandeepmothukuri/soc-lab-free.git
cd soc-lab-free
chmod +x scripts/setup-host.sh
sudo ./scripts/setup-host.sh
./scripts/network-setup.sh
./scripts/health-check.sh
```

---

## 🎯 Hands-On Lab Exercises

| # | Exercise | Tools Used | MITRE ATT&CK |
|---|---|---|---|
| 1 | Initial Recon & Asset Discovery | OpenVAS | TA0043 Reconnaissance |
| 2 | Vulnerability Scan & Prioritization | OpenVAS + Wazuh | TA0007 Discovery |
| 3 | Phishing Email Detection | PMG + ClamAV | T1566 Phishing |
| 4 | Lateral Movement Detection | Wazuh Rules | T1021 Remote Services |
| 5 | Privilege Escalation Alerting | Wazuh + Lynis | T1068 Exploitation |
| 6 | Network Anomaly Detection | pfSense + Snort | T1046 Network Scan |
| 7 | CASB Policy Enforcement | Squid + pfSense | T1537 Data Exfiltration |
| 8 | Incident Response Automation | Integration Scripts | All phases |

---

## 📚 Documentation

- [Network Setup Guide](docs/network-setup.md)
- [VM Build Guide](docs/vm-build-guide.md)
- [Paid vs Free Tool Comparison](docs/tool-comparison.md)

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

# 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:

- Security Operations
- Detection Engineering
- Threat Hunting
- Incident Response
- SIEM / XDR
- SOAR
- DFIR
- MITRE ATT&CK
- Security Automation
- AI-Augmented SOC Operations

This repository is maintained as a practical security engineering environment for designing, testing and validating modern SOC capabilities.

- GitHub: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- Website: [cybertechnology.in](https://cybertechnology.in)
- LinkedIn: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- Email: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository | Description |
|---|---|
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for automated triage |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response |
| [cyberblue](https://github.com/sandeepmothukuri/cyberblue) | Containerised blue-team platform — SIEM, DFIR, CTI, SOAR, Network Analysis |
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage |
| [awesome-lists](https://github.com/sandeepmothukuri/awesome-lists) | SOC/DFIR detection lists, threat-hunting references and security research resources |

---
⭐ **Star this repo if it helped you — it helps other SOC analysts find it!**
