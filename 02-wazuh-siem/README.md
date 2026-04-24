# Module 02 — Wazuh SIEM / XDR
## Replaces: Splunk

---

## What You'll Build

A fully operational SIEM/XDR platform that:
- Ingests logs from all lab VMs (Linux + Windows)
- Detects threats in real-time using MITRE ATT&CK-mapped rules
- Provides file integrity monitoring (FIM)
- Performs active response (auto-block attackers)
- Shows a Kibana-equivalent dashboard (OpenSearch Dashboards)
- Correlates OpenVAS vulnerability data with log events

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│          WAZUH SERVER (192.168.10.10)            │
│                                                  │
│  ┌───────────────┐   ┌──────────────────────┐   │
│  │  wazuh-manager│   │  OpenSearch           │   │
│  │  (Analysis    │   │  (Data Store)         │   │
│  │   Engine)     │   │  Port: 9200           │   │
│  └───────┬───────┘   └──────────┬───────────┘   │
│          │                      │                │
│  ┌───────▼──────────────────────▼───────────┐   │
│  │       OpenSearch Dashboards               │   │
│  │       (Wazuh UI) Port: 443                │   │
│  └───────────────────────────────────────────┘   │
└──────────────────────┬───────────────────────────┘
                       │
         ┌─────────────┼──────────────┐
         │             │              │
┌────────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
│ Ubuntu Target │ │ Metaspl3  │ │ WinServer │
│ Wazuh Agent   │ │ Wazuh Agt │ │ Wazuh Agt │
│ 192.168.30.10 │ │30.20      │ │30.30      │
└───────────────┘ └───────────┘ └───────────┘
```

---

## Step 1 — Install Wazuh Server

```bash
# On Wazuh VM (192.168.10.10, Ubuntu 22.04, 4GB RAM minimum)
sudo ./install-wazuh-server.sh
```

This installs:
- Wazuh Manager (analysis engine)
- OpenSearch (replaces Elasticsearch)
- OpenSearch Dashboards (replaces Kibana)
- Filebeat (log shipper)
- Wazuh API

### Access Dashboard

```
URL:      https://192.168.10.10
Username: admin
Password: (shown at end of install, also in /etc/wazuh-dashboard/wazuh.yml)
```

---

## Step 2 — Enroll Agent VMs

### Linux Agents (Ubuntu Target, Metasploitable3)

```bash
# Run on each Linux target VM
WAZUH_MANAGER="192.168.10.10" \
WAZUH_AGENT_NAME="ubuntu-target" \
sudo ./install-wazuh-agent.sh

# For Metasploitable3:
WAZUH_MANAGER="192.168.10.10" \
WAZUH_AGENT_NAME="metasploitable3" \
sudo ./install-wazuh-agent.sh
```

### Windows Agent

Download installer from Wazuh server or run in PowerShell:
```powershell
# On Windows Server 2019
$WAZUH_MANAGER = "192.168.10.10"
$WAZUH_AGENT_NAME = "windows-target"

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" `
    -OutFile "wazuh-agent.msi"

Start-Process msiexec.exe -ArgumentList `
    "/i wazuh-agent.msi /q WAZUH_MANAGER=$WAZUH_MANAGER WAZUH_AGENT_NAME=$WAZUH_AGENT_NAME" `
    -Wait

Start-Service WazuhSvc
```

---

## Step 3 — Deploy Custom SOC Rules

```bash
# On Wazuh Server — copy custom rules
sudo cp rules/local_rules.xml /var/ossec/etc/rules/
sudo cp rules/soc_custom_rules.xml /var/ossec/etc/rules/

# Validate rules syntax
sudo /var/ossec/bin/wazuh-logtest

# Restart to apply
sudo systemctl restart wazuh-manager
```

---

## Step 4 — Configure Key Detection Capabilities

### File Integrity Monitoring (FIM)

```xml
<!-- Already in configs/ossec.conf -->
<!-- Monitors: /etc, /usr/bin, /usr/sbin, C:\Windows\System32 -->
```

### Active Response (Auto-Block)

```bash
# Test: trigger a brute-force simulation from Kali
# On Kali (192.168.20.10):
hydra -l root -P /usr/share/wordlists/rockyou.txt \
    192.168.30.10 ssh -t 4

# Wazuh will detect after 8 failures (rule 5763) and block the IP
# Check blocks:
sudo /var/ossec/bin/agent_control -a
```

### Log Sources to Enable

Edit `configs/ossec.conf` — the following are pre-configured:
- `/var/log/auth.log` — SSH, sudo, login events
- `/var/log/syslog` — System events
- `/var/log/apache2/access.log` — Web server
- `/var/log/dpkg.log` — Package installs
- Windows Event Log (via agent)

---

## Step 5 — MITRE ATT&CK Dashboard

1. Login to `https://192.168.10.10`
2. Go to **Wazuh → MITRE ATT&CK**
3. You'll see a heatmap of techniques detected in your lab
4. Click any technique to drill down to raw alerts

---

## Hands-On Lab Exercises

### Exercise 1 — Brute Force Detection (T1110)
```bash
# From Kali
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.30.10 ssh
# Watch Wazuh dashboard: Security Events → Filter by rule.id:5763
```

### Exercise 2 — Privilege Escalation (T1068)
```bash
# On Ubuntu Target — create a SUID binary (common privesc)
sudo cp /bin/bash /tmp/rootbash
sudo chmod u+s /tmp/rootbash
# Wazuh FIM will alert on the new SUID file
```

### Exercise 3 — Lateral Movement Detection (T1021)
```bash
# From Kali — SSH to Ubuntu then pivot
ssh user@192.168.30.10
ssh user@192.168.30.20   # pivot attempt
# Both hops logged in Wazuh with source IPs
```

### Exercise 4 — Web Application Attack (T1190)
```bash
# Run Nikto against Metasploitable3 web server
nikto -h 192.168.30.20 -p 80
# Wazuh Apache log decoder will fire web attack rules
```

### Exercise 5 — Malware Simulation (T1105)
```bash
# Download EICAR test file (harmless, but AV-detected)
curl -o /tmp/eicar.com http://www.eicar.org/download/eicar.com
# If ClamAV is installed, Wazuh will alert on detection
```

---

## Useful Wazuh API Commands

```bash
# Authenticate
TOKEN=$(curl -su admin:PASSWORD https://192.168.10.10:55000/security/user/authenticate \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# List agents
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://192.168.10.10:55000/agents | python3 -m json.tool

# Get recent alerts
curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://192.168.10.10:55000/security/events?limit=20" | python3 -m json.tool

# Check agent status
curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://192.168.10.10:55000/agents?status=active" | python3 -m json.tool
```

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Dashboard not loading | `sudo systemctl restart wazuh-dashboard` |
| Agents not connecting | Check port 1514/1515 in pfSense rules |
| High CPU on manager | Reduce `max_eps` in ossec.conf |
| Alerts not appearing | Check filebeat: `sudo systemctl status filebeat` |
| OpenSearch not starting | Check RAM: needs minimum 2GB, set heap: `ES_JAVA_OPTS="-Xms1g -Xmx1g"` |
