# Module 01 — OpenVAS / Greenbone Community Edition
## Replaces: Nessus + Tenable.sc

---

## What You'll Build

A fully functional vulnerability management system that:
- Discovers all hosts in your lab network
- Runs authenticated + unauthenticated vulnerability scans
- Generates CVE-prioritized reports
- Pushes scan results to Wazuh SIEM (Module 02)
- Provides a web dashboard equivalent to Tenable.sc

---

## Architecture

```
┌────────────────────────────────────────┐
│  OpenVAS/Greenbone (192.168.10.20)     │
│                                        │
│  ┌──────────┐  ┌──────────┐           │
│  │ GVMd     │  │ GSA      │           │
│  │(Scanner) │  │(Web UI)  │           │
│  └────┬─────┘  └──────────┘           │
│       │                               │
│  ┌────▼─────────────────────────────┐ │
│  │ OpenVAS Scanner + NVT Feed       │ │
│  │ (~90,000+ vulnerability tests)   │ │
│  └──────────────────────────────────┘ │
└───────────────┬────────────────────────┘
                │  Scans
    ┌───────────▼──────────────────┐
    │  Target Network              │
    │  192.168.30.0/24             │
    │  Ubuntu / Metasploitable /   │
    │  Windows Server              │
    └──────────────────────────────┘
```

---

## Step 1 — Install OpenVAS

```bash
# On the OpenVAS VM (192.168.10.20, Ubuntu 22.04)
sudo ./install-openvas.sh
```

This script:
1. Adds the Greenbone Community PPA
2. Installs gvm, openvas, gsa, ospd-openvas
3. Sets up PostgreSQL database
4. Downloads NVT/SCAP/CERT feeds (~1.5 GB, takes 30-60 min)
5. Creates admin user
6. Starts all services

### Access the Web Interface

```
URL:      https://192.168.10.20:9392
Username: admin
Password: (displayed at end of install script)
```

---

## Step 2 — Configure Scan Targets

### Via WebUI

1. Navigate to **Configuration → Targets**
2. Click **New Target**
3. Set:
   - Name: `SOC-Lab-Targets`
   - Hosts: `192.168.30.0/24`
   - Port List: **All IANA assigned TCP**
   - SSH Credentials: (see Step 3)

### Via GVM CLI (faster)

```bash
# Create target via GVM command line
gvm-cli --gmp-username admin --gmp-password YOUR_PASSWORD \
    socket --xml \
    '<create_target>
        <name>SOC-Lab-Targets</name>
        <hosts>192.168.30.0/24</hosts>
        <port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>
    </create_target>'
```

---

## Step 3 — Configure SSH Credentials (Authenticated Scans)

Authenticated scans find 3-5x more vulnerabilities than unauthenticated.

```bash
# On each TARGET VM — create a dedicated scan user
sudo useradd -m -s /bin/bash gvm-scanner
sudo usermod -aG sudo gvm-scanner
echo "gvm-scanner:ScanPass123!" | sudo chpasswd

# Generate SSH key on OpenVAS VM
ssh-keygen -t ed25519 -f ~/.ssh/gvm-scanner -N ""
ssh-copy-id -i ~/.ssh/gvm-scanner.pub gvm-scanner@192.168.30.10
ssh-copy-id -i ~/.ssh/gvm-scanner.pub gvm-scanner@192.168.30.20
```

Then in the WebUI: **Configuration → Credentials → New Credential**
- Type: Username + SSH key
- Username: `gvm-scanner`
- Private key: paste content of `~/.ssh/gvm-scanner`

---

## Step 4 — Run Your First Scan

### Quick Scan (Discovery Only)

```bash
# Load the quick scan config
# configs/scan-config-quick.xml — applies "Host Discovery" template
```

### Full Vulnerability Scan

```bash
# Import the full scan config
gvm-cli socket --xml "$(cat configs/scan-config-full.xml)"
```

### Monitor Scan Progress

```bash
# Check running tasks
gvm-cli --gmp-username admin --gmp-password YOUR_PASSWORD \
    socket --xml '<get_tasks filter="status=Running"/>'
```

---

## Step 5 — Generate Reports

After scan completes:

1. **WebUI**: Results → Select scan → Download as **XML, PDF, or CSV**
2. **CLI export**:

```bash
# Export report as XML
REPORT_ID="your-report-uuid-here"
gvm-cli socket --xml \
    "<get_reports report_id='${REPORT_ID}' format_id='a994b278-1f62-11e1-96ac-406186ea4fc5'/>" \
    > reports/scan-report-$(date +%Y%m%d).xml
```

---

## Step 6 — Push Results to Wazuh SIEM

```bash
# The integration script watches for completed scans and sends to Wazuh
cd ../06-integrations
python3 scripts/openvas-to-wazuh.py --openvas-host 192.168.10.20 \
    --wazuh-host 192.168.10.10 --watch
```

---

## Hands-On Lab Exercises

### Exercise 1 — Discover Assets
- Set target to `192.168.30.0/24`
- Run **Host Discovery** scan
- Document all discovered hosts, open ports, OS fingerprints

### Exercise 2 — Authenticated vs Unauthenticated Scan
- Run unauthenticated scan on `192.168.30.20` (Metasploitable3)
- Add SSH credentials, run authenticated scan
- Compare: how many more CVEs are found with auth?

### Exercise 3 — CVE Triage
- Sort results by CVSS score
- Find all Critical (CVSS 9.0+) vulnerabilities
- For each one: look up CVE in NVD, identify remediation steps

### Exercise 4 — Scan Windows Target
- Create WMI credentials for Windows Server 2019
- Run authenticated scan on `192.168.30.30`
- Identify missing patches, weak configurations

### Exercise 5 — Scheduled Scanning
- Configure a weekly full scan task
- Set email notification on new Critical findings

---

## Key GVM CLI Commands

```bash
# List all targets
gvm-cli socket --xml '<get_targets/>'

# List scan configs
gvm-cli socket --xml '<get_scan_configs/>'

# Start a task
gvm-cli socket --xml '<start_task task_id="UUID"/>'

# Get task status
gvm-cli socket --xml '<get_tasks task_id="UUID"/>'

# List all reports
gvm-cli socket --xml '<get_reports/>'
```

---

## Troubleshooting

| Issue | Fix |
|---|---|
| GSA web UI not loading | `sudo systemctl restart gsad` |
| Feed sync stuck | `sudo runuser -u _gvm -- greenbone-nvt-sync` |
| Scanner not connecting | Check ospd socket: `sudo systemctl status ospd-openvas` |
| Postgres errors | `sudo -u postgres psql -c "\l"` — check gvmd DB exists |
| Slow scan | Reduce max concurrent NVTs in scan config |
