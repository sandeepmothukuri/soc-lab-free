# Module 05 — Lynis + Prowler
## Replaces: Guardstack Security

---

## What You'll Build

A Security Posture Management (SPM) system that:
- Audits all Linux VMs against CIS Benchmarks (Lynis)
- Checks cloud security posture (Prowler — even for local VMs via AWS-style mock)
- Generates prioritized hardening recommendations
- Tracks security score over time
- Exports findings to Wazuh SIEM

---

## Lynis — Host Security Auditing (Replaces Guardstack Host Module)

Lynis performs 300+ checks covering:
- Authentication & Authorization
- File permissions
- Kernel security (ASLR, NX bit, etc.)
- Network services
- Logging configuration
- Malware/rootkit detection
- CIS Benchmark compliance

---

## Step 1 — Install Lynis

```bash
# Option 1: Package manager (older version)
sudo apt install -y lynis

# Option 2: Latest from source (recommended)
cd /opt
sudo git clone https://github.com/CISOfy/lynis.git
sudo ln -sf /opt/lynis/lynis /usr/local/bin/lynis
```

---

## Step 2 — Run Lynis Audit

```bash
# Full system audit
sudo ./run-lynis.sh

# Quick audit (no waiting)
sudo lynis audit system --quick

# Audit specific tests only
sudo lynis audit system --tests-from-group "authentication,malware,networking"

# Audit and save report
sudo lynis audit system --report-file /tmp/lynis-$(hostname)-$(date +%Y%m%d).dat
```

### Understanding the Output

```
Lynis Security Scan Results
===================================
Hardening index : 58 [############        ]

Tests performed : 247
Plugins enabled : 0

Components:
- Firewall                [V]
- Malware scanner         [V]

Compliance status:
- CIS recommendations    [PARTIAL]
- PCI DSS               [PARTIAL]
- HIPAA                 [PARTIAL]
```

**Target hardening score: 80+**

---

## Step 3 — Fix Top Findings

### Common Critical Findings

**AUTH-9262 — Password aging not configured:**
```bash
sudo useradd -D -f 30
sudo chage --maxdays 90 --warndays 14 username
```

**KRNL-6000 — ASLR not active:**
```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/99-security.conf
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

**SSH-7408 — SSH root login allowed:**
```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**FILE-7524 — /tmp not mounted with noexec:**
```bash
# Add to /etc/fstab:
echo "tmpfs /tmp tmpfs defaults,nosuid,noexec,nodev 0 0" | sudo tee -a /etc/fstab
sudo mount -o remount /tmp
```

**NETW-3200 — No firewall detected:**
```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.10.0/24  # management
sudo ufw allow 22/tcp
sudo ufw enable
```

---

## Step 4 — Run Prowler (Cloud Security Posture)

Prowler checks AWS/Azure/GCP security but also works for **on-prem via custom checks**.

```bash
# Install Prowler
sudo pip3 install prowler --break-system-packages

# For AWS (if you have a free tier account)
prowler aws --profile default \
    --services iam s3 ec2 guardduty cloudtrail \
    --output-formats html json

# For local infrastructure (custom checks)
sudo ./run-prowler.sh

# Generate HTML report
prowler aws -M html -o /opt/prowler-reports/
```

### Prowler Custom Checks for Local VMs

```bash
# Check 1: Are SSH keys in use (not passwords)?
prowler aws --custom-checks sshkey-auth

# Check 2: Is SELinux/AppArmor enabled?
sestatus 2>/dev/null || aa-status 2>/dev/null

# Check 3: Any world-writable files in /etc?
find /etc -perm -002 -type f 2>/dev/null

# Check 4: Unpatched packages?
apt list --upgradable 2>/dev/null | grep -c security
```

---

## Step 5 — CIS Benchmark Hardening Script

```bash
# Apply CIS Level 1 hardening automatically
sudo ./configs/cis-harden.sh

# Check compliance after hardening
sudo lynis audit system --tests-from-category "hardening"
```

---

## Step 6 — Export to Wazuh SIEM

```bash
# Parse Lynis report and send findings to Wazuh
python3 << 'EOF'
import json, subprocess, datetime

# Parse Lynis report
report = {}
with open('/var/log/lynis-report.dat') as f:
    for line in f:
        if '=' in line:
            k, v = line.strip().split('=', 1)
            report[k] = v

# Create Wazuh-compatible alert
alert = {
    "timestamp": datetime.datetime.utcnow().isoformat(),
    "source": "lynis",
    "hostname": report.get('hostname', 'unknown'),
    "hardening_index": report.get('hardening_index', '0'),
    "warnings": report.get('warnings', '').split(','),
    "suggestions": len(report.get('suggestion', '').split(',')),
    "compliance_cis": report.get('compliance_cis', 'unknown')
}

# Send to Wazuh via active socket
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = f"1:{datetime.date.today().strftime('%b %d %H:%M:%S')} lynis: {json.dumps(alert)}"
sock.sendto(msg.encode(), ('192.168.10.10', 514))
print(f"Sent Lynis report to Wazuh: score={alert['hardening_index']}")
EOF
```

---

## Hardening Benchmark Tracker

Run this weekly and track your progress:

| Date | Lynis Score | CIS Pass | Critical Warnings | High Suggestions |
|---|---|---|---|---|
| Week 1 (baseline) | 45 | 35% | 12 | 34 |
| Week 2 (after fixes) | 62 | 55% | 6 | 18 |
| Week 3 (full hardening) | 78 | 75% | 2 | 8 |
| Target | 80+ | 80%+ | 0 | <5 |

---

## Hands-On Lab Exercises

### Exercise 1 — Baseline Audit
- Run Lynis on Ubuntu Target (fresh install, no hardening)
- Record score and top 10 findings
- Document in `reports/baseline-$(hostname)-$(date).md`

### Exercise 2 — Apply CIS Level 1
- Run `configs/cis-harden.sh` on Ubuntu Target
- Re-run Lynis audit
- Compare before/after scores

### Exercise 3 — Red Team → Blue Team
- From Kali: Exploit a weakness Lynis identified (e.g., world-writable directory)
- Check Wazuh to see if it was detected
- Fix the weakness via Lynis recommendation
- Verify Wazuh alert clears

### Exercise 4 — Windows Hardening
- Run CIS-CAT Lite (free) on Windows Server 2019
- Download: https://www.cisecurity.org/cybersecurity-tools/cis-cat-lite
- Run: `CIS-CAT-Lite-Assessor.bat`
- Review HTML report
- Apply top 5 recommendations

### Exercise 5 — Prowler AWS Free Tier
- Create free AWS account (300 USD credit, 12 months)
- Run Prowler against default AWS config
- Find all IAM issues, S3 public buckets, missing CloudTrail logs
- Fix each finding and re-run to verify
