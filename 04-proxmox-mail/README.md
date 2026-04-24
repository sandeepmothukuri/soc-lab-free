# Module 04 — Proxmox Mail Gateway + ClamAV + SpamAssassin
## Replaces: Mimecast

---

## What You'll Build

A production-grade email security gateway that:
- Filters all inbound/outbound SMTP traffic
- Detects spam with SpamAssassin + Bayesian filtering
- Scans attachments for malware with ClamAV
- Enforces SPF, DKIM, DMARC policies
- Quarantines suspicious emails
- Logs all mail events to Wazuh SIEM
- Simulates phishing email detection (T1566)

---

## Architecture

```
External Mail → SMTP Port 25
                    │
          ┌─────────▼──────────────────────┐
          │  Proxmox Mail Gateway           │
          │  192.168.10.30                  │
          │                                 │
          │  ┌─────────┐ ┌───────────────┐ │
          │  │ClamAV   │ │ SpamAssassin  │ │
          │  │Antivirus│ │ + Bayes       │ │
          │  └────┬────┘ └───────┬───────┘ │
          │       │              │          │
          │  ┌────▼──────────────▼───────┐ │
          │  │   PMG Policy Engine       │ │
          │  │   SPF/DKIM/DMARC Check    │ │
          │  │   Quarantine Manager      │ │
          │  └───────────────────────────┘ │
          └──────────────┬─────────────────┘
                         │ Clean mail only
                   ┌─────▼──────┐
                   │ Postfix    │
                   │ Mail Server│
                   └────────────┘
```

---

## Step 1 — Install Proxmox Mail Gateway

### Option A — Bare Metal / VM ISO Install

1. Download ISO: https://www.proxmox.com/en/downloads/proxmox-mail-gateway
2. Create VM in VirtualBox:
   - RAM: 2 GB, Disk: 30 GB
   - Adapter 1: Host-Only vboxnet0
3. Boot from ISO → Follow installer
4. Set IP: `192.168.10.30/24`, GW: `192.168.10.1`
5. Access WebUI: `https://192.168.10.30:8006`

### Option B — Install on Debian 12 (more flexible)

```bash
# Run as root on Debian 12
sudo ./install-pmg.sh
```

---

## Step 2 — Configure PMG via WebUI

URL: `https://192.168.10.30:8006`
Login: `root` / (set during install)

### Mail Processing Pipeline

**Mail Proxy → Transport:**

1. **Configuration → Mail Proxy → Default**
   - Relay Domains: `soc.lab`
   - Relay Host: (your internal mail server or 192.168.10.10)
   - Disable TLS: No (test lab)

2. **Configuration → Spam Detector**
   - Use SpamAssassin: ✓
   - Spam Score Threshold: 5.0 (quarantine above this)
   - Delete Threshold: 10.0 (delete above this)

3. **Configuration → Virus Detector**
   - Use ClamAV: ✓
   - Block Encrypted Archives: ✓
   - Block Macros in Office docs: ✓

---

## Step 3 — Configure Mail Filter Rules

### Rule Set Order (PMG processes top to bottom):

**Mail Filter → Rule:**

| Priority | Rule Name | Condition | Action |
|---|---|---|---|
| 1 | Block Dangerous Attachments | Filename matches *.exe,*.js,*.vbs,*.hta | Block |
| 2 | Block Macro Office Docs | Filename matches *.xlsm,*.docm,*.pptm | Quarantine |
| 3 | Mark Spam | Spam level > 5 | Mark + Quarantine |
| 4 | Block Virus | Virus found | Block + Notify Admin |
| 5 | DMARC Fail | DMARC=fail | Quarantine |
| 6 | SPF Softfail | SPF=softfail | Add Header [SPF FAIL] |
| 7 | Allow Clean Mail | Default | Accept |

---

## Step 4 — Configure ClamAV

```bash
# On PMG server
sudo ./install-pmg.sh   # ClamAV included

# Manual ClamAV update
sudo freshclam

# Test ClamAV with EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | \
    clamscan -

# Should output: stdin: Eicar-Signature FOUND
```

---

## Step 5 — Configure SPF/DKIM/DMARC

### SPF Record (add to DNS or /etc/hosts for testing)
```
soc.lab. IN TXT "v=spf1 ip4:192.168.10.30 -all"
```

### DKIM Key Generation
```bash
# Generate DKIM key pair
amavisd-new genrsa /etc/pmg/dkim/soc.lab.key 2048
openssl rsa -in /etc/pmg/dkim/soc.lab.key -pubout \
    -out /etc/pmg/dkim/soc.lab.pub

# View public key (add to DNS TXT record)
cat /etc/pmg/dkim/soc.lab.pub | \
    grep -v "PUBLIC KEY" | tr -d '\n'
```

### DMARC Record
```
_dmarc.soc.lab. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@soc.lab; pct=100"
```

---

## Step 6 — Phishing Email Detection Lab

### Send a Test Phishing Email

```bash
# From Kali (attacker) — simulate phishing with gophish or manual SMTP
# Install swaks (Swiss Army Knife SMTP)
sudo apt install -y swaks

# Send a phishing test email
swaks \
    --to victim@soc.lab \
    --from "paypal-security@paypai.com" \
    --server 192.168.10.30 \
    --port 25 \
    --header "Subject: Urgent: Verify your account" \
    --body "Click here to verify: http://evil.phishing.example/login" \
    --attach /tmp/invoice.exe

# PMG should:
# 1. Block the .exe attachment (rule 1)
# 2. Score high on SpamAssassin (lookalike domain)
# 3. Log to quarantine
# 4. Send alert to Wazuh
```

### Check Quarantine
- PMG WebUI → Mail Proxy → Quarantine
- Review blocked emails with full headers
- Check SpamAssassin score breakdown

---

## Step 7 — Wazuh Integration for Mail Events

```bash
# Configure PMG to forward syslog to Wazuh
echo '*.* @192.168.10.10:514' >> /etc/rsyslog.conf
systemctl restart rsyslog

# Wazuh will auto-parse postfix/pmg logs using built-in decoders
# Alerts fire for:
# - Virus detected (rule 67701)
# - Spam blocked (custom rule 100080)
# - Multiple failed auth attempts
```

---

## Hands-On Lab Exercises

### Exercise 1 — Malware Attachment Detection
- Send email with EICAR.COM test file via swaks
- Verify ClamAV blocks it
- Check Wazuh for mail security alert

### Exercise 2 — Phishing Domain Detection
- Send email from a typosquatted domain (paypa1.com, g00gle.com)
- Check SpamAssassin score
- Review DKIM/SPF check results

### Exercise 3 — Executive Spoofing
- Send email claiming to be from CEO (spoofed From: header)
- PMG should flag DMARC failure
- Practice writing a mail filter rule to block display name spoofing

### Exercise 4 — Email Header Forensics
- Take a quarantined email
- Analyze full headers: trace hop-by-hop path
- Identify originating IP, mail server, user agent

### Exercise 5 — Tune Spam Score
- Send 10 test emails, observe spam scores
- Adjust SpamAssassin score thresholds
- Train Bayes filter on known spam samples
