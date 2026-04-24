# Module 06 — Cross-Tool Integrations & Automation
## The SOC Brain — Connecting Everything Together

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    WAZUH SIEM (Hub)                     │
│                  192.168.10.10                          │
│                                                         │
│  Receives from:          Sends to:                      │
│  ─────────────           ─────────                      │
│  OpenVAS (vuln data) →   Active Response Scripts        │
│  pfSense (fw logs) →     Email Alerts                   │
│  Squid (proxy logs) →    Slack/Teams Webhooks           │
│  PMG (mail events) →     Ticket System (optional)       │
│  Lynis (audit scores) →  Custom Dashboards              │
│  All agent logs →        MITRE ATT&CK Heatmap           │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│         scripts/openvas-to-wazuh.py         │
│  Polls OpenVAS API → formats → sends to     │
│  Wazuh socket as syslog events              │
├─────────────────────────────────────────────┤
│         scripts/alert-correlator.py         │
│  Reads Wazuh alerts → correlates events     │
│  across tools → fires compound alerts       │
├─────────────────────────────────────────────┤
│         scripts/auto-response.sh            │
│  Triggered by Wazuh active response →       │
│  blocks IPs, isolates VMs, notifies team    │
└─────────────────────────────────────────────┘
```

---

## Integration 1 — OpenVAS → Wazuh

**What:** OpenVAS scan results flow into Wazuh as security events

**How to run:**
```bash
# Watch mode (continuous) — runs in background
python3 scripts/openvas-to-wazuh.py \
    --openvas-host 192.168.10.20 \
    --openvas-user admin \
    --openvas-pass YOUR_PASS \
    --wazuh-host 192.168.10.10 \
    --watch \
    --interval 300 &

# One-shot (pull latest scan results now)
python3 scripts/openvas-to-wazuh.py \
    --openvas-host 192.168.10.20 \
    --wazuh-host 192.168.10.10
```

**What you see in Wazuh:** Custom alerts under rule group `vuln_scan,openvas` — severity-mapped to Wazuh levels 8-14

---

## Integration 2 — Alert Correlation

**What:** Correlates events across tools to detect compound attack scenarios

**Example scenarios detected:**
- OpenVAS finds vuln on host X → Kali attacks same port → Wazuh fires combined alert
- Failed SSH brute force → followed by successful login → lateral movement chain
- PMG blocks phishing email → same sender IP seen in proxy logs → coordinated attack

```bash
python3 scripts/alert-correlator.py \
    --wazuh-api https://192.168.10.10:55000 \
    --wazuh-user admin \
    --wazuh-pass YOUR_PASS \
    --interval 60
```

---

## Integration 3 — Automated Incident Response

**What:** Wazuh active response triggers automatic containment

**Triggers:**
- Brute force (rule 5763) → firewall block
- Malware detected → isolate VM from network
- Critical vuln exploit attempted → alert + block

```bash
# Test active response manually
/var/ossec/bin/agent_control -b 192.168.20.10 -f firewall-drop0 -u 001
# Unblock:
/var/ossec/bin/agent_control -b 192.168.20.10 -f firewall-drop0 -u 001 -s
```

---

## Integration 4 — pfSense Logs → Wazuh

Configure pfSense to send logs:
```
Status → System Logs → Settings:
  Remote Log Servers: 192.168.10.10:514
  Remote Syslog Contents: Everything
```

Wazuh will auto-detect pfSense logs via built-in decoder and fire rules on:
- Firewall blocks (rules/pf.xml)
- Squid access (rules/squid.xml)
- Suricata IPS alerts (rules/suricata.xml)

---

## Integration 5 — Mail Events → Wazuh

PMG sends syslog to Wazuh (configured in Module 04).

Wazuh fires alerts on:
- `postfix[*]: reject:` → rule 3301 fires
- `clamav[*]: virus found` → custom rule 100080
- `pmg[*]: spam blocked` → custom rule 100081

---

## Hands-On Incident Response Playbook

See `playbooks/incident-response.md` for full SOC workflows.
