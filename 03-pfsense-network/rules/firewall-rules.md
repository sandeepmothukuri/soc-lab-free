# pfSense Firewall Rules — SOC Lab

## Rule Set Overview

Apply these rules in pfSense WebGUI → **Firewall → Rules**

---

## WAN Interface Rules (Inbound)

| # | Action | Protocol | Source | Dest | Port | Description |
|---|---|---|---|---|---|---|
| 1 | Block | Any | Any | Any | Any | Block all inbound (default — do not delete) |

> WAN is NAT only — no inbound rules needed for the lab.

---

## LAN Interface Rules (Management 192.168.10.0/24)

| # | Action | Protocol | Source | Dest | Port | Description |
|---|---|---|---|---|---|---|
| 1 | Pass | Any | LAN net | Any | Any | Management can access anything |
| 2 | Pass | TCP | LAN net | WAN net | 443,80 | HTTPS/HTTP to internet |
| 3 | Pass | TCP | LAN net | OPT1 net | Any | Management to target VMs |

---

## OPT1 Interface Rules (Target 192.168.30.0/24)

| # | Action | Protocol | Source | Dest | Port | Description |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP | OPT1 net | 192.168.10.10 | 1514,1515 | Wazuh agent to manager |
| 2 | Pass | UDP | OPT1 net | 192.168.10.10 | 514 | Syslog to Wazuh |
| 3 | Pass | TCP | OPT1 net | 192.168.10.20 | 9392 | OpenVAS agent comms |
| 4 | Pass | TCP | OPT1 net | 192.168.10.1 | 3128 | Squid proxy (HTTP/HTTPS) |
| 5 | Block | TCP | OPT1 net | Any | 80,443 | Block direct web (force proxy) |
| 6 | Block | Any | OPT1 net | LAN net | Any | Block direct access to management |
| 7 | Pass | Any | OPT1 net | Any | Any | Allow other traffic |

---

## NAT Rules (Outbound)

Set to **Hybrid Outbound NAT** mode:

| Interface | Source | Translation | Description |
|---|---|---|---|
| WAN | 192.168.10.0/24 | WAN address | Management NAT |
| WAN | 192.168.30.0/24 | WAN address | Target NAT |

---

## Port Forwards (DNAT — Simulating Exposed Services)

For the lab exercises, expose these target services:

| Interface | Proto | Dest Port | Target IP | Target Port | Description |
|---|---|---|---|---|---|
| LAN | TCP | 8080 | 192.168.30.20 | 80 | Metasploitable Web |
| LAN | TCP | 2222 | 192.168.30.20 | 22 | Metasploitable SSH |
| LAN | TCP | 3389 | 192.168.30.30 | 3389 | Windows RDP |

---

## Suricata Alert Thresholds

Configure in **Services → Suricata → Interfaces → Edit → Alerts**

```yaml
# Block immediately (Inline IPS mode):
emerging-malware: BLOCK
emerging-exploit: BLOCK
emerging-trojan: BLOCK

# Alert only (review before blocking):
emerging-scan: ALERT
emerging-shellcode: ALERT
emerging-policy: ALERT
```

---

## pfBlockerNG IP Block Lists

**Firewall → pfBlockerNG → IP → IPv4**

```
# Feodo Botnet C2
https://feodotracker.abuse.ch/downloads/ipblocklist.txt

# Known bad actors
http://cinsscore.com/list/ci-badguys.txt

# Spamhaus DROP
https://www.spamhaus.org/drop/drop.txt

# DShield Top Attackers
https://www.dshield.org/block.txt

# Emerging Threats Compromised
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
```

**Update Interval:** Every 4 hours

**Action:** Deny Both (block inbound and outbound)

---

## Squid Blocklist Files

Create these files on pfSense at `/usr/local/etc/squid/`:

### blocklist-domains.txt
```
# Known malware distribution domains
.malwaredomains.com
.virusshare.com
.zeus-tracker.com
.spamhaus.org
# Tor bridges
bridges.torproject.org
# Crypto miners
.coinhive.com
.cryptoloot.com
.coin-hive.com
```

### bad-patterns.txt (URL patterns)
```
# Command injection attempts
(cmd|exec|system|passthru|eval)\(
# Shell attempts
/bin/(sh|bash|zsh|ksh)
# Path traversal
\.\./\.\./
# SQLi
(union|select|insert|update|delete|drop)\s
```
