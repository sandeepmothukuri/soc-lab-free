# Enterprise vs Free Tool Comparison

## Nessus / Tenable.sc → Greenbone/OpenVAS

| Feature | Nessus Pro / Tenable.sc | Greenbone Community / OpenVAS |
|---|---|---|
| Vulnerability Scanning | ✅ | ✅ |
| CVE Detection | ✅ | ✅ |
| Network Discovery | ✅ | ✅ |
| Authenticated Scans | ✅ | ✅ |
| Custom Scan Policies | ✅ | ✅ |
| Report Generation | ✅ | ✅ |
| Asset Management | ✅ | ✅ (GVM) |
| API Access | ✅ | ✅ (GMP/REST) |
| Web Dashboard | ✅ | ✅ (GSA) |
| Plugin Updates | ✅ Automated | ✅ NVT feed |
| Price | $3,500+/yr | **FREE** |

**Capability gap:** Tenable.sc has more polished executive reporting and larger plugin library (~175k vs ~50k NVTs). For a lab, OpenVAS covers 100% of practical use cases.

---

## Splunk → Wazuh + OpenSearch

| Feature | Splunk Enterprise | Wazuh + OpenSearch |
|---|---|---|
| Log Ingestion | ✅ | ✅ |
| Real-time Alerting | ✅ | ✅ |
| Custom Rules/Correlation | ✅ (SPL) | ✅ (XML rules) |
| Dashboards | ✅ | ✅ (Kibana/OpenSearch) |
| File Integrity Monitoring | ✅ | ✅ |
| Vulnerability Detection | ✅ | ✅ |
| Threat Intelligence | ✅ | ✅ (MISP integration) |
| Incident Response | ✅ | ✅ (Active Response) |
| Compliance (PCI, HIPAA) | ✅ | ✅ |
| MITRE ATT&CK Mapping | ✅ | ✅ |
| Price | $150/GB/day | **FREE** |

**Capability gap:** Splunk's SPL query language is more powerful for ad-hoc analysis. Wazuh uses XML rules which are less flexible but sufficient for real SOC operations.

---

## Netskope → pfSense + Squid + mitmproxy

| Feature | Netskope | pfSense + Squid + mitmproxy |
|---|---|---|
| Web Traffic Inspection | ✅ | ✅ |
| SSL/TLS Decryption | ✅ | ✅ |
| Cloud App Control | ✅ | ✅ (Squid ACLs) |
| Data Loss Prevention | ✅ | Partial (mitmproxy scripts) |
| User/Group Policies | ✅ | ✅ |
| Bandwidth Control | ✅ | ✅ |
| Threat Protection | ✅ | ✅ (Snort/Suricata IPS) |
| Price | $15-30/user/month | **FREE** |

**Capability gap:** Netskope's DLP and cloud app intelligence are more sophisticated. pfSense provides strong network-layer control and with Suricata IPS is a very capable alternative.

---

## Mimecast → Proxmox Mail Gateway + ClamAV + SpamAssassin

| Feature | Mimecast | Proxmox Mail Gateway |
|---|---|---|
| Anti-Spam | ✅ | ✅ |
| Antivirus | ✅ | ✅ (ClamAV) |
| Email Archiving | ✅ | ✅ |
| Attachment Sandboxing | ✅ | Partial (ClamAV) |
| DKIM/SPF/DMARC | ✅ | ✅ |
| Quarantine Management | ✅ | ✅ |
| Phishing Detection | ✅ | ✅ |
| Web Console | ✅ | ✅ |
| Price | $4-8/user/month | **FREE** |

---

## Guardstack → Lynis + Prowler

| Feature | Guardstack | Lynis + Prowler |
|---|---|---|
| Linux Hardening Audit | ✅ | ✅ (Lynis) |
| Cloud Security Posture | ✅ | ✅ (Prowler) |
| CIS Benchmark Checks | ✅ | ✅ |
| Compliance Reports | ✅ | ✅ |
| Remediation Guidance | ✅ | ✅ |
| Continuous Monitoring | ✅ | Manual/Scheduled |
| Price | $500+/mo | **FREE** |
