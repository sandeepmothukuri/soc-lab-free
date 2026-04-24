# Incident Response Playbooks — SOC Lab

## Playbook 1 — SSH Brute Force → Successful Login

**Trigger:** Wazuh rule 5763 (brute force) + 5715 (successful login) from same IP

### Detection
```
Wazuh Alert: [CRITICAL] Brute Force Then Successful Login
Source IP: 192.168.20.10 (Kali Attacker)
Target: 192.168.30.10 (Ubuntu Target)
```

### Triage Steps

1. **Confirm the alert is real (not a false positive):**
   ```bash
   # On Wazuh server — query last 100 alerts from this IP
   curl -sk -H "Authorization: Bearer $TOKEN" \
       "https://192.168.10.10:55000/security/events?q=data.srcip=192.168.20.10" \
       | python3 -m json.tool | grep -E "rule|timestamp|srcip"
   ```

2. **Check if attacker is currently logged in:**
   ```bash
   # On Ubuntu Target (192.168.30.10)
   who
   last | head -20
   w
   # Check for active SSH sessions
   ss -tp | grep ssh
   ```

3. **Review what attacker did (if session is active):**
   ```bash
   # Audit log
   sudo ausearch -i -m USER_CMD --start today | head -50
   # Check bash history for logged-in user
   cat /home/compromised_user/.bash_history
   ```

### Containment

4. **Block attacker IP immediately:**
   ```bash
   # On Ubuntu Target (or Wazuh active response does this automatically)
   sudo iptables -I INPUT -s 192.168.20.10 -j DROP
   sudo iptables -I OUTPUT -d 192.168.20.10 -j DROP
   # Make persistent
   sudo iptables-save > /etc/iptables/rules.v4
   ```

5. **Terminate active session:**
   ```bash
   # Get the attacker's PTS (pseudo terminal)
   who
   # Kill their session
   sudo pkill -u attacker_username
   # Or by TTY:
   sudo fuser -k /dev/pts/1
   ```

6. **Block at pfSense (network-level block):**
   - pfSense WebGUI → Firewall → Rules → OPT1 → Add rule
   - Action: Block, Source: 192.168.20.10, Description: "Confirmed attacker"

### Eradication

7. **Check for persistence mechanisms:**
   ```bash
   # New cron jobs
   crontab -l -u root
   ls -la /etc/cron.d/ /var/spool/cron/

   # New SSH keys
   cat /root/.ssh/authorized_keys
   for user in $(cut -d: -f1 /etc/passwd); do
       f="/home/$user/.ssh/authorized_keys"
       [[ -f "$f" ]] && echo "=== $user ===" && cat "$f"
   done

   # New user accounts
   grep -E 'bash|sh$' /etc/passwd | awk -F: '$3>=1000'

   # SUID files (compare to baseline)
   find / -xdev -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_current.txt
   diff /tmp/suid_baseline.txt /tmp/suid_current.txt

   # Backdoor listeners
   ss -tlnp | grep -v ESTABLISHED
   ```

8. **Restore from known-good if compromised:**
   ```bash
   # If system was backdoored — restore VM snapshot
   # In VirtualBox: right-click VM → Snapshots → Restore
   ```

### Recovery & Lessons Learned

9. **Apply fixes:**
   - Run `05-lynis-prowler/configs/cis-harden.sh` on affected host
   - Verify SSH key-only auth: `PasswordAuthentication no` in sshd_config
   - Rotate all credentials on affected system
   - Update OpenVAS scan to check for same vulnerabilities on other hosts

10. **Document in report:**
    ```
    Incident: SSH-BF-2024-001
    Date: [DATE]
    Duration: [TIME TO DETECT] → [TIME TO CONTAIN]
    Root Cause: Weak password on root account
    Impact: [SCOPE]
    Remediation: Password policy enforced, fail2ban configured
    MITRE: T1110.001 → T1021.004
    ```

---

## Playbook 2 — Malware / Webshell Detected

**Trigger:** Wazuh FIM alert (rule 550/554) on `/var/www/` with `.php` extension + Wazuh rule 100060

### Detection
```
Wazuh Alert: [CRITICAL] New PHP file in web root — Possible webshell
File: /var/www/html/images/shell.php
Host: 192.168.30.10
```

### Triage

1. **Examine the suspicious file:**
   ```bash
   # On target host
   sudo cat /var/www/html/images/shell.php
   # Look for: eval(), system(), exec(), base64_decode(), $_GET/$_POST
   ```

2. **Check web server access log for use of this file:**
   ```bash
   grep 'shell.php' /var/log/apache2/access.log | tail -50
   # Look for POST requests or unusual query parameters
   ```

3. **Scan with ClamAV:**
   ```bash
   clamscan -r /var/www/html/ --log=/tmp/clamav-scan.log
   ```

4. **Check when file appeared and by what process:**
   ```bash
   # Auditd
   ausearch -f /var/www/html/images/shell.php | head -30
   # Check parent process
   ps aux | grep apache
   # Who wrote to web directory recently?
   find /var/www -newer /var/www/html/index.html -type f
   ```

### Containment

5. **Take webshell offline:**
   ```bash
   sudo mv /var/www/html/images/shell.php /root/evidence/shell.php.$(date +%s)
   sudo systemctl reload apache2
   ```

6. **Block the attacker's IP in pfSense (from access log source IP)**

7. **Consider taking web server offline temporarily:**
   ```bash
   sudo systemctl stop apache2
   ```

### Eradication & Recovery

8. **Full malware scan:**
   ```bash
   clamscan -r / --exclude-dir=/proc --exclude-dir=/sys \
       --log=/tmp/fullscan.log 2>/dev/null
   ```

9. **Check for additional webshells:**
   ```bash
   grep -r "eval(base64_decode" /var/www/ 2>/dev/null
   grep -r "system(\$_" /var/www/ 2>/dev/null
   grep -r "passthru(" /var/www/ 2>/dev/null
   ```

10. **Restore web content from backup or git:**
    ```bash
    cd /var/www/html
    git status   # if version-controlled
    git diff
    git checkout .
    ```

---

## Playbook 3 — Phishing Email Detected

**Trigger:** Wazuh alert from PMG/ClamAV showing phishing indicators

### Investigation

1. **Review quarantined email in PMG WebUI:**
   - `https://192.168.10.30:8006` → Mail Proxy → Quarantine
   - Read full headers: `Received:`, `X-Originating-IP:`, `DKIM-Signature:`

2. **Header analysis:**
   ```bash
   # Extract key headers
   grep -E 'From:|Reply-To:|Return-Path:|X-Originating-IP:' email.eml
   # Check IP reputation
   curl https://api.abuseipdb.com/api/v2/check?ipAddress=SENDER_IP \
       -H "Key: YOUR_API_KEY" | python3 -m json.tool
   ```

3. **Check if any users clicked links:**
   ```bash
   # Search Squid proxy logs for the phishing domain
   grep 'phishing-domain.com' /var/log/squid/access.log
   ```

4. **IOC Extraction:**
   ```bash
   # Extract URLs from email body
   grep -oP 'https?://[^\s"<>]+' email.eml | sort -u
   # Check each URL
   # Add to pfBlockerNG DNS blocklist if malicious
   ```

---

## Playbook 4 — Critical Vulnerability Discovered (OpenVAS)

**Trigger:** OpenVAS → Wazuh event with CVSS 9.0+ on production host

### Triage

1. **Validate the finding:**
   ```bash
   # On Wazuh
   curl -sk -H "Authorization: Bearer $TOKEN" \
       "https://192.168.10.10:55000/security/events?q=rule.groups=openvas&limit=5" \
       | python3 -m json.tool
   ```

2. **Confirm vulnerability exists:**
   ```bash
   # Example: CVE-2021-44228 (Log4Shell)
   # On target host
   dpkg -l | grep log4j
   find / -name "log4j*.jar" 2>/dev/null
   ```

3. **Check exploit availability:**
   ```bash
   # Search exploit-db
   searchsploit CVE-XXXX-XXXX
   msfconsole -x "search type:exploit cve:XXXX-XXXX"
   ```

4. **Risk prioritization:**
   - Is the service internet-facing? (pfSense rules)
   - Is the host in scope for sensitive data?
   - Is there a known working exploit?

### Remediation

5. **Apply patch:**
   ```bash
   sudo apt update && sudo apt upgrade -y PACKAGE
   # Or disable the vulnerable service temporarily
   sudo systemctl stop VULNERABLE_SERVICE
   ```

6. **Add compensating control in pfSense** (if patch not immediately available)

7. **Re-scan to verify fix:**
   ```bash
   # Create targeted scan for just this host and vulnerability
   gvm-cli socket --xml \
       "<create_task><name>Verify-CVE-Fix</name>
        <config id='daba56c8-73ec-11df-a475-002264764cea'/>
        <target id='TARGET_UUID'/></create_task>"
   ```
