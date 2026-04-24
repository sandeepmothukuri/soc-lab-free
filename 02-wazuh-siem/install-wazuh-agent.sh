#!/usr/bin/env bash
# =============================================================================
# install-wazuh-agent.sh — Install Wazuh Agent on target VMs
# Target: Ubuntu 22.04 / Debian 11 / Kali Linux
# Usage:  sudo WAZUH_MANAGER=192.168.10.10 WAZUH_AGENT_NAME=my-vm ./install-wazuh-agent.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# Config
WAZUH_MANAGER="${WAZUH_MANAGER:-192.168.10.10}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname)}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-linux-targets}"
WAZUH_VERSION="4.7"

info "Installing Wazuh Agent"
info "  Manager:    ${WAZUH_MANAGER}"
info "  Agent Name: ${WAZUH_AGENT_NAME}"
info "  Group:      ${WAZUH_AGENT_GROUP}"

# Add Wazuh repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -qq

# Install agent
WAZUH_MANAGER="${WAZUH_MANAGER}" \
WAZUH_MANAGER_PORT="1514" \
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" \
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP}" \
apt-get install -y wazuh-agent

# Configure agent
cat > /var/ossec/etc/ossec.conf << AGENT_CONF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux-target, ubuntu, ubuntu22</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <enrollment>
      <enabled>yes</enabled>
    </enrollment>
  </client>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <!-- Critical directories to monitor -->
    <directories realtime="yes" report_changes="yes" check_all="yes">/etc</directories>
    <directories realtime="yes" check_all="yes">/usr/bin,/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/bin,/sbin</directories>
    <directories realtime="yes" report_changes="yes">/root</directories>
    <directories realtime="yes" check_all="yes">/tmp</directories>
    <!-- Exclusions -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <!-- Check SUID/SGID bits -->
    <check_unreadable>no</check_unreadable>
    <skip_nfs>yes</skip_nfs>
    <nodiff>/etc/ssl/private.key</nodiff>
    <!-- Windows registry monitoring (for Windows agents) -->
  </syscheck>

  <!-- Log Analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn 2>/dev/null | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\_\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) == / \1 /' | head -80</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <!-- Active Response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

</ossec_config>
AGENT_CONF

# Enable and start
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

info "Agent status:"
systemctl status wazuh-agent --no-pager -l

echo ""
echo -e "${GREEN}Wazuh agent installed and connected to ${WAZUH_MANAGER}${NC}"
echo -e "${GREEN}Check enrollment in Wazuh dashboard → Agents${NC}"
