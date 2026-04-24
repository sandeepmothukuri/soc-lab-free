#!/usr/bin/env bash
# =============================================================================
# install-wazuh-server.sh — Deploy full Wazuh Stack (Manager + Indexer + Dashboard)
# Target: Ubuntu 22.04 LTS (192.168.10.10) — 4GB RAM minimum
# Replaces: Splunk Enterprise
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}══ Step $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# Check RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
[[ $RAM_MB -lt 3500 ]] && warn "Less than 4GB RAM detected (${RAM_MB}MB). Performance may be degraded."

WAZUH_VERSION="4.7"
WAZUH_INDEXER_PASS="$(openssl rand -base64 20 | tr -d '/+=')"
WAZUH_API_PASS="$(openssl rand -base64 20 | tr -d '/+=')"

step "1/6 — System Preparation"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl apt-transport-https lsb-release gnupg2 \
    openssl net-tools wget jq python3 python3-pip

# Set hostname
hostnamectl set-hostname wazuh-server

step "2/6 — Add Wazuh Repository"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -qq

step "3/6 — Install Wazuh Indexer (OpenSearch)"
apt-get install -y wazuh-indexer

# Configure Wazuh Indexer
cat > /etc/wazuh-indexer/opensearch.yml << INDEXER_CONF
network.host: 0.0.0.0
node.name: wazuh-indexer
cluster.initial_master_nodes:
  - wazuh-indexer
cluster.name: wazuh-cluster
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
  [".opendistro-alerting-config", ".opendistro-alerting-alert*",
   ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*",
   ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state",
   ".opendistro-reports-*", ".opendistro-notifications-*",
   ".opendistro-notebooks", ".opensearch-observability", ".ql-datasources",
   ".opendistro-asynchronous-search-response*", ".replication-metadata-store",
   ".opensearch-knn-models", ".geospatial-ip2geo-data*"]
compatibility.override_main_response_version: true
INDEXER_CONF

# Generate certificates using Wazuh cert tool
info "Generating SSL certificates..."
curl -sO https://packages.wazuh.com/4.7/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

cat > config.yml << CERTCONF
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "192.168.10.10"
  server:
    - name: wazuh-server
      ip: "192.168.10.10"
  dashboard:
    - name: wazuh-dashboard
      ip: "192.168.10.10"
CERTCONF

bash wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .

# Install certs for indexer
mkdir -p /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
    ./wazuh-indexer.pem ./wazuh-indexer-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Set JVM heap (50% of RAM, max 4g)
HEAP_SIZE=$(echo "$RAM_MB / 2" | bc)
[[ $HEAP_SIZE -gt 4096 ]] && HEAP_SIZE=4096
sed -i "s/-Xms4g/-Xms${HEAP_SIZE}m/" /etc/wazuh-indexer/jvm.options
sed -i "s/-Xmx4g/-Xmx${HEAP_SIZE}m/" /etc/wazuh-indexer/jvm.options

systemctl daemon-reload
systemctl enable --now wazuh-indexer

# Wait for indexer
info "Waiting for Wazuh Indexer to start..."
for i in {1..30}; do
    if curl -sk -u admin:admin https://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"'; then
        break
    fi
    sleep 5; echo -n "."
done
echo ""

# Init security
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

step "4/6 — Install Wazuh Manager"
apt-get install -y wazuh-manager filebeat

# Deploy custom ossec.conf
cp /etc/ossec.conf /etc/ossec.conf.bak 2>/dev/null || true
cp configs/ossec.conf /var/ossec/etc/ossec.conf

# Copy custom rules
cp rules/local_rules.xml /var/ossec/etc/rules/
cp rules/soc_custom_rules.xml /var/ossec/etc/rules/ 2>/dev/null || true

# Configure Filebeat for Wazuh
curl -sO https://packages.wazuh.com/4.7/tpl/wazuh/filebeat/filebeat.yml
cp filebeat.yml /etc/filebeat/filebeat.yml

mkdir -p /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ \
    ./wazuh-server.pem ./wazuh-server-key.pem ./root-ca.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs

curl -sO https://raw.githubusercontent.com/wazuh/wazuh/v4.7.0/extensions/filebeat/7.x/wazuh-template.json
filebeat setup --index-management -E setup.template.json.enabled=false

systemctl enable --now wazuh-manager filebeat

step "5/6 — Install Wazuh Dashboard (OpenSearch Dashboards)"
apt-get install -y wazuh-dashboard

mkdir -p /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ \
    ./wazuh-dashboard.pem ./wazuh-dashboard-key.pem ./root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

cat > /etc/wazuh-dashboard/opensearch_dashboards.yml << DASHBOARD_CONF
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://192.168.10.10:9200
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh
DASHBOARD_CONF

systemctl enable --now wazuh-dashboard

step "6/6 — Set Admin Password & Save Credentials"
# Change default indexer admin password
curl -sk -u admin:admin -X PUT "https://localhost:9200/_plugins/_security/api/internalusers/admin" \
    -H 'Content-Type: application/json' \
    -d "{\"password\": \"${WAZUH_INDEXER_PASS}\", \"backend_roles\": [\"admin\"]}"

# Save all credentials
mkdir -p /root/.soc-lab
cat > /root/.soc-lab/wazuh-credentials.txt << CREDS
=== Wazuh SOC Lab Credentials ===
Dashboard URL:    https://192.168.10.10
Username:         admin
Password:         ${WAZUH_INDEXER_PASS}

Wazuh API URL:    https://192.168.10.10:55000
API Username:     wazuh
API Password:     ${WAZUH_API_PASS}

OpenSearch URL:   https://192.168.10.10:9200
OS Username:      admin
OS Password:      ${WAZUH_INDEXER_PASS}
CREDS
chmod 600 /root/.soc-lab/wazuh-credentials.txt

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Wazuh SIEM Installation Complete!                       ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Dashboard:  https://192.168.10.10                       ║${NC}"
echo -e "${GREEN}║  Username:   admin                                       ║${NC}"
echo -e "${GREEN}║  Password:   ${WAZUH_INDEXER_PASS}                 ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next: Install agents on target VMs                      ║${NC}"
echo -e "${GREEN}║  Run: sudo WAZUH_MANAGER=192.168.10.10 ./install-wazuh-agent.sh ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
cat /root/.soc-lab/wazuh-credentials.txt
