#!/usr/bin/env bash
# =============================================================================
# install-openvas.sh — Install Greenbone Community Edition (OpenVAS)
# Target: Ubuntu 22.04 LTS (192.168.10.20)
# Replaces: Nessus + Tenable.sc
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

ADMIN_USER="admin"
ADMIN_PASS="$(openssl rand -base64 16 | tr -d '/+=')"
GVM_VERSION="22"   # GVM 22.x = OpenVAS 22.x

step "1/8 — System Update & Dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl wget gnupg2 ca-certificates lsb-release \
    python3 python3-pip postgresql postgresql-client \
    redis-server xmltoman xsltproc nmap net-tools \
    libglib2.0-dev libgnutls28-dev libgpgme-dev \
    gnutls-bin libksba-dev libpcap-dev pkg-config \
    libssh-gcrypt-dev libhiredis-dev gnutls-bin uuid-dev \
    libjson-glib-dev libical-dev libpq-dev libsnmp-dev \
    heimdal-dev libpopt-dev libgcrypt20-dev

step "2/8 — Add Greenbone Community PPA"
# Use Kali/Greenbone official repo
curl -fsSL https://www.greenbone.net/GBCommunitySigningKey.asc | \
    gpg --dearmor -o /usr/share/keyrings/greenbone.gpg

# For Ubuntu 22.04 (jammy) use backports approach via pip/source
# Alternatively use community Docker or Kali packages
info "Installing GVM via community packages..."

# Add Kali-compatible approach: use pip install for gvm-tools
pip3 install --break-system-packages gvm-tools 2>/dev/null || pip3 install gvm-tools

step "3/8 — Install OpenVAS via Greenbone Community Containers (Recommended)"
# The Greenbone Community Edition now ships as Docker Compose
# This is the officially supported free method

if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | bash
    usermod -aG docker ubuntu 2>/dev/null || true
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
    info "Installing Docker Compose..."
    apt-get install -y docker-compose-plugin
fi

step "4/8 — Download Greenbone Community Edition Docker Compose"
mkdir -p /opt/greenbone
cat > /opt/greenbone/docker-compose.yml << 'COMPOSE'
# Greenbone Community Edition — Official Docker Compose
# Source: https://greenbone.github.io/docs/latest/22.4/container/index.html
services:
  vulnerability-tests:
    image: greenbone/vulnerability-tests
    environment:
      STORAGE_PATH: /var/lib/openvas/22.04/vt-data/nasl
    volumes:
      - vt_data_vol:/mnt

  notus-data:
    image: greenbone/notus-data
    volumes:
      - notus_data_vol:/mnt

  scap-data:
    image: greenbone/scap-data
    volumes:
      - scap_data_vol:/mnt

  cert-bund-data:
    image: greenbone/cert-bund-data
    volumes:
      - cert_data_vol:/mnt

  dfn-cert-data:
    image: greenbone/dfn-cert-data
    volumes:
      - cert_data_vol:/mnt
    depends_on:
      - cert-bund-data

  data-objects:
    image: greenbone/data-objects
    volumes:
      - data_objects_vol:/mnt

  report-formats:
    image: greenbone/report-formats
    volumes:
      - data_objects_vol:/mnt
    depends_on:
      - data-objects

  gpg-data:
    image: greenbone/gpg-data
    volumes:
      - gpg_data_vol:/mnt

  redis-server:
    image: greenbone/redis-server
    restart: on-failure
    volumes:
      - redis_socket_vol:/run/redis/

  pg-gvm:
    image: greenbone/pg-gvm:stable
    restart: on-failure
    volumes:
      - psql_data_vol:/var/lib/postgresql
      - psql_socket_vol:/var/run/postgresql

  gvmd:
    image: greenbone/gvmd:stable
    restart: on-failure
    volumes:
      - gvmd_data_vol:/var/lib/gvm
      - scap_data_vol:/var/lib/gvm/scap-data/
      - cert_data_vol:/var/lib/gvm/cert-data
      - data_objects_vol:/var/lib/gvm/data-objects/gvmd
      - vt_data_vol:/var/lib/openvas/plugins
      - psql_data_vol:/var/lib/postgresql
      - gvmd_socket_vol:/run/gvmd
      - ospd_openvas_socket_vol:/run/ospd
      - notus_data_vol:/notus
      - psql_socket_vol:/var/run/postgresql
    depends_on:
      pg-gvm:
        condition: service_started

  ospd-openvas:
    image: greenbone/ospd-openvas:stable
    restart: on-failure
    init: true
    hostname: ospd-openvas.local
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
    command:
      [
        "ospd-openvas",
        "-f",
        "--config", "/etc/gvm/ospd-openvas.conf",
        "--mqtt-broker-address", "mqtt-broker",
        "--notus-feed-dir", "/notus",
        "-m", "666"
      ]
    volumes:
      - gpg_data_vol:/etc/openvas/gnupg
      - vt_data_vol:/var/lib/openvas/plugins
      - notus_data_vol:/notus
      - ospd_openvas_socket_vol:/run/ospd
      - redis_socket_vol:/run/redis/
    depends_on:
      redis-server:
        condition: service_started
      gpg-data:
        condition: service_completed_successfully
      vulnerability-tests:
        condition: service_completed_successfully

  mqtt-broker:
    restart: on-failure
    image: greenbone/mqtt-broker
    ports:
      - 1883:1883
    networks:
      default:
        aliases:
          - mqtt-broker
          - broker

  notus-scanner:
    restart: on-failure
    image: greenbone/notus-scanner:stable
    volumes:
      - notus_data_vol:/notus
      - gpg_data_vol:/etc/openvas/gnupg
    environment:
      NOTUS_SCANNER_MQTT_BROKER_ADDRESS: mqtt-broker
      NOTUS_SCANNER_PRODUCTS_DIRECTORY: /notus
    depends_on:
      - mqtt-broker
      - gpg-data

  gvm-tools:
    image: greenbone/gvm-tools
    volumes:
      - gvmd_socket_vol:/run/gvmd
      - ospd_openvas_socket_vol:/run/ospd
    depends_on:
      - gvmd
      - ospd-openvas

  openvas:
    image: greenbone/openvas-scanner:stable
    restart: on-failure
    volumes:
      - gpg_data_vol:/etc/openvas/gnupg
      - vt_data_vol:/var/lib/openvas/plugins
    environment:
      REDIS_SOCKET_PATH: /run/redis/redis.sock
      NOTUS_FEED_DIR: /notus
    depends_on:
      redis-server:
        condition: service_started

  gsa:
    image: greenbone/gsa:stable
    restart: on-failure
    ports:
      - 127.0.0.1:9392:80
    volumes:
      - gvmd_socket_vol:/run/gvmd
    depends_on:
      - gvmd

volumes:
  gpg_data_vol:
  scap_data_vol:
  cert_data_vol:
  data_objects_vol:
  gvmd_data_vol:
  psql_data_vol:
  vt_data_vol:
  notus_data_vol:
  redis_socket_vol:
  ospd_openvas_socket_vol:
  gvmd_socket_vol:
  psql_socket_vol:
COMPOSE

step "5/8 — Pull Greenbone Images (this takes time on first run)"
cd /opt/greenbone
docker compose -f docker-compose.yml pull

step "6/8 — Start Greenbone Community Edition"
docker compose -f docker-compose.yml up -d

step "7/8 — Wait for services to be ready (2-3 minutes)"
info "Waiting for gvmd to be healthy..."
for i in {1..36}; do
    if docker compose -f /opt/greenbone/docker-compose.yml \
        exec -T gvmd gvmd --get-users 2>/dev/null | grep -q admin; then
        info "gvmd is ready!"
        break
    fi
    echo -n "."
    sleep 5
done
echo ""

step "8/8 — Create Admin User"
docker compose -f /opt/greenbone/docker-compose.yml \
    exec -T gvmd gvmd --create-user="${ADMIN_USER}" --password="${ADMIN_PASS}" 2>/dev/null || \
    docker compose -f /opt/greenbone/docker-compose.yml \
    exec -T gvmd gvmd --user="${ADMIN_USER}" --new-password="${ADMIN_PASS}"

# Create systemd service for auto-start
cat > /etc/systemd/system/greenbone-community.service << SYSTEMD
[Unit]
Description=Greenbone Community Edition
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/greenbone
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=on-failure

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable greenbone-community

# Expose GSA on all interfaces (not just localhost)
info "Configuring GSA to listen on all interfaces..."
sed -i 's/127.0.0.1:9392/0.0.0.0:9392/' /opt/greenbone/docker-compose.yml
docker compose -f /opt/greenbone/docker-compose.yml up -d gsa

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Greenbone/OpenVAS Installation Complete!        ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  URL:      https://192.168.10.20:9392            ║${NC}"
echo -e "${GREEN}║  Username: ${ADMIN_USER}                                    ║${NC}"
echo -e "${GREEN}║  Password: ${ADMIN_PASS}               ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  NOTE: Feed sync runs in background.             ║${NC}"
echo -e "${GREEN}║  Full NVT sync takes 30-60 minutes.              ║${NC}"
echo -e "${GREEN}║  Check: docker compose logs -f notus-data        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"

# Save credentials
echo "OPENVAS_HOST=192.168.10.20" > /opt/greenbone/.env.creds
echo "OPENVAS_USER=${ADMIN_USER}" >> /opt/greenbone/.env.creds
echo "OPENVAS_PASS=${ADMIN_PASS}" >> /opt/greenbone/.env.creds
chmod 600 /opt/greenbone/.env.creds
info "Credentials saved to /opt/greenbone/.env.creds"
