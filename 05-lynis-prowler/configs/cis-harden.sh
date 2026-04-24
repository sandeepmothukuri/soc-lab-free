#!/usr/bin/env bash
# =============================================================================
# cis-harden.sh — Apply CIS Benchmark Level 1 hardening to Ubuntu 22.04
# WARNING: Test in lab before applying to production systems!
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
step()  { echo -e "\n${BLUE}[CIS]${NC} $*"; }

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

step "1 — Kernel Hardening (sysctl)"
cat > /etc/sysctl.d/99-cis-hardening.conf << 'SYSCTL'
# CIS 3.1 — Network Parameters (Host Only)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS 3.2 — Network Parameters (Host and Router)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# CIS 3.3 — IPv6
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ASLR
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Prevent core dumps
fs.suid_dumpable = 0

# Restrict ptrace
kernel.yama.ptrace_scope = 1
SYSCTL

sysctl -p /etc/sysctl.d/99-cis-hardening.conf &>/dev/null
info "Kernel parameters hardened"

step "2 — SSH Hardening (CIS 5.2)"
SSHD="/etc/ssh/sshd_config"
cp "$SSHD" "${SSHD}.bak-$(date +%Y%m%d)"

declare -A SSH_SETTINGS=(
    ["Protocol"]="2"
    ["LogLevel"]="VERBOSE"
    ["X11Forwarding"]="no"
    ["MaxAuthTries"]="4"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PermitRootLogin"]="no"
    ["PermitEmptyPasswords"]="no"
    ["PermitUserEnvironment"]="no"
    ["Ciphers"]="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    ["MACs"]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    ["KexAlgorithms"]="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="3"
    ["LoginGraceTime"]="60"
    ["Banner"]="/etc/issue.net"
    ["UsePAM"]="yes"
    ["AllowAgentForwarding"]="no"
    ["AllowTcpForwarding"]="no"
)

for key in "${!SSH_SETTINGS[@]}"; do
    value="${SSH_SETTINGS[$key]}"
    if grep -q "^${key}" "$SSHD"; then
        sed -i "s/^${key}.*/${key} ${value}/" "$SSHD"
    else
        echo "${key} ${value}" >> "$SSHD"
    fi
done

# Legal banner
cat > /etc/issue.net << 'BANNER'
***************************************************************************
NOTICE: This system is for authorized use only. Unauthorized access,
use, or modification is strictly prohibited and may be prosecuted.
All activities are monitored and logged.
***************************************************************************
BANNER

systemctl restart sshd
info "SSH hardened"

step "3 — Password Policy (CIS 5.3, 5.4)"
# PAM password complexity
apt-get install -y libpam-pwquality -qq

cat > /etc/security/pwquality.conf << 'PWQUALITY'
minlen = 14
minclass = 4
maxrepeat = 3
maxsequence = 3
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
dictcheck = 1
PWQUALITY

# Password aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Lock accounts after 5 failures
cat > /etc/security/faillock.conf << 'FAILLOCK'
audit
silent
deny = 5
fail_interval = 900
unlock_time = 900
FAILLOCK

info "Password policy hardened"

step "4 — File Permissions (CIS 6.1)"
# Fix world-writable files
chmod 644 /etc/passwd /etc/group /etc/gshadow /etc/shadow 2>/dev/null || true
chmod 640 /etc/shadow /etc/gshadow
chmod 755 /etc/passwd /etc/group

# Remove world-writable permission from /tmp items
find /tmp -perm -002 -not -type l -exec chmod o-w {} \; 2>/dev/null || true

# Remove unowned files (audit only, don't auto-fix)
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | wc -l)
[[ $UNOWNED -gt 0 ]] && warn "Found $UNOWNED unowned files — review manually: find / -xdev \( -nouser -o -nogroup \)"

# Check SUID/SGID files
info "SUID/SGID files (review these):"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -20

info "File permissions hardened"

step "5 — Firewall (CIS 3.5)"
if ! command -v ufw &>/dev/null; then
    apt-get install -y ufw -qq
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit ssh/tcp          # Rate limit SSH

# Allow Wazuh agent communication
ufw allow out to 192.168.10.10 port 1514 proto tcp
ufw allow out to 192.168.10.10 port 514 proto udp

ufw --force enable
info "UFW firewall enabled"

step "6 — Disable Unused Services"
UNUSED_SERVICES=(
    avahi-daemon
    cups
    isc-dhcp-server
    isc-dhcp-server6
    slapd
    nfs-server
    rpcbind
    bind9
    vsftpd
    dovecot
    smbd
    squid
    snmpd
    rsync
    nis
    talk
    telnet
    xinetd
)

for svc in "${UNUSED_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"
        systemctl disable "$svc"
        info "Disabled: $svc"
    fi
done

step "7 — Auditd (CIS 4.1)"
apt-get install -y auditd audispd-plugins -qq

cat > /etc/audit/rules.d/99-cis.rules << 'AUDITRULES'
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# CIS 4.1.4 — Record Events That Modify Date and Time Information
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# CIS 4.1.5 — Record Events That Modify User/Group Information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# CIS 4.1.6 — Record Events That Modify the System's Network Environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# CIS 4.1.7 — Record Events That Modify the System's MAC Policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# CIS 4.1.8 — Record Login/Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# CIS 4.1.9 — Record Session Initiation Events
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# CIS 4.1.11 — Record Discretionary Access Control Permission Modification
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# CIS 4.1.12 — Unsuccessful Unauthorized Access Attempts to Files
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# CIS 4.1.14 — Record Events that Modify the System's Mandatory Access Controls
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# CIS 4.1.15 — Record Sudo Usage
-w /var/log/sudo.log -p wa -k actions

# CIS 4.1.16 — Kernel Module Loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make the configuration immutable
-e 2
AUDITRULES

service auditd restart
info "Auditd configured with CIS rules"

step "Summary"
echo ""
echo -e "${GREEN}CIS Level 1 Hardening Applied!${NC}"
echo ""
echo "  Actions taken:"
echo "  ✓ Kernel parameters hardened (sysctl)"
echo "  ✓ SSH hardened (root login disabled, strong ciphers)"
echo "  ✓ Password policy set (14 char min, complexity required)"
echo "  ✓ Account lockout enabled (5 failures)"
echo "  ✓ File permissions checked"
echo "  ✓ UFW firewall enabled"
echo "  ✓ Unused services disabled"
echo "  ✓ Auditd configured with CIS rules"
echo ""
echo "  Run Lynis again to verify improvement:"
echo "  sudo lynis audit system --quick"
echo ""
warn "Reboot recommended to apply all kernel changes"
