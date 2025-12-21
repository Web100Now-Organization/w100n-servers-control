#!/bin/bash

# ============================================
# SERVER SETUP VERIFICATION SCRIPT
# Ubuntu 22.04 LTS / 24.04 LTS
# ============================================
# This script verifies all server setup configurations
# Run as root or with sudo

# Don't exit on error - we want to continue checking even if some checks fail
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to print status
print_status() {
    local status=$1
    local message=$2
    case $status in
        "OK")
            echo -e "${GREEN}✓${NC} $message"
            ((PASSED++))
            ;;
        "FAIL")
            echo -e "${RED}✗${NC} $message"
            ((FAILED++))
            ;;
        "WARN")
            echo -e "${YELLOW}⚠${NC} $message"
            ((WARNINGS++))
            ;;
        "INFO")
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
    esac
}

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check service status
check_service() {
    local service=$1
    if $SUDO_CMD systemctl list-unit-files 2>/dev/null | grep -q "^${service}.service" || systemctl list-unit-files 2>/dev/null | grep -q "^${service}.service"; then
        if $SUDO_CMD systemctl is-active --quiet "$service" 2>/dev/null || systemctl is-active --quiet "$service" 2>/dev/null; then
            print_status "OK" "$service service is active"
            return 0
        else
            print_status "WARN" "$service service exists but is not active"
            return 1
        fi
    else
        print_status "WARN" "$service service not found"
        return 1
    fi
}

echo "============================================"
echo "  🔍 SERVER SETUP VERIFICATION"
echo "============================================"
echo ""
echo "Starting verification checks..."
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: This script should be run as root or with sudo for full functionality"
    echo "   Some checks may fail without proper permissions"
    echo ""
    SUDO_CMD="sudo"
else
    SUDO_CMD=""
fi

# ============================================
# 1. SYSTEM INFORMATION
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📋 SYSTEM INFORMATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# OS Version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    print_status "INFO" "OS: $NAME $VERSION"
    if [[ "$VERSION_ID" == "22.04" ]] || [[ "$VERSION_ID" == "24.04" ]]; then
        print_status "OK" "OS version is supported (Ubuntu $VERSION_ID LTS)"
    else
        print_status "WARN" "OS version $VERSION_ID may not be fully supported"
    fi
else
    print_status "FAIL" "Cannot detect OS version"
fi

# Hostname
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
print_status "INFO" "Hostname: $HOSTNAME"

# Uptime
UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "unknown")
print_status "INFO" "Uptime: $UPTIME"

echo ""

# ============================================
# 2. SYSTEM RESOURCES
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  💻 SYSTEM RESOURCES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Disk Space
DISK_SPACE_RAW=$(df -BG / 2>/dev/null | tail -1 | awk '{print $4}' | sed 's/G//' || echo "0")
DISK_SPACE=${DISK_SPACE_RAW:-0}
if [ "$DISK_SPACE" -ge 10 ] 2>/dev/null; then
    print_status "OK" "Disk space: ${DISK_SPACE}GB available (minimum 10GB)"
else
    print_status "WARN" "Disk space: ${DISK_SPACE}GB available (minimum 10GB recommended)"
fi

# RAM
RAM_TOTAL_RAW=$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "0")
RAM_TOTAL=${RAM_TOTAL_RAW:-0}
RAM_GB=$((RAM_TOTAL / 1024))
if [ "$RAM_TOTAL" -ge 2048 ] 2>/dev/null; then
    print_status "OK" "RAM: ${RAM_GB}GB total (minimum 2GB)"
else
    print_status "WARN" "RAM: ${RAM_GB}GB total (minimum 2GB recommended)"
fi

# CPU
CPU_CORES=$(nproc 2>/dev/null || echo "0")
if [ "$CPU_CORES" -ge 1 ] 2>/dev/null; then
    print_status "OK" "CPU: $CPU_CORES core(s)"
else
    print_status "WARN" "CPU: Could not detect CPU cores"
fi

echo ""

# ============================================
# 3. INSTALLED SOFTWARE
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📦 INSTALLED SOFTWARE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Go
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}')
    print_status "OK" "Go is installed: $GO_VERSION"
    if echo "$PATH" | grep -q "/usr/local/go/bin"; then
        print_status "OK" "Go is in PATH"
    else
        print_status "WARN" "Go may not be in PATH for all users"
    fi
else
    print_status "FAIL" "Go is not installed"
fi

# Node.js
if command_exists node; then
    NODE_VERSION=$(node --version)
    print_status "OK" "Node.js is installed: $NODE_VERSION"
    if command_exists npm; then
        NPM_VERSION=$(npm --version)
        print_status "OK" "npm is installed: $NPM_VERSION"
    else
        print_status "FAIL" "npm is not installed"
    fi
else
    print_status "FAIL" "Node.js is not installed"
fi

# PM2
if command_exists pm2; then
    PM2_VERSION=$(pm2 --version)
    print_status "OK" "PM2 is installed: $PM2_VERSION"
else
    print_status "WARN" "PM2 is not installed"
fi

# pnpm
if command_exists pnpm; then
    PNPM_VERSION=$(pnpm --version)
    print_status "OK" "pnpm is installed: $PNPM_VERSION"
else
    print_status "WARN" "pnpm is not installed"
fi

# Docker
if command_exists docker; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    print_status "OK" "Docker is installed: $DOCKER_VERSION"
    if systemctl is-active --quiet docker; then
        print_status "OK" "Docker daemon is running"
    else
        print_status "WARN" "Docker daemon is not running"
    fi
else
    print_status "FAIL" "Docker is not installed"
fi

# Nginx
if command_exists nginx; then
    NGINX_VERSION=$(nginx -v 2>&1 | awk -F'/' '{print $2}')
    print_status "OK" "Nginx is installed: $NGINX_VERSION"
    if nginx -t >/dev/null 2>&1; then
        print_status "OK" "Nginx configuration is valid"
    else
        print_status "FAIL" "Nginx configuration is invalid"
    fi
else
    print_status "FAIL" "Nginx is not installed"
fi

echo ""

# ============================================
# 4. SSH CONFIGURATION
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔐 SSH CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# SSH Service
check_service "ssh"

# SSH Port
SSH_PORT=$($SUDO_CMD grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
if [ -n "$SSH_PORT" ] && [ "$SSH_PORT" != "22" ]; then
    print_status "OK" "SSH is configured on non-standard port: $SSH_PORT"
    if ss -tuln 2>/dev/null | grep -q ":$SSH_PORT " || netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
        print_status "OK" "SSH is listening on port $SSH_PORT"
    else
        print_status "WARN" "SSH port $SSH_PORT is not listening"
    fi
else
    print_status "WARN" "SSH is using default port 22"
fi

# SSH Config Security
if $SUDO_CMD grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null || grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    print_status "OK" "Password authentication is disabled"
else
    print_status "WARN" "Password authentication may be enabled"
fi

if $SUDO_CMD grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null || grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    print_status "OK" "Public key authentication is enabled"
else
    print_status "WARN" "Public key authentication may be disabled"
fi

if $SUDO_CMD grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config 2>/dev/null || grep -q "^PermitRootLogin prohibit-password" /etc/ssh/sshd_config 2>/dev/null; then
    print_status "OK" "Root login is restricted to key-based only"
else
    print_status "WARN" "Root login may not be properly restricted"
fi

# SSH Config Test
if $SUDO_CMD sshd -t >/dev/null 2>&1 || sshd -t >/dev/null 2>&1; then
    print_status "OK" "SSH configuration syntax is valid"
else
    print_status "WARN" "SSH configuration syntax check failed (may need root access)"
fi

echo ""

# ============================================
# 5. FIREWALL
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🛡️  FIREWALL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command_exists ufw; then
    UFW_STATUS=$($SUDO_CMD ufw status 2>/dev/null | head -1 || ufw status 2>/dev/null | head -1 || echo "")
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        print_status "OK" "UFW firewall is active"
        UFW_RULES=$($SUDO_CMD ufw status numbered 2>/dev/null | grep -c "^\[" || ufw status numbered 2>/dev/null | grep -c "^\[" || echo "0")
        print_status "INFO" "UFW rules configured: $UFW_RULES"
    else
        print_status "WARN" "UFW firewall is not active"
    fi
else
    print_status "WARN" "UFW is not installed"
fi

echo ""

# ============================================
# 6. FAIL2BAN
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🚫 FAIL2BAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command_exists fail2ban-client; then
    if $SUDO_CMD systemctl is-active --quiet fail2ban 2>/dev/null || systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_status "OK" "Fail2ban service is active"
        if $SUDO_CMD fail2ban-client status >/dev/null 2>&1 || fail2ban-client status >/dev/null 2>&1; then
            JAILS=$($SUDO_CMD fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $4}' || fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $4}' || echo "0")
            print_status "INFO" "Fail2ban jails: $JAILS"
        fi
    else
        print_status "WARN" "Fail2ban service is not active"
    fi
else
    print_status "WARN" "Fail2ban is not installed"
fi

echo ""

# ============================================
# 7. SECURITY CONFIGURATIONS
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔒 SECURITY CONFIGURATIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Kernel Hardening
if [ -r /etc/sysctl.d/99-hardening.conf ] || $SUDO_CMD test -f /etc/sysctl.d/99-hardening.conf 2>/dev/null; then
    print_status "OK" "Kernel hardening configuration exists"
else
    print_status "WARN" "Kernel hardening configuration not found"
fi

# Automatic Updates
if $SUDO_CMD systemctl is-enabled --quiet unattended-upgrades 2>/dev/null || systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
    print_status "OK" "Automatic security updates are enabled"
else
    print_status "WARN" "Automatic security updates may not be enabled"
fi

# AppArmor
if command_exists aa-status; then
    if aa-status >/dev/null 2>&1; then
        print_status "OK" "AppArmor is enabled"
    else
        print_status "WARN" "AppArmor is not enabled"
    fi
else
    print_status "WARN" "AppArmor is not installed"
fi

# Time Synchronization
if $SUDO_CMD systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null || $SUDO_CMD systemctl is-active --quiet systemd-timesyncd 2>/dev/null || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    print_status "OK" "Time synchronization service is active"
else
    print_status "WARN" "Time synchronization service is not active"
fi

# Audit Logging
if $SUDO_CMD systemctl is-active --quiet auditd 2>/dev/null || systemctl is-active --quiet auditd 2>/dev/null; then
    print_status "OK" "Audit logging (auditd) is active"
else
    print_status "WARN" "Audit logging (auditd) is not active"
fi

# File Integrity Monitoring
if command_exists aide; then
    print_status "OK" "AIDE (file integrity monitoring) is installed"
    if [ -f /var/lib/aide/aide.db ]; then
        print_status "OK" "AIDE database exists"
    else
        print_status "WARN" "AIDE database not found (initialization may be needed)"
    fi
else
    print_status "WARN" "AIDE is not installed"
fi

# Malware Scanning
if command_exists clamscan; then
    print_status "OK" "ClamAV is installed"
else
    print_status "WARN" "ClamAV is not installed"
fi

if command_exists rkhunter; then
    print_status "OK" "rkhunter is installed"
else
    print_status "WARN" "rkhunter is not installed"
fi

echo ""

# ============================================
# 8. LOG FILES
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📝 LOG FILES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CRITICAL_LOGS=(
    "/var/log/auth.log"
    "/var/log/nginx/access.log"
    "/var/log/nginx/error.log"
    "/var/log/fail2ban.log"
    "/var/log/security-scan.log"
    "/var/log/aide-check.log"
)

for log in "${CRITICAL_LOGS[@]}"; do
    if [ -f "$log" ] || ([ -d "$(dirname "$log")" ] && [ -w "$(dirname "$log")" ]); then
        print_status "OK" "Log file/directory accessible: $log"
    else
        print_status "WARN" "Log file/directory not accessible: $log"
    fi
done

echo ""

# ============================================
# 9. CRON JOBS
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ⏰ CRON JOBS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if crontab -l >/dev/null 2>&1; then
    CRONTAB=$(crontab -l)
    CRITICAL_JOBS=("security-scan" "aide-daily-check" "clamav" "rkhunter")
    FOUND_JOBS=0
    
    for job in "${CRITICAL_JOBS[@]}"; do
        if echo "$CRONTAB" | grep -q "$job"; then
            ((FOUND_JOBS++))
        fi
    done
    
    if [ "$FOUND_JOBS" -gt 0 ]; then
        print_status "OK" "Found $FOUND_JOBS critical cron job(s)"
    else
        print_status "WARN" "No critical cron jobs found"
    fi
else
    print_status "WARN" "No crontab configured"
fi

echo ""

# ============================================
# 10. SYSTEMD SERVICES
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔧 SYSTEMD SERVICES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CRITICAL_SERVICES=(
    "ssh:SSH service"
    "nginx:Nginx web server"
    "docker:Docker daemon"
    "fail2ban:Fail2ban intrusion prevention"
    "ufw:UFW firewall"
    "chronyd:Chrony time sync"
    "systemd-resolved:Systemd DNS resolver"
)

for service_info in "${CRITICAL_SERVICES[@]}"; do
    IFS=':' read -r service_name service_desc <<< "$service_info"
    check_service "$service_name"
done

echo ""

# ============================================
# 11. NETWORK PORTS
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 NETWORK PORTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if SSH port is listening
if [ -n "$SSH_PORT" ]; then
    if ss -tuln 2>/dev/null | grep -q ":$SSH_PORT " || netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
        print_status "OK" "SSH is listening on port $SSH_PORT"
    else
        print_status "WARN" "SSH port $SSH_PORT is not listening"
    fi
fi

# Check HTTP/HTTPS ports
if ss -tuln 2>/dev/null | grep -q ":80 " || netstat -tuln 2>/dev/null | grep -q ":80 "; then
    print_status "INFO" "Port 80 (HTTP) is listening"
else
    print_status "WARN" "Port 80 (HTTP) is not listening"
fi

if ss -tuln 2>/dev/null | grep -q ":443 " || netstat -tuln 2>/dev/null | grep -q ":443 "; then
    print_status "INFO" "Port 443 (HTTPS) is listening"
else
    print_status "WARN" "Port 443 (HTTPS) is not listening"
fi

echo ""

# ============================================
# 12. DOCKER SECURITY
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🐳 DOCKER SECURITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -r /etc/docker/daemon.json ] || $SUDO_CMD test -f /etc/docker/daemon.json 2>/dev/null; then
    print_status "OK" "Docker daemon.json exists"
    if $SUDO_CMD grep -q "userns-remap" /etc/docker/daemon.json 2>/dev/null || grep -q "userns-remap" /etc/docker/daemon.json 2>/dev/null; then
        print_status "OK" "Docker user namespace remapping is configured"
    else
        print_status "WARN" "Docker user namespace remapping may not be configured"
    fi
else
    print_status "WARN" "Docker daemon.json not found or not accessible"
fi

# Check Docker socket permissions
if [ -e /var/run/docker.sock ] || $SUDO_CMD test -e /var/run/docker.sock 2>/dev/null; then
    SOCK_PERMS=$($SUDO_CMD stat -c "%a" /var/run/docker.sock 2>/dev/null || stat -c "%a" /var/run/docker.sock 2>/dev/null || echo "000")
    if [ "$SOCK_PERMS" = "660" ] || [ "$SOCK_PERMS" = "600" ]; then
        print_status "OK" "Docker socket permissions are secure: $SOCK_PERMS"
    else
        print_status "WARN" "Docker socket permissions may be too permissive: $SOCK_PERMS"
    fi
fi

echo ""

# ============================================
# 13. NGINX SECURITY
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🌐 NGINX SECURITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -r /etc/nginx/nginx.conf ] || $SUDO_CMD test -f /etc/nginx/nginx.conf 2>/dev/null; then
    print_status "OK" "Nginx configuration file exists"
    
    # Check for security headers
    if $SUDO_CMD grep -r "add_header.*X-Frame-Options" /etc/nginx/ 2>/dev/null | grep -q "DENY\|SAMEORIGIN" || grep -r "add_header.*X-Frame-Options" /etc/nginx/ 2>/dev/null | grep -q "DENY\|SAMEORIGIN"; then
        print_status "OK" "Nginx security headers are configured"
    else
        print_status "WARN" "Nginx security headers may not be configured"
    fi
else
    print_status "WARN" "Nginx configuration file not found or not accessible"
fi

echo ""

# ============================================
# SUMMARY
# ============================================
echo "============================================"
echo "  📊 VERIFICATION SUMMARY"
echo "============================================"
echo ""
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC} $FAILED"
echo ""

TOTAL=$((PASSED + WARNINGS + FAILED))
if [ "$FAILED" -eq 0 ]; then
    if [ "$WARNINGS" -eq 0 ]; then
        echo -e "${GREEN}✅ All checks passed! Server is properly configured.${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  Server is configured, but some warnings were found.${NC}"
        exit 0
    fi
else
    echo -e "${RED}❌ Some critical checks failed. Please review the output above.${NC}"
    exit 1
fi

