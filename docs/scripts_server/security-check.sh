#!/bin/bash

# Enhanced Security Audit Script with Antivirus & Email Notifications
# Version: 3.0

# ============================================
# EMAIL CONFIGURATION
# ============================================
GMAIL_SENDER_EMAIL="notification@web100now.com"
GMAIL_APP_PASSWORD="xymr gnxf grvv dqzv"
LOG_REPORT_RECIPIENT="maksym_tymoshenko@web100now.com"
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"

# ============================================
# REPORT CONFIGURATION
# ============================================
REPORT_DIR="/root/security-reports"
REPORT_FILE="$REPORT_DIR/security-audit-$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$REPORT_DIR"

# Check for Python3 (required for email sending)
if ! command -v python3 &> /dev/null; then
    echo "⚠ Warning: python3 not found. Email notifications may not work."
    echo "   Install with: apt install python3 -y"
    echo ""
fi

# ============================================
# CRON JOB SETUP FUNCTION
# ============================================
setup_cron_job() {
    # Get the absolute path to this script
    SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        # Cron job already exists, skip setup
        return 0
    fi
    
    # Create cron job entry (run every hour)
    CRON_ENTRY="0 * * * * $SCRIPT_PATH >> /var/log/security-check-cron.log 2>&1"
    
    # Add cron job
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab - 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "✓ Cron job configured: security check will run every hour"
        echo "  Logs: /var/log/security-check-cron.log"
        echo ""
    fi
}

# Setup cron job automatically (only if not already configured)
# Called before exec to avoid logging setup message to report
setup_cron_job

# Redirect all output to both console and file
exec > >(tee -a "$REPORT_FILE")
exec 2>&1

echo "============================================"
echo "   🛡️  ENHANCED SECURITY AUDIT"
echo "   $(date)"
echo "============================================"
echo ""

# ============================================
# AUTOMATIC MALWARE REMOVAL
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 AUTOMATIC MALWARE REMOVAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

REMOVED_SERVICES=0
REMOVED_PROCESSES=0
REMOVED_FILES=0
CRITICAL_ALERTS=()
EMAIL_SUBJECT=""
EMAIL_BODY=""

# ============================================
# EMAIL FUNCTION
# ============================================
send_email() {
    local subject="$1"
    local body="$2"
    local recipient="${3:-$LOG_REPORT_RECIPIENT}"
    
    # Try using Python for email sending (most reliable)
    if command -v python3 &> /dev/null; then
        python3 << EOF
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sender = "$GMAIL_SENDER_EMAIL"
password = "$GMAIL_APP_PASSWORD"
recipient = "$recipient"
subject = "$subject"
body = """$body"""

msg = MIMEMultipart()
msg['From'] = sender
msg['To'] = recipient
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain', 'utf-8'))

try:
    server = smtplib.SMTP('$SMTP_SERVER', $SMTP_PORT)
    server.starttls()
    server.login(sender, password)
    server.sendmail(sender, recipient, msg.as_string())
    server.quit()
    print("Email sent successfully")
except Exception as e:
    print(f"Email sending failed: {e}")
EOF
    elif command -v mailx &> /dev/null; then
        # Fallback: use mailx
        echo "$body" | mailx -s "$subject" -r "$GMAIL_SENDER_EMAIL" "$recipient" 2>/dev/null
    else
        echo "⚠ Email sending failed - no mail client available (install python3 or mailx)"
    fi
}

# Function for immediate email alert (for critical real-time events)
send_immediate_alert() {
    local alert_type="$1"
    local alert_details="$2"
    
    local subject="🚨 IMMEDIATE ALERT: $alert_type - $(hostname) - $(date +%H:%M:%S)"
    local body="IMMEDIATE SECURITY ALERT
Server: $(hostname)
IP: $(hostname -I | awk '{print $1}')
Time: $(date)

Alert Type: $alert_type
Details: $alert_details

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action Required: Review server immediately!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"
    
    send_email "$subject" "$body" "$LOG_REPORT_RECIPIENT"
}

# Function to remove malicious systemd services
remove_malicious_services() {
    echo "Checking for malicious systemd services..."
    
    # List of suspicious service patterns
    SUSPICIOUS_SERVICES=$(systemctl list-units --all --type=service | \
        grep -iE "bot\.service|kinsing|system-daemon|system-sysinit|system-syslog|miner" | \
        awk '{print $1}' | grep -E "\.service$")
    
    if [ -n "$SUSPICIOUS_SERVICES" ]; then
        echo "🚨 Found malicious services:"
        echo "$SUSPICIOUS_SERVICES"
        echo ""
        
        for service in $SUSPICIOUS_SERVICES; do
            echo "  → Removing $service..."
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
            rm -f "/etc/systemd/system/$service"
            rm -f "/lib/systemd/system/$service"
            rm -f "/usr/lib/systemd/system/$service"
            ((REMOVED_SERVICES++))
        done
        
        systemctl daemon-reload
        systemctl reset-failed
        echo "✓ Removed $REMOVED_SERVICES malicious service(s)"
    else
        echo "✓ No malicious services found"
    fi
    echo ""
}

# Function to kill malicious processes
kill_malicious_processes() {
    echo "Checking for malicious processes..."
    
    # Find suspicious processes - comprehensive malware list (excluding PM2 managed processes)
    ALL_SUSP_PROCS=$(ps aux | grep -iE "xmrig|miner|kinsing|systemhelper|linuxsys|wsystemd|Gqr7dweg|1z1Mv3GA|B7mQL|lrt|bot|kdevtmpfsi|watchbog|ddgs|qW3xT|2t3ik|kinsingd|libsystem|libapache|libnetwork|libselinux|libnss|libssl|libcrypto|/tmp/go-build.*server|/tmp/.*/exe/server" | \
        grep -v grep)
    
    MALICIOUS_PROCS=""
    
    # Filter out PM2 managed processes
    if [ -n "$ALL_SUSP_PROCS" ]; then
        while IFS= read -r line; do
            PID=$(echo "$line" | awk '{print $2}')
            # Check if this process is managed by PM2
            PPID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
            IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
            
            # Check if parent or grandparent is PM2
            if [ -z "$IS_PM2" ] && [ -n "$PPID" ]; then
                GPPID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
                IS_PM2=$(ps aux | awk -v gppid="$GPPID" '$2 == gppid && /pm2|PM2/ {print $2}' | head -1)
            fi
            
            # Only add to malicious list if NOT from PM2
            if [ -z "$IS_PM2" ]; then
                if [ -z "$MALICIOUS_PROCS" ]; then
                    MALICIOUS_PROCS="$PID"
                else
                    MALICIOUS_PROCS="$MALICIOUS_PROCS $PID"
                fi
            else
                echo "  ✓ Process $PID is managed by PM2 (legitimate) - skipping"
            fi
        done <<< "$ALL_SUSP_PROCS"
    fi
    
    if [ -n "$MALICIOUS_PROCS" ]; then
        echo "🚨 Found malicious processes (not from PM2):"
        for pid in $MALICIOUS_PROCS; do
            ps aux | awk -v pid="$pid" '$2 == pid'
        done
        echo ""
        
        for pid in $MALICIOUS_PROCS; do
            echo "  → Killing process $pid..."
            kill -9 "$pid" 2>/dev/null
            ((REMOVED_PROCESSES++))
        done
        
        echo "✓ Killed $REMOVED_PROCESSES malicious process(es)"
    else
        echo "✓ No malicious processes found"
    fi
    echo ""
}

# Function to remove malicious files and directories
remove_malicious_files() {
    echo "Checking for malicious files and directories..."
    
    # Remove suspicious files
    MALICIOUS_PATHS=(
        "/etc/data/kinsing"
        "/etc/data"
        "/usr/local/bin/systemhelper"
        "/usr/sbin/wsystemd"
        "/dev/*.sh"
        "/dev/x86"
        "/dev/x64"
        "/tmp/*xmrig*"
        "/tmp/*miner*"
        "/var/tmp/*xmrig*"
        "/var/tmp/*miner*"
        "/dev/shm/*xmrig*"
        "/dev/shm/*miner*"
    )
    
    for path in "${MALICIOUS_PATHS[@]}"; do
        if [ -e "$path" ] 2>/dev/null || [ -d "$path" ] 2>/dev/null; then
            echo "  → Removing $path..."
            rm -rf "$path" 2>/dev/null
            ((REMOVED_FILES++))
        fi
    done
    
    # Check for bot.service file specifically
    if [ -f "/etc/systemd/system/bot.service" ]; then
        echo "  → Removing /etc/systemd/system/bot.service..."
        rm -f "/etc/systemd/system/bot.service"
        ((REMOVED_FILES++))
    fi
    
    # Find and remove any executable files with suspicious names
    find /tmp /var/tmp /dev/shm -type f -executable \( \
        -name "*xmrig*" -o -name "*miner*" -o -name "*kinsing*" \
        -o -name "*Gqr7dweg*" -o -name "*1z1Mv3GA*" -o -name "*B7mQL*" \) 2>/dev/null | \
        while read -r file; do
            echo "  → Removing suspicious file: $file"
            rm -f "$file" 2>/dev/null
            ((REMOVED_FILES++))
        done
    
    # Check for suspicious Go servers in /tmp (excluding PM2 managed)
    ps aux | grep -E "/tmp/go-build.*server|/tmp/.*/exe/server" | grep -v grep | while read -r line; do
        pid=$(echo "$line" | awk '{print $2}')
        # Check if this process is managed by PM2
        PPID=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
        
        if [ -z "$IS_PM2" ] && [ -n "$PPID" ]; then
            GPPID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
            IS_PM2=$(ps aux | awk -v gppid="$GPPID" '$2 == gppid && /pm2|PM2/ {print $2}' | head -1)
        fi
        
        if [ -z "$IS_PM2" ]; then
            echo "  → Found suspicious Go server process (NOT from PM2): PID $pid"
            kill -9 "$pid" 2>/dev/null
            ((REMOVED_PROCESSES++))
        else
            echo "  ✓ Go server PID $pid is managed by PM2 (legitimate) - skipping"
        fi
    done
    
    # Remove suspicious Go build directories (only if no PM2 processes are using them)
    find /tmp -type d -name "go-build*" 2>/dev/null | while read -r dir; do
        # Check if any process in this directory is managed by PM2
        DIR_IN_USE_BY_PM2=0
        ps aux | grep -E "/tmp/go-build.*server" | grep -v grep | while read -r proc_line; do
            if echo "$proc_line" | grep -q "$dir"; then
                PROC_PID=$(echo "$proc_line" | awk '{print $2}')
                PPID=$(ps -o ppid= -p "$PROC_PID" 2>/dev/null | tr -d ' ')
                IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
                if [ -n "$IS_PM2" ]; then
                    DIR_IN_USE_BY_PM2=1
                fi
            fi
        done
        
        if [ $DIR_IN_USE_BY_PM2 -eq 0 ]; then
            echo "  → Removing suspicious Go build directory: $dir"
            rm -rf "$dir" 2>/dev/null
            ((REMOVED_FILES++))
        fi
    done
    
    if [ $REMOVED_FILES -gt 0 ]; then
        echo "✓ Removed $REMOVED_FILES malicious file(s)/directory(ies)"
    else
        echo "✓ No malicious files found"
    fi
    echo ""
}

# Function to check and block suspicious ports
check_suspicious_ports() {
    echo "Checking for suspicious open ports..."
    
    # Check for suspicious ports
    ALL_SUSP_PORTS=$(ss -tulpn | grep "0.0.0.0" | grep -oE ":(2110[0-9]|2111[0-9]|8082|4444|5555|7777|3333)" | sed 's/://' | sort -u)
    
    if [ -n "$ALL_SUSP_PORTS" ]; then
        echo "Found potentially suspicious ports: $ALL_SUSP_PORTS"
        PORT_DETAILS=""
        PORTS_TO_BLOCK=""
        
        for port in $ALL_SUSP_PORTS; do
            # Check if port is from Docker container
            PORT_INFO=$(ss -tulpn | grep ":$port " | head -1)
            DOCKER_CONTAINER=""
            
            # Check if port is exposed by Docker container
            if command -v docker &> /dev/null; then
                DOCKER_CONTAINER=$(docker ps --format "{{.Names}}\t{{.Ports}}" | grep ":$port" | awk '{print $1}' | head -1)
            fi
            
            if [ -n "$DOCKER_CONTAINER" ]; then
                echo "  ⚠ Port $port is from Docker container: $DOCKER_CONTAINER"
                echo "    (This is likely a legitimate service, not blocking)"
                # Don't block ports from Docker containers, but note them
                if [ "$port" = "8082" ]; then
                    # Port 8082 might be legitimate (Go backend)
                    echo "    ℹ️  Port 8082 is likely your Go backend server"
                fi
            else
                # Port is not from Docker - check if it's from dockerd itself
                if echo "$PORT_INFO" | grep -q "dockerd"; then
                    echo "  ⚠ Port $port is from dockerd (Docker daemon)"
                    echo "    (Review Docker configuration - this might be Docker API)"
                else
                    echo "  🚨 Port $port is suspicious (not from Docker container)"
                    echo "  → Blocking port $port with UFW..."
                    ufw deny "$port/tcp" 2>/dev/null
                    ufw deny "$port/udp" 2>/dev/null
                    CRITICAL_ALERTS+=("Suspicious port $port is open and exposed to internet")
                    PORTS_TO_BLOCK="$PORTS_TO_BLOCK $port"
                    
                    # Check for active connections
                    ACTIVE_CONN=$(ss -tunap | grep ":$port " | grep ESTABLISHED)
                    if [ -n "$ACTIVE_CONN" ]; then
                        echo "    ⚠ Active connections to port $port:"
                        echo "$ACTIVE_CONN" | sed 's/^/      /'
                        PORT_DETAILS+="Port $port has active connections:\n$ACTIVE_CONN\n\n"
                        send_immediate_alert "Active Connection to Suspicious Port" "Port $port - $ACTIVE_CONN"
                    fi
                fi
            fi
        done
        
        if [ -n "$PORT_DETAILS" ]; then
            send_immediate_alert "Suspicious Ports Open with Active Connections" "$PORT_DETAILS"
        fi
        
        if [ -n "$PORTS_TO_BLOCK" ]; then
            ufw reload 2>/dev/null
            echo "✓ Blocked suspicious ports:$PORTS_TO_BLOCK"
        else
            echo "✓ No suspicious ports to block (all are from Docker containers)"
        fi
    else
        echo "✓ No suspicious ports found"
    fi
    echo ""
}

# Execute removal functions
remove_malicious_services
kill_malicious_processes
remove_malicious_files
check_suspicious_ports

if [ $REMOVED_SERVICES -gt 0 ] || [ $REMOVED_PROCESSES -gt 0 ] || [ $REMOVED_FILES -gt 0 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ CLEANUP SUMMARY:"
    echo "   Services removed: $REMOVED_SERVICES"
    echo "   Processes killed: $REMOVED_PROCESSES"
    echo "   Files removed: $REMOVED_FILES"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "⚠️  System cleanup completed. Continuing with security audit..."
    echo ""
fi

# 1. SSH Security
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. SSH CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Port: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')"
echo "PermitRootLogin: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')"
echo "PasswordAuthentication: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')"
echo "PubkeyAuthentication: $(grep "^PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}')"
echo ""

# 2. Firewall
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. FIREWALL STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ufw status numbered
echo ""

# 3. Open Ports
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. OPEN PORTS (exposed to internet)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking for 0.0.0.0 bindings:"
ss -tunlp | grep "0.0.0.0" | grep -v "127.0.0"
echo ""

echo "Checking for suspicious ports (Docker API, unknown services):"
ALL_SUSP_PORTS=$(ss -tulpn | grep "0.0.0.0" | grep -oE ":(2110[0-9]|2111[0-9]|8082|4444|5555|7777|3333)" | sed 's/://' | sort -u)
if [ -n "$ALL_SUSP_PORTS" ]; then
    REAL_SUSP_PORTS=""
    DOCKER_PORTS=""
    
    for port in $ALL_SUSP_PORTS; do
        # Check if port is from Docker container
        if command -v docker &> /dev/null; then
            DOCKER_CONTAINER=$(docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null | grep ":$port" | awk '{print $1}' | head -1)
        fi
        
        if [ -n "$DOCKER_CONTAINER" ]; then
            if [ -z "$DOCKER_PORTS" ]; then
                DOCKER_PORTS="$port (from $DOCKER_CONTAINER)"
            else
                DOCKER_PORTS="$DOCKER_PORTS, $port (from $DOCKER_CONTAINER)"
            fi
            echo "  ⚠ Port $port: from Docker container '$DOCKER_CONTAINER' (legitimate service)"
        else
            if [ -z "$REAL_SUSP_PORTS" ]; then
                REAL_SUSP_PORTS="$port"
            else
                REAL_SUSP_PORTS="$REAL_SUSP_PORTS $port"
            fi
            echo "  🚨 Port $port: $(ss -tulpn | grep ":$port " | head -1)"
        fi
    done
    
    if [ -n "$DOCKER_PORTS" ]; then
        echo "  ℹ️  Docker container ports (not blocking): $DOCKER_PORTS"
    fi
    
    if [ -n "$REAL_SUSP_PORTS" ]; then
        echo "🚨 Real suspicious ports (not from Docker): $REAL_SUSP_PORTS"
        CRITICAL_ALERTS+=("Suspicious ports open (not from Docker): $REAL_SUSP_PORTS")
    else
        echo "✓ All suspicious-looking ports are from Docker containers (legitimate)"
    fi
else
    echo "✓ No suspicious ports found"
fi
echo ""

# 4. Malware Scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. COMPREHENSIVE MALWARE SCAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking for malware processes:"
ALL_MALWARE_PROCS=$(ps aux | grep -iE "xmrig|miner|kinsing|systemhelper|linuxsys|wsystemd|Gqr7dweg|1z1Mv3GA|B7mQL|lrt|bot|kdevtmpfsi|watchbog|ddgs|qW3xT|2t3ik|kinsingd|libsystem|libapache|libnetwork|libselinux|libnss|libssl|libcrypto|/tmp/go-build.*server|/tmp/.*/exe/server" | grep -v grep)
REAL_MALWARE_PROCS=""

if [ -n "$ALL_MALWARE_PROCS" ]; then
    while IFS= read -r line; do
        PID=$(echo "$line" | awk '{print $2}')
        # Check if this is a Go server from PM2
        if echo "$line" | grep -qE "/tmp/go-build.*server|/tmp/.*/exe/server"; then
            PPID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
            IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
            if [ -z "$IS_PM2" ] && [ -n "$PPID" ]; then
                GPPID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
                IS_PM2=$(ps aux | awk -v gppid="$GPPID" '$2 == gppid && /pm2|PM2/ {print $2}' | head -1)
            fi
            if [ -n "$IS_PM2" ]; then
                # Skip PM2 managed Go servers
                continue
            fi
        fi
        
        # Add to real malware list
        if [ -z "$REAL_MALWARE_PROCS" ]; then
            REAL_MALWARE_PROCS="$line"
        else
            REAL_MALWARE_PROCS="$REAL_MALWARE_PROCS\n$line"
        fi
    done <<< "$ALL_MALWARE_PROCS"
    
    if [ -n "$REAL_MALWARE_PROCS" ]; then
        echo "🚨 Malware processes found:"
        echo -e "$REAL_MALWARE_PROCS"
        CRITICAL_ALERTS+=("Malware processes detected")
    else
        echo "✓ No malware processes found (Go servers are from PM2 - legitimate)"
    fi
else
    echo "✓ No malware processes found"
fi
echo ""

echo "Checking malicious files:"
[ -f /etc/ld.so.preload ] && echo "⚠ ROOTKIT: ld.so.preload found!" && CRITICAL_ALERTS+=("ROOTKIT: ld.so.preload found") || echo "✓ No ld.so.preload (good)"
ls -la /dev/*.sh /dev/x86 /dev/x64 2>/dev/null && echo "⚠ Suspicious files in /dev!" && CRITICAL_ALERTS+=("Suspicious files in /dev") || echo "✓ No suspicious files in /dev"
ls -la /usr/local/bin/systemhelper /usr/sbin/wsystemd 2>/dev/null && echo "⚠ Malware binaries found!" && CRITICAL_ALERTS+=("Malware binaries found") || echo "✓ No systemhelper/wsystemd"
ls -la /etc/data/kinsing 2>/dev/null && echo "⚠ Kinsing malware found!" && CRITICAL_ALERTS+=("Kinsing malware found") || echo "✓ No kinsing"
echo ""

echo "Checking for hidden miners and suspicious executables:"
ALL_SUSP_FILES=$(find /tmp /var/tmp /dev/shm -name "*xmrig*" -o -name "*miner*" -o -name "*docker-daemon*" -o -name "*go-build*" -o -name "*server" -type f -executable 2>/dev/null)
REAL_SUSP_FILES=""

if [ -n "$ALL_SUSP_FILES" ]; then
    while IFS= read -r file; do
        # Check if this file is used by PM2 process
        IS_PM2_FILE=0
        if echo "$file" | grep -qE "go-build.*server|/exe/server"; then
            # Check if any process using this file is from PM2
            ps aux | grep -E "$file" | grep -v grep | while read -r proc_line; do
                PROC_PID=$(echo "$proc_line" | awk '{print $2}')
                PPID=$(ps -o ppid= -p "$PROC_PID" 2>/dev/null | tr -d ' ')
                IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
                if [ -n "$IS_PM2" ]; then
                    IS_PM2_FILE=1
                fi
            done
        fi
        
        # Only add if not from PM2 and not a known legitimate pattern
        if [ $IS_PM2_FILE -eq 0 ] && ! echo "$file" | grep -qE "node_modules|\.next|pm2"; then
            if [ -z "$REAL_SUSP_FILES" ]; then
                REAL_SUSP_FILES="$file"
            else
                REAL_SUSP_FILES="$REAL_SUSP_FILES\n$file"
            fi
        fi
    done <<< "$ALL_SUSP_FILES"
    
    if [ -n "$REAL_SUSP_FILES" ]; then
        echo "⚠ Potential malware found:"
        echo -e "$REAL_SUSP_FILES" | head -10
        CRITICAL_ALERTS+=("Suspicious executables in temp directories")
    else
        echo "✓ No miners or suspicious files in temp directories (Go servers are from PM2 - legitimate)"
    fi
else
    echo "✓ No miners or suspicious files in temp directories"
fi
echo ""

echo "Checking for suspicious Go servers:"
GO_SERVERS=$(ps aux | grep -E "/tmp/go-build.*server|/tmp/.*/exe/server" | grep -v grep)
if [ -n "$GO_SERVERS" ]; then
    SUSP_GO_SERVERS=""
    LEGIT_GO_SERVERS=""
    
    while IFS= read -r line; do
        PID=$(echo "$line" | awk '{print $2}')
        # Check if this process is managed by PM2
        PPID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
        IS_PM2=$(ps aux | awk -v ppid="$PPID" '$2 == ppid && /pm2|PM2/ {print $2}' | head -1)
        
        if [ -z "$IS_PM2" ] && [ -n "$PPID" ]; then
            GPPID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
            IS_PM2=$(ps aux | awk -v gppid="$GPPID" '$2 == gppid && /pm2|PM2/ {print $2}' | head -1)
        fi
        
        if [ -n "$IS_PM2" ]; then
            if [ -z "$LEGIT_GO_SERVERS" ]; then
                LEGIT_GO_SERVERS="$line"
            else
                LEGIT_GO_SERVERS="$LEGIT_GO_SERVERS\n$line"
            fi
        else
            if [ -z "$SUSP_GO_SERVERS" ]; then
                SUSP_GO_SERVERS="$line"
            else
                SUSP_GO_SERVERS="$SUSP_GO_SERVERS\n$line"
            fi
        fi
    done <<< "$GO_SERVERS"
    
    if [ -n "$LEGIT_GO_SERVERS" ]; then
        echo "✓ Go servers managed by PM2 (legitimate):"
        echo -e "$LEGIT_GO_SERVERS" | sed 's/^/  /'
    fi
    
    if [ -n "$SUSP_GO_SERVERS" ]; then
        echo "🚨 Suspicious Go servers found (NOT from PM2):"
        echo -e "$SUSP_GO_SERVERS" | sed 's/^/  /'
        CRITICAL_ALERTS+=("Suspicious Go server processes detected (not from PM2)")
    fi
    
    if [ -z "$SUSP_GO_SERVERS" ] && [ -z "$LEGIT_GO_SERVERS" ]; then
        echo "✓ No Go servers found"
    fi
else
    echo "✓ No suspicious Go servers found"
fi
echo ""

# 5. Cron Jobs
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. CRON JOBS CHECK"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Root crontab:"
crontab -l 2>/dev/null || echo "✓ No root crontab"
echo ""
echo "System cron.d files:"
ls -la /etc/cron.d/ | grep -v "e2scrub\|sysstat\|popularity\|placeholder" || echo "✓ Only system cron files"
echo ""

# 6. Suspicious Services
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. SYSTEMD SERVICES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking suspicious services:"
SUSP_SERVICES=$(systemctl list-units --all --type=service | \
  grep -iE "bot|system-daemon|system-sysinit|system-syslog|kinsing" | \
  awk '{print $1}')
if [ -n "$SUSP_SERVICES" ]; then
    echo "🚨 Suspicious services found:"
    echo "$SUSP_SERVICES"
    echo ""
    echo "Checking service files:"
    for svc in $SUSP_SERVICES; do
        svc_name=$(echo "$svc" | sed 's/\.service$//')
        if [ -f "/etc/systemd/system/$svc_name.service" ]; then
            echo "  → /etc/systemd/system/$svc_name.service exists"
            echo "    Content preview:"
            head -5 "/etc/systemd/system/$svc_name.service" 2>/dev/null | sed 's/^/      /'
        fi
    done
else
    echo "✓ No suspicious services found"
fi
echo ""

# 7. Docker Security
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. DOCKER SECURITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Containers with exposed ports:"
docker ps --format "table {{.Names}}\t{{.Ports}}" | grep "0.0.0.0" | grep -v "127.0.0.1" || echo "✓ No containers exposed to internet"
echo ""

# 8. System Load
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. SYSTEM LOAD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
uptime
echo ""

# 9. Failed Login Attempts
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "9. FAILED LOGIN ATTEMPTS (last 10)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || echo "✓ No failed attempts"
echo ""

# 10. Blocked IPs (Fail2ban)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "10. FAIL2BAN STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fail2ban-client status sshd 2>/dev/null || echo "⚠ Fail2ban not configured yet"
echo ""

# 10.5. Suspicious Log Activity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "10.5. SUSPICIOUS LOG ACTIVITY (Last Hour)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for suspicious SSH activity in last hour
SINCE_TIME=$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-1H '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")

# Check auth.log for suspicious patterns
if [ -f /var/log/auth.log ]; then
    echo "Checking auth.log for suspicious activity..."
    
    # Multiple failed login attempts from same IP
    FAILED_ATTEMPTS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 | awk '{print $11}' | sort | uniq -c | sort -rn | head -5)
    if [ -n "$FAILED_ATTEMPTS" ]; then
        HIGH_FAIL_COUNT=$(echo "$FAILED_ATTEMPTS" | awk '$1 > 10 {print}')
        if [ -n "$HIGH_FAIL_COUNT" ]; then
            echo "🚨 High number of failed login attempts detected:"
            echo "$HIGH_FAIL_COUNT"
            send_immediate_alert "High Failed Login Attempts" "$HIGH_FAIL_COUNT"
            CRITICAL_ALERTS+=("High number of failed login attempts detected")
        fi
    fi
    
    # Successful logins from unknown IPs
    RECENT_LOGINS=$(grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20 | grep -v "$(hostname -I | awk '{print $1}')")
    if [ -n "$RECENT_LOGINS" ]; then
        UNKNOWN_IP_LOGINS=$(echo "$RECENT_LOGINS" | awk '{print $11}' | grep -vE "127.0.0.1|::1|localhost" | sort -u)
        if [ -n "$UNKNOWN_IP_LOGINS" ]; then
            echo "⚠ Recent logins from IPs:"
            echo "$UNKNOWN_IP_LOGINS"
            # Send alert only if IP is truly unknown (not in known_hosts, not seen before in auth.log)
            for ip in $UNKNOWN_IP_LOGINS; do
                # Перевірка чи IP вже був у логах раніше (більше ніж 24 години тому)
                PREVIOUS_LOGINS=$(grep "Accepted.*$ip" /var/log/auth.log 2>/dev/null | head -1)
                if [ -z "$PREVIOUS_LOGINS" ] && ! grep -q "$ip" /root/.ssh/known_hosts 2>/dev/null && ! grep -q "$ip" ~/.ssh/known_hosts 2>/dev/null; then
                    # Це справді новий IP - відправити alert
                    LOGIN_DETAILS=$(echo "$RECENT_LOGINS" | grep "$ip" | tail -1)
                    send_immediate_alert "Login from Unknown IP" "IP: $ip - $LOGIN_DETAILS"
                    CRITICAL_ALERTS+=("Login from unknown IP: $ip")
                    echo "  🚨 Alert sent for new IP: $ip"
                else
                    echo "  ✓ IP $ip is known (seen before or in known_hosts)"
                fi
            done
        fi
    fi
    
    # Check for privilege escalation attempts
    PRIV_ESC=$(grep -iE "sudo|su|su -" /var/log/auth.log 2>/dev/null | tail -20 | grep -iE "failed|denied")
    if [ -n "$PRIV_ESC" ]; then
        echo "⚠ Privilege escalation attempts detected:"
        echo "$PRIV_ESC" | head -5
        CRITICAL_ALERTS+=("Privilege escalation attempts detected")
    fi
fi

# Check syslog for suspicious activity
if [ -f /var/log/syslog ]; then
    echo ""
    echo "Checking syslog for suspicious activity..."
    
    # Check for kernel module loading (potential rootkit)
    KERNEL_MODULES=$(grep -i "module" /var/log/syslog 2>/dev/null | tail -20 | grep -iE "load|insert|remove")
    if [ -n "$KERNEL_MODULES" ]; then
        echo "⚠ Kernel module activity detected:"
        echo "$KERNEL_MODULES" | head -5
        CRITICAL_ALERTS+=("Suspicious kernel module activity")
    fi
    
    # Check for file system mount/unmount
    FS_MOUNTS=$(grep -iE "mount|umount" /var/log/syslog 2>/dev/null | tail -20 | grep -vE "systemd|udev")
    if [ -n "$FS_MOUNTS" ]; then
        echo "⚠ File system mount activity:"
        echo "$FS_MOUNTS" | head -5
    fi
fi

# Check journalctl for system errors
echo ""
echo "Checking systemd journal for errors (last hour)..."
JOURNAL_ERRORS=$(journalctl --since "1 hour ago" --priority=err 2>/dev/null | grep -vE "systemd|NetworkManager|dbus" | head -10)
if [ -n "$JOURNAL_ERRORS" ]; then
    ERROR_COUNT=$(echo "$JOURNAL_ERRORS" | wc -l)
    if [ $ERROR_COUNT -gt 5 ]; then
        echo "⚠ Multiple system errors detected:"
        echo "$JOURNAL_ERRORS" | head -5
        CRITICAL_ALERTS+=("Multiple system errors in last hour")
    fi
fi

# Check for suspicious cron executions
echo ""
echo "Checking for suspicious cron executions..."
# Фільтруємо стандартні системні cron jobs
SUSP_CRON=$(grep CRON /var/log/syslog 2>/dev/null | tail -50 | \
    grep -vE "systemd|anacron|apt|run-parts|debian-sa1|sysstat|logrotate|man-db|popularity-contest|e2scrub|dpkg|chkrootkit|rkhunter|clamav|freshclam|updatedb|locate" | \
    grep -iE "root|www-data|nobody" | \
    grep -vE "CMD.*cd /" | \
    grep -vE "CMD.*test -x")
if [ -n "$SUSP_CRON" ]; then
    echo "⚠ Suspicious cron executions:"
    echo "$SUSP_CRON" | head -5
    send_immediate_alert "Suspicious Cron Execution" "$SUSP_CRON"
    CRITICAL_ALERTS+=("Suspicious cron executions detected")
else
    echo "✓ No suspicious cron executions found"
fi

echo "✓ Log check completed"
echo ""

# 11. Updates Available
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "11. SYSTEM UPDATES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
apt list --upgradable 2>/dev/null | grep -v "Listing" || echo "✓ System up to date"
echo ""

# 12. Disk Space
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "12. DISK USAGE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
df -h | grep -E "Filesystem|/$|/var"
echo ""

# 13. ClamAV Antivirus Scan
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "13. ANTIVIRUS SCAN (ClamAV)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v clamscan &> /dev/null; then
    # Check when last scan was performed (scan only once every 2 days)
    CLAMAV_LAST_SCAN_FILE="$REPORT_DIR/.clamav_last_scan"
    SHOULD_SCAN=0
    
    if [ -f "$CLAMAV_LAST_SCAN_FILE" ]; then
        LAST_SCAN_DATE=$(cat "$CLAMAV_LAST_SCAN_FILE" 2>/dev/null)
        LAST_SCAN_TIMESTAMP=$(date -d "$LAST_SCAN_DATE" +%s 2>/dev/null || echo "0")
        CURRENT_TIMESTAMP=$(date +%s)
        DAYS_DIFF=$(( (CURRENT_TIMESTAMP - LAST_SCAN_TIMESTAMP) / 86400 ))
        
        if [ $DAYS_DIFF -ge 2 ]; then
            SHOULD_SCAN=1
            echo "Last ClamAV scan: $LAST_SCAN_DATE ($DAYS_DIFF days ago)"
            echo "Running ClamAV scan (runs once every 2 days)..."
        else
            REMAINING_DAYS=$((2 - DAYS_DIFF))
            echo "Last ClamAV scan: $LAST_SCAN_DATE ($DAYS_DIFF days ago)"
            echo "⏭️  Skipping ClamAV scan (will run in $REMAINING_DAYS day(s))"
            echo "   (ClamAV scan runs once every 2 days to save resources)"
        fi
    else
        SHOULD_SCAN=1
        echo "No previous ClamAV scan found. Running first scan..."
    fi
    
    if [ $SHOULD_SCAN -eq 1 ]; then
        echo "Scanning critical directories..."
        echo "This may take 5-10 minutes..."
        echo ""
        
        # Quick scan of critical directories
        clamscan -r -i \
          /tmp \
          /var/tmp \
          /dev/shm \
          /usr/local/bin \
          /usr/sbin \
          /etc/cron.d \
          /etc/init.d \
          /root 2>/dev/null | tail -10
        
        INFECTED=$(clamscan -r -i /tmp /var/tmp /dev/shm /usr/local/bin /usr/sbin 2>/dev/null | grep "Infected files:" | awk '{print $3}')
        
        if [ "$INFECTED" -gt 0 ] 2>/dev/null; then
            echo "🚨 INFECTED FILES FOUND: $INFECTED"
            CRITICAL_ALERTS+=("ClamAV found $INFECTED infected file(s)")
        else
            echo "✓ No infected files found"
        fi
        
        # Save scan date
        date +"%Y-%m-%d %H:%M:%S" > "$CLAMAV_LAST_SCAN_FILE"
        echo "✓ Scan completed. Next scan will run in 2 days."
    fi
else
    echo "⚠ ClamAV not installed"
    echo "   Install with: apt install clamav -y && freshclam"
fi
echo ""

# 14. Rootkit Hunter
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "14. ROOTKIT SCAN (rkhunter)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v rkhunter &> /dev/null; then
    echo "Running rootkit scan..."
    rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | tail -20
    
    if rkhunter --check --skip-keypress --report-warnings-only 2>&1 | grep -q "Warning"; then
        echo "⚠ Warnings found - review /var/log/rkhunter.log"
    else
        echo "✓ No rootkits detected"
    fi
else
    echo "⚠ rkhunter not installed"
    echo "   Install with: apt install rkhunter -y && rkhunter --update"
fi
echo ""

# 15. chkrootkit
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "15. ROOTKIT CHECK (chkrootkit)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v chkrootkit &> /dev/null; then
    echo "Checking for rootkits..."
    chkrootkit 2>/dev/null | grep -E "INFECTED|Checking" | tail -20
    
    if chkrootkit 2>&1 | grep -qiE "INFECTED.*Xor|Xor.*DDoS"; then
        # Перевірити чи це не false positive
        REAL_XOR_THREAT=$(ps aux | grep -iE "xor.*ddos|\.xord|\.xorddos" | grep -v grep)
        REAL_XOR_FILES=$(find /etc/init.d /usr/bin /usr/sbin /tmp /var/tmp -name "*xor*ddos*" -o -name "\.xord*" 2>/dev/null)
        
        if [ -z "$REAL_XOR_THREAT" ] && [ -z "$REAL_XOR_FILES" ]; then
            echo "⚠ chkrootkit false positive detected (legitimate xor files in libraries)"
            echo "✓ No actual Linux.Xor.DDoS threat found"
        else
            echo "🚨 CRITICAL: Linux.Xor.DDoS detected!"
            send_immediate_alert "Linux.Xor.DDoS Detected" "Real threat found: $REAL_XOR_THREAT $REAL_XOR_FILES"
            CRITICAL_ALERTS+=("Linux.Xor.DDoS botnet detected")
        fi
    elif chkrootkit 2>&1 | grep -q "INFECTED"; then
        echo "🚨 INFECTIONS FOUND!"
        INFECTED_DETAILS=$(chkrootkit 2>&1 | grep "INFECTED")
        send_immediate_alert "Rootkit Detected by chkrootkit" "$INFECTED_DETAILS"
        CRITICAL_ALERTS+=("Rootkit detected by chkrootkit")
    else
        echo "✓ No rootkits found by chkrootkit"
    fi
else
    echo "⚠ chkrootkit not installed"
    echo "   Install with: apt install chkrootkit -y"
fi
echo ""

# 16. Network Connections
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "16. SUSPICIOUS NETWORK CONNECTIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Checking for connections to known mining pools..."
MINING_CONN=$(ss -tunap | grep ESTABLISHED | grep -iE "pool|xmr|monero|:3333|:4444|:5555|:7777")
if [ -n "$MINING_CONN" ]; then
    echo "🚨 Mining pool connection detected!"
    echo "$MINING_CONN"
    send_immediate_alert "Mining Pool Connection" "$MINING_CONN"
    CRITICAL_ALERTS+=("Mining pool connection detected")
else
    echo "✓ No mining connections"
fi
echo ""

echo "Checking for suspicious active connections to sensitive ports:"
ALL_SUSP_ACTIVE_CONN=$(ss -tunap | grep ESTABLISHED | grep -v "127.0.0\|:80\|:443\|:22\|:2222\|:2254" | grep -E ":(3306|27017|27020|2110[0-9]|2111[0-9]|8082|4444|5555|7777|3333)")
REAL_SUSP_ACTIVE_CONN=""

if [ -n "$ALL_SUSP_ACTIVE_CONN" ]; then
    while IFS= read -r conn; do
        # Extract port from connection
        PORT=$(echo "$conn" | grep -oE ":(3306|27017|27020|2110[0-9]|2111[0-9]|8082|4444|5555|7777|3333)" | sed 's/://' | head -1)
        
        # Check if port is from Docker container
        IS_DOCKER_PORT=0
        if command -v docker &> /dev/null && [ -n "$PORT" ]; then
            DOCKER_CONTAINER=$(docker ps --format "{{.Names}}\t{{.Ports}}" 2>/dev/null | grep ":$PORT" | awk '{print $1}' | head -1)
            if [ -n "$DOCKER_CONTAINER" ]; then
                IS_DOCKER_PORT=1
                echo "  ℹ️  Connection to port $PORT is from Docker container '$DOCKER_CONTAINER' (legitimate)"
            fi
        fi
        
        # Only add if not from Docker
        if [ $IS_DOCKER_PORT -eq 0 ]; then
            if [ -z "$REAL_SUSP_ACTIVE_CONN" ]; then
                REAL_SUSP_ACTIVE_CONN="$conn"
            else
                REAL_SUSP_ACTIVE_CONN="$REAL_SUSP_ACTIVE_CONN\n$conn"
            fi
        fi
    done <<< "$ALL_SUSP_ACTIVE_CONN"
    
    if [ -n "$REAL_SUSP_ACTIVE_CONN" ]; then
        echo "🚨 Suspicious active connections detected (not from Docker):"
        echo -e "$REAL_SUSP_ACTIVE_CONN"
        send_immediate_alert "Suspicious Active Connection" "$REAL_SUSP_ACTIVE_CONN"
        CRITICAL_ALERTS+=("Suspicious active connections to sensitive ports")
    else
        echo "✓ No suspicious active connections (all are to Docker containers - legitimate)"
    fi
else
    echo "✓ No suspicious active connections"
fi
echo ""

echo "Unknown external connections:"
UNKNOWN_CONN=$(ss -tunap | grep ESTABLISHED | grep -v "127.0.0\|:80\|:443\|:22\|:2222\|:2254" | head -10)
if [ -n "$UNKNOWN_CONN" ]; then
    echo "$UNKNOWN_CONN"
    # Send alert if there are many unknown connections
    CONN_COUNT=$(echo "$UNKNOWN_CONN" | wc -l)
    if [ $CONN_COUNT -gt 5 ]; then
        send_immediate_alert "Multiple Unknown Connections" "$UNKNOWN_CONN"
        CRITICAL_ALERTS+=("Multiple unknown external connections detected")
    fi
else
    echo "✓ Only known connections"
fi
echo ""

# 17. File Integrity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "17. CRITICAL FILE INTEGRITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Checking critical system files..."
FILES_MODIFIED=0

# Check if critical files were modified recently (last 24h)
for file in /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/sudoers; do
    if [ -f "$file" ]; then
        MOD_TIME=$(stat -c %Y "$file" 2>/dev/null || stat -f %m "$file" 2>/dev/null)
        NOW=$(date +%s)
        DIFF=$((NOW - MOD_TIME))
        
        if [ $DIFF -lt 86400 ]; then
            echo "⚠ $file modified in last 24h"
            ((FILES_MODIFIED++))
        fi
    fi
done

if [ $FILES_MODIFIED -eq 0 ]; then
    echo "✓ No critical files modified recently"
else
    echo "⚠ $FILES_MODIFIED critical files modified recently (review changes)"
fi
echo ""

# 18. Docker Container Health
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "18. DOCKER CONTAINER HEALTH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOTAL=$(docker ps -a -q | wc -l)
RUNNING=$(docker ps -q | wc -l)
UNHEALTHY=$(docker ps --filter "health=unhealthy" -q | wc -l)
RESTARTING=$(docker ps --filter "status=restarting" -q | wc -l)

echo "Total containers: $TOTAL"
echo "Running: $RUNNING"
echo "Unhealthy: $UNHEALTHY"
echo "Restarting: $RESTARTING"

if [ $UNHEALTHY -gt 0 ] || [ $RESTARTING -gt 0 ]; then
    echo ""
    echo "⚠ Problematic containers:"
    docker ps -a --filter "health=unhealthy" --filter "status=restarting" --format "table {{.Names}}\t{{.Status}}"
fi
echo ""

echo "============================================"
echo "   📊  SECURITY SCORE"
echo "============================================"

SCORE=100
ISSUES=0
CRITICAL=0

# Deduct points for issues and collect critical alerts
grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config && ((SCORE-=20)) && ((ISSUES++)) && echo "⚠ SSH passwords enabled (-20)"
[[ $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}') == "22" ]] && ((SCORE-=15)) && ((ISSUES++)) && echo "⚠ SSH on default port 22 (-15)"
! ufw status | grep -q "Status: active" && ((SCORE-=25)) && ((ISSUES++)) && echo "⚠ Firewall not active (-25)"
ss -tunlp | grep "0.0.0.0" | grep -qE ":3306|:27017|:27020" && ((SCORE-=30)) && ((ISSUES++)) && ((CRITICAL++)) && CRITICAL_ALERTS+=("Databases exposed to internet") && echo "🚨 Databases exposed to internet (-30) [CRITICAL]"
[ -f /etc/ld.so.preload ] && ((SCORE-=50)) && ((CRITICAL++)) && CRITICAL_ALERTS+=("ROOTKIT detected: ld.so.preload found") && echo "🚨 ROOTKIT detected: ld.so.preload (-50) [CRITICAL]"
# Check for malware processes (excluding PM2 managed Go servers)
REAL_MALWARE_CHECK=$(ps aux | grep -iE "xmrig|miner|kinsing|systemhelper|linuxsys|wsystemd|Gqr7dweg|1z1Mv3GA|B7mQL|lrt|bot|kdevtmpfsi|watchbog|ddgs|qW3xT|2t3ik|kinsingd" | grep -v grep | grep -vE "/tmp/go-build.*server.*pm2|PM2")
if [ -n "$REAL_MALWARE_CHECK" ]; then
    ((SCORE-=50)) && ((CRITICAL++)) && CRITICAL_ALERTS+=("MALWARE process detected") && echo "🚨 MALWARE process detected (-50) [CRITICAL]"
fi
systemctl list-units --all --type=service | grep -qiE "bot\.service|kinsing" && ((SCORE-=50)) && ((CRITICAL++)) && CRITICAL_ALERTS+=("MALICIOUS systemd service detected") && echo "🚨 MALICIOUS service detected (-50) [CRITICAL]"
[ -f /etc/systemd/system/bot.service ] && ((SCORE-=50)) && ((CRITICAL++)) && CRITICAL_ALERTS+=("bot.service malware file found") && echo "🚨 bot.service malware found (-50) [CRITICAL]"
[ $RESTARTING -gt 2 ] && ((SCORE-=10)) && ((ISSUES++)) && echo "⚠ Multiple containers restarting (-10)"
[ $REMOVED_SERVICES -gt 0 ] && ((CRITICAL++)) && CRITICAL_ALERTS+=("$REMOVED_SERVICES malicious service(s) removed")
[ $REMOVED_PROCESSES -gt 0 ] && ((CRITICAL++)) && CRITICAL_ALERTS+=("$REMOVED_PROCESSES malicious process(es) killed")
[ $REMOVED_FILES -gt 0 ] && ((CRITICAL++)) && CRITICAL_ALERTS+=("$REMOVED_FILES malicious file(s) removed")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $SCORE -ge 95 ]; then
    echo "✅ SECURITY SCORE: $SCORE/100 - EXCELLENT"
    echo "🏆 Server is very well secured!"
elif [ $SCORE -ge 85 ]; then
    echo "✅ SECURITY SCORE: $SCORE/100 - VERY GOOD"
    echo "👍 Server is well protected"
elif [ $SCORE -ge 70 ]; then
    echo "⚠️  SECURITY SCORE: $SCORE/100 - GOOD"
    echo "Some improvements recommended"
elif [ $SCORE -ge 50 ]; then
    echo "⚠️  SECURITY SCORE: $SCORE/100 - NEEDS IMPROVEMENT"
    echo "⚠️  Action required to improve security"
elif [ $SCORE -ge 30 ]; then
    echo "🚨 SECURITY SCORE: $SCORE/100 - POOR"
    echo "🚨 URGENT: Server is vulnerable!"
else
    echo "🚨🚨🚨 SECURITY SCORE: $SCORE/100 - CRITICAL"
    echo "🚨 IMMEDIATE ACTION REQUIRED!"
    echo "🚨 Server is highly compromised!"
fi

echo ""
echo "Issues found: $ISSUES"
echo "Critical issues: $CRITICAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Full report saved to: $REPORT_FILE"
echo ""

# Recommendations
if [ $SCORE -lt 90 ] || [ $REMOVED_SERVICES -gt 0 ] || [ $REMOVED_PROCESSES -gt 0 ] || [ $REMOVED_FILES -gt 0 ]; then
    echo "============================================"
    echo "  📋 RECOMMENDATIONS"
    echo "============================================"
    
    if [ $REMOVED_SERVICES -gt 0 ] || [ $REMOVED_PROCESSES -gt 0 ] || [ $REMOVED_FILES -gt 0 ]; then
        echo "  • ✅ Malware cleanup completed automatically"
        echo "  • 🔄 Consider rebooting the server to ensure all malware is removed"
        echo "  • 🔍 Monitor system logs for suspicious activity: journalctl -f"
        echo "  • 🛡️  Review fail2ban logs: fail2ban-client status sshd"
        echo ""
    fi
    
    grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config && echo "  • Disable SSH password authentication"
    [[ $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}') == "22" ]] && echo "  • Change SSH to non-standard port (2222 or 2254)"
    ! ufw status | grep -q "Status: active" && echo "  • Enable UFW firewall"
    ss -tunlp | grep -q "0.0.0.0.*:3306\|0.0.0.0.*:27017" && echo "  • 🚨 URGENT: Close database ports to internet!"
    [ -f /etc/ld.so.preload ] && echo "  • 🚨🚨🚨 CRITICAL: Remove rootkit and reinstall server!"
    systemctl list-units --all --type=service | grep -qiE "bot\.service|kinsing" && echo "  • 🚨 CRITICAL: Remove malicious systemd services!"
    [ $RESTARTING -gt 0 ] && echo "  • Check why containers are restarting: docker logs CONTAINER"
    
    echo ""
fi

# ============================================
# EMAIL NOTIFICATION FOR CRITICAL ISSUES
# ============================================
if [ $CRITICAL -gt 0 ] || [ $REMOVED_SERVICES -gt 0 ] || [ $REMOVED_PROCESSES -gt 0 ] || [ $REMOVED_FILES -gt 0 ] || [ ${#CRITICAL_ALERTS[@]} -gt 0 ]; then
    echo "============================================"
    echo "  📧 SENDING CRITICAL ALERT EMAIL"
    echo "============================================"
    
    EMAIL_SUBJECT="🚨 CRITICAL: Security Alert - $(hostname) - $(date +%Y-%m-%d\ %H:%M:%S)"
    
    EMAIL_BODY="CRITICAL SECURITY ALERT
Server: $(hostname)
IP: $(hostname -I | awk '{print $1}')
Date: $(date)
Time: $(date +%H:%M:%S)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY SCORE: $SCORE/100
Critical Issues: $CRITICAL
Total Issues: $ISSUES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CLEANUP SUMMARY:
- Services removed: $REMOVED_SERVICES
- Processes killed: $REMOVED_PROCESSES
- Files removed: $REMOVED_FILES

CRITICAL ALERTS:
"
    
    # Add critical alerts
    for alert in "${CRITICAL_ALERTS[@]}"; do
        EMAIL_BODY+="🚨 $alert"$'\n'
    done
    
    # Add detected issues (excluding legitimate PM2 processes and Docker containers)
    EMAIL_BODY+=$'\n'"DETECTED ISSUES:"$'\n'
    [ -f /etc/ld.so.preload ] && EMAIL_BODY+="🚨 ROOTKIT: ld.so.preload found!"$'\n'
    # Check for real malware (excluding PM2 managed Go servers)
    REAL_MALWARE_EMAIL=$(ps aux | grep -iE "xmrig|miner|kinsing|systemhelper|linuxsys|wsystemd|Gqr7dweg|1z1Mv3GA|B7mQL|lrt|bot|kdevtmpfsi|watchbog|ddgs|qW3xT|2t3ik|kinsingd" | grep -v grep | grep -vE "/tmp/go-build.*server.*pm2|PM2")
    [ -n "$REAL_MALWARE_EMAIL" ] && EMAIL_BODY+="🚨 MALWARE process detected!"$'\n'
    systemctl list-units --all --type=service | grep -qiE "bot\.service|kinsing" && EMAIL_BODY+="🚨 MALICIOUS service detected!"$'\n'
    # Check for exposed databases (only if not from Docker containers bound to localhost)
    if ss -tulpn | grep "0.0.0.0" | grep -qE ":3306|:27017|:27020"; then
        # Check if these ports are from Docker containers
        DB_EXPOSED=0
        for db_port in 3306 27017 27020; do
            if ss -tulpn | grep "0.0.0.0" | grep -q ":$db_port"; then
                DOCKER_DB=$(docker ps --format "{{.Ports}}" 2>/dev/null | grep ":$db_port" | grep -v "127.0.0.1:$db_port")
                if [ -z "$DOCKER_DB" ]; then
                    DB_EXPOSED=1
                fi
            fi
        done
        [ $DB_EXPOSED -eq 1 ] && EMAIL_BODY+="🚨 Databases exposed to internet!"$'\n'
    fi
    
    EMAIL_BODY+=$'\n'"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"$'\n'
    EMAIL_BODY+="Full report saved to: $REPORT_FILE"$'\n'
    EMAIL_BODY+="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"$'\n'
    EMAIL_BODY+=$'\n'"Please review the server immediately!"$'\n'
    
    # Send email
    send_email "$EMAIL_SUBJECT" "$EMAIL_BODY" "$LOG_REPORT_RECIPIENT"
    echo "✓ Critical alert email sent to $LOG_REPORT_RECIPIENT"
    echo ""
fi

echo "============================================"