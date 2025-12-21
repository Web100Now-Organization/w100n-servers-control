package start_server_setting

import (
	"fmt"
	"time"
)

// hardenSSH configures SSH security settings
func (s *ServerSetup) hardenSSH() error {
	sshConfigPath := "/etc/ssh/sshd_config"
	backupPath := "/etc/ssh/sshd_config.backup"

	// Backup original config
	s.runCommandAsRoot("cp", sshConfigPath, backupPath)

	// SSH secure configuration with generated port
	sshConfig := fmt.Sprintf(`# Secure SSH Configuration
Port %d
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security - Modern OpenSSH uses Protocol 2 by default (no need to specify)
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 3:50:10
StrictModes yes

# Modern Key Exchange and Ciphers
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# Disable dangerous features
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
Compression no

# Network
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
TCPKeepAlive yes

# Misc
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Restrict users - allow the setup user and root
AllowUsers %s root

# Additional security
HostbasedAuthentication no
IgnoreRhosts yes
RhostsRSAAuthentication no
RSAAuthentication no

# Logging
SyslogFacility AUTHPRIV
LogLevel INFO
`, s.config.SSHPort, s.username)

	// Write config directly to remote server
	if err := s.writeFileToRemote([]byte(sshConfig), sshConfigPath, "644"); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}

	// Test SSH config
	if _, err := s.runCommandAsRoot("sshd", "-t"); err != nil {
		return fmt.Errorf("SSH config test failed: %w", err)
	}

	// Use reload instead of restart to avoid disconnecting current session
	// On Ubuntu 22.04/24.04, the service is 'ssh', not 'sshd'
	// Try reload first (safer), fallback to restart if reload fails
	if _, err := s.runCommandAsRoot("systemctl", "reload", "ssh"); err != nil {
		// If reload fails (e.g., port change requires restart), use restart
		// But first verify the new port is accessible
		if _, err2 := s.runCommandAsRoot("systemctl", "restart", "ssh"); err2 != nil {
			// Fallback to sshd if ssh service doesn't exist
			if _, err3 := s.runCommandAsRoot("systemctl", "restart", "sshd"); err3 != nil {
				return fmt.Errorf("failed to reload/restart SSH service (tried 'ssh' and 'sshd'): %w", err)
			}
		}
		// Wait a moment for SSH to restart
		time.Sleep(2 * time.Second)
		// Verify SSH is running on new port
		checkCmd := fmt.Sprintf("ss -tuln | grep -q ':%d ' || netstat -tuln 2>/dev/null | grep -q ':%d '", s.config.SSHPort, s.config.SSHPort)
		if _, err := s.runCommandAsRoot("bash", "-c", checkCmd); err != nil {
			return fmt.Errorf("SSH service restarted but port %d is not listening", s.config.SSHPort)
		}
	}

	return nil
}

// configureFirewall configures UFW firewall
func (s *ServerSetup) configureFirewall() error {
	// Reset firewall
	s.runCommandAsRoot("ufw", "--force", "reset")

	// Set defaults
	s.runCommandAsRoot("ufw", "default", "deny", "incoming")
	s.runCommandAsRoot("ufw", "default", "allow", "outgoing")

	// Allow SSH on generated port
	s.runCommandAsRoot("ufw", "allow", fmt.Sprintf("%d/tcp", s.config.SSHPort), "comment", "SSH")

	// Allow HTTP/HTTPS
	s.runCommandAsRoot("ufw", "allow", "80/tcp", "comment", "HTTP")
	s.runCommandAsRoot("ufw", "allow", "443/tcp", "comment", "HTTPS")

	// Enable firewall
	_, err := s.runCommandAsRoot("ufw", "--force", "enable")
	return err
}

// configureFail2ban configures Fail2ban
func (s *ServerSetup) configureFail2ban() error {
	fail2banConfig := fmt.Sprintf(`[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sendername = Fail2Ban
action = %%(action_mwl)s
backend = systemd

[sshd]
enabled = true
port = %d
logpath = %%(_sshd_logs)s
backend = %%(_sshd_backend)s
maxretry = 3
bantime = 7200
findtime = 600

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
bantime = 600
`, s.config.SSHPort)

	if err := s.writeFileToRemote([]byte(fail2banConfig), "/etc/fail2ban/jail.local", "644"); err != nil {
		return fmt.Errorf("failed to write Fail2ban config: %w", err)
	}

	s.runCommandAsRoot("systemctl", "enable", "fail2ban")
	_, err := s.runCommandAsRoot("systemctl", "restart", "fail2ban")
	return err
}

// hardenKernel configures kernel security parameters
func (s *ServerSetup) hardenKernel() error {
	sysctlConfig := `# Kernel Security Hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.panic = 10
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1

# Memory Protection (ASLR)
kernel.randomize_va_space = 2

# Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 (якщо не використовується)
net.ipv6.conf.all.disable_ipv6 = 1

# TCP hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Prevent IP spoofing
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
`

	if err := s.writeFileToRemote([]byte(sysctlConfig), "/etc/sysctl.conf", "644"); err != nil {
		return fmt.Errorf("failed to write sysctl config: %w", err)
	}

	_, err := s.runCommandAsRoot("sysctl", "-p")
	return err
}

// secureDocker configures Docker security
func (s *ServerSetup) secureDocker() error {
	dockerConfig := `{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "userns-remap": "default"
}
`

	s.runCommandAsRoot("mkdir", "-p", "/etc/docker")
	if err := s.writeFileToRemote([]byte(dockerConfig), "/etc/docker/daemon.json", "644"); err != nil {
		return fmt.Errorf("failed to write Docker config: %w", err)
	}

	// Configure Docker socket permissions
	s.runCommandAsRoot("chmod", "660", "/var/run/docker.sock")
	s.runCommandAsRoot("chown", "root:docker", "/var/run/docker.sock")

	_, err := s.runCommandAsRoot("systemctl", "restart", "docker")
	return err
}

// hardenNginx configures Nginx security
func (s *ServerSetup) hardenNginx() error {
	securityHeaders := `# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Hide Nginx version
server_tokens off;

# Limit request size
client_max_body_size 20M;
client_body_timeout 20s;
client_header_timeout 20s;
`

	rateLimitConfig := `# Rate Limiting
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Apply in server blocks:
# limit_req zone=general burst=20 nodelay;
# limit_conn conn_limit 10;
`

	if err := s.writeFileToRemote([]byte(securityHeaders), "/etc/nginx/conf.d/security-headers.conf", "644"); err != nil {
		return fmt.Errorf("failed to write Nginx security headers: %w", err)
	}

	if err := s.writeFileToRemote([]byte(rateLimitConfig), "/etc/nginx/conf.d/rate-limit.conf", "644"); err != nil {
		return fmt.Errorf("failed to write Nginx rate limit config: %w", err)
	}

	// Test Nginx config
	if _, err := s.runCommandAsRoot("nginx", "-t"); err != nil {
		return fmt.Errorf("nginx config test failed: %w", err)
	}

	_, err := s.runCommandAsRoot("systemctl", "restart", "nginx")
	return err
}

// enableAutoUpdates enables automatic security updates
func (s *ServerSetup) enableAutoUpdates() error {
	autoUpdatesConfig := `Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
`

	if err := s.writeFileToRemote([]byte(autoUpdatesConfig), "/etc/apt/apt.conf.d/50unattended-upgrades", "644"); err != nil {
		return fmt.Errorf("failed to write auto-updates config: %w", err)
	}

	s.runCommandAsRoot("systemctl", "enable", "unattended-upgrades")
	_, err := s.runCommandAsRoot("systemctl", "start", "unattended-upgrades")
	return err
}

// setupMalwareScanning sets up daily malware scanning
func (s *ServerSetup) setupMalwareScanning() error {
	scanScript := `#!/bin/bash
LOG="/var/log/security-scan.log"
echo "=== Security Scan $(date) ===" >> $LOG

# Update malware signatures
freshclam >> $LOG 2>&1
rkhunter --update >> $LOG 2>&1

# Scan critical directories
clamscan -r -i /tmp /var/tmp /usr/local/bin /usr/sbin /etc/cron.d /etc/init.d >> $LOG 2>&1

# Rootkit check
rkhunter --check --skip-keypress --report-warnings-only >> $LOG 2>&1

# Check for suspicious processes
ps aux | grep -iE "xmrig|miner|kinsing|systemhelper" >> $LOG 2>&1

echo "=== Scan complete ===" >> $LOG
`

	if err := s.writeFileToRemote([]byte(scanScript), "/usr/local/bin/daily-security-scan.sh", "755"); err != nil {
		return fmt.Errorf("failed to write scan script: %w", err)
	}

	// Add to crontab
	cronCmd := `(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/daily-security-scan.sh") | crontab -`
	_, err := s.runCommandAsRoot("bash", "-c", cronCmd)
	return err
}

// fixNginxCachePermissions fixes Nginx cache directory permissions
func (s *ServerSetup) fixNginxCachePermissions() error {
	s.runCommandAsRoot("mkdir", "-p", "/var/cache/nginx/proxy_temp")
	s.runCommandAsRoot("chown", "-R", "www-data:www-data", "/var/cache/nginx/")
	_, err := s.runCommandAsRoot("chmod", "-R", "755", "/var/cache/nginx/")
	return err
}

// configureTimezone sets system timezone
func (s *ServerSetup) configureTimezone() error {
	_, err := s.runCommandAsRoot("timedatectl", "set-timezone", "America/Chicago")
	return err
}

// setupAuditLogging sets up auditd
func (s *ServerSetup) setupAuditLogging() error {
	// Install auditd
	s.runCommandAsRoot("apt", "install", "-y", "auditd")

	auditRules := `# Monitor important files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/cron.d/ -p wa -k cron
-w /etc/init.d/ -p wa -k init
-w /usr/local/bin/ -p wa -k binaries
-w /usr/sbin/ -p wa -k binaries

# Monitor suspicious activity
-a always,exit -F arch=b64 -S execve -k exec
`

	// Write audit rules to temp file, then append to existing rules
	if err := s.writeFileToRemote([]byte(auditRules), "/tmp/audit.rules", "644"); err != nil {
		return fmt.Errorf("failed to write audit rules: %w", err)
	}

	// Append to existing rules
	if _, err := s.runCommandAsRoot("bash", "-c", "cat /tmp/audit.rules >> /etc/audit/rules.d/audit.rules"); err != nil {
		return fmt.Errorf("failed to add audit rules: %w", err)
	}

	s.runCommandAsRoot("systemctl", "enable", "auditd")
	_, err := s.runCommandAsRoot("systemctl", "restart", "auditd")
	return err
}

// configureLogRotation sets up log rotation for security logs
func (s *ServerSetup) configureLogRotation() error {
	logrotateConfig := `/var/log/auth.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/var/log/nginx/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}

/var/log/fail2ban.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}

/var/log/security-scan.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}

/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        systemctl reload auditd > /dev/null 2>&1 || true
    endscript
}
`

	if err := s.writeFileToRemote([]byte(logrotateConfig), "/etc/logrotate.d/security", "644"); err != nil {
		return fmt.Errorf("failed to write logrotate config: %w", err)
	}

	return nil
}

// configureTimeSync configures NTP/Chrony for time synchronization
func (s *ServerSetup) configureTimeSync() error {
	// Install chrony (more secure than ntp)
	s.runCommandAsRoot("apt", "install", "-y", "chrony")

	chronyConfig := `# Use Ubuntu NTP pool
pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst

# Use time servers from pool.ntp.org project
pool pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock
rtcsync

# Increase the minimum number of selectable sources
#minsources 2

# Allow NTP client access from local network
#allow 192.168.0.0/16

# Serve time even if not synchronized to a time source
#local stratum 10

# Specify file containing keys for NTP authentication
keyfile /etc/chrony/chrony.keys

# Save the drift and offset statistics
logdir /var/log/chrony
maxupdateskew 100.0

# Disable logging of client accesses
noclientlog
`

	if err := s.writeFileToRemote([]byte(chronyConfig), "/etc/chrony/chrony.conf", "644"); err != nil {
		return fmt.Errorf("failed to write chrony config: %w", err)
	}

	s.runCommandAsRoot("systemctl", "enable", "chronyd")
	_, err := s.runCommandAsRoot("systemctl", "restart", "chronyd")
	if err != nil {
		// Fallback to chrony service name (some systems use 'chrony' instead of 'chronyd')
		if _, err2 := s.runCommandAsRoot("systemctl", "restart", "chrony"); err2 != nil {
			return fmt.Errorf("failed to restart chrony service (tried both 'chronyd' and 'chrony'): %w", err)
		}
	}
	return nil
}

// configureAppArmor sets up AppArmor for application isolation
func (s *ServerSetup) configureAppArmor() error {
	// Install AppArmor
	s.runCommandAsRoot("apt", "install", "-y", "apparmor", "apparmor-utils")

	// Enable AppArmor
	s.runCommandAsRoot("systemctl", "enable", "apparmor")
	_, err := s.runCommandAsRoot("systemctl", "start", "apparmor")
	if err != nil {
		return fmt.Errorf("failed to start AppArmor: %w", err)
	}

	// Set AppArmor to enforcing mode (if profiles exist)
	s.runCommandAsRoot("aa-enforce", "/etc/apparmor.d/*")

	// Ensure AppArmor profiles are loaded
	s.runCommandAsRoot("apparmor_parser", "-r", "/etc/apparmor.d/*")

	return nil
}

// setupFileIntegrityMonitoring sets up AIDE for file integrity checking
func (s *ServerSetup) setupFileIntegrityMonitoring() error {
	// Install AIDE
	s.runCommandAsRoot("apt", "install", "-y", "aide", "aide-common")

	// Initialize AIDE database (non-interactive)
	s.runCommandAsRoot("aideinit", "-y", "-f")

	// Create daily check script
	checkScript := `#!/bin/bash
LOG="/var/log/aide-check.log"
echo "=== AIDE Check $(date) ===" >> $LOG

# Run AIDE check
aide --check >> $LOG 2>&1

# If changes detected, send alert
if [ $? -ne 0 ]; then
    echo "warning: File integrity check failed! Review $LOG for details." >> $LOG
    # You can add email notification here if needed
fi

echo "=== Check complete ===" >> $LOG
`

	if err := s.writeFileToRemote([]byte(checkScript), "/usr/local/bin/aide-daily-check.sh", "755"); err != nil {
		return fmt.Errorf("failed to write AIDE check script: %w", err)
	}

	// Add to crontab (daily at 2 AM)
	cronCmd := `(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/aide-daily-check.sh") | crontab -`
	_, err := s.runCommandAsRoot("bash", "-c", cronCmd)
	return err
}

// configureResourceLimits sets up system resource limits
func (s *ServerSetup) configureResourceLimits() error {
	limitsConfig := `# Security resource limits
* soft nofile 65535
* hard nofile 65535
* soft nproc 32768
* hard nproc 32768
root soft nofile 65535
root hard nofile 65535
root soft nproc 32768
root hard nproc 32768

# Prevent fork bombs
* soft nproc 4096
* hard nproc 8192

# Memory limits
* soft core 0
* hard core 0
`

	if err := s.writeFileToRemote([]byte(limitsConfig), "/etc/security/limits.conf", "644"); err != nil {
		return fmt.Errorf("failed to write limits config: %w", err)
	}

	// Also configure systemd limits
	systemdLimits := `[Manager]
DefaultLimitNOFILE=65535:65535
DefaultLimitNPROC=32768:32768
`

	s.runCommandAsRoot("mkdir", "-p", "/etc/systemd/system.conf.d")
	if err := s.writeFileToRemote([]byte(systemdLimits), "/etc/systemd/system.conf.d/limits.conf", "644"); err != nil {
		return fmt.Errorf("failed to write systemd limits: %w", err)
	}

	_, err := s.runCommandAsRoot("systemctl", "daemon-reload")
	return err
}

// configureDNSSecurity configures secure DNS settings
func (s *ServerSetup) configureDNSSecurity() error {
	resolvedConfig := `[Resolve]
DNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4
FallbackDNS=9.9.9.9 149.112.112.112
DNSSEC=yes
DNSOverTLS=yes
Cache=yes
`

	if err := s.writeFileToRemote([]byte(resolvedConfig), "/etc/systemd/resolved.conf", "644"); err != nil {
		return fmt.Errorf("failed to write resolved config: %w", err)
	}

	_, err := s.runCommandAsRoot("systemctl", "restart", "systemd-resolved")
	return err
}
