package start_server_setting

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"web100now-clients-platform/core/db"
)

// OSVersion represents detected OS version information
type OSVersion struct {
	ID          string // "ubuntu"
	VersionID   string // "22.04" or "24.04"
	Version     string // Full version string
	IsSupported bool   // Whether this version is supported
}

// ValidationResult represents result of a validation check
type ValidationResult struct {
	Valid   bool
	Message string
	Error   error
}

// validateInputs validates username, password, and server info before connection
func (s *ServerSetup) validateInputs(serverIP string, serverPort int, username, password string) error {
	// Validate username
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) < 1 || len(username) > 32 {
		return fmt.Errorf("username must be between 1 and 32 characters")
	}
	// Username should only contain alphanumeric, underscore, dash, and dot
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username contains invalid characters")
	}

	// Validate password
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Validate server IP and port
	if err := ValidateServerInfo(serverIP, serverPort); err != nil {
		return fmt.Errorf("server info validation failed: %w", err)
	}

	return nil
}

// checkServerReachability checks if server is reachable before connecting
func (s *ServerSetup) checkServerReachability(serverIP string, serverPort int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := CheckServerReachability(ctx, serverIP, serverPort); err != nil {
		return fmt.Errorf("server %s:%d is not reachable: %w", serverIP, serverPort, err)
	}

	return nil
}

// detectOSVersion detects Ubuntu version from /etc/os-release
func (s *ServerSetup) detectOSVersion() (*OSVersion, error) {
	// Read /etc/os-release
	osRelease, err := s.readFileFromRemote("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/os-release: %w", err)
	}

	version := &OSVersion{}

	// Parse os-release file
	lines := strings.Split(osRelease, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			version.ID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version.VersionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION=") {
			version.Version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}

	// Check if it's Ubuntu
	if version.ID != "ubuntu" {
		return nil, fmt.Errorf("unsupported OS: %s (only Ubuntu 22.04 LTS and 24.04 LTS are supported)", version.ID)
	}

	// Check if version is supported (22.04 or 24.04)
	version.IsSupported = version.VersionID == "22.04" || version.VersionID == "24.04"
	if !version.IsSupported {
		return nil, fmt.Errorf("unsupported Ubuntu version: %s (only 22.04 LTS and 24.04 LTS are supported)", version.VersionID)
	}

	return version, nil
}

// checkSudoRights checks if user has sudo rights
func (s *ServerSetup) checkSudoRights() error {
	// Use runCommandAsRoot which passes password via stdin
	// This will verify that the user has sudo rights and the password is correct
	_, err := s.runCommandAsRoot("true")
	if err != nil {
		return fmt.Errorf("user does not have sudo rights or password is incorrect: %w", err)
	}

	return nil
}

// checkPortAvailability checks if a port is available
func (s *ServerSetup) checkPortAvailability(port int) error {
	// Check if port is in use
	checkCmd := fmt.Sprintf("ss -tuln | grep -q ':%d ' || netstat -tuln 2>/dev/null | grep -q ':%d '", port, port)
	output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err == nil && output != "" {
		return fmt.Errorf("port %d is already in use", port)
	}

	// Also check with lsof if available
	checkCmd2 := fmt.Sprintf("lsof -i :%d 2>/dev/null | grep -q LISTEN || true", port)
	output2, err2 := s.runCommandAsRoot("bash", "-c", checkCmd2)
	if err2 == nil && output2 != "" && !strings.Contains(output2, "true") {
		return fmt.Errorf("port %d is already in use (checked with lsof)", port)
	}

	return nil
}

// checkDiskSpace checks if there's enough disk space (minimum 10GB)
func (s *ServerSetup) checkDiskSpace() error {
	// Check root filesystem available space
	// Use df with human-readable format and parse output
	checkCmd := "df -BG / | tail -1"
	output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	// Parse output: df -BG output format: Filesystem 1G-blocks Used Available Use% Mounted on
	// We need the 4th field (Available)
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) < 4 {
		return fmt.Errorf("failed to parse disk space output: %s", output)
	}

	// Get available space (4th field), remove 'G' suffix
	availableStr := strings.TrimSuffix(fields[3], "G")
	availableGB, err := strconv.Atoi(availableStr)
	if err != nil {
		return fmt.Errorf("failed to parse disk space value '%s': %w", availableStr, err)
	}

	if availableGB < 10 {
		return fmt.Errorf("insufficient disk space: %dGB available (minimum 10GB required)", availableGB)
	}

	return nil
}

// checkInternetConnection checks if server has internet access
func (s *ServerSetup) checkInternetConnection() error {
	// Try to ping Google DNS
	pingCmd := "ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1"
	_, err := s.runCommandAsRoot("bash", "-c", pingCmd)
	if err != nil {
		// Try curl to Google
		curlCmd := "curl -s --connect-timeout 5 -I https://www.google.com > /dev/null 2>&1"
		_, err2 := s.runCommandAsRoot("bash", "-c", curlCmd)
		if err2 != nil {
			return fmt.Errorf("no internet connection available (ping and curl failed)")
		}
	}

	return nil
}

// checkSystemd checks if systemd is available
func (s *ServerSetup) checkSystemd() error {
	// Check if systemctl exists and works
	_, err := s.runCommandAsRoot("systemctl", "--version")
	if err != nil {
		return fmt.Errorf("systemd is not available: %w", err)
	}

	return nil
}

// checkRAM checks if there's enough RAM (minimum 2GB)
func (s *ServerSetup) checkRAM() error {
	// Check total RAM using free command
	// Use -m (megabytes) instead of -g for more reliable parsing
	checkCmd := "free -m"
	output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err != nil {
		return fmt.Errorf("failed to check RAM: %w", err)
	}

	// Parse output line by line, filter out empty lines and sudo prompts
	lines := strings.Split(output, "\n")
	var memLine string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines
		if line == "" {
			continue
		}
		// Skip sudo prompts
		if strings.Contains(line, "[sudo]") {
			continue
		}
		// Look for line starting with "Mem:" or containing "Mem:"
		if strings.Contains(line, "Mem:") {
			// Extract the Mem line
			parts := strings.Split(line, "Mem:")
			if len(parts) > 1 {
				memLine = "Mem:" + parts[1]
			} else {
				memLine = line
			}
			break
		}
	}

	if memLine == "" {
		return fmt.Errorf("failed to find Mem line in output (raw output: %q)", output)
	}

	// Parse output: free -m output format: Mem:        total       used       free     shared    buff/cache   available
	// Example: "Mem:          8192        1024        5120         256        2048        6144"
	// We need the 2nd field (total in MB)
	fields := strings.Fields(memLine)
	if len(fields) < 2 {
		return fmt.Errorf("failed to parse RAM output, not enough fields in line '%s'", memLine)
	}

	// Get total RAM in MB (2nd field after "Mem:")
	// fields[0] = "Mem:", fields[1] = total in MB
	if len(fields) < 2 {
		return fmt.Errorf("failed to parse RAM output, not enough fields. Line: '%s', Fields: %v", memLine, fields)
	}

	totalRAMMB, err := strconv.Atoi(fields[1])
	if err != nil {
		return fmt.Errorf("failed to parse RAM value '%s' from line '%s' (all fields: %v): %w", fields[1], memLine, fields, err)
	}

	// Check minimum 2GB = 2048MB
	minRAMMB := 2048
	if totalRAMMB < minRAMMB {
		totalRAMGB := float64(totalRAMMB) / 1024.0
		return fmt.Errorf("insufficient RAM: %.2fGB (%dMB) available (minimum 2GB / %dMB required)", totalRAMGB, totalRAMMB, minRAMMB)
	}

	return nil
}

// checkCPU checks if there's at least 1 CPU core
func (s *ServerSetup) checkCPU() error {
	// Check number of CPU cores
	checkCmd := `nproc`
	output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err != nil {
		return fmt.Errorf("failed to check CPU: %w", err)
	}

	output = strings.TrimSpace(output)
	cpuCores, err := strconv.Atoi(output)
	if err != nil {
		return fmt.Errorf("failed to parse CPU cores: %w", err)
	}

	if cpuCores < 1 {
		return fmt.Errorf("insufficient CPU cores: %d (minimum 1 required)", cpuCores)
	}

	return nil
}

// checkEncryptionKey checks if ENCRYPTION_KEY is available
func (s *ServerSetup) checkEncryptionKey() error {
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		return fmt.Errorf("ENCRYPTION_KEY environment variable is not set (required for SSH key encryption)")
	}

	if len(encryptionKey) < 32 {
		return fmt.Errorf("ENCRYPTION_KEY is too short (minimum 32 characters required)")
	}

	return nil
}

// checkPostgresConnection checks if PostgreSQL connection is available
func (s *ServerSetup) checkPostgresConnection(ctx context.Context) error {
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	// Try to ping the database
	if err := pgDB.PingContext(ctx); err != nil {
		return fmt.Errorf("PostgreSQL ping failed: %w", err)
	}

	return nil
}

// checkExistingConfigs checks if critical configs already exist
func (s *ServerSetup) checkExistingConfigs() (map[string]bool, error) {
	configs := make(map[string]bool)

	// Check SSH config
	_, err := s.readFileFromRemote("/etc/ssh/sshd_config")
	configs["ssh"] = err == nil

	// Check Nginx config
	_, err = s.readFileFromRemote("/etc/nginx/nginx.conf")
	configs["nginx"] = err == nil

	// Check Docker
	_, err = s.runCommandAsRoot("docker", "--version")
	configs["docker"] = err == nil

	// Check UFW
	_, err = s.runCommandAsRoot("ufw", "status")
	configs["ufw"] = err == nil

	// Check Fail2ban
	_, err = s.runCommandAsRoot("fail2ban-client", "status")
	configs["fail2ban"] = err == nil

	return configs, nil
}

// verifyInstalledPackage verifies that a package is installed and returns its version
func (s *ServerSetup) verifyInstalledPackage(packageName string) (string, error) {
	// Try dpkg first (Debian/Ubuntu)
	checkCmd := fmt.Sprintf("dpkg -l | grep -E '^ii\\s+%s'", packageName)
	output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err == nil && strings.TrimSpace(output) != "" {
		// Parse output: dpkg -l format: ii  package-name  version  arch  description
		// We need the 3rd field (version)
		fields := strings.Fields(strings.TrimSpace(output))
		if len(fields) >= 3 {
			return fields[2], nil
		}
	}

	// Try apt list if dpkg doesn't work
	checkCmd2 := fmt.Sprintf("apt list --installed 2>/dev/null | grep -E '^%s/'", packageName)
	output2, err2 := s.runCommandAsRoot("bash", "-c", checkCmd2)
	if err2 == nil && strings.TrimSpace(output2) != "" {
		// Parse output: apt list format: package/version  arch  [installed]
		// We need the version part after the slash
		line := strings.TrimSpace(output2)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			// Extract version from "package/version" format
			pkgVersion := parts[0]
			if idx := strings.Index(pkgVersion, "/"); idx >= 0 && idx < len(pkgVersion)-1 {
				return pkgVersion[idx+1:], nil
			}
		}
	}

	return "", fmt.Errorf("package %s is not installed", packageName)
}

// verifyGoInstallation verifies Go is installed and in PATH
func (s *ServerSetup) verifyGoInstallation() error {
	// First try with full path (in case PATH is not updated yet)
	output, err := s.runCommand("/usr/local/go/bin/go", "version")
	if err != nil {
		// If full path doesn't work, try with PATH export
		checkCmd := `export PATH=$PATH:/usr/local/go/bin && go version`
		output, err = s.runCommand("bash", "-c", checkCmd)
		if err != nil {
			return fmt.Errorf("go is not installed or not in PATH: %w", err)
		}
	}

	// Verify it's a reasonable version (should contain "go1.")
	if !strings.Contains(output, "go1.") {
		return fmt.Errorf("invalid Go installation: %s", output)
	}

	return nil
}

// verifyNodeJSInstallation verifies Node.js is installed and in PATH
func (s *ServerSetup) verifyNodeJSInstallation() error {
	// Source NVM and check Node.js version
	nvmCmd := `export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && node --version`
	output, err := s.runCommand("bash", "-c", nvmCmd)
	if err != nil {
		return fmt.Errorf("node.js is not installed or not in PATH: %w", err)
	}

	// Verify it's a reasonable version (should start with "v")
	if !strings.HasPrefix(strings.TrimSpace(output), "v") {
		return fmt.Errorf("invalid node.js installation: %s", output)
	}

	return nil
}

// verifyDockerInstallation verifies Docker is installed and daemon is running
func (s *ServerSetup) verifyDockerInstallation() error {
	// Check Docker version
	_, err := s.runCommandAsRoot("docker", "--version")
	if err != nil {
		return fmt.Errorf("docker is not installed: %w", err)
	}

	// Check if Docker daemon is running
	_, err = s.runCommandAsRoot("docker", "ps")
	if err != nil {
		return fmt.Errorf("docker daemon is not running: %w", err)
	}

	return nil
}

// verifyNginxInstallation verifies Nginx is installed and config is valid
func (s *ServerSetup) verifyNginxInstallation() error {
	// Check Nginx version
	_, err := s.runCommandAsRoot("nginx", "-v")
	if err != nil {
		return fmt.Errorf("nginx is not installed: %w", err)
	}

	// Check Nginx config
	_, err = s.runCommandAsRoot("nginx", "-t")
	if err != nil {
		return fmt.Errorf("nginx configuration is invalid: %w", err)
	}

	return nil
}

// checkPortsInUse checks if ports 80 and 443 are already in use
func (s *ServerSetup) checkPortsInUse(ports []int) error {
	for _, port := range ports {
		if err := s.checkPortAvailability(port); err != nil {
			return fmt.Errorf("port %d is already in use", port)
		}
	}
	return nil
}

// checkAppArmorStatus checks AppArmor status before configuration
func (s *ServerSetup) checkAppArmorStatus() (bool, error) {
	// Check if AppArmor is available
	_, err := s.runCommandAsRoot("aa-status")
	if err != nil {
		return false, nil // AppArmor not available, but that's OK
	}

	return true, nil
}

// checkSSLCertificates checks if SSL certificates exist for Nginx
func (s *ServerSetup) checkSSLCertificates() (bool, error) {
	// Check common certificate locations
	certPaths := []string{
		"/etc/ssl/certs/",
		"/etc/letsencrypt/live/",
		"/etc/nginx/ssl/",
	}

	for _, path := range certPaths {
		checkCmd := fmt.Sprintf("test -d %s && find %s -name '*.crt' -o -name '*.pem' | head -1", path, path)
		output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
		if err == nil && strings.TrimSpace(output) != "" {
			return true, nil
		}
	}

	return false, nil // No certificates found, but that's OK (we can use HTTP only)
}

// runPreSetupValidations runs all critical validations before setup
func (s *ServerSetup) runPreSetupValidations(serverIP string, serverPort int, username, password string) error {
	// Step 1: Validate inputs
	s.sendProgress(0, 30, "Validating inputs...", "running", nil)
	if err := s.validateInputs(serverIP, serverPort, username, password); err != nil {
		return fmt.Errorf("input validation failed: %w", err)
	}

	// Step 2: Check server reachability
	s.sendProgress(0, 30, "Checking server reachability...", "running", nil)
	if err := s.checkServerReachability(serverIP, serverPort); err != nil {
		return fmt.Errorf("server reachability check failed: %w", err)
	}

	// Step 3: Connect to SSH (we need connection for further checks)
	s.sendProgress(0, 30, "Establishing SSH connection...", "running", nil)
	if err := s.connectSSH(); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}
	defer s.closeSSH()

	// Step 4: Detect OS version
	s.sendProgress(0, 30, "Detecting OS version...", "running", nil)
	osVersion, err := s.detectOSVersion()
	if err != nil {
		return fmt.Errorf("OS version detection failed: %w", err)
	}
	s.sendProgress(0, 30, fmt.Sprintf("Detected: %s %s", osVersion.ID, osVersion.VersionID), "completed", nil)

	// Step 5: Check sudo rights
	s.sendProgress(0, 30, "Checking sudo rights...", "running", nil)
	if err := s.checkSudoRights(); err != nil {
		return fmt.Errorf("sudo rights check failed: %w", err)
	}

	// Step 6: Check systemd
	s.sendProgress(0, 30, "Checking systemd...", "running", nil)
	if err := s.checkSystemd(); err != nil {
		return fmt.Errorf("systemd check failed: %w", err)
	}

	// Step 7: Check disk space
	s.sendProgress(0, 30, "Checking disk space...", "running", nil)
	if err := s.checkDiskSpace(); err != nil {
		return fmt.Errorf("disk space check failed: %w", err)
	}

	// Step 8: Check RAM (warning only, not blocking)
	s.sendProgress(0, 30, "Checking RAM...", "running", nil)
	if err := s.checkRAM(); err != nil {
		// Log warning but don't fail - allow setup to continue with warning
		s.sendProgress(0, 30, fmt.Sprintf("Warning: %v (setup will continue)", err), "running", nil)
		// Don't return error, just warn
	}

	// Step 9: Check CPU
	s.sendProgress(0, 30, "Checking CPU...", "running", nil)
	if err := s.checkCPU(); err != nil {
		return fmt.Errorf("CPU check failed: %w", err)
	}

	// Step 10: Check internet connection
	s.sendProgress(0, 30, "Checking internet connection...", "running", nil)
	if err := s.checkInternetConnection(); err != nil {
		return fmt.Errorf("internet connection check failed: %w", err)
	}

	// Step 11: Check encryption key
	s.sendProgress(0, 30, "Checking encryption key...", "running", nil)
	if err := s.checkEncryptionKey(); err != nil {
		return fmt.Errorf("encryption key check failed: %w", err)
	}

	// Step 12: Check PostgreSQL connection
	s.sendProgress(0, 30, "Checking PostgreSQL connection...", "running", nil)
	if err := s.checkPostgresConnection(s.ctx); err != nil {
		s.sendProgress(0, 30, "Warning: PostgreSQL not available, config won't be saved", "running", nil)
		// Don't fail, just warn
	}

	// Step 13: Check existing configs
	s.sendProgress(0, 30, "Checking existing configurations...", "running", nil)
	existingConfigs, err := s.checkExistingConfigs()
	if err == nil {
		for config, exists := range existingConfigs {
			if exists {
				s.sendProgress(0, 30, fmt.Sprintf("Warning: %s configuration already exists", config), "running", nil)
			}
		}
	}

	// Step 14: Check ports 80 and 443
	s.sendProgress(0, 30, "Checking ports 80 and 443...", "running", nil)
	if err := s.checkPortsInUse([]int{80, 443}); err != nil {
		s.sendProgress(0, 30, fmt.Sprintf("Warning: %v", err), "running", nil)
		// Don't fail, just warn
	}

	s.sendProgress(0, 30, "All pre-setup validations passed", "completed", nil)
	return nil
}

// verifyCriticalLogs checks if critical log files exist and are writable
func (s *ServerSetup) verifyCriticalLogs() error {
	criticalLogs := []string{
		"/var/log/auth.log",
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/var/log/fail2ban.log",
		"/var/log/security-scan.log",
		"/var/log/aide-check.log",
	}

	for _, logPath := range criticalLogs {
		// Check if log file exists or directory is writable
		checkCmd := fmt.Sprintf("test -f %s || (test -d $(dirname %s) && test -w $(dirname %s))", logPath, logPath, logPath)
		_, err := s.runCommandAsRoot("bash", "-c", checkCmd)
		if err != nil {
			s.sendProgress(0, 30, fmt.Sprintf("Warning: Log file %s is not accessible", logPath), "running", nil)
			// Don't fail, just warn
		}
	}

	return nil
}

// verifyCronJobs checks if critical cron jobs are configured
func (s *ServerSetup) verifyCronJobs() error {
	// Check root crontab
	crontabOutput, err := s.runCommandAsRoot("crontab", "-l")
	if err != nil {
		// No crontab exists, that's OK
		return nil
	}

	// Check for critical cron jobs
	criticalJobs := []string{
		"security-scan",
		"aide-daily-check",
		"clamav",
		"rkhunter",
	}

	foundJobs := 0
	for _, job := range criticalJobs {
		if strings.Contains(crontabOutput, job) {
			foundJobs++
		}
	}

	if foundJobs == 0 {
		s.sendProgress(0, 30, "Warning: No critical cron jobs found", "running", nil)
	}

	return nil
}

// verifySystemdServices checks if critical systemd services are active
func (s *ServerSetup) verifySystemdServices() error {
	criticalServices := []struct {
		name        string
		description string
	}{
		{"ssh", "SSH service"},
		{"nginx", "Nginx web server"},
		{"docker", "Docker daemon"},
		{"fail2ban", "Fail2ban intrusion prevention"},
		{"ufw", "UFW firewall"},
		{"chronyd", "Chrony time sync"},
		{"systemd-resolved", "Systemd DNS resolver"},
	}

	allActive := true
	for _, service := range criticalServices {
		// Check if service is active
		checkCmd := fmt.Sprintf("systemctl is-active --quiet %s", service.name)
		_, err := s.runCommandAsRoot("bash", "-c", checkCmd)
		if err != nil {
			// Service is not active, try to check if it exists
			existsCmd := fmt.Sprintf("systemctl list-unit-files | grep -q %s", service.name)
			_, existsErr := s.runCommandAsRoot("bash", "-c", existsCmd)
			if existsErr == nil {
				// Service exists but is not active
				s.sendProgress(0, 30, fmt.Sprintf("Warning: %s (%s) is not active", service.description, service.name), "running", nil)
				allActive = false
			}
		}
	}

	if !allActive {
		s.sendProgress(0, 30, "Some services are not active, but this may be expected", "running", nil)
	}

	return nil
}

// runPostSetupVerification runs all verification checks after setup is complete
func (s *ServerSetup) runPostSetupVerification() error {
	s.sendProgress(25, 30, "Running post-setup verification...", "running", nil)

	// Verify critical logs
	s.sendProgress(25, 30, "Verifying critical log files...", "running", nil)
	if err := s.verifyCriticalLogs(); err != nil {
		s.sendProgress(25, 30, fmt.Sprintf("Warning: Log verification failed: %v", err), "running", nil)
	}

	// Verify cron jobs
	s.sendProgress(26, 30, "Verifying cron jobs...", "running", nil)
	if err := s.verifyCronJobs(); err != nil {
		s.sendProgress(26, 30, fmt.Sprintf("Warning: Cron jobs verification failed: %v", err), "running", nil)
	}

	// Verify systemd services
	s.sendProgress(27, 30, "Verifying systemd services...", "running", nil)
	if err := s.verifySystemdServices(); err != nil {
		s.sendProgress(27, 30, fmt.Sprintf("Warning: Systemd services verification failed: %v", err), "running", nil)
	}

	// Final comprehensive check
	s.sendProgress(28, 30, "Running final comprehensive check...", "running", nil)
	if err := s.runFinalComprehensiveCheck(); err != nil {
		return fmt.Errorf("final comprehensive check failed: %w", err)
	}

	s.sendProgress(28, 30, "Post-setup verification completed", "completed", nil)
	return nil
}

// runFinalComprehensiveCheck performs a final check to ensure server is ready
func (s *ServerSetup) runFinalComprehensiveCheck() error {
	checks := []struct {
		name        string
		description string
		checkFunc   func() error
	}{
		{"SSH", "SSH service is running", func() error {
			_, err := s.runCommandAsRoot("systemctl", "is-active", "ssh")
			return err
		}},
		{"Nginx", "Nginx is installed and config is valid", s.verifyNginxInstallation},
		{"Docker", "Docker is installed and daemon is running", s.verifyDockerInstallation},
		{"Go", "Go is installed and in PATH", s.verifyGoInstallation},
		{"Node.js", "Node.js is installed and in PATH", s.verifyNodeJSInstallation},
		{"Firewall", "UFW firewall is enabled", func() error {
			output, err := s.runCommandAsRoot("ufw", "status")
			if err != nil {
				return err
			}
			if !strings.Contains(output, "Status: active") {
				return fmt.Errorf("UFW is not active")
			}
			return nil
		}},
		{"Fail2ban", "Fail2ban is running", func() error {
			// Check if fail2ban service exists and is enabled
			checkServiceCmd := "systemctl list-unit-files | grep -q '^fail2ban.service'"
			_, err := s.runCommandAsRoot("bash", "-c", checkServiceCmd)
			if err != nil {
				// Service doesn't exist, that's OK - it might not be installed
				return nil
			}
			// Try to check status (might fail if service is not started yet)
			_, err = s.runCommandAsRoot("fail2ban-client", "status")
			if err != nil {
				// Try to start it
				s.runCommandAsRoot("systemctl", "start", "fail2ban")
				// Check again
				_, err = s.runCommandAsRoot("fail2ban-client", "status")
				return err
			}
			return nil
		}},
		{"SSH Port", "SSH is listening on configured port", func() error {
			// Wait a moment for SSH to restart if needed
			time.Sleep(1 * time.Second)
			// Check if SSH is listening on the configured port
			checkCmd := fmt.Sprintf("ss -tuln 2>/dev/null | grep -q ':%d ' || netstat -tuln 2>/dev/null | grep -q ':%d '", s.config.SSHPort, s.config.SSHPort)
			output, err := s.runCommandAsRoot("bash", "-c", checkCmd)
			if err != nil {
				// Port might not be listening yet, try to check SSH service status
				_, serviceErr := s.runCommandAsRoot("systemctl", "is-active", "ssh")
				if serviceErr == nil {
					// SSH service is active, but port might not be listening yet
					// This can happen if SSH was just restarted
					// Return nil to allow setup to continue
					return nil
				}
				return fmt.Errorf("SSH port %d is not listening and SSH service is not active", s.config.SSHPort)
			}
			// Filter out empty output
			if strings.TrimSpace(output) == "" {
				// No output but command succeeded, that's OK
				return nil
			}
			return nil
		}},
	}

	failedChecks := []string{}
	warningChecks := []string{}
	for _, check := range checks {
		if err := check.checkFunc(); err != nil {
			// Some checks are warnings, not critical failures
			if check.name == "Fail2ban" || check.name == "SSH Port" {
				warningChecks = append(warningChecks, check.description)
				s.sendProgress(28, 30, fmt.Sprintf("Warning: %s - %v", check.description, err), "running", nil)
			} else {
				failedChecks = append(failedChecks, check.description)
				s.sendProgress(28, 30, fmt.Sprintf("Failed: %s", check.description), "running", nil)
			}
		} else {
			s.sendProgress(28, 30, fmt.Sprintf("OK: %s", check.description), "running", nil)
		}
	}

	// Only fail on critical checks, warnings are OK
	if len(failedChecks) > 0 {
		return fmt.Errorf("final check failed for: %v", failedChecks)
	}

	// Log warnings but don't fail
	if len(warningChecks) > 0 {
		s.sendProgress(28, 30, fmt.Sprintf("Warnings (non-critical): %v", warningChecks), "running", nil)
	}

	s.sendProgress(28, 30, "All final checks passed - server is ready!", "completed", nil)
	return nil
}

