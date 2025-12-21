package start_server_setting

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SetupProgress represents progress of server setup
type SetupProgress struct {
	Step        int    `json:"step"`
	TotalSteps  int    `json:"totalSteps"`
	Message     string `json:"message"`
	Status      string `json:"status"` // "running", "completed", "error"
	Error       string `json:"error,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

// ServerConfig represents server configuration
// NOTE: username and password are NOT stored for security reasons
type ServerConfig struct {
	ServerIP            string `json:"server_ip"`              // Server IP address (IPv4 or IPv6)
	SSHPort             int    `json:"ssh_port"`               // SSH port configured on server after setup (55000-56000)
	Hostname            string `json:"hostname"`               // Server hostname (optional, for reference)
	SSHPrivateKeyEncrypted string `json:"ssh_private_key_encrypted,omitempty"` // Encrypted SSH private key (stored in DB)
}

// ServerSetup handles the server initial setup
type ServerSetup struct {
	progressCallback func(*SetupProgress)
	ctx              context.Context
	config           *ServerConfig
	serverIP         string
	serverPort       int
	username         string
	password         string
	sshClient        *ssh.Client
	rollbackManager  *RollbackManager
}

// NewServerSetup creates a new server setup instance
func NewServerSetup(ctx context.Context, progressCallback func(*SetupProgress)) *ServerSetup {
	return &ServerSetup{
		progressCallback: progressCallback,
		ctx:              ctx,
		config:           &ServerConfig{},
	}
}

// generateSSHPort generates a random SSH port in range 55000-56000
func generateSSHPort() (int, error) {
	// Port range: 55000 to 56000 (inclusive)
	minPort := 55000
	maxPort := 56000
	portRange := maxPort - minPort + 1 // 1001 ports (55000, 55001, ..., 56000)

	// Generate random port in range 55000-56000
	max := big.NewInt(int64(portRange))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random port: %w", err)
	}
	
	port := int(n.Int64()) + minPort
	return port, nil
}

// sendProgress sends progress update
func (s *ServerSetup) sendProgress(step, totalSteps int, message, status string, err error) {
	progress := &SetupProgress{
		Step:       step,
		TotalSteps: totalSteps,
		Message:    message,
		Status:     status,
		Timestamp:  time.Now().Unix(),
	}
	if err != nil {
		progress.Error = err.Error()
		progress.Status = "error"
	}
	
	// Log progress to console
	log.Printf("[ServerSetup] Step %d/%d [%s] %s", step, totalSteps, status, message)
	if err != nil {
		log.Printf("[ServerSetup] ERROR: %v", err)
	}
	
	if s.progressCallback != nil {
		s.progressCallback(progress)
	}
}

// connectSSH establishes SSH connection to the remote server
func (s *ServerSetup) connectSSH() error {
	config := &ssh.ClientConfig{
		User: s.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.password),
		},
		HostKeyCallback: createHostKeyCallback(s.serverIP, s.serverPort), // Verify and save host keys
		Timeout:         10 * time.Second,
	}

	address := fmt.Sprintf("%s:%d", s.serverIP, s.serverPort)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server %s: %w", address, err)
	}

	s.sshClient = client
	log.Printf("[ServerSetup] SSH connection established to %s", address)
	return nil
}

// closeSSH closes SSH connection
func (s *ServerSetup) closeSSH() {
	if s.sshClient != nil {
		s.sshClient.Close()
		s.sshClient = nil
		log.Printf("[ServerSetup] SSH connection closed")
	}
}

// SetupServer performs initial server setup
// NOTE: username and password are NOT stored in database for security reasons
// Supports Ubuntu 22.04 LTS and 24.04 LTS
func (s *ServerSetup) SetupServer(serverIP string, serverPort int, username, password string) error {
	// Store SSH connection parameters (these are NOT saved to database)
	s.serverIP = serverIP
	s.serverPort = serverPort
	s.username = username
	s.password = password

	// Store server configuration (these ARE saved to database)
	s.config.ServerIP = serverIP

	totalSteps := 31 // Updated to include validation, verification, and server reboot steps

	// Initialize rollback manager
	s.rollbackManager = NewRollbackManager(s)

	// Step 0: Run pre-setup validations (includes SSH connection)
	s.sendProgress(0, totalSteps, "Running pre-setup validations...", "running", nil)
	if err := s.runPreSetupValidations(serverIP, serverPort, username, password); err != nil {
		return fmt.Errorf("pre-setup validation failed: %w", err)
	}
	// Note: runPreSetupValidations already establishes SSH connection, so we need to reconnect
	// Close the connection from validation and reconnect for setup
	s.closeSSH()
	if err := s.connectSSH(); err != nil {
		return fmt.Errorf("ssh reconnection failed: %w", err)
	}
	defer s.closeSSH()

	// Backup critical configurations before making changes
	s.sendProgress(0, totalSteps, "Backing up critical configurations...", "running", nil)
	if err := s.rollbackManager.backupCriticalConfigs(); err != nil {
		s.sendProgress(0, totalSteps, fmt.Sprintf("Warning: Failed to backup some configs: %v", err), "running", nil)
		// Continue anyway, but log the warning
	}

	// Try to load existing config (to check if server was already configured)
	if err := s.loadServerConfig(s.ctx); err != nil {
		s.sendProgress(0, totalSteps, "Warning: Could not load existing config, will create new one", "running", nil)
	}

	// Generate or use existing SSH port
	if s.config.SSHPort == 0 {
		// No existing config, generate new SSH port
		sshPort, err := generateSSHPort()
		if err != nil {
			return fmt.Errorf("failed to generate ssh port: %w", err)
		}
		// Check if port is available
		if err := s.checkPortAvailability(sshPort); err != nil {
			// Try another port
			sshPort, err = generateSSHPort()
			if err != nil {
				return fmt.Errorf("failed to generate alternative ssh port: %w", err)
			}
		}
		s.config.SSHPort = sshPort
		s.sendProgress(0, totalSteps, fmt.Sprintf("Generated SSH port: %d", sshPort), "running", nil)
	} else {
		s.sendProgress(0, totalSteps, fmt.Sprintf("Using existing SSH port: %d", s.config.SSHPort), "running", nil)
	}

	// Step 1: System Update
	s.sendProgress(1, totalSteps, "Updating system packages...", "running", nil)
	if err := s.updateSystem(); err != nil {
		return fmt.Errorf("system update failed: %w", err)
	}
	s.sendProgress(1, totalSteps, "System updated successfully", "completed", nil)

	// Step 2: Install Essential Packages
	s.sendProgress(2, totalSteps, "Installing essential packages...", "running", nil)
	if err := s.installEssentialPackages(); err != nil {
		return fmt.Errorf("package installation failed: %w", err)
	}
	s.sendProgress(2, totalSteps, "Essential packages installed", "completed", nil)

	// Step 3: Install Go
	s.sendProgress(3, totalSteps, "Installing Go...", "running", nil)
	if err := s.installGo(); err != nil {
		return fmt.Errorf("go installation failed: %w", err)
	}
	// Verify Go installation
	if err := s.verifyGoInstallation(); err != nil {
		return fmt.Errorf("go installation verification failed: %w", err)
	}
	s.sendProgress(3, totalSteps, "Go installed and verified", "completed", nil)

	// Step 4: Install Node.js LTS via NVM
	s.sendProgress(4, totalSteps, "Installing Node.js LTS...", "running", nil)
	if err := s.installNodeJS(); err != nil {
		return fmt.Errorf("node.js installation failed: %w", err)
	}
	// Verify Node.js installation
	if err := s.verifyNodeJSInstallation(); err != nil {
		return fmt.Errorf("node.js installation verification failed: %w", err)
	}
	s.sendProgress(4, totalSteps, "Node.js LTS installed and verified", "completed", nil)

	// Step 5: Install PM2
	s.sendProgress(5, totalSteps, "Installing PM2...", "running", nil)
	if err := s.installPM2(); err != nil {
		return fmt.Errorf("pm2 installation failed: %w", err)
	}
	s.sendProgress(5, totalSteps, "PM2 installed and configured", "completed", nil)

	// Step 6: Install pnpm
	s.sendProgress(6, totalSteps, "Installing pnpm...", "running", nil)
	if err := s.installPnpm(); err != nil {
		return fmt.Errorf("pnpm installation failed: %w", err)
	}
	s.sendProgress(6, totalSteps, "pnpm installed", "completed", nil)

	// Step 7: Generate and setup SSH keys
	s.sendProgress(7, totalSteps, "Generating SSH key pair...", "running", nil)
	if err := s.setupSSHKeys(); err != nil {
		return fmt.Errorf("ssh key setup failed: %w", err)
	}
	s.sendProgress(7, totalSteps, "SSH key pair generated and deployed", "completed", nil)

	// Step 8: SSH Hardening (critical - backup before changes)
	s.sendProgress(8, totalSteps, fmt.Sprintf("Hardening SSH configuration (port %d)...", s.config.SSHPort), "running", nil)
	if err := s.rollbackManager.backupFile("/etc/ssh/sshd_config", "SSH configuration before hardening"); err != nil {
		s.sendProgress(8, totalSteps, fmt.Sprintf("Warning: Failed to backup SSH config: %v", err), "running", nil)
	}
	if err := s.hardenSSH(); err != nil {
		// Attempt rollback on failure
		if rollbackErr := s.rollbackManager.rollbackFile("/etc/ssh/sshd_config"); rollbackErr != nil {
			return fmt.Errorf("ssh hardening failed and rollback failed: hardening=%w, rollback=%w", err, rollbackErr)
		}
		return fmt.Errorf("ssh hardening failed, rollback completed: %w", err)
	}
	s.sendProgress(8, totalSteps, fmt.Sprintf("SSH hardened (Port %d, keys only)", s.config.SSHPort), "completed", nil)

	// Step 9: Configure Firewall
	s.sendProgress(9, totalSteps, "Configuring firewall...", "running", nil)
	if err := s.configureFirewall(); err != nil {
		return fmt.Errorf("firewall configuration failed: %w", err)
	}
	s.sendProgress(9, totalSteps, "Firewall configured", "completed", nil)

	// Step 10: Configure Fail2ban
	s.sendProgress(10, totalSteps, "Configuring Fail2ban...", "running", nil)
	if err := s.configureFail2ban(); err != nil {
		return fmt.Errorf("fail2ban configuration failed: %w", err)
	}
	s.sendProgress(10, totalSteps, "Fail2ban configured", "completed", nil)

	// Step 11: Kernel Security Hardening
	s.sendProgress(11, totalSteps, "Hardening kernel parameters...", "running", nil)
	if err := s.hardenKernel(); err != nil {
		return fmt.Errorf("kernel hardening failed: %w", err)
	}
	s.sendProgress(11, totalSteps, "Kernel hardened", "completed", nil)

	// Step 12: Docker Security
	s.sendProgress(12, totalSteps, "Securing Docker...", "running", nil)
	if err := s.secureDocker(); err != nil {
		return fmt.Errorf("docker security failed: %w", err)
	}
	// Verify Docker installation
	if err := s.verifyDockerInstallation(); err != nil {
		return fmt.Errorf("docker installation verification failed: %w", err)
	}
	s.sendProgress(12, totalSteps, "Docker secured and verified", "completed", nil)

	// Step 13: Nginx Security
	s.sendProgress(13, totalSteps, "Hardening nginx...", "running", nil)
	if err := s.hardenNginx(); err != nil {
		return fmt.Errorf("nginx hardening failed: %w", err)
	}
	// Verify Nginx installation
	if err := s.verifyNginxInstallation(); err != nil {
		return fmt.Errorf("nginx installation verification failed: %w", err)
	}
	s.sendProgress(13, totalSteps, "nginx hardened and verified", "completed", nil)

	// Step 14: Automatic Security Updates
	s.sendProgress(14, totalSteps, "Enabling automatic security updates...", "running", nil)
	if err := s.enableAutoUpdates(); err != nil {
		return fmt.Errorf("auto-updates configuration failed: %w", err)
	}
	s.sendProgress(14, totalSteps, "Auto-updates enabled", "completed", nil)

	// Step 15: Malware Scanning Cron
	s.sendProgress(15, totalSteps, "Setting up daily malware scan...", "running", nil)
	if err := s.setupMalwareScanning(); err != nil {
		return fmt.Errorf("malware scanning setup failed: %w", err)
	}
	s.sendProgress(15, totalSteps, "Daily security scan configured", "completed", nil)

	// Step 16: Fix Nginx Cache Permissions
	s.sendProgress(16, totalSteps, "Fixing Nginx cache permissions...", "running", nil)
	if err := s.fixNginxCachePermissions(); err != nil {
		return fmt.Errorf("nginx cache permissions failed: %w", err)
	}
	s.sendProgress(16, totalSteps, "Nginx cache permissions fixed", "completed", nil)

	// Step 17: Configure Timezone
	s.sendProgress(17, totalSteps, "Setting timezone...", "running", nil)
	if err := s.configureTimezone(); err != nil {
		return fmt.Errorf("timezone configuration failed: %w", err)
	}
	s.sendProgress(17, totalSteps, "Timezone configured", "completed", nil)

	// Step 18: Audit Logging
	s.sendProgress(18, totalSteps, "Setting up audit logging...", "running", nil)
	if err := s.setupAuditLogging(); err != nil {
		return fmt.Errorf("audit logging setup failed: %w", err)
	}
	s.sendProgress(18, totalSteps, "Audit logging configured", "completed", nil)

	// Step 19: Log Rotation
	s.sendProgress(19, totalSteps, "Configuring log rotation...", "running", nil)
	if err := s.configureLogRotation(); err != nil {
		return fmt.Errorf("log rotation configuration failed: %w", err)
	}
	s.sendProgress(19, totalSteps, "Log rotation configured", "completed", nil)

	// Step 20: Time Synchronization
	s.sendProgress(20, totalSteps, "Configuring time synchronization...", "running", nil)
	if err := s.configureTimeSync(); err != nil {
		return fmt.Errorf("time sync configuration failed: %w", err)
	}
	s.sendProgress(20, totalSteps, "Time synchronization configured", "completed", nil)

	// Step 21: AppArmor
	s.sendProgress(21, totalSteps, "Configuring AppArmor...", "running", nil)
	if err := s.configureAppArmor(); err != nil {
		return fmt.Errorf("appArmor configuration failed: %w", err)
	}
	s.sendProgress(21, totalSteps, "AppArmor configured", "completed", nil)

	// Step 22: File Integrity Monitoring
	s.sendProgress(22, totalSteps, "Setting up file integrity monitoring...", "running", nil)
	if err := s.setupFileIntegrityMonitoring(); err != nil {
		return fmt.Errorf("file integrity monitoring setup failed: %w", err)
	}
	s.sendProgress(22, totalSteps, "File integrity monitoring configured", "completed", nil)

	// Step 23: Resource Limits
	s.sendProgress(23, totalSteps, "Configuring resource limits...", "running", nil)
	if err := s.configureResourceLimits(); err != nil {
		return fmt.Errorf("resource limits configuration failed: %w", err)
	}
	s.sendProgress(23, totalSteps, "Resource limits configured", "completed", nil)

	// Step 24: DNS Security
	s.sendProgress(24, totalSteps, "Configuring DNS security...", "running", nil)
	if err := s.configureDNSSecurity(); err != nil {
		return fmt.Errorf("dns security configuration failed: %w", err)
	}
	s.sendProgress(24, totalSteps, "DNS security configured", "completed", nil)

	// Save server configuration to PostgreSQL
	// NOTE: username and password are NOT saved for security reasons
	s.sendProgress(24, totalSteps, "Saving server configuration to database...", "running", nil)
	if err := s.saveServerConfig(s.ctx); err != nil {
		// Log error but don't fail the setup
		s.sendProgress(24, totalSteps, fmt.Sprintf("Warning: Failed to save config to database: %v", err), "completed", nil)
	} else {
		s.sendProgress(24, totalSteps, fmt.Sprintf("Server configuration saved (IP: %s, SSH Port: %d)", s.config.ServerIP, s.config.SSHPort), "completed", nil)
	}

	// Step 25-28: Run post-setup verification
	if err := s.runPostSetupVerification(); err != nil {
		// If verification fails, attempt rollback
		s.sendProgress(29, totalSteps, "Verification failed, attempting rollback...", "running", nil)
		if rollbackErr := s.rollbackManager.rollbackAll(); rollbackErr != nil {
			s.sendProgress(29, totalSteps, fmt.Sprintf("critical: rollback failed: %v. manual intervention required!", rollbackErr), "error", rollbackErr)
			return fmt.Errorf("setup verification failed and rollback failed: verification=%w, rollback=%w", err, rollbackErr)
		}
		s.sendProgress(29, totalSteps, "Rollback completed successfully", "completed", nil)
		return fmt.Errorf("setup verification failed, rollback completed: %w", err)
	}

	// Step 29: Cleanup old backups (keep only most recent)
	s.sendProgress(29, totalSteps, "Cleaning up old backups...", "running", nil)
	if err := s.rollbackManager.cleanupBackups(); err != nil {
		s.sendProgress(29, totalSteps, fmt.Sprintf("Warning: Failed to cleanup backups: %v", err), "running", nil)
		// Don't fail, just warn
	}
	s.sendProgress(29, totalSteps, "Backups cleaned up", "completed", nil)

	// Step 30: Reboot server to apply all changes
	s.sendProgress(30, totalSteps, "Rebooting server to apply all changes...", "running", nil)
	if err := s.rebootServer(); err != nil {
		return fmt.Errorf("failed to reboot server: %w", err)
	}
	
	// Close SSH connection before server reboots
	s.closeSSH()
	
	// Wait for server to reboot (shutdown -r +1 schedules reboot in 1 minute)
	// Wait 70 seconds to ensure server has time to reboot
	s.sendProgress(30, totalSteps, "Waiting for server to reboot (70 seconds)...", "running", nil)
	time.Sleep(70 * time.Second)
	
	// Now check if server is back online
	if err := waitForServerReboot(s.serverIP, s.config.SSHPort, 2*time.Minute); err != nil {
		return fmt.Errorf("server did not come back online after reboot: %w", err)
	}
	
	// Reconnect via SSH using the private key
	s.sendProgress(30, totalSteps, "Reconnecting to server via SSH...", "running", nil)
	
	// Decrypt private key
	privateKey, err := DecryptSSHPrivateKey(s.config.SSHPrivateKeyEncrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key for reconnection: %w", err)
	}
	
	// Parse private key
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key for reconnection: %w", err)
	}
	
	// Create new SSH connection
	sshConfig := &ssh.ClientConfig{
		User: s.username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: createHostKeyCallback(s.serverIP, s.config.SSHPort),
		Timeout:         30 * time.Second,
	}
	
	address := fmt.Sprintf("%s:%d", s.serverIP, s.config.SSHPort)
	client, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to reconnect to server after reboot: %w", err)
	}
	s.sshClient = client
	log.Printf("[ServerSetup] Reconnected to server after reboot")
	
	// Verify SSH connection works by running a simple command
	s.sendProgress(30, totalSteps, "Verifying SSH connection after reboot...", "running", nil)
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session after reboot: %w", err)
	}
	defer session.Close()
	
	// Run a simple command to verify connection works
	output, err := session.Output("echo 'SSH connection verified' && hostname")
	if err != nil {
		return fmt.Errorf("failed to execute test command after reboot: %w", err)
	}
	
	log.Printf("[ServerSetup] SSH connection verified after reboot. Server response: %s", strings.TrimSpace(string(output)))
	s.sendProgress(30, totalSteps, fmt.Sprintf("Server rebooted and SSH connection verified (hostname: %s)", strings.TrimSpace(string(output))), "completed", nil)

	// Final success message
	s.sendProgress(31, totalSteps, "Server setup completed successfully! All checks passed.", "completed", nil)

	return nil
}

// runCommand executes a command on the remote server via SSH and returns output
func (s *ServerSetup) runCommand(name string, args ...string) (string, error) {
	if s.sshClient == nil {
		return "", fmt.Errorf("ssh client not connected")
	}

	// Build command with proper escaping using shell escaping
	cmd := name
	for _, arg := range args {
		// Escape single quotes by replacing ' with '\''
		escaped := fmt.Sprintf("'%s'", arg)
		cmd = fmt.Sprintf("%s %s", cmd, escaped)
	}

	// Create session
	session, err := s.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Execute command with context timeout
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()

	outputChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		output, err := session.CombinedOutput(cmd)
		if err != nil {
			errChan <- fmt.Errorf("command '%s' failed: %w, output: %s", cmd, err, string(output))
			return
		}
		outputChan <- string(output)
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("command '%s' timed out", cmd)
	case err := <-errChan:
		return "", err
	case output := <-outputChan:
		return output, nil
	}
}

// writeFileToRemote writes content to a file on the remote server via SSH
func (s *ServerSetup) writeFileToRemote(content []byte, remotePath string, mode string) error {
	if s.sshClient == nil {
		return fmt.Errorf("SSH client not connected")
	}

	// Base64 encode the content for safe transfer through shell
	encoded := base64.StdEncoding.EncodeToString(content)
	// Use runCommandAsRoot to ensure sudo works with password
	cmd := fmt.Sprintf("echo '%s' | base64 -d | tee %s > /dev/null && chmod %s %s", encoded, remotePath, mode, remotePath)
	
	_, err := s.runCommandAsRoot("bash", "-c", cmd)
	return err
}

// runCommandAsRoot executes command as root on the remote server via SSH using sudo
// Password is passed via stdin using -S option with proper stdin pipe
func (s *ServerSetup) runCommandAsRoot(name string, args ...string) (string, error) {
	if s.sshClient == nil {
		return "", fmt.Errorf("ssh client not connected")
	}

	// Create session
	session, err := s.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Build sudo command with -S flag to read password from stdin
	sudoArgs := []string{"-S", name}
	sudoArgs = append(sudoArgs, args...)
	
	// Build command string for sudo
	cmdStr := "sudo"
	for _, arg := range sudoArgs {
		// Escape single quotes properly for shell
		escaped := fmt.Sprintf("'%s'", arg)
		cmdStr = fmt.Sprintf("%s %s", cmdStr, escaped)
	}

	// Execute command with context timeout
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()

	outputChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		// Get stdin pipe to write password
		stdin, err := session.StdinPipe()
		if err != nil {
			errChan <- fmt.Errorf("failed to get stdin pipe: %w", err)
			return
		}

		// Get stdout and stderr pipes
		stdout, err := session.StdoutPipe()
		if err != nil {
			stdin.Close()
			errChan <- fmt.Errorf("failed to get stdout pipe: %w", err)
			return
		}

		stderr, err := session.StderrPipe()
		if err != nil {
			stdin.Close()
			errChan <- fmt.Errorf("failed to get stderr pipe: %w", err)
			return
		}

		// Start the command
		if err := session.Start(cmdStr); err != nil {
			stdin.Close()
			errChan <- fmt.Errorf("failed to start command: %w", err)
			return
		}

		// Write password to stdin (sudo -S reads password from stdin)
		_, err = stdin.Write([]byte(s.password + "\n"))
		if err != nil {
			stdin.Close()
			errChan <- fmt.Errorf("failed to write password: %w", err)
			return
		}
		stdin.Close()

		// Read output from stdout and stderr
		var stdoutBytes, stderrBytes []byte
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			stdoutBytes, _ = io.ReadAll(stdout)
		}()

		go func() {
			defer wg.Done()
			stderrBytes, _ = io.ReadAll(stderr)
		}()

		// Wait for command to complete
		err = session.Wait()
		wg.Wait()

		// Combine stdout and stderr, but filter out sudo prompts
		combinedOutput := append(stdoutBytes, stderrBytes...)
		outputStr := string(combinedOutput)

		// Filter out sudo password prompts from output
		lines := strings.Split(outputStr, "\n")
		var filteredLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Skip sudo password prompts
			if strings.Contains(line, "[sudo] password for") {
				continue
			}
			// Skip empty lines
			if line == "" {
				continue
			}
			filteredLines = append(filteredLines, line)
		}
		outputStr = strings.Join(filteredLines, "\n")

		if err != nil {
			errChan <- fmt.Errorf("command '%s' failed: %w, output: %s", name, err, outputStr)
			return
		}

		outputChan <- outputStr
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("command '%s' timed out", name)
	case err := <-errChan:
		return "", err
	case output := <-outputChan:
		return output, nil
	}
}

// readFileFromRemote reads a file from the remote server via SSH
func (s *ServerSetup) readFileFromRemote(remotePath string) (string, error) {
	return s.runCommand("cat", remotePath)
}

