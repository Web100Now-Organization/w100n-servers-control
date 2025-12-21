package start_server_setting

import (
	"fmt"
	"log"
	"strings"
)

// updateSystem updates system packages
func (s *ServerSetup) updateSystem() error {
	if _, err := s.runCommandAsRoot("apt", "update"); err != nil {
		return err
	}
	if _, err := s.runCommandAsRoot("apt", "upgrade", "-y"); err != nil {
		return err
	}
	if _, err := s.runCommandAsRoot("apt", "autoremove", "-y"); err != nil {
		return err
	}
	return nil
}

// installEssentialPackages installs essential system packages
func (s *ServerSetup) installEssentialPackages() error {
	packages := []string{
		"nginx",
		"docker.io",
		"docker-compose",
		"nodejs",
		"npm",
		"curl",
		"wget",
		"git",
		"ufw",
		"fail2ban",
		"iptables",
		"htop",
		"net-tools",
		"rkhunter",
		"chkrootkit",
		"clamav",
		"clamav-daemon",
		"unattended-upgrades",
		"logrotate",
		"rsync",
	}

	args := append([]string{"install", "-y"}, packages...)
	_, err := s.runCommandAsRoot("apt", args...)
	return err
}

// installGo installs Go 1.23.6
func (s *ServerSetup) installGo() error {
	goVersion := "1.23.6"
	goURL := fmt.Sprintf("https://go.dev/dl/go%s.linux-amd64.tar.gz", goVersion)
	
	// Download Go
	if _, err := s.runCommand("wget", goURL); err != nil {
		return fmt.Errorf("failed to download Go: %w", err)
	}

	// Remove old Go installation
	s.runCommandAsRoot("rm", "-rf", "/usr/local/go")

	// Extract Go
	tarFile := fmt.Sprintf("go%s.linux-amd64.tar.gz", goVersion)
	if _, err := s.runCommandAsRoot("tar", "-C", "/usr/local", "-xzf", tarFile); err != nil {
		return fmt.Errorf("failed to extract Go: %w", err)
	}

	// Cleanup
	// Remove downloaded file
	s.runCommand("rm", "-f", tarFile)

	// Add to PATH in .bashrc and also in /etc/profile.d for system-wide access
	bashrcPath := "/root/.bashrc"
	profileDPath := "/etc/profile.d/go.sh"
	goPath := "export PATH=$PATH:/usr/local/go/bin"
	gopathVar := "export GOPATH=$HOME/go"
	binPath := "export PATH=$PATH:$GOPATH/bin"

	// Add to .bashrc for root user
	bashrcContent, err := s.readFileFromRemote(bashrcPath)
	if err == nil {
		if !strings.Contains(bashrcContent, goPath) {
			appendContent := "\n" + goPath + "\n" + gopathVar + "\n" + binPath + "\n"
			_, err := s.runCommand("bash", "-c", fmt.Sprintf("echo '%s' >> %s", appendContent, bashrcPath))
			if err != nil {
				log.Printf("Warning: Failed to append to .bashrc: %v", err)
			}
		}
	}

	// Create system-wide profile script for Go
	goProfileScript := fmt.Sprintf(`#!/bin/bash
%s
%s
%s
`, goPath, gopathVar, binPath)
	if err := s.writeFileToRemote([]byte(goProfileScript), profileDPath, "644"); err != nil {
		log.Printf("Warning: Failed to create /etc/profile.d/go.sh: %v", err)
	}

	return nil
}

// installNodeJS installs Node.js LTS via NVM
func (s *ServerSetup) installNodeJS() error {
	// Install NVM
	nvmScript := "https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh"
	if _, err := s.runCommand("curl", "-o-", nvmScript); err != nil {
		return fmt.Errorf("failed to download NVM: %w", err)
	}

	// Run NVM install script
	if _, err := s.runCommand("bash", "-c", "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash"); err != nil {
		return fmt.Errorf("failed to install NVM: %w", err)
	}

	// Source NVM and install Node.js LTS
	nvmCmd := `export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && nvm install --lts && nvm use --lts && nvm alias default node`
	if _, err := s.runCommand("bash", "-c", nvmCmd); err != nil {
		return fmt.Errorf("failed to install Node.js LTS: %w", err)
	}

	return nil
}

// installPM2 installs PM2 globally
func (s *ServerSetup) installPM2() error {
	nvmCmd := `export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && npm install -g pm2`
	if _, err := s.runCommand("bash", "-c", nvmCmd); err != nil {
		return fmt.Errorf("failed to install PM2: %w", err)
	}

	// Setup PM2 startup
	pm2StartupCmd := `export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && pm2 startup systemd -u root --hp /root`
	if _, err := s.runCommand("bash", "-c", pm2StartupCmd); err != nil {
		// PM2 startup might fail if already configured, continue
		log.Printf("PM2 startup configuration warning: %v", err)
	}

	return nil
}

// installPnpm installs pnpm globally
func (s *ServerSetup) installPnpm() error {
	nvmCmd := `export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && npm install -g pnpm`
	_, err := s.runCommand("bash", "-c", nvmCmd)
	return err
}

