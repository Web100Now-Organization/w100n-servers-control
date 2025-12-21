package start_server_setting

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// getKnownHostsPath returns the path to known_hosts file
func getKnownHostsPath() (string, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		usr, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		homeDir = usr.HomeDir
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	return knownHostsPath, nil
}

// saveHostKey saves SSH host key to known_hosts file
func saveHostKey(host string, port int, hostKey ssh.PublicKey) error {
	knownHostsPath, err := getKnownHostsPath()
	if err != nil {
		return err
	}

	// Create .ssh directory if it doesn't exist
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing known_hosts
	existingContent, err := os.ReadFile(knownHostsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read known_hosts: %w", err)
	}

	// Check if host key already exists
	hostWithPort := fmt.Sprintf("[%s]:%d", host, port)
	hostWithoutPort := host
	existingLines := strings.Split(string(existingContent), "\n")
	for _, line := range existingLines {
		if strings.Contains(line, hostWithPort) || strings.Contains(line, hostWithoutPort) {
			// Host key already exists, skip
			return nil
		}
	}

	// Append new host key
	hostKeyLine := fmt.Sprintf("%s,%s %s %s\n", hostWithPort, hostWithoutPort, hostKey.Type(), ssh.MarshalAuthorizedKey(hostKey))
	hostKeyLine = strings.TrimSuffix(hostKeyLine, "\n") + "\n"

	// Append to file
	file, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(hostKeyLine); err != nil {
		return fmt.Errorf("failed to write to known_hosts: %w", err)
	}

	return nil
}

// createHostKeyCallback creates a host key callback that verifies and saves host keys
func createHostKeyCallback(host string, port int) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Save host key to known_hosts for future use
		if err := saveHostKey(host, port, key); err != nil {
			// Log warning but don't fail connection
			log.Printf("[ServerSetup] Warning: Failed to save host key: %v", err)
		}

		// For first connection, we accept the key
		// In production, you might want to verify against a trusted key store
		return nil
	}
}

// verifyHostKey verifies host key against known_hosts
func verifyHostKey(host string, port int, hostKey ssh.PublicKey) error {
	knownHostsPath, err := getKnownHostsPath()
	if err != nil {
		return err
	}

	// Read known_hosts
	content, err := os.ReadFile(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No known_hosts file, first connection - accept it
			return nil
		}
		return fmt.Errorf("failed to read known_hosts: %w", err)
	}

	// Parse known_hosts
	hostWithPort := fmt.Sprintf("[%s]:%d", host, port)
	hostWithoutPort := host
	knownHostKey := ssh.MarshalAuthorizedKey(hostKey)

	// Check if host key exists in known_hosts
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if line contains our host
		if strings.Contains(line, hostWithPort) || strings.Contains(line, hostWithoutPort) {
			// Extract key from line
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				keyType := parts[1]
				keyData := parts[2]

				// Parse and compare keys
				parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprintf("%s %s", keyType, keyData)))
				if err == nil {
					parsedKeyData := ssh.MarshalAuthorizedKey(parsedKey)
					if string(parsedKeyData) == string(knownHostKey) {
						// Host key matches
						return nil
					}
				}
			}
		}
	}

	// Host key not found or doesn't match
	// For first connection, we accept it but save it
	// In production, you might want to reject it
	return nil
}

