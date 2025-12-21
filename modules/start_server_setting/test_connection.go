package start_server_setting

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSSHConnection tests SSH connection to a server using private key
// Returns hostname, OS info, and error if any
func TestSSHConnection(ctx context.Context, serverIP string, serverPort int, username string, privateKeyPEM string) (hostname string, osInfo string, err error) {
	// Trim whitespace from private key
	privateKeyPEM = strings.TrimSpace(privateKeyPEM)
	
	// Parse private key - try different methods
	var signer ssh.Signer
	signer, err = ssh.ParsePrivateKey([]byte(privateKeyPEM))
	if err != nil {
		// Try parsing with passphrase (empty passphrase)
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKeyPEM), []byte(""))
		if err != nil {
			// Try to parse as raw key without PEM headers
			if !strings.Contains(privateKeyPEM, "BEGIN") {
				// Key might be missing PEM headers, try adding them
				if strings.Contains(privateKeyPEM, "PRIVATE KEY") {
					// Already has some structure, try as-is
				} else {
					return "", "", fmt.Errorf("failed to parse private key: invalid format (missing PEM headers?): %w", err)
				}
			}
			return "", "", fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	
	log.Printf("[TestConnection] Successfully parsed private key for user %s", username)

	// Extract public key from private key for verification
	publicKeyFromPrivate := signer.PublicKey()
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKeyFromPrivate)
	log.Printf("[TestConnection] Extracted public key from private key (first 50 chars): %s", string(publicKeyBytes[:min(50, len(publicKeyBytes))]))

	// Create SSH config
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Accept host key for testing
			return nil
		},
		Timeout: 10 * time.Second,
	}

	// Connect to server
	address := fmt.Sprintf("%s:%d", serverIP, serverPort)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return "", "", fmt.Errorf("failed to connect to SSH server %s: %w", address, err)
	}
	defer client.Close()

	log.Printf("[TestConnection] SSH connection established to %s", address)

	// Get hostname
	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	hostnameOutput, err := session.Output("hostname")
	if err != nil {
		return "", "", fmt.Errorf("failed to get hostname: %w", err)
	}
	hostname = strings.TrimSpace(string(hostnameOutput))

	// Get OS info
	session2, err := client.NewSession()
	if err != nil {
		return hostname, "", fmt.Errorf("failed to create SSH session for OS info: %w", err)
	}
	defer session2.Close()

	// Try to get OS info (works on most Linux systems)
	osInfoOutput, err := session2.Output("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME || uname -a")
	if err != nil {
		// If command fails, try simpler version
		osInfoOutput, err = session2.Output("uname -a")
		if err != nil {
			osInfo = "Unknown OS"
		} else {
			osInfo = strings.TrimSpace(string(osInfoOutput))
		}
	} else {
		// Extract PRETTY_NAME from os-release
		output := string(osInfoOutput)
		if strings.Contains(output, "PRETTY_NAME=") {
			parts := strings.Split(output, "PRETTY_NAME=")
			if len(parts) > 1 {
				osInfo = strings.Trim(strings.TrimSpace(parts[1]), "\"")
			} else {
				osInfo = strings.TrimSpace(output)
			}
		} else {
			osInfo = strings.TrimSpace(output)
		}
	}

	log.Printf("[TestConnection] Successfully connected to %s (hostname: %s, OS: %s)", address, hostname, osInfo)
	return hostname, osInfo, nil
}

