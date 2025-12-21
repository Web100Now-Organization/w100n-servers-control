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

// FixSSHPublicKeyOnServer adds public key to authorized_keys on server if connection fails
// This function tries to connect with password first, then adds the public key
func FixSSHPublicKeyOnServer(ctx context.Context, serverIP string, serverPort int, username string, password string, privateKeyPEM string) error {
	// First, try to connect with password to add the public key
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 10 * time.Second,
	}

	address := fmt.Sprintf("%s:%d", serverIP, serverPort)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("failed to connect with password to add public key: %w", err)
	}
	defer client.Close()

	log.Printf("[FixSSHKey] Connected with password, adding public key...")

	// Parse private key to get public key
	privateKeyPEM = strings.TrimSpace(privateKeyPEM)
	signer, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get public key from private key
	publicKey := signer.PublicKey()
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)
	publicKeyStr := strings.TrimSpace(string(publicKeyBytes))

	// Determine SSH directory
	sshDir := fmt.Sprintf("/home/%s/.ssh", username)
	if username == "root" {
		sshDir = "/root/.ssh"
	}

	// Create .ssh directory if it doesn't exist
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Create .ssh directory
	createDirCmd := fmt.Sprintf("mkdir -p %s && chmod 700 %s", sshDir, sshDir)
	if err := session.Run(createDirCmd); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Add public key to authorized_keys
	authorizedKeysPath := fmt.Sprintf("%s/authorized_keys", sshDir)
	keyComment := fmt.Sprintf("w100n_auto_generated_%s", serverIP)
	publicKeyWithComment := fmt.Sprintf("%s %s", publicKeyStr, keyComment)

	// Check if key already exists, if not add it
	checkAndAddCmd := fmt.Sprintf("grep -qF '%s' %s 2>/dev/null || echo '%s' >> %s", keyComment, authorizedKeysPath, publicKeyWithComment, authorizedKeysPath)
	if err := session.Run(checkAndAddCmd); err != nil {
		return fmt.Errorf("failed to add public key: %w", err)
	}

	// Set correct permissions
	chmodCmd := fmt.Sprintf("chmod 600 %s && chown %s:%s %s", authorizedKeysPath, username, username, authorizedKeysPath)
	if err := session.Run(chmodCmd); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	log.Printf("[FixSSHKey] Public key added successfully to %s", authorizedKeysPath)
	return nil
}

