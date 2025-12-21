package start_server_setting

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"web100now-clients-platform/core/db/modules/postgres_database"
	"golang.org/x/crypto/ssh"
)

// GenerateSSHKeyPair generates a new SSH key pair (RSA 4096 bits)
// Returns private key PEM and public key (OpenSSH format)
func GenerateSSHKeyPair() (privateKeyPEM []byte, publicKey []byte, err error) {
	// Generate RSA private key (4096 bits)
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	privateKeyPEM = pem.EncodeToMemory(privateKeyBlock)

	// Generate public key in OpenSSH format
	publicKeyRSA, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey = ssh.MarshalAuthorizedKey(publicKeyRSA)

	return privateKeyPEM, publicKey, nil
}

// EncryptSSHPrivateKey encrypts SSH private key using ENCRYPTION_KEY
// If DISABLE_SSH_KEY_ENCRYPTION=true, returns plain text (for local testing)
func EncryptSSHPrivateKey(privateKeyPEM []byte) (string, error) {
	// Check if encryption is disabled (for local testing)
	if os.Getenv("DISABLE_SSH_KEY_ENCRYPTION") == "true" {
		return string(privateKeyPEM), nil
	}
	return postgres_database.EncryptString(string(privateKeyPEM))
}

// DecryptSSHPrivateKey decrypts encrypted SSH private key
// If DISABLE_SSH_KEY_ENCRYPTION=true, returns key as-is (for local testing)
func DecryptSSHPrivateKey(encryptedKey string) ([]byte, error) {
	// Check if encryption is disabled (for local testing)
	if os.Getenv("DISABLE_SSH_KEY_ENCRYPTION") == "true" {
		return []byte(encryptedKey), nil
	}
	decrypted, err := postgres_database.DecryptString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH private key: %w", err)
	}
	return []byte(decrypted), nil
}

// SaveSSHPublicKeyToRemote adds public key to authorized_keys on remote server
func (s *ServerSetup) SaveSSHPublicKeyToRemote(publicKey []byte, username string) error {
	// Create .ssh directory if it doesn't exist
	sshDir := fmt.Sprintf("/home/%s/.ssh", username)
	if username == "root" {
		sshDir = "/root/.ssh"
	}

	// Create .ssh directory with correct permissions
	if _, err := s.runCommandAsRoot("mkdir", "-p", sshDir); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set correct ownership
	if _, err := s.runCommandAsRoot("chown", fmt.Sprintf("%s:%s", username, username), sshDir); err != nil {
		return fmt.Errorf("failed to set ownership of .ssh directory: %w", err)
	}

	// Set correct permissions (700)
	if _, err := s.runCommandAsRoot("chmod", "700", sshDir); err != nil {
		return fmt.Errorf("failed to set permissions on .ssh directory: %w", err)
	}

	// Create authorized_keys file if it doesn't exist
	authorizedKeysPath := fmt.Sprintf("%s/authorized_keys", sshDir)
	
	// Check if authorized_keys exists, if not create it
	if _, err := s.runCommand("test", "-f", authorizedKeysPath); err != nil {
		// File doesn't exist, create it
		if _, err := s.runCommandAsRoot("touch", authorizedKeysPath); err != nil {
			return fmt.Errorf("failed to create authorized_keys file: %w", err)
		}
	}

	// Append public key to authorized_keys (check if it's already there first)
	// Use a comment to identify our key
	keyComment := fmt.Sprintf("w100n_auto_generated_%s", s.config.ServerIP)
	publicKeyStr := strings.TrimSpace(string(publicKey))
	publicKeyWithComment := fmt.Sprintf("%s %s", publicKeyStr, keyComment)
	
	// Check if key already exists
	checkCmd := fmt.Sprintf("grep -qF '%s' %s 2>/dev/null", keyComment, authorizedKeysPath)
	_, err := s.runCommandAsRoot("bash", "-c", checkCmd)
	if err == nil {
		// Key already exists, skip
		log.Printf("[SaveSSHPublicKey] Key with comment '%s' already exists in authorized_keys", keyComment)
	} else {
		// Key doesn't exist, add it using base64 to avoid shell escaping issues
		// Encode the key with comment to base64
		keyData := []byte(publicKeyWithComment + "\n")
		encodedKey := base64.StdEncoding.EncodeToString(keyData)
		
		// Append using base64 decode and append to file
		appendCmd := fmt.Sprintf("echo '%s' | base64 -d >> %s", encodedKey, authorizedKeysPath)
		if _, err := s.runCommandAsRoot("bash", "-c", appendCmd); err != nil {
			return fmt.Errorf("failed to add public key to authorized_keys: %w", err)
		}
		log.Printf("[SaveSSHPublicKey] Successfully added public key with comment '%s' to authorized_keys", keyComment)
	}

	// Set correct ownership on authorized_keys
	if _, err := s.runCommandAsRoot("chown", fmt.Sprintf("%s:%s", username, username), authorizedKeysPath); err != nil {
		return fmt.Errorf("failed to set ownership of authorized_keys: %w", err)
	}

	// Set correct permissions (600)
	if _, err := s.runCommandAsRoot("chmod", "600", authorizedKeysPath); err != nil {
		return fmt.Errorf("failed to set permissions on authorized_keys: %w", err)
	}

	// Verify the key was added correctly
	verifyCmd := fmt.Sprintf("grep -qF '%s' %s", keyComment, authorizedKeysPath)
	if _, err := s.runCommandAsRoot("bash", "-c", verifyCmd); err != nil {
		return fmt.Errorf("failed to verify public key was added to authorized_keys: %w", err)
	}

	log.Printf("[SaveSSHPublicKey] Public key successfully added and verified in authorized_keys")
	
	// Reload SSH service to ensure changes take effect immediately
	// This is important because SSH may cache authorized_keys in some configurations
	log.Printf("[SaveSSHPublicKey] Reloading SSH service to apply changes...")
	if _, err := s.runCommandAsRoot("systemctl", "reload", "ssh"); err != nil {
		// If reload fails (e.g., port change), try restart
		log.Printf("[SaveSSHPublicKey] Reload failed, trying restart...")
		if _, err2 := s.runCommandAsRoot("systemctl", "restart", "ssh"); err2 != nil {
			// Fallback to sshd if ssh service doesn't exist
			if _, err3 := s.runCommandAsRoot("systemctl", "restart", "sshd"); err3 != nil {
				return fmt.Errorf("failed to reload/restart SSH service after adding key: %w", err)
			}
		}
		// Wait a moment for SSH to restart
		time.Sleep(2 * time.Second)
		log.Printf("[SaveSSHPublicKey] SSH service restarted successfully")
	} else {
		log.Printf("[SaveSSHPublicKey] SSH service reloaded successfully")
	}

	return nil
}

// setupSSHKeys generates SSH key pair, saves public key to remote server, and stores encrypted private key
func (s *ServerSetup) setupSSHKeys() error {
	// Generate SSH key pair
	privateKeyPEM, publicKey, err := GenerateSSHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate SSH key pair: %w", err)
	}

	// Save public key to remote server
	if err := s.SaveSSHPublicKeyToRemote(publicKey, s.username); err != nil {
		return fmt.Errorf("failed to save public key to remote server: %w", err)
	}

	// Encrypt private key
	encryptedPrivateKey, err := EncryptSSHPrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Store encrypted private key in config (will be saved to DB later)
	s.config.SSHPrivateKeyEncrypted = encryptedPrivateKey

	return nil
}
