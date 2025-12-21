package start_server_setting

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"web100now-clients-platform/core/db"
)

// saveServerConfig saves server configuration to PostgreSQL
// Configuration is stored in table "servers" in the core database
// NOTE: username and password are NOT stored for security reasons
func (s *ServerSetup) saveServerConfig(ctx context.Context) error {
	if s.config.ServerIP == "" {
		return fmt.Errorf("server IP is required to save configuration")
	}

	// Get hostname from remote server (optional, for reference)
	// If SSH is connected, get hostname from remote server
	// Otherwise, use server IP as fallback
	hostname := s.config.ServerIP // Fallback to IP if can't get hostname
	if s.sshClient != nil {
		hostnameOutput, err := s.runCommand("hostname")
		if err == nil && hostnameOutput != "" {
			// Trim whitespace from hostname output
			hostname = strings.TrimSpace(hostnameOutput)
			// Remove newline if present
			if len(hostname) > 0 && hostname[len(hostname)-1] == '\n' {
				hostname = hostname[:len(hostname)-1]
			}
		}
	}

	// Get PostgreSQL connection
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	// Upsert server configuration (update if exists, insert if not)
	// server_ip is used as unique identifier
	// Store username in hostname field if hostname is empty or use hostname as username hint
	query := `
		INSERT INTO servers (server_ip, ssh_port, hostname, ssh_private_key_encrypted, setup_date, updated_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (server_ip)
		DO UPDATE SET
			ssh_port = EXCLUDED.ssh_port,
			hostname = EXCLUDED.hostname,
			ssh_private_key_encrypted = EXCLUDED.ssh_private_key_encrypted,
			updated_at = EXCLUDED.updated_at
	`

	now := time.Now()
	// Store username in hostname field if hostname is empty (as a hint for connection)
	// Format: "username@hostname" or just "username" if hostname is empty
	hostnameWithUser := hostname
	if hostname == s.config.ServerIP || hostname == "" {
		// If hostname is IP or empty, use username as hostname hint
		hostnameWithUser = s.username
	} else {
		// Store as "username@hostname" format
		hostnameWithUser = fmt.Sprintf("%s@%s", s.username, hostname)
	}
	
	_, err = pgDB.ExecContext(ctx, query,
		s.config.ServerIP,              // server_ip (unique identifier)
		s.config.SSHPort,               // ssh_port (configured SSH port after setup)
		hostnameWithUser,               // hostname (stores username@hostname or username)
		s.config.SSHPrivateKeyEncrypted, // ssh_private_key_encrypted (encrypted private key)
		now,                            // setup_date
		now,                            // updated_at
		now,                            // created_at (used only on insert)
	)
	if err != nil {
		return fmt.Errorf("failed to save server config to PostgreSQL: %w", err)
	}

	return nil
}

// loadServerConfig loads server configuration from PostgreSQL
// Uses server_ip as identifier (not hostname, as hostname can change)
func (s *ServerSetup) loadServerConfig(ctx context.Context) error {
	if s.config.ServerIP == "" {
		// No server IP set yet, cannot load config
		return nil
	}

	// Get PostgreSQL connection
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		// PostgreSQL not available, will generate new port
		return nil
	}

	// Find server config by server_ip
	query := `SELECT ssh_port, hostname, ssh_private_key_encrypted FROM servers WHERE server_ip = $1`
	var sshPort int
	var hostname sql.NullString
	var sshPrivateKeyEncrypted sql.NullString
	err = pgDB.QueryRowContext(ctx, query, s.config.ServerIP).Scan(&sshPort, &hostname, &sshPrivateKeyEncrypted)
	if err == sql.ErrNoRows {
		// No existing config, will create new one
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to load server config from PostgreSQL: %w", err)
	}

	// Load configuration
	s.config.SSHPort = sshPort
	if hostname.Valid {
		s.config.Hostname = hostname.String
	}
	if sshPrivateKeyEncrypted.Valid {
		s.config.SSHPrivateKeyEncrypted = sshPrivateKeyEncrypted.String
	}

	return nil
}

// ServerConfigFromDB represents server configuration loaded from database
type ServerConfigFromDB struct {
	ServerIP              string
	SSHPort               int
	Hostname              string
	SSHPrivateKeyEncrypted string
	Username              string // This is not stored in DB, we need to get it from setup or use default
}

// LoadServerConfigFromDB loads server configuration from PostgreSQL by server IP
// Returns server config or error if not found
func LoadServerConfigFromDB(ctx context.Context, serverIP string) (*ServerConfigFromDB, error) {
	if serverIP == "" {
		return nil, fmt.Errorf("server IP is required")
	}

	// Get PostgreSQL connection
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return nil, fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	// Find server config by server_ip
	query := `SELECT ssh_port, hostname, ssh_private_key_encrypted FROM servers WHERE server_ip = $1`
	var sshPort int
	var hostname sql.NullString
	var sshPrivateKeyEncrypted sql.NullString
	err = pgDB.QueryRowContext(ctx, query, serverIP).Scan(&sshPort, &hostname, &sshPrivateKeyEncrypted)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("server configuration not found for IP: %s", serverIP)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load server config from PostgreSQL: %w", err)
	}

	config := &ServerConfigFromDB{
		ServerIP:              serverIP,
		SSHPort:               sshPort,
		SSHPrivateKeyEncrypted: "",
		Username:              "root", // Default username, will be extracted from hostname if available
		Hostname:              "",
	}

	if hostname.Valid && hostname.String != "" {
		hostnameStr := hostname.String
		config.Hostname = hostnameStr
		
		// Extract username from hostname if stored as "username@hostname" format
		if strings.Contains(hostnameStr, "@") {
			parts := strings.SplitN(hostnameStr, "@", 2)
			if len(parts) == 2 {
				config.Username = parts[0] // username
				config.Hostname = parts[1] // actual hostname
			}
		} else {
			// If no @ symbol, hostname might be the username itself
			// Try to use it as username if it looks like a username (not an IP)
			if !strings.Contains(hostnameStr, ".") || len(hostnameStr) < 7 {
				// Likely a username (short, no dots, or just a name)
				config.Username = hostnameStr
				config.Hostname = "" // No actual hostname
			}
		}
	}
	if sshPrivateKeyEncrypted.Valid {
		config.SSHPrivateKeyEncrypted = sshPrivateKeyEncrypted.String
	}

	return config, nil
}
