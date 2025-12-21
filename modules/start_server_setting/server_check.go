package start_server_setting

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ServerInfo represents server connection information
type ServerInfo struct {
	IP   string
	Port int
}

// CheckServerReachability checks if server is reachable by IP and port
func CheckServerReachability(ctx context.Context, ip string, port int) error {
	address := fmt.Sprintf("%s:%d", ip, port)
	
	// Create context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	// Try to connect to the server
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return fmt.Errorf("server %s:%d is not reachable: %w", ip, port, err)
	}
	
	// Close connection immediately after checking
	conn.Close()
	
	return nil
}

// ValidateServerInfo validates server IP and port
func ValidateServerInfo(ip string, port int) error {
	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	// Validate port range
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 1-65535)", port)
	}
	
	return nil
}

