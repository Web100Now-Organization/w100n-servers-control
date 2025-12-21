package start_server_setting

import (
	"fmt"
	"log"
	"net"
	"time"
)

// rebootServer reboots the remote server
// Note: We use 'shutdown -r +1' to schedule reboot in 1 minute, which allows
// the command to complete before SSH connection is terminated
func (s *ServerSetup) rebootServer() error {
	log.Printf("[Reboot] Initiating server reboot (scheduled in 1 minute)...")

	// Use 'shutdown -r +1' to schedule reboot in 1 minute
	// This gives time for the command to complete before SSH connection closes
	// The '+1' means reboot in 1 minute
	if _, err := s.runCommandAsRoot("shutdown", "-r", "+1"); err != nil {
		// If shutdown command fails, try alternative: use systemd-run to execute reboot in background
		log.Printf("[Reboot] shutdown command failed, trying alternative method...")
		rebootCmd := "systemd-run --no-block /sbin/reboot"
		if _, err2 := s.runCommandAsRoot("bash", "-c", rebootCmd); err2 != nil {
			return fmt.Errorf("failed to schedule server reboot (tried shutdown and systemd-run): %w", err)
		}
		log.Printf("[Reboot] Server reboot scheduled via systemd-run")
		return nil
	}

	log.Printf("[Reboot] Server reboot scheduled via shutdown (will reboot in 1 minute)")
	return nil
}

// waitForServerReboot waits for server to come back online after reboot
func waitForServerReboot(serverIP string, serverPort int, maxWaitTime time.Duration) error {
	log.Printf("[Reboot] Waiting for server to reboot (max %v)...", maxWaitTime)

	deadline := time.Now().Add(maxWaitTime)
	checkInterval := 5 * time.Second

	for time.Now().Before(deadline) {
		// Try to connect to SSH port
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", serverIP, serverPort), 3*time.Second)
		if err == nil {
			conn.Close()
			log.Printf("[Reboot] Server is back online!")
			// Wait a bit more for SSH service to fully start
			time.Sleep(5 * time.Second)
			return nil
		}

		remaining := time.Until(deadline)
		log.Printf("[Reboot] Server not ready yet, waiting... (remaining: %v)", remaining.Round(time.Second))
		time.Sleep(checkInterval)
	}

	return fmt.Errorf("server did not come back online within %v", maxWaitTime)
}
