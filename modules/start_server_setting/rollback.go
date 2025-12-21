package start_server_setting

import (
	"fmt"
	"log"
	"time"
)

// BackupConfig represents a backup of a critical configuration file
type BackupConfig struct {
	FilePath    string
	BackupPath  string
	BackupTime  time.Time
	Description string
}

// RollbackManager manages backups and rollbacks of critical configurations
type RollbackManager struct {
	backups []BackupConfig
	setup   *ServerSetup
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(setup *ServerSetup) *RollbackManager {
	return &RollbackManager{
		backups: make([]BackupConfig, 0),
		setup:   setup,
	}
}

// backupFile creates a backup of a critical configuration file
func (rm *RollbackManager) backupFile(filePath, description string) error {
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.backup_%s", filePath, timestamp)

	// Create backup
	backupCmd := fmt.Sprintf("cp %s %s", filePath, backupPath)
	_, err := rm.setup.runCommandAsRoot("bash", "-c", backupCmd)
	if err != nil {
		return fmt.Errorf("failed to backup %s: %w", filePath, err)
	}

	// Store backup info
	backup := BackupConfig{
		FilePath:    filePath,
		BackupPath:  backupPath,
		BackupTime:  time.Now(),
		Description: description,
	}
	rm.backups = append(rm.backups, backup)

	log.Printf("[RollbackManager] Backed up %s to %s", filePath, backupPath)
	return nil
}

// rollbackFile restores a file from backup
func (rm *RollbackManager) rollbackFile(filePath string) error {
	// Find the most recent backup for this file
	var latestBackup *BackupConfig
	for i := len(rm.backups) - 1; i >= 0; i-- {
		if rm.backups[i].FilePath == filePath {
			latestBackup = &rm.backups[i]
			break
		}
	}

	if latestBackup == nil {
		return fmt.Errorf("no backup found for %s", filePath)
	}

	// Restore from backup
	restoreCmd := fmt.Sprintf("cp %s %s", latestBackup.BackupPath, filePath)
	_, err := rm.setup.runCommandAsRoot("bash", "-c", restoreCmd)
	if err != nil {
		return fmt.Errorf("failed to restore %s from backup: %w", filePath, err)
	}

	log.Printf("[RollbackManager] Restored %s from %s", filePath, latestBackup.BackupPath)
	return nil
}

// rollbackAll restores all backed up files
func (rm *RollbackManager) rollbackAll() error {
	log.Printf("[RollbackManager] Starting rollback of all configurations...")

	// Rollback in reverse order (most recent first)
	for i := len(rm.backups) - 1; i >= 0; i-- {
		backup := rm.backups[i]
		if err := rm.rollbackFile(backup.FilePath); err != nil {
			log.Printf("[RollbackManager] Warning: Failed to rollback %s: %v", backup.FilePath, err)
			// Continue with other rollbacks
		}
	}

	// Restart services that might have been affected
	services := []string{"ssh", "nginx", "fail2ban", "ufw"}
	for _, service := range services {
		// Try to restart service (ignore errors if service doesn't exist)
		rm.setup.runCommandAsRoot("systemctl", "restart", service)
	}

	log.Printf("[RollbackManager] Rollback completed")
	return nil
}

// cleanupBackups removes old backup files (keeps only the most recent)
func (rm *RollbackManager) cleanupBackups() error {
	// Group backups by file path
	backupsByFile := make(map[string][]BackupConfig)
	for _, backup := range rm.backups {
		backupsByFile[backup.FilePath] = append(backupsByFile[backup.FilePath], backup)
	}

	// For each file, keep only the most recent backup
	for _, backups := range backupsByFile {
		if len(backups) <= 1 {
			continue // Keep the only backup
		}

		// Find most recent backup
		var mostRecent BackupConfig
		for _, backup := range backups {
			if backup.BackupTime.After(mostRecent.BackupTime) {
				mostRecent = backup
			}
		}

		// Remove older backups
		for _, backup := range backups {
			if backup.BackupPath != mostRecent.BackupPath {
				rm.setup.runCommandAsRoot("rm", "-f", backup.BackupPath)
				log.Printf("[RollbackManager] Removed old backup: %s", backup.BackupPath)
			}
		}
	}

	return nil
}

// backupCriticalConfigs creates backups of all critical configuration files
func (rm *RollbackManager) backupCriticalConfigs() error {
	criticalConfigs := []struct {
		path        string
		description string
	}{
		{"/etc/ssh/sshd_config", "SSH configuration"},
		{"/etc/nginx/nginx.conf", "Nginx main configuration"},
		{"/etc/ufw/user.rules", "UFW firewall rules"},
		{"/etc/fail2ban/jail.local", "Fail2ban configuration"},
		{"/etc/sysctl.conf", "Kernel parameters"},
		{"/etc/docker/daemon.json", "Docker daemon configuration"},
		{"/etc/chrony/chrony.conf", "Chrony time sync configuration"},
		{"/etc/systemd/resolved.conf", "Systemd DNS configuration"},
	}

	for _, config := range criticalConfigs {
		// Check if file exists before backing up
		checkCmd := fmt.Sprintf("test -f %s", config.path)
		_, err := rm.setup.runCommandAsRoot("bash", "-c", checkCmd)
		if err == nil {
			// File exists, create backup
			if err := rm.backupFile(config.path, config.description); err != nil {
				log.Printf("[RollbackManager] Warning: Failed to backup %s: %v", config.path, err)
				// Continue with other backups
			}
		}
	}

	return nil
}

