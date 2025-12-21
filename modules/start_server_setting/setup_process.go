package start_server_setting

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"web100now-clients-platform/core/db"
)

// SaveSetupProcess saves setup process information to database
// Stores setupId and serverIP for WebSocket subscription lookup
func SaveSetupProcess(ctx context.Context, setupID, serverIP string) error {
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	query := `
		INSERT INTO server_setups (setup_id, server_ip, status, created_at, updated_at)
		VALUES ($1, $2, 'running', $3, $3)
		ON CONFLICT (setup_id)
		DO UPDATE SET
			server_ip = EXCLUDED.server_ip,
			status = 'running',
			updated_at = EXCLUDED.updated_at
	`

	now := time.Now()
	_, err = pgDB.ExecContext(ctx, query, setupID, serverIP, now)
	if err != nil {
		return fmt.Errorf("failed to save setup process to PostgreSQL: %w", err)
	}

	return nil
}

// GetSetupProcessServerIP retrieves server IP for a given setup ID
func GetSetupProcessServerIP(ctx context.Context, setupID string) (string, error) {
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return "", fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	query := `SELECT server_ip FROM server_setups WHERE setup_id = $1 AND status = 'running'`
	var serverIP string
	err = pgDB.QueryRowContext(ctx, query, setupID).Scan(&serverIP)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("setup process not found: %s", setupID)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get setup process from PostgreSQL: %w", err)
	}

	return serverIP, nil
}

// UpdateSetupProcessStatus updates setup process status (completed or failed)
func UpdateSetupProcessStatus(ctx context.Context, setupID string, status string) error {
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	query := `
		UPDATE server_setups
		SET status = $1, updated_at = $2, completed_at = $2
		WHERE setup_id = $3
	`

	now := time.Now()
	_, err = pgDB.ExecContext(ctx, query, status, now, setupID)
	if err != nil {
		return fmt.Errorf("failed to update setup process status: %w", err)
	}

	return nil
}

// DeleteSetupProcess deletes setup process record from database
// Called after setup completion to clean up
func DeleteSetupProcess(ctx context.Context, setupID string) error {
	pgDB, err := db.GetPostgresDB()
	if err != nil {
		return fmt.Errorf("PostgreSQL connection not available: %w", err)
	}

	query := `DELETE FROM server_setups WHERE setup_id = $1`
	_, err = pgDB.ExecContext(ctx, query, setupID)
	if err != nil {
		return fmt.Errorf("failed to delete setup process from PostgreSQL: %w", err)
	}

	return nil
}

