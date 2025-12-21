package start_server_setting

import (
	"context"

	"web100now-clients-platform/core/db"
)

// RunMigrations runs database migrations for this module
// Migrations are stored in the migrations/ subdirectory relative to this package
func RunMigrations(ctx context.Context) error {
	// Path to migrations directory relative to project root
	migrationsDir := "app/plugins/w100n_servers_control/modules/start_server_setting/migrations"
	
	// Use the core migration system with our migrations directory
	return db.RunMigrations(ctx, migrationsDir)
}

