-- Create server_setups table for storing active server setup processes
-- This table stores temporary setup process information for WebSocket subscriptions
-- Records are automatically cleaned up after setup completion

CREATE TABLE IF NOT EXISTS server_setups (
    id SERIAL PRIMARY KEY,
    setup_id VARCHAR(255) NOT NULL UNIQUE,
    server_ip VARCHAR(45) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'running', -- 'running', 'completed', 'failed'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Create index on setup_id for fast lookups
CREATE INDEX IF NOT EXISTS idx_server_setups_setup_id ON server_setups(setup_id);

-- Create index on server_ip for querying by server
CREATE INDEX IF NOT EXISTS idx_server_setups_server_ip ON server_setups(server_ip);

-- Create index on status for querying active setups
CREATE INDEX IF NOT EXISTS idx_server_setups_status ON server_setups(status);

-- Add comments
COMMENT ON TABLE server_setups IS 'Stores active server setup processes for WebSocket subscriptions. Records are cleaned up after completion.';
COMMENT ON COLUMN server_setups.setup_id IS 'Unique setup identifier (e.g., setup-1766108037485225000)';
COMMENT ON COLUMN server_setups.server_ip IS 'Server IP address being configured';
COMMENT ON COLUMN server_setups.status IS 'Setup status: running, completed, failed';
COMMENT ON COLUMN server_setups.created_at IS 'Timestamp when setup process started';
COMMENT ON COLUMN server_setups.updated_at IS 'Timestamp when record was last updated';
COMMENT ON COLUMN server_setups.completed_at IS 'Timestamp when setup process completed (NULL if still running)';

