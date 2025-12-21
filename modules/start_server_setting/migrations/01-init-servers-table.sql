-- Create servers table for storing server configurations
-- This table stores configuration for each server identified by server IP address
-- NOTE: Username and password are NOT stored for security reasons

CREATE TABLE IF NOT EXISTS servers (
    id SERIAL PRIMARY KEY,
    server_ip VARCHAR(45) NOT NULL UNIQUE, -- IPv4 or IPv6 address
    ssh_port INTEGER NOT NULL, -- SSH port configured on server after setup (55000-56000 range, dynamically generated)
    hostname VARCHAR(255), -- Server hostname (optional, for reference)
    ssh_private_key_encrypted TEXT, -- Encrypted SSH private key (AES-256-GCM) for key-based authentication. Encrypted using ENCRYPTION_KEY from .env.
    setup_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index on server_ip for faster lookups (already unique, but good for queries)
CREATE INDEX IF NOT EXISTS idx_servers_server_ip ON servers(server_ip);

-- Create index on updated_at for querying recent servers
CREATE INDEX IF NOT EXISTS idx_servers_updated_at ON servers(updated_at);

-- Add comments to table and columns
COMMENT ON TABLE servers IS 'Stores server configuration for each server identified by IP address. Username and password are NOT stored for security.';
COMMENT ON COLUMN servers.server_ip IS 'Server IP address (IPv4 or IPv6) - unique identifier';
COMMENT ON COLUMN servers.ssh_port IS 'SSH port configured on server after setup (55000-56000 range, dynamically generated)';
COMMENT ON COLUMN servers.hostname IS 'Server hostname (optional, for reference only)';
COMMENT ON COLUMN servers.ssh_private_key_encrypted IS 'Encrypted SSH private key (AES-256-GCM) for key-based authentication. Encrypted using ENCRYPTION_KEY from .env.';
COMMENT ON COLUMN servers.setup_date IS 'Date when server was first configured';
COMMENT ON COLUMN servers.created_at IS 'Timestamp when record was created';
COMMENT ON COLUMN servers.updated_at IS 'Timestamp when record was last updated';

