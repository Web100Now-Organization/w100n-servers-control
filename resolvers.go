package servers_control

import (
	"context"
	"fmt"
	"sync"
	"time"

	"web100now-clients-platform/app/graph/model"
	"web100now-clients-platform/app/plugins/w100n_servers_control/modules/start_server_setting"
	"web100now-clients-platform/core/logger"
)

// Resolver is the resolver for the servers_control plugin
type Resolver struct {
	activeSetups sync.Map // map[string]*activeSetup - key is setupId
}

type activeSetup struct {
	setup   *start_server_setting.ServerSetup
	progress chan *start_server_setting.SetupProgress
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewResolver creates a new instance of the servers_control resolver
func NewResolver() *Resolver {
	return &Resolver{}
}

// StartServerSetup starts the initial server setup process
func (r *Resolver) StartServerSetup(ctx context.Context, serverIP string, serverPort int, username string, password string) (*model.ServerSetupResponse, error) {
	logger.LogInfo(fmt.Sprintf("[ServersControl] StartServerSetup called for server %s:%d, user: %s", serverIP, serverPort, username))

	// Validate server info
	if err := start_server_setting.ValidateServerInfo(serverIP, serverPort); err != nil {
		return &model.ServerSetupResponse{
			Success: false,
			Message: fmt.Sprintf("Invalid server information: %v", err),
		}, nil
	}

	// Check if server is reachable
	if err := start_server_setting.CheckServerReachability(ctx, serverIP, serverPort); err != nil {
		logger.LogError(fmt.Sprintf("[ServersControl] Server %s:%d is not reachable", serverIP, serverPort), err)
		return &model.ServerSetupResponse{
			Success: false,
			Message: fmt.Sprintf("Server %s:%d is not reachable: %v", serverIP, serverPort, err),
		}, nil
	}

	logger.LogInfo(fmt.Sprintf("[ServersControl] Server %s:%d is reachable, proceeding with setup", serverIP, serverPort))

	// Generate setup ID
	setupID := generateSetupID()

	// Save setup process to database (setupId and serverIP)
	if err := start_server_setting.SaveSetupProcess(ctx, setupID, serverIP); err != nil {
		logger.LogError(fmt.Sprintf("[ServersControl] Failed to save setup process to database: %s", setupID), err)
		return &model.ServerSetupResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to save setup process: %v", err),
		}, nil
	}

	// Create context for setup
	setupCtx, cancel := context.WithCancel(context.Background())

	// Create progress channel
	progressChan := make(chan *start_server_setting.SetupProgress, 100)

	// Create progress callback
	progressCallback := func(progress *start_server_setting.SetupProgress) {
		select {
		case progressChan <- progress:
		default:
			// Channel full, skip
		}
	}

	// Create server setup instance
	setup := start_server_setting.NewServerSetup(setupCtx, progressCallback)

	// Store active setup progress channel in memory (for WebSocket subscription)
	r.activeSetups.Store(setupID, &activeSetup{
		setup:    setup,
		progress: progressChan,
		ctx:      setupCtx,
		cancel:   cancel,
	})

	// Start setup in background
	go func() {
		var setupErr error
		
		logger.LogInfo(fmt.Sprintf("[ServersControl] Starting server setup process for setupID: %s", setupID))
		setupErr = setup.SetupServer(serverIP, serverPort, username, password)
		
		// Update status in database
		status := "completed"
		if setupErr != nil {
			status = "failed"
			logger.LogError(fmt.Sprintf("[ServersControl] Server setup failed: %s", setupID), setupErr)
		} else {
			logger.LogInfo(fmt.Sprintf("[ServersControl] ✅ Server setup completed successfully: %s", setupID))
		}
		
		// Update status in database
		if err := start_server_setting.UpdateSetupProcessStatus(context.Background(), setupID, status); err != nil {
			logger.LogError(fmt.Sprintf("[ServersControl] Failed to update setup status: %s", setupID), err)
		}
		
		// Clean up from memory
		defer func() {
			close(progressChan)
			r.activeSetups.Delete(setupID)
			cancel()
			logger.LogInfo(fmt.Sprintf("[ServersControl] Cleaned up setup resources from memory for: %s", setupID))
		}()
		
		// Clean up from database after a short delay (to allow WebSocket to finish)
		go func() {
			time.Sleep(10 * time.Second) // Give time for final WebSocket messages
			if err := start_server_setting.DeleteSetupProcess(context.Background(), setupID); err != nil {
				logger.LogError(fmt.Sprintf("[ServersControl] Failed to delete setup process from database: %s", setupID), err)
			} else {
				logger.LogInfo(fmt.Sprintf("[ServersControl] Deleted setup process from database: %s", setupID))
			}
		}()
	}()

	return &model.ServerSetupResponse{
		Success: true,
		Message: "Server setup started",
		SetupID: &setupID,
	}, nil
}

// ServerSetupProgress returns progress updates for a server setup
func (r *Resolver) ServerSetupProgress(ctx context.Context, setupID string) (<-chan *model.ServerSetupProgress, error) {
	logger.LogInfo(fmt.Sprintf("[ServersControl] ServerSetupProgress subscription started: %s", setupID))

	// Verify setup exists in database and get serverIP
	serverIP, err := start_server_setting.GetSetupProcessServerIP(ctx, setupID)
	if err != nil {
		logger.LogError(fmt.Sprintf("[ServersControl] Setup not found in database: %s", setupID), err)
		return nil, fmt.Errorf("setup not found: %s", setupID)
	}
	logger.LogInfo(fmt.Sprintf("[ServersControl] Setup found in database: %s, serverIP: %s", setupID, serverIP))

	// Get active setup progress channel from memory
	setupValue, ok := r.activeSetups.Load(setupID)
	if !ok {
		return nil, fmt.Errorf("setup progress channel not found (setup may have completed): %s", setupID)
	}

	activeSetup := setupValue.(*activeSetup)

	// Create output channel
	out := make(chan *model.ServerSetupProgress)

	go func() {
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				return
			case progress, ok := <-activeSetup.progress:
				if !ok {
					logger.LogInfo(fmt.Sprintf("[ServersControl] Progress channel closed for setup: %s", setupID))
					return
				}

				// Log progress update to console
				logger.LogInfo(fmt.Sprintf("[ServersControl] Progress update [%s] Step %d/%d: %s", setupID, progress.Step, progress.TotalSteps, progress.Message))
				if progress.Error != "" {
					logger.LogError(fmt.Sprintf("[ServersControl] Setup error [%s] Step %d: %s", setupID, progress.Step, progress.Error), fmt.Errorf(progress.Error))
				}

				totalSteps := progress.TotalSteps
				timestamp := int(progress.Timestamp) // Convert int64 to int
				modelProgress := &model.ServerSetupProgress{
					Step:      progress.Step,
					TotalSteps: totalSteps,
					Message:   progress.Message,
					Status:    progress.Status,
					Timestamp: timestamp,
				}

				if progress.Error != "" {
					modelProgress.Error = &progress.Error
				}

				select {
				case out <- modelProgress:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out, nil
}

// TestServerConnection tests SSH connection to a server using configuration from database
func (r *Resolver) TestServerConnection(ctx context.Context, serverIP string) (*model.ServerConnectionTestResponse, error) {
	logger.LogInfo(fmt.Sprintf("[ServersControl] TestServerConnection called for server %s", serverIP))

	// Load server configuration from database
	config, err := start_server_setting.LoadServerConfigFromDB(ctx, serverIP)
	if err != nil {
		errMsg := fmt.Sprintf("failed to load server configuration: %v", err)
		logger.LogError(fmt.Sprintf("[ServersControl] Failed to load config for %s", serverIP), err)
		return &model.ServerConnectionTestResponse{
			Success: false,
			Message: errMsg,
			Error:   &errMsg,
		}, nil
	}

	// Validate server info
	if err := start_server_setting.ValidateServerInfo(config.ServerIP, config.SSHPort); err != nil {
		errMsg := fmt.Sprintf("invalid server information: %v", err)
		return &model.ServerConnectionTestResponse{
			Success: false,
			Message: errMsg,
			Error:   &errMsg,
		}, nil
	}

	// Decrypt private key
	logger.LogInfo(fmt.Sprintf("[ServersControl] Decrypting private key for %s (username: %s, port: %d)", serverIP, config.Username, config.SSHPort))
	privateKey, err := start_server_setting.DecryptSSHPrivateKey(config.SSHPrivateKeyEncrypted)
	if err != nil {
		errMsg := fmt.Sprintf("failed to decrypt private key: %v", err)
		logger.LogError(fmt.Sprintf("[ServersControl] Failed to decrypt key for %s", serverIP), err)
		return &model.ServerConnectionTestResponse{
			Success: false,
			Message: errMsg,
			Error:   &errMsg,
		}, nil
	}

	// Log key length for debugging (don't log actual key)
	logger.LogInfo(fmt.Sprintf("[ServersControl] Private key decrypted successfully (length: %d bytes)", len(privateKey)))
	
	// Log first few characters of key for debugging (to verify it's a valid PEM)
	privateKeyStr := string(privateKey)
	if len(privateKeyStr) > 50 {
		logger.LogInfo(fmt.Sprintf("[ServersControl] Private key starts with: %s...", privateKeyStr[:50]))
	}

	// Test SSH connection
	logger.LogInfo(fmt.Sprintf("[ServersControl] Attempting SSH connection to %s:%d as user %s", config.ServerIP, config.SSHPort, config.Username))
	hostname, osInfo, err := start_server_setting.TestSSHConnection(ctx, config.ServerIP, config.SSHPort, config.Username, string(privateKey))
	if err != nil {
		errMsg := fmt.Sprintf("failed to connect to server: %v", err)
		logger.LogError(fmt.Sprintf("[ServersControl] Connection test failed for %s:%d", config.ServerIP, config.SSHPort), err)
		return &model.ServerConnectionTestResponse{
			Success: false,
			Message: errMsg,
			Error:   &errMsg,
		}, nil
	}

	successMsg := fmt.Sprintf("Successfully connected to server %s:%d", config.ServerIP, config.SSHPort)
	logger.LogInfo(fmt.Sprintf("[ServersControl] ✅ Connection test successful: %s (hostname: %s, OS: %s)", config.ServerIP, hostname, osInfo))

	return &model.ServerConnectionTestResponse{
		Success:  true,
		Message:  successMsg,
		Hostname: &hostname,
		OsInfo:   &osInfo,
	}, nil
}

// generateSetupID generates a unique setup ID
func generateSetupID() string {
	// Generate unique ID based on timestamp
	return fmt.Sprintf("setup-%d", time.Now().UnixNano())
}

