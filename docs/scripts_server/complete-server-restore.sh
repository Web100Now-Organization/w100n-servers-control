#!/bin/bash

# ============================================
# COMPLETE SERVER SETUP & RESTORE SCRIPT
# ============================================

# DON'T use 'set -e' to allow script to continue on errors
set +e

BACKUP_DIR="/root/backup"
STATE_FILE="/root/.restore-state"

# Create state file if doesn't exist
touch $STATE_FILE

# Function to check if step is done
is_step_done() {
    grep -q "^$1$" $STATE_FILE
}

# Function to mark step as done
mark_step_done() {
    echo "$1" >> $STATE_FILE
}

echo "============================================"
echo "  🚀 SERVER SETUP & RESTORE"
echo "============================================"
echo ""

# Show already completed steps
if [ -s $STATE_FILE ]; then
    echo "✓ Already completed steps:"
    cat $STATE_FILE | sed 's/^/  - /'
    echo ""
fi

# ============================================
# STEP 1: SSH KEY SETUP
# ============================================
if ! is_step_done "step1_ssh"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 1: SSH Key Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    if [ -f ~/.ssh/authorized_keys ] && [ -s ~/.ssh/authorized_keys ]; then
        echo "✓ SSH key already exists, skipping..."
    else
        echo ""
        echo "⚠️  MANUAL ACTION REQUIRED:"
        echo "Add your SSH public key to: /root/.ssh/authorized_keys"
        echo ""
        echo "On your Mac run:"
        echo "  cat ~/.ssh/id_ed25519.pub"
        echo ""
        echo "Then paste the output into /root/.ssh/authorized_keys on server"
        echo ""
        read -p "Press Enter when you've added the SSH key..."
    fi
    
    chmod 600 ~/.ssh/authorized_keys 2>/dev/null
    echo "✓ SSH key permissions set"
    mark_step_done "step1_ssh"
    echo ""
else
    echo "⏭️  STEP 1: SSH Key - Already done, skipping"
    echo ""
fi

# ============================================
# STEP 2: VERIFY SYSTEM
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: System Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Checking services..."
systemctl is-active --quiet nginx && echo "✓ Nginx running" || echo "⚠ Nginx not running"
systemctl is-active --quiet docker && echo "✓ Docker running" || echo "⚠ Docker not running"

echo ""
echo "Installed versions:"
echo "  Nginx: $(nginx -v 2>&1 | cut -d/ -f2)"
echo "  Docker: $(docker --version 2>&1 | awk '{print $3}' | tr -d ',')"
echo "  Node: $(node -v 2>/dev/null || echo 'not installed')"
echo "  PM2: $(pm2 -v 2>/dev/null || echo 'not installed')"
echo ""

# ============================================
# STEP 2.5: INSTALL NODE.JS, PM2, PNPM
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2.5: Installing Node.js Tools"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Node.js version
NODE_VERSION=$(node -v 2>/dev/null | cut -d'v' -f2 | cut -d'.' -f1)
NEED_INSTALL=false

if ! command -v node &> /dev/null; then
    echo "Node.js not found, installing..."
    NEED_INSTALL=true
elif [ "$NODE_VERSION" -lt 18 ]; then
    echo "Node.js v$NODE_VERSION is too old (need v18+), upgrading..."
    NEED_INSTALL=true
else
    echo "✓ Node.js $(node -v) is OK"
fi

# Install/Upgrade Node.js via NVM
if [ "$NEED_INSTALL" = true ]; then
    # Install NVM
    export NVM_DIR="$HOME/.nvm"
    if [ ! -d "$NVM_DIR" ]; then
        echo "Installing NVM..."
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    fi
    
    # Load NVM
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    # Install Node.js LTS (v22)
    echo "Installing Node.js LTS..."
    nvm install 22
    nvm use 22
    nvm alias default 22
    
    # Add to .bashrc if not already there
    if ! grep -q "NVM_DIR" ~/.bashrc; then
        cat >> ~/.bashrc << 'NVMEOF'

# NVM
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
NVMEOF
    fi
    
    echo "✓ Node.js $(node -v) installed/upgraded"
fi

# Check and install PM2
if ! command -v pm2 &> /dev/null; then
    echo "Installing PM2..."
    npm install -g pm2
    pm2 startup systemd -u root --hp /root
    pm2 save
    echo "✓ PM2 $(pm2 -v) installed"
else
    echo "✓ PM2 already installed: $(pm2 -v)"
fi

# Check and install pnpm
if ! command -v pnpm &> /dev/null; then
    echo "Installing pnpm..."
    
    # Use official installer (works better than npm)
    curl -fsSL https://get.pnpm.io/install.sh | sh -
    
    # Add to current session
    export PNPM_HOME="$HOME/.local/share/pnpm"
    export PATH="$PNPM_HOME:$PATH"
    
    # Add to .bashrc if not already there
    if ! grep -q "PNPM_HOME" ~/.bashrc; then
        cat >> ~/.bashrc << 'PNPMEOF'

# pnpm
export PNPM_HOME="$HOME/.local/share/pnpm"
case ":$PATH:" in
  *":$PNPM_HOME:"*) ;;
  *) export PATH="$PNPM_HOME:$PATH" ;;
esac
PNPMEOF
    fi
    
    echo "✓ pnpm $(pnpm -v 2>/dev/null || echo 'installed') installed"
else
    echo "✓ pnpm already installed: $(pnpm -v)"
fi

echo ""
echo "Node.js tools summary:"
echo "  Node: $(node -v)"
echo "  npm: $(npm -v)"
echo "  PM2: $(pm2 -v)"
echo "  pnpm: $(pnpm -v)"
echo ""

# ============================================
# STEP 3: RESTORE CONFIGURATIONS
# ============================================
if ! is_step_done "step3_configs"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 3: Restoring Configurations"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f "$BACKUP_DIR/nginx-"*".tar.gz" ]; then
        echo "Restoring Nginx configs..."
        tar -xzf $BACKUP_DIR/nginx-*.tar.gz -C /
        
        # Enable all sites (create symlinks)
        echo "Enabling Nginx sites..."
        mkdir -p /etc/nginx/sites-enabled
        
        # Remove default symlink if exists
        rm -f /etc/nginx/sites-enabled/default
        
        # Create symlinks for all sites
        ENABLED_COUNT=0
        for site in /etc/nginx/sites-available/*; do
            if [ -f "$site" ] && [[ $(basename "$site") != "default" ]]; then
                site_name=$(basename "$site")
                # Create symlink if doesn't exist
                if [ ! -L "/etc/nginx/sites-enabled/$site_name" ]; then
                    ln -s "$site" "/etc/nginx/sites-enabled/$site_name"
                    echo "  ✓ Enabled: $site_name"
                    ((ENABLED_COUNT++))
                fi
            fi
        done
        
        echo "Total sites enabled: $ENABLED_COUNT"
        echo ""
        
        # Test configuration
        if nginx -t 2>&1; then
            echo "✓ Nginx config OK"
            systemctl reload nginx 2>/dev/null && echo "✓ Nginx reloaded" || echo "⚠ Nginx reload failed"
        else
            echo "⚠ Nginx config has errors"
        fi
    else
        echo "⚠ Nginx backup not found"
    fi
    
    if [ -f "$BACKUP_DIR/pm2-"*".tar.gz" ]; then
        echo "Restoring PM2 configs..."
        tar -xzf $BACKUP_DIR/pm2-*.tar.gz -C /
        echo "✓ PM2 configs restored"
    else
        echo "⚠ PM2 backup not found"
    fi
    
    if [ -f "$BACKUP_DIR/docker-compose-"*".tar.gz" ]; then
        echo "Restoring docker-compose files..."
        tar -xzf $BACKUP_DIR/docker-compose-*.tar.gz -C /
        echo "✓ Docker compose files restored"
    else
        echo "⚠ Docker compose backup not found"
    fi
    
    mark_step_done "step3_configs"
    echo ""
else
    echo "⏭️  STEP 3: Configurations - Already done, skipping"
    echo ""
fi

# ============================================
# STEP 4: RESTORE PROJECT FILES
# ============================================
if ! is_step_done "step4_projects"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 4: Restoring Project Files"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f "$BACKUP_DIR/projects-"*".tar.gz" ]; then
        echo "Restoring projects (this may take 2-5 minutes)..."
        tar -xzf $BACKUP_DIR/projects-*.tar.gz -C /
        
        echo "Checking restored files:"
        ls -la /var/web100now/ 2>/dev/null && echo "✓ /var/web100now restored" || echo "⚠ /var/web100now not found"
        ls -la /var/tablq/ 2>/dev/null && echo "✓ /var/tablq restored" || echo "⚠ /var/tablq not found"
        
        echo "Size: $(du -sh /var/web100now 2>/dev/null | cut -f1)"
    else
        echo "⚠ Projects backup not found in $BACKUP_DIR"
    fi
    
    mark_step_done "step4_projects"
    echo ""
else
    echo "⏭️  STEP 4: Project Files - Already done, skipping"
    echo "   Size: $(du -sh /var/web100now 2>/dev/null | cut -f1)"
    echo ""
fi

# ============================================
# STEP 5: RESTORE DOCKER VOLUMES
# ============================================
if ! is_step_done "step5_volumes"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 5: Restoring Docker Volumes (Databases)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f "$BACKUP_DIR/docker-volumes-all-"*".tar.gz" ]; then
        echo "Restoring Docker volumes (MySQL, MongoDB)..."
        tar -xzf $BACKUP_DIR/docker-volumes-all-*.tar.gz -C /
        
        echo "Fixing permissions..."
        chown -R 999:999 /var/lib/docker/volumes/*/ 2>/dev/null
        chmod -R 755 /var/lib/docker/volumes/ 2>/dev/null
        
        echo "Volumes restored:"
        ls -la /var/lib/docker/volumes/ | grep -E "mongo|mysql|db_data"
        
        echo "Total size: $(du -sh /var/lib/docker/volumes/ 2>/dev/null | cut -f1)"
    else
        echo "⚠ Docker volumes backup not found"
    fi
    
    # Restore raw MongoDB if exists
    if [ -f "$BACKUP_DIR/mongo-web100now-raw-"*".tar.gz" ]; then
        echo "Restoring raw MongoDB data..."
        tar -xzf $BACKUP_DIR/mongo-web100now-raw-*.tar.gz -C /
        chown -R 999:999 /var/web100now/*/mongo_data 2>/dev/null
        echo "✓ Raw MongoDB data restored"
    fi
    
    mark_step_done "step5_volumes"
    echo ""
else
    echo "⏭️  STEP 5: Docker Volumes - Already done, skipping"
    echo "   Size: $(du -sh /var/lib/docker/volumes/ 2>/dev/null | cut -f1)"
    echo ""
fi

# ============================================
# STEP 6: START DOCKER CONTAINERS
# ============================================
if ! is_step_done "step6_docker"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 6: Starting Docker Containers"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo "⏭️  STEP 6: Docker Containers - Already done, checking status..."
    docker ps --format "table {{.Names}}\t{{.Status}}" | head -10
    echo ""
    echo "To restart all containers, run:"
    echo "  docker restart \$(docker ps -aq)"
    echo ""
fi

if ! is_step_done "step6_docker"; then

# Find all docker-compose.yml files
echo "Finding all docker-compose projects..."
COMPOSE_FILES=$(find /var/web100now /var/tablq -name "docker-compose.yml" 2>/dev/null)
COMPOSE_COUNT=$(echo "$COMPOSE_FILES" | grep -c "docker-compose.yml" || echo "0")

echo "Found $COMPOSE_COUNT docker-compose projects"
echo ""

# Counter
STARTED=0
FAILED=0

# Start each project
while IFS= read -r compose_file; do
    if [ -n "$compose_file" ] && [ -f "$compose_file" ]; then
        project_dir=$(dirname "$compose_file")
        project_name=$(basename "$project_dir")
        
        echo "[$((STARTED + FAILED + 1))/$COMPOSE_COUNT] Starting: $project_name"
        echo "  Location: $project_dir"
        
        cd "$project_dir"
        
        # Try to start
        if docker-compose up -d 2>&1 | tee /tmp/docker-start-${project_name}.log; then
            sleep 3
            # Check if containers actually started
            if docker-compose ps 2>/dev/null | grep -q "Up"; then
                echo "  ✓ Started successfully"
                ((STARTED++))
            else
                echo "  ⚠ Started but containers not running (check logs)"
                echo "     docker-compose logs in $project_dir"
                ((FAILED++))
            fi
        else
            echo "  ✗ Failed to start (see /tmp/docker-start-${project_name}.log)"
            ((FAILED++))
        fi
        echo ""
    fi
done <<< "$COMPOSE_FILES"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Docker containers summary:"
echo "  Started: $STARTED"
echo "  Failed: $FAILED"
echo "  Total: $COMPOSE_COUNT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    echo "All running containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | head -20
    
    mark_step_done "step6_docker"
    echo ""
fi

# ============================================
# STEP 7: START PM2 APPS
# ============================================
if ! is_step_done "step7_pm2"; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 7: Starting PM2 Applications"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Load NVM for PM2
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    if [ -f "/root/.pm2/dump.pm2" ]; then
        echo "Restoring PM2 apps..."
        pm2 resurrect || echo "⚠ PM2 resurrect failed (maybe no saved apps)"
        pm2 save
        pm2 list
    else
        echo "⚠ PM2 dump not found - no apps to restore"
    fi
    
    mark_step_done "step7_pm2"
    echo ""
else
    echo "⏭️  STEP 7: PM2 Apps - Already done, current status:"
    pm2 list 2>/dev/null || echo "   No PM2 apps running"
    echo ""
fi

# ============================================
# STEP 8: VERIFY EVERYTHING
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 8: Final Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "System load:"
uptime

echo ""
echo "Docker containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "PM2 apps:"
pm2 list 2>/dev/null || echo "PM2 not configured"

echo ""
echo "Nginx status:"
curl -I http://localhost 2>/dev/null | head -1 || echo "⚠ Nginx not responding"

echo ""
echo "Open ports (should be localhost only for DB):"
ss -tunlp | grep "0.0.0.0" | grep -v ":80\|:443\|:2222\|:25"

echo ""
echo "============================================"
echo "  ✅ RESTORE COMPLETE!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Test SSH: ssh -p 2254 root@SERVER_IP"
echo "  2. Check websites in browser"
echo "  3. Run security audit: /root/security-check.sh"
echo ""
echo "To reset and run from scratch:"
echo "  rm /root/.restore-state"
echo "  ./complete-server-restore.sh"
echo ""