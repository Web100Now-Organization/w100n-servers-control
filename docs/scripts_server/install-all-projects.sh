#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🔍 Searching for projects with package.json in /var/web100now..."
echo ""

# Counters
total_projects=0
success_count=0
error_count=0

# Create temp file for counters (to avoid subshell issue)
COUNTER_FILE=$(mktemp)
echo "0 0 0" > "$COUNTER_FILE"

# Find all package.json files (max 5 levels deep)
while IFS= read -r package_file; do
    # Read counters from file
    read total_projects success_count error_count < "$COUNTER_FILE"
    total_projects=$((total_projects + 1))
    echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
    
    project_dir=$(dirname "$package_file")
    project_name=$(basename "$project_dir")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${YELLOW}📦 Project: $project_name${NC}"
    echo "📂 Directory: $project_dir"
    
    # Navigate to directory
    cd "$project_dir" || continue
    
    # Read name from package.json
    pm2_name=$(node -p "try { require('./package.json').name } catch(e) { '' }" 2>/dev/null)
    
    if [ -z "$pm2_name" ]; then
        echo -e "${RED}⚠ Could not read 'name' from package.json${NC}"
        pm2_name="$project_name"
    fi
    
    echo -e "${BLUE}🏷  PM2 Name: $pm2_name${NC}"
    echo ""
    
    # Check if process exists in PM2
    pm2_status=$(pm2 jlist 2>/dev/null | node -p "
        try {
            const list = JSON.parse(require('fs').readFileSync('/dev/stdin', 'utf8'));
            const app = list.find(a => a.name === '$pm2_name');
            app ? app.pm2_env.status : 'not_found';
        } catch(e) { 'not_found' }
    " 2>/dev/null)
    
    if [ "$pm2_status" = "errored" ]; then
        echo -e "${RED}🔴 PM2 process '$pm2_name' has 'errored' status${NC}"
        echo -e "${YELLOW}🗑  Deleting old process...${NC}"
        pm2 delete "$pm2_name" 2>/dev/null
        need_restart=true
    elif [ "$pm2_status" = "online" ]; then
        echo -e "${GREEN}✅ PM2 process '$pm2_name' is already running${NC}"
        need_restart=false
    elif [ "$pm2_status" = "stopped" ]; then
        echo -e "${YELLOW}⏸  PM2 process '$pm2_name' is stopped${NC}"
        need_restart=true
    else
        echo -e "${BLUE}ℹ  PM2 process '$pm2_name' not found${NC}"
        need_restart=true
    fi
    
    echo ""
    
    # Install dependencies
    echo -e "${GREEN}▶ Running: pnpm install${NC}"
    if pnpm install 2>&1 | tee /tmp/pnpm_install.log; then
        echo -e "${GREEN}✅ pnpm install - success${NC}"
    else
        echo -e "${RED}❌ pnpm install - failed${NC}"
        read total_projects success_count error_count < "$COUNTER_FILE"
        error_count=$((error_count + 1))
        echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
        echo ""
        continue
    fi
    
    echo ""
    
    # Check if build script exists
    has_build=$(node -p "try { JSON.stringify(require('./package.json').scripts.build) !== 'undefined' } catch(e) { false }" 2>/dev/null)
    
    if [ "$has_build" = "true" ]; then
        echo -e "${GREEN}▶ Running: pnpm run build${NC}"
        if pnpm run build 2>&1 | tee /tmp/pnpm_build.log; then
            echo -e "${GREEN}✅ pnpm run build - success${NC}"
        else
            echo -e "${RED}❌ pnpm run build - failed${NC}"
            read total_projects success_count error_count < "$COUNTER_FILE"
            error_count=$((error_count + 1))
            echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
            echo ""
            continue
        fi
    else
        echo -e "${YELLOW}⚠ 'build' script not found in package.json (skipping)${NC}"
    fi
    
    echo ""
    
    # Start via PM2 if needed
    if [ "$need_restart" = true ]; then
        echo -e "${BLUE}🚀 Starting via PM2...${NC}"
        
        # Check if ecosystem.config.js exists
        if [ -f "ecosystem.config.js" ]; then
            echo -e "${GREEN}▶ Found ecosystem.config.js${NC}"
            if pm2 start ecosystem.config.js --update-env 2>&1; then
                echo -e "${GREEN}✅ PM2 start - success${NC}"
                read total_projects success_count error_count < "$COUNTER_FILE"
                success_count=$((success_count + 1))
                echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
            else
                echo -e "${RED}❌ PM2 start - failed${NC}"
                read total_projects success_count error_count < "$COUNTER_FILE"
                error_count=$((error_count + 1))
                echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
            fi
        else
            # Try to start via package.json start script
            has_start=$(node -p "try { JSON.stringify(require('./package.json').scripts.start) !== 'undefined' } catch(e) { false }" 2>/dev/null)
            
            if [ "$has_start" = "true" ]; then
                echo -e "${GREEN}▶ Starting via 'pnpm start'${NC}"
                # Use node interpreter explicitly to avoid pnpm version issues
                if pm2 start --interpreter node --name "$pm2_name" -- $(which pnpm) start 2>&1; then
                    echo -e "${GREEN}✅ PM2 start - success${NC}"
                    read total_projects success_count error_count < "$COUNTER_FILE"
                    success_count=$((success_count + 1))
                    echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
                else
                    echo -e "${RED}❌ PM2 start - failed${NC}"
                    read total_projects success_count error_count < "$COUNTER_FILE"
                    error_count=$((error_count + 1))
                    echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
                fi
            else
                echo -e "${YELLOW}⚠ ecosystem.config.js or start script not found${NC}"
            fi
        fi
    else
        echo -e "${BLUE}♻️  Restarting existing process...${NC}"
        if pm2 restart "$pm2_name" --update-env 2>&1; then
            echo -e "${GREEN}✅ PM2 restart - success${NC}"
            read total_projects success_count error_count < "$COUNTER_FILE"
            success_count=$((success_count + 1))
            echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
        else
            echo -e "${RED}❌ PM2 restart - failed${NC}"
            read total_projects success_count error_count < "$COUNTER_FILE"
            error_count=$((error_count + 1))
            echo "$total_projects $success_count $error_count" > "$COUNTER_FILE"
        fi
    fi
    
    echo ""
    echo -e "${GREEN}✅ $project_name - completed${NC}"
    echo ""
done < <(find /var/web100now -maxdepth 5 -name "package.json" -type f -not -path "*/.next/*" -not -path "*/node_modules/*" -not -path "*/.git/*")

# Read final counters
read total_projects success_count error_count < "$COUNTER_FILE"
rm -f "$COUNTER_FILE"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}🎉 Processing completed!${NC}"
echo ""
echo -e "${BLUE}📊 Statistics:${NC}"
echo -e "   Total projects: $total_projects"
echo -e "   ${GREEN}Successful: $success_count${NC}"
echo -e "   ${RED}Errors: $error_count${NC}"
echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "   1. Check status: ${GREEN}pm2 list${NC}"
echo "   2. View logs: ${GREEN}pm2 logs${NC}"
echo "   3. Save configuration: ${GREEN}pm2 save${NC}"
echo ""
echo -e "${BLUE}💡 Tip: If you see pnpm errors, try:${NC}"
echo "   ${GREEN}npm uninstall -g pnpm && npm install -g pnpm@9${NC}"
echo ""