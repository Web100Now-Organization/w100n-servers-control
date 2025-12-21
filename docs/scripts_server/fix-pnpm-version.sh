#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🔧 Fixing pnpm version compatibility issues..."
echo ""

# Check current versions
echo -e "${BLUE}📊 Current versions:${NC}"
echo "Node.js: $(node -v)"
echo "npm: $(npm -v)"
echo "pnpm: $(pnpm -v 2>/dev/null || echo 'not installed')"
echo "PM2: $(pm2 -v 2>/dev/null || echo 'not installed')"
echo ""

# Uninstall current pnpm
echo -e "${YELLOW}🗑  Uninstalling current pnpm...${NC}"
npm uninstall -g pnpm 2>/dev/null

# Install compatible pnpm version (v9 works with older Node.js)
echo -e "${GREEN}📦 Installing pnpm@9 (compatible version)...${NC}"
npm install -g pnpm@9

# Verify installation
echo ""
echo -e "${GREEN}✅ New pnpm version: $(pnpm -v)${NC}"
echo ""

# Update PM2 to latest
echo -e "${BLUE}🔄 Updating PM2...${NC}"
pm2 save 2>/dev/null
pm2 kill 2>/dev/null
npm uninstall -g pm2 2>/dev/null
npm install -g pm2@latest

echo ""
echo -e "${GREEN}✅ PM2 updated: $(pm2 -v)${NC}"
echo ""

# Restart PM2
echo -e "${BLUE}♻️  Restarting PM2 daemon...${NC}"
pm2 resurrect 2>/dev/null || echo "No previous PM2 processes to restore"
pm2 list

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}🎉 Fix completed!${NC}"
echo ""
echo -e "${YELLOW}📝 What was fixed:${NC}"
echo "   • Downgraded pnpm to v9 (compatible with older Node.js in PM2)"
echo "   • Updated PM2 to latest version"
echo "   • Restarted PM2 daemon"
echo ""
echo -e "${BLUE}💡 Next steps:${NC}"
echo "   1. Run the install script: ${GREEN}./install-all-projects.sh${NC}"
echo "   2. Or manually: ${GREEN}pm2 restart all${NC}"
echo ""

