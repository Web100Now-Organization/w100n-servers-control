#!/bin/bash

#######################################
# MAIN SERVER INITIALIZATION SCRIPT
# Runs all setup scripts in correct order
#######################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/root/backup"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Server Initialization"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if this is a restore or fresh setup
HAS_BACKUP=false
if [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
    echo "✓ Backup found in $BACKUP_DIR"
    HAS_BACKUP=true
else
    echo "ℹ No backup found - fresh setup"
fi
echo ""

read -p "Continue? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1/4: Secure Server Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "$SCRIPT_DIR/secure-server-setup.sh" ]; then
    bash "$SCRIPT_DIR/secure-server-setup.sh"
    echo ""
    echo -e "${GREEN}✓ Server setup complete${NC}"
else
    echo -e "${YELLOW}⚠ secure-server-setup.sh not found, skipping${NC}"
fi

sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2/4: Create Secure User"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "$SCRIPT_DIR/create-secure-user.sh" ]; then
    bash "$SCRIPT_DIR/create-secure-user.sh"
    echo ""
    echo -e "${GREEN}✓ User created${NC}"
else
    echo -e "${YELLOW}⚠ create-secure-user.sh not found, skipping${NC}"
fi

sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3/4: Restore (if backup exists)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$HAS_BACKUP" = true ]; then
    if [ -f "$SCRIPT_DIR/complete-server-restore.sh" ]; then
        read -p "Run restore from backup? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            bash "$SCRIPT_DIR/complete-server-restore.sh"
            echo ""
            echo -e "${GREEN}✓ Restore complete${NC}"
        else
            echo "Restore skipped"
        fi
    else
        echo -e "${YELLOW}⚠ complete-server-restore.sh not found${NC}"
    fi
else
    echo "No backup - skipping restore"
fi

sleep 2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4/4: Security Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "$SCRIPT_DIR/security-check.sh" ]; then
    bash "$SCRIPT_DIR/security-check.sh"
    echo ""
    echo -e "${GREEN}✓ Security check complete${NC}"
else
    echo -e "${YELLOW}⚠ security-check.sh not found${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ SERVER INITIALIZATION COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Summary:"
echo "  ✓ Server secured"
echo "  ✓ User created"
if [ "$HAS_BACKUP" = true ]; then
    echo "  ✓ Backup restored"
fi
echo "  ✓ Security verified"
echo ""
echo "Next steps:"
echo "  1. Test SSH connection from local machine"
echo "  2. Check websites/apps"
echo "  3. Monitor logs: docker ps, pm2 list"
echo ""
echo "Quick fixes available:"
echo "  bash scripts/quick-fix.sh"
echo ""


