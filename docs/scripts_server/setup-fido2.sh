#!/bin/bash

# ============================================
# FIDO2 SSH SETUP SCRIPT
# ============================================

set -e

echo "============================================"
echo "  🔐 FIDO2 SSH Setup"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ============================================
# STEP 1: Check OpenSSH version
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Checking OpenSSH version"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SSH_VERSION=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+' | head -1)
echo "OpenSSH version: $SSH_VERSION"

# Check if version is 8.2 or higher
MAJOR=$(echo $SSH_VERSION | cut -d. -f1)
MINOR=$(echo $SSH_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 8 ] || ([ "$MAJOR" -eq 8 ] && [ "$MINOR" -lt 2 ]); then
    echo -e "${RED}✗ OpenSSH version $SSH_VERSION is too old. Need 8.2+ for FIDO2 support${NC}"
    echo "Upgrading OpenSSH..."
    
    apt-get update
    apt-get install -y openssh-client openssh-server
    
    systemctl restart ssh
    echo -e "${GREEN}✓ OpenSSH upgraded${NC}"
else
    echo -e "${GREEN}✓ OpenSSH version $SSH_VERSION supports FIDO2${NC}"
fi

echo ""

# ============================================
# STEP 2: Check libfido2
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Checking libfido2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if dpkg -l | grep -q libfido2-1; then
    FIDO_VERSION=$(dpkg -l | grep libfido2-1 | awk '{print $3}')
    echo -e "${GREEN}✓ libfido2 installed: $FIDO_VERSION${NC}"
else
    echo "Installing libfido2..."
    apt-get update
    apt-get install -y libfido2-1 libfido2-dev
    echo -e "${GREEN}✓ libfido2 installed${NC}"
fi

echo ""

# ============================================
# STEP 3: Configure SSH for FIDO2
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Configuring SSH for FIDO2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_BACKUP="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"

# Backup config
cp "$SSH_CONFIG" "$SSH_CONFIG_BACKUP"
echo "✓ Backup created: $SSH_CONFIG_BACKUP"

# Check and enable PubkeyAuthentication
if ! grep -q "^PubkeyAuthentication" "$SSH_CONFIG"; then
    echo "PubkeyAuthentication yes" >> "$SSH_CONFIG"
    echo "✓ Added PubkeyAuthentication yes"
elif grep -q "^PubkeyAuthentication no" "$SSH_CONFIG"; then
    sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' "$SSH_CONFIG"
    echo "✓ Changed PubkeyAuthentication to yes"
else
    echo "✓ PubkeyAuthentication already enabled"
fi

# Ensure AuthorizedKeysFile includes standard location
if ! grep -q "^AuthorizedKeysFile" "$SSH_CONFIG"; then
    echo "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2" >> "$SSH_CONFIG"
    echo "✓ Added AuthorizedKeysFile"
fi

# Test SSH config
if sshd -t; then
    echo -e "${GREEN}✓ SSH configuration is valid${NC}"
    systemctl reload ssh
    echo -e "${GREEN}✓ SSH reloaded${NC}"
else
    echo -e "${RED}✗ SSH configuration has errors. Restoring backup...${NC}"
    cp "$SSH_CONFIG_BACKUP" "$SSH_CONFIG"
    exit 1
fi

echo ""

# ============================================
# STEP 4: Setup .ssh directory
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Setting up .ssh directory"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/authorized_keys ]; then
    touch ~/.ssh/authorized_keys
    echo "✓ Created authorized_keys file"
fi

chmod 600 ~/.ssh/authorized_keys
echo -e "${GREEN}✓ .ssh directory ready${NC}"
echo ""

# ============================================
# STEP 5: Instructions for key generation
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: Generate FIDO2 key on your Mac"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: You need a physical FIDO2 key (YubiKey, Google Titan, etc.)${NC}"
echo ""
echo "On your Mac, run one of these commands:"
echo ""
echo -e "${BLUE}# For ECDSA-SK (recommended):${NC}"
echo "  ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ecdsa_sk -C \"your_email@example.com\""
echo ""
echo -e "${BLUE}# OR for Ed25519-SK:${NC}"
echo "  ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -C \"your_email@example.com\""
echo ""
echo -e "${YELLOW}You will be prompted to touch your FIDO2 key during generation.${NC}"
echo ""
read -p "Press Enter when you've generated the key on your Mac..."

echo ""

# ============================================
# STEP 6: Get public key from user
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 6: Add FIDO2 public key to server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "On your Mac, display the public key:"
echo ""
echo -e "${BLUE}  cat ~/.ssh/id_ecdsa_sk.pub${NC}"
echo ""
echo -e "${BLUE}  # OR${NC}"
echo ""
echo -e "${BLUE}  cat ~/.ssh/id_ed25519_sk.pub${NC}"
echo ""
echo -e "${YELLOW}Copy the entire public key (starts with 'sk-ecdsa-sha2-nistp256@openssh.com' or 'sk-ssh-ed25519@openssh.com')${NC}"
echo ""
echo "Paste the public key below (press Enter, then paste, then Enter again, then Ctrl+D):"
echo ""

# Read multi-line input until EOF (Ctrl+D)
PUBLIC_KEY=$(cat)

# Validate the key
if echo "$PUBLIC_KEY" | grep -qE "^(sk-ecdsa-sha2-nistp256@openssh\.com|sk-ssh-ed25519@openssh\.com)"; then
    echo ""
    echo -e "${GREEN}✓ Valid FIDO2 public key detected${NC}"
    
    # Check if key already exists
    if grep -Fxq "$PUBLIC_KEY" ~/.ssh/authorized_keys; then
        echo -e "${YELLOW}⚠ Key already exists in authorized_keys${NC}"
    else
        # Add key to authorized_keys
        echo "$PUBLIC_KEY" >> ~/.ssh/authorized_keys
        echo -e "${GREEN}✓ FIDO2 public key added to authorized_keys${NC}"
    fi
    
    # Show current authorized keys count
    KEY_COUNT=$(wc -l < ~/.ssh/authorized_keys)
    echo "Total keys in authorized_keys: $KEY_COUNT"
else
    echo -e "${RED}✗ Invalid FIDO2 public key format${NC}"
    echo "Key should start with 'sk-ecdsa-sha2-nistp256@openssh.com' or 'sk-ssh-ed25519@openssh.com'"
    exit 1
fi

echo ""

# ============================================
# STEP 7: Test connection
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 7: Testing FIDO2 connection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To test the connection from your Mac, run:"
echo ""
echo -e "${BLUE}  ssh -i ~/.ssh/id_ecdsa_sk root@$(hostname -I | awk '{print $1}')${NC}"
echo ""
echo -e "${YELLOW}You will be prompted to touch your FIDO2 key when connecting.${NC}"
echo ""
echo "Current server IP addresses:"
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1"
echo ""

# ============================================
# FINAL SUMMARY
# ============================================
echo "============================================"
echo -e "  ${GREEN}✅ FIDO2 Setup Complete!${NC}"
echo "============================================"
echo ""
echo "Summary:"
echo "  ✓ OpenSSH configured for FIDO2"
echo "  ✓ libfido2 installed"
echo "  ✓ Public key added to ~/.ssh/authorized_keys"
echo ""
echo "Next steps:"
echo "  1. Test connection from your Mac with FIDO2 key"
echo "  2. Consider disabling password authentication (optional)"
echo "  3. Keep your FIDO2 key safe!"
echo ""
echo "To disable password authentication (optional):"
echo "  Edit /etc/ssh/sshd_config and set:"
echo "    PasswordAuthentication no"
echo "    ChallengeResponseAuthentication no"
echo ""
echo "Then run: systemctl reload ssh"
echo ""

