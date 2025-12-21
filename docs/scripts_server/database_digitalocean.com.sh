#!/bin/bash

# ============================================
# DIGITAL OCEAN MONGODB CONNECTION MANAGER
# ============================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

CONFIG_DIR="/root/.mongodb-digitalocean"
CONFIG_FILE="$CONFIG_DIR/databases.json"

# Create config directory
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Function to print header
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to print info
print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# ============================================
# Install MongoDB Shell (mongosh)
# ============================================
install_mongosh() {
    if command -v mongosh &> /dev/null; then
        print_success "MongoDB Shell already installed: $(mongosh --version | head -1)"
        return 0
    fi
    
    print_info "Installing MongoDB Shell (mongosh)..."
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS"
        return 1
    fi
    
    # Install based on OS
    case $OS in
        ubuntu|debian)
            # Install mongosh for Ubuntu/Debian
            curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
            echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
            apt-get update
            apt-get install -y mongodb-mongosh
            ;;
        centos|rhel|fedora)
            # Install mongosh for CentOS/RHEL
            cat > /etc/yum.repos.d/mongodb-org-7.0.repo << EOF
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-7.0.asc
EOF
            yum install -y mongodb-mongosh
            ;;
        *)
            print_error "Unsupported OS: $OS"
            return 1
            ;;
    esac
    
    if command -v mongosh &> /dev/null; then
        print_success "MongoDB Shell installed: $(mongosh --version | head -1)"
    else
        print_error "Failed to install MongoDB Shell"
        return 1
    fi
}

# ============================================
# Ensure MongoDB Shell is installed
# ============================================
ensure_mongosh_installed() {
    if ! command -v mongosh &> /dev/null; then
        print_warning "MongoDB Shell (mongosh) is not installed"
        print_info "Installing MongoDB Shell..."
        if ! install_mongosh; then
            print_error "Failed to install MongoDB Shell. Please install it manually using option 8."
            return 1
        fi
    fi
    return 0
}

# ============================================
# Add new database connection
# ============================================
add_database() {
    print_header "Add New Database Connection"
    
    echo "Enter database connection details:"
    echo ""
    
    read -p "Database name (alias): " db_name
    if [ -z "$db_name" ]; then
        print_error "Database name cannot be empty"
        return 1
    fi
    
    # Check if already exists
    if [ -f "$CONFIG_FILE" ]; then
        if jq -e ".[\"$db_name\"]" "$CONFIG_FILE" > /dev/null 2>&1; then
            print_warning "Database '$db_name' already exists"
            read -p "Overwrite? (y/n): " overwrite
            if [ "$overwrite" != "y" ]; then
                return 1
            fi
        fi
    fi
    
    read -p "MongoDB connection string (mongodb+srv://...): " connection_string
    
    # Extract username, password, host from connection string if provided
    if [[ $connection_string == mongodb+srv://* ]]; then
        # Parse connection string
        CONN_STR="$connection_string"
    else
        # Manual entry
        read -p "Username: " username
        read -sp "Password: " password
        echo ""
        read -p "Host (mongodb+srv://...): " host
        read -p "Database name (default: admin): " database
        database=${database:-admin}
        
        # Build connection string
        CONN_STR="mongodb+srv://${username}:${password}@${host}/${database}?retryWrites=true&w=majority"
    fi
    
    # Save to config file
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "{}" > "$CONFIG_FILE"
    fi
    
    # Add/update database config
    jq --arg name "$db_name" --arg conn "$CONN_STR" \
       ".[\$name] = {\"connection_string\": \$conn, \"added_at\": \"$(date -Iseconds)\"}" \
       "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    chmod 600 "$CONFIG_FILE"
    
    print_success "Database '$db_name' added"
    
    # Test connection
    echo ""
    read -p "Test connection now? (y/n): " test_conn
    if [ "$test_conn" == "y" ]; then
        test_connection "$db_name"
    fi
}

# ============================================
# Test database connection
# ============================================
test_connection() {
    local db_name=$1
    
    if ! ensure_mongosh_installed; then
        return 1
    fi
    
    if [ -z "$db_name" ]; then
        print_error "Database name required"
        return 1
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    local conn_str=$(jq -r ".[\"$db_name\"].connection_string" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$conn_str" ] || [ "$conn_str" == "null" ]; then
        print_error "Database '$db_name' not found"
        return 1
    fi
    
    print_info "Testing connection to '$db_name'..."
    
    # Test connection (timeout after 10 seconds)
    if timeout 10 mongosh "$conn_str" --eval "db.adminCommand('ping')" --quiet 2>/dev/null; then
        print_success "Connection successful!"
        return 0
    else
        print_error "Connection failed"
        return 1
    fi
}

# ============================================
# Connect to database
# ============================================
connect_database() {
    local db_name=$1
    
    if ! ensure_mongosh_installed; then
        return 1
    fi
    
    if [ -z "$db_name" ]; then
        if ! select_database "Select database to connect"; then
            return 1
        fi
        db_name="$SELECTED_DB"
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    local conn_str=$(jq -r ".[\"$db_name\"].connection_string" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$conn_str" ] || [ "$conn_str" == "null" ]; then
        print_error "Database '$db_name' not found"
        return 1
    fi
    
    print_info "Connecting to '$db_name'..."
    echo ""
    
    # Connect to MongoDB
    mongosh "$conn_str"
}

# ============================================
# List all databases
# ============================================
list_databases() {
    print_header "Configured Databases"
    
    if [ ! -f "$CONFIG_FILE" ] || [ ! -s "$CONFIG_FILE" ]; then
        print_warning "No databases configured"
        return 1
    fi
    
    echo ""
    jq -r 'to_entries[] | "\(.key) - Added: \(.value.added_at // "unknown")"' "$CONFIG_FILE" | while IFS=' - ' read -r name date; do
        echo -e "  ${GREEN}•${NC} $name ${BLUE}($date)${NC}"
    done
    echo ""
}

# ============================================
# Select database from list by number
# ============================================
select_database() {
    local prompt_text=${1:-"Select database"}
    
    if [ ! -f "$CONFIG_FILE" ] || [ ! -s "$CONFIG_FILE" ]; then
        print_warning "No databases configured"
        return 1
    fi
    
    # Save database list to temp file
    local temp_file=$(mktemp)
    jq -r 'to_entries[] | "\(.key)|\(.value.added_at // "unknown")"' "$CONFIG_FILE" > "$temp_file"
    
    local total=$(wc -l < "$temp_file")
    
    if [ "$total" -eq 0 ]; then
        print_error "No databases found"
        rm -f "$temp_file"
        return 1
    fi
    
    echo ""
    echo "$prompt_text:"
    echo ""
    
    # Display numbered list
    local counter=1
    while IFS='|' read -r db_name date; do
        if [ -n "$db_name" ]; then
            echo -e "  ${GREEN}$counter${NC}) $db_name ${BLUE}($date)${NC}"
            ((counter++))
        fi
    done < "$temp_file"
    
    echo ""
    read -p "Enter number (1-$total): " selection
    
    if [ -z "$selection" ] || ! [[ "$selection" =~ ^[0-9]+$ ]]; then
        print_error "Invalid selection"
        rm -f "$temp_file"
        return 1
    fi
    
    if [ "$selection" -ge 1 ] && [ "$selection" -le "$total" ]; then
        SELECTED_DB=$(sed -n "${selection}p" "$temp_file" | cut -d'|' -f1)
        rm -f "$temp_file"
        return 0
    else
        print_error "Invalid number. Must be between 1 and $total"
        rm -f "$temp_file"
        return 1
    fi
}

# ============================================
# Remove database
# ============================================
remove_database() {
    print_header "Remove Database Connection"
    
    if ! select_database "Select database to remove"; then
        return 1
    fi
    
    local db_name="$SELECTED_DB"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    if ! jq -e ".[\"$db_name\"]" "$CONFIG_FILE" > /dev/null 2>&1; then
        print_error "Database '$db_name' not found"
        return 1
    fi
    
    read -p "Are you sure you want to remove '$db_name'? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        return 1
    fi
    
    jq "del(.[\"$db_name\"])" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    print_success "Database '$db_name' removed"
}

# ============================================
# Show connection string (masked)
# ============================================
show_connection_string() {
    local db_name=$1
    
    if [ -z "$db_name" ]; then
        if ! select_database "Select database"; then
            return 1
        fi
        db_name="$SELECTED_DB"
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    local conn_str=$(jq -r ".[\"$db_name\"].connection_string" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$conn_str" ] || [ "$conn_str" == "null" ]; then
        print_error "Database '$db_name' not found"
        return 1
    fi
    
    # Mask password in connection string
    local masked=$(echo "$conn_str" | sed 's/:\/\/[^:]*:[^@]*@/:\/\/***:***@/')
    
    echo ""
    print_info "Connection string for '$db_name':"
    echo "  $masked"
    echo ""
}

# ============================================
# Create connection script
# ============================================
create_connection_script() {
    local db_name=$1
    
    if ! ensure_mongosh_installed; then
        return 1
    fi
    
    if [ -z "$db_name" ]; then
        if ! select_database "Select database to create script for"; then
            return 1
        fi
        db_name="$SELECTED_DB"
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    local conn_str=$(jq -r ".[\"$db_name\"].connection_string" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$conn_str" ] || [ "$conn_str" == "null" ]; then
        print_error "Database '$db_name' not found"
        return 1
    fi
    
    local script_path="/usr/local/bin/mongo-${db_name}"
    
    cat > "$script_path" << EOF
#!/bin/bash
# Auto-generated connection script for $db_name
mongosh "$conn_str" "\$@"
EOF
    
    chmod +x "$script_path"
    
    print_success "Connection script created: $script_path"
    echo ""
    print_info "You can now connect using: mongo-${db_name}"
}

# ============================================
# Restore database from backup directory
# ============================================
restore_from_backup() {
    print_header "Restore Database from Backup"
    
    if ! ensure_mongosh_installed; then
        return 1
    fi
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        return 1
    fi
    
    # Select target database
    if ! select_database "Select target database to restore to"; then
        return 1
    fi
    local target_db="$SELECTED_DB"
    
    # Get connection string
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "No databases configured"
        return 1
    fi
    
    local conn_str=$(jq -r ".[\"$target_db\"].connection_string" "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$conn_str" ] || [ "$conn_str" == "null" ]; then
        print_error "Database '$target_db' not found"
        return 1
    fi
    
    # Get backup path
    echo ""
    read -p "Enter path to backup directory (e.g., /home/m.w100n/mongo_data.backup_20251215_143346): " backup_path
    
    if [ -z "$backup_path" ]; then
        print_error "Backup path cannot be empty"
        return 1
    fi
    
    if [ ! -d "$backup_path" ]; then
        print_error "Backup directory does not exist: $backup_path"
        return 1
    fi
    
    print_info "Backup path: $backup_path"
    print_info "Target database: $target_db"
    echo ""
    read -p "Continue with restore? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        return 1
    fi
    
    # Create temp directory for dump
    local temp_dump_dir=$(mktemp -d)
    local temp_container_name="mongo-restore-temp-$$"
    
    print_info "Starting temporary MongoDB container with backup data..."
    
    # Start temporary MongoDB container with backup data
    if ! docker run -d --name "$temp_container_name" \
        -v "$backup_path:/data/db" \
        -p 27018:27017 \
        mongo:8.0 --noauth 2>/dev/null; then
        print_error "Failed to start temporary MongoDB container"
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    # Wait for MongoDB to start
    print_info "Waiting for MongoDB to start..."
    sleep 10
    
    # Check if container is running
    if ! docker ps | grep -q "$temp_container_name"; then
        print_error "Temporary container failed to start"
        docker logs "$temp_container_name" 2>&1 | tail -20
        docker rm -f "$temp_container_name" 2>/dev/null
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    # Install mongodb-database-tools if needed
    if ! command -v mongodump &> /dev/null; then
        print_info "Installing MongoDB Database Tools..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
        else
            print_error "Cannot detect OS"
            docker rm -f "$temp_container_name" 2>/dev/null
            rm -rf "$temp_dump_dir"
            return 1
        fi
        
        case $OS in
            ubuntu|debian)
                wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | apt-key add -
                echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
                apt-get update
                apt-get install -y mongodb-database-tools
                ;;
            centos|rhel|fedora)
                cat > /etc/yum.repos.d/mongodb-org-7.0.repo << EOF
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-7.0.asc
EOF
                yum install -y mongodb-database-tools
                ;;
            *)
                print_error "Unsupported OS: $OS"
                docker rm -f "$temp_container_name" 2>/dev/null
                rm -rf "$temp_dump_dir"
                return 1
                ;;
        esac
    fi
    
    # Create dump from temporary container
    print_info "Creating dump from backup data..."
    if ! mongodump --host localhost:27018 --out "$temp_dump_dir" 2>/dev/null; then
        print_error "Failed to create dump from backup"
        docker rm -f "$temp_container_name" 2>/dev/null
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    print_success "Dump created successfully"
    
    # Stop and remove temporary container
    print_info "Stopping temporary container..."
    docker rm -f "$temp_container_name" 2>/dev/null
    
    # Restore to DigitalOcean MongoDB
    print_info "Restoring to DigitalOcean MongoDB: $target_db"
    echo ""
    
    # Find the database name in dump
    local db_name=$(ls -1 "$temp_dump_dir" 2>/dev/null | head -1)
    if [ -z "$db_name" ]; then
        print_error "No database found in dump"
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    print_info "Found database in dump: $db_name"
    read -p "Restore database '$db_name' to '$target_db'? (y/n): " confirm_restore
    if [ "$confirm_restore" != "y" ]; then
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    # Restore using mongorestore
    if ! mongorestore --uri="$conn_str" --drop "$temp_dump_dir/$db_name" 2>/dev/null; then
        print_error "Failed to restore to DigitalOcean MongoDB"
        rm -rf "$temp_dump_dir"
        return 1
    fi
    
    print_success "Database restored successfully!"
    
    # Cleanup
    rm -rf "$temp_dump_dir"
    
    echo ""
    read -p "Test connection to restored database? (y/n): " test_conn
    if [ "$test_conn" == "y" ]; then
        test_connection "$target_db"
    fi
}

# ============================================
# Main menu
# ============================================
main_menu() {
    while true; do
        clear
        echo "============================================"
        echo "  🗄️  Digital Ocean MongoDB Manager"
        echo "============================================"
        echo ""
        echo "  1) ➕ Add new database"
        echo "  2) 📋 List all databases"
        echo "  3) 🔌 Connect to database"
        echo "  4) 🧪 Test connection"
        echo "  5) 👁️  Show connection string"
        echo "  6) 🔧 Create connection script"
        echo "  7) 🗑️  Remove database"
        echo "  8) 📦 Install/Update MongoDB Shell"
        echo "  9) 🔄 Restore from backup"
        echo "  0) ❌ Exit"
        echo ""
        read -p "Your choice (0-9): " choice
        
        case $choice in
            1)
                add_database
                read -p "Press Enter to continue..."
                ;;
            2)
                list_databases
                read -p "Press Enter to continue..."
                ;;
            3)
                connect_database
                ;;
            4)
                if select_database "Select database to test"; then
                    test_connection "$SELECTED_DB"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                show_connection_string
                read -p "Press Enter to continue..."
                ;;
            6)
                create_connection_script
                read -p "Press Enter to continue..."
                ;;
            7)
                remove_database
                read -p "Press Enter to continue..."
                ;;
            8)
                install_mongosh
                read -p "Press Enter to continue..."
                ;;
            9)
                restore_from_backup
                read -p "Press Enter to continue..."
                ;;
            0)
                echo ""
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# ============================================
# Check if jq is installed
# ============================================
if ! command -v jq &> /dev/null; then
    print_info "Installing jq..."
    apt-get update && apt-get install -y jq || yum install -y jq
fi

# ============================================
# Run
# ============================================
if [ "$1" == "add" ]; then
    add_database
elif [ "$1" == "list" ]; then
    list_databases
elif [ "$1" == "connect" ]; then
    connect_database "$2"
elif [ "$1" == "test" ]; then
    test_connection "$2"
elif [ "$1" == "remove" ]; then
    remove_database
elif [ "$1" == "show" ]; then
    show_connection_string "$2"
elif [ "$1" == "script" ]; then
    create_connection_script "$2"
elif [ "$1" == "install" ]; then
    install_mongosh
elif [ "$1" == "restore" ]; then
    restore_from_backup
else
    main_menu
fi

