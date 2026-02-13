#!/bin/bash

# =============================================================================
# WireGuard Gateway & SSH Security Hardening Suite
# Support: Debian 11/12/13, Ubuntu 20.04/22.04/24.04+
# Purpose: Seamless installation on minimal systems, NAT protection and high security.
# =============================================================================


# Rollback function to restore system state in case of failure
rollback() {
    local step=$1
    warn "Rollback starting... Step: $step"
    
    case "$step" in
        "services")
            systemctl stop wg-quick@wg0 2>/dev/null || true
            systemctl disable wg-quick@wg0 2>/dev/null || true
            ;;
        "firewall")
            # Restore original SSH config if we backed up
            if [[ -f "/etc/ssh/sshd_config.d/99-custom.conf.bak" ]]; then
                mv "/etc/ssh/sshd_config.d/99-custom.conf.bak" "/etc/ssh/sshd_config.d/99-custom.conf" 2>/dev/null || true
                systemctl reload ssh 2>/dev/null || true
            fi
            ;;
        *)
            warn "Undefined rollback step: $step"
            ;;
    esac
}

# Error handling function to log errors and perform cleanup
handle_error() {
    local exit_code=$?
    echo -e "${RED}[ERROR]${NC} Error occurred: Line $1, Exit code: $exit_code" | tee -a "$LOG_FILE"
    
    # Attempt cleanup if needed
    if [[ -n "$BACKUP_CREATED" ]]; then
        echo -e "${YELLOW}[WARNING]${NC} Backup file found, restore recommended: $BACKUP_CREATED" | tee -a "$LOG_FILE"
    fi
    
    trap - ERR
    exit $exit_code
}

# Set trap to catch errors
trap 'handle_error $LINENO' ERR

# --- COLORS AND LOGGING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
LOG_FILE="/var/log/wg_setup.log"

log() { echo -e "${BLUE}[$(date +%T)]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; trap - ERR; exit 1; }

# --- 1. PREREQUISITE CHECKS ---
echo -e "${CYAN}===================================================="
echo -e "   WIREGUARD GATEWAY & SSH SECURITY INSTALLER"
echo -e "====================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   error "This script must be run with root privileges!"
fi

# PATH correction (for minimal systems)
export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin

# --- SYSTEM STATE CHECK ---
log "Checking system state..."

# Check if existing WireGuard configuration exists
EXISTING_WG_CONFIG=""
if [[ -d /etc/wireguard ]]; then
    EXISTING_WG_CONFIG="$(find /etc/wireguard -maxdepth 1 -name '*.conf' -print -quit 2>/dev/null)"
fi
if [[ -n "$EXISTING_WG_CONFIG" ]]; then
    warn "Existing WireGuard configuration found: $EXISTING_WG_CONFIG"
    read -p "Continuing will overwrite these configurations. Continue? (y/n) [n]: " WG_OVERWRITE
    WG_OVERWRITE=${WG_OVERWRITE:-n}
    if [[ "$WG_OVERWRITE" != "y" ]]; then
        error "User cancelled."
    fi
fi

# Is WireGuard service running?
if systemctl is-active --quiet wg-quick@wg0; then
    warn "Found running WireGuard service. Stopping..."
    systemctl stop wg-quick@wg0 >> "$LOG_FILE" 2>&1 || true
fi

# --- 2. CONFIGURATION SETUP ---
echo -e "${YELLOW}Please configure installation settings (Press Enter for defaults):${NC}"
echo ""

# Get current user info early
CURRENT_USER="${SUDO_USER:-$USER}"
IS_ROOT_USER=false
if [[ "$CURRENT_USER" == "root" || -z "$CURRENT_USER" || ( "$EUID" -eq 0 && -z "$SUDO_USER" ) ]]; then
    IS_ROOT_USER=true
fi

read -p "WireGuard Port [41194]: " INPUT_WG
WG_PORT=${INPUT_WG:-41194}

# DNS Selection
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}DNS Configuration${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  1) Cloudflare  (1.1.1.1, 1.0.0.1)"
echo -e "  2) Google      (8.8.8.8, 8.8.4.4)"
echo -e "  3) AdGuard     (94.140.14.14, 94.140.15.15)"
echo -e "  4) Custom"
read -p "Select DNS provider [1]: " DNS_CHOICE
DNS_CHOICE=${DNS_CHOICE:-1}

case "$DNS_CHOICE" in
    1) CLIENT_DNS="1.1.1.1, 1.0.0.1" ;;
    2) CLIENT_DNS="8.8.8.8, 8.8.4.4" ;;
    3) CLIENT_DNS="94.140.14.14, 94.140.15.15" ;;
    4)
        read -p "Primary DNS: " CUSTOM_DNS1
        read -p "Secondary DNS: " CUSTOM_DNS2
        if [[ -z "$CUSTOM_DNS1" ]]; then
            warn "No DNS entered, using Cloudflare as default."
            CLIENT_DNS="1.1.1.1, 1.0.0.1"
        elif [[ -z "$CUSTOM_DNS2" ]]; then
            CLIENT_DNS="$CUSTOM_DNS1"
        else
            CLIENT_DNS="$CUSTOM_DNS1, $CUSTOM_DNS2"
        fi
        ;;
    *) CLIENT_DNS="1.1.1.1, 1.0.0.1" ;;
esac
log "DNS configured: $CLIENT_DNS"
echo ""

read -p "Enable automatic security updates? (y/n) [y]: " AUTO_UP
AUTO_UP=${AUTO_UP:-y}

read -p "Reset all existing Firewall (UFW) rules? (y/n) [n]: " RESET_UFW
RESET_UFW=${RESET_UFW:-n}

# Ask about Root Login - but prevent if logged in as root
if [[ "$IS_ROOT_USER" == "true" ]]; then
    echo -e "${RED}⚠️  WARNING: You are logged in as ROOT user!${NC}"
    echo -e "${YELLOW}Disabling root login would lock you out of the system.${NC}"
    echo -e "${YELLOW}Root SSH login will remain ENABLED for your safety.${NC}"
    DISABLE_ROOT=n
    read -p "Press Enter to continue..."
else
    read -p "Disable SSH Root Login? (Recommended for security) (y/n) [y]: " DISABLE_ROOT
    DISABLE_ROOT=${DISABLE_ROOT:-y}
fi

# --- 3. SYSTEM PREPARATION AND PACKAGE INSTALLATION ---
log "Preparing system packages..."

# Update with retry mechanism
RETRY_COUNT=0
MAX_RETRIES=3
while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
    log "Fetching package lists... (attempt: $(($RETRY_COUNT + 1))/$MAX_RETRIES)"
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        log "Package lists updated successfully."
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; then
            warn "Failed to fetch package lists, retrying..."
            sleep 5
        else
            error "Could not update package lists. Please check your internet connection."
        fi
    fi
done

# Install packages with dependency check
PACKAGES="procps iproute2 iptables curl wget ufw fail2ban qrencode openresolv wireguard wireguard-tools unattended-upgrades"

log "Installing required packages: $PACKAGES"

# Check if packages are already installed
MISSING_PACKAGES=""
for pkg in $PACKAGES; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    fi
done

if [[ -n "$MISSING_PACKAGES" ]]; then
    log "Missing packages to install: $MISSING_PACKAGES"
    if ! apt-get install -y $MISSING_PACKAGES --no-install-recommends >> "$LOG_FILE" 2>&1; then
        warn "Some packages failed to install, retrying with --fix-missing..."
        apt-get install -f -y --no-install-recommends >> "$LOG_FILE" 2>&1 || true
        apt-get install -y $MISSING_PACKAGES --no-install-recommends >> "$LOG_FILE" 2>&1 || \
            warn "Some packages could not be installed but continuing with setup..."
    fi
else
    log "All required packages are already installed."
fi

# Verify critical packages are installed
for pkg in wireguard wireguard-tools ufw; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        warn "$pkg package may be missing or not properly installed."
    fi
done

# --- 4. SECURE SSH CONFIGURATION ---
log "Configuring SSH security..."
mkdir -p /etc/ssh/sshd_config.d/

if [[ "$DISABLE_ROOT" == "y" || "$DISABLE_ROOT" == "Y" ]]; then
    PERMIT_ROOT="no"
    log "Root login will be disabled."
    success "You're logged in as '$CURRENT_USER' - you'll still be able to connect with this user."
else
    PERMIT_ROOT="yes"
    if [[ "$IS_ROOT_USER" == "true" ]]; then
        warn "Root login remains enabled (you are logged in as root)."
    else
        warn "Root login remains enabled (not recommended for security)!"
    fi
fi

cat > /etc/ssh/sshd_config.d/99-custom.conf <<EOF
PermitRootLogin $PERMIT_ROOT
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

if ! sshd -t; then
    error "SSH configuration error detected! Stopping operation."
fi

# --- 5. NETWORK DETECTION AND KEY GENERATION ---
log "Detecting network interface and IP..."

# Network interface detection with fallbacks
NET_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -z "$NET_INTERFACE" ]]; then
    # Fallback to first non-loopback interface
    NET_INTERFACE=$(ip link show | grep -v "lo:" | grep -o "^[0-9]*: [^:]*" | head -n1 | cut -d: -f2 | tr -d ' ')
    if [[ -z "$NET_INTERFACE" ]]; then
        error "Network interface not found. Please configure manually."
    else
        warn "Default network interface not found, using: $NET_INTERFACE"
    fi
fi
log "Network interface determined: $NET_INTERFACE"

# Server public IP detection with multiple fallbacks
SERVER_PUBLIC_IP="IP_NOT_FOUND"
for service in "ifconfig.me" "ipecho.net/plain" "checkip.amazonaws.com" "ident.me" "icanhazip.com"; do
    log "Getting external IP address: $service"
    TEMP_IP=$(curl -s -4 --connect-timeout 10 "$service" 2>/dev/null | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | head -n1)
    if [[ -n "$TEMP_IP" && "$TEMP_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        SERVER_PUBLIC_IP="$TEMP_IP"
        log "External IP address obtained: $SERVER_PUBLIC_IP"
        break
    fi
done

if [[ "$SERVER_PUBLIC_IP" == "IP_NOT_FOUND" ]]; then
    warn "Could not obtain external IP address. Setup will continue but needs to be entered manually."
    read -p "Please enter your server's external IP address: " MANUAL_IP
    if [[ -n "$MANUAL_IP" ]]; then
        SERVER_PUBLIC_IP="$MANUAL_IP"
        log "Manual IP address set: $SERVER_PUBLIC_IP"
    else
        error "Cannot continue without external IP address."
    fi
fi

# IP Forwarding
cat > /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
/sbin/sysctl -p /etc/sysctl.d/99-wireguard.conf >> "$LOG_FILE" 2>&1 || true

# Key Generation
WG_DIR="/etc/wireguard"
mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
SERVER_PRIV=$(wg genkey); SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey); CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# --- 6. FIREWALL (UFW) AND NAT CONFIGURATION ---

# Backup current UFW rules before making changes
if [[ -f "/etc/ufw/before.rules" ]]; then
    cp "/etc/ufw/before.rules" "/etc/ufw/before.rules.backup.$(date +%s)" 2>/dev/null || true
    log "UFW before.rules backup created"
fi

if [[ "$RESET_UFW" == "y" ]]; then
    warn "Resetting UFW rules..."
    ufw --force reset >> "$LOG_FILE" 2>&1
fi

log "Processing firewall rules..."

# Check if UFW is already enabled
if ufw status | grep -q "Status: active"; then
    warn "UFW already active, existing rules will be preserved"
    # Check if our ports are already allowed
    if ! ufw status | grep -q "22/tcp"; then
        ufw allow 22/tcp comment 'SSH' >> "$LOG_FILE" 2>&1
    else
        log "SSH port (22) already allowed"
    fi
    
    if ! ufw status | grep -q "$WG_PORT/udp"; then
        ufw allow $WG_PORT/udp comment 'WireGuard Port' >> "$LOG_FILE" 2>&1
    else
        log "WireGuard port ($WG_PORT) already allowed"
    fi
else
    # Fresh UFW setup
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw allow 22/tcp comment 'SSH' >> "$LOG_FILE" 2>&1
    ufw allow $WG_PORT/udp comment 'WireGuard Port' >> "$LOG_FILE" 2>&1
fi

# Modify UFW default forward policy
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

# Smart NAT Control
UFW_BEFORE="/etc/ufw/before.rules"
WG_NAT_RULE="-A POSTROUTING -s 10.8.0.0/24 -o $NET_INTERFACE -j MASQUERADE"

if grep -q "\*nat" "$UFW_BEFORE"; then
    warn "Detected existing NAT rules!"
    echo -e "1) PRESERVE existing rules (insert WireGuard rule in between)"
    echo -e "2) DELETE existing NAT table (write only WireGuard rule)"
    read -p "Selection (1/2): " NAT_CHOICE
    
    if [[ "$NAT_CHOICE" == "1" ]]; then
        # If rule doesn't exist, insert into *nat table
        if ! grep -q "10.8.0.0/24" "$UFW_BEFORE"; then
             # Check if *nat table exists
            if grep -q "^\*nat" "$UFW_BEFORE"; then
                 # Insert after *nat line
                 sed -i "/^\*nat/a $WG_NAT_RULE" "$UFW_BEFORE"
            else
                 # Create *nat table if it doesn't exist (unlikely if choice 1 was offered but safe fallback)
                 sed -i "1i*nat\n:POSTROUTING ACCEPT [0:0]\n$WG_NAT_RULE\nCOMMIT\n" "$UFW_BEFORE"
            fi
        fi
    else
        log "Cleaning old NAT table, backup: $UFW_BEFORE.bak"
        cp "$UFW_BEFORE" "$UFW_BEFORE.bak"
        sed -i '/\*nat/,/COMMIT/d' "$UFW_BEFORE"
        sed -i "1i*nat\n:POSTROUTING ACCEPT [0:0]\n$WG_NAT_RULE\nCOMMIT\n" "$UFW_BEFORE"
    fi
else
    log "Creating new NAT table..."
    sed -i "1i*nat\n:POSTROUTING ACCEPT [0:0]\n$WG_NAT_RULE\nCOMMIT\n" "$UFW_BEFORE"
fi

ufw --force enable >> "$LOG_FILE" 2>&1

# --- 7. SERVICE CONFIGURATION ---
log "Writing server and client configurations..."

# Server Config
cat > $WG_DIR/wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
# IPTables rules added as additional security
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_INTERFACE -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.8.0.2/32
EOF

# Client Config
cat > $WG_DIR/client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.8.0.2/24
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 $WG_DIR/*.conf

# --- 8. AUTOMATED SECURITY UPDATES AND FAIL2BAN CONFIGURATION ---
if [[ "$AUTO_UP" == "y" ]]; then
    log "Configuring automatic security updates..."
    if command -v unattended-upgrade >/dev/null 2>&1; then
        echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
        dpkg-reconfigure -f noninteractive unattended-upgrades >> "$LOG_FILE" 2>&1
    else
        warn "unattended-upgrades package not installed, automatic updates could not be configured."
    fi
fi

# Fail2ban service check
if systemctl is-enabled --quiet fail2ban 2>/dev/null; then
    log "fail2ban already enabled"
else
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
fi

# Restart fail2ban
systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || warn "fail2ban service could not be restarted"

# Enable WireGuard service with validation
if [[ -f "$WG_DIR/wg0.conf" ]]; then
    # Validate WireGuard configuration before enabling
    if wg-quick strip wg0 > /dev/null 2>&1; then
        if systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
            log "wg-quick@wg0 already enabled"
        else
            systemctl enable wg-quick@wg0 >> "$LOG_FILE" 2>&1
        fi
        
        # Try to start the service now to verify configuration
        log "Starting WireGuard service..."
        if systemctl start wg-quick@wg0 2>> "$LOG_FILE"; then
            log "WireGuard service started successfully"
        else
            warn "WireGuard service could not be started, check configuration."
        fi
    else
        warn "WireGuard configuration could not be validated. Check wg0.conf file."
    fi
else
    warn "$WG_DIR/wg0.conf file not found."
fi

# --- 9. GENERATING INSTALLATION SUMMARY ---
USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
[[ -z "$USER_HOME" || "$USER_HOME" == "/root" ]] && USER_HOME="/root"
NOTES_FILE="$USER_HOME/installation_notes.txt"

cat > "$NOTES_FILE" <<EOF
==================================================
WIREGUARD & SSH INSTALLATION REPORT ($(date))
==================================================

[SSH INFORMATION]
Port: 22
Command: ssh ${CURRENT_USER}@$SERVER_PUBLIC_IP
Root Login: $PERMIT_ROOT

[WIREGUARD INFORMATION]
Port: $WG_PORT
Server IP: $SERVER_PUBLIC_IP
Internal IP Range: 10.8.0.0/24

[CLIENT CONFIGURATION FILE]
--------------------------------------------------
$(cat $WG_DIR/client.conf)
--------------------------------------------------

==================================================
EOF

chown "$SUDO_USER:$SUDO_USER" "$NOTES_FILE" 2>/dev/null || true

echo -e "\n${GREEN}========================================${NC}"
success "Installation completed successfully!"
warn "Notes saved: $NOTES_FILE"
echo -e "\n${BLUE}--- CLIENT QR CODE ---${NC}"
if command -v qrencode &>/dev/null; then
    qrencode -t ansiutf8 < $WG_DIR/client.conf
else
    warn "qrencode not installed, QR code skipped."
fi
echo -e "${BLUE}----------------------${NC}\n"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}CLIENT CONFIGURATION${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat $WG_DIR/client.conf
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}⚠️  Save this output! You'll need it for the client/gateway setup.${NC}"
echo -e "${GREEN}📁 File location:${NC} $WG_DIR/client.conf"
echo ""

# Disable error trap before final output
trap - ERR

# Restart SSH to apply hardening (no port change, safe)
systemctl restart sshd >> "$LOG_FILE" 2>&1 || warn "Could not restart SSH service."
success "SSH hardening applied (no reboot needed)."

read -p "Reboot system now? (y/n) [n]: " REBOOT_FINAL
REBOOT_FINAL=${REBOOT_FINAL:-n}

if [[ "$REBOOT_FINAL" == "y" || "$REBOOT_FINAL" == "Y" ]]; then
    log "Rebooting system..."
    sleep 2
    reboot
else
    success "Setup complete!"
fi
