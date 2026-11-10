#!/bin/bash

# =============================================================================
# WireGuard Gateway & SSH Security Hardening Suite
# Support: Debian 11/12/13, Ubuntu 20.04/22.04/24.04+, Raspbian, DietPi, Armbian
# Purpose: Seamless installation on minimal systems, NAT protection and high security.
# =============================================================================

# PATH correction (for minimal systems)
export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export DEBIAN_FRONTEND=noninteractive

# --- COLORS AND LOGGING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'
LOG_FILE="/var/log/wg_setup.log"
WG_DIR="/etc/wireguard"
WG_CLIENTS_DIR="$WG_DIR/clients"

log() { echo -e "${BLUE}[$(date +%T)]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }

# Helper: read from /dev/tty if stdin is not a terminal (e.g. curl | bash)
ask() {
    local prompt="$1" var="$2" default="$3" _input
    if [[ -n "${!var}" ]]; then
        return
    fi
    if [[ -t 0 ]]; then
        read -r -p "$prompt" _input
    elif [[ -e /dev/tty ]] && read -r -p "$prompt" _input < /dev/tty 2>/dev/null; then
        :
    else
        _input="$default"
    fi
    [[ -z "$_input" ]] && _input="$default"
    eval "$var=\"\$_input\""
}

# --- 1. PREREQUISITE AND PERMISSION CHECKS ---
check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run with root privileges! (e.g. sudo bash $0)"
    fi

    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect operating system: /etc/os-release not found."
    fi

    # Source OS information
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-$OS_ID}"

    case "$OS_ID" in
        ubuntu|debian|raspbian|dietpi|armbian|pop|linuxmint)
            log "Detected supported OS: $OS_NAME"
            ;;
        *)
            warn "Your operating system ($OS_NAME) is not officially tested."
            ask "Do you want to continue anyway? (y/n) [n]: " FORCE_RUN "n"
            if [[ "$FORCE_RUN" != "y" && "$FORCE_RUN" != "Y" ]]; then
                error "Installation cancelled."
            fi
            ;;
    esac
}

# --- HELPER: GET REAL USER & HOME DIRECTORY ---
get_user_info() {
    CURRENT_USER="${SUDO_USER:-$USER}"
    if [[ -z "$CURRENT_USER" || "$CURRENT_USER" == "root" ]]; then
        CURRENT_USER="root"
        USER_HOME="/root"
        IS_ROOT_USER=true
    else
        USER_HOME=$(getent passwd "$CURRENT_USER" | cut -d: -f6)
        [[ -z "$USER_HOME" ]] && USER_HOME="/home/$CURRENT_USER"
        IS_ROOT_USER=false
    fi
}

# --- HELPER: DETECT NETWORK INTERFACE AND EXTERNAL IP ---
detect_network() {
    log "Detecting primary network interface..."
    NET_INTERFACE=$(ip -4 route ls | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$NET_INTERFACE" ]]; then
        NET_INTERFACE=$(ip link show | grep -v "lo:" | grep -o "^[0-9]*: [^:]*" | head -n1 | cut -d: -f2 | tr -d ' ')
    fi

    if [[ -z "$NET_INTERFACE" ]]; then
        error "Could not detect default network interface. Please check network configuration."
    fi
    log "Network interface: $NET_INTERFACE"

    log "Detecting server public IP..."
    SERVER_PUBLIC_IP=""
    for service in "https://api.ipify.org" "https://checkip.amazonaws.com" "https://icanhazip.com" "https://ifconfig.me"; do
        TEMP_IP=$(curl -s -4 --connect-timeout 5 "$service" 2>/dev/null | tr -d '\r\n ' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$')
        if [[ -n "$TEMP_IP" ]]; then
            SERVER_PUBLIC_IP="$TEMP_IP"
            break
        fi
    done

    if [[ -z "$SERVER_PUBLIC_IP" ]]; then
        warn "Could not automatically determine public IPv4."
        ask "Please enter your server's public IP address or domain: " SERVER_PUBLIC_IP ""
        if [[ -z "$SERVER_PUBLIC_IP" ]]; then
            error "Public IP or domain is required for WireGuard clients to connect."
        fi
    fi
    log "Server Public Endpoint: $SERVER_PUBLIC_IP"
}

# --- HELPER: DETECT ACTIVE SSH PORT ---
detect_ssh_port() {
    local detected_port
    detected_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' | head -n1)
    if [[ -z "$detected_port" && -f /etc/ssh/sshd_config ]]; then
        detected_port=$(grep -i '^Port ' /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    fi
    SSH_PORT=${detected_port:-22}
    log "Detected SSH port: $SSH_PORT"
}

# --- 2. PACKAGE INSTALLATION ---
install_packages() {
    log "Updating package repositories..."
    local retry=0
    local max_retries=3
    while [[ $retry -lt $max_retries ]]; do
        if apt-get update -y >> "$LOG_FILE" 2>&1; then
            break
        fi
        retry=$((retry + 1))
        warn "apt-get update failed, retrying ($retry/$max_retries)..."
        sleep 3
    done

    # Notice: We intentionally do NOT install resolvconf/openresolv on the server.
    # On modern Ubuntu (22.04/24.04), installing resolvconf breaks systemd-resolved (127.0.0.53).
    # WireGuard server does not need resolvconf; only clients parsing 'DNS =' directives do.
    local required_pkgs="wireguard wireguard-tools iptables iproute2 procps curl wget ufw fail2ban python3-systemd qrencode unattended-upgrades"

    log "Installing required packages: $required_pkgs"
    apt-get install -y --no-install-recommends $required_pkgs >> "$LOG_FILE" 2>&1 || {
        warn "Standard install had issues, attempting --fix-broken..."
        apt-get install -f -y >> "$LOG_FILE" 2>&1 || true
        apt-get install -y --no-install-recommends $required_pkgs >> "$LOG_FILE" 2>&1 || error "Failed to install required packages."
    }

    if ! command -v wg &>/dev/null; then
        error "WireGuard (wg) command not found after installation. Aborting."
    fi
    success "Required packages successfully installed."
}

# --- 3. SSH HARDENING ---
configure_ssh() {
    log "Configuring SSH security hardening..."
    detect_ssh_port
    mkdir -p /etc/ssh/sshd_config.d/

    local permit_root="yes"
    if [[ "$IS_ROOT_USER" == "true" ]]; then
        warn "Logged in directly as root without a secondary sudo user."
        warn "Root login will remain ENABLED to prevent total lockout."
        permit_root="yes"
    else
        ask "Disable SSH Root Login? (Recommended: you are logged in as '$CURRENT_USER') (y/n) [y]: " DISABLE_ROOT "y"
        if [[ "$DISABLE_ROOT" == "y" || "$DISABLE_ROOT" == "Y" ]]; then
            permit_root="no"
            log "Root login will be disabled."
        else
            permit_root="yes"
            warn "Root login will remain enabled."
        fi
    fi

    # Determine existing PasswordAuthentication preference if present
    local pass_auth="yes"
    if sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'; then
        pass_auth="no"
        log "Preserving existing SSH setting: PasswordAuthentication no (key-only)"
    fi

    # Backup existing custom config if present
    [[ -f /etc/ssh/sshd_config.d/99-custom.conf ]] && cp /etc/ssh/sshd_config.d/99-custom.conf /etc/ssh/sshd_config.d/99-custom.conf.bak 2>/dev/null || true

    # Ensure main sshd_config includes sshd_config.d/*.conf
    if [[ -f /etc/ssh/sshd_config ]] && ! grep -qiE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config; then
        echo -e "\nInclude /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi

    cat > /etc/ssh/sshd_config.d/99-custom.conf <<EOF
# WireGuard Gateway SSH Hardening
Port $SSH_PORT
PermitRootLogin $permit_root
PasswordAuthentication $pass_auth
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    # Test configuration before restarting service
    if ! sshd -t; then
        warn "SSHD syntax test failed! Reverting SSH custom config..."
        rm -f /etc/ssh/sshd_config.d/99-custom.conf
        [[ -f /etc/ssh/sshd_config.d/99-custom.conf.bak ]] && mv /etc/ssh/sshd_config.d/99-custom.conf.bak /etc/ssh/sshd_config.d/99-custom.conf
    else
        # Compatible with Ubuntu 24.04 (ssh.socket) and older distros (ssh.service / sshd.service)
        if systemctl is-active --quiet ssh.socket; then
            systemctl reload ssh.socket >> "$LOG_FILE" 2>&1 || true
        elif systemctl list-units --type=service | grep -q "ssh.service"; then
            systemctl reload-or-restart ssh >> "$LOG_FILE" 2>&1 || true
        elif systemctl list-units --type=service | grep -q "sshd.service"; then
            systemctl reload-or-restart sshd >> "$LOG_FILE" 2>&1 || true
        fi
        success "SSH hardening applied safely on port $SSH_PORT."
    fi
}

# --- 4. FAIL2BAN CONFIGURATION ---
configure_fail2ban() {
    log "Configuring Fail2ban with systemd journal backend..."
    mkdir -p /etc/fail2ban/jail.d/

    # Uses systemd backend which is fully compatible with Debian 12 (no rsyslog) and Ubuntu 24.04
    cat > /etc/fail2ban/jail.d/ssh-hardening.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || true
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || warn "Could not restart fail2ban service."
    success "Fail2ban enabled and monitoring SSH (port $SSH_PORT)."
}

# --- 5. SYSTEM KERNEL & FIREWALL CONFIGURATION ---
configure_firewall() {
    log "Enabling IP forwarding in kernel..."
    cat > /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl --system >> "$LOG_FILE" 2>&1 || sysctl -p /etc/sysctl.d/99-wireguard.conf >> "$LOG_FILE" 2>&1 || true

    log "Configuring UFW (Uncomplicated Firewall)..."
    ask "Reset existing UFW firewall rules? (y/n) [n]: " RESET_UFW "n"
    if [[ "$RESET_UFW" == "y" || "$RESET_UFW" == "Y" ]]; then
        warn "Resetting UFW rules..."
        ufw --force reset >> "$LOG_FILE" 2>&1 || true
    fi

    # Set default policies
    ufw default deny incoming >> "$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >> "$LOG_FILE" 2>&1 || true

    # Allow SSH and WireGuard port
    ufw allow "$SSH_PORT/tcp" comment "SSH Port" >> "$LOG_FILE" 2>&1 || true
    ufw allow "$WG_PORT/udp" comment "WireGuard VPN" >> "$LOG_FILE" 2>&1 || true

    # Allow routed forwarding specifically for WireGuard without opening global forwarding
    ufw route allow in on wg0 out on "$NET_INTERFACE" >> "$LOG_FILE" 2>&1 || true
    ufw route allow in on "$NET_INTERFACE" out on wg0 >> "$LOG_FILE" 2>&1 || true

    # Enable UFW
    ufw --force enable >> "$LOG_FILE" 2>&1 || true
    success "Firewall (UFW) configured: SSH ($SSH_PORT/tcp) and WireGuard ($WG_PORT/udp) opened."
}

# --- 6. INITIAL SERVER INSTALLATION ---
install_wireguard_server() {
    echo -e "${YELLOW}Please configure installation settings (Press Enter for defaults):${NC}\n"

    ask "WireGuard Port [41194]: " INPUT_WG "41194"
    WG_PORT="${INPUT_WG:-41194}"

    # DNS Selection
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Client DNS Configuration${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  1) Cloudflare  (1.1.1.1, 1.0.0.1)"
    echo -e "  2) Google      (8.8.8.8, 8.8.4.4)"
    echo -e "  3) AdGuard     (94.140.14.14, 94.140.15.15)"
    echo -e "  4) Custom"
    ask "Select DNS provider [1]: " DNS_CHOICE "1"

    case "$DNS_CHOICE" in
        1) CLIENT_DNS="1.1.1.1, 1.0.0.1" ;;
        2) CLIENT_DNS="8.8.8.8, 8.8.4.4" ;;
        3) CLIENT_DNS="94.140.14.14, 94.140.15.15" ;;
        4)
            ask "Primary DNS: " CUSTOM_DNS1 ""
            ask "Secondary DNS: " CUSTOM_DNS2 ""
            if [[ -z "$CUSTOM_DNS1" ]]; then
                CLIENT_DNS="1.1.1.1, 1.0.0.1"
            elif [[ -z "$CUSTOM_DNS2" ]]; then
                CLIENT_DNS="$CUSTOM_DNS1"
            else
                CLIENT_DNS="$CUSTOM_DNS1, $CUSTOM_DNS2"
            fi
            ;;
        *) CLIENT_DNS="1.1.1.1, 1.0.0.1" ;;
    esac
    log "Client DNS set to: $CLIENT_DNS"

    ask "Enable automatic security updates? (y/n) [y]: " AUTO_UP "y"

    # Install packages
    install_packages

    # Detect network and ports
    detect_network
    detect_ssh_port

    # Security steps
    configure_ssh
    configure_fail2ban
    configure_firewall

    # Automated security updates
    if [[ "$AUTO_UP" == "y" || "$AUTO_UP" == "Y" ]]; then
        if command -v unattended-upgrade >/dev/null 2>&1; then
            echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections 2>/dev/null || true
            dpkg-reconfigure -f noninteractive unattended-upgrades >> "$LOG_FILE" 2>&1 || true
            success "Automatic security updates configured."
        fi
    fi

    # Generate Server Keys
    mkdir -p "$WG_DIR" "$WG_CLIENTS_DIR"
    chmod 700 "$WG_DIR"
    local server_priv; server_priv=$(wg genkey)
    local server_pub; server_pub=$(echo "$server_priv" | wg pubkey)

    # Save server details
    echo "$server_priv" > "$WG_DIR/server_private.key"
    echo "$server_pub" > "$WG_DIR/server_public.key"
    chmod 600 "$WG_DIR"/server_*.key

    # Save meta parameters for peer generation
    cat > "$WG_DIR/params" <<EOF
SERVER_PUB_IP="$SERVER_PUBLIC_IP"
SERVER_PUB_KEY="$server_pub"
SERVER_PORT="$WG_PORT"
SERVER_NIC="$NET_INTERFACE"
CLIENT_DNS="$CLIENT_DNS"
EOF
    chmod 600 "$WG_DIR/params"

    # Write Server Configuration
    # Uses clean in-interface iptables PostUp/PostDown to manage NAT forwarding
    cat > "$WG_DIR/wg0.conf" <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = $WG_PORT
PrivateKey = $server_priv
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NET_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NET_INTERFACE -j MASQUERADE

EOF
    chmod 600 "$WG_DIR/wg0.conf"

    # Enable and start WireGuard service
    systemctl enable wg-quick@wg0 >> "$LOG_FILE" 2>&1 || true
    systemctl restart wg-quick@wg0 >> "$LOG_FILE" 2>&1 || error "Failed to start WireGuard service."
    success "WireGuard server service active on UDP port $WG_PORT."

    # Add initial client
    echo ""
    log "Generating your first VPN client profile..."
    add_client "client1"

    # Installation summary
    generate_summary
}

# --- 7. CLIENT MANAGEMENT FUNCTIONS ---
add_client() {
    local client_name="$1"
    if [[ -z "$client_name" ]]; then
        ask "Enter client name (letters/numbers only): " client_name "client2"
    fi
    client_name=$(echo "$client_name" | tr -dc 'a-zA-Z0-9_-')
    [[ -z "$client_name" ]] && client_name="client_$(date +%s)"

    if [[ -f "$WG_CLIENTS_DIR/$client_name.conf" ]]; then
        warn "A client with name '$client_name' already exists!"
        return 1
    fi

    # Read server parameters
    if [[ -f "$WG_DIR/params" ]]; then
        . "$WG_DIR/params"
    else
        error "Server params file not found ($WG_DIR/params)."
    fi

    # Find the next available IP address in 10.8.0.x
    local next_ip=2
    while grep -q "10\.8\.0\.$next_ip/" "$WG_DIR/wg0.conf" 2>/dev/null; do
        next_ip=$((next_ip + 1))
        if [[ $next_ip -gt 254 ]]; then
            error "No more available IPs in the 10.8.0.0/24 subnet!"
        fi
    done
    local client_ip="10.8.0.$next_ip"

    # Generate client keys
    local client_priv; client_priv=$(wg genkey)
    local client_pub; client_pub=$(echo "$client_priv" | wg pubkey)

    # Append peer to server config
    cat >> "$WG_DIR/wg0.conf" <<EOF
# Peer: $client_name
[Peer]
PublicKey = $client_pub
AllowedIPs = $client_ip/32

EOF

    # Apply live to wireguard interface without restarting
    wg set wg0 peer "$client_pub" allowed-ips "$client_ip/32" 2>/dev/null || true

    # Generate client configuration file
    mkdir -p "$WG_CLIENTS_DIR"
    local client_file="$WG_CLIENTS_DIR/$client_name.conf"
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_priv
Address = $client_ip/24
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $SERVER_PUB_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 "$client_file"

    # Copy to user's home directory for easy retrieval
    cp "$client_file" "$USER_HOME/$client_name.conf" 2>/dev/null || true
    chown "$CURRENT_USER:$CURRENT_USER" "$USER_HOME/$client_name.conf" 2>/dev/null || true

    success "Client '$client_name' created successfully (IP: $client_ip)."
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}QR CODE FOR MOBILE (${client_name})${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 < "$client_file"
    else
        warn "qrencode not installed, QR code display skipped."
    fi
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Configuration file saved at:${NC} $client_file"
    echo -e "${GREEN}User copy saved at:${NC} $USER_HOME/$client_name.conf"
    echo ""
}

list_clients() {
    echo -e "\n${CYAN}════════════════════════════════════════${NC}"
    echo -e "${BOLD}          CONFIGURED CLIENTS            ${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    if [[ ! -d "$WG_CLIENTS_DIR" ]] || [[ -z "$(ls -A "$WG_CLIENTS_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}No client profiles found in $WG_CLIENTS_DIR.${NC}"
        return
    fi

    printf "%-20s %-15s %-25s\n" "CLIENT NAME" "IP ADDRESS" "CONFIG PATH"
    echo "------------------------------------------------------------"
    for f in "$WG_CLIENTS_DIR"/*.conf; do
        [[ -e "$f" ]] || continue
        local cname; cname=$(basename "$f" .conf)
        local cip; cip=$(grep -m1 '^Address' "$f" | awk '{print $3}')
        printf "%-20s %-15s %-25s\n" "$cname" "$cip" "$f"
    done
    echo ""
}

revoke_client() {
    local client_to_remove="$1"
    if [[ -z "$client_to_remove" ]]; then
        list_clients
        ask "Enter the name of the client to revoke: " client_to_remove ""
    fi
    if [[ -z "$client_to_remove" || ! -f "$WG_CLIENTS_DIR/$client_to_remove.conf" ]]; then
        warn "Client '$client_to_remove' not found."
        return 1
    fi

    # Read client's public key from private key
    local c_priv; c_priv=$(grep -m1 '^PrivateKey' "$WG_CLIENTS_DIR/$client_to_remove.conf" | awk '{print $3}')
    local c_pub; c_pub=$(echo "$c_priv" | wg pubkey 2>/dev/null)

    # Remove peer dynamically from WireGuard
    if [[ -n "$c_pub" ]]; then
        wg set wg0 peer "$c_pub" remove 2>/dev/null || true
    fi

    # Remove from wg0.conf
    # Removes the comment line and the [Peer] block
    sed -i "/# Peer: $client_to_remove/,+4d" "$WG_DIR/wg0.conf" 2>/dev/null || true

    # Remove config file
    rm -f "$WG_CLIENTS_DIR/$client_to_remove.conf"
    rm -f "$USER_HOME/$client_to_remove.conf"

    success "Client '$client_to_remove' has been completely revoked."
}

# --- 8. SUMMARY REPORT ---
generate_summary() {
    local notes_file="$USER_HOME/installation_notes.txt"
    cat > "$notes_file" <<EOF
==================================================
WIREGUARD & SSH INSTALLATION REPORT ($(date))
==================================================

[SSH HARDENING]
Port: $SSH_PORT
Command: ssh ${CURRENT_USER}@$SERVER_PUBLIC_IP -p $SSH_PORT
Root Login: $permit_root

[WIREGUARD GATEWAY]
Port: $WG_PORT (UDP)
Server Public IP: $SERVER_PUBLIC_IP
Subnet: 10.8.0.0/24
Clients Directory: $WG_CLIENTS_DIR

[CLIENT PROFILES]
Initial client configuration saved to:
- $WG_CLIENTS_DIR/client1.conf
- $USER_HOME/client1.conf

[MANAGEMENT]
To add, list or revoke clients at any time, run:
  sudo bash install.sh
==================================================
EOF
    chown "$CURRENT_USER:$CURRENT_USER" "$notes_file" 2>/dev/null || true
    success "Installation report saved to: $notes_file"
}

# --- 9. INTERACTIVE MENU (WHEN ALREADY INSTALLED) ---
manage_menu() {
    echo -e "${CYAN}====================================================${NC}"
    echo -e "   ${BOLD}WIREGUARD GATEWAY MANAGEMENT PANEL${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e "WireGuard is already installed and running on this server."
    echo ""
    echo -e "  1) ${GREEN}Add a new client profile (QR Code)${NC}"
    echo -e "  2) ${BLUE}List existing clients${NC}"
    echo -e "  3) ${YELLOW}Show QR Code / config for an existing client${NC}"
    echo -e "  4) ${RED}Revoke / delete a client${NC}"
    echo -e "  5) Check WireGuard status & traffic (wg show)${NC}"
    echo -e "  6) Reinstall / Reconfigure from scratch${NC}"
    echo -e "  7) Exit"
    echo ""
    ask "Select an option [1-7]: " MENU_CHOICE "1"

    case "$MENU_CHOICE" in
        1)
            add_client ""
            ;;
        2)
            list_clients
            ;;
        3)
            list_clients
            ask "Enter client name to display: " SHOW_NAME ""
            if [[ -f "$WG_CLIENTS_DIR/$SHOW_NAME.conf" ]]; then
                echo -e "\n${BLUE}--- QR CODE ($SHOW_NAME) ---${NC}"
                qrencode -t ansiutf8 < "$WG_CLIENTS_DIR/$SHOW_NAME.conf"
                echo -e "\n${GREEN}--- CONFIG FILE ($SHOW_NAME) ---${NC}"
                cat "$WG_CLIENTS_DIR/$SHOW_NAME.conf"
            else
                warn "Client '$SHOW_NAME' not found."
            fi
            ;;
        4)
            revoke_client
            ;;
        5)
            echo -e "\n${CYAN}--- WIREguard LIVE STATUS ---${NC}"
            wg show
            echo ""
            ;;
        6)
            warn "Reinstalling will overwrite existing configurations!"
            ask "Are you sure you want to proceed? (y/n) [n]: " CONFIRM_REINSTALL "n"
            if [[ "$CONFIRM_REINSTALL" == "y" || "$CONFIRM_REINSTALL" == "Y" ]]; then
                systemctl stop wg-quick@wg0 2>/dev/null || true
                install_wireguard_server
            else
                log "Reinstall cancelled."
            fi
            ;;
        7)
            exit 0
            ;;
        *)
            warn "Invalid choice."
            ;;
    esac
}

# --- MAIN EXECUTION ---
echo -e "${CYAN}====================================================${NC}"
echo -e "   ${BOLD}WIREGUARD GATEWAY & SSH SECURITY HARDENING${NC}"
echo -e "${CYAN}====================================================${NC}"

check_prerequisites
get_user_info

# Non-interactive CLI flag support
if [[ "$1" == "--add-client" ]]; then
    add_client "$2"
    exit 0
elif [[ "$1" == "--revoke-client" ]]; then
    revoke_client "$2"
    exit 0
elif [[ "$1" == "--list" ]]; then
    list_clients
    exit 0
elif [[ "$1" == "--status" ]]; then
    wg show
    exit 0
fi

# Check if already installed
if [[ -f "$WG_DIR/wg0.conf" ]] && systemctl is-active --quiet wg-quick@wg0; then
    manage_menu
else
    install_wireguard_server
fi
