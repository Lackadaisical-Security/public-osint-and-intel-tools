#!/usr/bin/env bash
# MAC Address Randomization Tool
# Randomize MAC address for network interfaces (Linux only)
# Requires root privileges

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Usage: sudo $0 [interface]"
   exit 1
fi

# Function to print colored output
print_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to generate random MAC address
generate_random_mac() {
    # First byte must have bit 1 (local) set and bit 0 (unicast) unset
    # So we use x2, x6, xA, xE for first digit
    local first_digit=$(printf '%X' $((RANDOM % 4 * 4 + 2)))
    local first_byte="${first_digit}$(printf '%X' $((RANDOM % 16)))"
    
    # Generate remaining 5 bytes
    local mac="${first_byte}"
    for i in {1..5}; do
        mac="${mac}:$(printf '%02X' $((RANDOM % 256)))"
    done
    
    echo "$mac"
}

# Function to get current MAC address
get_current_mac() {
    local interface=$1
    ip link show "$interface" | awk '/ether/ {print $2}'
}

# Function to get interface state
is_interface_up() {
    local interface=$1
    ip link show "$interface" | grep -q "state UP"
}

# Function to randomize MAC address
randomize_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    
    print_info "Interface: $interface"
    
    # Get current MAC
    local current_mac=$(get_current_mac "$interface")
    print_info "Current MAC: $current_mac"
    
    # Check if interface is up
    local was_up=false
    if is_interface_up "$interface"; then
        was_up=true
        print_info "Bringing interface down..."
        ip link set dev "$interface" down
    fi
    
    # Change MAC address
    print_info "Setting new MAC: $new_mac"
    ip link set dev "$interface" address "$new_mac"
    
    # Bring interface back up if it was up
    if [ "$was_up" = true ]; then
        print_info "Bringing interface up..."
        ip link set dev "$interface" up
    fi
    
    # Verify change
    local actual_mac=$(get_current_mac "$interface")
    if [ "$actual_mac" = "$new_mac" ]; then
        print_info "MAC address successfully randomized"
        return 0
    else
        print_error "MAC address change failed"
        return 1
    fi
}

# Function to restore original MAC address
restore_mac() {
    local interface=$1
    
    print_info "Restoring original MAC address..."
    print_info "Restarting NetworkManager..."
    
    # Bring interface down
    ip link set dev "$interface" down
    
    # Remove custom MAC
    ip link set dev "$interface" address 00:00:00:00:00:00 2>/dev/null || true
    
    # Bring interface up
    ip link set dev "$interface" up
    
    # Restart network manager to restore original
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet NetworkManager; then
            systemctl restart NetworkManager
        elif systemctl is-active --quiet networking; then
            systemctl restart networking
        fi
    fi
    
    print_info "Original MAC should be restored"
}

# Function to list network interfaces
list_interfaces() {
    print_info "Available network interfaces:"
    ip link show | awk -F': ' '/^[0-9]+:/ {print "  " $2}' | grep -v '^lo$'
}

# Function to make MAC change permanent
make_permanent() {
    local interface=$1
    local new_mac=$2
    
    print_warning "Making MAC change permanent..."
    
    # Create NetworkManager config
    local nm_config="/etc/NetworkManager/conf.d/99-random-mac.conf"
    
    cat > "$nm_config" << EOF
[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random

[device-mac-randomization]
wifi.scan-rand-mac-address=yes
EOF
    
    print_info "Created NetworkManager config: $nm_config"
    print_info "MAC address will be randomized on each connection"
    print_info "Restart NetworkManager: systemctl restart NetworkManager"
}

# Main script
main() {
    echo "==================================================="
    echo "  MAC Address Randomization Tool"
    echo "==================================================="
    echo ""
    
    # Parse arguments
    local interface=""
    local action="randomize"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--list)
                list_interfaces
                exit 0
                ;;
            -r|--restore)
                action="restore"
                shift
                ;;
            -p|--permanent)
                action="permanent"
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS] [INTERFACE]"
                echo ""
                echo "Options:"
                echo "  -l, --list       List available network interfaces"
                echo "  -r, --restore    Restore original MAC address"
                echo "  -p, --permanent  Make MAC randomization permanent"
                echo "  -h, --help       Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0 wlan0              # Randomize MAC for wlan0"
                echo "  $0 --restore eth0     # Restore original MAC for eth0"
                echo "  $0 --permanent wlan0  # Make MAC randomization permanent"
                exit 0
                ;;
            *)
                interface=$1
                shift
                ;;
        esac
    done
    
    # If no interface specified, list interfaces
    if [ -z "$interface" ]; then
        list_interfaces
        echo ""
        read -p "Enter interface name: " interface
    fi
    
    # Check if interface exists
    if ! ip link show "$interface" &> /dev/null; then
        print_error "Interface '$interface' not found"
        list_interfaces
        exit 1
    fi
    
    # Perform action
    case $action in
        randomize)
            randomize_mac "$interface"
            ;;
        restore)
            restore_mac "$interface"
            ;;
        permanent)
            new_mac=$(generate_random_mac)
            make_permanent "$interface" "$new_mac"
            ;;
    esac
    
    echo ""
    echo "==================================================="
    echo "  Operation Complete"
    echo "==================================================="
}

# Run main function
main "$@"
