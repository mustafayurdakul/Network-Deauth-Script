# Network Deauthentication Tool

A powerful bash script for monitoring wireless networks and performing deauthentication attacks for security testing.

## Description

This tool automates the process of:
1. Selecting a network interface
2. Putting it into monitor mode
3. Scanning for available wireless networks
4. Identifying clients connected to a selected network
5. Performing controlled deauthentication attacks
6. Monitoring network activity

## Features

- Interactive color-coded command-line interface
- Command-line options for non-interactive usage
- Automatic interface switching to monitor mode
- Network discovery with detailed information
- Client detection and analysis
- Continuous or limited packet deauthentication options
- Targeted deauthentication (specific client or broadcast)
- Automatic cleanup of temporary files
- Robust error handling

## Requirements

- Linux operating system
- Root privileges
- Aircrack-ng suite installed (airmon-ng, airodump-ng, aireplay-ng)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/network-deauth-script.git
   cd network-deauth-script
   ```

2. Make the script executable:
   ```bash
   chmod +x network_deauth.sh
   ```

## Usage

### Interactive Mode

Run the script with root privileges:

```bash
sudo ./network_deauth.sh
```

Follow the interactive prompts to:
1. Select a wireless interface
2. Scan for nearby networks
3. Select a target network
4. View connected clients
5. Choose deauthentication options
6. Execute the attack

### Command-line Options

```bash
sudo ./network_deauth.sh -i wlan0  # Specify wireless interface
sudo ./network_deauth.sh --help    # Display help information
```

## Workflow

1. The script first checks for required tools
2. It lists available wireless interfaces
3. Puts selected interface into monitor mode
4. Scans for nearby wireless networks
5. Allows selection of a target network
6. Scans for clients connected to the target
7. Provides options for deauthentication attacks:
   - Target all clients (broadcast)
   - Target specific clients
   - Set packet count or continuous mode
8. Executes the deauthentication attack
9. Provides options to continue with different targets
10. Cleans up resources when finished

## Important Warning

This tool is intended for **educational purposes** and **authorized security testing only**. 

**Legal Notice**: Using this tool to disrupt networks without explicit permission from the network owner is illegal in most jurisdictions and could result in:
- Civil liability
- Criminal charges
- Fines and/or imprisonment

Always obtain proper authorization before using this tool on any network.

## Troubleshooting

If you encounter issues:
- Ensure you have the aircrack-ng suite installed (`apt install aircrack-ng`)
- Verify your wireless card supports monitor mode
- Check that you're running the script with root privileges
- Make sure no other processes are using the wireless interface

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
