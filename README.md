# Network Deauth

A bash script for monitoring wireless networks and performing network analysis.

## Description

This tool automates the process of:
1. Selecting a network interface
2. Putting it into monitor mode
3. Scanning for available wireless networks
4. Identifying clients connected to a selected network
5. Performing network analysis functions

## Requirements

- Linux operating system
- Root privileges
- Aircrack-ng suite installed (airmon-ng, airodump-ng, aireplay-ng)

## Installation

1. Save the script to a file named `network_deauth.sh`
2. Make the script executable:
   ```bash
   chmod +x network_deauth.sh
   ```

## Usage

Run the script with root privileges:

```bash
sudo ./network_deauth.sh
```

Follow the interactive prompts to:
1. Select a network interface
2. Scan for networks
3. Select a target network
4. View connected clients
5. Select analysis options

## Important Warning

This tool is intended for **educational purposes** and **authorized security testing only**. 

**Legal Notice**: Using this tool to monitor or analyze networks without explicit permission from the network owner is illegal in most jurisdictions and could result in:
- Civil liability
- Criminal charges
- Fines and/or imprisonment

Always obtain proper authorization before using this tool on any network.

## Features

- Automatic interface switching to monitor mode
- Network discovery and information gathering
- Client detection and analysis
- Interactive command-line interface
- Automatic cleanup of temporary files

## Troubleshooting

If you encounter issues:
- Ensure you have the aircrack-ng suite installed
- Verify your wireless card supports monitor mode
- Check that you're running the script with root privileges
- Make sure no other processes are using the wireless interface

## License

This tool is provided for educational purposes only. Use at your own risk.
