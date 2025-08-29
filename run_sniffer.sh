#!/bin/bash
# Packet Sniffing Tool Launcher
# Usage: ./run_sniffer.sh [interface] [logfile]

INTERFACE=${1:-eth0}               # Default to eth0 if not specified
LOGFILE=${2:-packets.log}          # Default log file name

echo "[+] Launching Packet Sniffer..."
echo "    Interface: $INTERFACE"
echo "    Log File : $LOGFILE"
echo "----------------------------------------------------"

# Run with sudo (raw sockets require root)
sudo python3 packet_sniffer.py --interface "$INTERFACE" --log "$LOGFILE"
