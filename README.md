# Packet Sniffer Tool

## Overview
This project is a simple packet sniffer tool written in Python. It uses the `socket` and `scapy` libraries to capture and analyze network packets on a specified interface. The tool continuously listens for incoming packets and prints a summary of each packet to the console.

## Features
- Capture all packets on a specified network interface.
- Display a summary of each captured packet.
- Handle large amounts of data efficiently.
- Graceful shutdown on user interruption.

## Requirements
- Python 3.x
- `scapy` library

## Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/packet-sniffer-tool.git
   cd packet-sniffer-tool
