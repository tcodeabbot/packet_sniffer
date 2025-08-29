

# 🕵️ Packet Sniffing Tool

A **Python + Shell-based Packet Sniffer** for capturing and analyzing live network traffic.
This tool decodes **Ethernet, IPv4, ICMP, TCP, and UDP packets**, generates **terminal-based reports**, and logs results for further analysis.

---

## 🚀 Features

* Capture raw packets using Python’s **socket programming**.
* Decode headers for:

  * **Ethernet** (source/destination MAC)
  * **IPv4** (source/destination IP, TTL, protocol)
  * **TCP** (ports, sequence, ACK, flags)
  * **UDP** (ports, length)
  * **ICMP** (type, code, checksum)
* **Terminal-based report** for real-time monitoring.
* **Log file output** for offline analysis.
* Shell wrapper script (`run_sniffer.sh`) for easy execution.
* CLI arguments for **interface** and **log file selection**.

---

## 📂 Project Structure

```
packet-sniffer/
│
├── packet_sniffer.py      # Main Python sniffer script
├── run_sniffer.sh         # Shell wrapper for easy execution
├── packets.log            # Example log file (created at runtime)
└── README.md              # Project documentation
```

---

## ⚙️ Installation

### Requirements

* **Linux** (uses `AF_PACKET` sockets, not supported natively on Windows/Mac).
* **Python 3.7+**
* Root privileges (`sudo`) for raw socket access.

### Clone the repository

```bash
git clone https://github.com/your-username/packet-sniffer.git
cd packet-sniffer
```

---

## ▶️ Usage

### Run directly with Python

```bash
sudo python3 packet_sniffer.py --interface eth0 --log packets.log
```

### Run with Shell wrapper

```bash
chmod +x run_sniffer.sh
./run_sniffer.sh [interface] [logfile]
```

**Examples:**

```bash
./run_sniffer.sh                # Defaults: eth0, packets.log
./run_sniffer.sh wlan0 traffic.log
```

---

## 📊 Sample Output

**Terminal Report:**

```
[+] Packet Sniffer started on interface: eth0
[+] Logging to packets.log
================================================================================

2025-08-28 22:10:15 Ethernet Frame:
  Destination: 01:23:45:67:89:ab, Source: de:ad:be:ef:ca:fe, Protocol: 8
  IPv4 Packet:
    Version: 4, Header Length: 20, TTL: 64
    Protocol: 6, Source: 192.168.1.10, Target: 172.217.9.78
    TCP Segment:
      Source Port: 54321, Dest Port: 443
      Sequence: 123456789, Acknowledgment: 987654321
      Flags: {'URG': 0, 'ACK': 1, 'PSH': 1, 'RST': 0, 'SYN': 0, 'FIN': 0}
```

**Log File (`packets.log`):**
Contains the same structured output saved during execution.

---

## 🔒 Security Disclaimer

This tool is for **educational and research purposes only**.

* Running a packet sniffer on networks you don’t own or have permission to monitor may violate laws or policies.
* Use responsibly in controlled environments, such as test labs or personal networks.

---

## 📈 Future Improvements

* Cross-platform support using **Scapy** (Windows/macOS).
* Support for **DNS, HTTP, TLS parsing**.
* Add a **summary report generator** (e.g., count TCP/UDP/ICMP packets).
* Optional **GUI dashboard** with live packet visualization.

---

## 🛠️ Technologies Used

* **Python 3**
* **Shell scripting**
* **Socket programming**
* **Struct module** for packet parsing

---

## 📜 License

MIT License © 2025 \tcodeabbot

---
