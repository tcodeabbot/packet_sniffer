#!/usr/bin/env python3
"""
Packet Sniffing Tool
Author: Abbot

Description:
A Python-based packet sniffer that captures live packets on the network interface,
decodes Ethernet/IP/TCP/UDP/ICMP headers, and generates terminal-based reports.
Also supports logging captured traffic to a file for further analysis.
"""

import socket
import struct
import textwrap
import datetime

# Utility function to format MAC addresses
def format_mac(addr_bytes):
    return ':'.join(map('{:02x}'.format, addr_bytes))

# Format multi-line text for payload display
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

class PacketSniffer:
    def __init__(self, interface=None, log_file="packets.log"):
        self.interface = interface
        self.log_file = log_file

    def start(self):
        # AF_PACKET is Linux specific; for cross-platform use scapy
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        print(f"[+] Packet Sniffer started on interface: {self.interface or 'default'}")
        print(f"[+] Logging to {self.log_file}")
        print("=" * 80)

        with open(self.log_file, "a") as logfile:
            while True:
                raw_data, addr = conn.recvfrom(65536)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(raw_data)
                eth_report = f"\n{timestamp} Ethernet Frame:\n" \
                             f"  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}"

                print(eth_report)
                logfile.write(eth_report + "\n")

                # IPv4 packets
                if eth_proto == 8:
                    (version, header_length, ttl, proto, src, target, data) = self.parse_ipv4_packet(data)
                    ipv4_report = f"  IPv4 Packet:\n" \
                                  f"    Version: {version}, Header Length: {header_length}, TTL: {ttl}\n" \
                                  f"    Protocol: {proto}, Source: {src}, Target: {target}"
                    print(ipv4_report)
                    logfile.write(ipv4_report + "\n")

                    # ICMP
                    if proto == 1:
                        icmp_type, code, checksum, data = self.parse_icmp_packet(data)
                        icmp_report = f"    ICMP Packet:\n" \
                                      f"      Type: {icmp_type}, Code: {code}, Checksum: {checksum}"
                        print(icmp_report)
                        logfile.write(icmp_report + "\n")

                    # TCP
                    elif proto == 6:
                        (src_port, dest_port, sequence, acknowledgment, flags, data) = self.parse_tcp_segment(data)
                        tcp_report = f"    TCP Segment:\n" \
                                     f"      Source Port: {src_port}, Dest Port: {dest_port}\n" \
                                     f"      Sequence: {sequence}, Acknowledgment: {acknowledgment}\n" \
                                     f"      Flags: {flags}"
                        print(tcp_report)
                        logfile.write(tcp_report + "\n")

                    # UDP
                    elif proto == 17:
                        src_port, dest_port, size, data = self.parse_udp_segment(data)
                        udp_report = f"    UDP Segment:\n" \
                                     f"      Source Port: {src_port}, Dest Port: {dest_port}, Length: {size}"
                        print(udp_report)
                        logfile.write(udp_report + "\n")

    # Ethernet
    def parse_ethernet_frame(self, data):
        dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
        return format_mac(dest), format_mac(src), socket.htons(proto), data[14:]

    # IPv4
    def parse_ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.format_ipv4(src), self.format_ipv4(target), data[header_length:]

    def format_ipv4(self, addr):
        return '.'.join(map(str, addr))

    # ICMP
    def parse_icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    # TCP
    def parse_tcp_segment(self, data):
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = {
            'URG': (offset_reserved_flags & 32) >> 5,
            'ACK': (offset_reserved_flags & 16) >> 4,
            'PSH': (offset_reserved_flags & 8) >> 3,
            'RST': (offset_reserved_flags & 4) >> 2,
            'SYN': (offset_reserved_flags & 2) >> 1,
            'FIN': offset_reserved_flags & 1
        }
        return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

    # UDP
    def parse_udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]


if __name__ == "__main__":
    sniffer = PacketSniffer()
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffer...")
