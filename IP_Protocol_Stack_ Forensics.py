Packet Capture and Analysis Script

from scapy.all import *

def analyze_packet(packet):
    print("\n--- Packet Captured ---")
    # Ethernet Layer (Network Access Layer)
    if packet.haslayer(Ether):
        print(f"Source MAC: {packet[Ether].src}")
        print(f"Destination MAC: {packet[Ether].dst}")

    # IP Layer (Internet Layer)
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    # TCP Layer (Transport Layer)
    if packet.haslayer(TCP):
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")

    # UDP Layer (Transport Layer)
    elif packet.haslayer(UDP):
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    # Application Layer
    if packet.haslayer(Raw):
        print(f"Payload: {packet[Raw].load}")

# Sniff packets
print("Sniffing packets... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)

TCP Traffic Monitoring Script

import socket

# Sniff TCP packets
def sniff_tcp_packets():
    # Create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print("Listening for TCP packets... Press Ctrl+C to stop.")

    while True:
        packet, addr = sock.recvfrom(65565)
        print(f"Packet received from {addr}")
        print(f"Packet Data: {packet[:64]}")
        print("---")

# Run the sniffer
sniff_tcp_packets()
