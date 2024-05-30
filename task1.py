pip install scapy
from scapy.all import sniff, IP, TCP

# Define a callback function to process packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"  TCP {tcp_layer.sport} -> {tcp_layer.dport}")

# Sniff packets (you might need to run this script with sudo)
print("Starting network sniffer...")
sniff(prn=packet_callback, count=10)  # Adjust count to capture more packets

sniff(prn=packet_callback, filter="tcp port 80", count=10)