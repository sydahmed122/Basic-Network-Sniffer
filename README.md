# Basic-Network-Sniffer
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src  # Source IP
        ip_dst = packet[IP].dst  # Destination IP
        protocol = packet[IP].proto  # Protocol number

        # Display packet details
        print(f"[IP Packet] Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")

    # Check if the packet is TCP
    if TCP in packet:
        print(f"   [TCP] Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

    # Check if the packet is UDP
    if UDP in packet:
        print(f"   [UDP] Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")


# Start sniffing (set iface to your network interface, or leave empty for default)
print("Starting packet sniffing...")
sniff(prn=packet_callback, store=False, count=10)

#output
![Image](https://github.com/user-attachments/assets/2ae0d342-c3bd-42f7-b14a-7925cc744096)
