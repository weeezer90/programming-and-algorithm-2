import time
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether, DNS, ARP

# A list to store up to 10 packets captured
captured_packets = []

# Function to handle and display the packet information
def packet_handler(packet):
    try:
        # Process packets with IP, IPv6, or ARP layers
        if packet.haslayer(IP) or packet.haslayer(IPv6) or packet.haslayer(ARP):
            captured_packets.append(packet)  # Store the packet
            
            # Display packet information for the first 10 packets
            if len(captured_packets) <= 10:
                print(f"\nPacket {len(captured_packets)}:")
                if packet.haslayer(IP):
                    print(f"Source: {packet[IP].src} -> Destination: {packet[IP].dst}")
                elif packet.haslayer(IPv6):
                    print(f"Source: {packet[IPv6].src} -> Destination: {packet[IPv6].dst}")
                elif packet.haslayer(ARP):
                    print(f"Source: {packet[ARP].psrc} -> Destination: {packet[ARP].pdst}")
                
                # Determine the protocol
                if packet.haslayer(TCP):
                    print(f"Protocol: TCP")
                    print(f"TCP Info: Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
                elif packet.haslayer(UDP):
                    print(f"Protocol: UDP")
                    print(f"UDP Info: Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")
                elif packet.haslayer(ICMP):
                    print(f"Protocol: ICMP")
                    print(f"ICMP Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")
                elif packet.haslayer(DNS):
                    print(f"Protocol: DNS")
                    print(f"DNS Query: {packet[DNS].qd.qname.decode('utf-8')}")
                elif packet.haslayer(ARP):
                    print(f"Protocol: ARP")
                    print(f"ARP Request: {packet[ARP].psrc} -> {packet[ARP].pdst}")
                else:
                    print(f"Protocol: Unknown")
            
            # Stop sniffing after 10 packets
            if len(captured_packets) >= 10:
                return False  # Stop sniffing
                
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start sniffing and display results
def start_sniffing(interface="Wi-Fi", packet_count=10, timeout=60):
    print(f"\nStarting packet capture on interface {interface}...")  # Begin sniffing
    sniff(prn=packet_handler, store=0, count=packet_count, timeout=timeout, iface=interface)

    print("\nSniffing complete. Captured 10 packets. 🎉")

if __name__ == "__main__":
    # Start sniffing for 10 packets (change interface name as needed)
    start_sniffing(interface="Wi-Fi", packet_count=10, timeout=60)
    print("\nScript ran successfully! 🚀✨")