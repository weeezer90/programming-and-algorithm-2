import time
import threading
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Ether, DNS, ARP

# GUI Application Class
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer GUI")
        self.root.geometry("600x400")
        
        # Textbox for displaying captured packets
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
        self.text_area.pack(pady=10)
        
        # Start and Stop buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)
        
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)
        
        self.sniffing = False
        self.sniff_thread = None
        self.interface = "Wi-Fi"  # Change based on your system
        self.packet_limit = 10
        
    def packet_handler(self, packet):
        if self.sniffing:
            try:
                packet_info = ""
                if packet.haslayer(IP):
                    packet_info += f"Source: {packet[IP].src} -> Destination: {packet[IP].dst}\n"
                elif packet.haslayer(IPv6):
                    packet_info += f"Source: {packet[IPv6].src} -> Destination: {packet[IPv6].dst}\n"
                elif packet.haslayer(ARP):
                    packet_info += f"Source: {packet[ARP].psrc} -> Destination: {packet[ARP].pdst}\n"
                
                if packet.haslayer(TCP):
                    packet_info += f"Protocol: TCP | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}\n"
                elif packet.haslayer(UDP):
                    packet_info += f"Protocol: UDP | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}\n"
                elif packet.haslayer(ICMP):
                    packet_info += f"Protocol: ICMP | Type: {packet[ICMP].type}, Code: {packet[ICMP].code}\n"
                elif packet.haslayer(DNS) and packet.haslayer(IP):
                    packet_info += f"Protocol: DNS | Query: {packet[DNS].qd.qname.decode('utf-8')}\n"
                elif packet.haslayer(ARP):
                    packet_info += f"Protocol: ARP | Request: {packet[ARP].psrc} -> {packet[ARP].pdst}\n"
                else:
                    packet_info += "Protocol: Unknown\n"
                
                # Append packet info to text area
                self.text_area.insert(tk.END, packet_info + "\n")
                self.text_area.see(tk.END)
            except Exception as e:
                self.text_area.insert(tk.END, f"Error processing packet: {e}\n")
                self.text_area.see(tk.END)
    
    def sniff_packets(self):
        sniff(prn=self.packet_handler, store=0, count=self.packet_limit, iface=self.interface)
    
    def start_sniffing(self):
        self.sniffing = True
        self.text_area.insert(tk.END, "Starting packet capture...\n")
        self.text_area.see(tk.END)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "Sniffing stopped.\n")
        self.text_area.see(tk.END)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
# Run the GUI Application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()