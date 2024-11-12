from scapy.all import *
import pyfiglet
from colorama import init, Fore

# Intitalize colorama
init(autoreset=True)

# Function to display the welcome message with ASCII art
def display_welcome_message():
     # ASCII welcome message using pyfiglet
     welcome_text = pyfiglet.figlet_format("Network Analyzer", font="slant")
     # Print the welcome message in cyan color
     print(Fore.CYAN + welcome_text)
     
# Funnction to analyze and print packet details
def packet_analyzer(packet):
    # Check if the Packet has ann IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.proto
        print(f"IP Source: {ip_src} | IP Destination: {ip_dst} | Protocol: {protocol} ")

        # Check if the packet has a TCP or UDP layer and print port information
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP Source Port: {sport} | TCP Destination Port: {dport}")
        elif packet.haslayer(UDP):
                  sport = packet[UDP].sport
                  dport = packet[UDP].dport
                  print(f"UDP Source Port: {sport}  | UDP Destination Port: {dport}")
        

        print("-" * 50)

    
# Main Function to start the packet sniffer
def start_sniffer():
    print("Starting Network Traffic Analyzer...")
    # Start sniffing Packets on the default interface
    sniff(prn=packet_analyzer, store=0)

if __name__ == "__main__":
    start_sniffer()

