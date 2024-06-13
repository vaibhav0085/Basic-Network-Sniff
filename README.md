 **NOTE**: THIS CODE IS VALID FOR Ubuntu/Debian, IF YOU WILL WILL RUN THIS CODE ON WINDOWS YOU WILL RECIEVE A WARNING(WARNING: No libpcap provider available ! pcap won't be used; \n Usage: python sniffer.py <interface>). 
!!!!!READ THIS FILE IN "CODE MODE" OR "BLAME MODE" FOR BETTER UNDERSATNDING!!!!
____________________________________________________________________________________________________________________________________________________________________
____________________________________________________________________________________________________________________________________________________________________

________________________________________________________________**Basic-Network-Sniff**_____________________________________________________________________________
Creating a network sniffer in Python is an excellent way to understand network traffic and packet structure. We can use the 'scapy' library, which is powerful for network packet manipulation and analysis. Below is a step-by-step guide to build a simple network sniffer:
____________________________________________________________________________________________________________________________________________________________________
Step 1: Install Required Libraries
First, you need to install 'scapy'. You can do this using pip:
syntax: pip install scapy
____________________________________________________________________________________________________________________________________________________________________
Step 2: Import Libraries
We'll need scapy and some standard Python libraries for our sniffer.
python code:
from scapy.all import sniff, IP, TCP, UDP
____________________________________________________________________________________________________________________________________________________________________
Step 3: Define Packet Processing Function
This function will be called for each packet captured by the sniffer. We'll print basic information about the packet, such as source and destination IP addresses, and the protocol.
python code:
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")
____________________________________________________________________________________________________________________________________________________________________
Step 4: Start sniffing
Use the sniff function from scapy to start capturing packets. We can specify the number of packets to capture and the function to call for each packet.
python code:
def start_sniffing(interface, packet_count):
    print(f"starting sniffer on {interface} for {packet_count} packets")
    sniff(iface=interface, prn=process_packet, count=packet_count, store=False)
example:
if __name__ == "__main__":
    start_sniffing(interface="eth0", packet_count=10)
____________________________________________________________________________________________________________________________________________________________________
Running the Sniffer
To run the sniffer, save the script to a file, e.g., network_sniffer.py, and execute it with Python:
bash
Copy code
sudo python network_sniffer.py
Note: Running a network sniffer typically requires elevated privileges, hence the use of sudo.
____________________________________________________________________________________________________________________________________________________________________
Enhancements
You can extend this basic sniffer in various ways:
Capture other protocols (e.g., ARP, ICMP).
Save captured packets to a file for later analysis.
Add filters to capture only specific types of traffic.
Analyze packet contents in more detail.
____________________________________________________________________________________________________________________________________________________________________
SUMMERY:
This script sets up a basic network sniffer that captures and prints information about IP, TCP, and UDP packets. By studying and extending this code, you can gain a deeper understanding of network traffic and packet structures.
_______________________________________________________________________________________________________THANKYOU_____________________________________________________
