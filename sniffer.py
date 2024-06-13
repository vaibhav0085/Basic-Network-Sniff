import sys
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            print(f"\n[IP] {ip_layer.src} -> {ip_layer.dst}")

            if TCP in packet:
                tcp_layer = packet[TCP]
                print(f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            
            elif UDP in packet:
                udp_layer = packet[UDP]
                print(f"[UDP] {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
            
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                print(f"[ICMP] {ip_layer.src} -> {ip_layer.dst} Type: {icmp_layer.type}")

    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    try:
        print(f"Starting sniffer on interface {interface}...")
        sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print("You need to run this script with administrative privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
