from scapy.all import *

def handle_packet(packet):
    if IPv6 in packet:
        src_ip = packet[IPv6].src
        dest_ip = packet[IPv6].dst
        print(f"IPv6 Packet: Source IP: {src_ip}, Destination IP: {dest_ip}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            print(f"TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            print(f"UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}")

        elif ICMPv6 in packet:
            icmp_type = packet[ICMPv6].type
            print(f"ICMPv6 Packet: Type: {icmp_type}")

        else:
            print("Other IPv6 Protocol")

def main():
    sniff(filter="ip6", prn=handle_packet)

if __name__ == "__main__":
    main()
