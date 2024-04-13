import socket
import struct
import textwrap

def main():
    # Create a raw socket to capture packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"Ethernet Frame: Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
            print(f"IPv4 Packet: Version: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}, Source IP: {src_ip}, Target IP: {target_ip}")

            if proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f"ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}")

            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_segment(data)
                print(f"TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Sequence: {sequence}, Acknowledgment: {acknowledgment}, Flags: URG:{flag_urg}, ACK:{flag_ack}, PSH:{flag_psh}, RST:{flag_rst}, SYN:{flag_syn}, FIN:{flag_fin}")

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_segment(data)
                print(f"UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")

            else:
                print(f"Other IPv4 Protocol: {proto}")

        else:
            print(f"Other Ethernet Protocol: {eth_proto}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ":".join(map("{:02x}".format, bytes_addr))

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]

def get_ip(addr):
    return ".".join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

if __name__ == "__main__":
    main()
