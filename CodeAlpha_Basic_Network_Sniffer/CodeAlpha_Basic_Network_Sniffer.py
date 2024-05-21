import socket
import struct
import textwrap

def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    
    # Bind the socket to the public interface
    conn.bind(('192.168.56.1', 0))

    
    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            # Receive data
            raw_data, addr = conn.recvfrom(65536)
            print(parse_packet(raw_data))
    except KeyboardInterrupt:
        # Turn off promiscuous mode
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

# Parse Ethernet frame
def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(proto), data[14:]

# Format MAC address
def format_mac_address(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Parse IPv4 packet
def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Parse ICMP packet
def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Parse TCP segment
def parse_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Parse UDP packet
def parse_udp_packet(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

# Parse packet
def parse_packet(data):
    eth_dest_mac, eth_src_mac, eth_proto, eth_data = parse_ethernet_frame(data)
    if eth_proto == 8:
        version, header_length, ttl, proto, src, target, ipv4_data = parse_ipv4_packet(eth_data)
        if proto == 1:
            icmp_type, code, checksum, icmp_data = parse_icmp_packet(ipv4_data)
            return f'IPv4 Packet\n\tSource: {src}, Destination: {target}\n\tICMP Packet\n\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}'
        elif proto == 6:
            src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = parse_tcp_segment(ipv4_data)
            return f'IPv4 Packet\n\tSource: {src}, Destination: {target}\n\tTCP Segment\n\t\tSource Port: {src_port}, Destination Port: {dest_port}, Sequence: {sequence}, Acknowledgment: {acknowledgement}, Flags: URG={flag_urg}, ACK={flag_ack}, PSH={flag_psh}, RST={flag_rst}, SYN={flag_syn}, FIN={flag_fin}'
        elif proto == 17:
            src_port, dest_port, length, udp_data = parse_udp_packet(ipv4_data)
            return f'IPv4 Packet\n\tSource: {src}, Destination: {target}\n\tUDP Packet\n\t\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {length}'
        else:
            return 'IPv4 Packet\n\tSource: {src}, Destination: {target}\n\tUnknown Protocol Data'
    else:
        return 'Ethernet Frame\n\tUnknown Protocol Data'

# Run the main function
main()
