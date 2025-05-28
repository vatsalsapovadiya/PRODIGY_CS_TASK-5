import socket
import struct
import textwrap


def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Permission denied: Please run this script with sudo/root.")
        return
    except Exception as e:
        print(f"[!] Failed to create socket: {e}")
        return

    print("[*] Network sniffer started. Listening for traffic...\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

            # IPv4
            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print('  IPv4 Packet:')
                print(f'    Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(f'    Protocol: {proto}, Source: {src}, Target: {target}')

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('    ICMP Packet:')
                    print(f'      Type: {icmp_type}, Code: {code}, Checksum: {checksum}')

                # TCP
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                    print('    TCP Segment:')
                    print(f'      Source Port: {src_port}, Destination Port: {dest_port}')
                    print(f'      Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                    print(f'      Flags:')
                    print(f'        URG: {flags[0]}, ACK: {flags[1]}, PSH: {flags[2]}, RST: {flags[3]}, SYN: {flags[4]}, FIN: {flags[5]}')

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print('    UDP Segment:')
                    print(f'      Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

                else:
                    print('    Other IPv4 Data:')
                    print(format_multi_line('      ', data))
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")


def ethernet_frame(data):
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest), get_mac_addr(src), proto, data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = [
        (offset_reserved_flags & 32) >> 5,  # URG
        (offset_reserved_flags & 16) >> 4,  # ACK
        (offset_reserved_flags & 8) >> 3,   # PSH
        (offset_reserved_flags & 4) >> 2,   # RST
        (offset_reserved_flags & 2) >> 1,   # SYN
        offset_reserved_flags & 1           # FIN
    ]
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\\x{:02x}'.format(byte) for byte in string)
        if size % 4:
            size += 4 - (size % 4)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':
    main()
