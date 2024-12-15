# CodeAlpha1
import socket import struct import binascii

def create_raw_socket(): """Create a raw socket to capture packets.""" try: raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800)) # EtherType for IP raw_socket.bind(("eth0", 0)) # Use the correct network interface (eth0 is common, but change it as needed) return raw_socket except Exception as e: print(f"Error creating socket: {e}") return None

def parse_ethernet_header(packet): """Parse the Ethernet header.""" try: eth_header = struct.unpack("!6s6sH", packet[:14]) dest_mac = ':'.join(format(x, '02x') for x in eth_header[0]) src_mac = ':'.join(format(x, '02x') for x in eth_header[1]) eth_protocol = hex(eth_header[2]) return dest_mac, src_mac, eth_protocol except Exception as e: print(f"Error parsing Ethernet header: {e}") return None, None, None

def parse_ip_header(packet): """Parse the IP header.""" try: ip_header = packet[14:34] iph = struct.unpack("!BBHHHBBH4s4s", ip_header) version_ihl = iph[0] version = version_ihl >> 4 ihl = version_ihl & 0xF ttl = iph[5] protocol = iph[6] src_ip = socket.inet_ntoa(iph[8]) dest_ip = socket.inet_ntoa(iph[9]) return version, ttl, protocol, src_ip, dest_ip except Exception as e: print(f"Error parsing IP header: {e}") return None, None, None, None, None

def get_protocol_name(protocol_num): """Return the protocol name based on the protocol number.""" protocols = { 1: "ICMP", 6: "TCP", 17: "UDP" } return protocols.get(protocol_num, f"Unknown ({protocol_num})")

def print_packet_info(dest_mac, src_mac, eth_protocol, version, ttl, protocol, src_ip, dest_ip): """Print out the packet information in a human-readable format.""" print(f"Destination MAC: {dest_mac}") print(f"Source MAC: {src_mac}") print(f"Ethernet Protocol: {eth_protocol}") print(f"IP Version: {version}") print(f"TTL: {ttl}") print(f"Protocol: {get_protocol_name(protocol)}") print(f"Source IP: {src_ip}") print(f"Destination IP: {dest_ip}") print("-" * 50)

def main(): """Main function to capture and analyze packets.""" raw_socket = create_raw_socket() if raw_socket is None: return

print("Starting packet capture...")
try:
    while True:
        packet, _ = raw_socket.recvfrom(65535)  # Receive the raw packet
        dest_mac, src_mac, eth_protocol = parse_ethernet_header(packet)

        if dest_mac and src_mac and eth_protocol:
            print(f"\nCaptured a packet:")
            print_packet_info(dest_mac, src_mac, eth_protocol, None, None, None, None, None)

            if eth_protocol == '0x800':  # Check if the Ethernet type is IP (0x0800)
                version, ttl, protocol, src_ip, dest_ip = parse_ip_header(packet)
                if version and ttl and protocol and src_ip and dest_ip:
                    print_packet_info(dest_mac, src_mac, eth_protocol, version, ttl, protocol, src_ip, dest_ip)
except KeyboardInterrupt:
    print("\nPacket capture stopped by user.")
except Exception as e:
    print(f"Error during packet capture: {e}")
finally:
    raw_socket.close()
    print("Socket closed.")
