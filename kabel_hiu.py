import socket
import struct

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while(True):
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:\n")
        print("Destination {}, Source {}, Protocol {}".format(dest_mac,src_mac,eth_proto))

        if eth_proto == 0x0800: #IPv4
            (version,header_length,ttl,proto, src, target,data) = ipv4_head(data)
            print("IPV4 Packet: ")
            print("Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print("Protocol: {}, Source: {}, Target: {}".format(proto,src,target))

            if(proto==1): #ICMP
                icmp_type, code,checksum, data = icmp_packet(data)
                print('ICMP PACKET:')
                print("Type: {}, Code: {}, Checksum: {}".format(icmp_type,code,checksum))
            elif(proto==6): #TCP
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
                print("TCP PACKET:")
                print("Source port: {}, Destination Port: {}".format(src_port,dest_port))
                print("Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print("Flags : ")
                print("URG : {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
            elif(proto==17): #UDP
                src_port, dest_port, length,data = udp_packet(data)
                print("UDP PACKAGE:")
                print("Source Port {}, Destination Port {}, Length {}".format(src_port,dest_port,length))
        elif eth_proto==0x0806:
            htype, ptype,hlen, plen, oper, mac_addr, src_ip,dest_mac_addr,dest_ip, data = arp_head(data)
            print("ARP:")
            print("Hardware type: {}, Protocol type: {}, HLEN: {}, PLEN: {}".format(htype, ptype, hlen,plen))
            print("Oper: {}, Source Address: {}, Source IP: {}, Dest Address:{}, Dest IP: {}".format(oper,mac_addr,src_ip,dest_mac_addr,dest_ip))


#Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]

#Format MAC address to readable format
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#Unpack IPv4 packet
def ipv4_head(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    payload = data[header_length:]
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), payload

#Unpack ARP Header
def arp_head(data):
    htype,ptype,hlen,plen,oper,src_mac, src_ip, dest_mac, dest_ip = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    mac_addr = get_mac_addr(src_mac)
    dest_mac_addr = get_mac_addr(dest_mac)

    return htype, ptype,hlen, plen, oper, mac_addr, ipv4(src_ip),dest_mac_addr,ipv4(dest_ip), data[28:]

#Format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack TCP packet
def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1) >> 0
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UDP packet
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()