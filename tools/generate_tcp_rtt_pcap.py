#!/usr/bin/env python3
"""
Generate a small pcap that contains a TCP handshake and one data/ACK pair
such that Wireshark's TCP analysis will observe an RTT sample.

This script uses Scapy to craft packets and write a pcap with timestamps.
"""
import os
import sys
t0 = 0.0
try:
    from scapy.all import Ether, IP, TCP, wrpcap
    have_scapy = True
except Exception:
    have_scapy = False

out_dir = os.path.join(os.path.dirname(__file__), '..', 'test')
os.makedirs(out_dir, exist_ok=True)
out_pcap = os.path.abspath(os.path.join(out_dir, 'tcp_avg_rtt_test.pcap'))

# Addresses and ports
mac_a = b'\x02\x00\x00\x00\x00\x01'
mac_b = b'\x02\x00\x00\x00\x00\x02'
ip_a = '192.0.2.1'
ip_b = '192.0.2.2'
sport = 12345
dport = 80

# timestamps
t0 = 0.0
times = [t0, t0 + 0.001, t0 + 0.002, t0 + 0.010, t0 + 0.030]

payload = b'Hello'

def ip_to_bytes(ip_str):
    return bytes(map(int, ip_str.split('.')))

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def build_ether(ip_src, ip_dst, src_mac, dst_mac, sport, dport, seq, ack, flags, payload_bytes=b''):
    # Ethernet header
    eth_type = b'\x08\x00'  # IPv4
    eth = dst_mac + src_mac + eth_type

    # IP header (without checksum yet)
    ver_ihl = 0x45
    tos = 0
    ip_len = 20 + 20 + len(payload_bytes)
    ident = 0
    flags_frag = 0
    ttl = 64
    proto = 6
    src_ip_b = ip_to_bytes(ip_src)
    dst_ip_b = ip_to_bytes(ip_dst)
    ip_header = bytes([
        ver_ihl, tos,
    ]) + ip_len.to_bytes(2, 'big') + ident.to_bytes(2, 'big') + flags_frag.to_bytes(2, 'big') + bytes([ttl, proto]) + b'\x00\x00' + src_ip_b + dst_ip_b
    # compute IP checksum
    ip_ck = checksum(ip_header)
    ip_header = ip_header[:10] + ip_ck.to_bytes(2, 'big') + ip_header[12:]

    # TCP header
    data_offset = 5 << 4
    window = 65535
    urg_ptr = 0
    tcp_flags = flags
    tcp_header = sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big') + seq.to_bytes(4, 'big') + ack.to_bytes(4, 'big') + bytes([data_offset, tcp_flags]) + window.to_bytes(2, 'big') + b'\x00\x00' + urg_ptr.to_bytes(2, 'big')

    # TCP checksum via pseudo-header
    pseudo = src_ip_b + dst_ip_b + bytes([0, proto]) + (len(tcp_header) + len(payload_bytes)).to_bytes(2, 'big')
    tcp_ck = checksum(pseudo + tcp_header + payload_bytes)
    tcp_header = tcp_header[:16] + tcp_ck.to_bytes(2, 'big') + tcp_header[18:]

    frame = eth + ip_header + tcp_header + payload_bytes
    return frame

if have_scapy:
    # Use scapy if available (simpler)
    from scapy.all import Ether, IP, TCP, wrpcap
    packets = []
    # build same sequence as the fallback writer
    mac_a_str = '02:00:00:00:00:01'
    mac_b_str = '02:00:00:00:00:02'
    p1 = Ether(src=mac_a_str, dst=mac_b_str)/IP(src=ip_a, dst=ip_b)/TCP(sport=sport, dport=dport, flags='S', seq=1000)
    p1.time = times[0]
    packets.append(p1)
    p2 = Ether(src=mac_b_str, dst=mac_a_str)/IP(src=ip_b, dst=ip_a)/TCP(sport=dport, dport=sport, flags='SA', seq=2000, ack=1001)
    p2.time = times[1]
    packets.append(p2)
    p3 = Ether(src=mac_a_str, dst=mac_b_str)/IP(src=ip_a, dst=ip_b)/TCP(sport=sport, dport=dport, flags='A', seq=1001, ack=2001)
    p3.time = times[2]
    packets.append(p3)
    p4 = Ether(src=mac_a_str, dst=mac_b_str)/IP(src=ip_a, dst=ip_b)/TCP(sport=sport, dport=dport, flags='PA', seq=1001, ack=2001)/payload
    p4.time = times[3]
    packets.append(p4)
    p5 = Ether(src=mac_b_str, dst=mac_a_str)/IP(src=ip_b, dst=ip_a)/TCP(sport=dport, dport=sport, flags='A', seq=2001, ack=1006)
    p5.time = times[4]
    packets.append(p5)
    wrpcap(out_pcap, packets)
    print("Wrote pcap:", out_pcap)
    print("Packets written:", len(packets))
    print("Timestamps (s):", [p.time for p in packets])
else:
    # Pure-Python pcap writer fallback (no external deps)
    # Build frames
    frames = []
    # SYN
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1000, 0, 0x02, b''))
    # SYN-ACK
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2000, 1001, 0x12, b''))
    # ACK
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x10, b''))
    # PSH+ACK data
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    # ACK for data
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2001, 1006, 0x10, b''))

    # Write PCAP global header and packets
    with open(out_pcap, 'wb') as f:
        # global header (pcap, microsecond precision)
        f.write(b'\xd4\xc3\xb2\xa1')            # magic
        f.write((2).to_bytes(2, 'little'))        # major
        f.write((4).to_bytes(2, 'little'))        # minor
        f.write((0).to_bytes(4, 'little'))        # thiszone
        f.write((0).to_bytes(4, 'little'))        # sigfigs
        f.write((65535).to_bytes(4, 'little'))    # snaplen
        f.write((1).to_bytes(4, 'little'))        # network (LINKTYPE_ETHERNET)

        for ts, frame in zip(times, frames):
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            incl_len = len(frame)
            orig_len = incl_len
            f.write(ts_sec.to_bytes(4, 'little'))
            f.write(ts_usec.to_bytes(4, 'little'))
            f.write(incl_len.to_bytes(4, 'little'))
            f.write(orig_len.to_bytes(4, 'little'))
            f.write(frame)

    print("Wrote pcap (fallback writer):", out_pcap)
