#!/usr/bin/env python3
"""
Generate several test pcaps exercising TCP behaviors (baseline, retransmission,
out-of-order, high retransmission) and run tshark to collect conversation stats.
Writes results to test/tcp_stats_results.csv and retains pcaps under test/.

This script avoids external deps and writes raw ethernet frames
with IPv4/TCP headers.
"""
import os
import struct
import csv
import subprocess
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_DIR = ROOT / 'test'
TEST_DIR.mkdir(exist_ok=True)
TSHARK = str(ROOT / 'build' / 'run' / 'tshark')

# Common addresses/ports
mac_a = b'\x02\x00\x00\x00\x00\x01'
mac_b = b'\x02\x00\x00\x00\x00\x02'
ip_a = '192.0.2.1' # Add your IP address here
ip_b = '192.0.2.2' # Add your IP address here
sport = 12345
dport = 80
payload = b'Hello'

def ip_to_bytes(ip_str):
    return bytes(map(int, ip_str.split('.')))

# simple ip/tcp checksum helper
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
    eth_type = b'\x08\x00'  # IPv4
    eth = dst_mac + src_mac + eth_type
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
    ip_ck = checksum(ip_header)
    ip_header = ip_header[:10] + ip_ck.to_bytes(2, 'big') + ip_header[12:]
    data_offset = 5 << 4
    window = 65535
    urg_ptr = 0
    tcp_flags = flags
    tcp_header = sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big') + seq.to_bytes(4, 'big') + ack.to_bytes(4, 'big') + bytes([data_offset, tcp_flags]) + window.to_bytes(2, 'big') + b'\x00\x00' + urg_ptr.to_bytes(2, 'big')
    pseudo = src_ip_b + dst_ip_b + bytes([0, proto]) + (len(tcp_header) + len(payload_bytes)).to_bytes(2, 'big')
    tcp_ck = checksum(pseudo + tcp_header + payload_bytes)
    tcp_header = tcp_header[:16] + tcp_ck.to_bytes(2, 'big') + tcp_header[18:]
    frame = eth + ip_header + tcp_header + payload_bytes
    return frame

PCAP_GLOBAL_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def write_pcap(path, times, frames):
    with open(path, 'wb') as f:
        f.write(PCAP_GLOBAL_HDR)
        for ts, frame in zip(times, frames):
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            incl_len = len(frame)
            orig_len = incl_len
            f.write(struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len))
            f.write(frame)

# Scenario builders

def baseline_pcap(path):
    t0 = 0.0
    times = [t0, t0+0.001, t0+0.002, t0+0.010, t0+0.030]
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
    write_pcap(path, times, frames)

def retransmission_pcap(path):
    # duplicate data later => retransmission
    t0 = 0.0
    times = [t0, t0+0.001, t0+0.002, t0+0.010, t0+0.030, t0+0.050]
    frames = []
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1000, 0, 0x02, b''))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2000, 1001, 0x12, b''))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x10, b''))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    # retransmit duplicate
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2001, 1006, 0x10, b''))
    write_pcap(path, times, frames)

def out_of_order_pcap(path):
    # Send two data segments but with order swapped at capture time
    t0 = 0.0
    # Two PSH segments with seq 1001 and seq 1006, but deliver 1006 first
    times = [t0, t0+0.001, t0+0.002, t0+0.005, t0+0.010, t0+0.030]
    frames = []
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1000, 0, 0x02, b''))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2000, 1001, 0x12, b''))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x10, b''))
    # data segment 2 (seq 1006) arrives before segment 1 (seq 1001)
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1006, 2001, 0x18, payload))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2001, 1011, 0x10, b''))
    write_pcap(path, times, frames)

def high_retrans_pcap(path):
    # Include multiple retransmissions quickly to simulate "losses/s"
    t0 = 0.0
    times = [t0, t0+0.001, t0+0.002]
    frames = []
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1000, 0, 0x02, b''))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2000, 1001, 0x12, b''))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x10, b''))
    # original data
    for i in range(3):
        times.append(t0 + 0.010 + i*0.005)
        frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    # multiple retransmits
    for i in range(5):
        times.append(t0 + 0.030 + i*0.002)
        frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    # final ack
    times.append(t0 + 0.080)
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2001, 1016, 0x10, b''))
    write_pcap(path, times, frames)


def force_ooo_pcap(path):
    # Create a packet with a far-ahead sequence number that arrives before the lower-sequence packet to force an OOO detection by the analyzer.
    t0 = 0.0
    times = [t0, t0+0.001, t0+0.002, t0+0.005, t0+0.030]
    frames = []
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1000, 0, 0x02, b''))
    frames.append(build_ether(ip_b, ip_a, mac_b, mac_a, dport, sport, 2000, 1001, 0x12, b''))
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x10, b''))
    # Far-ahead segment (seq 3000) arrives early
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 3000, 2001, 0x18, payload))
    # then the expected lower-seq segment arrives
    frames.append(build_ether(ip_a, ip_b, mac_a, mac_b, sport, dport, 1001, 2001, 0x18, payload))
    write_pcap(path, times, frames)

SCENARIOS = [
    ('baseline', baseline_pcap),
    ('retransmission', retransmission_pcap),
    ('out_of_order', out_of_order_pcap),
    ('force_ooo', force_ooo_pcap),
    ('high_retrans', high_retrans_pcap),
]

RESULT_CSV = TEST_DIR / 'tcp_stats_results.csv'


def run_tshark_fields(pcap):
    # extract per-frame fields
    cmd = [TSHARK, '-r', str(pcap), '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.analysis.retransmission', '-e', 'tcp.analysis.out_of_order', '-e', 'tcp.analysis.ack_rtt']
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        print('tshark failed:', p.stderr)
        return None
    lines = [line for line in p.stdout.splitlines()]
    # parse ack_rtt samples
    ack_rtts = []
    retrans_count = 0
    ooo_count = 0
    for line in lines:
        parts = line.split('\t')
        # fields may be empty; ack_rtt may be at index 3
        if len(parts) >= 4 and parts[3].strip() != '':
            try:
                ack_rtts.append(float(parts[3]))
            except Exception:
                pass
        if len(parts) >= 2 and parts[1].strip() == '1':
            retrans_count += 1
        if len(parts) >= 3 and parts[2].strip() == '1':
            ooo_count += 1
    return {'ack_rtts': ack_rtts, 'retrans': retrans_count, 'ooo': ooo_count, 'raw_lines': lines}


def run_tshark_per_packet(pcap, out_csv_path):
    """Dump a per-packet CSV with detailed TCP fields to help debug OOO detection."""
    fields = [
        'frame.number', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
        'tcp.seq', 'tcp.len', 'tcp.flags', 'tcp.analysis.retransmission',
        'tcp.analysis.out_of_order', 'tcp.analysis.ack_rtt'
    ]
    cmd = [TSHARK, '-r', str(pcap), '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    # request CSV-like output with commas
    cmd += ['-E', 'header=y', '-E', 'separator=,']
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        print('tshark per-packet extraction failed:', p.stderr)
        return False
    # write out exactly what tshark emitted (CSV header + rows)
    with open(out_csv_path, 'w', newline='') as f:
        f.write(p.stdout)
    return True


def compute_expected_ooo(pcap):
    """Simple external OOO detector: walks frames in capture order and
    counts packets whose sequence number is greater than the currently
    expected nextseq for that flow. This is a heuristic for testing the conversation-level counter.
    """
    cmd = [TSHARK, '-r', str(pcap), '-T', 'fields', '-e', 'frame.number', '-e', 'ip.src', '-e', 'tcp.seq', '-e', 'tcp.len']
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        return None
    nextseq = {}  # map (ip.src, ip.dst, sport, dport) simplified by ip.src only for our test pcaps
    ooo = 0
    for line in p.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) < 4:
            continue
        ipsrc = parts[1].strip()
        seq = parts[2].strip()
        length = parts[3].strip()
        if seq == '':
            continue
        try:
            seq_v = int(seq)
            len_v = int(length) if length != '' else 0
        except Exception:
            continue
        exp = nextseq.get(ipsrc, None)
        if exp is None:
            # first packet of this src; set expected next
            nextseq[ipsrc] = seq_v + len_v
            continue
        # If seq_v != exp, and seq_v > exp, it's an OOO (packet with higher seq arrived before expected)
        if seq_v > exp:
            ooo += 1
            # still update nextseq to max
            nextseq[ipsrc] = max(exp, seq_v + len_v)
        else:
            # normal in-order or duplicate, advance expected
            nextseq[ipsrc] = max(exp, seq_v + len_v)
    return ooo


def run_conv_tcp(pcap):
    cmd = [TSHARK, '-r', str(pcap), '-q', '-z', 'conv,tcp']
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout + p.stderr


def summarize():
    rows = []
    for name, builder in SCENARIOS:
        pcap_path = TEST_DIR / f'tcp_stats_{name}.pcap'
        print('Building', name, '->', pcap_path)
        builder(pcap_path)
        # generate a per-packet CSV for debugging
        per_packet_csv = TEST_DIR / f'per_packet_{name}.csv'
        ok = run_tshark_per_packet(pcap_path, per_packet_csv)
        if not ok:
            print('Warning: failed to generate per-packet CSV for', name)

        fields = run_tshark_fields(pcap_path)
        conv = run_conv_tcp(pcap_path)
        if fields is None:
            print('Skipping', name, 'due to tshark error')
            continue
        ack_rtts = fields['ack_rtts']
        median_ms = round(statistics.median(ack_rtts)*1000, 3) if ack_rtts else ''
        avg_ms = round(statistics.mean(ack_rtts)*1000, 3) if ack_rtts else ''
        rtt_count = len(ack_rtts)
        retrans = fields['retrans']
        ooo = fields['ooo']
        expected_ooo = compute_expected_ooo(pcap_path)
        # If dissector OOO count differs from our heuristic, emit a clear warning and
        # point to the per-packet CSV for inspection.
        if expected_ooo is not None and ooo != expected_ooo:
            print('\n*** WARNING: out_of_order mismatch for', name, '\n  dissector out_of_order=', ooo, 'expected_ooo=', expected_ooo)
            print('  See', per_packet_csv, 'for per-packet fields to investigate.\n')
        # approximate losses/sec: retrans / duration from conv output (try to parse duration)
        dur = None
        for line in conv.splitlines():
            if 'Duration' in line and '%' not in line:
                parts = line.strip().split()
                try:
                    val = parts[-1].replace(',', '.')
                    dur = float(val)
                except Exception:
                    pass
        losses_per_s = ''
        if dur and dur > 0:
            losses_per_s = round(retrans / dur, 3)
        rows.append({
            'scenario': name,
            'pcap': str(pcap_path.name),
            'median_rtt_ms': median_ms,
            'avg_rtt_ms': avg_ms,
            'rtt_samples': rtt_count,
            'retransmissions': retrans,
            'out_of_order': ooo,
            'expected_ooo': expected_ooo,
            'losses_per_s': losses_per_s,
            'conv_summary': conv.strip().replace('\n', '\\n')
        })
    # write CSV
    with open(RESULT_CSV, 'w', newline='') as csvf:
        fieldnames = ['scenario','pcap','median_rtt_ms','avg_rtt_ms','rtt_samples','retransmissions','out_of_order','expected_ooo','losses_per_s','conv_summary']
        w = csv.DictWriter(csvf, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print('Wrote results to', RESULT_CSV)

if __name__ == '__main__':
    summarize()
