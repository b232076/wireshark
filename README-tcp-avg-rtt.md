Wireshark TCP Avg RTT patch - Test README

Goal
----
Provide a minimal test and instructions to validate the new "Avg RTT (ms)" column added to the Conversations window for TCP.

Files added by the patch
------------------------
- epan/conversation_table.h/c  : stores and aggregates RTT samples from TCP analysis
- ui/qt/models/atap_data_model.*: UI changed to add an "Avg RTT (ms)" extended column
- tools/generate_tcp_rtt_pcap.py : helper script that generates a small pcap with a TCP handshake and one data/ACK pair that should produce an RTT sample
- test/tcp_avg_rtt_test.pcap    : generated pcap (created by running the script)

How to build (quick)
--------------------
From the repository root, using the existing build directory:

```bash
cd /home/beavpm/dev/wireshark/build
make -j$(nproc)
```

If you don't have a build directory yet, follow your usual Wireshark build steps (cmake ..; make).

How to generate the test pcap
----------------------------
This repo includes a small script using Scapy to generate a deterministic pcap with timestamps:

```bash
python3 tools/generate_tcp_rtt_pcap.py
```

It writes the file to `test/tcp_avg_rtt_test.pcap` under the repository root.

Note: the script requires Scapy. Install with:

```bash
python3 -m pip install --user scapy
```

How to test in Wireshark
------------------------
1) Build the patched Wireshark as shown above (or use your existing build of the modified tree).
2) Run the built Wireshark (or open the capture with the built `wireshark` binary in `run/wireshark`):

```bash
run/wireshark test/tcp_avg_rtt_test.pcap
```

3) Open the Conversations window (Statistics -> Conversations) and select protocol TCP.
4) Find the new extended column "Avg RTT (ms)" — it should display a value (e.g., ~20.000 ms) for the conversation in the generated pcap.

Notes & limitations
-------------------
- The RTT is computed from per-ACK RTT samples aggregated from the TCP analysis module (the `tcpd->acked_table` entries). If no samples exist, the code falls back to the initial RTT sample (`ts_first_rtt`) when available.
- The test pcap is synthetic; real traffic will yield more samples and a more robust average.
- If you want optimization, the aggregation can be moved into the TCP dissector so the conversation tap only reads pre-aggregated counters (future step).

If you want, I can also:
- Add an automated test that runs `tshark` or a tap against the pcap to assert the Avg RTT value,
- Move aggregation into the TCP dissector for better performance.
