#!/usr/bin/env python3
"""
Dump and XOR-decode every phone↔plug packet in a pcap so we can see
what's actually in the 56-byte "obfuscated" body (payload bytes 16..71).

Key used so far (from notes/03-protocol.md): body XOR'd with TXID (4 bytes)
repeated gives the plaintext body. We verify that and print the decoded
bytes side-by-side with ASCII interpretation.

Usage:
    python3 analyze_body.py captures/03-phone-side.pcap
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def iter_udp_payloads_from_pcap(path: Path):
    """Yield (ts, src_ip, dst_ip, src_port, dst_port, udp_payload) for every
    UDP datagram in a libpcap (not pcapng) file. Supports raw-IP linktype 101
    (what PCAPdroid emits) and Ethernet linktype 1.
    """
    with path.open("rb") as f:
        magic, _ver_major, _ver_minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack(
            "<IHHIIII", f.read(24)
        )
        # libpcap magic: 0xa1b2c3d4 = microsecond, 0xa1b23c4d = nanosecond
        if magic not in (0xA1B2C3D4, 0xA1B23C4D):
            raise RuntimeError(f"not a libpcap file (magic={magic:08x})")

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack("<IIII", hdr)
            packet = f.read(incl_len)
            if len(packet) < incl_len:
                return

            ts = ts_sec + ts_frac / (1e9 if magic == 0xA1B23C4D else 1e6)

            if linktype == 1:  # Ethernet
                if len(packet) < 14:
                    continue
                ethertype = struct.unpack(">H", packet[12:14])[0]
                if ethertype != 0x0800:
                    continue
                ip_offset = 14
            elif linktype == 101:  # raw IP
                ip_offset = 0
            else:
                raise RuntimeError(f"unsupported linktype {linktype}")

            ip = packet[ip_offset:]
            if len(ip) < 20:
                continue
            version_ihl = ip[0]
            if version_ihl >> 4 != 4:
                continue
            ihl = (version_ihl & 0x0F) * 4
            proto = ip[9]
            if proto != 17:  # UDP
                continue
            src_ip = ".".join(str(b) for b in ip[12:16])
            dst_ip = ".".join(str(b) for b in ip[16:20])

            udp = ip[ihl:]
            if len(udp) < 8:
                continue
            src_port, dst_port, udp_len, _checksum = struct.unpack(">HHHH", udp[:8])
            payload = udp[8:udp_len]

            yield ts, src_ip, dst_ip, src_port, dst_port, payload


def xor_decode_body(payload: bytes) -> bytes:
    """Decode bytes 16..71 by XOR with TXID (bytes 0..3) repeated."""
    txid = payload[0:4]
    body = payload[16:72]  # 56 bytes
    key = (txid * ((len(body) + 3) // 4))[: len(body)]
    return bytes(a ^ b for a, b in zip(body, key))


def pretty(decoded: bytes) -> str:
    hex_part = decoded.hex(" ", 4)
    ascii_part = "".join(
        chr(b) if 32 <= b < 127 else "." for b in decoded
    )
    return f"{hex_part}\n        ascii: {ascii_part!r}"


def main():
    pcap_path = Path(sys.argv[1])
    PLUG_IP = "192.168.0.87"
    PLUG_PORT = 1022

    first_ts = None
    print(f"{'#':>3}  {'t(s)':>6}  {'dir':<10}  txid     opcode state  decoded-body")
    print("-" * 110)

    n = 0
    for ts, src_ip, dst_ip, src_port, dst_port, payload in iter_udp_payloads_from_pcap(pcap_path):
        if len(payload) < 84:
            continue
        if PLUG_PORT not in (src_port, dst_port):
            continue
        if PLUG_IP not in (src_ip, dst_ip):
            continue

        if first_ts is None:
            first_ts = ts

        direction = "phone→plug" if dst_ip == PLUG_IP else "plug→phone"
        txid = payload[0:4]
        opcode = payload[76]
        state = payload[80]

        decoded = xor_decode_body(payload)
        n += 1
        print(
            f"{n:>3}  {ts - first_ts:>6.2f}  {direction:<10}  "
            f"{txid.hex()}  0x{opcode:02x}   0x{state:02x}   {pretty(decoded)}"
        )


if __name__ == "__main__":
    main()
