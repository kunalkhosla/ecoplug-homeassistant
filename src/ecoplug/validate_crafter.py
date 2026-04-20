#!/usr/bin/env python3
"""
Offline validation: re-craft every captured phone→plug packet using its
original TXID and verify the output matches the captured payload byte-for-byte.

If this passes, we know the crafter can produce a packet the plug would
have seen in real life — a strong pre-check before live-testing against
the plug.

Usage:
    python3 validate_crafter.py captures/03-phone-side.pcap
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow importing sibling modules when run as a script.
sys.path.insert(0, str(Path(__file__).parent))

from analyze_body import iter_udp_payloads_from_pcap  # noqa: E402
from crafter import craft_command, craft_query, State  # noqa: E402


PLUG_IP = "192.168.0.87"
PLUG_PORT = 1022


def main():
    pcap_path = Path(sys.argv[1])

    checked = 0
    mismatches = 0
    kinds = {"command_on": 0, "command_off": 0, "query": 0}

    for _ts, src_ip, dst_ip, _sp, dst_port, payload in iter_udp_payloads_from_pcap(pcap_path):
        if dst_ip != PLUG_IP or dst_port != PLUG_PORT:
            continue
        if len(payload) != 152:
            continue

        txid = payload[0:4]
        opcode = payload[76]
        state_byte = payload[80]

        if opcode == 0x6A:
            rebuilt = craft_command(State(state_byte), txid=txid)
            kinds["command_on" if state_byte else "command_off"] += 1
        elif opcode == 0x69:
            rebuilt = craft_query(txid=txid)
            kinds["query"] += 1
        else:
            print(f"  skipping unknown opcode 0x{opcode:02x} (txid={txid.hex()})")
            continue

        checked += 1
        if rebuilt != payload:
            mismatches += 1
            # Show where they differ.
            diffs = [i for i in range(152) if rebuilt[i] != payload[i]]
            print(f"  MISMATCH txid={txid.hex()} opcode=0x{opcode:02x} state={state_byte}")
            print(f"    differing byte offsets: {diffs}")
            print(f"    captured : {payload.hex()}")
            print(f"    rebuilt  : {rebuilt.hex()}")

    print()
    print(f"checked {checked} phone→plug packets; {mismatches} mismatches")
    print(f"breakdown: {kinds}")
    if mismatches == 0:
        print("OK — the crafter reproduces every captured phone→plug packet exactly.")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
