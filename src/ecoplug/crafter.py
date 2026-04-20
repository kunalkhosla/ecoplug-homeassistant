#!/usr/bin/env python3
"""
Build ECO Plug UDP command packets from scratch.

Approach: the 56-byte body is XOR-obfuscated with the 4-byte TXID repeated.
After decoding, the body is a fixed 56-byte plaintext for every command
packet (see notes/03-protocol.md). So crafting a valid packet for a fresh
TXID is: plaintext XOR (TXID×14) — assuming the plug doesn't also validate
the TXID structure itself.

Usage as a module:
    from crafter import craft_command, craft_query, State
    pkt = craft_command(State.ON)

CLI self-test:
    python3 crafter.py <plug_ip> on|off
"""
from __future__ import annotations

import enum
import os
import socket
import sys
import time
from dataclasses import dataclass

PLUG_PORT = 1022
LOCAL_SRC_PORT = 9090

# Plaintext body (56 bytes) observed in every phone→plug COMMAND packet after
# XOR-decoding with TXID. Holds regardless of ON vs OFF, regardless of TXID.
_COMMAND_BODY_PT = bytes.fromhex(
    "79765143"    # 'yvQC' — magic
    "3b777774"    #
    "22402226"    #
    "1b273339"    #
    "2434444c"    #
    "1a79651c"    #
    "737c2233"    #
    "3f5b7785"    # start of arithmetic-progression filler (bytes 28..47)
    "48688898"    #   delta per byte: 0x09 0x0d 0x11 0x13
    "517599ab"    #
    "5a82aabe"    #
    "638fbbd1"    # end of filler
    "0d971f2a"    # unknown constant
    "0dffe9e5"    # command-only tail (queries have a different varying tail)
)
assert len(_COMMAND_BODY_PT) == 56

# Plaintext body for QUERY packets. The last 4 bytes (52..55) vary per query
# in the phone app's output — they may be a nonce/timestamp. In practice the
# plug seems to answer any query regardless, so we use a known-good captured
# value here.
_QUERY_BODY_PT = bytes.fromhex(
    "79765143"
    "3b777774"
    "22402226"
    "1b273339"
    "2434444c"
    "1a79651c"
    "737c2233"
    "3f5b7785"
    "48688898"
    "517599ab"
    "5a82aabe"
    "638fbbd1"
    "0d971f2a"
    "f8adddf7"  # observed in one captured query
)
assert len(_QUERY_BODY_PT) == 56

# Packet layout:
#   [0..3]   TXID
#   [4..15]  constant header
#   [16..71] body (XOR-obfuscated)
#   [72..75] padding 00 00 00 00
#   [76..79] opcode (69=query, 6A=command) as LE u32
#   [80..83] state (0 or 1) as LE u32
#   [84..151] padding zeros
_HEADER = bytes.fromhex("1700000000000000dae20c00")  # 12 bytes
_OPCODE_COMMAND = 0x6A
_OPCODE_QUERY = 0x69


class State(enum.IntEnum):
    OFF = 0
    ON = 1


def _xor_with_txid(pt: bytes, txid: bytes) -> bytes:
    assert len(txid) == 4
    key = (txid * ((len(pt) + 3) // 4))[: len(pt)]
    return bytes(a ^ b for a, b in zip(pt, key))


def _fresh_txid_command() -> bytes:
    """Two random bytes + `2dac` suffix observed in captured command TXIDs."""
    return os.urandom(2) + b"\x2d\xac"


def _fresh_txid_query() -> bytes:
    """Two random bytes + `e669` suffix observed in captured query TXIDs."""
    return os.urandom(2) + b"\xe6\x69"


def _build(txid: bytes, body_pt: bytes, opcode: int, state: int) -> bytes:
    body_enc = _xor_with_txid(body_pt, txid)
    payload = (
        txid
        + _HEADER
        + body_enc
        + b"\x00\x00\x00\x00"
        + bytes([opcode, 0, 0, 0])
        + bytes([state, 0, 0, 0])
        + b"\x00" * 68
    )
    assert len(payload) == 152, f"payload is {len(payload)}, expected 152"
    return payload


def craft_command(state: State, txid: bytes | None = None) -> bytes:
    """Build a fresh command packet for a desired state."""
    return _build(txid or _fresh_txid_command(), _COMMAND_BODY_PT, _OPCODE_COMMAND, int(state))


def craft_query(txid: bytes | None = None) -> bytes:
    """Build a fresh state-query packet."""
    return _build(txid or _fresh_txid_query(), _QUERY_BODY_PT, _OPCODE_QUERY, 0)


@dataclass
class PlugReply:
    raw: bytes
    txid: bytes
    state: State
    device_name: str

    @classmethod
    def parse(cls, raw: bytes) -> "PlugReply":
        return cls(
            raw=raw,
            txid=raw[0:4],
            state=State(raw[80]),
            device_name=raw[112:128].rstrip(b"\x00").decode("utf-8", errors="replace"),
        )


def _send(plug_ip: str, payload: bytes, repeats: int = 4, timeout: float = 2.0) -> PlugReply | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", LOCAL_SRC_PORT))
    except OSError:
        sock.bind(("0.0.0.0", 0))
    sock.settimeout(timeout)
    try:
        for _ in range(repeats):
            sock.sendto(payload, (plug_ip, PLUG_PORT))
            time.sleep(0.01)
        data, _ = sock.recvfrom(1024)
        return PlugReply.parse(data)
    except socket.timeout:
        return None
    finally:
        sock.close()


def main():
    if len(sys.argv) != 3 or sys.argv[2].lower() not in {"on", "off", "query"}:
        print("Usage: crafter.py <plug_ip> on|off|query", file=sys.stderr)
        sys.exit(2)
    plug_ip = sys.argv[1]
    op = sys.argv[2].lower()

    if op == "query":
        pkt = craft_query()
    else:
        pkt = craft_command(State.ON if op == "on" else State.OFF)

    print(f"[{op.upper()}] txid={pkt[0:4].hex()}  sending {len(pkt)} bytes")
    reply = _send(plug_ip, pkt)
    if reply is None:
        print("  no reply")
        sys.exit(1)
    print(f"  reply: txid={reply.txid.hex()}  state={reply.state.name}  name={reply.device_name!r}")


if __name__ == "__main__":
    main()
