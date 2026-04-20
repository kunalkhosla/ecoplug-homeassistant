#!/usr/bin/env python3
"""
Passive discovery by listening for ECO Plug heartbeat broadcasts.

Every ~2 seconds each plug on the LAN sends a 272-byte UDP broadcast from
`<plug_ip>:10229` to `255.255.255.255:10228`. The payload begins with the
magic bytes `\\x00\\x00\\x00\\x00\\x00\\x55\\xAA\\x55\\xAA\\x00` followed by
ASCII `"ECO Plugs\\0"`.

The rest of the broadcast is XOR-obfuscated (same scheme family as the
control protocol, but the key is not yet decoded — not needed for IP
discovery). We use the magic bytes to identify plugs and the UDP source
IP to learn each plug's address.

CLI:
    python3 discovery.py            # listen forever
    python3 discovery.py --timeout 30
"""
from __future__ import annotations

import argparse
import socket
import time

BROADCAST_PORT = 10228
MAGIC = b"\x00\x00\x00\x00\x00\x55\xaa\x55\xaa\x00ECO Plugs\x00"


def looks_like_ecoplug(payload: bytes) -> bool:
    return len(payload) >= len(MAGIC) and payload.startswith(MAGIC)


def listen(timeout: float | None = None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", BROADCAST_PORT))

    seen = {}  # ip -> last_seen_ts
    deadline = None if timeout is None else time.monotonic() + timeout

    try:
        while deadline is None or time.monotonic() < deadline:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
            try:
                data, (src_ip, _src_port) = sock.recvfrom(2048)
            except socket.timeout:
                break
            if not looks_like_ecoplug(data):
                continue
            if src_ip not in seen:
                print(f"found ECO Plug at {src_ip} (payload {len(data)} bytes)")
            seen[src_ip] = time.monotonic()
    finally:
        sock.close()

    return sorted(seen.keys())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=None,
                        help="seconds to listen; default listens forever")
    args = parser.parse_args()
    found = listen(timeout=args.timeout)
    if args.timeout is not None:
        print()
        print(f"discovered {len(found)} plug(s): {found}")


if __name__ == "__main__":
    main()
