#!/usr/bin/env python3
"""Learn a plug's per-device identity from the Home Assistant host itself.

Each plug validates a 4-byte id (offset 12) and a 56-byte body that are unique
to it, so every user must recover their own. The README's original recipe was
PCAPdroid on a rooted-ish Android phone; this script needs no phone tooling at
all and works with an iPhone, a tablet, or anything else running the app.

HOW IT WORKS
    The phone and the plug are usually both on Wi-Fi, so their unicast traffic
    is bridged inside the access point and never reaches a passive sniffer on
    the wire. To see it, we answer ARP for the plug's IP -- periodic gratuitous
    ARP plus an instant spoofed reply to any "who has <plug>" -- so the phone
    addresses its frames to us at layer 2. The kernel then forwards them on to
    the real plug (ip_forward=1, send_redirects=0), so the plug still actuates
    and the app behaves normally. Every ARP cache we touch is restored on exit,
    including on crash or SIGTERM.

    This is a plain man-in-the-middle on your own LAN, against your own device.
    Run it only on a network you administer.

USAGE
    sudo python3 capture_identity.py --plug-ip 192.168.1.32 [--iface eth0]
    ...then open the ECO Plugs app and toggle the plug ON, then OFF.

It prints a ready-to-paste Home Assistant config block.

Requires Linux (AF_PACKET) and root. Read-only with respect to the plug: it
never sends a command of its own.
"""
from __future__ import annotations

import argparse
import binascii
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

PLUG_PORT = 1022
BCAST = b"\xff" * 6
ETH_ARP = b"\x08\x06"
ETH_IP = b"\x08\x00"


def mac_str(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def ip_bytes(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def iface_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as fh:
        return bytes.fromhex(fh.read().strip().replace(":", ""))


def iface_ip(iface: str) -> str:
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                         capture_output=True, text=True).stdout
    for part in out.split():
        if "/" in part and part.count(".") == 3:
            return part.split("/")[0]
    raise SystemExit(f"could not determine IPv4 address of {iface}")


def resolve_mac(ip: str) -> bytes:
    """Get a neighbour's MAC, prodding it with a ping if the cache is cold."""
    for attempt in range(3):
        out = subprocess.run(["ip", "-4", "neigh", "show", ip],
                             capture_output=True, text=True).stdout.split()
        if "lladdr" in out:
            return bytes.fromhex(out[out.index("lladdr") + 1].replace(":", ""))
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
        time.sleep(0.5)
    raise SystemExit(f"could not resolve MAC for {ip} -- is the plug online?")


def neighbours(exclude: set[str]) -> list[tuple[bytes, bytes]]:
    out = subprocess.run(["ip", "-4", "neigh"], capture_output=True, text=True).stdout
    hosts = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts and parts[0] not in exclude:
            try:
                hosts.append((ip_bytes(parts[0]),
                              bytes.fromhex(parts[parts.index("lladdr") + 1]
                                            .replace(":", ""))))
            except ValueError:
                pass
    return hosts


def arp_frame(op, sha, spa, tha, tpa, dst_mac, src_mac) -> bytes:
    return (dst_mac + src_mac + ETH_ARP
            + b"\x00\x01\x08\x00\x06\x04" + struct.pack("!H", op)
            + sha + spa + tha + tpa)


def parse_udp(raw: bytes):
    if len(raw) < 42 or raw[12:14] != ETH_IP:
        return None
    ip = raw[14:]
    if ip[9] != 17:
        return None
    ihl = (ip[0] & 0x0F) * 4
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport, ulen = struct.unpack("!HHH", udp[:6])
    return {
        "src": ".".join(map(str, ip[12:16])),
        "dst": ".".join(map(str, ip[16:20])),
        "sport": sport,
        "dport": dport,
        "payload": udp[8:8 + max(0, ulen - 8)],
    }


def decode_body(pkt: bytes) -> bytes:
    """Body plaintext = ciphertext XOR the TXID repeated."""
    txid, body = pkt[0:4], pkt[16:72]
    return bytes(body[i] ^ txid[i % 4] for i in range(len(body)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plug-ip", required=True)
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--duration", type=int, default=300,
                    help="seconds to capture (default 300)")
    args = ap.parse_args()

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, lambda *_: sys.exit(0))

    pi_mac = iface_mac(args.iface)
    pi_ip = iface_ip(args.iface)
    plug_mac = resolve_mac(args.plug_ip)
    plug_ipb = ip_bytes(args.plug_ip)
    print(f"interface {args.iface} {pi_ip} ({mac_str(pi_mac)})")
    print(f"plug      {args.plug_ip} ({mac_str(plug_mac)})")

    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    tx.bind((args.iface, 0))
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    rx.bind((args.iface, 0))
    rx.settimeout(1.0)

    # Forward what we intercept, and don't tell the phone to bypass us.
    for key in ("net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.send_redirects=0",
                f"net.ipv4.conf.{args.iface}.send_redirects=0"):
        subprocess.run(["sysctl", "-w", key], capture_output=True)

    stop = threading.Event()
    exclude = {args.plug_ip, pi_ip}

    def poison() -> None:
        while not stop.is_set():
            tx.send(arp_frame(2, pi_mac, plug_ipb, BCAST, plug_ipb, BCAST, pi_mac))
            tx.send(arp_frame(1, pi_mac, plug_ipb, b"\x00" * 6, plug_ipb, BCAST, pi_mac))
            for tip, tmac in neighbours(exclude):
                tx.send(arp_frame(2, pi_mac, plug_ipb, tmac, tip, tmac, pi_mac))
            stop.wait(2.0)

    threading.Thread(target=poison, daemon=True).start()
    print("\nredirect active -- now open the ECO Plugs app and toggle the plug "
          "ON, then OFF.\n(Ctrl-C once you have both.)\n")

    bodies: dict[int, bytes] = {}     # opcode -> plaintext body
    device_id: bytes | None = None
    states_seen: set[int] = set()
    talker: str | None = None
    end = time.time() + args.duration
    try:
        while time.time() < end:
            try:
                raw, _ = rx.recvfrom(65535)
            except socket.timeout:
                continue

            if raw[12:14] == ETH_ARP:
                a = raw[14:]
                if len(a) >= 28 and struct.unpack("!H", a[6:8])[0] == 1 \
                        and a[24:28] == plug_ipb and a[8:14] != pi_mac:
                    reply = arp_frame(2, pi_mac, plug_ipb, a[8:14], a[14:18],
                                      a[8:14], pi_mac)
                    for _ in range(3):
                        tx.send(reply)
                continue

            p = parse_udp(raw)
            if not p or p["dst"] != args.plug_ip or p["dport"] != PLUG_PORT:
                continue
            if p["src"] in (pi_ip, args.plug_ip) or len(p["payload"]) != 152:
                continue

            pkt = p["payload"]
            opcode, state = pkt[76], pkt[80]
            if device_id is None:
                device_id = pkt[12:16]
                talker = p["src"]
                print(f"  app is at {talker}; device id {device_id.hex()}")
            if opcode not in bodies:
                bodies[opcode] = decode_body(pkt)
                print(f"  captured opcode 0x{opcode:02x} "
                      f"({'command' if opcode == 0x6a else 'query'})")
            if opcode == 0x6A:
                states_seen.add(state)
            if 0x6A in bodies and 0x69 in bodies and len(states_seen) >= 2:
                print("  got a command body, a query body, and both states.")
                break
    finally:
        stop.set()
        heal = arp_frame(2, plug_mac, plug_ipb, BCAST, plug_ipb, BCAST, plug_mac)
        for _ in range(5):
            tx.send(heal)
            for tip, tmac in neighbours(exclude):
                tx.send(arp_frame(2, plug_mac, plug_ipb, tmac, tip, tmac, plug_mac))
            time.sleep(0.3)
        print(f"  [ARP restored: {args.plug_ip} -> {mac_str(plug_mac)}]")

    if not bodies or device_id is None:
        print("\nNothing captured. Check that the phone is on the SAME subnet as "
              "the plug -- over a VPN or a guest VLAN the app falls back to the "
              "cloud and no local packet exists to intercept.")
        return 1

    command_body = bodies.get(0x6A) or next(iter(bodies.values()))
    query_body = bodies.get(0x69)

    print("\n" + "=" * 66)
    print("Add this to configuration.yaml:\n")
    print("switch:")
    print("  - platform: ecoplug")
    print(f"    host: {args.plug_ip}")
    print("    name: Pool Pump")
    print(f'    mac: "{mac_str(plug_mac)}"')
    print(f'    command_body: "{binascii.hexlify(command_body).decode()}"')
    if query_body and query_body != command_body:
        print(f'    query_body: "{binascii.hexlify(query_body).decode()}"')
    print("=" * 66)
    expected = bytes(reversed(plug_mac[3:])) + b"\x00"
    if expected != device_id:
        print(f"\nnote: device id {device_id.hex()} does not match the value derived "
              f"from the MAC ({expected.hex()}). Use device_id instead of mac:\n"
              f'    device_id: "{device_id.hex()}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
