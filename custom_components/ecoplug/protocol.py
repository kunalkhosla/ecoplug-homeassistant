"""ECO Plug UDP protocol — pure asyncio, no Home Assistant deps.

Layered separately so it can be imported by the HA integration AND unit tests
AND ad-hoc scripts without pulling HA in.

Protocol summary (see notes/03-protocol.md in the repo root for derivation):

- UDP unicast to plug at IP:1022. Reply comes from the plug's 1022 back to
  the sender's source port.
- Each outbound command is sent ~4 times for reliability.
- Every packet is exactly 152 bytes.
- The 56-byte body (offsets 16..71) is XOR-obfuscated with the 4-byte TXID
  repeated. The plaintext body is fixed for every command packet, so we just
  XOR the same known plaintext with a fresh TXID to craft any command.
"""
from __future__ import annotations

import asyncio
import enum
import os
from dataclasses import dataclass


PLUG_PORT = 1022
LOCAL_SRC_PORT = 9090
DEFAULT_TIMEOUT = 2.0
DEFAULT_RETRANSMITS = 4
RETRANSMIT_SPACING = 0.01


# Plaintext command body derived by XOR-decoding captured phone→plug command
# packets with their TXIDs. Verified to reproduce every captured command
# packet byte-for-byte (see src/ecoplug/validate_crafter.py).
_COMMAND_BODY_PT = bytes.fromhex(
    "79765143"    # "yvQC" — magic
    "3b777774"
    "22402226"
    "1b273339"
    "2434444c"
    "1a79651c"
    "737c2233"
    "3f5b7785"    # bytes 28..47: arithmetic-progression filler (+09 +0d +11 +13 per byte)
    "48688898"
    "517599ab"
    "5a82aabe"
    "638fbbd1"
    "0d971f2a"
    "0dffe9e5"
)
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
    "f8adddf7"
)
assert len(_COMMAND_BODY_PT) == 56 and len(_QUERY_BODY_PT) == 56


_HEADER = bytes.fromhex("1700000000000000dae20c00")
_OPCODE_COMMAND = 0x6A
_OPCODE_QUERY = 0x69
_STATE_OFFSET = 80


class State(enum.IntEnum):
    OFF = 0
    ON = 1


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
            state=State(raw[_STATE_OFFSET]),
            device_name=raw[112:128].rstrip(b"\x00").decode("utf-8", errors="replace"),
        )


def _xor_with_txid(pt: bytes, txid: bytes) -> bytes:
    key = (txid * ((len(pt) + 3) // 4))[: len(pt)]
    return bytes(a ^ b for a, b in zip(pt, key))


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
    return payload


def craft_command(state: State, txid: bytes | None = None) -> bytes:
    if txid is None:
        txid = os.urandom(2) + b"\x2d\xac"  # observed suffix in captured command TXIDs
    return _build(txid, _COMMAND_BODY_PT, _OPCODE_COMMAND, int(state))


def craft_query(txid: bytes | None = None) -> bytes:
    if txid is None:
        txid = os.urandom(2) + b"\xe6\x69"  # observed suffix in captured query TXIDs
    return _build(txid, _QUERY_BODY_PT, _OPCODE_QUERY, 0)


class _UdpReplyProtocol(asyncio.DatagramProtocol):
    """Collects the first datagram the peer sends back."""

    def __init__(self) -> None:
        self._future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

    @property
    def future(self) -> asyncio.Future[bytes]:
        return self._future

    def datagram_received(self, data: bytes, addr) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def send_and_wait(
    plug_ip: str,
    payload: bytes,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retransmits: int = DEFAULT_RETRANSMITS,
) -> PlugReply | None:
    """Send a crafted packet to the plug and wait for one UDP reply.

    Returns None on timeout. Binds local port 9090 if available (mimics the
    phone app) so a plug that happens to hard-code destination port 9090 on
    replies still reaches us; falls back to an ephemeral port if 9090 is busy.
    """
    loop = asyncio.get_running_loop()

    import socket  # local import so module import is HA-friendly

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", LOCAL_SRC_PORT))
    except OSError:
        sock.bind(("0.0.0.0", 0))
    sock.setblocking(False)

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _UdpReplyProtocol(), sock=sock
    )
    try:
        for _ in range(retransmits):
            transport.sendto(payload, (plug_ip, PLUG_PORT))
            await asyncio.sleep(RETRANSMIT_SPACING)
        try:
            raw = await asyncio.wait_for(protocol.future, timeout=timeout)
            return PlugReply.parse(raw)
        except asyncio.TimeoutError:
            return None
    finally:
        transport.close()


async def set_state(plug_ip: str, state: State) -> PlugReply | None:
    return await send_and_wait(plug_ip, craft_command(state))


async def get_state(plug_ip: str) -> PlugReply | None:
    return await send_and_wait(plug_ip, craft_query())
