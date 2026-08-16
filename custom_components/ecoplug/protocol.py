"""ECO Plug UDP protocol — pure asyncio, no Home Assistant deps.

Layered separately so it can be imported by the HA integration AND unit tests
AND ad-hoc scripts without pulling HA in.

Protocol summary (see notes/03-protocol.md for the derivation and
notes/04-second-device.md for what a second physical plug revealed):

- UDP unicast to plug at IP:1022. Reply comes from the plug's 1022 back to
  the sender's source port.
- Each outbound command is sent ~4 times for reliability.
- Every packet is exactly 152 bytes.
- The 56-byte body (offsets 16..71) is XOR-obfuscated with the 4-byte TXID
  repeated. The plaintext body is fixed for a given plug, so crafting a
  command is just: plaintext XOR fresh TXID.

PER-DEVICE IDENTITY
-------------------
The plaintext body and the 4-byte id at offset 12 are NOT universal — they
identify one specific plug, and the plug validates both. Testing a second
physical HOWT01A against this repo's original hardcoded constants:

    our id + our body   -> ACCEPTED
    our id + HIS body   -> ignored
    our id + zero body  -> ignored
    HIS id + our body   -> ignored

So both halves are checked independently. Of the 56 body bytes, 37 are
identical between the two plugs and 19 differ (offsets 0..9, 23..27, 48..51).
The id at offset 12 is the low three bytes of the plug's MAC, little-endian,
NUL-padded — that part is derivable, but the body is not: it is absent from
the plug's broadcast heartbeat and shows no derivation from the MAC.

Consequence: every plug needs its identity captured once. See
`src/ecoplug/capture_identity.py`, which does that from the Home Assistant
host itself without a rooted phone or PCAPdroid.
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

_HEADER_PREFIX = bytes.fromhex("1700000000000000")  # offsets 4..11, universal
_OPCODE_COMMAND = 0x6A
_OPCODE_QUERY = 0x69
_STATE_OFFSET = 80


class State(enum.IntEnum):
    OFF = 0
    ON = 1


@dataclass(frozen=True)
class PlugIdentity:
    """The per-device credentials a plug validates on every packet.

    device_id     4 bytes written at offset 12. Low three bytes of the plug's
                  MAC in little-endian order, then a NUL. Use `from_mac`.
    command_body  56-byte plaintext body for opcode 0x6A.
    query_body    56-byte plaintext body for opcode 0x69. On some units this
                  is identical to command_body; on others the trailing four
                  bytes differ. Defaults to command_body.
    *_txid_suffix Optional 2-byte tail forced onto generated TXIDs. The
                  original captures showed a constant tail per device, but a
                  second plug accepts fully random TXIDs, so this is only kept
                  for units that turn out to be strict. None = fully random.
    """

    device_id: bytes
    command_body: bytes
    query_body: bytes | None = None
    command_txid_suffix: bytes | None = None
    query_txid_suffix: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.device_id) != 4:
            raise ValueError("device_id must be 4 bytes")
        if len(self.command_body) != 56:
            raise ValueError("command_body must be 56 bytes")
        if self.query_body is not None and len(self.query_body) != 56:
            raise ValueError("query_body must be 56 bytes")

    @property
    def _query_body(self) -> bytes:
        return self.query_body if self.query_body is not None else self.command_body

    @staticmethod
    def device_id_from_mac(mac: str | bytes) -> bytes:
        """Low three MAC bytes, little-endian, NUL-padded to 4.

        '38:2b:78:1a:2b:3c' -> 3c 2b 1a 00
        """
        if isinstance(mac, str):
            mac = bytes.fromhex(mac.replace(":", "").replace("-", ""))
        if len(mac) != 6:
            raise ValueError("MAC must be 6 bytes")
        return bytes(reversed(mac[3:])) + b"\x00"

    @classmethod
    def from_mac(cls, mac: str | bytes, command_body: bytes,
                 query_body: bytes | None = None) -> "PlugIdentity":
        return cls(cls.device_id_from_mac(mac), command_body, query_body)


# The author's own HOWT01A, kept as the default so existing configs that
# predate per-device identity keep working unchanged. It will NOT drive any
# other plug -- see the module docstring.
AUTHOR_HOWT01A = PlugIdentity(
    device_id=bytes.fromhex("dae20c00"),
    command_body=bytes.fromhex(
        "79765143"    # device-specific (originally mislabelled "yvQC magic")
        "3b777774"    # device-specific
        "22402226"    # first two bytes device-specific
        "1b273339"    # universal
        "2434444c"    # universal
        "1a79651c"    # last byte device-specific
        "737c2233"    # device-specific
        "3f5b7785"    # bytes 28..47: arithmetic-progression filler, universal
        "48688898"    #   delta per byte: +09 +0d +11 +13
        "517599ab"
        "5a82aabe"
        "638fbbd1"
        "0d971f2a"    # device-specific
        "0dffe9e5"    # universal command tail
    ),
    query_body=bytes.fromhex(
        "79765143" "3b777774" "22402226" "1b273339" "2434444c" "1a79651c"
        "737c2233" "3f5b7785" "48688898" "517599ab" "5a82aabe" "638fbbd1"
        "0d971f2a" "f8adddf7"
    ),
    command_txid_suffix=bytes.fromhex("2dac"),
    query_txid_suffix=bytes.fromhex("e669"),
)

DEFAULT_IDENTITY = AUTHOR_HOWT01A


@dataclass
class PlugReply:
    raw: bytes
    txid: bytes
    state: State
    device_name: str
    timestamp: int | None = None
    tz_offset: int | None = None

    @classmethod
    def parse(cls, raw: bytes) -> "PlugReply":
        name_offset, name = _find_device_name(raw)
        timestamp = tz_offset = None
        if name_offset is not None:
            # The trailer is laid out relative to the name field:
            #   name-12  uint32 LE  unix timestamp (the plug's clock)
            #   name-8   int32  LE  timezone offset in seconds
            # Confirmed on two units whose name fields sit at different
            # offsets (112 and 108), each decoding to its own capture date
            # and its own timezone.
            timestamp = int.from_bytes(raw[name_offset - 12:name_offset - 8], "little")
            tz_offset = int.from_bytes(raw[name_offset - 8:name_offset - 4],
                                       "little", signed=True)
        return cls(
            raw=raw,
            txid=raw[0:4],
            state=State(raw[_STATE_OFFSET]),
            device_name=name,
            timestamp=timestamp,
            tz_offset=tz_offset,
        )


def _find_device_name(raw: bytes) -> tuple[int | None, str]:
    """Locate the NUL-terminated device name in a reply.

    Its offset is not constant across firmware revisions: the author's unit
    puts it at 112, a second unit at 108, with the timestamp and timezone
    fields shifted by the same 4 bytes. Rather than hardcode either, scan the
    4-byte-aligned candidates for the first printable NUL-terminated run.
    """
    for off in range(104, 129, 4):
        chunk = raw[off:off + 32]
        if not chunk:
            continue
        text = chunk.split(b"\x00", 1)[0]
        if text and all(32 <= c < 127 for c in text):
            return off, text.decode("ascii")
    return None, ""


def _xor_with_txid(pt: bytes, txid: bytes) -> bytes:
    key = (txid * ((len(pt) + 3) // 4))[: len(pt)]
    return bytes(a ^ b for a, b in zip(pt, key))


def _make_txid(suffix: bytes | None) -> bytes:
    return os.urandom(2) + suffix if suffix else os.urandom(4)


def _build(txid: bytes, device_id: bytes, body_pt: bytes,
           opcode: int, state: int) -> bytes:
    return (
        txid
        + _HEADER_PREFIX
        + device_id
        + _xor_with_txid(body_pt, txid)
        + b"\x00\x00\x00\x00"
        + bytes([opcode, 0, 0, 0])
        + bytes([state, 0, 0, 0])
        + b"\x00" * 68
    )


def craft_command(state: State, txid: bytes | None = None,
                  identity: PlugIdentity = DEFAULT_IDENTITY) -> bytes:
    if txid is None:
        txid = _make_txid(identity.command_txid_suffix)
    return _build(txid, identity.device_id, identity.command_body,
                  _OPCODE_COMMAND, int(state))


def craft_query(txid: bytes | None = None,
                identity: PlugIdentity = DEFAULT_IDENTITY) -> bytes:
    if txid is None:
        txid = _make_txid(identity.query_txid_suffix)
    return _build(txid, identity.device_id, identity._query_body,
                  _OPCODE_QUERY, 0)


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


async def set_state(plug_ip: str, state: State,
                    identity: PlugIdentity = DEFAULT_IDENTITY) -> PlugReply | None:
    return await send_and_wait(plug_ip, craft_command(state, identity=identity))


async def get_state(plug_ip: str,
                    identity: PlugIdentity = DEFAULT_IDENTITY) -> PlugReply | None:
    return await send_and_wait(plug_ip, craft_query(identity=identity))
