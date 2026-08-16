"""Unit tests for the ECO Plug protocol crafter.

Run with: python3 -m unittest tests/test_protocol.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow importing the `custom_components.ecoplug.protocol` module directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.ecoplug.protocol import (  # noqa: E402
    AUTHOR_HOWT01A,
    PlugIdentity,
    PlugReply,
    State,
    craft_command,
    craft_query,
)


class TestCrafter(unittest.TestCase):

    def test_command_length(self):
        self.assertEqual(len(craft_command(State.ON)), 152)
        self.assertEqual(len(craft_command(State.OFF)), 152)

    def test_query_length(self):
        self.assertEqual(len(craft_query()), 152)

    def test_command_opcode_and_state(self):
        pkt_on = craft_command(State.ON)
        self.assertEqual(pkt_on[76], 0x6A)
        self.assertEqual(pkt_on[80], 1)

        pkt_off = craft_command(State.OFF)
        self.assertEqual(pkt_off[76], 0x6A)
        self.assertEqual(pkt_off[80], 0)

    def test_query_opcode(self):
        pkt_q = craft_query()
        self.assertEqual(pkt_q[76], 0x69)

    def test_txid_suffix(self):
        """The reference plug pins TXID tails, matching its captured traffic.

        A second plug accepts fully random TXIDs, so the suffix is a per-device
        quirk rather than a protocol rule -- see test_random_txid_when_no_suffix.
        """
        self.assertEqual(craft_command(State.ON)[2:4], b"\x2d\xac")
        self.assertEqual(craft_command(State.OFF)[2:4], b"\x2d\xac")
        self.assertEqual(craft_query()[2:4], b"\xe6\x69")

    def test_fixed_header(self):
        for pkt in (craft_command(State.ON), craft_command(State.OFF), craft_query()):
            self.assertEqual(pkt[4:16].hex(), "1700000000000000dae20c00")

    def test_command_reproduces_captured_packet(self):
        """Using a captured TXID must regenerate the captured packet exactly.

        This is the ground-truth proof that our crafter matches the real
        ECO Plugs app. Captured packet is pkt 48 in 03-phone-side.pcap
        (OFF command with TXID a8442dac).
        """
        captured_hex = (
            "a8442dac1700000000000000dae20c00"
            "d1327cef93335ad88a040f8ab3631e95"
            "8c7069e0b23d48b0db380f9f971f5a29"
            "e02ca534f931b407f2c68712cbcb967d"
            "a5d33286a5bbc449"
            "000000006a00000000000000" + "00" * 68
        )
        captured = bytes.fromhex(captured_hex)
        rebuilt = craft_command(State.OFF, txid=bytes.fromhex("a8442dac"))
        self.assertEqual(rebuilt, captured)

    def test_parse_reply(self):
        """Parse a captured plug→phone reply."""
        # Pkt 7 from 03-phone-side.pcap (reply to initial query, state=ON).
        captured_hex = (
            "ea71e6691700000000000000dae20c00"
            "9307b72aca038903fe3bf4730e6efd4e"
            "4151c25d8761fb6bc3739466d52a91ec"
            "a2196ef1bb047fc2b0f34cd789fe5db8"
            "531a593b8d1d93c0"                  # end of body @ byte 72
            "0000000069000000"                  # marker + opcode @ 72..79
            "0100000000000000000000000000000000000000"  # state + zeros @ 80..99
            "aa39e669"                          # unix timestamp @ 100..103
            "b0b9ffff01000000"                  # tz offset @ 104..107
            "506f6f6c2050756d7000000000000000"  # "Pool Pump" @ 112..127
            + "00" * 24                         # trailing padding
        )
        reply = PlugReply.parse(bytes.fromhex(captured_hex))
        self.assertEqual(reply.txid.hex(), "ea71e669")
        self.assertEqual(reply.state, State.ON)
        self.assertEqual(reply.device_name, "Pool Pump")
        # 0x69e639aa = 2026-04-20 14:35 UTC, the day this capture was taken.
        self.assertEqual(reply.timestamp, 0x69E639AA)
        self.assertEqual(reply.tz_offset, -18000)  # UTC-5


class TestPlugIdentity(unittest.TestCase):
    """A second physical plug proved the identity fields are per-device."""

    SECOND_BODY = bytes(range(56))  # stand-in; real bodies are per-device

    def test_device_id_from_mac(self):
        """Offset 12 is the low three MAC bytes, little-endian, NUL-padded."""
        self.assertEqual(
            PlugIdentity.device_id_from_mac("38:2b:78:1a:2b:3c").hex(), "3c2b1a00")
        self.assertEqual(
            PlugIdentity.device_id_from_mac("382b780ce2da").hex(), "dae20c00")

    def test_device_id_matches_reference_plug(self):
        """The author's hardcoded id is consistent with the MAC rule."""
        self.assertEqual(
            PlugIdentity.device_id_from_mac("00:00:00:0c:e2:da"),
            AUTHOR_HOWT01A.device_id)

    def test_identity_changes_packet_bytes(self):
        """A different identity must produce a different packet."""
        other = PlugIdentity(device_id=bytes.fromhex("3c2b1a00"),
                             command_body=self.SECOND_BODY)
        txid = bytes.fromhex("a8442dac")
        mine = craft_command(State.OFF, txid=txid, identity=other)
        theirs = craft_command(State.OFF, txid=txid)
        self.assertNotEqual(mine, theirs)
        self.assertEqual(mine[12:16].hex(), "3c2b1a00")
        self.assertEqual(mine[16:72],
                         bytes(self.SECOND_BODY[i] ^ txid[i % 4] for i in range(56)))

    def test_query_body_defaults_to_command_body(self):
        """Some units use one body for both opcodes."""
        ident = PlugIdentity(device_id=bytes.fromhex("3c2b1a00"),
                             command_body=self.SECOND_BODY)
        txid = bytes.fromhex("11223344")
        self.assertEqual(craft_command(State.ON, txid=txid, identity=ident)[16:72],
                         craft_query(txid=txid, identity=ident)[16:72])

    def test_random_txid_when_no_suffix(self):
        """Without a pinned suffix, the whole TXID is random (and accepted)."""
        ident = PlugIdentity(device_id=bytes.fromhex("3c2b1a00"),
                             command_body=self.SECOND_BODY)
        tails = {craft_command(State.ON, identity=ident)[2:4] for _ in range(50)}
        self.assertGreater(len(tails), 1)

    def test_rejects_wrong_lengths(self):
        with self.assertRaises(ValueError):
            PlugIdentity(device_id=b"\x00", command_body=self.SECOND_BODY)
        with self.assertRaises(ValueError):
            PlugIdentity(device_id=bytes(4), command_body=b"\x00" * 10)


class TestReplyLayoutVariants(unittest.TestCase):
    """The trailer's offset is not constant across firmware revisions.

    The reference unit puts the device name at 112; a second unit puts it at
    108, with the timestamp and timezone shifted by the same 4 bytes. The
    parser locates the name rather than hardcoding either offset.
    """

    @staticmethod
    def _reply(name_offset: int, name: bytes, timestamp: int, tz: int) -> bytes:
        raw = bytearray(152)
        raw[0:4] = bytes.fromhex("11223344")
        raw[76] = 0x69
        raw[80] = 1
        raw[name_offset - 12:name_offset - 8] = timestamp.to_bytes(4, "little")
        raw[name_offset - 8:name_offset - 4] = tz.to_bytes(4, "little", signed=True)
        raw[name_offset:name_offset + len(name)] = name
        return bytes(raw)

    def test_name_at_112(self):
        reply = PlugReply.parse(
            self._reply(112, b"Pool Pump", 0x69E639AA, -18000))
        self.assertEqual(reply.device_name, "Pool Pump")
        self.assertEqual(reply.timestamp, 0x69E639AA)
        self.assertEqual(reply.tz_offset, -18000)

    def test_name_at_108(self):
        reply = PlugReply.parse(
            self._reply(108, b"Pool Box", 0x6A81D464, -14400))
        self.assertEqual(reply.device_name, "Pool Box")
        self.assertEqual(reply.timestamp, 0x6A81D464)
        self.assertEqual(reply.tz_offset, -14400)

    def test_state_offset_is_stable(self):
        """Byte 80 tracks the relay on both units, so polling works everywhere."""
        for offset in (108, 112):
            raw = bytearray(self._reply(offset, b"Plug", 0, 0))
            raw[80] = 0
            self.assertEqual(PlugReply.parse(bytes(raw)).state, State.OFF)
            raw[80] = 1
            self.assertEqual(PlugReply.parse(bytes(raw)).state, State.ON)


if __name__ == "__main__":
    unittest.main()
