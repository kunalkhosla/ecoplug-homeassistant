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
    State,
    craft_command,
    craft_query,
    PlugReply,
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
        """Command TXIDs end in 2dac; queries end in e669 — matching captured traffic."""
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
            "aa39e669"                          # response counter @ 100..103
            "b0b9ffff01000000"                  # flags @ 104..111
            "506f6f6c2050756d7000000000000000"  # "Pool Pump" @ 112..127
            + "00" * 24                         # trailing padding
        )
        reply = PlugReply.parse(bytes.fromhex(captured_hex))
        self.assertEqual(reply.txid.hex(), "ea71e669")
        self.assertEqual(reply.state, State.ON)
        self.assertEqual(reply.device_name, "Pool Pump")


if __name__ == "__main__":
    unittest.main()
