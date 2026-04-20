"""Switch platform for ECO Plug via UDP packet replay.

Drives the DEWENWILS HOWT01A / ECO Plugs family of 240V outdoor smart boxes
by replaying captured ON/OFF/QUERY UDP packets on port 1022. No cloud, no
account. Only works when Home Assistant is on the same LAN as the plug.

Config example:
    switch:
      - platform: ecoplug
        host: 192.168.0.87
        name: Pool Pump
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import voluptuous as vol

from homeassistant.components.switch import SwitchEntity, PLATFORM_SCHEMA
from homeassistant.const import CONF_HOST, CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.config_validation import (
    make_entity_service_schema,  # noqa: F401  (kept for future service defs)
)
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

_LOGGER = logging.getLogger(__name__)

DEFAULT_NAME = "ECO Plug"
PLUG_PORT = 1022
LOCAL_SRC_PORT = 9090
RESPONSE_TIMEOUT = 2.0
RETRANSMITS = 4
RETRANSMIT_DELAY = 0.01

# Captured from pcap 03-phone-side.pcap (pkt 48), command=OFF
_PACKET_OFF = bytes.fromhex(
    "a8442dac1700000000000000dae20c00"
    "d1327cef93335ad88a040f8ab3631e95"
    "8c7069e0b23d48b0db380f9f971f5a29"
    "e02ca534f931b407f2c68712cbcb967d"
    "a5d33286a5bbc449"
    "000000006a000000"
    "00000000" + "00" * 68
)

# Captured from pcap 03-phone-side.pcap (pkt 77), command=ON
_PACKET_ON = bytes.fromhex(
    "425d2dac1700000000000000dae20c00"
    "3b2b7cef792a5ad8601d0f8a597a1e95"
    "666969e0582448b031210f9f7d065a29"
    "0a35a5341328b40718df871221d2967d"
    "4fca32864fa2c449"
    "000000006a000000"
    "01000000" + "00" * 68
)

# Captured from pcap 03-phone-side.pcap (pkt 4), query packet
_PACKET_QUERY = bytes.fromhex(
    "ea71e6691700000000000000dae20c00"
    "9307b72ad106911dc831c44ff156d550"
    "ce45a225f0088375990dc45ad52a91ec"
    "a2196ef1bb047fc2b0f34cd789fe5db8"
    "e7e6f94312dc3b9e"
    "0000000069000000"
    "00000000" + "00" * 68
)

for _pkt in (_PACKET_OFF, _PACKET_ON, _PACKET_QUERY):
    assert len(_pkt) == 152

# State byte (offset 80..83): 01 00 00 00 = ON, 00 00 00 00 = OFF
_STATE_OFFSET = 80


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    }
)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    """Set up the ECO Plug switch from YAML config."""
    host = config[CONF_HOST]
    name = config[CONF_NAME]
    async_add_entities([EcoPlugSwitch(host, name)], update_before_add=True)


class _UdpReplayProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that captures the first reply."""

    def __init__(self) -> None:
        self.future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


class EcoPlugSwitch(SwitchEntity):
    """Controls an ECO Plug / DEWENWILS plug via replayed UDP commands."""

    _attr_should_poll = True

    def __init__(self, host: str, name: str) -> None:
        self._host = host
        self._attr_name = name
        self._attr_unique_id = f"ecoplug_{host.replace('.', '_')}"
        self._attr_is_on: bool | None = None
        self._lock = asyncio.Lock()

    async def _send_and_read(self, payload: bytes) -> bytes | None:
        """Send the given payload to the plug and wait for one UDP reply."""
        loop = asyncio.get_running_loop()

        # Reuse-addr + bind to 9090 so the plug's reply lands on our socket.
        # If 9090 is already taken (another HA restart race) we fall back to an
        # ephemeral port; the plug replies to the sender's port regardless.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", LOCAL_SRC_PORT))
        except OSError:
            sock.bind(("0.0.0.0", 0))
        sock.setblocking(False)

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UdpReplayProtocol(), sock=sock
            )
        except Exception:
            sock.close()
            raise

        try:
            for _ in range(RETRANSMITS):
                transport.sendto(payload, (self._host, PLUG_PORT))
                await asyncio.sleep(RETRANSMIT_DELAY)

            try:
                reply = await asyncio.wait_for(protocol.future, timeout=RESPONSE_TIMEOUT)
                return reply
            except asyncio.TimeoutError:
                _LOGGER.debug("ecoplug %s: no reply within %ss", self._host, RESPONSE_TIMEOUT)
                return None
        finally:
            transport.close()

    @staticmethod
    def _parse_state(reply: bytes) -> bool | None:
        if len(reply) < _STATE_OFFSET + 4:
            return None
        return reply[_STATE_OFFSET] == 1

    async def async_turn_on(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await self._send_and_read(_PACKET_ON)
            if reply is not None:
                self._attr_is_on = self._parse_state(reply) or True
            else:
                # Optimistic: if no reply, trust the command went through.
                self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await self._send_and_read(_PACKET_OFF)
            if reply is not None:
                parsed = self._parse_state(reply)
                self._attr_is_on = parsed if parsed is not None else False
            else:
                self._attr_is_on = False
        self.async_write_ha_state()

    async def async_update(self) -> None:
        async with self._lock:
            reply = await self._send_and_read(_PACKET_QUERY)
        if reply is None:
            # Keep last known state; don't flap to unavailable on a single miss.
            return
        parsed = self._parse_state(reply)
        if parsed is not None:
            self._attr_is_on = parsed
