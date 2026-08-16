"""Switch platform for ECO Plug via crafted UDP commands.

Drives the DEWENWILS HOWT01A / ECO Plugs family of 240V outdoor smart boxes
by sending dynamically-crafted UDP packets on port 1022. No cloud, no
account. Only works when Home Assistant is on the same LAN as the plug
(or on a network that can route unicast UDP to the plug's IP:1022).

Each plug has its own identity that it validates on every packet, so a
`mac` + `command_body` pair captured from YOUR plug is required. Run
`src/ecoplug/capture_identity.py` once to obtain them.

Config:
    switch:
      - platform: ecoplug
        host: 192.168.0.87
        name: Pool Pump
        mac: "38:2b:78:1a:2b:3c"
        command_body: "a1b2c3d4...."     # 112 hex chars
        query_body: "a1b2c3d4...."       # optional; defaults to command_body
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.switch import SwitchEntity, PLATFORM_SCHEMA
from homeassistant.const import CONF_HOST, CONF_MAC, CONF_NAME
from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from .protocol import (
    DEFAULT_IDENTITY,
    PlugIdentity,
    State,
    get_state,
    set_state,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_NAME = "ECO Plug"

CONF_DEVICE_ID = "device_id"
CONF_COMMAND_BODY = "command_body"
CONF_QUERY_BODY = "query_body"

# Platform default: query the plug every 10 seconds instead of HA's
# switch-platform default of 30s. The exchange is one UDP send + one reply,
# negligible network cost on a LAN.
SCAN_INTERVAL = timedelta(seconds=10)


def _hex_bytes(expected_len: int):
    """Config validator for a fixed-length hex string."""

    def validate(value: Any) -> bytes:
        try:
            raw = bytes.fromhex(cv.string(value).replace(":", "").replace(" ", ""))
        except ValueError as err:
            raise vol.Invalid(f"expected hex, got {value!r}") from err
        if len(raw) != expected_len:
            raise vol.Invalid(
                f"expected {expected_len} bytes ({expected_len * 2} hex chars), "
                f"got {len(raw)}"
            )
        return raw

    return validate


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
        # Identity: give either mac or device_id, plus the captured body.
        vol.Exclusive(CONF_MAC, "plug_id"): cv.string,
        vol.Exclusive(CONF_DEVICE_ID, "plug_id"): _hex_bytes(4),
        vol.Optional(CONF_COMMAND_BODY): _hex_bytes(56),
        vol.Optional(CONF_QUERY_BODY): _hex_bytes(56),
    }
)


def _identity_from_config(config: ConfigType) -> PlugIdentity:
    """Build a PlugIdentity, falling back to the author's plug if unspecified.

    The fallback exists only so configs written before per-device identity
    keep working. It cannot drive anyone else's plug, so say so loudly.
    """
    command_body = config.get(CONF_COMMAND_BODY)
    mac = config.get(CONF_MAC)
    device_id = config.get(CONF_DEVICE_ID)

    if command_body is None or (mac is None and device_id is None):
        _LOGGER.warning(
            "ecoplug: no per-device identity configured for %s, falling back to "
            "the reference plug's constants. This works ONLY on the original "
            "author's unit; every other plug validates its own identity and will "
            "silently ignore these packets. Run src/ecoplug/capture_identity.py "
            "and set mac + command_body.",
            config[CONF_HOST],
        )
        return DEFAULT_IDENTITY

    if device_id is None:
        device_id = PlugIdentity.device_id_from_mac(mac)
    return PlugIdentity(
        device_id=device_id,
        command_body=command_body,
        query_body=config.get(CONF_QUERY_BODY),
    )


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    host = config[CONF_HOST]
    name = config[CONF_NAME]
    identity = _identity_from_config(config)
    async_add_entities([EcoPlugSwitch(host, name, identity)], update_before_add=True)


class EcoPlugSwitch(SwitchEntity):
    _attr_should_poll = True

    def __init__(self, host: str, name: str, identity: PlugIdentity) -> None:
        self._host = host
        self._identity = identity
        self._attr_name = name
        self._attr_unique_id = f"ecoplug_{host.replace('.', '_')}"
        self._attr_is_on: bool | None = None
        self._lock = asyncio.Lock()

    async def async_turn_on(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await set_state(self._host, State.ON, self._identity)
            self._attr_is_on = (reply.state == State.ON) if reply else True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await set_state(self._host, State.OFF, self._identity)
            self._attr_is_on = (reply.state == State.ON) if reply else False
        self.async_write_ha_state()

    async def async_update(self) -> None:
        async with self._lock:
            reply = await get_state(self._host, self._identity)
        if reply is None:
            return  # keep last known state on a single missed poll
        self._attr_is_on = reply.state == State.ON
