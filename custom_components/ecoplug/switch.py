"""Switch platform for ECO Plug via crafted UDP commands.

Drives the DEWENWILS HOWT01A / ECO Plugs family of 240V outdoor smart boxes
by sending dynamically-crafted UDP packets on port 1022. No cloud, no
account. Only works when Home Assistant is on the same LAN as the plug
(or on a network that can route unicast UDP to the plug's IP:1022).

Config:
    switch:
      - platform: ecoplug
        host: 192.168.0.87
        name: Pool Pump
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.switch import SwitchEntity, PLATFORM_SCHEMA
from homeassistant.const import CONF_HOST, CONF_NAME
from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from .protocol import State, get_state, set_state

_LOGGER = logging.getLogger(__name__)

DEFAULT_NAME = "ECO Plug"

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
    host = config[CONF_HOST]
    name = config[CONF_NAME]
    async_add_entities([EcoPlugSwitch(host, name)], update_before_add=True)


class EcoPlugSwitch(SwitchEntity):
    _attr_should_poll = True

    def __init__(self, host: str, name: str) -> None:
        self._host = host
        self._attr_name = name
        self._attr_unique_id = f"ecoplug_{host.replace('.', '_')}"
        self._attr_is_on: bool | None = None
        self._lock = asyncio.Lock()

    async def async_turn_on(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await set_state(self._host, State.ON)
            self._attr_is_on = (reply.state == State.ON) if reply else True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        async with self._lock:
            reply = await set_state(self._host, State.OFF)
            self._attr_is_on = (reply.state == State.ON) if reply else False
        self.async_write_ha_state()

    async def async_update(self) -> None:
        async with self._lock:
            reply = await get_state(self._host)
        if reply is None:
            return  # keep last known state on a single missed poll
        self._attr_is_on = reply.state == State.ON
