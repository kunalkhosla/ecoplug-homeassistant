# ecoplug-homeassistant

Custom Home Assistant integration for DEWENWILS / ECO Plug / WiOn / Woods / Workchoice / KAB family of Wi-Fi smart plugs.

## Why this exists

- `pyecoplug` (community integration) is unmaintained and fails on recent HA versions.
- DEWENWILS cloud account linking to Google Home has a broken OAuth flow as of 2026-04.
- Target hardware: DEWENWILS HOWT01A / B07PP2KNNH (40A/2HP pool-pump rated Wi-Fi box, ESP8266 inside).

## Approach

Reverse-engineer the local protocol the ECO Plugs phone app uses to talk to the plug, then implement a clean Python library + HA `custom_component`.

## Layout

- `captures/` — raw `.pcap` and `.pcapng` traffic captures
- `notes/` — protocol analysis, packet format notes
- `src/ecoplug/` — Python library (pure asyncio, no HA deps)
- `custom_components/ecoplug/` — HA integration wrapping the library

## Status

Early R&D. No working code yet.
