# ecoplug-homeassistant

A working Home Assistant custom integration for the DEWENWILS / ECO Plug family of Wi-Fi smart plugs — **local control, no cloud, no account**.

Developed against a **DEWENWILS HOWT01A** (Amazon ASIN `B07PP2KNNH`, "Outdoor Wi-Fi Box, Heavy Duty 40A 120–277 VAC 2HP"), which uses the ECO Plugs mobile app. Should work on other units in the same firmware family (Workchoice / Woods / WiOn / KAB / DEWENWILS variants) but has not been tested.

## Why

- No official HA integration exists for these devices.
- The community `pyecoplug` integration is unmaintained and uses an older protocol version; it fails to discover units running current firmware on recent Home Assistant versions (tested against HA Core 2026.4.3 / HAOS 17.2).
- DEWENWILS's Google Home account-linking was broken at the time of development — OAuth completes but no devices are returned to Google, so that workaround isn't viable either.
- Flashing the device (Tasmota / ESPHome) is doable but requires disassembly, soldering, and USB-serial — too invasive for a 240V outdoor pool-pump box that works fine.

## What this integration does

Speaks the plug's native local UDP protocol on **port 1022** — the same protocol the ECO Plugs phone app uses when the phone and plug are on the same LAN. All command packets are dynamically crafted with a fresh TXID, so the integration works for **any** plug on the LAN (not just a specific one whose packets were recorded).

- **Turn on / turn off** — craft and send a 152-byte UDP command, parse the reply's state byte.
- **State polling** every 10 seconds.
- **Optimistic state update** if the plug doesn't reply to a single command.

Two entities of interest live in the repo:

- [`custom_components/ecoplug/protocol.py`](custom_components/ecoplug/protocol.py) — pure-asyncio protocol module with `craft_command`, `craft_query`, `set_state`, `get_state`. No Home Assistant deps; works standalone.
- [`custom_components/ecoplug/switch.py`](custom_components/ecoplug/switch.py) — thin HA switch-platform wrapper.

## How it was built (short version)

1. **Captured ECO Plugs app traffic from the phone** with PCAPdroid (Android). Found that the app sends 152-byte UDP unicast from src port 9090 to the plug's port 1022 and receives a matching reply.
2. **Reverse-engineered the 152-byte payload layout**: TXID, 12-byte fixed header, 56-byte XOR-obfuscated body, plaintext opcode (`69`=query / reply, `6A`=command), plaintext state (`00` / `01`), plus trailing padding. See [`notes/03-protocol.md`](notes/03-protocol.md).
3. **Decoded the body**: XOR with the TXID repeated yields a nearly fixed plaintext (and a totally fixed one for every command), so crafting packets for a new TXID is trivial. See [`src/ecoplug/analyze_body.py`](src/ecoplug/analyze_body.py).
4. **Verified the crafter offline**: [`src/ecoplug/validate_crafter.py`](src/ecoplug/validate_crafter.py) re-builds every captured command packet and confirms a byte-for-byte match.
5. **Live-tested** by crafting commands with random fresh TXIDs (never used by the app) and driving the pump from a laptop on the LAN. Plug accepted them and toggled.
6. **Wrapped as an HA custom component**.

## Installation

### Via HACS (as a custom repository)

1. In HACS → three-dot menu → **Custom repositories** → add `https://github.com/kunalkhosla/ecoplug-homeassistant` as type **Integration**.
2. Install "ECO Plug (local UDP)" from the list.
3. Restart Home Assistant.
4. Configure (see YAML below).

### Manually

1. Copy `custom_components/ecoplug/` into your HA `/config/custom_components/` directory.
2. Restart Home Assistant.

### Configure

Add to `configuration.yaml`:

```yaml
switch:
  - platform: ecoplug
    host: 192.168.0.87      # your plug's LAN IP — reserve it in DHCP
    name: Pool Pump
    scan_interval: 10       # optional; seconds between state polls (default 10)
```

`scan_interval` is standard HA — tune it for how fast you need external
changes (toggles from the ECO Plugs app, physical button, etc.) to show up
in HA. Smaller = faster sync but more UDP traffic. 5 is fine on a LAN.

Restart HA again. The entity shows up as e.g. `switch.pool_pump`.

**Prerequisite:** Home Assistant must be on a network that can route UDP unicast to the plug's IP:1022. Wired HA → Wi-Fi plug is fine (APs forward wired→Wi-Fi unicast). Wi-Fi HA on the same SSID as the plug is fine. HA on a different VLAN / SSID with client isolation may not be.

## Discovery (optional)

The plug broadcasts a 272-byte heartbeat on `UDP :10229 → 255.255.255.255:10228` every ~2 seconds, starting with the magic bytes `\x00\x00\x00\x00\x00\x55\xAA\x55\xAA\x00 "ECO Plugs\x00"`. You can scan for plugs on your LAN with:

```
python3 src/ecoplug/discovery.py --timeout 10
```

This prints every source IP that sent a heartbeat — useful for finding a plug's IP without opening the ECO Plugs app.

## Testing

```
python3 -m unittest tests/test_protocol.py -v
```

Includes a byte-exact reproduction test: crafting with a captured TXID must produce the exact captured packet.

## Limitations / known issues

- **State only updates on poll** (10-second interval) unless you tap the HA switch itself. When you toggle from the ECO Plugs app, HA picks up the change within ~10 seconds.
- **The body's trailing 4 bytes in query packets** are still not fully understood (they vary per query in the captured app traffic). We use a fixed value that the plug accepts. If some future firmware revision validates that field strictly, queries may break.
- **Only one device type validated** (DEWENWILS HOWT01A). Other ECO Plugs family members may differ.

## Repository layout

```
custom_components/ecoplug/        # the HA integration
  manifest.json
  protocol.py                     # crafter + asyncio UDP — no HA deps
  switch.py                       # HA switch-platform wrapper
  __init__.py
src/ecoplug/                      # standalone scripts used during dev
  crafter.py                      # CLI: python3 crafter.py <ip> on|off|query
  analyze_body.py                 # decode every packet in a pcap
  validate_crafter.py             # offline: crafter ≡ captured packets
  discovery.py                    # listen for LAN heartbeats
  replay_test.py                  # earliest proof of control
tests/
  test_protocol.py
notes/                            # protocol deep-dive + capture findings
captures/                         # pcap files (gitignored)
hacs.json
```

## Credits

Protocol reverse-engineering, implementation, tests, and this documentation by **[Claude Code](https://claude.com/claude-code)** (Anthropic's Opus 4.7), pair-programming with the repo owner. Built in ~3 hours on 2026-04-20 starting from a dead integration and no prior understanding of the device's protocol. See [`BUILD_STORY.md`](BUILD_STORY.md) for the full play-by-play.

Protocol naming and the idea of "ECO Plug family" plug control inspired by the original [`rsnodgrass/pyecoplug`](https://github.com/rsnodgrass/pyecoplug) integration, which handled earlier firmware variants of these devices but no longer works on current firmware or current HA.
