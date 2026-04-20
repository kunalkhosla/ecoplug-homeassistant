# ecoplug-homeassistant

A working Home Assistant custom integration for the DEWENWILS / ECO Plug family of 240V Wi-Fi smart boxes — **local control, no cloud, no account**.

Developed specifically against a **DEWENWILS HOWT01A** (Amazon ASIN `B07PP2KNNH`, "Outdoor Wi-Fi Box, Heavy Duty 40A 120–277 VAC 2HP"), which uses the ECO Plugs mobile app. Should also work against other units in the same firmware family (Workchoice / Woods / WiOn / KAB / etc.) but has not been tested.

## Why

- The DEWENWILS/ECO Plugs device family has **no official HA integration**.
- The community `pyecoplug` integration is unmaintained and uses an older version of the protocol; it fails to discover units running the current firmware on recent Home Assistant versions (tested on HA Core 2026.4.3 / HAOS 17.2).
- Google Home account-linking for ECO Plugs was broken at the time of development — OAuth completed but no devices were returned to Google, making the "bridge through Google" workaround non-viable.
- Flashing the device (Tasmota / ESPHome) is doable but requires disassembly, soldering, and USB-serial hardware. For a 240V outdoor pool-pump box this was not preferred.

## What this integration does

- Talks to the plug over the LAN via UDP unicast on **port 1022** (the protocol the ECO Plugs phone app uses when the phone is on the same LAN as the plug).
- Replays three pre-captured UDP packets:
  - **ON command** (opcode `0x6A`, state `0x01`)
  - **OFF command** (opcode `0x6A`, state `0x00`)
  - **State query** (opcode `0x69`)
- Reads the plug's reply (echoed TXID, opcode `0x69`, state byte at offset 80) to confirm the actual on/off state.

That's it — it's intentionally tiny. See [`custom_components/ecoplug/switch.py`](custom_components/ecoplug/switch.py).

## How it was built (1-minute tour)

1. **Captured ECO Plugs app traffic from the phone** with PCAPdroid to see what the app actually does when you tap ON/OFF. Key finding: the app opens a UDP socket bound to local port `9090` and sends 152-byte payloads to `plug_ip:1022`. See [notes/02-capture-findings.md](notes/02-capture-findings.md).
2. **Reverse-engineered the payload format**: TXID + fixed header + XOR-obfuscated body + plaintext opcode + plaintext state byte. See [notes/03-protocol.md](notes/03-protocol.md).
3. **Replay test from HAOS** succeeded on the first try — the plug accepts captured packets verbatim, with no nonce/timestamp validation. See [`src/ecoplug/replay_test.py`](src/ecoplug/replay_test.py).
4. **Wrapped as a minimal HA `custom_component`** with a single switch platform configured via YAML.

## Installation (manual)

1. Copy the `custom_components/ecoplug/` folder into your HA `/config/custom_components/` directory.
2. Add to your `configuration.yaml`:
   ```yaml
   switch:
     - platform: ecoplug
       host: 192.168.0.87      # your plug's LAN IP (reserve it in DHCP!)
       name: Pool Pump
   ```
3. Restart Home Assistant.
4. The switch appears as e.g. `switch.pool_pump` under Settings → Devices & Services → Entities.

Prerequisite: **HA must be on the same L2 LAN as the plug** (or on a VLAN that allows unicast UDP to the plug's IP:1022). Wired HA → Wi-Fi plug works fine because APs forward wired→Wi-Fi unicast normally. Wi-Fi-only HA on the same SSID as the plug also works. Wi-Fi HA on a *different* SSID / VLAN may not.

## Limitations of this implementation (Option B)

- **Single plug only.** The captured payloads are specific to your plug's TXID / obfuscated body. A second plug wouldn't respond to the same packets.
- **No auto-discovery.** You must configure the plug's IP manually (and reserve it in DHCP).
- **If you factory-reset or re-pair the plug**, the body bytes may go stale. Uncertain — the plug might continue to accept them, or might not. If they stop working, re-capture via PCAPdroid and replace the hex strings in `switch.py`.
- **Not packaged for HACS yet.**

See [issue #1](../../issues/1) for the follow-up that would remove all of these limitations by properly decoding the body.

## Repository layout

- `custom_components/ecoplug/` — the HA integration
- `src/ecoplug/` — standalone Python scripts used during development (e.g. `replay_test.py`)
- `notes/` — protocol notes, capture findings
- `captures/` — local pcap files (gitignored; contents contain LAN addresses)

## Credit

Protocol naming + packet layout inspired by the original [`rsnodgrass/pyecoplug`](https://github.com/rsnodgrass/pyecoplug) integration, which handled earlier-firmware variants of these same devices.
