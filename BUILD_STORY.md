# How this integration was built

> Also published as a blog post: **[Cracking a pool pump's Wi-Fi protocol in an afternoon](https://kunalkhosla.github.io/blogs/2026/04/20/ecoplug-pool-pump.html)**

This integration was reverse-engineered and implemented in a **single ~3-hour session** on 2026-04-20, collaborating with [Claude Code](https://claude.com/claude-code) (Anthropic's CLI coding agent, running as Opus 4.7 with 1M context).

The human — a Home Assistant user with no prior experience reverse-engineering network protocols — drove from their Mac, handled physical access to the plug, and verified each step in the real world. Claude Code did the investigation, packet analysis, cryptanalysis, Python implementation, and deployment scripting over SSH to the HAOS box.

No specialized tools beyond: Wireshark, PCAPdroid on an Android phone, `tcpdump` on the HAOS SSH add-on, and Python's stdlib.

## The journey

### Dead ends (first hour)

1. **Assumed it was Tuya** — these plugs look like rebranded Tuya/Smart Life devices, so the first plan was to use HA's Tuya integration. Wrong: DEWENWILS uses the ECO Plugs app, a completely separate ecosystem.
2. **Tried the existing `pyecoplug` community integration** via HACS — installed fine, but never discovered the plug. The integration hangs startup and produces no switch entity on current HA.
3. **Tried Google Home as a bridge** — ECO Plugs' OAuth linking to Google was broken (completes login but returns no devices to Google).
4. **Looked at Tasmota / ESPHome flashing** — doable (the device has an ESP8266), but requires disassembly and soldering on a 240V outdoor pool-pump box.
5. **Considered replacing the hardware** with a Shelly Pro 2 + definite-purpose contactor. Works long-term but ~$80 and an electrician.

None of the off-the-shelf options worked. We decided to reverse-engineer the protocol ourselves.

### Reverse engineering

**Capture #1 — from HAOS Ethernet, filter `host <plug_ip>`:**
- Plug broadcasts 272-byte UDP packets to `255.255.255.255:10228` every 2 sec. Starts with magic `\x00...\x55\xAA\x55\xAA\x00"ECO Plugs\x00"`.
- Plug resolves `server1.eco-plugs.net` via DNS periodically but **never actually talks to the cloud** during the capture.
- No phone→plug unicast visible.

**Capture #2 — same vantage, wider filter, while toggling from phone:**
- Still no phone→plug unicast on Ethernet.
- Phone (on same IoT Wi-Fi as plug) broadcasting `pyecoplug`-style discovery on ports 25 and 5888. **Plug ignores it** — different protocol version.
- Toggles work physically (user sitting next to the pump) but we can't see the commands.

This is the key insight: **APs do not forward Wi-Fi↔Wi-Fi unicast onto the Ethernet segment**. Phone and plug are both Wi-Fi clients on the same AP, so their unicast stays inside the AP and HAOS (wired) is blind to it. The capture vantage was wrong.

**Capture #3 — from the phone itself, via PCAPdroid (Android):**
- Phone sends 152-byte UDP unicast from `:9090 → plug_ip:1022`.
- Plug replies from `:1022 → phone:9090`.
- Each command is retransmitted ~4 times.

Now we had the command channel.

### Protocol decode

The 152-byte payload structure turned out to be:

| Bytes | Field |
|-------|-------|
| 0–3 | Transaction ID (random per command; response echoes it) |
| 4–15 | Fixed header `17 00 00 00 00 00 00 00 DA E2 0C 00` |
| 16–71 | XOR-obfuscated body (56 bytes) |
| 72–75 | `00 00 00 00` |
| 76–79 | Opcode — `6A` for commands, `69` for queries/replies |
| 80–83 | State — `00` off, `01` on |
| 84+ | Padding / response-only fields |

**The body "encryption" is just XOR with the TXID repeated every 4 bytes.** We figured this out by comparing two same-type packets byte-by-byte: the XOR of their bodies exactly matches the XOR of their TXIDs at positions 0, 4, 8, ... — classic fingerprint of a 4-byte repeating key.

XOR-decoding the body reveals **a fixed 56-byte plaintext across every command packet**, starting with ASCII `"yvQC"` and containing some bytes that look like arithmetic-progression filler. The plug appears to only validate structure, not content — so to craft a new command packet for any TXID, we XOR the known plaintext with the TXID and plug in the opcode + state byte in plaintext.

### The first live test

Rather than immediately trying to craft a fresh packet, we tested with the simplest thing first: **replay a captured OFF command byte-for-byte** against the plug from the HAOS SSH session:

```
python3 /tmp/replay_test.py 192.168.0.87
[OFF replay] sending 152 bytes → 192.168.0.87:1022
[OFF replay] REPLY from ('192.168.0.87', 1022): 152 bytes
  state[80:84] = 00000000
```

Pool pump physically turned off. Replay works — no nonce or timestamp validation.

### The dynamic crafter

Replay works for one plug but not for a general integration. So we built a crafter that takes `(desired_state)` and produces a valid packet with a fresh random TXID. Verified offline by re-building every captured command packet using the captured TXIDs — all 16 matched byte-for-byte.

Live test from the Mac with a never-before-seen TXID (`7cdd2dac`):

```
[OFF] txid=7cdd2dac sending 152 bytes
  reply: txid=7cdd2dac state=OFF
```

Pump off. Then ON with another fresh TXID. Pump on. Dynamic crafting proven.

### Shipping

- `custom_components/ecoplug/protocol.py` — 150-line pure-asyncio module with `craft_command`, `craft_query`, `send_and_wait`.
- `custom_components/ecoplug/switch.py` — thin HA switch-platform wrapper, 10-second poll.
- 8 unit tests including byte-exact reproduction of a captured packet.
- Deployed to `/config/custom_components/ecoplug/` via SSH, restart HA, switch appears and works.
- Tagged v0.2.0 and published as a GitHub release so HACS users can install it as a custom repository.

## Credit

**Investigation, protocol analysis, Python, tests, documentation: [Claude Code](https://claude.com/claude-code) (Opus 4.7)**

**Hardware + physical validation + direction: [Kunal Khosla](https://github.com/kunalkhosla)**

If you own a DEWENWILS / ECO Plugs-family unit and Google Home integration is broken for you too, give this a try. Issues and PRs welcome.
