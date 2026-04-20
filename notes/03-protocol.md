# Protocol: phone ↔ plug UDP control

## Transport

- UDP, unicast on the LAN (stays on Wi-Fi; doesn't traverse wired segment).
- Phone binds src port **9090**, sends to plug at **IP:1022**.
- Plug responds from its port **1022** back to phone's 9090.
- Each command is sent **~4 times** (retransmission for reliability).

## Payload layout (152 bytes)

| Bytes | Size | Contents | Notes |
|-------|------|----------|-------|
| 0–3   | 4    | Transaction ID | Random per command; response echoes the same value. Also serves as XOR key for the body. |
| 4–15  | 12   | Header | `17 00 00 00 00 00 00 00 DA E2 0C 00` — constant. |
| 16–71 | 56   | Obfuscated body | XOR'd against TXID repeated. Decoded starts with ASCII `"yvQC"`. Contents still to decode beyond that. |
| 72–75 | 4    | `00 00 00 00` | Padding / marker. |
| 76–79 | 4    | Opcode | `69 00 00 00` in OFF / query commands and all responses. `6A 00 00 00` in ON commands. |
| 80–83 | 4    | State | `00 00 00 00` = off, `01 00 00 00` = on. |
| 84–99 | 16   | Zeros | |
| 100–103 | 4  | Sequence counter | Present only in plug responses. Increments across replies (aa, ab, b2, b6, bd, c2, c3 seen). |
| 104–107 | 4  | `B0 B9 FF FF` | Response-only, constant. |
| 108–111 | 4  | `01 00 00 00` | Response-only. |
| 112–127 | 16 | Device name ASCII | Response-only. Null-padded. Observed: `"Pool Pump\0..."` |
| 128–151 | 24 | Zeros | |

## Observed obfuscation

The "body" (bytes 16–71) XOR'd with `TXID` repeated yields the same plaintext across all phone→plug packets (confirmed via cross-packet XOR: byte-wise difference between two same-type packets matches exactly the difference between their TXIDs, byte 0 by byte 0).

First 4 bytes of decoded body: `0x79 0x76 0x51 0x43` = ASCII `"yvQC"`. Likely a protocol magic / auth hint. Rest of the 56 bytes needs more analysis; may contain a session token, app/device identifier, or checksum.

## Commands observed

### Phone → plug: "turn OFF"
- Opcode `69`, state `00`.
- Body middle contains something specific to OFF (since the phone sends the *correct* obfuscated bytes that XOR-decode to the same plaintext structure regardless of command — structure is encrypted but opcode byte at offset 76 is in plaintext).

### Phone → plug: "turn ON"
- Opcode `6A`, state `01`.

### Plug → phone: state report
- Always opcode `69`. State byte reports current reality.
- Trails a plaintext device-name and a response counter.

## Open questions

1. **Can we replay a captured ON/OFF packet verbatim and get the plug to obey?** If yes → we have control, even without understanding the body obfuscation fully.
2. Does the body contain a nonce or timestamp that the plug validates? If yes, replay fails after the window.
3. Does the plug authenticate the sender (e.g., by MAC, or by something in the body)? If yes, our spoofed packets from HAOS might be rejected.

## Reachability from HAOS

HAOS (wired, 192.168.0.194) can send UDP unicast to plug (Wi-Fi, 192.168.0.87:1022) — the AP forwards wired→Wi-Fi unicast normally. Only Wi-Fi↔Wi-Fi unicast stays inside the AP. So we can run the "HA integration" from HAOS and it will reach the plug.
