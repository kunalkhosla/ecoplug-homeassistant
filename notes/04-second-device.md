# What a second physical plug revealed

`notes/03-protocol.md` was derived from one DEWENWILS HOWT01A. This note records
what changed once a **second, independent** HOWT01A (a different household, a
different timezone, MAC `38:2b:78:1a:2b:3c`) was put through the same analysis.

Short version: the crafting scheme in this repo was right, but three things that
looked universal turned out to be properties of one specific plug.

## 1. The body is per-device, and the plug validates it

The original notes describe the 56-byte body's first word as a `"yvQC"` magic
constant. It is not magic — it is device identity. Probing the second plug with
query packets (opcode `0x69`, so the relay never moves) isolates which half of
the packet is checked:

| packet | result |
|---|---|
| our id + our body | **accepted** |
| our id + this repo's body | ignored |
| our id + this repo's *query* body | ignored |
| our id + all-zero body | ignored |
| our id + `00 01 02 … 37` body | ignored |
| this repo's id + our body | ignored |
| this repo's id + this repo's body | ignored |

Both the 4-byte id at offset 12 and the 56-byte body are validated, and they are
validated **independently**. Neither alone is sufficient.

This is why users other than the repo author have seen the integration silently
do nothing: the crafted packets are well-formed but carry someone else's
identity, and the plug drops them without a reply.

## 2. Which bytes are universal, and which are not

Diffing the two plugs' command bodies: **37 of 56 bytes are identical**, and
**19 differ**, at offsets `0..9`, `23..27`, and `48..51`.

```
word  offset  bytes (second plug, device-specific bytes redacted as xx)
 0     0..3   xx xx xx xx   device
 1     4..7   xx xx xx xx   device
 2     8..11  xx xx 22 26   half device, half universal
 3    12..15  1b 27 33 39   universal
 4    16..19  24 34 44 4c   universal
 5    20..23  1a 79 65 xx   last byte device
 6    24..27  xx xx xx xx   device
 7    28..31  3f 5b 77 85   universal — start of the arithmetic-progression
 8    32..35  48 68 88 98   filler; per-byte deltas +09 +0d +11 +13
 9    36..39  51 75 99 ab
10    40..43  5a 82 aa be
11    44..47  63 8f bb d1
12    48..51  xx xx xx xx   device — does not continue the progression on
                            either plug, so probably a checksum over identity
13    52..55  0d ff e9 e5   universal command tail
```

The two plugs' bodies are withheld here deliberately: on a shared LAN they are
all that stands between a neighbour and your pump. The offsets above are the
reusable finding; a third device can confirm the split without either body being
published.

## 3. The id at offset 12 *is* derivable — the body is not

Offset 12 is the low three bytes of the plug's MAC, little-endian, NUL-padded:

```
MAC 38:2b:78:1a:2b:3c  ->  3c 2b 1a 00
MAC ..:..:..:0c:e2:da  ->  da e2 0c 00   (matches this repo's hardcoded value)
```

So that half needs no capture. The body does, and these routes to deriving it
were tried and **failed**:

- **Not in the heartbeat.** The 272-byte broadcast decrypts cleanly
  (`key = pkt[20:24]`, `P[i] = pkt[i] ^ key[(i-20) % 4]`), but it contains no
  body word, not the device id, and not the MAC in any byte order. Self-
  provisioning from a passive listen is therefore not possible.
- **Not obviously MAC-derived.** With two samples and 19 unknown bytes there is
  no visible transform, and word 12 looks like a checksum over an identity that
  may include a factory serial rather than just the MAC.

A third device would materially help here — if you have one, the offsets in §2
are the thing to check.

## 4. The reply trailer moves between firmware revisions

The reference unit puts the device name at offset 112. The second unit puts it
at **108**, with everything before it shifted by the same 4 bytes:

| field | reference unit | second unit |
|---|---|---|
| state | 80 | 80 |
| unix timestamp (u32 LE) | 100 | 96 |
| timezone offset, seconds (i32 LE) | 104 | 100 |
| device name (NUL-terminated) | 112 | 108 |

Both decode sensibly, which is what confirms the reading: the reference
capture's stamp is `0x69e639aa` = 2026-04-20 14:35 UTC, its capture date, with
tz `-18000` (UTC-5); the second plug reads the present moment with tz `-14400`
(UTC-4). The fields the original notes called a "response counter" and "flags"
are a clock and a timezone.

`PlugReply.parse` now locates the name instead of hardcoding an offset, and
derives the timestamp and timezone relative to it.

**The state byte at 80 does not move**, and it tracks the relay on both units:

```
query  -> reply[80]=0x00   (relay off)
set ON -> reply[80]=0x01
query  -> reply[80]=0x01
set OFF-> reply[80]=0x00
```

So the polling design in `switch.py` is sound on both devices.

## 5. TXID structure is not validated

`03-protocol.md` observed that captured TXIDs end in a constant 2-byte tail
(`2dac` for commands, `e669` for queries) and the crafter reproduces it. The
second plug's app uses a different tail (`ef0b` for both opcodes), and that plug
accepts **fully random** 4-byte TXIDs — 210 of 210 captured packets were
reproduced byte-for-byte, and live commands with `os.urandom(4)` were accepted.

The tail is therefore a per-session artifact, not a protocol rule. It is kept as
an optional `PlugIdentity` field in case some firmware is strict.

## 6. The plug is not local-only

Worth recording, since `03-protocol.md` describes the device as speaking only to
the LAN. While capturing, the second plug was also receiving `0x6a` commands
straight from the vendor cloud (`35.245.74.111` and `74.244.153.166`) arriving at
`:1022` via UDP hole-punch, and it performs DNS lookups through the gateway. It
also runs its own internal schedule — mid-capture it switched itself on with no
app involvement.

Practical consequence for Home Assistant: HA is one of at least three things
driving the relay, so its view can be stale between polls. The 10-second default
is a reasonable compromise; a lower `scan_interval` costs one small datagram.

## How the capture was done without PCAPdroid

The phone and the plug are usually both on Wi-Fi, so their unicast traffic is
bridged inside the access point and never reaches a wired sniffer — which is why
the original recipe needed capture software running on the phone itself.

`src/ecoplug/capture_identity.py` avoids that by answering ARP for the plug's IP
from the Home Assistant host, so the phone addresses its frames to HA at layer 2;
the kernel forwards them on to the real plug, so the plug still actuates and the
app notices nothing. It needs Linux, root, and a LAN you administer — but no
phone tooling, which means it works with an iPhone.
