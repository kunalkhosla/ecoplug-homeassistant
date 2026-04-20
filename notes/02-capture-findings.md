# Findings from capture 02 (with-toggles)

Captured on HAOS `enp1s0` with filter `(net 192.168.0.0/24 and udp) or (host 192.168.0.87)`. 523 packets over ~58 seconds. User confirmed toggling the plug 5–6 times from the ECO Plugs app on their phone, and the plug responded **instantly and physically** every time.

## Actors on LAN 192.168.0.0/24

| IP | Role |
|---|---|
| 192.168.0.87  | The DEWENWILS HOWT01A plug |
| 192.168.0.145 | The user's phone (running ECO Plugs app) |
| 192.168.0.194 | HAOS (our capture point, also LAN DNS resolver) |

## What we see

### Plug (.87)

- Broadcasts 272-byte UDP packets every ~2 sec:
  - `192.168.0.87:10229 → 255.255.255.255:10228`
  - Payload starts with a fixed header: `00 00 00 00 00 55 AA 55 AA 00 "ECO Plugs\0"` (~16 bytes)
  - Remaining ~256 bytes change in every packet → encrypted or obfuscated
- Periodic DNS lookups for `server1.eco-plugs.net` → resolves to `35.245.74.111` (Google Cloud).
- **NEVER seen talking to the cloud IP** (no TCP, no UDP).
- DNS queries from plug go to HAOS (.194:53) — HAOS is acting as the LAN DNS resolver.

### Phone (.145)

- Broadcasts 170-byte UDP packets in bursts on:
  - `:8900 → 255.255.255.255:5888`
  - `:8900 → 255.255.255.255:25`
- Bursts come in groups of ~7 packets, roughly aligned with when the user toggled (times 10.3s, 23.4s, 36.3s, 49.3s in the capture).
- These match the **old pyecoplug discovery protocol** exactly (ports 5888 + 25).
- **The plug never responds** to these discovery broadcasts — it speaks a newer protocol on 10228/10229.

### Missing from capture

- **No unicast phone↔plug traffic observed.** This is the key mystery, solved below.

## Why we see no unicast command packets

HAOS is on Ethernet (`enp1s0`). Plug and phone are both on Wi-Fi. Wi-Fi APs bridge broadcast/multicast onto Ethernet but typically **do not** forward unicast traffic between two Wi-Fi clients of the same BSSID onto the wired segment — it's L2-switched within the AP. So unicast phone→plug packets never traverse `enp1s0` where our tcpdump ran.

This explains:

- Why we see no command packets even though toggles worked instantly.
- Why the plug never talks to cloud — the ECO Plugs app must be controlling it **locally** over Wi-Fi when both are on the same LAN, bypassing the cloud entirely.

## Next capture vantage points to try

1. **Phone-side capture** — PCAPdroid on Android, or `rvictl` on macOS for iOS-tethered capture. Sees exactly what the app is sending.
2. **Mac Wi-Fi monitor mode** — capture 802.11 frames on the IoT SSID, decrypt with WPA2 PSK in Wireshark. Sees phone↔plug directly.
3. **ARP-spoof from HAOS or Mac** — trick phone into sending plug-bound traffic via us. More invasive, captures only the relevant flows.

Priority: phone-side (easiest and cleanest).

## Secondary finding — broadcast payload analysis

The plug's 272-byte heartbeat has ~16 bytes of fixed header and ~256 bytes that differ per packet. If the plug encodes its state in those broadcasts (common pattern), diffing payloads taken just before/after a toggle should reveal which bytes encode on/off. This lets us at least **read** plug state without any crypto work.
