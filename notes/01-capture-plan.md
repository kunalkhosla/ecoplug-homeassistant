# Capture plan

## Hypotheses to resolve

1. **Does the plug speak a local protocol at all?** (LAN UDP/TCP with the phone app)
   Or does the phone only ever talk to the ECO Plugs cloud, which then relays to the plug?
2. **If local, what port/protocol/payload?**
3. **If only cloud-relayed, is the plug→cloud connection persistent TLS?**
   (If yes, local-control reverse engineering is very likely not feasible — we'd pivot to flashing.)

## Environment

- Plug: DEWENWILS HOWT01A, 192.168.0.87 (IoT Wi-Fi)
- HAOS: 192.168.0.194 on `enp1s0` (same LAN as plug) — our capture point
- Phone: moving from main Wi-Fi → IoT Wi-Fi for this test

## Capture procedure

1. **On HAOS** (via SSH add-on), run:
   ```
   tcpdump -i enp1s0 -w /tmp/ecoplug-all.pcap host 192.168.0.87
   ```
2. **On phone**: open ECO Plugs app, tap the plug on/off several times with ~5s between toggles.
3. **Stop tcpdump** (Ctrl+C on HAOS).
4. **Transfer the pcap** to Mac for analysis (scp or samba).

## Analysis goals

- Identify peer IPs the plug talks to: LAN (phone) vs WAN (cloud servers).
- Count packets per destination to gauge cloud vs local chatter.
- If local packets exist: decode protocol.
- If only cloud: note outbound cloud IPs/ports, assess TLS.
