# thread-cli

An interactive terminal sniffer for a Thread network, in the style of `mdns-cli`. It drives an
OpenThread RCP (e.g. an ESP32-C6 running `ot_rcp`) over spinel as a promiscuous 802.15.4 radio,
decrypts MAC and MLE traffic with the network key, and lists every device it hears with its
MAC (extended) address, RSSI, role, RLOC16, routes, children and IPv6 addresses.

```
thread-cli  3 thread devices  ch 25  PAN 0x1234  MyHome  443 frames, 44 decrypted  sort:rloc      key seq 4
leader router 19, partition 0x1a2b3c4d  mesh-local fd11:2233:4455:6677::/64
────────────────────────────────────────────────────────────────────────────────────────────────────────
▾ 9a:3c:51:e2:d0:7b:44:f1  0x4c00  leader        -84 dBm ▃▃▃▃▄▄▃▃▄▄▄▃    186 fr    2s
      role          leader
      mac (ext)     9a:3c:51:e2:d0:7b:44:f1
      rloc16        0x4c00  router id 19
      rssi          last -84  avg -87.2  min -102  max -80  dBm over 186 frames  ▃▃▃▃▄▃▃▃▄▄▄▄
      mle           Advertisement ×67, Discovery Request ×1; last Advertisement 2s ago
      leader data   partition 0x1a2b3c4d, weighting 65, data version 168/239, leader router 19
      routes        router 19 0x4c00  (self)
      children      0x4c12  sleepy child  -102 dBm
                    0x4c70  sleepy child  -84 dBm
▸ (ext unknown)            0x4c70  sleepy child  -84 dBm ▄▃▃▃▃▃▃▃▃▃▃▃     98 fr    1s
```

## Run

Needs Python ≥ 3.10 with `pyserial` and `cryptography` (both packaged by most distros), and a radio
flashed with the ESP-IDF `ot_rcp` example built for spinel over USB (`sdkconfig.ci.rcp_usb`).

```sh
thread-cli --key 00112233445566778899aabbccddeeff -c 25
thread-cli --dataset 0e080000000000010000000300001935060004001fffe0...   # key, channel, PAN, prefix, name
thread-cli --key-file ~/.config/thread-logger/networkkey -c 25 -w capture.pcap
thread-cli --dataset ... --replay capture.pcap          # offline, from a pcap (TAP or WITHFCS)
thread-cli --dataset ... --json -t 60 | jq '.devices[] | {ext, rloc16, role, rssi}'
```

The port defaults to the only `/dev/serial/by-id/usb-Espressif_USB_JTAG*` device; pass `-u` when
there is more than one. Without a key, frames are still listed (with RSSI) but not decrypted.

The network key comes from, in order: `--key`, `--key-file`, `--dataset`, `$THREAD_NETWORK_KEY`,
then `~/.config/thread-cli/networkkey` or `~/.config/thread-logger/networkkey` if one exists (keep
it `chmod 600`). So with a key file and a config file, plain `thread-cli` is enough.

## Config

`~/.config/thread-cli/config.json` (or `$XDG_CONFIG_HOME/thread-cli/config.json`) holds defaults for
the options and the device names given with `N`:

```json
{
  "port": "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_XX:XX:XX:XX:XX:XX-if00",
  "pan": "0x1234",
  "channel": 25,
  "names": {
    "9a3c51e2d07b44f1": "kitchen sensor"
  }
}
```

Command-line options win over the dataset, which wins over the config. Names are keyed by
extended address, the only identifier that survives a reattach (RLOC16s change), so a device can be
named once its ext address is known. They show in the device list, in parent/route/child lines,
in the filter and the `name` sort, and in `--json` output.

`-w FILE` saves everything to a pcap with 802.15.4 TAP headers (RSSI, LQI, channel), which Wireshark
opens directly; add the key under IEEE 802.15.4 → Decryption Keys with "Thread hash".

## Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `k` `j` | move |
| `PgUp` `PgDn`, `Home` `End` / `g` `G` | page, first, last |
| `Enter`, `Space` | fold open or closed |
| `→` / `l` | fold open, then step through the values on the row |
| `←` / `h` | step back, then fold closed or jump to the parent |
| `e` / `E` | expand all / collapse all |
| `p` | ping the device, or the address picked with right/left; again to stop |
| `c` | copy the value under the cursor (OSC 52, plus wl-copy / xclip / xsel) |
| `N` | name the device (Enter saves, Esc cancels, Ctrl-U clears; an empty name removes it) |
| `T` | tree view: children listed under their parent router (toggle) |
| `s` | cycle sort: rloc, rssi, last seen, frames, name |
| `/` | filter |
| `a` | show / hide devices on other PANs (Zigbee etc. on the same channel) |
| `[` `]` | previous / next channel |
| `Esc` | clear the filter, then quit |
| `?` | key list |
| `q` | quit |

## Ping

Ping runs from this host, not from the radio (the RCP is a passive sniffer), using an unprivileged
ICMPv6 socket, one probe a second with a 12 s timeout for sleepy children. Only addresses routed
off-mesh are reachable: OMR addresses (`fdxx::/64` advertised by the border router, which the host
learns via RA). The mesh-local addresses (ML-EID, RLOC) and link-local addresses are listed but
reachable only from inside the mesh.

OMR addresses are learned from the air: from a child's Address Registration TLV (MLE Child ID /
Child Update Request), and from the source address of traffic a device originates.

## How it works

- `spinel.py`: HDLC-lite framing and the four property sets that turn an RCP into a sniffer
  (`PHY_ENABLED`, `MAC_FILTER_MODE=monitor`, `PHY_CHAN`, `MAC_RAW_STREAM_ENABLED`); received frames
  arrive as `STREAM_RAW` with RSSI/LQI metadata.
- `crypto.py`: Thread key derivation (HMAC-SHA256(network key, key sequence ‖ "Thread") → MLE key ‖
  MAC key) and AES-CCM* with the 13-byte nonce (source ext address ‖ frame counter ‖ level).
- `wpan.py`: 802.15.4 frame parsing (2006 and 2015 frame versions, aux security header, IEs).
- `lowpan.py`: 6LoWPAN mesh/fragment headers, IPHC + NHC (UDP, extension headers, IPv6-in-IPv6) and
  reassembly, producing plain IPv6 packets.
- `mle.py`: MLE decryption (AAD = IPv6 source ‖ destination ‖ aux header) and TLV parsing: Source
  Address, Mode, Leader Data, Route64, Connectivity, Address16, Address Registration, Network Data,
  Version, Timeout, datasets.
- `store.py`: per-device state. Devices are keyed by extended address. A frame with only a short
  source address is decrypted by trying each known device's extended address as the nonce source;
  the one whose MIC verifies identifies the sender. Immediate acks (no source address) are credited
  to the destination of the frame they acknowledge, which gives RSSI for one-way talkers too.

A sleepy child shows as `(ext unknown)` until it sends an MLE message (Child Update Request or Child
ID Request); until then its data polls can be counted and measured but not decrypted. Sleepy children
only send MLE when they attach or change addresses, which can be hours apart, so thread-cli remembers
devices between runs (below).

### Remembered devices

Every device identified in a run (MAC/ext address, last RLOC16, mode, version, timeout, routable
IPv6 addresses) is saved per PAN in `~/.config/thread-cli/devices.json`, every 30 s and on exit,
replays included. In later runs those addresses are tried on encrypted frames from short addresses
the decoder can't place yet (the one last seen on that RLOC16 first), so a child seen in any earlier
run is identified by its first data poll; the MIC only verifies with the right address, so a stale
entry never mislabels a device. Its remembered mode and addresses fill in right away (marked
`remembered`), which gives ping targets before it sends anything. Entries not seen for 90 days are
dropped; `--no-remember` neither reads nor writes the file.

To learn from captures made by other tools, replay them oldest first:

```sh
for f in ~/thread-logs/*.pcap; do thread-cli --replay "$f" --json > /dev/null; done
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests build encrypted MLE and MAC frames from scratch and check the decoder: advertisement
parsing, wrong-key rejection, short-address resolution by trial decryption, ack attribution and
address learning.
