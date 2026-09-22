# walljack

[![CI](https://github.com/Ion-VR/walljack/actions/workflows/ci.yml/badge.svg)](https://github.com/Ion-VR/walljack/actions/workflows/ci.yml)

A small, cross-platform command-line tool that tells you **what switch and port a
network wall jack is wired to**, by listening for the discovery frames the
switch is already sending.

Plug a laptop into a mystery jack, run `walljack`, and it prints the answer as
soon as the switch speaks up, usually in a few seconds:

```
Listening on Intel(R) Ethernet Connection, up to 35s (stops at the first answer, Ctrl+C to give up)...
  found LLDP neighbour: 00:1b:0c:1a:2b:3c / Gi1/0/24

=== LLDP neighbour 1 of 1 ===
  Chassis ID        : 00:1b:0c:1a:2b:3c
  Port ID           : Gi1/0/24
  Port Description  : Uplink to AP-floor3
  System Name       : sw-access-3
  VLAN              : 110
  Management IP     : 10.20.0.5
```

It speaks both [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol)
and [CDP](https://en.wikipedia.org/wiki/Cisco_Discovery_Protocol). That matters
more than it sounds: plenty of access ports, especially in older enterprise and
hospitality estates, run CDP with LLDP switched off. An LLDP-only tool reports
"nothing found" on those jacks, which looks like a broken tool rather than an
absent protocol.

## Install

Grab a binary from [Releases](https://github.com/Ion-VR/walljack/releases), or
build it yourself (see below).

Either way you need a packet capture driver on the host, because reading raw
layer-2 frames is not something an ordinary socket can do:

| OS | Runtime requirement |
|---|---|
| Windows | [Npcap](https://npcap.com/), installed with **"WinPcap API-compatible mode"** ticked |
| Linux | libpcap (`sudo apt install libpcap0.8`), already present on most systems |
| macOS | ships with the OS |

Capture also needs elevated privileges: an **Administrator** terminal on
Windows, or `sudo` on Linux and macOS.

## Usage

```sh
walljack                            # pick an interface, stop at the first answer
walljack -l                         # list interfaces and exit
walljack -i 6                       # skip the picker, using the number from -l
walljack -i eth0                    # ...or the interface name
walljack -i TP-LINK                 # ...or any unambiguous fragment of its description
walljack -d 90s                     # wait longer before giving up
walljack -all                       # listen the whole window, collect every neighbour
walljack -o jacks.csv               # append the result to a CSV file
walljack -o jacks.csv -label "B214" # ...tagged with a room or jack reference
walljack -version
```

`-i` takes whichever of those three is least effort. On Windows the real device
name is a GUID like `\Device\NPF_{C538A4E2-...}`, so the listing number or a
fragment of the description is almost always what you want.

Double-clicking `walljack.exe` in Explorer works too: it opens its own window,
asks which interface to use, and waits for a keypress at the end so the answer
does not vanish.

By default walljack stops the moment it hears a neighbour, so it normally
returns in seconds rather than sitting out the full window. Use `-all` when a
jack might have more than one device behind it, for example a desk phone with a
PC port, or when you want both the LLDP and CDP view of the same switch.

### Surveying a whole floor

The `-o` flag appends one row per neighbour to a CSV, which turns the tool from
a lookup into a documentation exercise. Run it once per jack:

```sh
walljack -i eth0 -o jacks.csv -label "B214-a"
walljack -i eth0 -o jacks.csv -label "B214-b"
walljack -i eth0 -o jacks.csv -label "corridor-2"
```

```csv
timestamp,label,interface,protocol,chassis_id,port_id,port_description,system_name,platform,vlan,management_ip,system_description
2026-09-17T14:02:11+01:00,B214-a,eth0,LLDP,00:1b:0c:1a:2b:3c,Gi1/0/24,Uplink to AP-floor3,sw-access-3,,110,10.20.0.5,
2026-09-17T14:04:52+01:00,B214-b,eth0,CDP,sw-access-3,GigabitEthernet1/0/25,,sw-access-3,cisco WS-C2960X-48FPD-L,110,10.20.0.5,
2026-09-17T14:07:03+01:00,corridor-2,eth0,none,,,,,,,,
```

A jack where nothing answered still gets a row, with `protocol` set to `none`.
A dead or unmanaged jack is a real survey result, and a gap in the sheet cannot
be told apart from a jack you never got round to testing.

### What each field comes from

| Field | LLDP | CDP |
|---|---|---|
| Chassis ID / Device ID | Chassis ID TLV, subtype-aware (MAC, network address, …) | Device ID, usually the hostname |
| Port ID | Port ID TLV | Port ID |
| Port Description | Port Description TLV | not sent |
| System Name | System Name TLV | System Name, falling back to Device ID |
| Platform | not sent | Platform (hardware model) |
| VLAN | IEEE 802.1 org-specific TLV, Port VLAN ID (PVID) | Native VLAN |
| Management IP | Management Address TLV (IPv4/IPv6) | Management Address, falling back to the general Address TLV |
| System Description | System Description TLV | Software Version string |

Blanks are normal. Most of these TLVs are optional and plenty of gear sends only
the mandatory ones.

## Why Go (and not Python + scapy)

A Python + [scapy](https://scapy.net/) version is genuinely faster to prototype.
Scapy already knows the LLDP and CDP TLV layouts, and you can sniff in a few
lines. The reason this project is Go is the *deliverable*, not the protocol work:

| | Go + gopacket | Python + scapy |
|---|---|---|
| Ship to a colleague's laptop | one `walljack.exe`, no runtime | needs Python + scapy + admin to pip-install |
| Cross-compile Win/Linux/macOS | one CI job per OS | per-machine interpreter setup |
| Start-up time | instant | interpreter + import cost |
| Prototyping speed | more boilerplate | very fast |

For a tool meant to live on a USB stick and run on whatever laptop is to hand,
Go wins. (Honest caveat: live capture still needs a packet capture driver on the
host either way, see Install.)

## Build from source

Building needs the capture library's **headers** as well as the runtime, plus a
C toolchain, because `gopacket/pcap` uses cgo:

| OS | Build requirements |
|---|---|
| Windows | [Npcap SDK](https://npcap.com/#download) + MinGW-w64 |
| Linux | `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/Fedora) + `build-essential` |
| macOS | Xcode command line tools |

```sh
go mod tidy
go build -o walljack ./cmd/walljack        # Linux/macOS
go build -o walljack.exe ./cmd/walljack    # Windows
```

On Windows, point cgo at the SDK first:

```pwsh
$env:CGO_CFLAGS  = "-IC:\npcap-sdk\Include"
$env:CGO_LDFLAGS = "-LC:\npcap-sdk\Lib\x64"
```

Cross-compiling between operating systems needs the target's pcap headers and a
cross C toolchain, so the simplest path is to build on each OS. That is exactly
what [the release workflow](.github/workflows/release.yml) does.

## How it works

1. `pcap.FindAllDevs` enumerates interfaces; you pick one, or pass `-i`.
2. The handle is opened in promiscuous mode with a BPF filter of
   `ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc`, so only LLDP frames and
   traffic to the Cisco discovery multicast are delivered. CDP rides inside
   LLC/SNAP and has no ethertype of its own, hence the second clause.
3. Each frame is handed to
   [internal/discovery](internal/discovery), which tries the LLDP decoder and
   then the CDP decoder and flattens whichever matches into one `Neighbor`
   record. The Cisco multicast is shared with VTP, DTP, PAgP and UDLD, so frames
   that are not CDP simply fall through.
4. Neighbours are de-duplicated by protocol + chassis + port. The first one ends
   the capture unless `-all` was given.

## Troubleshooting

**"no capture interfaces found" or a FindAllDevs error.** Npcap or libpcap is
not installed, or you are not running elevated.

**No advertisements seen.** The jack may hang off an unmanaged switch, both
protocols may be disabled on the port, or an intermediate device is consuming
the frames. Try `-d 90s` first: the advertisement interval is usually 30s but it
is configurable, and some gear is set much slower.

**A field shows `(not advertised)`.** That TLV is optional and this switch is
not sending it. It is not an error.

## License

[MIT](LICENSE)
