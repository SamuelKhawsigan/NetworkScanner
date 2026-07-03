# Office WiFi / LAN Scanner

A professional-grade network reconnaissance tool for authorized IT and security work on corporate LANs. It discovers live hosts (ARP for same-subnet MAC-level detail, or ICMP for cross-VLAN reach), scans ports, and fingerprints each device using SNMP, mDNS, NetBIOS, SMB, UPnP, and HTTP. It scores classification confidence, flags security risks, tracks device history across scans, and supports a known-device whitelist — surfaced through either a live rich-terminal dashboard or an optional web dashboard.

## Security

**The web dashboard (`wifi-scan-web`) has NO authentication.** Anyone who can
reach the bound host/port gets full read access to scan results and can
trigger new scans. This is a deliberate, current tradeoff for office-LAN-only
use, not an oversight — but it means:

- Only run it on trusted office-LAN networks.
- Never port-forward it or put it behind an internet-facing reverse proxy.
- If that assumption ever changes (remote access, untrusted network, etc.),
  authentication must be added first.

## Requirements

- Python 3.10+ (tested on 3.12)
- Linux
- **Raw-socket privileges** — root, or the `CAP_NET_RAW` capability. See the
  callout under Installation; this is the single most common deployment
  snag.

### Raw sockets: root / CAP_NET_RAW (read this before deploying)

All discovery (ARP and ICMP) and the TCP/banner probing send raw packets via
scapy, which **requires elevated privileges**. In practice:

- Running with `sudo` (or as root) just works.
- In an **unprivileged container** (LXC/Docker without extra capabilities),
  raw sockets are blocked and scans silently return zero hosts even though
  the network is reachable. Grant the container `CAP_NET_RAW` (and
  `CAP_NET_ADMIN` for some interface operations), or run it privileged.
- To grant the capability to the interpreter instead of using `sudo`:
  `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f venv/bin/python3)`
  — note this must be re-applied if the venv's Python is replaced.

If a scan comes back empty on a network you know is populated, this is almost
always the cause.

## Installation (clean Ubuntu machine or container)

```bash
# 1. System packages
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git libpcap0.8 tcpdump

# 2. Clone
git clone https://github.com/SamuelKhawsigan/NetworkScanner.git
cd NetworkScanner

# 3. Virtualenv + dependencies
python3 -m venv venv
source venv/bin/activate
pip install -e .                         # installs deps + the console scripts
# (equivalently: pip install -r wifi_scanner/requirements.txt)
```

`libpcap0.8` and `tcpdump` back scapy's layer-2 send/receive path; scapy will
run without them via native raw sockets but is more reliable with them
present. `pip install -e .` also installs the `wifi-scan` (CLI) and
`wifi-scan-web` (dashboard) launchers.

The repo also ships `./wifi-scan` and `./wifi-scan-web` wrapper scripts that
invoke the repo-root `venv` directly, so you can run them without activating
the venv first.

## Quick start

```bash
# Full scan of the default subnet (ARP discovery — same-subnet, gives MACs)
sudo ./wifi-scan

# Cross-VLAN discovery via ICMP (routable, IP-only — no MAC)
sudo ./wifi-scan --discovery icmp --target 10.8.0.0/16

# Quick ARP-only sweep (no port scan, ~30s)
sudo ./wifi-scan --mode quick

# Continuous watch mode — alerts on new/changed devices
sudo ./wifi-scan --mode watch --interval 60

# Scan a different subnet, export to JSON
sudo ./wifi-scan --target 192.168.1.0/24 --output json --out-file scan.json
```

## Web dashboard

A single-page web UI (FastAPI + server-sent events) that runs scans on demand,
streams progress live, and shows the device table, security alerts, and
history — with ARP/ICMP discovery selectable per scan.

```bash
# Start it (binds 0.0.0.0:8000 by default — reachable from the office LAN)
sudo ./wifi-scan-web

# Then open http://<this-host-ip>:8000/ in a browser
# Bind to loopback only, or a different port:
sudo ./wifi-scan-web --host 127.0.0.1 --port 8080
```

> **No authentication** — see the [Security](#security) section. Office-LAN
> use only.

## Scan modes

| Mode      | What it does                                              | Typical runtime |
|-----------|-----------------------------------------------------------|-----------------|
| `quick`   | ARP sweep + OUI vendor lookup only                        | ~30s            |
| `full`    | ARP + port scan + all protocol fingerprinting (default)   | 3–5 min         |
| `stealth` | Low packet rate, no SNMP/banners, passive protocols only  | 5–10 min        |
| `watch`   | Continuous re-scan loop, alerts on new/changed devices    | indefinite      |

## Discovery methods (`--discovery`)

Two genuinely different capabilities — pick one, they're not interchangeable:

| Method | Reach | Identity | Trigger |
|--------|-------|----------|---------|
| `arp` (default) | Local broadcast domain only (same subnet/VLAN as this host) | MAC address | `--discovery arp` |
| `icmp` | Routable — reaches hosts on other subnets/VLANs that ARP can't see | **IP only, no MAC** | `--discovery icmp` |

`--discovery icmp` runs an ICMP echo (ping) sweep instead of ARP. It finds
hosts ARP can never see (different VLAN, routed subnet), but every host it
finds is `NO_MAC_ICMP`-flagged and shows `(no MAC — ICMP)` in the MAC column
— OUI vendor lookup, `RANDOMIZED_MAC` detection, and ARP-poison detection are
all skipped for these hosts since none of them are meaningful without a MAC.
Port scanning, protocol fingerprinting, and classification still run
normally (they work over IP).

**History/tracking tradeoff:** device history is normally keyed by MAC. ICMP
hosts have none, so they're tracked by IP instead. On a DHCP network this
means an ICMP-discovered "new" device might just be an existing device that
got handed a new IP — a false-positive `NEW_DEVICE`, not a bug. Treat
`NEW_DEVICE` alerts from ICMP-discovered hosts with that in mind; ARP-sourced
`NEW_DEVICE` alerts (keyed on real MACs) don't have this caveat.

## CLI reference

```
Usage: wifi-scan [OPTIONS]

Options:
  --target CIDR           Target network(s), comma-separated [default: 10.8.9.0/24]
  --mode [quick|full|stealth|watch]
                          Scan mode [default: full]
  --discovery [arp|icmp]  Discovery method: arp (local broadcast domain,
                          gives MAC) or icmp (routable cross-VLAN, IP only —
                          no MAC) [default: arp]
  --ports [common|full|iot|printer|camera]
                          Port profile [default: common]
  --timeout SECS          ARP timeout per sweep [default: 2]
  --rate PPS              Packet rate cap [default: 100]
  --watch                 Enable continuous watch mode
  --interval SECS         Watch re-scan interval [default: 60]
  --sort [ip|mac|type|conf|flags]
                          Sort output table [default: ip]
  --filter EXPR           Filter: type=printer, flags=NEW_DEVICE, vendor=cisco
  --output [json|csv|both]
                          Export results
  --out-file PATH         Output file path (auto-named if omitted)
  --no-ports              Skip port scanning
  --no-snmp               Skip SNMP probing
  --stealth               Slow rate, no banners, minimal footprint
  --known-file PATH       JSON whitelist of approved devices (suppresses NEW_DEVICE)
  --history-db PATH       SQLite DB for historical tracking [default: data/history.db]
  --update-oui            Rebuild the local IEEE OUI vendor database
  --no-live               Disable live dashboard; print static report
  --verbose               Print history events and extra progress detail
  --debug                 Print per-host signal table after classification
  --dry-run               Show the scan plan without sending packets
  -V, --version           Show version and exit
  -h, --help              Show this message and exit
```

## Port profiles

| Profile   | Ports included                                                    |
|-----------|-------------------------------------------------------------------|
| `common`  | Standard services: SSH, HTTP/S, RDP, SMB, FTP, SMTP, VNC, …     |
| `iot`     | MQTT, CoAP, IPP, Jetdirect, Elasticsearch                        |
| `printer` | IPP, Jetdirect, LPD, HTTP/S                                      |
| `camera`  | RTSP, HTTP/S, Dahua DVR                                          |
| `full`    | Everything from all profiles plus additional uncommon ports       |

## Security flags

Each discovered host is annotated with any applicable risk flags:

| Flag              | Severity | Trigger                                               |
|-------------------|----------|-------------------------------------------------------|
| `OPEN_TELNET`     | High     | Port 23 open                                          |
| `OPEN_RDP`        | High     | Port 3389 open (exposed RDP)                          |
| `OPEN_VNC`        | High     | Port 5900 open                                        |
| `DEFAULT_SNMP`    | High     | Responds to `public` or `private` SNMP community      |
| `WEAK_CREDS_HINT` | High     | Login page on device known to ship with default creds |
| `ROGUE_AP_HINT`   | High     | Classified as AP but suspicious (randomized MAC or low confidence) |
| `MAC_CHANGED`     | High     | IP now answered by a different MAC than last scan     |
| `UNUSUAL_TTL`     | Warn     | Observed TTL doesn't match the detected OS family     |
| `NEW_DEVICE`      | Warn     | First-seen MAC, not in history                        |
| `IP_CHANGED`      | Warn     | Known MAC moved to a different IP                     |
| `RANDOMIZED_MAC`  | Info     | Locally administered (randomized) MAC address         |
| `NO_HOSTNAME`     | Info     | No hostname resolvable by any protocol                |
| `STEALTHY`        | Info     | Responds to discovery probe but exposes no open ports or signals |
| `NO_MAC_ICMP`      | Info     | Found via `--discovery icmp` — no MAC was attempted   |

Table rows are colour-coded: **red** = high-severity flag, **yellow** = warning, normal = clean.

## Known-device whitelist (`--known-file`)

Create a JSON file listing approved/expected devices by MAC address. Devices in this list will not trigger `NEW_DEVICE` or `ROGUE_AP_HINT` flags.

**Formats accepted:**

```json
["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
```

```json
[
  {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "gw-office"},
  {"mac": "11:22:33:44:55:66", "hostname": "corp-ap-01"}
]
```

You can also pass a previous scan's JSON export directly — the scanner reads its `devices` array automatically:

```bash
sudo wifi-scan --output json --out-file baseline.json   # first scan
sudo wifi-scan --known-file baseline.json               # subsequent scans
```

## Filtering and sorting

```bash
# Show only printers
sudo wifi-scan --filter type=printer

# Show only flagged devices, sorted by flag
sudo wifi-scan --filter flags=NEW_DEVICE --sort flags

# Show only Cisco devices
sudo wifi-scan --filter vendor=cisco
```

## JSON export schema

```json
{
  "scan_meta": {
    "timestamp": "2026-06-30T09:00:00+00:00",
    "target": "10.8.50.0/23",
    "mode": "full",
    "duration_secs": 142,
    "hosts_found": 47
  },
  "devices": [
    {
      "ip": "10.8.50.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "mac_known": true,
      "vendor": "Cisco Systems",
      "hostname": "gw-office",
      "device_type": "Router",
      "device_subtype": "Enterprise Router",
      "os": "Cisco IOS 15.x",
      "model": null,
      "open_ports": [22, 80, 443],
      "services": {"22": "SSH OpenSSH_8.2", "80": "HTTP", "443": "HTTPS"},
      "fingerprint_sources": ["snmp_sysdescr", "http_banner", "oui"],
      "confidence": 97,
      "confidence_label": "CONFIRMED",
      "risk_flags": [],
      "first_seen": "2026-06-30T09:00:00+00:00",
      "last_seen": "2026-06-30T09:02:22+00:00",
      "response_time_ms": 1.2
    }
  ],
  "alerts": [...],
  "summary": {
    "by_type": {"Router": 2, "Workstation": 18},
    "by_risk": {"clean": 39, "flagged": 8}
  }
}
```

## Historical tracking

The scanner maintains a SQLite database (`data/history.db` by default) across scans. On each run it:

- Upserts every discovered device (first/last seen, scan count)
- Records change events (`NEW_DEVICE`, `IP_CHANGED`, `MAC_CHANGED`)
- Sets risk flags on affected hosts so they surface in the live dashboard

Use `--history-db` to point at a different database, or `--known-file` to whitelist devices that should never appear as `NEW_DEVICE`.

## Known limitations

- **ARP discovery is same-subnet only.** ARP is a layer-2 broadcast protocol,
  so `--discovery arp` only sees hosts in the scanner's own broadcast domain
  (same subnet/VLAN). It cannot reach across a router. Use `--discovery icmp`
  for other subnets/VLANs.
- **ICMP discovery has no MAC**, which weakens identity-based features for
  those hosts: no vendor lookup, no randomized-MAC detection, and rogue/new-
  device detection falls back to IP-based identity. On DHCP networks that
  makes cross-VLAN `NEW_DEVICE` results less reliable (a re-leased IP can look
  like a new device). ICMP-discovered hosts are explicitly marked
  `(no MAC — ICMP)` / `NO_MAC_ICMP` so this is never ambiguous. Hosts that
  block ICMP echo won't appear at all in this mode.
- **The web dashboard has no authentication, by design** (office-LAN-only —
  see [Security](#security)). Anyone who can reach the port can view results
  and start scans. Don't expose it beyond a trusted network.
- **Fingerprinting is best-effort.** Classification and OS/vendor guesses are
  confidence-scored, not authoritative; treat low-confidence rows accordingly.

## Architecture

```
wifi_scanner/
├── main.py               # Entry point, CLI, scan orchestration
├── config.py             # All constants and defaults
├── scanner/
│   ├── arp.py            # ARP discovery engine (scapy, same-subnet, gives MAC)
│   ├── icmp.py           # ICMP echo discovery engine (scapy, routable, IP-only)
│   ├── port_scan.py      # Async TCP connect scanner + banner grabbing
│   ├── protocols.py      # NetBIOS, mDNS, SMB, SNMP, UPnP, HTTP probers
│   ├── oui.py            # MAC → vendor lookup (local SQLite + API fallback)
│   ├── fingerprint.py    # Multi-signal evidence gathering
│   ├── classifier.py     # Category + risk flag assignment
│   ├── scoring.py        # Confidence scoring (0–100)
│   ├── history.py        # SQLite change tracking
│   └── models.py         # Host dataclass
├── display/
│   ├── live_view.py      # rich.Live dashboard
│   ├── table.py          # Device table + summary rendering
│   └── alerts.py         # Security alert panel
├── output/
│   ├── json_export.py    # JSON report builder
│   └── csv_export.py     # CSV export
└── web/
    ├── server.py         # FastAPI app + SSE live updates
    └── dashboard.html    # Single-page web dashboard
```

## Running tests

```bash
cd NetworkScanner
source venv/bin/activate
python -m unittest discover -s tests -v
```
