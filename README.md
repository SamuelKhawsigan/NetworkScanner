# Office WiFi / LAN Scanner

A professional-grade network reconnaissance tool for authorized IT and security work on corporate LANs. Discovers every live host via ARP, fingerprints each device using SNMP, mDNS, NetBIOS, SMB, UPnP, and HTTP, scores classification confidence, and flags security risks — all in a live rich-terminal dashboard.

## Requirements

- Python 3.10+
- Root / Administrator privileges (scapy needs raw sockets)
- Linux or WSL2 (Windows with mirrored networking mode — see below)

## Installation

```bash
git clone <repo>
cd NetworkScanner/wifi_scanner
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

Or install the `wifi-scan` launcher directly:

```bash
pip install -e NetworkScanner/wifi_scanner
```

## Quick start

```bash
# Full scan of the default office subnet
sudo wifi-scan

# Quick ARP-only sweep (no port scan, ~30s)
sudo wifi-scan --mode quick

# Continuous watch mode — alerts on new/changed devices
sudo wifi-scan --mode watch --interval 60

# Scan a different subnet, export to JSON
sudo wifi-scan --target 192.168.1.0/24 --output json --out-file scan.json
```

## Scan modes

| Mode      | What it does                                              | Typical runtime |
|-----------|-----------------------------------------------------------|-----------------|
| `quick`   | ARP sweep + OUI vendor lookup only                        | ~30s            |
| `full`    | ARP + port scan + all protocol fingerprinting (default)   | 3–5 min         |
| `stealth` | Low packet rate, no SNMP/banners, passive protocols only  | 5–10 min        |
| `watch`   | Continuous re-scan loop, alerts on new/changed devices    | indefinite      |

## CLI reference

```
Usage: wifi-scan [OPTIONS]

Options:
  --target CIDR           Target network(s), comma-separated [default: 10.8.50.0/23]
  --mode [quick|full|stealth|watch]
                          Scan mode [default: full]
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
| `STEALTHY`        | Info     | Responds to ARP but exposes no open ports or signals  |

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

## WSL2 note

ARP scanning requires WSL2 to be in **mirrored networking mode** so it can reach the office LAN's broadcast domain.

Add this to `%USERPROFILE%\.wslconfig` on Windows, then restart WSL:

```ini
[wsl2]
networkingMode=mirrored
```

If ARP returns no results and you're on WSL2, this is almost certainly the cause. The scanner will remind you with a warning at startup and again if the sweep comes back empty.

## Architecture

```
wifi_scanner/
├── main.py               # Entry point, CLI, scan orchestration
├── config.py             # All constants and defaults
├── scanner/
│   ├── arp.py            # ARP discovery engine (scapy)
│   ├── port_scan.py      # Async TCP SYN scanner + banner grabbing
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
└── output/
    ├── json_export.py    # JSON report builder
    └── csv_export.py     # CSV export
```

## Running tests

```bash
cd NetworkScanner
source wifi_scanner/venv/bin/activate
pip install pytest
python -m pytest tests/ -v
```
