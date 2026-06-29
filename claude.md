You are rebuilding a professional-grade office WiFi network scanner tool in Python. This is a security/IT operations tool for authorized network reconnaissance on a corporate office LAN.

## Context
- Target network: 10.8.50.0/23 (covers 10.8.50.x and 10.8.51.x)
- Runtime environment: WSL2 on Windows 11, mirrored networking mode (required for ARP access to office LAN)
- User: IT/security role, supervisor-approved authority for network reconnaissance
- Previous version had: ARP scanning, MAC OUI lookup, randomized MAC detection, multi-tier confidence states, passive fingerprinting (NetBIOS, mDNS, SMB, SNMP, UPnP), watch mode with rich.Live, event logging

## Goal
Rebuild this scanner from scratch — cleaner, more capable, better structured. Make it genuinely useful as an IT security tool, not just a prototype.

---

## Architecture Requirements

### Project structure:
wifi_scanner/

├── main.py               # Entry point, CLI arg parsing

├── scanner/

│   ├── init.py

│   ├── arp.py            # ARP discovery engine

│   ├── port_scan.py      # Port scanning module

│   ├── fingerprint.py    # OS/device fingerprinting

│   ├── protocols.py      # NetBIOS, mDNS, SMB, SNMP, UPnP, DHCP probing

│   ├── oui.py            # MAC OUI lookup (local DB + fallback API)

│   ├── classifier.py     # Device type classification engine

│   └── scoring.py        # Confidence scoring system

├── display/

│   ├── init.py

│   ├── live_view.py      # rich.Live real-time dashboard

│   ├── table.py          # Device table rendering

│   └── alerts.py         # Security alert rendering

├── output/

│   ├── init.py

│   ├── json_export.py    # JSON report export

│   ├── csv_export.py     # CSV export

│   └── logger.py         # Event + audit logging

├── data/

│   ├── oui.db            # SQLite OUI database (build from IEEE CSV)

│   └── signatures.json   # Device fingerprint signatures

├── config.py             # All constants, defaults, thresholds

└── requirements.txt

---

## Core Modules — Detailed Requirements

### 1. ARP Discovery Engine (`scanner/arp.py`)
- Use `scapy` for ARP who-has broadcast sweep across target CIDR
- Support multi-subnet scanning (accept list of CIDRs)
- Configurable timeout, retry count, packet rate (throttle for stealth mode)
- Return: IP, MAC, response time (ms), TTL
- Handle ARP cache poisoning detection (same IP, different MAC across sweeps)
- Track first-seen and last-seen timestamps per host

### 2. Port Scanner (`scanner/port_scan.py`)
- TCP SYN scan using scapy (not nmap dependency)
- Scan a smart default port list:
  - Common: 21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 443, 445, 548, 554, 587, 631, 993, 995, 1883, 3306, 3389, 5900, 8080, 8443, 8888, 9100
  - IoT/printer: 9100, 515, 631, 9200
  - Cameras/NVR: 554, 8000, 8080, 37777
  - Smart home: 1883 (MQTT), 5683 (CoAP), 8123
- Configurable: `--ports` flag for custom port list or named profiles (common, full, iot, printer, camera)
- Concurrent scanning with asyncio or ThreadPoolExecutor, rate-limited
- Banner grabbing on open ports (TCP connect + read first 256 bytes)
- Service version detection from banner patterns

### 3. Fingerprinting Engine (`scanner/fingerprint.py`)
Pull together signals from all sources into a unified device profile:

**TTL-based OS hinting:**
- 64 → Linux/Android/macOS
- 128 → Windows
- 255 → Cisco/network gear
- Other values → flag as unusual

**Banner-based fingerprinting:**
- SSH banner → OS/version (e.g., OpenSSH 8.x → Ubuntu 22.04 mapping)
- HTTP Server header → Apache/Nginx/IIS/Python/lighttpd
- HTTP response body patterns → router admin pages, camera UIs, printer pages
- FTP banner → NAS, printer, server
- SNMP sysDescr → richest single field, parse for OS/model/firmware
- UPnP device description XML → manufacturer, model, deviceType
- mDNS/DNS-SD service types → `_airplay._tcp`, `_ipp._tcp`, `_smb._tcp`, `_ssh._tcp`, `_http._tcp`, etc.
- NetBIOS name + workgroup
- SMB OS string + domain

**Combine signals with weighted confidence:**
- Each signal source has a weight (SNMP = high, banner = medium, TTL = low)
- Final fingerprint is best-match with confidence %

### 4. Protocol Probers (`scanner/protocols.py`)

**NetBIOS (UDP 137):**
- Node status request → hostname, workgroup, MAC verification

**mDNS (UDP 5353):**
- Query PTR `_services._dns-sd._udp.local` → enumerate all advertised services
- Resolve each service → hostname, IP, TXT records
- Parse TXT for model info (especially Apple devices, printers)

**SMB (TCP 445):**
- Negotiate protocol → extract OS string, domain, computer name
- No auth required — just negotiate phase

**SNMP (UDP 161):**
- Try community strings: `public`, `private`, `community`, `admin`, `cisco`
- Walk OIDs: sysDescr, sysName, sysLocation, sysContact, ifDescr, ifPhysAddress
- Parse sysDescr for device type, vendor, firmware

**UPnP (UDP 1900 + HTTP):**
- Send M-SEARCH broadcast
- Fetch device description XML from Location header
- Parse: manufacturer, manufacturerURL, modelName, modelNumber, modelDescription, deviceType, friendlyName

**DHCP Fingerprinting (passive, UDP 67/68):**
- Sniff DHCP Discover/Request packets passively
- Extract Option 55 (parameter request list) → map to known fingerprints (dhcp-fingerprint.net style)
- Extract Option 60 (vendor class identifier) → direct vendor hint

**HTTP(S) Probing:**
- GET / on ports 80, 8080, 443, 8443
- Check title tag, server header, common admin page patterns
- Known patterns: `DD-WRT`, `OpenWrt`, `Tomato`, `Cisco IOS`, `HP Jetdirect`, `Hikvision`, `Dahua`, `Ubiquiti`

### 5. OUI Lookup (`scanner/oui.py`)
- Download IEEE OUI CSV on first run → store in SQLite at `data/oui.db`
- Lookup: first 3 octets → vendor name
- Randomized MAC detection: locally administered bit (bit 1 of first octet set) → flag as `RANDOMIZED_MAC`
- Multicast MAC detection
- Cache lookups in memory during session
- Fallback: macvendors.com API if not in local DB

### 6. Device Classifier (`scanner/classifier.py`)
Classification should be multi-layered. Each device gets:
- **Category** (primary): Router, Switch, Access Point, Server, Workstation, Laptop, Mobile, Printer, Camera, NAS, IoT, Smart TV, Unknown
- **Subcategory**: e.g., Workstation → Windows Workstation / Linux Workstation / Mac
- **Vendor** (from OUI + fingerprint)
- **Model** (if detectable)
- **OS** (if detectable)
- **Confidence %**
- **Risk flags** (see below)

Classification logic priority order:
1. SNMP sysDescr match → highest confidence
2. UPnP deviceType + model → high confidence  
3. mDNS service set match → high confidence
4. HTTP admin page pattern → medium-high
5. Open port profile match → medium
6. Banner grab pattern → medium
7. OUI vendor hint → low-medium
8. TTL OS hint → low

Include a signatures file (`data/signatures.json`) with patterns for common devices.

### 7. Confidence Scoring (`scanner/scoring.py`)
Assign each device a confidence score 0–100 based on:
- Number of corroborating signals
- Quality of signals (SNMP > banner > port profile > OUI)
- Conflicting signals reduce score
- Output as: `CONFIRMED (90–100)`, `HIGH (70–89)`, `MEDIUM (50–69)`, `LOW (30–49)`, `UNKNOWN (<30)`

---

## Security Analysis Features

### Risk Flag System
Each device gets a list of risk flags:

| Flag | Trigger |
|------|---------|
| `RANDOMIZED_MAC` | Locally administered MAC bit set |
| `NEW_DEVICE` | First seen in this session, not in historical DB |
| `MAC_CHANGED` | Same IP, different MAC vs last scan |
| `IP_CHANGED` | Same MAC, different IP vs last scan |
| `OPEN_TELNET` | Port 23 open |
| `OPEN_RDP` | Port 3389 open |
| `OPEN_VNC` | Port 5900 open |
| `DEFAULT_SNMP` | Responds to `public`/`private` community |
| `WEAK_CREDS_HINT` | HTTP login page with known default creds pattern |
| `UNUSUAL_TTL` | TTL doesn't match expected for detected OS |
| `NO_HOSTNAME` | No hostname resolvable |
| `STEALTHY` | Responds to ARP but no open ports, no protocol response |
| `ROGUE_AP_HINT` | Device looks like AP but not in known AP list |

---

## Display Requirements (`display/`)

### Live Dashboard (rich.Live)
Full-screen terminal UI during scanning:
╔══════════════════════════════════════════════════════════╗

║  OFFICE NETWORK SCANNER  │  10.8.50.0/23  │  [SCANNING] ║

║  Hosts: 47 found  │  Scan: 2m 14s  │  Updated: 14:32:05 ║

╚══════════════════════════════════════════════════════════╝
[Progress bars for: ARP sweep / Port scan / Fingerprinting]
┌─ DEVICES ──────────────────────────────────────────────┐

│ IP            MAC               Vendor        Type      Hostname         OS              Ports       Conf  Flags     │

│ 10.8.50.1     aa:bb:cc:dd:ee:ff Cisco         Router    gw-office        IOS 15.x        80,443,22   98%   —         │

│ 10.8.50.12    ...               HP            Printer   HP-LaserJet-M    —               9100,631    91%   DEFAULT_SNMP │

│ 10.8.51.44    (random)          RANDOMIZED    Unknown   —                —               —           12%   RANDOMIZED_MAC NEW_DEVICE │

└────────────────────────────────────────────────────────┘
┌─ SECURITY ALERTS ──────────────────────────────────────┐

│ [!] NEW_DEVICE     10.8.51.44  — Unknown device, randomized MAC         │

│ [!] OPEN_TELNET    10.8.50.88  — Telnet open on legacy device            │

│ [!] DEFAULT_SNMP   10.8.50.12  — Responds to 'public' community string  │

└────────────────────────────────────────────────────────┘
┌─ SUMMARY ──────────────────────────────────────────────┐

│ Routers: 2  Switches: 3  APs: 4  Workstations: 18  Printers: 5  Unknown: 8  Flagged: 6 │

└────────────────────────────────────────────────────────┘

- Color-code rows by risk: red = high risk flags, yellow = warnings, green = clean, dim = unknown
- Sortable columns (via `--sort` flag)
- Filter mode (via `--filter type=printer` or `--filter flags=NEW_DEVICE`)

---

## CLI Interface
Usage: python main.py [OPTIONS]
Options:

--target CIDR          Target network(s), comma-separated [default: 10.8.50.0/23]

--mode quick|full|stealth|watch   Scan mode [default: full]

--ports PROFILE        Port profile: common|full|iot|printer|camera|custom

--timeout SECS         ARP timeout per host [default: 2]

--rate PPS             Packets per second [default: 100]

--watch                Enable continuous watch mode (re-scan every N seconds)

--interval SECS        Watch mode re-scan interval [default: 60]

--sort ip|mac|type|conf|flags   Sort output table

--filter EXPR          Filter: type=router, flags=NEW_DEVICE, vendor=cisco

--output json|csv|both   Export results

--out-file PATH        Output file path

--no-ports             Skip port scanning (ARP + fingerprint only)

--no-snmp              Skip SNMP probing

--stealth              Slow rate, no banners, minimal footprint

--known-file PATH      JSON file of known/approved devices (for NEW_DEVICE detection)

--history-db PATH      SQLite DB for historical tracking [default: data/history.db]

--verbose              Verbose logging

--debug                Debug output

### Scan Modes:
- **quick**: ARP only + OUI lookup, no port scan, ~30s
- **full**: ARP + ports + all fingerprinting, ~3–5min
- **stealth**: Slow rate, no SNMP, no banners, only passive protocols
- **watch**: Continuous re-scan, alert on new/changed devices

---

## Historical Tracking (`data/history.db` — SQLite)
Schema:
```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    mac TEXT NOT NULL,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    os TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    scan_count INTEGER DEFAULT 1
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    event_type TEXT,   -- NEW_DEVICE, IP_CHANGED, MAC_CHANGED, etc.
    mac TEXT,
    ip TEXT,
    detail TEXT
);
```
- On each scan: upsert devices, insert events for changes
- `--known-file` can whitelist devices by MAC (suppress NEW_DEVICE flag)

---

## Output / Export

### JSON export schema:
```json
{
  "scan_meta": {
    "timestamp": "...",
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
      "first_seen": "...",
      "last_seen": "...",
      "response_time_ms": 1.2
    }
  ],
  "alerts": [...],
  "summary": {
    "by_type": {"Router": 2, "Workstation": 18, ...},
    "by_risk": {"clean": 39, "flagged": 8}
  }
}
```

---

## Implementation Notes

- Python 3.10+
- Key dependencies: `scapy`, `rich`, `click` (CLI), `aiohttp` (async HTTP probing), `python-nmap` optional fallback, `sqlite3` (stdlib)
- Must run as root/sudo (scapy requires raw sockets) — add a clear check at startup
- WSL2 mirrored networking note: add a check/warning if ARP packets come back empty, suggest mirrored mode
- All network operations should be async where possible (asyncio + scapy's AsyncSniffer)
- Graceful Ctrl+C handling: save partial results, show summary, export if --output set
- Modular: each scanner module should be independently testable
- Add a `--dry-run` mode that shows what would be scanned without sending packets

## Build Order (checkpoints)
1. Project scaffold + config + CLI skeleton
2. ARP engine working, basic rich table output
3. OUI DB build + lookup working
4. Port scanner + banner grabbing
5. Protocol probers (NetBIOS, mDNS, SMB, SNMP, UPnP, HTTP)
6. Fingerprint engine + classifier + scoring
7. Full live dashboard (rich.Live)
8. Historical DB + event tracking
9. JSON/CSV export
10. Watch mode
11. Security alert system
12. --known-file whitelist support
13. Polish: error handling, WSL2 warnings, graceful exit, README

Start with checkpoint 1 and proceed through each. Confirm with me at each checkpoint before continuing.
