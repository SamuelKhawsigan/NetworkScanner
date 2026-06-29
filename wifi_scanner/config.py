"""Central configuration: constants, defaults, and thresholds.

Everything tunable in the scanner lives here so the rest of the codebase can
import named values instead of hard-coding magic numbers.
"""

from __future__ import annotations

from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_ROOT / "data"
OUI_DB_PATH = DATA_DIR / "oui.db"
HISTORY_DB_PATH = DATA_DIR / "history.db"
SIGNATURES_PATH = DATA_DIR / "signatures.json"

# --------------------------------------------------------------------------- #
# Target / network defaults
# --------------------------------------------------------------------------- #
DEFAULT_TARGET = "10.8.50.0/23"          # covers 10.8.50.x and 10.8.51.x
DEFAULT_ARP_TIMEOUT = 2                   # seconds to wait per ARP sweep
DEFAULT_ARP_RETRIES = 2                   # who-has retransmissions
DEFAULT_RATE_PPS = 100                    # packet rate cap (packets/sec)
STEALTH_RATE_PPS = 10                     # slow rate used in stealth mode

# --------------------------------------------------------------------------- #
# Scan modes
# --------------------------------------------------------------------------- #
MODES = ("quick", "full", "stealth", "watch")
DEFAULT_MODE = "full"
DEFAULT_WATCH_INTERVAL = 60               # seconds between watch re-scans

# --------------------------------------------------------------------------- #
# Port profiles
# --------------------------------------------------------------------------- #
PORTS_COMMON = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 443, 445, 548, 554, 587,
    631, 993, 995, 1883, 3306, 3389, 5900, 8080, 8443, 8888, 9100,
]
PORTS_IOT = [1883, 5683, 8123, 9100, 515, 631, 9200]
PORTS_PRINTER = [515, 631, 9100, 9200, 80, 443]
PORTS_CAMERA = [554, 8000, 8080, 37777, 80, 443]
PORTS_FULL = sorted(set(
    PORTS_COMMON + PORTS_IOT + PORTS_PRINTER + PORTS_CAMERA
    + [111, 135, 389, 636, 1025, 1900, 2049, 3000, 5000, 5060, 5353,
       6379, 7547, 8009, 8081, 8088, 8200, 8291, 9000, 27017, 49152]
))

PORT_PROFILES = {
    "common": PORTS_COMMON,
    "full": PORTS_FULL,
    "iot": PORTS_IOT,
    "printer": PORTS_PRINTER,
    "camera": PORTS_CAMERA,
}
DEFAULT_PORT_PROFILE = "common"

# Concurrency / timeouts for the port scanner
PORT_SCAN_TIMEOUT = 1.0                   # seconds per TCP connect attempt
PORT_SCAN_READ_TIMEOUT = 1.5              # seconds to wait for a banner
PORT_SCAN_CONCURRENCY = 200               # max simultaneous connections
BANNER_BYTES = 256                        # bytes to read for banner grabbing

# Ports where the server stays silent until spoken to — send an HTTP probe.
HTTP_PROBE_PORTS = {80, 8080, 8000, 8008, 8081, 8088, 8888, 8009, 3000, 5000, 7547}

# Well-known port -> short service name (banner-less fallback labelling).
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 515: "printer", 548: "afp",
    554: "rtsp", 587: "smtp", 631: "ipp", 993: "imaps", 995: "pop3s",
    1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5353: "mdns",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9100: "jetdirect", 9200: "elasticsearch",
    27017: "mongodb", 37777: "dahua-dvr",
}

# --------------------------------------------------------------------------- #
# Fingerprinting
# --------------------------------------------------------------------------- #
# TTL -> OS family hinting (low-confidence signal)
TTL_OS_HINTS = {
    64: "Linux/Android/macOS",
    128: "Windows",
    255: "Network gear (Cisco/etc.)",
}

# Relative weight of each fingerprint signal source (higher = more trusted)
SIGNAL_WEIGHTS = {
    "snmp_sysdescr": 40,
    "upnp": 30,
    "mdns": 28,
    "smb": 25,
    "netbios": 20,
    "http_banner": 18,
    "http_body": 18,
    "ssh_banner": 15,
    "ftp_banner": 12,
    "port_profile": 12,
    "oui": 8,
    "ttl": 4,
}

# --------------------------------------------------------------------------- #
# SNMP
# --------------------------------------------------------------------------- #
SNMP_COMMUNITIES = ["public", "private", "community", "admin", "cisco"]
SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
}

# --------------------------------------------------------------------------- #
# OUI lookup
# --------------------------------------------------------------------------- #
IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
MACVENDORS_API_URL = "https://api.macvendors.com/"

# --------------------------------------------------------------------------- #
# Device categories
# --------------------------------------------------------------------------- #
DEVICE_CATEGORIES = (
    "Router", "Switch", "Access Point", "Server", "Workstation", "Laptop",
    "Mobile", "Printer", "Camera", "NAS", "IoT", "Smart TV", "Unknown",
)

# --------------------------------------------------------------------------- #
# Confidence scoring thresholds (score -> label)
# --------------------------------------------------------------------------- #
CONFIDENCE_LABELS = [
    (90, "CONFIRMED"),
    (70, "HIGH"),
    (50, "MEDIUM"),
    (30, "LOW"),
    (0, "UNKNOWN"),
]


def confidence_label(score: int) -> str:
    """Map a 0-100 confidence score to its label."""
    for threshold, label in CONFIDENCE_LABELS:
        if score >= threshold:
            return label
    return "UNKNOWN"


# --------------------------------------------------------------------------- #
# Risk flags (canonical names + human-readable descriptions)
# --------------------------------------------------------------------------- #
RISK_FLAGS = {
    "RANDOMIZED_MAC": "Locally administered (randomized) MAC address",
    "NEW_DEVICE": "First seen this session, not in historical DB",
    "MAC_CHANGED": "Same IP, different MAC vs last scan",
    "IP_CHANGED": "Same MAC, different IP vs last scan",
    "OPEN_TELNET": "Telnet (port 23) open",
    "OPEN_RDP": "RDP (port 3389) open",
    "OPEN_VNC": "VNC (port 5900) open",
    "DEFAULT_SNMP": "Responds to default SNMP community string",
    "WEAK_CREDS_HINT": "HTTP login page with known default-creds pattern",
    "UNUSUAL_TTL": "TTL doesn't match expected for detected OS",
    "NO_HOSTNAME": "No hostname resolvable",
    "STEALTHY": "Responds to ARP but no open ports / protocol response",
    "ROGUE_AP_HINT": "Looks like an AP but not in the known-AP list",
}

# Port -> risk flag mapping for quick lookups
PORT_RISK_FLAGS = {
    23: "OPEN_TELNET",
    3389: "OPEN_RDP",
    5900: "OPEN_VNC",
}

# High-severity flags colour a table row red; any other flag colours it yellow.
# (RANDOMIZED_MAC / NEW_DEVICE / NO_HOSTNAME are informational, not red.)
HIGH_RISK_FLAGS = {
    "OPEN_TELNET", "OPEN_RDP", "OPEN_VNC", "DEFAULT_SNMP",
    "WEAK_CREDS_HINT", "ROGUE_AP_HINT", "MAC_CHANGED",
}

# --------------------------------------------------------------------------- #
# Output / sorting / filtering
# --------------------------------------------------------------------------- #
SORT_KEYS = ("ip", "mac", "type", "conf", "flags")
DEFAULT_SORT = "ip"
OUTPUT_FORMATS = ("json", "csv", "both")
