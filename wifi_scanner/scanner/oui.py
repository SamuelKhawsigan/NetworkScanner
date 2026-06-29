"""MAC OUI lookup + MAC address analysis.

Three concerns, kept separable for testing:

1. Pure MAC bit analysis (locally-administered / multicast / OUI prefix) — no
   I/O, works fully offline. This is what flags RANDOMIZED_MAC.
2. Building a local SQLite OUI database from the IEEE registry CSV.
3. Lookups against that DB with an in-memory session cache and an optional
   macvendors.com API fallback (off by default to avoid rate limits).
"""

from __future__ import annotations

import csv
import io
import re
import sqlite3
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .. import config
from .models import Host

_NON_HEX = re.compile(r"[^0-9a-fA-F]")


# --------------------------------------------------------------------------- #
# Pure MAC analysis (offline)
# --------------------------------------------------------------------------- #
def clean_mac_hex(mac: str) -> str:
    """Strip separators, lowercase — 'AA:BB:CC' -> 'aabbcc'."""
    return _NON_HEX.sub("", mac).lower()


def first_octet(mac: str) -> int | None:
    """Integer value of the first octet, or None if the MAC is too short."""
    h = clean_mac_hex(mac)
    return int(h[:2], 16) if len(h) >= 2 else None


def oui_prefix(mac: str) -> str | None:
    """First three octets as a 6-char lowercase hex key, or None."""
    h = clean_mac_hex(mac)
    return h[:6] if len(h) >= 6 else None


def is_locally_administered(mac: str) -> bool:
    """True if the locally-administered bit (0x02 of octet 1) is set.

    Set on randomized / software-assigned MACs; never on real OUI burn-ins.
    """
    octet = first_octet(mac)
    return octet is not None and bool(octet & 0x02)


def is_multicast(mac: str) -> bool:
    """True if the multicast/group bit (0x01 of octet 1) is set."""
    octet = first_octet(mac)
    return octet is not None and bool(octet & 0x01)


@dataclass
class MacInfo:
    """Result of analysing + looking up a MAC."""

    vendor: str | None = None
    randomized: bool = False
    multicast: bool = False
    source: str | None = None            # 'local' | 'api' | None


# --------------------------------------------------------------------------- #
# OUI database build
# --------------------------------------------------------------------------- #
def parse_oui_csv(text: str) -> dict[str, str]:
    """Parse IEEE oui.csv text into {prefix: vendor}.

    Columns: Registry, Assignment, Organization Name, Organization Address.
    """
    mapping: dict[str, str] = {}
    reader = csv.reader(io.StringIO(text))
    next(reader, None)                      # skip header row
    for row in reader:
        if len(row) < 3:
            continue
        prefix = clean_mac_hex(row[1])[:6]
        vendor = row[2].strip()
        if len(prefix) == 6 and vendor:
            mapping[prefix] = vendor
    return mapping


def build_oui_db(db_path, mapping: dict[str, str]) -> int:
    """Write {prefix: vendor} into a fresh SQLite table. Returns row count."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS oui "
            "(prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)"
        )
        conn.execute("DELETE FROM oui")
        conn.executemany(
            "INSERT OR REPLACE INTO oui(prefix, vendor) VALUES (?, ?)",
            mapping.items(),
        )
        conn.commit()
        return conn.execute("SELECT COUNT(*) FROM oui").fetchone()[0]
    finally:
        conn.close()


def download_oui_csv(url: str = config.IEEE_OUI_CSV_URL, timeout: int = 30) -> str:
    """Fetch the IEEE OUI registry CSV."""
    request = urllib.request.Request(url, headers={"User-Agent": "wifi-scanner/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def update_oui_db(
    db_path=config.OUI_DB_PATH, url: str = config.IEEE_OUI_CSV_URL, timeout: int = 30
) -> int:
    """Download the registry and (re)build the local DB. Returns row count."""
    mapping = parse_oui_csv(download_oui_csv(url, timeout))
    return build_oui_db(db_path, mapping)


# --------------------------------------------------------------------------- #
# macvendors.com API fallback
# --------------------------------------------------------------------------- #
def macvendors_fetch(
    mac: str, url: str = config.MACVENDORS_API_URL, timeout: int = 5
) -> str | None:
    """Look up a MAC via the macvendors.com API. Returns vendor or None."""
    request = urllib.request.Request(
        url + mac, headers={"User-Agent": "wifi-scanner/0.1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            vendor = response.read().decode("utf-8", errors="replace").strip()
            return vendor or None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Session lookup
# --------------------------------------------------------------------------- #
class OuiLookup:
    """Vendor lookups with an in-memory cache and optional API fallback."""

    def __init__(
        self,
        db_path=config.OUI_DB_PATH,
        enable_api: bool = False,
        api_fetcher=None,
    ):
        self.db_path = Path(db_path)
        self.enable_api = enable_api
        self._api_fetcher = api_fetcher or macvendors_fetch
        self._cache: dict[str, MacInfo] = {}
        self._conn: sqlite3.Connection | None = None
        if self.db_path.exists():
            # read-only so a scan never mutates the registry DB
            self._conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro", uri=True
            )

    @property
    def has_db(self) -> bool:
        return self._conn is not None

    def _query_local(self, prefix: str) -> str | None:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT vendor FROM oui WHERE prefix = ?", (prefix,)
        ).fetchone()
        return row[0] if row else None

    def lookup(self, mac: str) -> MacInfo:
        """Analyse + resolve a MAC, memoized for the session."""
        key = clean_mac_hex(mac)
        if key in self._cache:
            return self._cache[key]

        info = MacInfo(
            randomized=is_locally_administered(mac),
            multicast=is_multicast(mac),
        )
        prefix = oui_prefix(mac)

        # A locally-administered MAC has no meaningful real vendor.
        if not info.randomized and prefix:
            vendor = self._query_local(prefix)
            if vendor:
                info.vendor, info.source = vendor, "local"
            elif self.enable_api:
                vendor = self._api_fetcher(mac)
                if vendor:
                    info.vendor, info.source = vendor, "api"

        self._cache[key] = info
        return info

    def annotate(self, host: Host) -> MacInfo:
        """Set host.vendor and append RANDOMIZED_MAC where applicable."""
        info = self.lookup(host.mac)
        if info.vendor:
            host.vendor = info.vendor
        if info.randomized and "RANDOMIZED_MAC" not in host.risk_flags:
            host.risk_flags.append("RANDOMIZED_MAC")
        return info

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
