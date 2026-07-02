"""Historical device tracking in SQLite (`data/history.db`).

Each scan upserts a row per *identity key* in `devices` (first/last seen, scan
count) and records change `events` by diffing the current hosts against
stored state:

- NEW_DEVICE  — an identity never seen before (suppressed on the very first
  scan, which only establishes a baseline, and for whitelisted MACs)
- IP_CHANGED  — a known identity now answers on a different IP
- MAC_CHANGED — an IP previously owned by one MAC is now answered by another

The identity key is the host's MAC when one was attempted (ARP discovery,
`host.mac_known=True`), or `ip:<ip>` when it wasn't (ICMP discovery — see
scanner/icmp.py). The `devices.mac` column holds whichever of those applies;
`mac_known` records which kind it is. This is a real tradeoff, not a bug: on
a DHCP network, an IP-keyed ICMP identity is only as stable as the lease, so
a device getting a new IP looks like a brand-new device (a false-positive
NEW_DEVICE) rather than an IP_CHANGED on an already-known device. See the
README "ICMP discovery" note.

The detected changes are written back onto the hosts as risk flags so they show
up in the table and alerts.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Host

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac TEXT NOT NULL UNIQUE,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    os TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    scan_count INTEGER DEFAULT 1,
    mac_known INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    event_type TEXT,
    mac TEXT,
    ip TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
"""


def _identity_key(host: Host) -> str:
    """MAC when one was attempted, else a synthesized IP-based identity.

    See the module docstring for why this is a deliberate tradeoff for
    ICMP-discovered (mac_known=False) hosts, not a bug.
    """
    return host.mac if host.mac_known else f"ip:{host.ip}"


@dataclass
class HistoryEvent:
    event_type: str
    mac: str
    ip: str
    detail: str
    timestamp: str


class HistoryDB:
    """SQLite-backed device/event history."""

    def __init__(self, db_path):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Additive migration for DBs created before `mac_known` existed —
        CREATE TABLE IF NOT EXISTS in SCHEMA doesn't touch existing tables."""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(devices)")}
        if "mac_known" not in cols:
            self.conn.execute("ALTER TABLE devices ADD COLUMN mac_known INTEGER DEFAULT 1")

    # -- internal helpers ------------------------------------------------- #
    def _load_state(self):
        rows = self.conn.execute("SELECT * FROM devices").fetchall()
        by_identity = {r["mac"]: r for r in rows}
        ip_to_identity = {r["ip"]: r["mac"] for r in rows if r["ip"]}
        return by_identity, ip_to_identity

    def _insert_event(self, event: HistoryEvent) -> None:
        self.conn.execute(
            "INSERT INTO events(timestamp, event_type, mac, ip, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (event.timestamp, event.event_type, event.mac, event.ip, event.detail),
        )

    def _insert_device(self, host: Host, ts: str) -> None:
        self.conn.execute(
            "INSERT INTO devices(mac, ip, hostname, vendor, device_type, os, "
            "first_seen, last_seen, scan_count, mac_known) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (_identity_key(host), host.ip, host.hostname, host.vendor,
             host.device_type, host.os, ts, ts, int(host.mac_known)),
        )

    def _update_device(self, host: Host, ts: str) -> None:
        # COALESCE keeps a previously-known value when this scan didn't learn it.
        self.conn.execute(
            "UPDATE devices SET ip = ?, hostname = COALESCE(?, hostname), "
            "vendor = COALESCE(?, vendor), device_type = COALESCE(?, device_type), "
            "os = COALESCE(?, os), last_seen = ?, scan_count = scan_count + 1, "
            "mac_known = ? WHERE mac = ?",
            (host.ip, host.hostname, host.vendor, host.device_type, host.os,
             ts, int(host.mac_known), _identity_key(host)),
        )

    @staticmethod
    def _flag(host: Host, flag: str) -> None:
        if flag not in host.risk_flags:
            host.risk_flags.append(flag)

    # -- public API ------------------------------------------------------- #
    def record_scan(self, hosts: list[Host], now: datetime | None = None,
                    known_macs: set[str] | None = None) -> list[HistoryEvent]:
        """Diff hosts against history, persist, and return the change events."""
        now = now or datetime.now(timezone.utc)
        ts = now.isoformat()
        known_macs = known_macs or set()
        by_identity, ip_to_identity = self._load_state()
        baseline = not by_identity              # first ever scan -> no NEW_DEVICE
        events: list[HistoryEvent] = []

        def emit(event_type, identity, ip, detail):
            event = HistoryEvent(event_type, identity, ip, detail, ts)
            self._insert_event(event)
            events.append(event)
            return event

        for host in hosts:
            identity = _identity_key(host)
            prev_identity_for_ip = ip_to_identity.get(host.ip)
            prev_row_for_ip = (by_identity.get(prev_identity_for_ip)
                               if prev_identity_for_ip else None)
            prev_was_real_mac = bool(prev_row_for_ip and prev_row_for_ip["mac_known"])
            # Only a real MAC->MAC mismatch counts as MAC_CHANGED. If either
            # side is a synthesized ip:<ip> identity (ICMP discovery), the
            # "change" is just a different discovery method or a missed MAC
            # probe, not evidence of spoofing/replacement.
            if (prev_identity_for_ip and prev_identity_for_ip != identity
                    and host.mac_known and prev_was_real_mac):
                emit("MAC_CHANGED", identity, host.ip,
                     f"IP {host.ip} was {prev_identity_for_ip}, now {identity}")
                self._flag(host, "MAC_CHANGED")

            prev = by_identity.get(identity)
            if prev is None:
                if not baseline and identity not in known_macs:
                    emit("NEW_DEVICE", identity, host.ip, f"first seen at {host.ip}")
                    self._flag(host, "NEW_DEVICE")
                self._insert_device(host, ts)
            else:
                if prev["ip"] and prev["ip"] != host.ip:
                    emit("IP_CHANGED", identity, host.ip,
                         f"{prev['ip']} -> {host.ip}")
                    self._flag(host, "IP_CHANGED")
                # Surface the true first-seen for reporting/export.
                if prev["first_seen"]:
                    try:
                        host.first_seen = datetime.fromisoformat(prev["first_seen"])
                    except ValueError:
                        pass
                self._update_device(host, ts)

        self.conn.commit()
        return events

    def get_device(self, mac: str):
        return self.conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()

    def device_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    def event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def recent_events(self, limit: int = 20):
        return self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def close(self) -> None:
        self.conn.close()
