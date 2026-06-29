"""Historical device tracking in SQLite (`data/history.db`).

Each scan upserts a row per MAC in `devices` (first/last seen, scan count) and
records change `events` by diffing the current hosts against stored state:

- NEW_DEVICE  — a MAC never seen before (suppressed on the very first scan,
  which only establishes a baseline, and for whitelisted MACs)
- IP_CHANGED  — a known MAC now answers on a different IP
- MAC_CHANGED — an IP previously owned by one MAC is now answered by another

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
    scan_count INTEGER DEFAULT 1
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
        self.conn.commit()

    # -- internal helpers ------------------------------------------------- #
    def _load_state(self):
        rows = self.conn.execute("SELECT * FROM devices").fetchall()
        by_mac = {r["mac"]: r for r in rows}
        ip_to_mac = {r["ip"]: r["mac"] for r in rows if r["ip"]}
        return by_mac, ip_to_mac

    def _insert_event(self, event: HistoryEvent) -> None:
        self.conn.execute(
            "INSERT INTO events(timestamp, event_type, mac, ip, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (event.timestamp, event.event_type, event.mac, event.ip, event.detail),
        )

    def _insert_device(self, host: Host, ts: str) -> None:
        self.conn.execute(
            "INSERT INTO devices(mac, ip, hostname, vendor, device_type, os, "
            "first_seen, last_seen, scan_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (host.mac, host.ip, host.hostname, host.vendor, host.device_type,
             host.os, ts, ts),
        )

    def _update_device(self, host: Host, ts: str) -> None:
        # COALESCE keeps a previously-known value when this scan didn't learn it.
        self.conn.execute(
            "UPDATE devices SET ip = ?, hostname = COALESCE(?, hostname), "
            "vendor = COALESCE(?, vendor), device_type = COALESCE(?, device_type), "
            "os = COALESCE(?, os), last_seen = ?, scan_count = scan_count + 1 "
            "WHERE mac = ?",
            (host.ip, host.hostname, host.vendor, host.device_type, host.os,
             ts, host.mac),
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
        by_mac, ip_to_mac = self._load_state()
        baseline = not by_mac                  # first ever scan -> no NEW_DEVICE
        events: list[HistoryEvent] = []

        def emit(event_type, mac, ip, detail):
            event = HistoryEvent(event_type, mac, ip, detail, ts)
            self._insert_event(event)
            events.append(event)
            return event

        for host in hosts:
            prev_mac_for_ip = ip_to_mac.get(host.ip)
            if prev_mac_for_ip and prev_mac_for_ip != host.mac:
                emit("MAC_CHANGED", host.mac, host.ip,
                     f"IP {host.ip} was {prev_mac_for_ip}, now {host.mac}")
                self._flag(host, "MAC_CHANGED")

            prev = by_mac.get(host.mac)
            if prev is None:
                if not baseline and host.mac not in known_macs:
                    emit("NEW_DEVICE", host.mac, host.ip, f"first seen at {host.ip}")
                    self._flag(host, "NEW_DEVICE")
                self._insert_device(host, ts)
            else:
                if prev["ip"] and prev["ip"] != host.ip:
                    emit("IP_CHANGED", host.mac, host.ip,
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
