"""Checkpoint 8 tests: historical tracking + change events.

Uses in-memory / temp SQLite. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from wifi_scanner.scanner.history import HistoryDB
from wifi_scanner.scanner.models import Host

T0 = datetime(2026, 6, 29, 9, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)
T2 = T0 + timedelta(hours=2)


def host(ip, mac, **kw) -> Host:
    h = Host(ip=ip, mac=mac)
    for k, v in kw.items():
        setattr(h, k, v)
    return h


def icmp_host(ip, **kw) -> Host:
    """An ICMP-discovered host: no MAC ever attempted."""
    h = Host(ip=ip, mac="", mac_known=False, risk_flags=["NO_MAC_ICMP"])
    for k, v in kw.items():
        setattr(h, k, v)
    return h


class TestBaseline(unittest.TestCase):
    def test_first_scan_is_baseline_no_new_device(self):
        db = HistoryDB(":memory:")
        hosts = [host("10.8.50.1", "aa:bb:cc:00:00:01"),
                 host("10.8.50.2", "aa:bb:cc:00:00:02")]
        events = db.record_scan(hosts, now=T0)
        self.assertEqual(events, [])
        self.assertEqual(db.device_count(), 2)
        self.assertFalse(any("NEW_DEVICE" in h.risk_flags for h in hosts))
        db.close()

    def test_scan_count_increments(self):
        db = HistoryDB(":memory:")
        h = host("10.8.50.1", "aa:bb:cc:00:00:01")
        db.record_scan([h], now=T0)
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T1)
        self.assertEqual(db.get_device("aa:bb:cc:00:00:01")["scan_count"], 2)
        db.close()


class TestNewDevice(unittest.TestCase):
    def test_new_device_after_baseline(self):
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T0)
        newcomer = host("10.8.50.5", "aa:bb:cc:00:00:99")
        events = db.record_scan(
            [host("10.8.50.1", "aa:bb:cc:00:00:01"), newcomer], now=T1)
        types = [e.event_type for e in events]
        self.assertEqual(types, ["NEW_DEVICE"])
        self.assertEqual(events[0].mac, "aa:bb:cc:00:00:99")
        self.assertIn("NEW_DEVICE", newcomer.risk_flags)
        db.close()

    def test_known_macs_suppresses_new_device(self):
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T0)
        approved = host("10.8.50.6", "aa:bb:cc:00:00:77")
        events = db.record_scan(
            [approved], now=T1, known_macs={"aa:bb:cc:00:00:77"})
        self.assertEqual(events, [])
        self.assertNotIn("NEW_DEVICE", approved.risk_flags)
        db.close()


class TestIpChanged(unittest.TestCase):
    def test_ip_changed_for_known_mac(self):
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T0)
        moved = host("10.8.50.50", "aa:bb:cc:00:00:01")
        events = db.record_scan([moved], now=T1)
        self.assertEqual([e.event_type for e in events], ["IP_CHANGED"])
        self.assertIn("10.8.50.1 -> 10.8.50.50", events[0].detail)
        self.assertIn("IP_CHANGED", moved.risk_flags)
        db.close()


class TestMacChanged(unittest.TestCase):
    def test_mac_changed_for_same_ip(self):
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T0)
        # Same IP now answered by a different MAC -> possible spoofing.
        impostor = host("10.8.50.1", "de:ad:be:ef:00:99")
        events = db.record_scan([impostor], now=T1)
        kinds = {e.event_type for e in events}
        self.assertIn("MAC_CHANGED", kinds)
        self.assertIn("MAC_CHANGED", impostor.risk_flags)
        db.close()


class TestPersistence(unittest.TestCase):
    def test_survives_reopen_and_preserves_first_seen(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            db = HistoryDB(path)
            db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T0)
            db.close()

            db2 = HistoryDB(path)
            h = host("10.8.50.1", "aa:bb:cc:00:00:01", hostname="gw")
            db2.record_scan([h], now=T2)
            row = db2.get_device("aa:bb:cc:00:00:01")
            self.assertEqual(row["scan_count"], 2)
            self.assertEqual(row["first_seen"], T0.isoformat())
            self.assertEqual(row["hostname"], "gw")        # learned on 2nd scan
            # host's first_seen surfaced from history
            self.assertEqual(h.first_seen, T0)
            db2.close()
        finally:
            os.unlink(path)

    def test_coalesce_keeps_known_hostname(self):
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01", hostname="gw")], now=T0)
        # Second scan didn't resolve a hostname -> keep the old one.
        db.record_scan([host("10.8.50.1", "aa:bb:cc:00:00:01")], now=T1)
        self.assertEqual(db.get_device("aa:bb:cc:00:00:01")["hostname"], "gw")
        db.close()


class TestIcmpIdentityFallback(unittest.TestCase):
    """ICMP-discovered hosts (mac_known=False) have no MAC, so history.py
    falls back to an IP-based identity key for them. See the history.py
    module docstring and README "Discovery methods" for the known DHCP
    tradeoff this implies.
    """

    def test_two_icmp_hosts_same_scan_dont_collide(self):
        db = HistoryDB(":memory:")
        hosts = [icmp_host("10.8.9.20"), icmp_host("10.8.9.21")]
        events = db.record_scan(hosts, now=T0)   # must not raise (UNIQUE mac)
        self.assertEqual(events, [])
        self.assertEqual(db.device_count(), 2)
        db.close()

    def test_icmp_baseline_scan_no_new_device(self):
        db = HistoryDB(":memory:")
        h = icmp_host("10.8.9.20")
        events = db.record_scan([h], now=T0)
        self.assertEqual(events, [])
        self.assertNotIn("NEW_DEVICE", h.risk_flags)
        db.close()

    def test_icmp_host_new_ip_is_new_device_not_ip_changed(self):
        """Known limitation, not a bug: an ICMP identity is IP-shaped, so a
        device that gets a new DHCP lease looks like a brand-new device
        rather than an IP_CHANGED on a known one."""
        db = HistoryDB(":memory:")
        db.record_scan([icmp_host("10.8.9.20")], now=T0)
        moved = icmp_host("10.8.9.55")
        events = db.record_scan([moved], now=T1)
        self.assertEqual([e.event_type for e in events], ["NEW_DEVICE"])
        self.assertIn("NEW_DEVICE", moved.risk_flags)
        db.close()

    def test_arp_then_icmp_same_ip_no_spurious_mac_changed(self):
        """A real MAC seen via ARP, then the same IP seen via an ICMP sweep
        (no MAC), must not fire MAC_CHANGED — that flag means possible
        spoofing, and switching discovery method isn't that."""
        db = HistoryDB(":memory:")
        db.record_scan([host("10.8.9.20", "aa:bb:cc:00:00:01")], now=T0)
        via_icmp = icmp_host("10.8.9.20")
        events = db.record_scan([via_icmp], now=T1)
        kinds = {e.event_type for e in events}
        self.assertNotIn("MAC_CHANGED", kinds)
        self.assertNotIn("MAC_CHANGED", via_icmp.risk_flags)
        db.close()

    def test_icmp_then_arp_same_ip_no_spurious_mac_changed(self):
        """Same as above, reversed order: ICMP first, then a real MAC shows
        up on that IP via ARP — also not a MAC_CHANGED."""
        db = HistoryDB(":memory:")
        db.record_scan([icmp_host("10.8.9.20")], now=T0)
        via_arp = host("10.8.9.20", "aa:bb:cc:00:00:01")
        events = db.record_scan([via_arp], now=T1)
        kinds = {e.event_type for e in events}
        self.assertNotIn("MAC_CHANGED", kinds)
        self.assertNotIn("MAC_CHANGED", via_arp.risk_flags)
        db.close()

    def test_migration_adds_mac_known_column_to_old_db(self):
        """A history.db created before mac_known existed must open and work
        without manual migration."""
        import sqlite3

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE devices (
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
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    timestamp DATETIME,
                    event_type TEXT,
                    mac TEXT,
                    ip TEXT,
                    detail TEXT
                );
            """)
            conn.execute(
                "INSERT INTO devices(mac, ip, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:00:00:01', '10.8.9.1', ?, ?)",
                (T0.isoformat(), T0.isoformat()),
            )
            conn.commit()
            conn.close()

            db = HistoryDB(path)                # must not raise
            row = db.get_device("aa:bb:cc:00:00:01")
            self.assertEqual(row["mac_known"], 1)   # migrated default
            db.record_scan([icmp_host("10.8.9.20")], now=T1)  # must not raise
            db.close()
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
