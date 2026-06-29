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


if __name__ == "__main__":
    unittest.main()
