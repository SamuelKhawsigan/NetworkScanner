"""Checkpoint 12 tests: --known-file whitelist support.

Covers:
- load_known_macs parses MAC-list, device-object-list, and scan-export formats
- Malformed / missing files produce an empty set (no crash)
- NEW_DEVICE is suppressed for whitelisted MACs
- ROGUE_AP_HINT is suppressed for whitelisted MACs
- Non-whitelisted MACs still get flagged normally
- Case-insensitive MAC comparison

Run with:
    python -m pytest tests/test_checkpoint12.py -v
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from wifi_scanner.main import load_known_macs, _suppress_known_flags
from wifi_scanner.scanner.history import HistoryDB
from wifi_scanner.scanner.models import Host

T0 = datetime(2026, 6, 30, 9, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)


def _console():
    c = MagicMock()
    c.print = MagicMock()
    return c


def _write_json(data) -> str:
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, fh)
    fh.close()
    return fh.name


def host(ip, mac, **kw) -> Host:
    h = Host(ip=ip, mac=mac)
    for k, v in kw.items():
        setattr(h, k, v)
    return h


class TestLoadKnownMacs(unittest.TestCase):
    def tearDown(self):
        for attr in ("_path",):
            path = getattr(self, attr, None)
            if path and os.path.exists(path):
                os.unlink(path)

    def test_mac_string_list(self):
        path = _write_json(["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"])
        macs = load_known_macs(path, _console())
        self.assertIn("aa:bb:cc:dd:ee:ff", macs)
        self.assertIn("11:22:33:44:55:66", macs)
        self.assertEqual(len(macs), 2)
        os.unlink(path)

    def test_device_object_list(self):
        path = _write_json([
            {"mac": "AA:BB:CC:DD:EE:FF", "hostname": "gw"},
            {"mac": "11:22:33:44:55:66", "hostname": "printer"},
        ])
        macs = load_known_macs(path, _console())
        self.assertIn("aa:bb:cc:dd:ee:ff", macs)
        self.assertIn("11:22:33:44:55:66", macs)
        os.unlink(path)

    def test_scan_export_format(self):
        path = _write_json({
            "scan_meta": {"target": "10.8.50.0/23"},
            "devices": [
                {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.8.50.1"},
                {"mac": "11:22:33:44:55:66", "ip": "10.8.50.2"},
            ],
        })
        macs = load_known_macs(path, _console())
        self.assertIn("aa:bb:cc:dd:ee:ff", macs)
        self.assertIn("11:22:33:44:55:66", macs)
        os.unlink(path)

    def test_case_insensitive(self):
        path = _write_json(["AA:BB:CC:DD:EE:FF"])
        macs = load_known_macs(path, _console())
        self.assertIn("aa:bb:cc:dd:ee:ff", macs)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", macs)
        os.unlink(path)

    def test_missing_file_returns_empty(self):
        macs = load_known_macs("/nonexistent/path.json", _console())
        self.assertEqual(macs, set())

    def test_malformed_json_returns_empty(self):
        fh = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        fh.write("not valid json{{{")
        fh.close()
        macs = load_known_macs(fh.name, _console())
        self.assertEqual(macs, set())
        os.unlink(fh.name)

    def test_empty_devices_list_warns(self):
        path = _write_json([])
        console = _console()
        macs = load_known_macs(path, console)
        self.assertEqual(macs, set())
        console.print.assert_called()
        os.unlink(path)


class TestSuppressKnownFlags(unittest.TestCase):
    def test_new_device_suppressed_for_known_mac(self):
        h = host("10.8.50.10", "aa:bb:cc:dd:ee:ff",
                  risk_flags=["NEW_DEVICE", "NO_HOSTNAME"])
        _suppress_known_flags([h], {"aa:bb:cc:dd:ee:ff"})
        self.assertNotIn("NEW_DEVICE", h.risk_flags)
        self.assertIn("NO_HOSTNAME", h.risk_flags)

    def test_rogue_ap_hint_suppressed_for_known_mac(self):
        h = host("10.8.50.11", "aa:bb:cc:00:00:01",
                  risk_flags=["ROGUE_AP_HINT", "RANDOMIZED_MAC"])
        _suppress_known_flags([h], {"aa:bb:cc:00:00:01"})
        self.assertNotIn("ROGUE_AP_HINT", h.risk_flags)
        self.assertIn("RANDOMIZED_MAC", h.risk_flags)

    def test_unknown_mac_not_affected(self):
        h = host("10.8.50.12", "ff:ee:dd:cc:bb:aa",
                  risk_flags=["NEW_DEVICE"])
        _suppress_known_flags([h], {"aa:bb:cc:dd:ee:ff"})
        self.assertIn("NEW_DEVICE", h.risk_flags)

    def test_case_insensitive_match(self):
        h = host("10.8.50.13", "AA:BB:CC:DD:EE:FF",
                  risk_flags=["NEW_DEVICE"])
        _suppress_known_flags([h], {"aa:bb:cc:dd:ee:ff"})
        self.assertNotIn("NEW_DEVICE", h.risk_flags)

    def test_empty_known_set_is_noop(self):
        h = host("10.8.50.14", "aa:bb:cc:dd:ee:ff",
                  risk_flags=["NEW_DEVICE"])
        _suppress_known_flags([h], set())
        self.assertIn("NEW_DEVICE", h.risk_flags)


class TestKnownMacsWithHistory(unittest.TestCase):
    """Integration: known MACs suppress NEW_DEVICE in record_scan."""

    def test_whitelisted_mac_skips_new_device_flag(self):
        db = HistoryDB(":memory:")
        approved = host("10.8.50.20", "aa:bb:cc:00:00:77")
        # First scan establishes baseline.
        db.record_scan([approved], now=T0, known_macs={"aa:bb:cc:00:00:77"})

        # Wipe and re-scan — same MAC was never seen after reset, but it's known.
        db2 = HistoryDB(":memory:")
        events = db2.record_scan([approved], now=T1, known_macs={"aa:bb:cc:00:00:77"})
        self.assertFalse(any(e.event_type == "NEW_DEVICE" for e in events))
        self.assertNotIn("NEW_DEVICE", approved.risk_flags)
        db.close()
        db2.close()

    def test_non_whitelisted_mac_still_flagged(self):
        db = HistoryDB(":memory:")
        stranger = host("10.8.50.21", "de:ad:be:ef:00:01")
        # Baseline with a different device so stranger is treated as new.
        seed = host("10.8.50.1", "00:11:22:33:44:55")
        db.record_scan([seed], now=T0)
        events = db.record_scan([stranger], now=T1, known_macs={"aa:bb:cc:dd:ee:ff"})
        self.assertTrue(any(e.event_type == "NEW_DEVICE" for e in events))
        self.assertIn("NEW_DEVICE", stranger.risk_flags)
        db.close()


if __name__ == "__main__":
    unittest.main()
