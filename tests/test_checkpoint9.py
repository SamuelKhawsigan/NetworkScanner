"""Checkpoint 9 tests: JSON/CSV export + report building.

Run with: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

from wifi_scanner.display.alerts import collect_alerts
from wifi_scanner.output import csv_export, json_export
from wifi_scanner.main import _out_path
from wifi_scanner.scanner.models import Host

TS = datetime(2026, 6, 29, 14, 32, 5, tzinfo=timezone.utc)


def sample_hosts() -> list[Host]:
    gw = Host(ip="10.8.50.1", mac="78:9a:18:be:5c:41", vendor="MikroTik",
              hostname="gw-office", device_type="Router", device_subtype="MikroTik Router",
              os="RouterOS", open_ports=[22, 23, 80], confidence=86,
              confidence_label="HIGH", risk_flags=["OPEN_TELNET"],
              first_seen=TS, last_seen=TS, response_time_ms=4.4,
              fingerprint_sources=["snmp_sysdescr"])
    gw.services = {22: "SSH", 80: "HTTP"}
    phone = Host(ip="10.8.50.9", mac="d6:8e:d3:a9:b6:ef", device_type="Unknown",
                 confidence=0, confidence_label="UNKNOWN",
                 risk_flags=["RANDOMIZED_MAC", "NO_HOSTNAME"], response_time_ms=79.0)
    return [gw, phone]


class TestHostToDict(unittest.TestCase):
    def test_has_all_spec_keys(self):
        d = json_export.host_to_dict(sample_hosts()[0])
        for key in ("ip", "mac", "vendor", "hostname", "device_type",
                    "device_subtype", "os", "model", "open_ports", "services",
                    "fingerprint_sources", "confidence", "confidence_label",
                    "risk_flags", "first_seen", "last_seen", "response_time_ms"):
            self.assertIn(key, d)

    def test_services_keys_are_strings(self):
        d = json_export.host_to_dict(sample_hosts()[0])
        self.assertEqual(d["services"], {"22": "SSH", "80": "HTTP"})

    def test_first_seen_iso(self):
        d = json_export.host_to_dict(sample_hosts()[0])
        self.assertEqual(d["first_seen"], TS.isoformat())

    def test_mac_known_true_for_arp_host(self):
        d = json_export.host_to_dict(sample_hosts()[0])
        self.assertTrue(d["mac_known"])

    def test_mac_known_false_for_icmp_host(self):
        h = Host(ip="10.8.9.20", mac="", mac_known=False, risk_flags=["NO_MAC_ICMP"])
        d = json_export.host_to_dict(h)
        self.assertFalse(d["mac_known"])
        self.assertEqual(d["mac"], "")


class TestBuildReport(unittest.TestCase):
    def setUp(self):
        hosts = sample_hosts()
        self.report = json_export.build_report(
            hosts, target="10.8.50.0/23", mode="full", duration_secs=142.4,
            timestamp=TS, alerts=collect_alerts(hosts))

    def test_scan_meta(self):
        meta = self.report["scan_meta"]
        self.assertEqual(meta["target"], "10.8.50.0/23")
        self.assertEqual(meta["mode"], "full")
        self.assertEqual(meta["hosts_found"], 2)
        self.assertEqual(meta["duration_secs"], 142.4)
        self.assertEqual(meta["timestamp"], TS.isoformat())

    def test_devices_and_alerts(self):
        self.assertEqual(len(self.report["devices"]), 2)
        flags = {a["flag"] for a in self.report["alerts"]}
        self.assertIn("OPEN_TELNET", flags)
        self.assertNotIn("RANDOMIZED_MAC", flags)     # noise excluded

    def test_summary_by_type_and_risk(self):
        summary = self.report["summary"]
        self.assertEqual(summary["by_type"], {"Router": 1, "Unknown": 1})
        # Router is flagged (OPEN_TELNET); phone has only noise flags -> clean
        self.assertEqual(summary["by_risk"], {"clean": 1, "flagged": 1})


class TestJsonExport(unittest.TestCase):
    def test_roundtrip(self):
        hosts = sample_hosts()
        report = json_export.build_report(
            hosts, target="t", mode="full", duration_secs=1.0, timestamp=TS)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            json_export.export_json(report, path)
            with open(path, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["scan_meta"]["hosts_found"], 2)
            self.assertEqual(loaded["devices"][0]["device_type"], "Router")
        finally:
            os.unlink(path)


class TestCsvExport(unittest.TestCase):
    def test_csv_header_and_rows(self):
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            csv_export.export_csv(sample_hosts(), path)
            with open(path, encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["ip"], "10.8.50.1")
            self.assertEqual(rows[0]["open_ports"], "22;23;80")
            self.assertEqual(rows[0]["risk_flags"], "OPEN_TELNET")
            self.assertIn("22:SSH", rows[0]["services"])
            self.assertEqual(rows[0]["mac_known"], "True")
        finally:
            os.unlink(path)


class TestOutPath(unittest.TestCase):
    def test_default_when_no_base(self):
        self.assertEqual(_out_path(None, "scan_x", "json"), "scan_x.json")

    def test_base_without_extension(self):
        self.assertEqual(_out_path("report", "scan_x", "json"), "report.json")

    def test_base_with_matching_extension(self):
        self.assertEqual(_out_path("report.json", "scan_x", "json"), "report.json")

    def test_base_extension_swapped_for_format(self):
        self.assertEqual(_out_path("report.json", "scan_x", "csv"), "report.csv")


if __name__ == "__main__":
    unittest.main()
