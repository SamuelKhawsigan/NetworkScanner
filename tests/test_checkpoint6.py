"""Checkpoint 6 tests: fingerprint evidence, classifier, scoring.

Uses the real signatures.json so the JSON itself is validated. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from wifi_scanner.scanner import classifier, fingerprint, scoring
from wifi_scanner.scanner.fingerprint import Evidence
from wifi_scanner.scanner.models import Host
from wifi_scanner.scanner.protocols import HttpInfo, MdnsInfo, SmbInfo, SnmpResult


def host_with(**kw) -> Host:
    h = Host(ip=kw.pop("ip", "10.8.50.1"), mac=kw.pop("mac", "00:11:22:33:44:55"))
    for k, v in kw.items():
        setattr(h, k, v)
    return h


class TestSignaturesLoad(unittest.TestCase):
    def test_signatures_present(self):
        sigs = fingerprint.load_signatures(use_cache=False)
        self.assertTrue(sigs)
        names = {s["name"] for s in sigs}
        self.assertIn("MikroTik RouterOS", names)
        self.assertIn("QNAP NAS", names)


class TestClassifyRealDevices(unittest.TestCase):
    def test_mikrotik_router(self):
        host = host_with(vendor="Routerboard.com", open_ports=[22, 23, 80],
                         hostname="RouterOS")
        host.signals["snmp"] = SnmpResult(sys_descr="RouterOS RB750Gr3", sys_name="gw")
        classifier.classify_host(host)
        self.assertEqual(host.device_type, "Router")
        self.assertEqual(host.os, "RouterOS")
        self.assertEqual(host.vendor, "MikroTik")
        self.assertGreaterEqual(host.confidence, 70)
        self.assertIn(host.confidence_label, ("HIGH", "CONFIRMED"))

    def test_qnap_nas(self):
        host = host_with(ip="10.8.50.73", vendor="QNAP Systems, Inc.",
                         open_ports=[445, 548, 8080], hostname="QNAP-8BAY-KLS")
        host.signals["smb"] = SmbInfo(computer_name="QNAP-8BAY-KLS")
        host.signals["http"] = [HttpInfo(port=8080, server="QNAP", title="QTS")]
        classifier.classify_host(host)
        self.assertEqual(host.device_type, "NAS")
        self.assertEqual(host.vendor, "QNAP")

    def test_printer_by_ports_and_mdns(self):
        host = host_with(open_ports=[9100, 515, 631])
        host.signals["mdns"] = MdnsInfo(services=["_ipp._tcp.local"])
        classifier.classify_host(host)
        self.assertEqual(host.device_type, "Printer")

    def test_camera_by_port(self):
        host = host_with(open_ports=[554, 80], vendor="Hangzhou Hikvision")
        classifier.classify_host(host)
        self.assertEqual(host.device_type, "Camera")

    def test_unknown_phone_low_confidence(self):
        host = host_with(vendor="Intel Corporate")
        classifier.classify_host(host)
        self.assertEqual(host.device_type, "Unknown")
        self.assertLess(host.confidence, 30)
        self.assertEqual(host.confidence_label, "UNKNOWN")


class TestCategoryTieBreak(unittest.TestCase):
    def test_priority_breaks_equal_weight(self):
        # Equal-weight Router vs Camera -> Router wins (higher priority).
        evidence = [
            Evidence("a", 12, category="Camera"),
            Evidence("b", 12, category="Router"),
        ]
        self.assertEqual(classifier._choose_category(evidence), "Router")

    def test_higher_weight_wins(self):
        evidence = [
            Evidence("a", 40, category="Camera"),
            Evidence("b", 12, category="Router"),
        ]
        self.assertEqual(classifier._choose_category(evidence), "Camera")


class TestScoring(unittest.TestCase):
    def test_corroboration_raises_score(self):
        single = [Evidence("snmp_sysdescr", 40, category="Router")]
        triple = single + [
            Evidence("http", 18, category="Router"),
            Evidence("port_profile", 12, category="Router"),
        ]
        self.assertGreater(scoring.score(triple, "Router"),
                           scoring.score(single, "Router"))

    def test_conflict_lowers_score(self):
        clean = [Evidence("snmp_sysdescr", 40, category="Router")]
        conflicted = clean + [Evidence("port_profile", 12, category="Camera")]
        self.assertLess(scoring.score(conflicted, "Router"),
                        scoring.score(clean, "Router"))

    def test_empty_is_zero(self):
        self.assertEqual(scoring.score([], "Router"), 0)

    def test_unknown_with_vendor_is_low_nonzero(self):
        ev = [Evidence("vendor", 8, vendor="Intel")]
        s = scoring.score(ev, "Unknown")
        self.assertGreater(s, 0)
        self.assertLessEqual(s, 40)


class TestProfileFlags(unittest.TestCase):
    def test_no_hostname_flag(self):
        host = host_with(open_ports=[80])
        classifier.classify_host(host)
        self.assertIn("NO_HOSTNAME", host.risk_flags)

    def test_stealthy_for_silent_nonrandomized(self):
        host = host_with(vendor="Intel Corporate")   # no ports, no signals
        classifier.classify_host(host)
        self.assertIn("STEALTHY", host.risk_flags)

    def test_no_stealthy_for_randomized(self):
        host = host_with(mac="4a:da:eb:74:fb:b5", risk_flags=["RANDOMIZED_MAC"])
        classifier.classify_host(host)
        self.assertNotIn("STEALTHY", host.risk_flags)


if __name__ == "__main__":
    unittest.main()
