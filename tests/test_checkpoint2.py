"""Checkpoint 2 tests: ARP engine logic and table rendering.

No packets are sent — the scapy send/receive call is injected as a fake, so
these run unprivileged. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from wifi_scanner.scanner.arp import (
    ArpReply,
    arp_sweep,
    build_hosts,
    normalize_mac,
)
from wifi_scanner.scanner.models import Host
from wifi_scanner.display.table import build_host_table, build_poison_panel

FIXED_NOW = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)


class _FakePkt:
    """Stand-in for a scapy ARP reply / sent packet."""

    def __init__(self, psrc=None, hwsrc=None, time=None, sent_time=None):
        self.psrc = psrc
        self.hwsrc = hwsrc
        self.time = time
        self.sent_time = sent_time


def make_fake_srp(pairs):
    """Return an srp_fn that yields the given (sent, received) answer pairs."""
    def _srp_fn(packet, *, timeout, retry, inter, iface, verbose):
        return pairs, []
    return _srp_fn


class TestNormalizeMac(unittest.TestCase):
    def test_uppercase_to_lower(self):
        self.assertEqual(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")

    def test_dash_to_colon(self):
        self.assertEqual(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")

    def test_strips_whitespace(self):
        self.assertEqual(normalize_mac("  aa:bb:cc:dd:ee:ff "), "aa:bb:cc:dd:ee:ff")


class TestBuildHosts(unittest.TestCase):
    def test_single_reply_becomes_host(self):
        replies = [ArpReply(ip="10.8.50.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.5)]
        hosts, alerts = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(alerts, [])
        h = hosts[0]
        self.assertEqual(h.ip, "10.8.50.1")
        self.assertEqual(h.mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(h.response_time_ms, 1.5)
        self.assertEqual(h.first_seen, FIXED_NOW)
        self.assertEqual(h.last_seen, FIXED_NOW)

    def test_duplicate_ip_keeps_min_rtt(self):
        replies = [
            ArpReply(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01", rtt_ms=5.0),
            ArpReply(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01", rtt_ms=2.0),
        ]
        hosts, alerts = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].response_time_ms, 2.0)
        self.assertEqual(alerts, [])

    def test_poison_detection_same_ip_two_macs(self):
        replies = [
            ArpReply(ip="10.8.50.7", mac="aa:bb:cc:00:00:01"),
            ArpReply(ip="10.8.50.7", mac="aa:bb:cc:00:00:02"),
        ]
        hosts, alerts = build_hosts(replies, now=FIXED_NOW)
        # one host per IP, but a conflict alert raised
        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ip, "10.8.50.7")
        self.assertCountEqual(
            alerts[0].macs, ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
        )

    def test_sorted_numerically_not_lexically(self):
        replies = [
            ArpReply(ip="10.8.50.10", mac="aa:bb:cc:dd:ee:10"),
            ArpReply(ip="10.8.50.2", mac="aa:bb:cc:dd:ee:02"),
            ArpReply(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01"),
        ]
        hosts, _ = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual([h.ip for h in hosts], ["10.8.50.1", "10.8.50.2", "10.8.50.10"])

    def test_empty_input(self):
        hosts, alerts = build_hosts([], now=FIXED_NOW)
        self.assertEqual(hosts, [])
        self.assertEqual(alerts, [])


class TestArpSweep(unittest.TestCase):
    def test_sweep_with_injected_srp(self):
        sent = _FakePkt(sent_time=100.0)
        recv = _FakePkt(psrc="10.8.50.1", hwsrc="AA:BB:CC:DD:EE:01", time=100.0042)
        srp_fn = make_fake_srp([(sent, recv)])
        hosts, alerts = arp_sweep(
            ["10.8.50.0/24"], timeout=1, retries=0, rate_pps=100,
            now=FIXED_NOW, srp_fn=srp_fn,
        )
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "10.8.50.1")
        self.assertEqual(hosts[0].mac, "aa:bb:cc:dd:ee:01")
        # rtt computed from time - sent_time, in ms (~4.2 ms)
        self.assertAlmostEqual(hosts[0].response_time_ms, 4.2, places=1)
        self.assertEqual(alerts, [])

    def test_sweep_handles_missing_timing(self):
        sent = _FakePkt()                       # no sent_time -> rtt None
        recv = _FakePkt(psrc="10.8.50.5", hwsrc="aa:bb:cc:dd:ee:05")
        hosts, _ = arp_sweep(
            ["10.8.50.0/24"], srp_fn=make_fake_srp([(sent, recv)]), now=FIXED_NOW,
        )
        self.assertEqual(len(hosts), 1)
        self.assertIsNone(hosts[0].response_time_ms)

    def test_sweep_empty_answers(self):
        hosts, alerts = arp_sweep(
            ["10.8.50.0/24"], srp_fn=make_fake_srp([]), now=FIXED_NOW,
        )
        self.assertEqual(hosts, [])
        self.assertEqual(alerts, [])


class TestTableRendering(unittest.TestCase):
    def test_host_table_smoke(self):
        hosts = [Host(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01", response_time_ms=1.2)]
        table = build_host_table(hosts)
        self.assertEqual(table.row_count, 1)
        self.assertEqual(len(table.columns), 11)

    def test_host_table_flagged_row(self):
        h = Host(ip="10.8.50.9", mac="aa:bb:cc:dd:ee:09", risk_flags=["OPEN_TELNET"])
        table = build_host_table([h])
        self.assertEqual(table.row_count, 1)

    def test_icmp_host_mac_column_marked_not_blank(self):
        # mac_known=False must render as an explicit marker, never as a
        # blank cell indistinguishable from "MAC lookup failed".
        from rich.console import Console
        h = Host(ip="10.8.9.20", mac="", mac_known=False, risk_flags=["NO_MAC_ICMP"])
        console = Console(width=120, record=True)
        console.print(build_host_table([h]))
        out = console.export_text()
        self.assertIn("no MAC", out)
        self.assertIn("ICMP", out)

    def test_arp_host_mac_column_unaffected(self):
        h = Host(ip="10.8.50.9", mac="aa:bb:cc:dd:ee:09")
        from rich.console import Console
        console = Console(width=120, record=True)
        console.print(build_host_table([h]))
        out = console.export_text()
        self.assertIn("aa:bb:cc:dd:ee:09", out)
        self.assertNotIn("no MAC", out)

    def test_poison_panel_smoke(self):
        from wifi_scanner.scanner.models import PoisonAlert
        panel = build_poison_panel([PoisonAlert(ip="10.8.50.7", macs=["a", "b"])])
        self.assertEqual(panel.row_count, 1)

    def test_mac_with_emoji_shortcode_not_substituted(self):
        # Regression: ":cd:" / ":ab:" inside a MAC must not become emoji.
        from rich.console import Console
        h = Host(ip="10.8.51.5", mac="c2:60:07:cd:e2:86")
        console = Console(file=None, width=120, record=True)
        console.print(build_host_table([h]))
        out = console.export_text()
        self.assertIn("c2:60:07:cd:e2:86", out)
        self.assertNotIn("💿", out)

    def test_hostname_markup_not_interpreted(self):
        # Device-supplied hostname containing rich markup must render literally.
        from rich.console import Console
        h = Host(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01", hostname="[red]evil[/]")
        console = Console(width=120, record=True)
        console.print(build_host_table([h]))
        out = console.export_text()
        self.assertIn("[red]evil[/]", out)


if __name__ == "__main__":
    unittest.main()
