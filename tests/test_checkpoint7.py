"""Checkpoint 7 tests: sorting, filtering, summary, alerts, dashboard render.

The live dashboard is exercised by building its renderable (no real Live
session). Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from rich.console import Console

from wifi_scanner.display.alerts import collect_alerts, build_alerts_panel
from wifi_scanner.display.live_view import LiveDashboard, StaticReporter
from wifi_scanner.display.table import (
    build_summary, filter_hosts, sort_hosts,
)
from wifi_scanner.scanner.models import Host


def mkhost(ip, **kw) -> Host:
    h = Host(ip=ip, mac=kw.pop("mac", "00:11:22:33:44:55"))
    for k, v in kw.items():
        setattr(h, k, v)
    return h


HOSTS = [
    mkhost("10.8.50.10", device_type="Printer", vendor="HP", confidence=62,
           risk_flags=["NO_HOSTNAME"]),
    mkhost("10.8.50.1", device_type="Router", vendor="MikroTik", confidence=86,
           risk_flags=["OPEN_TELNET"]),
    mkhost("10.8.50.2", device_type="Unknown", confidence=0,
           risk_flags=["RANDOMIZED_MAC", "NO_HOSTNAME"]),
]


class TestSort(unittest.TestCase):
    def test_sort_ip_numeric(self):
        order = [h.ip for h in sort_hosts(HOSTS, "ip")]
        self.assertEqual(order, ["10.8.50.1", "10.8.50.2", "10.8.50.10"])

    def test_sort_conf_desc(self):
        order = [h.confidence for h in sort_hosts(HOSTS, "conf")]
        self.assertEqual(order, [86, 62, 0])

    def test_sort_flags_high_first(self):
        # OPEN_TELNET (high severity) should rank first.
        self.assertEqual(sort_hosts(HOSTS, "flags")[0].ip, "10.8.50.1")

    def test_sort_type(self):
        order = [h.device_type for h in sort_hosts(HOSTS, "type")]
        self.assertEqual(order, ["Printer", "Router", "Unknown"])


class TestFilter(unittest.TestCase):
    def test_filter_type(self):
        out = filter_hosts(HOSTS, {"type": "printer"})
        self.assertEqual([h.ip for h in out], ["10.8.50.10"])

    def test_filter_flag(self):
        out = filter_hosts(HOSTS, {"flags": "open_telnet"})
        self.assertEqual([h.ip for h in out], ["10.8.50.1"])

    def test_filter_vendor(self):
        out = filter_hosts(HOSTS, {"vendor": "mikrotik"})
        self.assertEqual([h.ip for h in out], ["10.8.50.1"])

    def test_filter_and_semantics(self):
        out = filter_hosts(HOSTS, {"type": "unknown", "flags": "randomized_mac"})
        self.assertEqual([h.ip for h in out], ["10.8.50.2"])

    def test_filter_no_match(self):
        self.assertEqual(filter_hosts(HOSTS, {"type": "camera"}), [])


class TestSummary(unittest.TestCase):
    def test_summary_renders(self):
        panel = build_summary(HOSTS)
        out = Console(width=100, record=True)
        out.print(panel)
        text = out.export_text()
        self.assertIn("Router: 1", text)
        self.assertIn("Flagged: 1", text)        # only OPEN_TELNET counts


class TestAlerts(unittest.TestCase):
    def test_collect_excludes_noise(self):
        alerts = collect_alerts(HOSTS)
        flags = {a.flag for a in alerts}
        self.assertIn("OPEN_TELNET", flags)
        self.assertNotIn("RANDOMIZED_MAC", flags)
        self.assertNotIn("NO_HOSTNAME", flags)

    def test_high_severity_sorts_first(self):
        hosts = [
            mkhost("10.8.50.5", risk_flags=["STEALTHY"]),       # warn
            mkhost("10.8.50.6", risk_flags=["OPEN_RDP"]),       # high
        ]
        alerts = collect_alerts(hosts)
        self.assertEqual(alerts[0].severity, "high")

    def test_empty_panel_is_green(self):
        panel = build_alerts_panel([])
        out = Console(width=80, record=True)
        out.print(panel)
        self.assertIn("No security alerts", out.export_text())


class TestReporters(unittest.TestCase):
    def _cfg(self):
        return SimpleNamespace(targets=["10.8.50.0/24"], filters={}, sort="ip")

    def test_static_reporter_is_noop_safe(self):
        rep = StaticReporter(self._cfg(), Console(file=None))
        with rep:
            rep.phase("ARP", "arp", 1)
            rep.advance("arp")
            rep.finish("arp")
            rep.set_hosts(HOSTS)
        self.assertEqual(rep.hosts, HOSTS)

    def test_live_dashboard_renders_without_session(self):
        dash = LiveDashboard(self._cfg(), Console(width=120, record=True))
        dash.set_hosts(HOSTS)
        dash.phase("Port scan", "ports", 10)
        dash.advance("ports", 3)
        group = dash._render()                    # build renderable, no Live
        Console(width=120, record=True).print(group)   # must not raise

    def test_live_dashboard_respects_filter(self):
        cfg = SimpleNamespace(targets=["x"], filters={"type": "router"}, sort="ip")
        dash = LiveDashboard(cfg, Console(width=120))
        dash.hosts = HOSTS
        table = dash._devices()
        self.assertEqual(table.row_count, 1)      # only the Router


if __name__ == "__main__":
    unittest.main()
