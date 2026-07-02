"""ICMP discovery engine tests.

Mirrors test_checkpoint2.py's approach for arp.py: the scapy send/receive
call is injected as a fake, so these run unprivileged with no real sockets.
Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from wifi_scanner.scanner.icmp import IcmpReply, build_hosts, icmp_sweep

FIXED_NOW = datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc)


class _FakePkt:
    """Stand-in for a scapy IP/ICMP reply / sent packet."""

    def __init__(self, src=None, ttl=None, time=None, sent_time=None):
        self.src = src
        self.ttl = ttl
        self.time = time
        self.sent_time = sent_time


def make_fake_sr(pairs):
    """Return an sr_fn that yields the given (sent, received) answer pairs."""
    def _sr_fn(packet, *, timeout, retry, inter, iface, verbose):
        return pairs, []
    return _sr_fn


class TestBuildHosts(unittest.TestCase):
    def test_single_reply_becomes_host_with_no_mac(self):
        replies = [IcmpReply(ip="10.8.9.20", rtt_ms=1.5, ttl=64)]
        hosts = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual(len(hosts), 1)
        h = hosts[0]
        self.assertEqual(h.ip, "10.8.9.20")
        self.assertEqual(h.mac, "")
        self.assertFalse(h.mac_known)
        self.assertIn("NO_MAC_ICMP", h.risk_flags)
        self.assertEqual(h.response_time_ms, 1.5)
        self.assertEqual(h.ttl, 64)
        self.assertEqual(h.first_seen, FIXED_NOW)
        self.assertEqual(h.last_seen, FIXED_NOW)

    def test_duplicate_ip_keeps_min_rtt(self):
        replies = [
            IcmpReply(ip="10.8.9.20", rtt_ms=5.0),
            IcmpReply(ip="10.8.9.20", rtt_ms=2.0),
        ]
        hosts = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].response_time_ms, 2.0)

    def test_sorted_numerically_not_lexically(self):
        replies = [
            IcmpReply(ip="10.8.9.10"),
            IcmpReply(ip="10.8.9.2"),
            IcmpReply(ip="10.8.9.1"),
        ]
        hosts = build_hosts(replies, now=FIXED_NOW)
        self.assertEqual([h.ip for h in hosts], ["10.8.9.1", "10.8.9.2", "10.8.9.10"])

    def test_empty_input(self):
        hosts = build_hosts([], now=FIXED_NOW)
        self.assertEqual(hosts, [])

    def test_every_host_carries_no_mac_icmp_flag(self):
        replies = [IcmpReply(ip="10.8.9.1"), IcmpReply(ip="10.8.9.2")]
        hosts = build_hosts(replies, now=FIXED_NOW)
        self.assertTrue(all("NO_MAC_ICMP" in h.risk_flags for h in hosts))
        self.assertTrue(all(not h.mac_known for h in hosts))


class TestIcmpSweep(unittest.TestCase):
    def test_sweep_with_injected_sr(self):
        sent = _FakePkt(sent_time=100.0)
        recv = _FakePkt(src="10.8.9.1", ttl=64, time=100.0042)
        sr_fn = make_fake_sr([(sent, recv)])
        hosts, poison = icmp_sweep(
            ["10.8.9.0/24"], timeout=1, retries=0, rate_pps=100,
            now=FIXED_NOW, sr_fn=sr_fn,
        )
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "10.8.9.1")
        self.assertEqual(hosts[0].mac, "")
        self.assertFalse(hosts[0].mac_known)
        self.assertAlmostEqual(hosts[0].response_time_ms, 4.2, places=1)
        self.assertEqual(hosts[0].ttl, 64)
        self.assertEqual(poison, [])   # no ARP-poison concept for ICMP

    def test_sweep_handles_missing_timing(self):
        sent = _FakePkt()                       # no sent_time -> rtt None
        recv = _FakePkt(src="10.8.9.5")
        hosts, _ = icmp_sweep(
            ["10.8.9.0/24"], sr_fn=make_fake_sr([(sent, recv)]), now=FIXED_NOW,
        )
        self.assertEqual(len(hosts), 1)
        self.assertIsNone(hosts[0].response_time_ms)

    def test_sweep_empty_answers(self):
        hosts, poison = icmp_sweep(
            ["10.8.9.0/24"], sr_fn=make_fake_sr([]), now=FIXED_NOW,
        )
        self.assertEqual(hosts, [])
        self.assertEqual(poison, [])

    def test_sweep_never_populates_mac_or_vendor(self):
        # Cross-VLAN host that ARP could never see — the whole point of this
        # discovery mode — must still come back with an explicitly-marked
        # absent MAC, not a silently blank one indistinguishable from a
        # failed ARP lookup.
        sent = _FakePkt(sent_time=100.0)
        recv = _FakePkt(src="172.16.5.9", ttl=128, time=100.001)
        hosts, _ = icmp_sweep(
            ["172.16.5.0/24"], sr_fn=make_fake_sr([(sent, recv)]), now=FIXED_NOW,
        )
        h = hosts[0]
        self.assertEqual(h.mac, "")
        self.assertFalse(h.mac_known)
        self.assertIsNone(h.vendor)


if __name__ == "__main__":
    unittest.main()
