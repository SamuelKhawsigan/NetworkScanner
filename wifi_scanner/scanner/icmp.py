"""ICMP echo discovery engine.

Sends ICMP echo (ping) requests across one or more target CIDRs and turns the
replies into `Host` objects. This is a genuinely different capability from
`arp.py`, not a replacement for it: ICMP is routable, so it reaches hosts on
other subnets/VLANs that ARP's local broadcast domain can't — but it carries
no MAC address at all. Every host built here has `mac_known=False` and the
`NO_MAC_ICMP` risk flag, so downstream code never confuses "no MAC attempted"
with "MAC lookup failed".

Like `arp.py`, the scapy send/receive call is isolated behind a single
injectable function so sweep/parsing/dedup logic can be unit-tested without
raw sockets or root.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Host


@dataclass
class IcmpReply:
    """A normalized single ICMP echo reply, decoupled from scapy packet objects."""

    ip: str
    rtt_ms: float | None = None
    ttl: int | None = None


def _ip_sort_key(ip: str):
    """Sort key that orders dotted-quad IPs numerically, not lexically."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def build_hosts(replies: list[IcmpReply], now: datetime | None = None) -> list[Host]:
    """Collapse raw ICMP replies into one Host per IP.

    No MAC, so no poison-alert concept (that's an ARP/L2 idea — see
    `arp.build_hosts`). De-duplicates multiple replies for the same IP,
    keeping the lowest RTT.
    """
    now = now or datetime.now(timezone.utc)
    by_ip: dict[str, Host] = {}

    for reply in replies:
        host = by_ip.get(reply.ip)
        if host is None:
            by_ip[reply.ip] = Host(
                ip=reply.ip,
                mac="",
                mac_known=False,
                response_time_ms=reply.rtt_ms,
                ttl=reply.ttl,
                first_seen=now,
                last_seen=now,
                risk_flags=["NO_MAC_ICMP"],
            )
        else:
            host.last_seen = now
            if reply.rtt_ms is not None and (
                host.response_time_ms is None or reply.rtt_ms < host.response_time_ms
            ):
                host.response_time_ms = reply.rtt_ms

    return sorted(by_ip.values(), key=lambda h: _ip_sort_key(h.ip))


def _default_sr(packet, *, timeout, retry, inter, iface, verbose):
    """Real scapy send/receive. Imported lazily so tests never need scapy's
    raw-socket path (sending still requires root at runtime)."""
    from scapy.sendrecv import sr  # noqa: WPS433 (intentional lazy import)

    return sr(
        packet, timeout=timeout, retry=retry, inter=inter, iface=iface,
        verbose=verbose,
    )


def _collect_replies(
    targets: list[str],
    timeout: int,
    retries: int,
    rate_pps: int,
    iface: str | None,
    sr_fn=None,
) -> list[IcmpReply]:
    """Send the ICMP echo sweep and normalize scapy answers into IcmpReply."""
    from scapy.layers.inet import ICMP, IP  # lazy: only needed for real sends

    sr_fn = sr_fn or _default_sr
    inter = (1.0 / rate_pps) if rate_pps else 0
    replies: list[IcmpReply] = []

    for cidr in targets:
        packet = IP(dst=cidr) / ICMP()
        answered, _unanswered = sr_fn(
            packet, timeout=timeout, retry=retries, inter=inter,
            iface=iface, verbose=0,
        )
        for sent, received in answered:
            rtt_ms = None
            try:
                rtt_ms = (received.time - sent.sent_time) * 1000.0
            except (AttributeError, TypeError):
                rtt_ms = None
            ttl = getattr(received, "ttl", None)
            replies.append(IcmpReply(ip=received.src, rtt_ms=rtt_ms, ttl=ttl))
    return replies


def icmp_sweep(
    targets: list[str],
    timeout: int = 2,
    retries: int = 1,
    rate_pps: int = 100,
    iface: str | None = None,
    now: datetime | None = None,
    sr_fn=None,
) -> tuple[list[Host], list]:
    """Run an ICMP echo sweep across `targets` and return (hosts, poison_alerts).

    The second element is always `[]` — kept only so `main._run_pipeline` can
    treat this and `arp.arp_sweep` interchangeably. `sr_fn` is injectable for
    testing; production code leaves it None to use the real scapy sender.
    """
    replies = _collect_replies(targets, timeout, retries, rate_pps, iface, sr_fn)
    return build_hosts(replies, now=now), []
