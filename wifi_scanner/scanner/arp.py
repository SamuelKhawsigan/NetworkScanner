"""ARP discovery engine.

Sends ARP who-has broadcasts across one or more target CIDRs and turns the
replies into `Host` objects. The scapy send/receive call is isolated behind a
single injectable function so the parsing, de-duplication, and ARP-poisoning
detection logic can be unit-tested without raw sockets or root.

Note on TTL: ARP is a layer-2 protocol and carries no IP TTL, so `Host.ttl`
stays None here — it gets populated later from IP-level responses during
fingerprinting.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Host, PoisonAlert


@dataclass
class ArpReply:
    """A normalized single ARP reply, decoupled from scapy packet objects."""

    ip: str
    mac: str
    rtt_ms: float | None = None
    ttl: int | None = None


def normalize_mac(mac: str) -> str:
    """Lowercase, colon-separated MAC form (accepts dash- or colon-delimited)."""
    return mac.strip().lower().replace("-", ":")


def _ip_sort_key(ip: str):
    """Sort key that orders dotted-quad IPs numerically, not lexically."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def build_hosts(
    replies: list[ArpReply], now: datetime | None = None
) -> tuple[list[Host], list[PoisonAlert]]:
    """Collapse raw replies into one Host per IP and detect MAC conflicts.

    - De-duplicates multiple replies for the same IP, keeping the lowest RTT.
    - Flags any IP answered by more than one distinct MAC as a PoisonAlert.
    """
    now = now or datetime.now(timezone.utc)
    by_ip: dict[str, Host] = {}
    macs_by_ip: dict[str, list[str]] = {}

    for reply in replies:
        mac = normalize_mac(reply.mac)
        seen = macs_by_ip.setdefault(reply.ip, [])
        if mac not in seen:
            seen.append(mac)

        host = by_ip.get(reply.ip)
        if host is None:
            by_ip[reply.ip] = Host(
                ip=reply.ip,
                mac=mac,
                response_time_ms=reply.rtt_ms,
                ttl=reply.ttl,
                first_seen=now,
                last_seen=now,
            )
        else:
            host.last_seen = now
            if reply.rtt_ms is not None and (
                host.response_time_ms is None or reply.rtt_ms < host.response_time_ms
            ):
                host.response_time_ms = reply.rtt_ms

    alerts = [
        PoisonAlert(ip=ip, macs=macs)
        for ip, macs in macs_by_ip.items()
        if len(macs) > 1
    ]
    hosts = sorted(by_ip.values(), key=lambda h: _ip_sort_key(h.ip))
    return hosts, alerts


def _default_srp(packet, *, timeout, retry, inter, iface, verbose):
    """Real scapy send/receive. Imported lazily so tests never need scapy's
    raw-socket path (sending still requires root at runtime)."""
    from scapy.sendrecv import srp  # noqa: WPS433 (intentional lazy import)

    return srp(
        packet, timeout=timeout, retry=retry, inter=inter, iface=iface,
        verbose=verbose,
    )


def _collect_replies(
    targets: list[str],
    timeout: int,
    retries: int,
    rate_pps: int,
    iface: str | None,
    srp_fn=None,
) -> list[ArpReply]:
    """Send the ARP sweep and normalize scapy answers into ArpReply objects."""
    from scapy.layers.l2 import ARP, Ether  # lazy: only needed for real sends

    srp_fn = srp_fn or _default_srp
    inter = (1.0 / rate_pps) if rate_pps else 0
    replies: list[ArpReply] = []

    for cidr in targets:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _unanswered = srp_fn(
            packet, timeout=timeout, retry=retries, inter=inter,
            iface=iface, verbose=0,
        )
        for sent, received in answered:
            rtt_ms = None
            try:
                rtt_ms = (received.time - sent.sent_time) * 1000.0
            except (AttributeError, TypeError):
                rtt_ms = None
            replies.append(
                ArpReply(ip=received.psrc, mac=received.hwsrc, rtt_ms=rtt_ms)
            )
    return replies


def arp_sweep(
    targets: list[str],
    timeout: int = 2,
    retries: int = 2,
    rate_pps: int = 100,
    iface: str | None = None,
    now: datetime | None = None,
    srp_fn=None,
) -> tuple[list[Host], list[PoisonAlert]]:
    """Run an ARP who-has sweep across `targets` and return (hosts, alerts).

    `srp_fn` is injectable for testing; production code leaves it None to use
    the real scapy sender.
    """
    replies = _collect_replies(targets, timeout, retries, rate_pps, iface, srp_fn)
    return build_hosts(replies, now=now)
