"""Shared data models passed between scanning stages.

`Host` starts life from a discovery sweep — ARP (Checkpoint 2) or, later,
ICMP — carrying only L2/timing data. Later checkpoints enrich the same object
in place with ports, services, fingerprint, classification, and risk flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Host:
    """A single discovered host, enriched as it moves through the pipeline."""

    ip: str
    mac: str = ""

    # True when discovery actually attempted to resolve a MAC (ARP) and this
    # is a real (possibly empty-on-failure) result. False means MAC was never
    # attempted at all — e.g. ICMP discovery, which is L3-only and crosses
    # subnets ARP can't reach. Keep this distinct from `mac == ""` so
    # "no MAC attempted" is never silently rendered the same as "MAC lookup
    # failed".
    mac_known: bool = True

    # --- ARP / timing (Checkpoint 2) ---
    response_time_ms: float | None = None
    ttl: int | None = None                       # filled during fingerprinting
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # --- enrichment (later checkpoints) ---
    vendor: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    device_subtype: str | None = None
    os: str | None = None
    model: str | None = None
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    # raw protocol-prober outputs keyed by source name (snmp, netbios, smb,
    # mdns, upnp, http) — consumed by the fingerprint/classifier stages
    signals: dict[str, object] = field(default_factory=dict)
    fingerprint_sources: list[str] = field(default_factory=list)
    confidence: int = 0
    confidence_label: str = "UNKNOWN"
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class PoisonAlert:
    """Same IP answered by more than one MAC within a sweep — possible spoofing."""

    ip: str
    macs: list[str]
