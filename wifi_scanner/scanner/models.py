"""Shared data models passed between scanning stages.

`Host` starts life from the ARP sweep (Checkpoint 2) carrying only L2/timing
data. Later checkpoints enrich the same object in place with ports, services,
fingerprint, classification, and risk flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Host:
    """A single discovered host, enriched as it moves through the pipeline."""

    ip: str
    mac: str

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
    fingerprint_sources: list[str] = field(default_factory=list)
    confidence: int = 0
    confidence_label: str = "UNKNOWN"
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class PoisonAlert:
    """Same IP answered by more than one MAC within a sweep — possible spoofing."""

    ip: str
    macs: list[str]
