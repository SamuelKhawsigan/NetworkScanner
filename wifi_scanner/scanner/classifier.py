"""Device classifier — pick a category from evidence and annotate the host.

Runs the full analysis pipeline per host: gather weighted evidence
(fingerprint), choose the best-supported category (ties broken by specificity),
derive OS/vendor/model, score confidence, and set the informational risk flags
that depend on the finished profile (NO_HOSTNAME, STEALTHY).
"""

from __future__ import annotations

from .. import config
from . import fingerprint, scoring
from .fingerprint import Evidence
from .models import Host

# Tie-break order: more specific / higher-value categories win an equal-weight tie.
CATEGORY_PRIORITY = [
    "Router", "Switch", "Access Point", "Server", "NAS", "Printer", "Camera",
    "Smart TV", "IoT", "Workstation", "Laptop", "Mobile", "Unknown",
]


def _choose_category(evidence: list[Evidence]) -> str:
    sums: dict[str, int] = {}
    for ev in evidence:
        if ev.category:
            sums[ev.category] = sums.get(ev.category, 0) + ev.weight
    if not sums:
        return "Unknown"
    top = max(sums.values())
    candidates = [cat for cat, weight in sums.items() if weight == top]
    return min(
        candidates,
        key=lambda c: CATEGORY_PRIORITY.index(c) if c in CATEGORY_PRIORITY else 99,
    )


def _subcategory_for(evidence: list[Evidence], category: str) -> str | None:
    best, best_weight = None, -1
    for ev in evidence:
        if ev.category == category and ev.subcategory and ev.weight > best_weight:
            best, best_weight = ev.subcategory, ev.weight
    return best


def classify_host(host: Host, signatures: list[dict] | None = None) -> list[Evidence]:
    """Analyse a host end-to-end and write the profile fields onto it."""
    evidence = fingerprint.gather_evidence(host, signatures)

    category = _choose_category(evidence)
    host.device_type = category
    host.device_subtype = _subcategory_for(evidence, category)
    host.os = fingerprint.best_field(evidence, "os")
    host.model = fingerprint.best_field(evidence, "model")
    refined_vendor = fingerprint.best_field(evidence, "vendor")
    if refined_vendor:
        host.vendor = refined_vendor

    host.confidence = scoring.score(evidence, category)
    host.confidence_label = config.confidence_label(host.confidence)

    _apply_profile_flags(host)
    return evidence


def _apply_profile_flags(host: Host) -> None:
    if not host.hostname and "NO_HOSTNAME" not in host.risk_flags:
        host.risk_flags.append("NO_HOSTNAME")
    # A non-randomized device that answers ARP but exposes nothing else is the
    # interesting "stealthy" case; silent phones (randomized MACs) are expected.
    randomized = "RANDOMIZED_MAC" in host.risk_flags
    if (not host.open_ports and not host.signals and not randomized
            and "STEALTHY" not in host.risk_flags):
        host.risk_flags.append("STEALTHY")


def classify_hosts(hosts: list[Host]) -> None:
    """Classify a batch of hosts using the shared signature set."""
    signatures = fingerprint.load_signatures()
    for host in hosts:
        classify_host(host, signatures)
