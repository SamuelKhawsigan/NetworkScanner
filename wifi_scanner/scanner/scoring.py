"""Confidence scoring — turn an evidence list into a 0-100 score.

Driven by: how much weight supports the chosen category, how many distinct
sources corroborate it, and how much weight conflicts with it. A device known
only by OUI vendor (no category) scores low but non-zero.
"""

from __future__ import annotations

from .fingerprint import Evidence

CONFLICT_PENALTY = 0.4
CORROBORATION_BONUS = 6
# The strongest single supporting signal sets the base; cap it below 90 so that
# reaching CONFIRMED requires corroboration from a second independent source.
BASE_CAP = 85


def score(evidence: list[Evidence], category: str | None) -> int:
    """Return a 0-100 confidence score for classifying as `category`.

    A single top-tier signal (e.g. SNMP sysDescr) gives a strong base; extra
    independent sources push toward CONFIRMED; conflicting evidence subtracts.
    """
    if not evidence:
        return 0

    if not category or category == "Unknown":
        # No category settled — credit any OS/vendor identification, modestly.
        identity = sum(ev.weight for ev in evidence if ev.os or ev.vendor)
        return max(0, min(40, round(identity * 0.5)))

    supporting = [ev for ev in evidence if ev.category == category]
    if not supporting:
        return 0

    top = max(ev.weight for ev in supporting)
    distinct = len({ev.source for ev in supporting})
    conflict = sum(ev.weight for ev in evidence if ev.category and ev.category != category)

    base = min(BASE_CAP, top * 2)
    raw = base + (distinct - 1) * CORROBORATION_BONUS - conflict * CONFLICT_PENALTY
    return max(0, min(100, round(raw)))
