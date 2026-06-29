"""JSON report building + export.

`build_report` assembles the spec's report structure (scan_meta / devices /
alerts / summary); `export_json` writes it to disk. Keeping the builder separate
means the CSV exporter and any future consumers share the exact same device
serialization.
"""

from __future__ import annotations

import json

from .. import config
from ..display.alerts import NON_ALERT_FLAGS
from ..scanner.models import Host


def _iso(value) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def host_to_dict(host: Host) -> dict:
    """Serialize a Host to the spec's device record shape."""
    return {
        "ip": host.ip,
        "mac": host.mac,
        "vendor": host.vendor,
        "hostname": host.hostname,
        "device_type": host.device_type,
        "device_subtype": host.device_subtype,
        "os": host.os,
        "model": host.model,
        "open_ports": list(host.open_ports),
        "services": {str(port): svc for port, svc in host.services.items()},
        "fingerprint_sources": list(host.fingerprint_sources),
        "confidence": host.confidence,
        "confidence_label": host.confidence_label,
        "risk_flags": list(host.risk_flags),
        "first_seen": _iso(host.first_seen),
        "last_seen": _iso(host.last_seen),
        "response_time_ms": (round(host.response_time_ms, 2)
                             if host.response_time_ms is not None else None),
    }


def _is_flagged(host: Host) -> bool:
    """A host counts as flagged if it carries any non-noise risk flag."""
    return any(f not in NON_ALERT_FLAGS for f in host.risk_flags)


def build_summary(hosts: list[Host]) -> dict:
    by_type: dict[str, int] = {}
    for host in hosts:
        key = host.device_type or "Unknown"
        by_type[key] = by_type.get(key, 0) + 1
    flagged = sum(1 for h in hosts if _is_flagged(h))
    return {
        "by_type": by_type,
        "by_risk": {"clean": len(hosts) - flagged, "flagged": flagged},
    }


def build_report(hosts: list[Host], *, target: str, mode: str,
                 duration_secs: float, timestamp, alerts=None) -> dict:
    """Assemble the full report dict."""
    alert_dicts = [
        {"flag": a.flag, "ip": a.ip, "severity": a.severity, "message": a.message}
        for a in (alerts or [])
    ]
    return {
        "scan_meta": {
            "timestamp": _iso(timestamp),
            "target": target,
            "mode": mode,
            "duration_secs": round(duration_secs, 1),
            "hosts_found": len(hosts),
            "tool_version": _tool_version(),
        },
        "devices": [host_to_dict(h) for h in hosts],
        "alerts": alert_dicts,
        "summary": build_summary(hosts),
    }


def _tool_version() -> str:
    from .. import __version__
    return __version__


def export_json(report: dict, path: str) -> str:
    """Write the report to `path` as pretty JSON. Returns the path."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, default=str)
    return path
