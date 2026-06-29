"""Flat CSV export — one row per device, list/dict fields joined with ';'."""

from __future__ import annotations

import csv

from .json_export import host_to_dict
from ..scanner.models import Host

CSV_COLUMNS = [
    "ip", "mac", "vendor", "hostname", "device_type", "device_subtype",
    "os", "model", "open_ports", "services", "fingerprint_sources",
    "confidence", "confidence_label", "risk_flags",
    "first_seen", "last_seen", "response_time_ms",
]


def _row(host: Host) -> dict:
    data = host_to_dict(host)
    data["open_ports"] = ";".join(str(p) for p in data["open_ports"])
    data["services"] = ";".join(f"{port}:{svc}" for port, svc in data["services"].items())
    data["fingerprint_sources"] = ";".join(data["fingerprint_sources"])
    data["risk_flags"] = ";".join(data["risk_flags"])
    return {col: data.get(col, "") for col in CSV_COLUMNS}


def export_csv(hosts: list[Host], path: str) -> str:
    """Write hosts to `path` as CSV. Returns the path."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for host in hosts:
            writer.writerow(_row(host))
    return path
