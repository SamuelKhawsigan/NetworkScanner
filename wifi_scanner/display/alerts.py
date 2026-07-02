"""Security alert collection and rendering.

Turns per-host risk flags into a prioritized alert list (high-severity first)
and a rich panel. Ubiquitous, low-signal flags (randomized MACs, missing
hostnames) are intentionally excluded so the alert panel stays meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import config
from ..scanner.models import Host

# Flags too common to be worth alerting on (they're visible in the table).
# NO_MAC_ICMP is expected on every host from an --discovery icmp sweep — it's
# metadata about the discovery method, not a security concern.
NON_ALERT_FLAGS = {"RANDOMIZED_MAC", "NO_HOSTNAME", "NO_MAC_ICMP"}


@dataclass
class Alert:
    flag: str
    ip: str
    severity: str          # "high" | "warn"
    message: str


def collect_alerts(hosts: list[Host]) -> list[Alert]:
    """Gather alert-worthy flags across hosts, high-severity first."""
    alerts: list[Alert] = []
    for host in hosts:
        for flag in host.risk_flags:
            if flag in NON_ALERT_FLAGS:
                continue
            severity = "high" if flag in config.HIGH_RISK_FLAGS else "warn"
            alerts.append(Alert(flag, host.ip, severity, config.RISK_FLAGS.get(flag, flag)))
    alerts.sort(key=lambda a: (0 if a.severity == "high" else 1, a.flag, _ip_key(a.ip)))
    return alerts


def _ip_key(ip: str):
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def build_alerts_panel(alerts: list[Alert], max_rows: int | None = None) -> Panel:
    """Render alerts as a panel; green when clean."""
    if not alerts:
        return Panel(Text("No security alerts.", style="green"),
                     title="Security Alerts", border_style="green", expand=False)

    table = Table(box=box.SIMPLE, show_header=False, expand=True, pad_edge=False)
    table.add_column(width=3)
    table.add_column("flag", style="bold", no_wrap=True)
    table.add_column("ip", no_wrap=True)
    table.add_column("message")

    shown = alerts[:max_rows] if max_rows is not None else alerts
    for alert in shown:
        style = "bold red" if alert.severity == "high" else "yellow"
        mark = "[!]" if alert.severity == "high" else "[*]"
        table.add_row(Text(mark, style=style), Text(alert.flag, style=style),
                      Text(alert.ip), Text(alert.message, style="dim"))

    if max_rows is not None and len(alerts) > max_rows:
        table.caption = f"… and {len(alerts) - max_rows} more"
        table.caption_style = "dim"

    border = "red" if any(a.severity == "high" for a in alerts) else "yellow"
    return Panel(table, title=f"Security Alerts ({len(alerts)})",
                 border_style=border, expand=False)
