"""Device table rendering.

Checkpoint 2 fills the L2/timing columns from the ARP sweep; the enrichment
columns (vendor, type, hostname, flags) render as em-dashes until later
checkpoints populate them.
"""

from __future__ import annotations

from rich import box
from rich.table import Table
from rich.text import Text

from .. import config
from ..scanner.models import Host, PoisonAlert

_DASH = "—"


def _fmt_rtt(ms: float | None) -> str:
    return f"{ms:.1f}" if ms is not None else _DASH


def _row_style(flags: list[str]) -> str | None:
    """Red for high-severity flags, yellow for informational ones, else none."""
    if any(f in config.HIGH_RISK_FLAGS for f in flags):
        return "red"
    if flags:
        return "yellow"
    return None


def _fmt_flags(flags: list[str]) -> Text:
    if not flags:
        return Text(_DASH, style="dim")
    high = any(f in config.HIGH_RISK_FLAGS for f in flags)
    return Text(" ".join(flags), style="bold red" if high else "yellow")


def build_host_table(hosts: list[Host], title: str = "Discovered Hosts") -> Table:
    """Render discovered hosts as a rich Table."""
    table = Table(
        title=title,
        title_style="bold cyan",
        box=box.SIMPLE_HEAVY,
        header_style="bold",
        expand=False,
    )
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("MAC", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Type")
    table.add_column("Hostname")
    table.add_column("RTT ms", justify="right")
    table.add_column("TTL", justify="right")
    table.add_column("Conf", justify="right")
    table.add_column("Flags")

    for h in hosts:
        row_style = _row_style(h.risk_flags)
        # Device-derived strings (mac/vendor/hostname/type) are wrapped in Text
        # so rich never interprets markup or emoji shortcodes inside them — a
        # MAC like "c2:60:07:cd:e2:86" must not turn ":cd:" into 💿.
        table.add_row(
            Text(h.ip),
            Text(h.mac),
            Text(h.vendor) if h.vendor else Text(_DASH, style="dim"),
            Text(h.device_type) if h.device_type else Text(_DASH, style="dim"),
            Text(h.hostname) if h.hostname else Text(_DASH, style="dim"),
            _fmt_rtt(h.response_time_ms),
            str(h.ttl) if h.ttl is not None else _DASH,
            f"{h.confidence}%" if h.confidence else _DASH,
            _fmt_flags(h.risk_flags),
            style=row_style,
        )
    return table


def build_poison_panel(alerts: list[PoisonAlert]) -> Table:
    """Render ARP-poisoning alerts (one IP, multiple MACs) as a warning table."""
    table = Table(
        title="⚠  ARP Conflicts (possible spoofing)",
        title_style="bold red",
        box=box.SIMPLE_HEAVY,
        header_style="bold red",
    )
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Conflicting MACs", style="red")
    for alert in alerts:
        table.add_row(Text(alert.ip), Text(", ".join(alert.macs), style="red"))
    return table
