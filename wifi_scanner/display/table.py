"""Device table rendering.

Checkpoint 2 fills the L2/timing columns from the ARP sweep; the enrichment
columns (vendor, type, hostname, flags) render as em-dashes until later
checkpoints populate them.
"""

from __future__ import annotations

import ipaddress

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import config
from ..scanner.models import Host, PoisonAlert

_DASH = "—"
_NO_MAC = "(no MAC — ICMP)"


def _fmt_mac(host: Host) -> Text:
    """Blank MAC from a real attempt looks identical to "never attempted"
    unless we say so explicitly — see the NO_MAC_ICMP risk flag."""
    if not host.mac_known:
        return Text(_NO_MAC, style="dim italic")
    return Text(host.mac)


def _fmt_rtt(ms: float | None) -> str:
    return f"{ms:.1f}" if ms is not None else _DASH


def _fmt_ports(ports: list[int]) -> Text:
    if not ports:
        return Text(_DASH, style="dim")
    return Text(",".join(str(p) for p in ports))


_CONF_STYLE = {
    "CONFIRMED": "bold green", "HIGH": "green",
    "MEDIUM": "yellow", "LOW": "dim", "UNKNOWN": "dim",
}


def _fmt_conf(confidence: int, label: str) -> Text:
    if not confidence:
        return Text(_DASH, style="dim")
    return Text(f"{confidence}%", style=_CONF_STYLE.get(label, ""))


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


def build_host_table(hosts: list[Host], title: str = "Discovered Hosts",
                     max_rows: int | None = None) -> Table:
    """Render discovered hosts as a rich Table.

    If `max_rows` is set and exceeded, only the first `max_rows` are shown and a
    caption notes how many were hidden (used by the cropped live preview).
    """
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
    table.add_column("OS")
    table.add_column("Ports")
    table.add_column("RTT ms", justify="right")
    table.add_column("TTL", justify="right")
    table.add_column("Conf", justify="right")
    table.add_column("Flags")

    shown = hosts[:max_rows] if max_rows is not None else hosts
    for h in shown:
        row_style = _row_style(h.risk_flags)
        # Device-derived strings (mac/vendor/hostname/type) are wrapped in Text
        # so rich never interprets markup or emoji shortcodes inside them — a
        # MAC like "c2:60:07:cd:e2:86" must not turn ":cd:" into 💿.
        table.add_row(
            Text(h.ip),
            _fmt_mac(h),
            Text(h.vendor) if h.vendor else Text(_DASH, style="dim"),
            Text(h.device_type) if h.device_type else Text(_DASH, style="dim"),
            Text(h.hostname) if h.hostname else Text(_DASH, style="dim"),
            Text(h.os) if h.os else Text(_DASH, style="dim"),
            _fmt_ports(h.open_ports),
            _fmt_rtt(h.response_time_ms),
            str(h.ttl) if h.ttl is not None else _DASH,
            _fmt_conf(h.confidence, h.confidence_label),
            _fmt_flags(h.risk_flags),
            style=row_style,
        )
    if max_rows is not None and len(hosts) > max_rows:
        table.caption = f"… and {len(hosts) - max_rows} more"
        table.caption_style = "dim"
    return table


# --------------------------------------------------------------------------- #
# Sorting / filtering / summary
# --------------------------------------------------------------------------- #
def _ip_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _flag_severity(flags: list[str]) -> int:
    high = sum(1 for f in flags if f in config.HIGH_RISK_FLAGS)
    return high * 100 + len(flags)


def sort_hosts(hosts: list[Host], key: str = "ip") -> list[Host]:
    """Return hosts sorted by one of: ip, mac, type, conf, flags."""
    if key == "mac":
        return sorted(hosts, key=lambda h: h.mac)
    if key == "type":
        return sorted(hosts, key=lambda h: (h.device_type or "zzz", _ip_key(h.ip)))
    if key == "conf":
        return sorted(hosts, key=lambda h: (-h.confidence, _ip_key(h.ip)))
    if key == "flags":
        return sorted(hosts, key=lambda h: (-_flag_severity(h.risk_flags), _ip_key(h.ip)))
    return sorted(hosts, key=lambda h: _ip_key(h.ip))


def _match_filter(host: Host, key: str, value: str) -> bool:
    vl = value.lower()
    if key == "type":
        return vl in (host.device_type or "").lower() or vl in (host.device_subtype or "").lower()
    if key == "flags":
        return any(vl == f.lower() for f in host.risk_flags)
    if key == "vendor":
        return vl in (host.vendor or "").lower()
    if key == "os":
        return vl in (host.os or "").lower()
    if key == "hostname":
        return vl in (host.hostname or "").lower()
    if key == "ip":
        return value in host.ip
    return True


def filter_hosts(hosts: list[Host], filters: dict[str, str]) -> list[Host]:
    """Keep hosts matching every filter clause (AND semantics)."""
    result = hosts
    for key, value in filters.items():
        result = [h for h in result if _match_filter(h, key, value)]
    return result


def build_summary(hosts: list[Host]) -> Panel:
    """One-line counts by device type plus a flagged total."""
    by_type: dict[str, int] = {}
    for h in hosts:
        by_type[h.device_type or "Unknown"] = by_type.get(h.device_type or "Unknown", 0) + 1
    flagged = sum(
        1 for h in hosts if any(f in config.HIGH_RISK_FLAGS for f in h.risk_flags)
    )
    parts = "   ".join(
        f"{t}: {c}" for t, c in sorted(by_type.items(), key=lambda x: -x[1])
    )
    text = Text(parts or "no hosts")
    text.append(f"      Flagged: {flagged}", style="bold red" if flagged else "dim")
    return Panel(text, title="Summary", border_style="cyan", expand=False)


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
