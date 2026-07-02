"""Entry point and CLI for the office WiFi/LAN scanner.

Checkpoint 1: scaffold + config + CLI skeleton. The argument surface, target
validation, environment checks, and --dry-run planning are wired up here. The
actual scan engines land in later checkpoints; until then the run path reports
the resolved plan and exits cleanly.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import sys
from dataclasses import dataclass, field

import click

from . import __version__
from . import config


# --------------------------------------------------------------------------- #
# Resolved run configuration
# --------------------------------------------------------------------------- #
@dataclass
class ScanConfig:
    """Fully resolved, validated configuration for a single run."""

    targets: list[str]
    mode: str
    discovery: str
    ports_profile: str
    ports: list[int]
    timeout: int
    rate_pps: int
    watch: bool
    interval: int
    sort: str
    filters: dict[str, str]
    output: str | None
    out_file: str | None
    no_ports: bool
    no_snmp: bool
    stealth: bool
    known_file: str | None
    history_db: str
    verbose: bool
    debug: bool
    dry_run: bool
    no_live: bool = False
    hosts_total: int = field(default=0)


# --------------------------------------------------------------------------- #
# Environment checks
# --------------------------------------------------------------------------- #
def is_root() -> bool:
    """True if running with the privileges scapy needs for raw sockets."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_wsl() -> bool:
    """Best-effort detection of WSL so we can surface the mirrored-mode note."""
    release = platform.uname().release.lower()
    return "microsoft" in release or "wsl" in release


def check_environment(cfg: ScanConfig, console: "Console") -> None:
    """Warn (don't hard-fail on dry-run) about privilege / environment issues."""
    if not is_root():
        msg = (
            "[yellow]![/] Not running as root. scapy needs raw sockets — "
            "re-run with [bold]sudo[/]."
        )
        if cfg.dry_run:
            console.print(msg + " [dim](dry-run: continuing)[/]")
        else:
            console.print(msg)
            sys.exit(1)

    if is_wsl():
        console.print(
            "[dim]i WSL2 detected. ARP needs [bold]mirrored networking mode[/] "
            "to reach the office LAN. If sweeps come back empty, set "
            "networkingMode=mirrored in .wslconfig and restart WSL.[/]"
        )


# --------------------------------------------------------------------------- #
# Validation / resolution helpers
# --------------------------------------------------------------------------- #
def parse_targets(target: str) -> list[str]:
    """Validate a comma-separated list of CIDRs/IPs and normalize them."""
    targets: list[str] = []
    for raw in target.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise click.BadParameter(f"invalid target '{raw}': {exc}")
        targets.append(str(net))
    if not targets:
        raise click.BadParameter("no valid targets supplied")
    return targets


def count_hosts(targets: list[str]) -> int:
    """Total usable host addresses across all target networks."""
    total = 0
    for t in targets:
        net = ipaddress.ip_network(t, strict=False)
        # num_addresses includes network/broadcast; subtract for /31+ sanity
        total += max(net.num_addresses - 2, 1) if net.num_addresses > 2 else net.num_addresses
    return total


def parse_filters(filter_expr: str | None) -> dict[str, str]:
    """Parse `--filter key=value[,key=value]` into a dict."""
    filters: dict[str, str] = {}
    if not filter_expr:
        return filters
    for clause in filter_expr.split(","):
        clause = clause.strip()
        if not clause:
            continue
        if "=" not in clause:
            raise click.BadParameter(
                f"filter '{clause}' must be key=value (e.g. type=printer)"
            )
        key, value = clause.split("=", 1)
        filters[key.strip().lower()] = value.strip()
    return filters


def resolve_ports(profile: str) -> list[int]:
    """Resolve a named port profile to a concrete port list."""
    return config.PORT_PROFILES.get(profile, config.PORTS_COMMON)


def apply_mode_overrides(cfg: ScanConfig) -> ScanConfig:
    """Adjust resolved config for scan-mode and stealth semantics."""
    if cfg.mode == "stealth" or cfg.stealth:
        cfg.rate_pps = min(cfg.rate_pps, config.STEALTH_RATE_PPS)
        cfg.no_snmp = True
    if cfg.mode == "quick":
        cfg.no_ports = True
    if cfg.mode == "watch":
        cfg.watch = True
    return cfg


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--target", default=config.DEFAULT_TARGET, show_default=True,
              help="Target network(s), comma-separated CIDRs.")
@click.option("--mode", type=click.Choice(config.MODES), default=config.DEFAULT_MODE,
              show_default=True, help="Scan mode.")
@click.option("--discovery", type=click.Choice(config.DISCOVERY_MODES),
              default=config.DEFAULT_DISCOVERY, show_default=True,
              help="Discovery method: arp (local broadcast domain, gives MAC) "
                   "or icmp (routable across subnets/VLANs, IP-only — no MAC).")
@click.option("--ports", "ports_profile", type=click.Choice(list(config.PORT_PROFILES)),
              default=config.DEFAULT_PORT_PROFILE, show_default=True,
              help="Port profile.")
@click.option("--timeout", default=config.DEFAULT_ARP_TIMEOUT, show_default=True,
              help="ARP timeout per sweep (seconds).")
@click.option("--rate", "rate_pps", default=config.DEFAULT_RATE_PPS, show_default=True,
              help="Packets per second cap.")
@click.option("--watch", is_flag=True, help="Continuous watch mode (re-scan loop).")
@click.option("--interval", default=config.DEFAULT_WATCH_INTERVAL, show_default=True,
              help="Watch re-scan interval (seconds).")
@click.option("--sort", type=click.Choice(config.SORT_KEYS), default=config.DEFAULT_SORT,
              show_default=True, help="Sort output table by key.")
@click.option("--filter", "filter_expr", default=None,
              help="Filter expr, e.g. type=router,flags=NEW_DEVICE.")
@click.option("--output", type=click.Choice(config.OUTPUT_FORMATS), default=None,
              help="Export results format.")
@click.option("--out-file", default=None, help="Output file path.")
@click.option("--no-ports", is_flag=True, help="Skip port scanning.")
@click.option("--no-snmp", is_flag=True, help="Skip SNMP probing.")
@click.option("--stealth", is_flag=True, help="Slow rate, no banners, minimal footprint.")
@click.option("--known-file", default=None, help="JSON of known/approved devices.")
@click.option("--history-db", default=str(config.HISTORY_DB_PATH), show_default=True,
              help="SQLite DB for historical tracking.")
@click.option("--verbose", is_flag=True, help="Verbose logging.")
@click.option("--debug", is_flag=True, help="Debug output.")
@click.option("--update-oui", is_flag=True, help="(Re)build the local OUI vendor DB, then scan.")
@click.option("--no-live", is_flag=True, help="Disable the live dashboard; print a static report.")
@click.option("--dry-run", is_flag=True, help="Show the scan plan without sending packets.")
@click.version_option(__version__, "-V", "--version", prog_name="wifi-scanner")
def cli(target, mode, discovery, ports_profile, timeout, rate_pps, watch, interval, sort,
        filter_expr, output, out_file, no_ports, no_snmp, stealth, known_file,
        history_db, verbose, debug, update_oui, no_live, dry_run):
    """Office WiFi/LAN scanner — authorized network reconnaissance."""
    from rich.console import Console
    console = Console()

    targets = parse_targets(target)
    cfg = ScanConfig(
        targets=targets,
        mode=mode,
        discovery=discovery,
        ports_profile=ports_profile,
        ports=resolve_ports(ports_profile),
        timeout=timeout,
        rate_pps=rate_pps,
        watch=watch,
        interval=interval,
        sort=sort,
        filters=parse_filters(filter_expr),
        output=output,
        out_file=out_file,
        no_ports=no_ports,
        no_snmp=no_snmp,
        stealth=stealth,
        known_file=known_file,
        history_db=history_db,
        verbose=verbose,
        debug=debug,
        dry_run=dry_run,
        no_live=no_live,
    )
    cfg = apply_mode_overrides(cfg)
    cfg.hosts_total = count_hosts(cfg.targets)

    check_environment(cfg, console)

    if update_oui:
        ensure_oui_db(console, force=True)

    if cfg.dry_run:
        print_plan(cfg, console)
        return

    print_plan(cfg, console)
    try:
        run_scan(cfg, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — stopping scan.[/]")


def ensure_oui_db(console: "Console", force: bool = False) -> bool:
    """Build the local OUI DB if missing (or forced). Best-effort — returns
    True if a usable DB exists afterward, False if the download failed."""
    from .scanner import oui

    if config.OUI_DB_PATH.exists() and not force:
        return True
    action = "Rebuilding" if force else "Downloading"
    console.print(f"[cyan]{action} IEEE OUI database[/] (one-time, ~a few MB) …")
    try:
        count = oui.update_oui_db()
        console.print(f"[green]OUI database ready — {count:,} vendor prefixes.[/]")
        return True
    except Exception as exc:  # network/parse failure shouldn't abort the scan
        console.print(
            f"[yellow]Could not build OUI DB ({exc}).[/] Continuing without "
            "vendor names; randomized-MAC detection still works (it's offline)."
        )
        return config.OUI_DB_PATH.exists()


def run_scan(cfg: ScanConfig, console: "Console") -> None:
    """Dispatch to a single scan or the continuous watch loop."""
    ensure_oui_db(console)            # prints; do it before any live display
    if cfg.watch:
        run_watch(cfg, console)
    else:
        run_single(cfg, console)


def _run_discovery(cfg: ScanConfig, reporter, console: "Console"):
    """Run the configured discovery sweep (arp or icmp). Returns (hosts, poison)."""
    if cfg.discovery == "icmp":
        from .scanner import icmp

        reporter.phase(f"ICMP sweep — {', '.join(cfg.targets)}", "arp")
        try:
            hosts, poison = icmp.icmp_sweep(
                cfg.targets, timeout=config.DEFAULT_ICMP_TIMEOUT,
                retries=config.DEFAULT_ICMP_RETRIES, rate_pps=cfg.rate_pps,
            )
        except PermissionError:
            console.print(
                "[red]Permission denied[/] — ICMP sweep needs raw sockets. "
                "Re-run with [bold]sudo[/]."
            )
            return None, [], []
        except ImportError as exc:
            console.print(
                f"[red]Missing dependency:[/] {exc}. "
                "Install it with [bold]pip install scapy[/]."
            )
            return None, [], []
        except OSError as exc:
            console.print(f"[red]ICMP sweep failed:[/] {exc}")
            return None, [], []
        empty_hint = (
            "[dim]ICMP sweep returned no replies — the target(s) may be "
            "blocking ICMP, or unreachable from this host.[/]"
        )
        return hosts, poison, empty_hint

    from .scanner import arp

    reporter.phase(f"ARP sweep — {', '.join(cfg.targets)}", "arp")
    try:
        hosts, poison = arp.arp_sweep(
            cfg.targets, timeout=cfg.timeout,
            retries=config.DEFAULT_ARP_RETRIES, rate_pps=cfg.rate_pps,
        )
    except PermissionError:
        console.print(
            "[red]Permission denied[/] — ARP sweep needs raw sockets. "
            "Re-run with [bold]sudo[/]."
        )
        return None, [], []
    except ImportError as exc:
        console.print(
            f"[red]Missing dependency:[/] {exc}. "
            "Install it with [bold]pip install scapy[/]."
        )
        return None, [], []
    except OSError as exc:
        console.print(f"[red]ARP sweep failed:[/] {exc}")
        return None, [], []
    empty_hint = (
        "[dim]ARP sweep returned no replies — check that the target "
        "network is reachable and that you are running as root.[/]"
    )
    return hosts, poison, empty_hint


def _run_pipeline(cfg: ScanConfig, reporter, console: "Console"):
    """One full scan pass driving `reporter`: discovery -> OUI -> ports ->
    probe -> classify. Returns (hosts, poison_alerts)."""
    from .scanner import classifier

    hosts, poison, empty_hint = _run_discovery(cfg, reporter, console)
    if hosts is None:
        return [], []
    reporter.finish("arp")
    reporter.set_hosts(hosts)

    if not hosts:
        if cfg.verbose:
            console.print(empty_hint)
        return hosts, poison

    if cfg.discovery == "arp":
        _annotate_oui(hosts)
    _run_port_scan(cfg, hosts, reporter)
    _run_protocols(cfg, hosts, reporter)

    reporter.phase("Classifying", "classify", len(hosts))
    classifier.classify_hosts(hosts)
    reporter.finish("classify")
    reporter.set_hosts(hosts)

    if cfg.debug:
        _debug_print_signals(hosts, console)

    return hosts, poison


def run_single(cfg: ScanConfig, console: "Console") -> None:
    """One scan pass with a transient dashboard, then the final report.

    Ctrl+C at any point is caught gracefully: whatever hosts were discovered
    before the interrupt are reported and exported normally.
    """
    import time
    from datetime import datetime, timezone
    from .display.live_view import LiveDashboard, StaticReporter

    started = time.monotonic()
    timestamp = datetime.now(timezone.utc)

    use_live = console.is_terminal and not cfg.no_live
    reporter = (LiveDashboard(cfg, console) if use_live
                else StaticReporter(cfg, console))

    hosts: list = []
    poison: list = []
    interrupted = False
    try:
        with reporter:
            hosts, poison = _run_pipeline(cfg, reporter, console)
    except KeyboardInterrupt:
        interrupted = True
        hosts = list(getattr(reporter, "hosts", []))
        console.print("\n[yellow]Scan interrupted — showing partial results.[/]")

    if not hosts:
        if not interrupted:
            console.print(
                "[yellow]No hosts answered.[/] On WSL2 this usually means "
                "mirrored networking isn't active — see the note above."
            )
        return

    events = _record_history(cfg, hosts, console)
    _print_final_report(cfg, hosts, poison, console)
    _report_history(events, console, verbose=cfg.verbose)

    if cfg.output:
        _write_exports(cfg, hosts, timestamp, time.monotonic() - started, console)


def run_watch(cfg: ScanConfig, console: "Console") -> None:
    """Continuous re-scanning with a persistent dashboard until Ctrl+C.

    Each pass diffs against history.db so new/changed devices surface as alerts
    in real time. On exit, prints the final report and exports if requested.
    """
    import time
    from datetime import datetime, timezone
    from rich.console import Console as RichConsole
    from .display.live_view import LiveDashboard, StaticReporter

    started = time.monotonic()
    timestamp = datetime.now(timezone.utc)
    quiet = RichConsole(quiet=True)          # swallow history prints during live

    console.print(
        f"[cyan]Watch mode[/] — re-scanning every {cfg.interval}s. "
        "Press Ctrl+C to stop."
    )
    use_live = console.is_terminal and not cfg.no_live
    dashboard = (LiveDashboard(cfg, console, transient=False) if use_live
                 else StaticReporter(cfg, console))

    hosts: list = []
    poison: list = []
    try:
        with dashboard:
            scan_num = 0
            while True:
                scan_num += 1
                if hasattr(dashboard, "begin_scan"):
                    dashboard.begin_scan(scan_num)
                hosts, poison = _run_pipeline(cfg, dashboard, console)
                if hosts:
                    _record_history(cfg, hosts, quiet)
                    dashboard.set_hosts(hosts)
                _watch_wait(dashboard, cfg.interval)
    except KeyboardInterrupt:
        pass

    console.print("\n[yellow]Watch stopped.[/]")
    if hosts:
        _print_final_report(cfg, hosts, poison, console)
        if cfg.output:
            _write_exports(cfg, hosts, timestamp, time.monotonic() - started, console)


def _watch_wait(dashboard, interval: int) -> None:
    """Sleep `interval` seconds, updating the countdown each second."""
    import time
    for remaining in range(interval, 0, -1):
        if hasattr(dashboard, "set_status"):
            dashboard.set_status(f"WAITING {remaining}s")
        time.sleep(1)


def load_known_macs(path: str, console: "Console") -> set[str]:
    """Load whitelisted MACs from a JSON known-file.

    Accepts three shapes:
    - A list of MAC strings:          ["aa:bb:...", ...]
    - A list of device objects:       [{"mac": "aa:bb:...", ...}, ...]
    - A scan-export object:           {"devices": [{"mac": "aa:bb:...", ...}]}
    MACs are normalised to lower-case so comparisons are case-insensitive.
    """
    import json
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[yellow]Could not load known-file '{path}' ({exc}) — ignored.[/]")
        return set()

    items = data
    if isinstance(data, dict):
        items = data.get("devices", [])

    macs: set[str] = set()
    for item in items:
        if isinstance(item, str):
            macs.add(item.lower())
        elif isinstance(item, dict) and "mac" in item:
            macs.add(str(item["mac"]).lower())

    if not macs:
        console.print(f"[yellow]Known-file '{path}' contained no recognisable MACs.[/]")
    return macs


def _suppress_known_flags(hosts, known_macs: set[str]) -> None:
    """Remove NEW_DEVICE and ROGUE_AP_HINT from hosts whose MAC is whitelisted."""
    suppress = {"NEW_DEVICE", "ROGUE_AP_HINT"}
    for host in hosts:
        if host.mac.lower() in known_macs:
            host.risk_flags = [f for f in host.risk_flags if f not in suppress]


def _record_history(cfg, hosts, console: "Console"):
    """Diff against history.db and apply NEW_DEVICE/IP_CHANGED/MAC_CHANGED flags."""
    from .scanner.history import HistoryDB

    known_macs: set[str] = set()
    if cfg.known_file:
        known_macs = load_known_macs(cfg.known_file, console)

    try:
        hist = HistoryDB(cfg.history_db)
    except Exception as exc:               # don't let history break a scan
        console.print(f"[yellow]History tracking unavailable ({exc}).[/]")
        return []
    try:
        events = hist.record_scan(hosts, known_macs=known_macs)
    finally:
        hist.close()

    if known_macs:
        _suppress_known_flags(hosts, known_macs)
    return events


def _report_history(events, console: "Console", verbose: bool = False) -> None:
    if not events:
        return
    if verbose:
        for ev in events:
            console.print(
                f"[dim]  {ev.event_type:<16} {ev.ip:<16} {ev.detail}[/]"
            )
    counts: dict[str, int] = {}
    for ev in events:
        counts[ev.event_type] = counts.get(ev.event_type, 0) + 1
    parts = ", ".join(f"{n} {t}" for t, n in sorted(counts.items()))
    console.print(f"[cyan]History:[/] {parts} since last scan.")


def _debug_print_signals(hosts, console: "Console") -> None:
    """Print raw signal counts per host for --debug inspection."""
    from rich.table import Table
    from rich import box

    table = Table(title="[dim]Debug: per-host signals[/]", box=box.SIMPLE,
                  show_header=True, header_style="dim")
    table.add_column("IP", style="dim")
    table.add_column("Signals")
    table.add_column("Ports")
    table.add_column("Conf")
    table.add_column("Flags")
    for h in hosts:
        sigs = ", ".join(h.signals.keys()) if h.signals else "—"
        ports = ", ".join(str(p) for p in h.open_ports[:6]) if h.open_ports else "—"
        flags = " ".join(h.risk_flags) if h.risk_flags else "—"
        table.add_row(h.ip, sigs, ports, str(h.confidence), flags)
    console.print(table)


def _out_path(base: str | None, default_base: str, ext: str) -> str:
    """Resolve an output path for a given extension."""
    from pathlib import Path
    if not base:
        return f"{default_base}.{ext}"
    path = Path(base)
    return str(path if path.suffix.lower() == f".{ext}" else path.with_suffix(f".{ext}"))


def _write_exports(cfg, hosts, timestamp, duration, console: "Console") -> None:
    """Write JSON/CSV exports per --output / --out-file."""
    from .output import csv_export, json_export
    from .display.alerts import collect_alerts

    default_base = f"scan_{timestamp:%Y%m%d_%H%M%S}"
    target = ",".join(cfg.targets)

    try:
        if cfg.output in ("json", "both"):
            report = json_export.build_report(
                hosts, target=target, mode=cfg.mode, duration_secs=duration,
                timestamp=timestamp, alerts=collect_alerts(hosts),
            )
            path = json_export.export_json(report, _out_path(cfg.out_file, default_base, "json"))
            console.print(f"[green]Wrote JSON[/] -> {path}")
        if cfg.output in ("csv", "both"):
            path = csv_export.export_csv(hosts, _out_path(cfg.out_file, default_base, "csv"))
            console.print(f"[green]Wrote CSV[/] -> {path}")
    except OSError as exc:
        console.print(f"[red]Export failed:[/] {exc}")


def _annotate_oui(hosts) -> None:
    from .scanner.oui import OuiLookup
    lookup = OuiLookup()
    try:
        for host in hosts:
            lookup.annotate(host)
    finally:
        lookup.close()


def _run_port_scan(cfg, hosts, reporter) -> None:
    if cfg.no_ports:
        return
    from .scanner import port_scan
    reporter.phase(f"Port scan — {cfg.ports_profile} profile", "ports",
                   len(hosts) * len(cfg.ports))
    port_scan.scan_and_annotate(
        hosts, cfg.ports,
        concurrency=config.PORT_SCAN_CONCURRENCY,
        rate_pps=cfg.rate_pps,
        do_banner=not cfg.stealth,
        progress_cb=lambda: reporter.advance("ports"),
    )
    reporter.finish("ports")
    reporter.set_hosts(hosts)


def _run_protocols(cfg, hosts, reporter) -> None:
    # Skipped in quick (ARP+OUI only) and stealth (no active probing).
    if cfg.mode == "quick" or cfg.stealth:
        return
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .scanner import protocols

    reporter.phase("Fingerprinting — SNMP/NetBIOS/mDNS/UPnP/SMB/HTTP",
                   "probe", len(hosts))
    workers = min(50, max(4, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(protocols.probe_host, h,
                        do_snmp=not cfg.no_snmp, timeout=float(cfg.timeout))
            for h in hosts
        ]
        for _ in as_completed(futures):
            reporter.advance("probe")
    reporter.finish("probe")
    reporter.set_hosts(hosts)


def _print_final_report(cfg, hosts, poison, console: "Console") -> None:
    from .display.table import (build_host_table, build_poison_panel,
                                build_summary, filter_hosts, sort_hosts)
    from .display.alerts import build_alerts_panel, collect_alerts

    view = filter_hosts(hosts, cfg.filters) if cfg.filters else hosts
    view = sort_hosts(view, cfg.sort or "ip")

    console.print(build_host_table(view))
    if poison:
        console.print(build_poison_panel(poison))
    console.print(build_alerts_panel(collect_alerts(hosts)))
    console.print(build_summary(hosts))

    identified = sum(1 for h in hosts if h.vendor)
    randomized = sum(1 for h in hosts if "RANDOMIZED_MAC" in h.risk_flags)
    named = sum(1 for h in hosts if h.hostname)
    classified = sum(1 for h in hosts if h.device_type and h.device_type != "Unknown")
    line = (f"[green]{len(hosts)} host(s)[/] — {identified} vendor-identified, "
            f"{randomized} randomized, {named} named, {classified} classified")
    if cfg.filters:
        line += f"  ([yellow]{len(view)}[/] shown after filter)"
    console.print(line + ".")


def print_plan(cfg: ScanConfig, console: "Console") -> None:
    """Render the resolved scan plan as a table."""
    from rich.table import Table

    table = Table(title="Scan Plan", title_style="bold cyan", show_header=False,
                  box=None, pad_edge=False)
    table.add_column("k", style="dim")
    table.add_column("v")
    table.add_row("Targets", ", ".join(cfg.targets))
    table.add_row("Host addresses", str(cfg.hosts_total))
    table.add_row("Mode", cfg.mode)
    if cfg.discovery == "icmp":
        table.add_row("Discovery", "icmp (routable, cross-VLAN — IP only, no MAC)")
    else:
        table.add_row("Discovery", "arp (local broadcast domain — gives MAC)")
    port_note = "skipped" if cfg.no_ports else f"{cfg.ports_profile} ({len(cfg.ports)} ports)"
    table.add_row("Port scan", port_note)
    table.add_row("SNMP", "skipped" if cfg.no_snmp else "enabled")
    table.add_row("Rate cap", f"{cfg.rate_pps} pps")
    table.add_row("ARP timeout", f"{cfg.timeout}s")
    if cfg.watch:
        table.add_row("Watch", f"every {cfg.interval}s")
    if cfg.filters:
        table.add_row("Filters", ", ".join(f"{k}={v}" for k, v in cfg.filters.items()))
    if cfg.output:
        table.add_row("Output", f"{cfg.output} -> {cfg.out_file or 'auto'}")
    if cfg.known_file:
        table.add_row("Known file", cfg.known_file)
    table.add_row("History DB", cfg.history_db)
    console.print(table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
