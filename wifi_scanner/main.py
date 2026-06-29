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
@click.option("--dry-run", is_flag=True, help="Show the scan plan without sending packets.")
@click.version_option(__version__, "-V", "--version", prog_name="wifi-scanner")
def cli(target, mode, ports_profile, timeout, rate_pps, watch, interval, sort,
        filter_expr, output, out_file, no_ports, no_snmp, stealth, known_file,
        history_db, verbose, debug, update_oui, dry_run):
    """Office WiFi/LAN scanner — authorized network reconnaissance."""
    from rich.console import Console
    console = Console()

    targets = parse_targets(target)
    cfg = ScanConfig(
        targets=targets,
        mode=mode,
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
    """Execute a scan. Checkpoints 2-3: ARP discovery, OUI vendor lookup,
    randomized-MAC flagging, and table output.

    Port scanning and fingerprinting land in later checkpoints.
    """
    from .scanner import arp
    from .scanner.oui import OuiLookup
    from .display.table import build_host_table, build_poison_panel

    ensure_oui_db(console)

    console.print(f"\n[cyan]ARP sweep[/] across {', '.join(cfg.targets)} …")
    hosts, alerts = arp.arp_sweep(
        cfg.targets,
        timeout=cfg.timeout,
        retries=config.DEFAULT_ARP_RETRIES,
        rate_pps=cfg.rate_pps,
    )

    if not hosts:
        console.print(
            "[yellow]No hosts answered.[/] On WSL2 this usually means "
            "mirrored networking isn't active — see the note above."
        )
        return

    # Vendor resolution + randomized-MAC flagging
    lookup = OuiLookup()
    try:
        for host in hosts:
            lookup.annotate(host)
    finally:
        lookup.close()

    # Port scan + banner grabbing (full mode; skipped by --no-ports / quick)
    if not cfg.no_ports:
        from .scanner import port_scan

        do_banner = not cfg.stealth
        console.print(
            f"[cyan]Port scan[/] — {len(cfg.ports)} ports/host "
            f"({cfg.ports_profile} profile)"
            + ("" if do_banner else ", banners disabled (stealth)") + " …"
        )
        port_scan.scan_and_annotate(
            hosts, cfg.ports,
            concurrency=config.PORT_SCAN_CONCURRENCY,
            rate_pps=cfg.rate_pps,
            do_banner=do_banner,
        )

    randomized = sum(1 for h in hosts if "RANDOMIZED_MAC" in h.risk_flags)
    identified = sum(1 for h in hosts if h.vendor)
    with_ports = sum(1 for h in hosts if h.open_ports)

    console.print(build_host_table(hosts))
    if alerts:
        console.print(build_poison_panel(alerts))
    summary = (
        f"\n[green]{len(hosts)} host(s) discovered[/] — "
        f"{identified} vendor-identified, {randomized} randomized MAC(s)"
    )
    if not cfg.no_ports:
        summary += f", {with_ports} with open ports"
    console.print(summary + ".")


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
