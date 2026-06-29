"""Real-time scan dashboard (rich.Live) + a static fallback reporter.

Both expose the same small interface (phase / advance / finish / set_hosts) so
the scan pipeline can drive either one. The live dashboard composes a header,
phase progress bars, a cropped device-table preview, an alerts panel, and a
summary line; it's transient, so after the scan the caller prints the full
final report. The static reporter just emits phase lines (used for non-TTY
output and tests).
"""

from __future__ import annotations

import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text

from .alerts import build_alerts_panel, collect_alerts
from .table import build_host_table, build_summary, filter_hosts, sort_hosts


class StaticReporter:
    """No-frills reporter: prints a line per phase, ignores progress."""

    def __init__(self, cfg, console: Console):
        self.cfg = cfg
        self.console = console
        self.hosts: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def phase(self, name: str, key: str | None = None, total: int = 1) -> None:
        self.console.print(f"[cyan]{name}[/] …")

    def advance(self, key: str, n: int = 1) -> None:
        pass

    def finish(self, key: str) -> None:
        pass

    def set_hosts(self, hosts: list) -> None:
        self.hosts = hosts


class LiveDashboard:
    """Full-screen live dashboard driven by the scan pipeline."""

    def __init__(self, cfg, console: Console, max_device_rows: int = 16):
        self.cfg = cfg
        self.console = console
        self.max_device_rows = max_device_rows
        self.hosts: list = []
        self.phase_name = "Initializing"
        self.start = time.monotonic()
        self._last = 0.0
        self._tasks: dict[str, int] = {}
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            expand=False,
        )
        self.live = Live(self._render(), console=console, refresh_per_second=6,
                         transient=True)

    # -- lifecycle -------------------------------------------------------- #
    def __enter__(self):
        self.live.__enter__()
        return self

    def __exit__(self, *exc):
        return self.live.__exit__(*exc)

    # -- pipeline interface ---------------------------------------------- #
    def phase(self, name: str, key: str | None = None, total: int = 1) -> None:
        self.phase_name = name
        if key and key not in self._tasks:
            self._tasks[key] = self.progress.add_task(name, total=max(1, total))
        self._update(force=True)

    def advance(self, key: str, n: int = 1) -> None:
        if key in self._tasks:
            self.progress.advance(self._tasks[key], n)
        self._update()

    def finish(self, key: str) -> None:
        if key in self._tasks:
            task = self.progress.tasks[self._tasks[key]]
            self.progress.update(self._tasks[key], completed=task.total)
        self._update(force=True)

    def set_hosts(self, hosts: list) -> None:
        self.hosts = hosts
        self._update(force=True)

    # -- rendering -------------------------------------------------------- #
    def _update(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last < 0.15:    # throttle heavy rebuilds
            return
        self._last = now
        self.live.update(self._render())

    def _header(self) -> Panel:
        elapsed = int(time.monotonic() - self.start)
        mm, ss = divmod(elapsed, 60)
        title = Text("OFFICE NETWORK SCANNER", style="bold cyan")
        title.append(f"   │   {', '.join(self.cfg.targets)}   │   ", style="white")
        title.append("SCANNING", style="bold yellow")
        line2 = Text(
            f"Hosts: {len(self.hosts)}    Elapsed: {mm:d}m{ss:02d}s    "
            f"Phase: {self.phase_name}",
            style="dim",
        )
        return Panel(Group(title, line2), border_style="cyan", expand=False)

    def _devices(self):
        hosts = self.hosts
        if self.cfg.filters:
            hosts = filter_hosts(hosts, self.cfg.filters)
        hosts = sort_hosts(hosts, self.cfg.sort or "ip")
        return build_host_table(hosts, max_rows=self.max_device_rows)

    def _render(self) -> Group:
        alerts = collect_alerts(self.hosts)
        return Group(
            self._header(),
            self.progress,
            self._devices(),
            build_alerts_panel(alerts, max_rows=6),
            build_summary(self.hosts),
        )
