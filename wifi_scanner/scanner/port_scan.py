"""TCP connect port scanner with banner grabbing.

Portable by design (see project memory): uses asyncio TCP **connect** scanning
rather than a scapy SYN scan, so it runs unprivileged on Linux/macOS/Windows and
— because it completes the handshake — can actually read service banners. A
scapy SYN mode can be added later as an optional privileged/stealth path.

The socket layer is reachable through an injectable `open_conn` coroutine so the
scheduling, banner, and service-detection logic is unit-testable without real
network I/O.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from .. import config
from .models import Host


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


# --------------------------------------------------------------------------- #
# Service identification (pure)
# --------------------------------------------------------------------------- #
_SERVER_HEADER = re.compile(r"server:\s*([^\r\n]+)", re.IGNORECASE)


def identify_service(port: int, banner: str) -> str:
    """Derive a human service label from a banner (+ port as a hint)."""
    text = banner.strip()
    low = text.lower()

    if text.startswith("SSH-"):
        return text.splitlines()[0][:60]          # e.g. SSH-2.0-OpenSSH_8.2p1
    if "http/" in low:
        match = _SERVER_HEADER.search(text)
        return f"HTTP {match.group(1).strip()}" if match else "HTTP"
    if low.startswith("220") and "ftp" in low:
        return f"FTP {text.splitlines()[0][:50]}"
    if low.startswith("220") and ("smtp" in low or "esmtp" in low):
        return f"SMTP {text.splitlines()[0][:50]}"
    if "mysql" in low:
        return "MySQL"
    if port == 23:
        return "Telnet"
    if port == 3389:
        return "RDP"
    if port == 5900:
        return "VNC"
    if text:
        return text.splitlines()[0][:50]
    return config.WELL_KNOWN_PORTS.get(port, "open")


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Spaces out connection starts to honour a packets-per-second cap."""

    def __init__(self, rate_pps: int):
        self.min_interval = (1.0 / rate_pps) if rate_pps else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if not self.min_interval:
            return
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            if self._next > now:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self.min_interval


# --------------------------------------------------------------------------- #
# Connection + banner
# --------------------------------------------------------------------------- #
async def _default_open_conn(ip: str, port: int, timeout: float):
    """Real connector — opens a TCP connection with a timeout."""
    return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)


async def _grab_banner(reader, writer, port: int, read_timeout: float) -> str:
    """Read a server-first banner; for HTTP-ish ports, prompt with a HEAD."""
    data = b""
    try:
        data = await asyncio.wait_for(
            reader.read(config.BANNER_BYTES), timeout=read_timeout
        )
    except (asyncio.TimeoutError, OSError):
        data = b""

    if not data and port in config.HTTP_PROBE_PORTS:
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(
                reader.read(config.BANNER_BYTES), timeout=read_timeout
            )
        except (asyncio.TimeoutError, OSError):
            data = b""

    return data.decode("latin-1", errors="replace") if data else ""


async def probe_port(
    ip: str,
    port: int,
    *,
    timeout: float,
    read_timeout: float,
    limiter: RateLimiter | None = None,
    open_conn=None,
    do_banner: bool = True,
) -> PortResult | None:
    """Probe one port; return a PortResult if open, else None."""
    open_conn = open_conn or _default_open_conn
    if limiter:
        await limiter.wait()

    try:
        reader, writer = await open_conn(ip, port, timeout)
    except (asyncio.TimeoutError, OSError):
        return None                                # closed / filtered

    banner = ""
    try:
        if do_banner:
            banner = await _grab_banner(reader, writer, port, read_timeout)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass

    return PortResult(port=port, service=identify_service(port, banner), banner=banner)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def scan_targets(
    hosts: list[Host],
    ports: list[int],
    *,
    timeout: float = config.PORT_SCAN_TIMEOUT,
    read_timeout: float = config.PORT_SCAN_READ_TIMEOUT,
    concurrency: int = config.PORT_SCAN_CONCURRENCY,
    rate_pps: int = 0,
    open_conn=None,
    do_banner: bool = True,
) -> dict[str, list[PortResult]]:
    """Scan every (host, port) pair under shared concurrency + rate limits."""
    semaphore = asyncio.Semaphore(concurrency)
    limiter = RateLimiter(rate_pps)
    results: dict[str, list[PortResult]] = {h.ip: [] for h in hosts}

    async def one(ip: str, port: int) -> None:
        async with semaphore:
            result = await probe_port(
                ip, port, timeout=timeout, read_timeout=read_timeout,
                limiter=limiter, open_conn=open_conn, do_banner=do_banner,
            )
        if result:
            results[ip].append(result)

    await asyncio.gather(
        *(one(h.ip, port) for h in hosts for port in ports)
    )
    return results


def scan_and_annotate(
    hosts: list[Host],
    ports: list[int],
    *,
    timeout: float = config.PORT_SCAN_TIMEOUT,
    read_timeout: float = config.PORT_SCAN_READ_TIMEOUT,
    concurrency: int = config.PORT_SCAN_CONCURRENCY,
    rate_pps: int = 0,
    open_conn=None,
    do_banner: bool = True,
) -> dict[str, list[PortResult]]:
    """Run the scan and write open_ports/services/risk-flags back onto hosts."""
    results = asyncio.run(
        scan_targets(
            hosts, ports, timeout=timeout, read_timeout=read_timeout,
            concurrency=concurrency, rate_pps=rate_pps, open_conn=open_conn,
            do_banner=do_banner,
        )
    )
    for host in hosts:
        found = sorted(results.get(host.ip, []), key=lambda r: r.port)
        host.open_ports = [r.port for r in found]
        host.services = {r.port: r.service for r in found}
        for result in found:
            flag = config.PORT_RISK_FLAGS.get(result.port)
            if flag and flag not in host.risk_flags:
                host.risk_flags.append(flag)
    return results
