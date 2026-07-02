"""Web dashboard server for the office WiFi/LAN scanner.

Starts a FastAPI server that:
  - Serves the single-page dashboard at /
  - Exposes REST endpoints for current scan state and history
  - Accepts POST /api/scan to start a scan in a background thread
  - Streams live scan events to the browser via Server-Sent Events

Run with:
    sudo wifi-scan-web [--host 0.0.0.0] [--port 8000]

No authentication — office-LAN-only use. See README "Security" section.
"""

from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import config
from ..display.alerts import collect_alerts
from ..scanner.models import Host

_DASHBOARD = (Path(__file__).parent / "dashboard.html").read_text()


# --------------------------------------------------------------------------- #
# Shared scan state (thread-safe)
# --------------------------------------------------------------------------- #

class ScanState:
    """Single-instance shared state between the scan thread and SSE clients."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False
        self.phase = "idle"
        self.scan_num = 0
        self.started_at: datetime | None = None
        self.hosts: list[Host] = []
        self.poison: list = []
        self._listeners: list[queue.Queue] = []

    # -- subscription -------------------------------------------------------- #
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self._listeners.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._listeners.remove(q)
            except ValueError:
                pass

    def emit(self, event: dict) -> None:
        data = json.dumps(event, default=str)
        with self._lock:
            for q in self._listeners:
                try:
                    q.put_nowait(data)
                except queue.Full:
                    pass

    # -- lifecycle ----------------------------------------------------------- #
    def try_start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
            self.scan_num += 1
            self.started_at = datetime.now(timezone.utc)
            return True

    def finish(self) -> None:
        with self._lock:
            self.running = False
            self.phase = "idle"


_state = ScanState()


# --------------------------------------------------------------------------- #
# Reporter that feeds SSE events while the pipeline runs
# --------------------------------------------------------------------------- #

class SseReporter:
    """Implements the scanner reporter interface and pushes events to SSE."""

    def __init__(self, state: ScanState) -> None:
        self._state = state
        self.hosts: list[Host] = []
        self._tasks: dict[str, dict] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def phase(self, name: str, key: str | None = None, total: int = 1) -> None:
        self._state.phase = name
        if key:
            self._tasks[key] = {"completed": 0, "total": max(1, total)}
        self._state.emit({"type": "phase", "name": name, "key": key, "total": total})

    def advance(self, key: str, n: int = 1) -> None:
        if key in self._tasks:
            self._tasks[key]["completed"] += n
            t = self._tasks[key]
            self._state.emit({"type": "progress", "key": key,
                               "completed": t["completed"], "total": t["total"]})

    def finish(self, key: str) -> None:
        if key in self._tasks:
            t = self._tasks[key]
            self._state.emit({"type": "progress", "key": key,
                               "completed": t["total"], "total": t["total"]})

    def set_hosts(self, hosts: list) -> None:
        self.hosts = hosts
        self._state.hosts = hosts
        self._state.emit({"type": "hosts",
                           "hosts": [_host_dict(h) for h in hosts]})


# --------------------------------------------------------------------------- #
# Serialisation helpers
# --------------------------------------------------------------------------- #

def _host_dict(h: Host) -> dict:
    return {
        "ip": h.ip,
        "mac": h.mac,
        "mac_known": h.mac_known,
        "vendor": h.vendor,
        "hostname": h.hostname,
        "device_type": h.device_type,
        "device_subtype": h.device_subtype,
        "os": h.os,
        "model": h.model,
        "open_ports": h.open_ports,
        "services": {str(k): v for k, v in h.services.items()},
        "confidence": h.confidence,
        "confidence_label": h.confidence_label,
        "risk_flags": h.risk_flags,
        "response_time_ms": h.response_time_ms,
        "first_seen": h.first_seen.isoformat() if h.first_seen else None,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None,
    }


def _alert_dict(a) -> dict:
    return {"flag": a.flag, "ip": a.ip, "severity": a.severity, "message": a.message}


# --------------------------------------------------------------------------- #
# FastAPI application
# --------------------------------------------------------------------------- #

app = FastAPI(title="Network Scanner")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(_DASHBOARD)


@app.get("/api/status")
async def get_status():
    elapsed = None
    if _state.started_at:
        elapsed = (datetime.now(timezone.utc) - _state.started_at).total_seconds()
    return {
        "running": _state.running,
        "phase": _state.phase,
        "scan_num": _state.scan_num,
        "host_count": len(_state.hosts),
        "elapsed_secs": elapsed,
    }


@app.get("/api/hosts")
async def get_hosts():
    return JSONResponse([_host_dict(h) for h in _state.hosts])


@app.get("/api/alerts")
async def get_alerts():
    return JSONResponse([_alert_dict(a) for a in collect_alerts(_state.hosts)])


@app.get("/api/history")
async def get_history(limit: int = 40):
    try:
        from ..scanner.history import HistoryDB
        db = HistoryDB(str(config.HISTORY_DB_PATH))
        rows = db.recent_events(limit)
        events = [dict(r) for r in rows]
        db.close()
        return JSONResponse(events)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


class ScanRequest(BaseModel):
    target: str = config.DEFAULT_TARGET
    mode: str = "full"
    discovery: str = config.DEFAULT_DISCOVERY
    ports_profile: str = "common"
    no_ports: bool = False
    no_snmp: bool = False


@app.post("/api/scan")
async def trigger_scan(req: ScanRequest):
    if not _state.try_start():
        raise HTTPException(409, detail="A scan is already running")

    def _run() -> None:
        from rich.console import Console
        from ..main import (ScanConfig, _run_pipeline, _record_history,
                            apply_mode_overrides, count_hosts)

        console = Console(quiet=True)
        targets = [t.strip() for t in req.target.split(",") if t.strip()]
        cfg = ScanConfig(
            targets=targets,
            mode=req.mode,
            discovery=req.discovery,
            ports_profile=req.ports_profile,
            ports=config.PORT_PROFILES.get(req.ports_profile, config.PORTS_COMMON),
            timeout=config.DEFAULT_ARP_TIMEOUT,
            rate_pps=config.DEFAULT_RATE_PPS,
            watch=False, interval=60, sort="ip", filters={},
            output=None, out_file=None,
            no_ports=req.no_ports, no_snmp=req.no_snmp,
            stealth=False, known_file=None,
            history_db=str(config.HISTORY_DB_PATH),
            verbose=False, debug=False, dry_run=False,
        )
        cfg = apply_mode_overrides(cfg)
        cfg.hosts_total = count_hosts(cfg.targets)

        reporter = SseReporter(_state)
        try:
            hosts, poison = _run_pipeline(cfg, reporter, console)
            _state.hosts = hosts
            _state.poison = poison
            if hosts:
                _record_history(cfg, hosts, console)
            alerts = [_alert_dict(a) for a in collect_alerts(hosts)]
            _state.emit({
                "type": "complete",
                "host_count": len(hosts),
                "alerts": alerts,
            })
        except Exception as exc:
            _state.emit({"type": "error", "message": str(exc)})
        finally:
            _state.finish()

    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started", "scan_num": _state.scan_num}


@app.get("/api/scan/stream")
async def scan_stream():
    import asyncio

    q = _state.subscribe()
    initial = json.dumps({
        "type": "hosts",
        "hosts": [_host_dict(h) for h in _state.hosts],
    }, default=str)

    async def generate():
        yield f"data: {initial}\n\n"
        loop = asyncio.get_event_loop()
        try:
            while True:
                try:
                    data = await loop.run_in_executor(
                        None, lambda: q.get(timeout=25)
                    )
                    yield f"data: {data}\n\n"
                    parsed = json.loads(data)
                    if parsed.get("type") in ("complete", "error"):
                        break
                except queue.Empty:
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            _state.unsubscribe(q)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Network Scanner web dashboard")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind host [default: 0.0.0.0]")
    parser.add_argument("--port", type=int, default=8000,
                        help="Bind port [default: 8000]")
    parser.add_argument("--reload", action="store_true",
                        help="Auto-reload on code changes (dev mode)")
    args = parser.parse_args()

    print(f"\nNetwork Scanner dashboard → http://{args.host}:{args.port}/\n")
    uvicorn.run(
        "wifi_scanner.web.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
