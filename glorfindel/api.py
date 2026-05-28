from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as e:
    raise ImportError(
        "War Room requires extra dependencies: pip install eregion[war-room]"
    ) from e

app = FastAPI(title="Glorfindel War Room", docs_url=None, redoc_url=None)

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.get("/api/state")
async def state() -> dict:
    from glorfindel import escalations as esc_module
    from glorfindel.actions import active_blocks, active_isolations

    now = datetime.now(timezone.utc)
    isolations = {i["resource_id"]: i for i in active_isolations()}
    blocks: dict[str, list] = {}
    for b in active_blocks():
        blocks.setdefault(b["resource_id"], []).append(b)

    resources = []
    for resource_id in sorted(set(isolations) | set(blocks)):
        vm_name = resource_id.split("/")[-1]
        states = []
        if resource_id in isolations:
            states.append({
                "type": "isolated",
                "since": isolations[resource_id].get("isolated_at", ""),
            })
        for b in blocks.get(resource_id, []):
            states.append({
                "type": "blocked",
                "ip": b["ip"],
                "since": b.get("blocked_at", ""),
            })
        resources.append({
            "resource_id": resource_id,
            "vm_name": vm_name,
            "states": states,
        })

    return {
        "resources": resources,
        "escalations": esc_module.pending(),
        "now": now.isoformat(),
    }


@app.get("/api/watch/status")
async def watch_status() -> dict:
    """Heartbeat-based: watch writes ~/.glorfindel/watch_heartbeat every ~60s."""
    hb = Path.home() / ".glorfindel" / "watch_heartbeat"
    if not hb.exists():
        return {"status": "stopped"}
    try:
        ts = datetime.fromisoformat(hb.read_text().strip())
        age_s = (datetime.now(timezone.utc) - ts).total_seconds()
        if age_s < 90:
            return {
                "status": "running",
                "since": ts.isoformat(),
                "age_s": int(age_s),
            }
        return {"status": "stale", "age_s": int(age_s)}
    except Exception:
        return {"status": "unknown"}


@app.get("/api/scenarios")
async def scenarios() -> dict:
    candidates = [
        Path("scenarios/azure"),
        Path(__file__).parent.parent / "scenarios" / "azure",
    ]
    for d in candidates:
        if d.exists():
            return {
                "scenarios": [
                    {"name": f.stem, "path": str(f)}
                    for f in sorted(d.glob("*.yaml"))
                ]
            }
    return {"scenarios": []}


@app.get("/api/config")
async def config() -> dict:
    import os

    subscription = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    tenant = os.environ.get("AZURE_TENANT_ID", "")
    client_id = os.environ.get("AZURE_CLIENT_ID", "")

    # Detection history: workspaces + TTP coverage from recent signal files
    workspaces: set[str] = set()
    ttp_events: dict[str, set[str]] = {}
    runs = Path("runs")
    if runs.exists():
        for f in sorted(
            runs.glob("*_signals.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:10]:
            for line in f.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    ws = d.get("context", {}).get("workspace_id", "")
                    if ws:
                        workspaces.add(ws)
                    ttp = d.get("ttp", "")
                    event = d.get("event", "")
                    if ttp and event in ("detection", "detection_timeout"):
                        ttp_events.setdefault(ttp, set()).add(event)
                except Exception:
                    pass

    coverage = {
        ttp: {
            "detected": "detection" in events,
            "timeout": "detection_timeout" in events,
        }
        for ttp, events in sorted(ttp_events.items())
    }

    # Isolation files
    iso_dir = Path.home() / ".glorfindel" / "isolation"
    isolations = []
    if iso_dir.exists():
        for f in iso_dir.glob("*.json"):
            try:
                d = json.loads(f.read_text())
                isolations.append({
                    "vm": f.stem,
                    "isolated_at": d.get("isolated_at", ""),
                    "resource_id": d.get("resource_id", ""),
                })
            except Exception:
                pass

    # Block files
    blk_dir = Path.home() / ".glorfindel" / "blocks"
    blocks = []
    if blk_dir.exists():
        for f in blk_dir.glob("*.json"):
            try:
                entries = json.loads(f.read_text())
                if not isinstance(entries, list):
                    entries = [entries]
                for entry in entries:
                    blocks.append({
                        "vm": f.stem,
                        "ip": entry.get("ip", ""),
                        "blocked_at": entry.get("blocked_at", ""),
                    })
            except Exception:
                pass

    return {
        "azure": {
            "subscription_id": subscription,
            "tenant_id": tenant,
            "client_id": client_id,
            "configured": bool(subscription and tenant and client_id),
        },
        "detection": {
            "workspaces": sorted(workspaces),
            "coverage": coverage,
        },
        "state": {
            "isolations": isolations,
            "blocks": blocks,
        },
    }


@app.get("/api/feed/history")
async def feed_history() -> dict:
    return {"entries": _load_recent(40)}


@app.websocket("/api/feed")
async def feed_ws(ws: WebSocket) -> None:
    await ws.accept()

    positions: dict[str, int] = {}
    runs = Path("runs")

    def _init() -> None:
        if not runs.exists():
            return
        for pat in ("*_signals.jsonl", "*_debug.jsonl"):
            for f in runs.glob(pat):
                positions[str(f)] = f.stat().st_size

    _init()

    for entry in _load_recent(40):
        await ws.send_json(entry)

    try:
        while True:
            await asyncio.sleep(2)
            if not runs.exists():
                continue
            for pat, kind in (
                ("*_signals.jsonl", "signal"),
                ("*_debug.jsonl", "action"),
            ):
                for f in runs.glob(pat):
                    key = str(f)
                    # Files not seen at _init() are new — read from start
                    prev = positions.get(key, 0)
                    cur = f.stat().st_size
                    if cur <= prev:
                        positions[key] = cur
                        continue
                    with open(f) as fh:
                        fh.seek(prev)
                        for raw in fh:
                            raw = raw.strip()
                            if not raw:
                                continue
                            try:
                                entry = _parse(json.loads(raw), kind)
                                await ws.send_json(entry)
                            except Exception:
                                pass
                        positions[key] = fh.tell()
    except WebSocketDisconnect:
        pass


@app.post("/api/action/revert/{vm_name}")
async def action_revert(vm_name: str) -> dict:
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"No active actions found for {vm_name}"}
    result = subprocess.run(
        [_bin(), "revert", resource_id, "--yes"],
        capture_output=True, text=True, timeout=60,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "ok": result.returncode == 0,
    }


@app.post("/api/action/restore/{vm_name}")
async def action_restore(vm_name: str) -> dict:
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"Resource ID not found for {vm_name}"}
    asyncio.create_task(_bg_restore(resource_id))
    return {"status": "started", "resource_id": resource_id}


@app.post("/api/action/ack/{esc_id}")
async def action_ack(esc_id: str) -> dict:
    from glorfindel import escalations as esc_module
    esc_module.resolve(esc_id)
    return {"ok": True}


async def _bg_restore(resource_id: str) -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: subprocess.run(
            [_bin(), "restore", resource_id, "--yes"],
            capture_output=True, text=True, timeout=1800,
        ),
    )


def _find_resource_id(vm_name: str) -> str | None:
    from glorfindel.actions import active_blocks, active_isolations

    for i in active_isolations():
        if i["resource_id"].split("/")[-1] == vm_name:
            return i["resource_id"]
    for b in active_blocks():
        if b["resource_id"].split("/")[-1] == vm_name:
            return b["resource_id"]
    return None


def _bin() -> str:
    c = Path(sys.executable).parent / "glorfindel"
    return str(c) if c.exists() else "glorfindel"


def _load_recent(n: int) -> list[dict]:
    runs = Path("runs")
    if not runs.exists():
        return []

    sig_files = sorted(
        runs.glob("*_signals.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    dbg_files = sorted(
        runs.glob("*_debug.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not sig_files and not dbg_files:
        return []

    name = sig_files[0].name if sig_files else dbg_files[0].name
    prefix = name.replace("_signals.jsonl", "").replace("_debug.jsonl", "")
    entries: list[tuple[str, dict]] = []

    for path, kind in [
        (runs / f"{prefix}_signals.jsonl", "signal"),
        (runs / f"{prefix}_debug.jsonl", "action"),
    ]:
        if path.exists():
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    entries.append((d.get("timestamp", ""), _parse(d, kind)))
                except Exception:
                    pass

    entries.sort(key=lambda x: x[0])
    return [e for _, e in entries[-n:]]


def _parse(data: dict, kind: str) -> dict:
    if kind == "signal":
        return {
            "type": "signal",
            "timestamp": data.get("timestamp", ""),
            "event": data.get("event", ""),
            "ttp": data.get("ttp", ""),
            "severity": data.get("severity", ""),
            "vm": data.get("resource_id", "").split("/")[-1],
        }
    sig = data.get("signal", {})
    outcome = data.get("outcome", {})
    return {
        "type": "action",
        "timestamp": data.get("timestamp", ""),
        "action": data.get("action", ""),
        "escalate": data.get("escalate", False),
        "confidence": data.get("confidence", 0),
        "verified": outcome.get("verified"),
        "ttp": sig.get("ttp", ""),
        "vm": sig.get("resource_id", "").split("/")[-1],
    }


def serve(host: str = "0.0.0.0", port: int = 7007) -> None:
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "War Room requires extra dependencies: "
            "pip install eregion[war-room]"
        ) from e
    print(f"  War Room  →  http://localhost:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
