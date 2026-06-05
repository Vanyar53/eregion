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

    # Discovered assets — fresh read from disk (watch service may have updated the file)
    discovered: list[dict] = []
    try:
        from glorfindel.discovery import AssetRegistry
        discovered = AssetRegistry().to_dicts()
    except Exception:
        pass

    # Posture gaps (infrastructure readiness issues)
    posture_gaps: list[dict] = []
    try:
        from glorfindel.posture import PostureChecker
        from glorfindel.config import load_glorfindel_config
        _gcfg = load_glorfindel_config()
        _pc = PostureChecker(_gcfg, None, dry_run=True)
        posture_gaps = _pc.active_gaps()
    except Exception:
        pass

    return {
        "resources": resources,
        "escalations": esc_module.pending(),
        "restores": _active_restores(),
        "discovered_assets": discovered,
        "posture_gaps": posture_gaps,
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
        Path("annatar/scenarios/azure"),
        Path(__file__).parent.parent / "annatar" / "scenarios" / "azure",
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

    # Load Glorfindel infra config (glorfindel-config.yaml)
    try:
        from glorfindel.config import load_glorfindel_config
        glorfindel_cfg = load_glorfindel_config()
        glorfindel_cfg_dict = {
            "monitoring_backends": [
                {"name": b.name, "type": b.type,
                 "workspace_id": b.workspace_id[:8] + "…" if b.workspace_id else "",
                 "discovery_enabled": b.discovery.enabled,
                 "discovery_interval_s": b.discovery.interval_s}
                for b in glorfindel_cfg.monitoring_backends
            ],
            "action_backends": [
                {"name": b.name, "type": b.type, "vault_name": b.vault_name}
                for b in glorfindel_cfg.action_backends
            ],
            "exceptions_count": len(glorfindel_cfg.exceptions),
        }
    except Exception:
        glorfindel_cfg_dict = {"monitoring_backends": [], "action_backends": [], "exceptions_count": 0}

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

    # Detection config (backends, assets, rules)
    rules_info: list[dict] = []
    known_resources: list[dict] = []
    backends_info: list[dict] = []
    assets_info: list[dict] = []
    rules_candidates = [
        Path("glorfindel/rules/azure/detection_rules.yaml"),
        Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml",
    ]
    rules_path: Path | None = next(
        (p for p in rules_candidates if p.exists()), None
    )
    if rules_path:
        try:
            from glorfindel.detection_rules import _load_status, load_config
            cfg = load_config(rules_path, glorfindel_cfg=glorfindel_cfg)
            status = _load_status()

            for b in cfg.backends:
                backends_info.append({
                    "name": b.name,
                    "type": b.type,
                    "workspace_id": b.workspace_id,
                    "endpoint": b.endpoint,
                })

            # Action backends (RSV, storage...) from glorfindel-config.yaml
            for b in glorfindel_cfg.action_backends:
                assets_info.append({
                    "name": b.name,
                    "type": b.type,
                    "resource_id": "",
                    "monitoring_backends": [],
                    "vault_name": b.vault_name,
                    "resource_group": b.resource_group,
                })

            for rule in cfg.rules:
                s = status.get(rule.name, {})
                rules_info.append({
                    "name": rule.name,
                    "ttp": rule.ttp,
                    "source": rule.source,
                    "description": rule.description,
                    "query": rule.query,
                    "interval_s": rule.interval_s,
                    "asset_name": rule.asset_name,
                    "monitoring_backend_name": rule.monitoring_backend_name,
                    "last_poll": s.get("last_poll", ""),
                    "last_match": s.get("last_match", ""),
                    "last_error": s.get("last_error", ""),
                    "match_count": s.get("match_count", 0),
                })
        except Exception:
            pass

    llm_model = (
        os.environ.get("GLORFINDEL_LLM_MODEL") or "anthropic/claude-sonnet-4-6"
    )
    llm_provider = llm_model.split("/")[0] if "/" in llm_model else llm_model

    return {
        "azure": {
            "subscription_id": subscription,
            "tenant_id": tenant,
            "client_id": client_id,
            "configured": bool(subscription and tenant and client_id),
        },
        "llm": {
            "model": llm_model,
            "provider": llm_provider,
            "base_url": os.environ.get("GLORFINDEL_LLM_BASE_URL", ""),
        },
        "detection": {
            "rules": rules_info,
            "rules_file": str(rules_path) if rules_path else None,
        },
        "monitoring_backends": backends_info,
        "assets": assets_info,
        "known_resources": known_resources,
        "glorfindel_config": glorfindel_cfg_dict,
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
        for pat in ("*_signals.jsonl", "*_debug.jsonl", "manual_actions.jsonl"):
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
                ("manual_actions.jsonl", "action"),
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


@app.post("/api/action/release/{vm_name}")
async def action_release(vm_name: str) -> dict:
    """Release isolation only — use after restore when the VM is clean."""
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"No active isolation found for {vm_name}"}
    result = await asyncio.to_thread(
        subprocess.run,
        [_bin(), "release", resource_id, "--yes"],
        capture_output=True, text=True, timeout=60,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "ok": result.returncode == 0,
    }


@app.post("/api/action/revert/{vm_name}")
async def action_revert(vm_name: str) -> dict:
    """Full reset — release isolation + unblock all IPs."""
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"No active actions found for {vm_name}"}
    result = await asyncio.to_thread(
        subprocess.run,
        [_bin(), "reset", resource_id, "--yes"],
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
    _restore_start(vm_name, resource_id)
    asyncio.create_task(_bg_restore(resource_id, vm_name))
    return {"status": "started", "resource_id": resource_id}


@app.post("/api/action/ack/{esc_id}")
async def action_ack(esc_id: str) -> dict:
    from glorfindel import escalations as esc_module
    esc_module.resolve(esc_id)
    return {"ok": True}


@app.get("/api/audit/{vm_name}")
async def audit_resource(vm_name: str) -> dict:
    """Remediation readiness audit for a single resource."""
    from glorfindel import audit as _audit
    from glorfindel.actions import AzureConnector

    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        rules_candidates = [
            Path("glorfindel/rules/azure/detection_rules.yaml"),
            Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml",
        ]
        rp = next((p for p in rules_candidates if p.exists()), None)
        if rp:
            from glorfindel.discovery import AssetRegistry
            for asset in AssetRegistry().all():
                if asset.name == vm_name or asset.resource_id.split("/")[-1] == vm_name:
                    resource_id = asset.resource_id
                    break
    if not resource_id:
        return {"error": f"resource_id not found for {vm_name}"}

    connector = AzureConnector(dry_run=False)
    # Run blocking Azure SDK calls in a thread pool — prevents event loop stall.
    result = await asyncio.to_thread(_audit.run, resource_id, connector)
    return result.to_dict()


@app.get("/api/audit")
async def audit_all() -> dict:
    """Remediation readiness audit for all assets in detection_rules.yaml."""
    from glorfindel import audit as _audit
    from glorfindel.actions import AzureConnector
    from glorfindel.detection_rules import load_config

    rules_candidates = [
        Path("glorfindel/rules/azure/detection_rules.yaml"),
        Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml",
    ]
    rp = next((p for p in rules_candidates if p.exists()), None)
    if not rp:
        return {"audits": []}

    connector = AzureConnector(dry_run=False)

    # Vault name: from glorfindel-config.yaml action_backends (source of truth)
    try:
        from glorfindel.config import load_glorfindel_config
        _cfg = load_glorfindel_config()
        rsv = _cfg.backup_vault()
        vault = rsv.vault_name if rsv and rsv.vault_name else os.environ.get("GLORFINDEL_BACKUP_VAULT", "rsv-annatar")
    except Exception:
        vault = os.environ.get("GLORFINDEL_BACKUP_VAULT", "rsv-annatar")
        _cfg = None

    # VM targets: fresh read from disk (watch service may have updated the file)
    from glorfindel.discovery import AssetRegistry
    discovered = AssetRegistry().all()
    targets = [(a.resource_id, a.name) for a in discovered if a.resource_id]
    if not targets:
        # Legacy fallback: rules with inline resource_id
        from glorfindel.detection_rules import load_config
        cfg = load_config(rp, glorfindel_cfg=_cfg)
        targets = [
            (r.resource_id, r.asset_name or r.resource_id.split("/")[-1])
            for r in cfg.rules
            if r.resource_id and "${" not in r.resource_id
        ]

    # Deduplicate, then run all audits concurrently in thread pool threads.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for rid, asset_name in targets:
        if rid not in seen:
            seen.add(rid)
            unique.append((rid, asset_name))

    async def _audit_one(rid: str, asset_name: str) -> dict:
        result = await asyncio.to_thread(_audit.run, rid, connector, vault)
        d = result.to_dict()
        d["vault"] = vault
        d["asset_name"] = asset_name
        return d

    audits = await asyncio.gather(*(_audit_one(rid, name) for rid, name in unique))
    return {"audits": list(audits)}


@app.get("/api/actions/{vm_name}")
async def vm_actions(vm_name: str, limit: int = 5) -> dict:
    """Return recent Glorfindel decisions for a VM (reasoning + confidence)."""
    import time as _time
    runs = Path("runs")
    if not runs.exists():
        return {"actions": []}

    cutoff = _time.time() - 24 * 3600
    actions: list[dict] = []

    for f in sorted(
        runs.glob("*_debug.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if f.stat().st_mtime < cutoff:
            break
        for line in reversed(f.read_text().splitlines()):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                rid = (d.get("signal") or {}).get("resource_id", "")
                if rid.split("/")[-1] != vm_name:
                    continue
                action = d.get("action", "")
                if not action or action in ("snapshot", "improve_detection"):
                    continue
                import re as _re
                full = d.get("reasoning") or ""
                # Strip markdown for display
                full_clean = _re.sub(r'\*\*(.*?)\*\*', r'\1', full)
                full_clean = _re.sub(r'\*(.*?)\*', r'\1', full_clean).strip()
                actions.append({
                    "action": action,
                    "reasoning": _extract_conclusion(full),
                    "full_reasoning": full_clean[:2000],
                    "confidence": d.get("confidence"),
                    "timestamp": d.get("timestamp", ""),
                    "outcome": (d.get("outcome") or {}).get("status", ""),
                    "ttp": (d.get("signal") or {}).get("ttp", ""),
                    "escalate": d.get("escalate", False),
                })
                if len(actions) >= limit:
                    break
            except Exception:
                pass
        if len(actions) >= limit:
            break

    return {"actions": actions}


@app.get("/api/discovered")
async def discovered_assets() -> dict:
    """Return assets discovered from monitoring backends."""
    try:
        from glorfindel.discovery import AssetRegistry
        return {"assets": AssetRegistry().to_dicts()}
    except Exception:
        return {"assets": []}


@app.get("/api/pending/rules")
async def pending_rules() -> dict:
    from glorfindel.proposed_rules import pending
    return {"proposals": pending()}


@app.post("/api/action/approve-rule/{proposal_id}")
async def approve_rule(proposal_id: str) -> dict:
    rules_candidates = [
        Path("glorfindel/rules/azure/detection_rules.yaml"),
        Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml",
    ]
    rules_path = next((p for p in rules_candidates if p.exists()), None)
    if not rules_path:
        return {"error": "detection_rules.yaml not found"}
    try:
        from glorfindel.proposed_rules import approve
        proposal = approve(proposal_id, rules_path)
        return {"ok": True, "rule_name": proposal["rule_name"]}
    except ValueError as e:
        return {"error": str(e)}


@app.post("/api/action/reject-rule/{proposal_id}")
async def action_reject_rule(proposal_id: str) -> dict:
    """Reject a proposed detection rule without adding it to detection_rules.yaml."""
    try:
        from glorfindel.proposed_rules import reject
        proposal = reject(proposal_id)
        return {"ok": True, "rule_name": proposal["rule_name"]}
    except ValueError as e:
        return {"error": str(e)}


_RESTORE_TRACKING = Path.home() / ".glorfindel" / "restore_in_progress.json"


def _restore_start(vm_name: str, resource_id: str) -> None:
    import json as _json
    data: dict = {}
    try:
        if _RESTORE_TRACKING.exists():
            data = _json.loads(_RESTORE_TRACKING.read_text())
    except Exception:
        pass
    data[vm_name] = {
        "resource_id": resource_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _RESTORE_TRACKING.parent.mkdir(parents=True, exist_ok=True)
    _RESTORE_TRACKING.write_text(_json.dumps(data))


def _restore_done(vm_name: str) -> None:
    import json as _json
    try:
        if not _RESTORE_TRACKING.exists():
            return
        data = _json.loads(_RESTORE_TRACKING.read_text())
        data.pop(vm_name, None)
        _RESTORE_TRACKING.write_text(_json.dumps(data))
    except Exception:
        pass


def _active_restores() -> list[dict]:
    import json as _json
    try:
        if not _RESTORE_TRACKING.exists():
            return []
        data = _json.loads(_RESTORE_TRACKING.read_text())
        now = datetime.now(timezone.utc)
        result = []
        for vm_name, info in data.items():
            started = datetime.fromisoformat(info["started_at"])
            elapsed_s = int((now - started).total_seconds())
            result.append({
                "vm_name": vm_name,
                "resource_id": info["resource_id"],
                "started_at": info["started_at"],
                "elapsed_s": elapsed_s,
                "elapsed_label": (
                    f"{elapsed_s // 60}m{elapsed_s % 60:02d}s"
                    if elapsed_s >= 60 else f"{elapsed_s}s"
                ),
            })
        return result
    except Exception:
        return []


async def _bg_restore(resource_id: str, vm_name: str = "") -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: subprocess.run(
            [_bin(), "restore", resource_id, "--yes"],
            capture_output=True, text=True, timeout=1800,
        ),
    )
    if vm_name:
        _restore_done(vm_name)


def _find_resource_id(vm_name: str) -> str | None:
    from glorfindel.actions import active_blocks, active_isolations

    for i in active_isolations():
        if i["resource_id"].split("/")[-1] == vm_name:
            return i["resource_id"]
    for b in active_blocks():
        if b["resource_id"].split("/")[-1] == vm_name:
            return b["resource_id"]

    # Fallback 1: pending escalations (e.g. restore_from_backup without prior isolation)
    try:
        from glorfindel import escalations as _esc
        for esc in _esc.pending():
            rid = esc.get("resource_id", "")
            if rid.split("/")[-1] == vm_name:
                return rid
    except Exception:
        pass

    # Fallback 2: discovered asset registry (fresh read from disk)
    try:
        from glorfindel.discovery import AssetRegistry
        for asset in AssetRegistry().all():
            if asset.name == vm_name or asset.resource_id.split("/")[-1] == vm_name:
                return asset.resource_id
    except Exception:
        pass

    return None


def _write_manual_feed(action: str, resource_id: str, outcome: dict) -> None:
    """Write an operator action entry to runs/manual_actions.jsonl for the live feed."""
    runs = Path("runs")
    runs.mkdir(exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "confidence": 1.0,
        "escalate": False,
        "signal": {"resource_id": resource_id, "ttp": "", "severity": ""},
        "outcome": outcome,
    }
    with open(runs / "manual_actions.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def _extract_conclusion(text: str, max_chars: int = 120) -> str:
    """Extract the conclusion from a step-by-step LLM reasoning.

    The reasoning is typically structured as:
        Étape 1 – ... (preamble)
        Étape 2 – ... (analysis)
        Étape N – ... (conclusion / action decision)

    We take the LAST step chunk since it contains the decision rationale,
    not the first which is always the preamble.
    """
    import re
    clean = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    clean = re.sub(r'\*(.*?)\*', r'\1', clean)
    # Split on step markers (Étape N / Step N) — any variant
    parts = re.split(r'(?i)(?:étape|step)\s+\d+\s*[–\-:]', clean)
    # Take the last non-trivial chunk (usually the conclusion)
    chunk = next(
        (p.strip() for p in reversed(parts) if len(p.strip()) > 20),
        clean,
    )
    # First sentence of that chunk
    sentence = re.split(r'[.!?]\s+', chunk)[0] or chunk
    return sentence.strip()[:max_chars]


def _bin() -> str:
    c = Path(sys.executable).parent / "glorfindel"
    return str(c) if c.exists() else "glorfindel"


def _load_recent(n: int, window_h: float = 4.0) -> list[dict]:
    """Load recent feed entries across all runs in the last window_h hours."""
    runs = Path("runs")
    if not runs.exists():
        return []

    import time as _time
    cutoff = _time.time() - window_h * 3600
    entries: list[tuple[str, dict]] = []

    for pat, kind in [
        ("*_signals.jsonl", "signal"),
        ("*_debug.jsonl", "action"),
    ]:
        for f in runs.glob(pat):
            if f.stat().st_mtime < cutoff:
                continue
            for line in f.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    entries.append(
                        (d.get("timestamp", ""), _parse(d, kind))
                    )
                except Exception:
                    pass

    manual = runs / "manual_actions.jsonl"
    if manual.exists():
        for line in manual.read_text().splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                entries.append((d.get("timestamp", ""), _parse(d, "action")))
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
