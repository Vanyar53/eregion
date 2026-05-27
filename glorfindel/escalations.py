from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_STORE = Path.home() / ".glorfindel" / "escalations.jsonl"


def record(
    signal_id: str,
    resource_id: str,
    action: str,
    escalation_type: str,
    reason: str,
    run_id: str = "",
    suggested_steps: list[str] | None = None,
) -> str:
    """Append an escalation and return its id."""
    esc = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signal_id": signal_id,
        "resource_id": resource_id,
        "action": action,
        "escalation_type": escalation_type,
        "reason": reason,
        "run_id": run_id,
        "suggested_steps": suggested_steps or [],
        "status": "pending",
        "resolved_at": None,
    }
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STORE, "a") as f:
        f.write(json.dumps(esc) + "\n")
    _notify(esc)
    return esc["id"]


def resolve(escalation_id: str) -> None:
    """Mark an escalation as resolved."""
    if not _STORE.exists():
        return
    lines = _STORE.read_text().splitlines()
    updated = []
    for line in lines:
        e = json.loads(line)
        if e["id"] == escalation_id:
            e["status"] = "resolved"
            e["resolved_at"] = datetime.now(timezone.utc).isoformat()
        updated.append(json.dumps(e))
    _STORE.write_text("\n".join(updated) + "\n")


def resolve_by_resource(resource_id: str, action: str) -> int:
    """Resolve all pending escalations matching resource_id + action. Returns count."""
    if not _STORE.exists():
        return 0
    lines = _STORE.read_text().splitlines()
    updated = []
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for line in lines:
        e = json.loads(line)
        if (
            e["status"] == "pending"
            and e["resource_id"] == resource_id
            and e["action"] == action
        ):
            e["status"] = "resolved"
            e["resolved_at"] = now
            count += 1
        updated.append(json.dumps(e))
    _STORE.write_text("\n".join(updated) + "\n")
    return count


def pending() -> list[dict]:
    """Return all unresolved escalations, oldest first."""
    if not _STORE.exists():
        return []
    result = []
    for line in _STORE.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e["status"] == "pending":
            result.append(e)
    return result


def notify_action(
    action: str,
    resource_id: str,
    run_id: str,
    confidence: float,
    explanation: str,
    verified: bool | None,
) -> None:
    """POST an autonomous action notification to GLORFINDEL_WEBHOOK_URL if set."""
    import os
    url = os.environ.get("GLORFINDEL_WEBHOOK_URL", "")
    if not url:
        return
    try:
        import requests
        resource_short = resource_id.split("/")[-1]
        status = "✓ verified" if verified else ("⚠ unverified" if verified is None else "✗ failed")
        requests.post(url, json={
            "text": (
                f":robot_face: *Glorfindel autonomous action* — `{action}` "
                f"on `{resource_short}` {status}\n"
                f"> {explanation[:500]}\n"
                f"Confidence: {int(confidence * 100)}% | Run: `{run_id}`"
            )
        }, timeout=5)
    except Exception:
        pass  # notification failure must never block the agent


def _notify(esc: dict) -> None:
    """POST an escalation notification to GLORFINDEL_WEBHOOK_URL if set."""
    import os
    url = os.environ.get("GLORFINDEL_WEBHOOK_URL", "")
    if not url:
        return
    try:
        import requests
        resource_short = esc["resource_id"].split("/")[-1]
        requests.post(url, json={
            "text": (
                f":rotating_light: *Glorfindel escalation* — `{esc['action']}` "
                f"on `{resource_short}`\n"
                f"> {esc['reason'][:500]}\n"
                f"Run: `{esc['run_id']}`"
            )
        }, timeout=5)
    except Exception:
        pass  # notification failure must never block the agent
