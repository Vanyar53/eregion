from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_STORE = Path.home() / ".glorfindel" / "escalations.jsonl"


_ACTION_LABELS = {
    "isolate_vm": "VM isolée du réseau",
    "release_isolation": "Isolation levée",
    "snapshot": "Snapshot forensique créé",
    "block_suspicious_ip": "IP suspecte bloquée",
    "revoke_temp_access": "Accès temporaire révoqué",
    "restore_from_backup": "Restauration depuis backup",
    "delete_resource": "Ressource supprimée",
    "wipe_storage": "Stockage effacé",
    "modify_network_rule": "Règle réseau modifiée",
    "escalate_permissions": "Permissions élevées",
    "improve_detection": "Règle de détection proposée",
}

_ESCALATION_LABELS = {
    "low_confidence": "detection timeout",
    "destructive_action": "action destructive",
    "proposed_action": "action inconnue",
    "verification_failed": "vérification échouée",
    "proposed_rule": "règle de détection proposée",
    "posture_gap": "gap de posture",
}


def record(
    signal_id: str,
    resource_id: str,
    action: str,
    escalation_type: str,
    reason: str,
    run_id: str = "",
    suggested_steps: list[str] | None = None,
    ttp: str = "",
    severity: str = "",
    proposal_id: str = "",
    proposed_query: str = "",
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
        "ttp": ttp,
        "severity": severity,
        "proposal_id": proposal_id,
        "proposed_query": proposed_query,
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
    """Resolve all pending escalations matching resource_id + action."""
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
    ttp: str = "",
    severity: str = "",
) -> None:
    """POST an autonomous action notification to the webhook if set."""
    import os
    url = os.environ.get("GLORFINDEL_WEBHOOK_URL", "")
    if not url:
        return
    try:
        import requests
        resource_short = resource_id.split("/")[-1]
        label = _ACTION_LABELS.get(action, action)
        if verified:
            status = "✓"
        elif verified is None:
            status = "⚠"
        else:
            status = "✗"
        pct = f"{int(confidence * 100)}% confidence"
        meta = " · ".join(filter(None, [ttp, severity, pct]))
        requests.post(url, json={
            "text": (
                f":robot_face: *{label}* {status}  |  `{resource_short}`\n"
                f"`{action}` · {meta}\n"
                f"> {explanation[:800]}\n"
                f"`{run_id}`"
            )
        }, timeout=5)
    except Exception:
        pass  # notification failure must never block the agent


def _notify(esc: dict) -> None:
    """POST an escalation notification to GLORFINDEL_WEBHOOK_URL if set.

    Skipped when DISCORD_BOT_TOKEN is set — the bot handles escalations in
    per-VM threads, which is a better UX than a flat channel message.
    """
    import os
    if os.environ.get("DISCORD_BOT_TOKEN", ""):
        return
    url = os.environ.get("GLORFINDEL_WEBHOOK_URL", "")
    if not url:
        return
    try:
        import requests
        resource_short = esc["resource_id"].split("/")[-1]
        label = _ACTION_LABELS.get(esc["action"], esc["action"])
        type_label = _ESCALATION_LABELS.get(
            esc["escalation_type"], esc["escalation_type"]
        )
        parts = [esc.get("ttp", ""), esc.get("severity", ""), type_label]
        meta = " · ".join(filter(None, parts))
        requests.post(url, json={
            "text": (
                f":rotating_light: *{label}*  |  `{resource_short}`\n"
                f"`{esc['action']}` · {meta}\n"
                f"> {esc['reason'][:500]}\n"
                f"`{esc['run_id']}`"
            )
        }, timeout=5)
    except Exception:
        pass  # notification failure must never block the agent
