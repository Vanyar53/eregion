from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_STORE = Path.home() / ".glorfindel" / "escalations.jsonl"

# A re-fired escalation refreshes its (LLM-generated) content only when confidence
# moves at least this much — keeps a standing card current without flickering its
# reason/steps on every poll for a stable finding.
_MATERIAL_CONFIDENCE_DELTA = 0.1


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
    "investigate_detection_gap": "Détection empêchée — enquête requise",
}

_ESCALATION_LABELS = {
    "low_confidence": "detection timeout",
    "destructive_action": "action destructive",
    "proposed_action": "action inconnue",
    "verification_failed": "vérification échouée",
    "proposed_rule": "règle de détection proposée",
    "posture_gap": "gap de posture",
    "detection_blocked": "détection empêchée (règle déjà en place)",
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
    confidence: float = 0.0,
    action_params: dict | None = None,
) -> str:
    """Append an escalation and return its id.

    Dedup: a pending escalation with the same action + resource_id + escalation_type
    is NOT duplicated — instead the standing one is kept as a single card and made
    *live*:
      - `occurrences` is incremented and `last_seen` bumped (cheap, every re-fire) so
        the operator sees "this keeps happening" at a glance (`first_seen` is preserved);
      - the expensive content (reason / suggested_steps / confidence) is refreshed ONLY
        on a MATERIAL change (a confidence shift ≥ _MATERIAL_CONFIDENCE_DELTA) so the
        card reflects the current situation without flickering on every poll, and the
        FIRST triage is preserved (`first_reason` / `first_suggested_steps`).
    This stops the re-decide output from being silently discarded on a persistent
    finding (the stale-card behaviour seen in the field).
    """
    rid_lower = resource_id.lower()
    now = datetime.now(timezone.utc).isoformat()
    steps = suggested_steps or []
    if _STORE.exists():
        lines = _STORE.read_text().splitlines()
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if (
                e.get("status") == "pending"
                and e.get("resource_id", "").lower() == rid_lower
                and e.get("action") == action
                and e.get("escalation_type") == escalation_type
            ):
                e["occurrences"] = int(e.get("occurrences", 1)) + 1
                e["last_seen"] = now
                try:
                    material = abs(
                        float(confidence or 0.0) - float(e.get("confidence") or 0.0)
                    ) >= _MATERIAL_CONFIDENCE_DELTA
                except (TypeError, ValueError):
                    material = False
                if material:
                    # Preserve the initial triage before overwriting with the latest.
                    e.setdefault("first_reason", e.get("reason", ""))
                    e.setdefault("first_suggested_steps", e.get("suggested_steps", []))
                    e.setdefault("first_confidence", e.get("confidence", 0.0))
                    e["reason"] = reason
                    e["suggested_steps"] = steps
                    e["confidence"] = confidence
                    e["updated_at"] = now
                lines[i] = json.dumps(e, default=str)
                _STORE.write_text("\n".join(lines) + "\n")
                return e["id"]

    esc = {
        "id": str(uuid.uuid4()),
        "timestamp": now,
        "first_seen": now,
        "last_seen": now,
        "occurrences": 1,
        "signal_id": signal_id,
        "resource_id": resource_id,
        "action": action,
        "escalation_type": escalation_type,
        "reason": reason,
        "run_id": run_id,
        "suggested_steps": steps,
        "ttp": ttp,
        "severity": severity,
        "proposal_id": proposal_id,
        "proposed_query": proposed_query,
        "confidence": confidence,
        "action_params": action_params or {},
        "status": "pending",
        "resolved_at": None,
    }
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STORE, "a") as f:
        f.write(json.dumps(esc, default=str) + "\n")
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
        updated.append(json.dumps(e, default=str))
    _STORE.write_text("\n".join(updated) + "\n")


def resolve_by_resource(resource_id: str, action: str) -> int:
    """Resolve all pending escalations matching resource_id + action.

    resource_id comparison is case-insensitive — Azure ARM IDs are
    case-insensitive but Python string equality is not.
    """
    if not _STORE.exists():
        return 0
    rid_lower = resource_id.lower()
    lines = _STORE.read_text().splitlines()
    updated = []
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for line in lines:
        e = json.loads(line)
        if (
            e["status"] == "pending"
            and e.get("resource_id", "").lower() == rid_lower
            and e["action"] == action
        ):
            e["status"] = "resolved"
            e["resolved_at"] = now
            count += 1
        updated.append(json.dumps(e, default=str))
    _STORE.write_text("\n".join(updated) + "\n")
    return count


def resolve_by_proposal(proposal_id: str) -> int:
    """Resolve all pending proposed_rule escalations for a given proposal_id."""
    if not _STORE.exists() or not proposal_id:
        return 0
    lines = _STORE.read_text().splitlines()
    updated = []
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for line in lines:
        if not line.strip():
            updated.append(line)
            continue
        try:
            e = json.loads(line)
        except Exception:
            updated.append(line)
            continue
        if (
            e.get("status") == "pending"
            and e.get("escalation_type") == "proposed_rule"
            and e.get("proposal_id") == proposal_id
        ):
            e["status"] = "resolved"
            e["resolved_at"] = now
            count += 1
        updated.append(json.dumps(e, default=str))
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
