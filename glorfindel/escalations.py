from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
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
    "activate_autonomy": "Réponse autonome en attente de confirmation",
    "review_isolation": "Isolation à revoir (TTL dépassé)",
}

_ESCALATION_LABELS = {
    "low_confidence": "confiance insuffisante",
    "destructive_action": "action destructive",
    "proposed_action": "action inconnue",
    "verification_failed": "vérification échouée",
    "proposed_rule": "règle de détection proposée",
    "posture_gap": "gap de posture",
    "orphan_rule": "règle orpheline (carte disparue)",
    "detection_blocked": "détection empêchée (règle déjà en place)",
    "mode_hold": "action retenue (mode human_only)",
    "write_blocked": "écriture refusée (droits)",
    "action_failed": "action en échec",
    "cycle_failed": "signal non traité (cycle interrompu)",
    "uncharacterized_signal": "signal non caractérisé (garde-fou)",
    "release_hold": "levée retenue (restauration non terminée, ou rejeu possible au démarrage)",
    "ttl_exceeded": "isolation levée à l'expiration du TTL",
    "unattributed_signal": "détection non attribuée à cette VM",
    "telemetry_gap": "télémétrie incomplète (requêtes d'enquête en échec)",
    "unstable_decision": "décision instable (les tirages ne s'accordent pas)",
    "readiness_hold": "VM retenue en observation (préparation)",
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
    rule_name: str = "",
    source: str = "",
    exercise_run: str = "",
    explanation: str = "",
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

    `source` (B2, eregion_core/exercise.py): `exercise` when an injector's window covers
    this VM, else `real` (empty on older cards = real). It is part of the dedup key: a
    real detection never merges into a pending exercise card, nor the reverse.
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
                and (e.get("source") or "real") == (source or "real")
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
                    if explanation:
                        e["explanation"] = explanation
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
        "rule_name": rule_name,
        "source": source,
        "exercise_run": exercise_run,
        # The model's plain-language explanation of the decision — what an operator judges
        # on; `reason` is often the gate's wording (a mode hold, low confidence).
        "explanation": explanation,
        "status": "pending",
        "resolved_at": None,
    }
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STORE, "a") as f:
        f.write(json.dumps(esc, default=str) + "\n")
    _notify(esc)
    return esc["id"]


def resolve(escalation_id: str, note: str = "") -> None:
    """Mark an escalation as resolved — `note`: what resolved it, when Glorfindel did
    (an orphan rule taken off, A3)."""
    if not _STORE.exists():
        return
    lines = _STORE.read_text().splitlines()
    updated = []
    for line in lines:
        e = json.loads(line)
        if e["id"] == escalation_id:
            e["status"] = "resolved"
            e["resolved_at"] = datetime.now(timezone.utc).isoformat()
            if note:
                e["resolution"] = note
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
    note: str = "",
) -> None:
    """POST an autonomous action notification to the webhook if set. `note`: what the
    action left open (an isolation by rules: Azure's DNS / IMDS — S7)."""
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
                + (f"> ⚠ {note[:300]}\n" if note else "")
                + f"`{run_id}`"
            )
        }, timeout=5)
    except Exception:
        pass  # notification failure must never block the agent


def discord_bot_configured(environ=None) -> bool:
    """The Discord bot posts the escalations (one thread per VM): the webhook then stays
    silent. A bot needs its token and its channel — a channel alone runs no bot, and an
    escalation always goes somewhere, or the watch says it does not.

    Only the bot's container holds the token (M-3, #183): docker compose tells the watch
    and the War Room that it is set with GLORFINDEL_DISCORD_BOT ("1" or "", from
    ${DISCORD_BOT_TOKEN:+1}), never its value. Outside compose, DISCORD_BOT_TOKEN itself."""
    import os
    env = os.environ if environ is None else environ
    token = env.get("GLORFINDEL_DISCORD_BOT") or env.get("DISCORD_BOT_TOKEN")
    return bool(token and env.get("DISCORD_CHANNEL_ID"))


def alerting_configured(environ=None) -> bool:
    """An escalation reaches someone: the webhook, or the Discord bot."""
    import os
    env = os.environ if environ is None else environ
    return bool(env.get("GLORFINDEL_WEBHOOK_URL") or discord_bot_configured(env))


def _notify(esc: dict) -> None:
    """POST an escalation notification to GLORFINDEL_WEBHOOK_URL if set.

    Skipped when the Discord bot is configured — the bot handles escalations in
    per-VM threads, which is a better UX than a flat channel message.
    """
    import os
    if discord_bot_configured():
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


# ── Observation: was a recommendation right? ─────────────────────────────────────
#
# The decision to let Glorfindel act alone rests on a measured number: over weeks of
# human_only, how often would a disruptive action have been wrong. The operator judges
# each card (right / wrong / unsure); the report counts. See docs/observation.md.

VERDICTS = ("right", "wrong", "unsure")
# Recommended actions that disrupt the workload: a wrong one is the false positive the
# autonomy decision weighs.
DISRUPTIVE_ACTIONS = ("isolate_vm", "block_suspicious_ip")
# Cards that are not a decision on a detection: posture, housekeeping, proposals.
_NOT_DECISIONS = {"posture_gap", "orphan_rule", "proposed_rule", "readiness_hold",
                  "ttl_exceeded", "detection_blocked"}


def all_escalations() -> list[dict]:
    """Every card, resolved ones included, in file order. Unreadable lines are skipped."""
    if not _STORE.exists():
        return []
    out = []
    for line in _STORE.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def set_verdict(escalation_id: str, verdict: str, note: str = "") -> dict:
    """Record the operator's judgement of a card — independent of its acknowledgement.

    `escalation_id`: the full id or a unique prefix of at least 6 characters (the War
    Room and `pending` show 8). Raises ValueError on an unknown verdict or an ambiguous
    prefix, KeyError when no card matches. Returns the updated card."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
    ref = (escalation_id or "").strip().lower()
    if len(ref) < 6:
        raise ValueError("give the card id, or at least its first 6 characters")
    lines = _STORE.read_text().splitlines() if _STORE.exists() else []
    hits = []
    for i, line in enumerate(lines):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if str(e.get("id", "")).lower().startswith(ref):
            hits.append((i, e))
    exact = [h for h in hits if str(h[1].get("id", "")).lower() == ref]
    hits = exact or hits
    if not hits:
        raise KeyError(f"no card {escalation_id}")
    if len(hits) > 1:
        raise ValueError(f"{escalation_id} matches {len(hits)} cards — give more characters")
    i, e = hits[0]
    e["verdict"] = verdict
    e["verdict_at"] = datetime.now(timezone.utc).isoformat()
    e["verdict_note"] = note
    lines[i] = json.dumps(e, default=str)
    _STORE.write_text("\n".join(lines) + "\n")
    return e


def rule_of(e: dict) -> str:
    """The detection rule behind a card: recorded since the observation kit, otherwise
    read from the RulePoller's signal id (`rule-<name>-<8 hex>`)."""
    if e.get("rule_name"):
        return e["rule_name"]
    sid = str(e.get("signal_id") or "")
    if sid.startswith("rule-"):
        parts = sid[len("rule-"):].rsplit("-", 1)
        if len(parts) == 2 and len(parts[1]) == 8:
            return parts[0]
    return ""


def is_decision(e: dict) -> bool:
    """A card that carries a decision on a detection — not posture, housekeeping, a
    proposal, or an alert of the reassertion."""
    sid = str(e.get("signal_id") or "")
    return (e.get("escalation_type") not in _NOT_DECISIONS
            and not sid.startswith(("reassert-", "ttl-", "posture-")))


def _ip_of(e: dict) -> str:
    return str((e.get("action_params") or {}).get("ip") or "").strip()


def _when(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(e.get("first_seen") or e.get("timestamp")).replace("Z", "+00:00"))
    except ValueError:
        return None


def recurrence(e: dict, escs: list[dict] | None = None, days: int = 7) -> dict | None:
    """The earlier cards on the same IP in the last `days` days — in observation nothing is
    blocked, so a scanner comes back and opens a new card after each ack (three cards for
    one attacker on bree, 16–17/10). Said on the card, never judged for the operator."""
    ip, me = _ip_of(e), _when(e)
    if not ip or me is None:
        return None
    window = timedelta(days=days)
    prev = [x for x in (all_escalations() if escs is None else escs)
            if x.get("id") != e.get("id") and _ip_of(x) == ip
            and (w := _when(x)) is not None and w < me and me - w <= window]
    if not prev:
        return None
    last = max(prev, key=_when)
    return {"previous": len(prev), "last_id": last.get("id"), "last_seen": last.get("first_seen"),
            "last_verdict": last.get("verdict")}


def to_judge(since: datetime | None = None, limit: int = 100) -> list[dict]:
    """The decision cards still waiting for the operator's verdict, newest first — pending
    or acknowledged (a verdict is independent of the ack): what the War Room's "To judge"
    list shows during an observation. An exercise card stays in the list, flagged
    (``exercise``, ``exercise_run``) — H-1: a window is a claim from the injectors' host, and
    whoever can write one could otherwise hide a real attack from the operator. The
    observation report still counts it apart (``observation_report``)."""
    out = []
    escs = all_escalations()
    for e in escs:
        if not is_decision(e) or e.get("verdict") in VERDICTS:
            continue
        when = e.get("first_seen") or e.get("timestamp") or ""
        if since is not None:
            try:
                if datetime.fromisoformat(str(when).replace("Z", "+00:00")) < since:
                    continue
            except ValueError:
                continue
        card = {k: e.get(k) for k in (
            "id", "action", "escalation_type", "resource_id", "ttp", "severity", "confidence",
            "reason", "explanation", "action_params", "first_seen", "last_seen", "occurrences",
            "status", "rule_name")}
        card["exercise"] = e.get("source") == "exercise"
        card["exercise_run"] = (e.get("exercise_run") or "") if card["exercise"] else ""
        card["recurrence"] = recurrence(e, escs)
        out.append(card)
    out.sort(key=lambda c: str(c.get("first_seen") or ""), reverse=True)
    return out[:limit]


def observation_report(since: datetime | None = None) -> dict:
    """Counts of the operator's verdicts on decision cards since `since` (all if None).
    A card counts once, however many times it re-fired (its `occurrences`). An exercise
    card (B2: an injector's window covered the VM) is left out — counted in `exercises`."""
    def bucket() -> dict:
        return {"right": 0, "wrong": 0, "unsure": 0, "unjudged": 0}

    by_action: dict[str, dict] = {}
    by_rule: dict[str, dict] = {}
    disruptive = bucket()
    cards = 0
    exercises = 0
    block_ips: list[str] = []
    for e in all_escalations():
        if not is_decision(e):
            continue
        when = e.get("first_seen") or e.get("timestamp") or ""
        if since is not None:
            try:
                if datetime.fromisoformat(str(when).replace("Z", "+00:00")) < since:
                    continue
            except ValueError:
                continue
        if e.get("source") == "exercise":
            exercises += 1
            continue
        cards += 1
        v = e.get("verdict") if e.get("verdict") in VERDICTS else "unjudged"
        by_action.setdefault(e.get("action") or "?", bucket())[v] += 1
        by_rule.setdefault(rule_of(e) or "(sans règle)", bucket())[v] += 1
        if e.get("action") in DISRUPTIVE_ACTIONS:
            disruptive[v] += 1
        if e.get("action") == "block_suspicious_ip" and _ip_of(e):
            block_ips.append(_ip_of(e))
    judged = disruptive["right"] + disruptive["wrong"]
    return {
        "since": since.isoformat() if since else None,
        "cards": cards,
        "exercises": exercises,
        # A returning scanner opens a card per visit: how many attackers behind the blocks.
        "blocks": {"cards": len(block_ips), "distinct_ips": len(set(block_ips))},
        "judged": sum(b["right"] + b["wrong"] + b["unsure"] for b in by_action.values()),
        "by_action": by_action,
        "by_rule": by_rule,
        "disruptive": {**disruptive, "false_rate": (disruptive["wrong"] / judged) if judged else None},
    }

