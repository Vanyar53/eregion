from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_STORE = Path.home() / ".glorfindel" / "proposed_rules.jsonl"


def record(
    run_id: str,
    ttp: str,
    resource_id: str,
    rule_name: str,
    source: str,
    workspace_id: str,
    query: str,
    interval_s: float,
    explanation: str,
    confidence: float,
    analysis: str,
    signal_id: str = "",
) -> str:
    """Append a proposed detection rule and return its id."""
    proposal = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "signal_id": signal_id,
        "ttp": ttp,
        "resource_id": resource_id,
        "rule_name": rule_name,
        "source": source,
        "workspace_id": workspace_id,
        "query": query,
        "interval_s": interval_s,
        "explanation": explanation,
        "confidence": confidence,
        "analysis": analysis,
        "status": "pending",
        "approved_at": None,
    }
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STORE, "a") as f:
        f.write(json.dumps(proposal) + "\n")
    return proposal["id"]


def pending() -> list[dict]:
    """Return all unapproved proposals, oldest first."""
    if not _STORE.exists():
        return []
    result = []
    for line in _STORE.read_text().splitlines():
        if not line.strip():
            continue
        p = json.loads(line)
        if p["status"] == "pending":
            result.append(p)
    return result


def approve(proposal_id: str, rules_yaml_path: str | Path) -> dict:
    """Mark a proposal as approved and append the rule to detection_rules.yaml."""
    if not _STORE.exists():
        raise ValueError(f"Proposal {proposal_id} not found")

    lines = _STORE.read_text().splitlines()
    proposal: dict | None = None
    updated = []
    for line in lines:
        if not line.strip():
            continue
        p = json.loads(line)
        if p["id"] == proposal_id and p["status"] == "pending":
            p["status"] = "approved"
            p["approved_at"] = datetime.now(timezone.utc).isoformat()
            proposal = p
        updated.append(json.dumps(p))

    if proposal is None:
        raise ValueError(f"Proposal {proposal_id} not found or already approved")

    _STORE.write_text("\n".join(updated) + "\n")

    _append_to_rules_yaml(proposal, Path(rules_yaml_path))
    return proposal


def reject(proposal_id: str) -> dict:
    """Mark a proposal as rejected without touching detection_rules.yaml."""
    if not _STORE.exists():
        raise ValueError(f"Proposal {proposal_id} not found")

    lines = _STORE.read_text().splitlines()
    proposal: dict | None = None
    updated = []
    for line in lines:
        if not line.strip():
            continue
        p = json.loads(line)
        if p["id"] == proposal_id and p["status"] == "pending":
            p["status"] = "rejected"
            proposal = p
        updated.append(json.dumps(p))

    if proposal is None:
        raise ValueError(f"Proposal {proposal_id} not found or not pending")

    _STORE.write_text("\n".join(updated) + "\n")
    return proposal


def _append_to_rules_yaml(proposal: dict, rules_path: Path) -> None:
    """Append a proposed rule to detection_rules.yaml.

    Writes the new format (assets reference) when possible by reverse-
    looking up which asset matches the proposal's resource_id.
    Falls back to inline workspace_id/resource_id for robustness.
    """
    from glorfindel.detection_rules import load_config
    indented_query = "".join(
        f"      {line}\n" for line in proposal["query"].splitlines()
    )

    # Try to resolve asset and backend names from existing config
    asset_name = proposal.get("asset_name", "")
    backend_name = proposal.get("monitoring_backend_name", "")

    if not asset_name:
        try:
            cfg = load_config(rules_path)
            match = cfg.asset_for_resource(proposal.get("resource_id", ""))
            if match:
                asset_name = match.name
                if match.monitoring_backends:
                    backend_name = match.monitoring_backends[0]
        except Exception:
            pass

    if asset_name:
        # New format — no inline workspace_id / resource_id
        block = (
            f"\n"
            f"  - name: {proposal['rule_name']}\n"
            f"    description: >\n"
            f"      Auto-proposed by Glorfindel after detection_missed (TTP: {proposal['ttp']}).\n"
            f"      {proposal['explanation'][:120]}\n"
            f"    enabled: true\n"
            f"    ttp: {proposal['ttp']}\n"
            f"    assets: [{asset_name}]\n"
            f"    interval_s: {proposal['interval_s']}\n"
            f"    query: |\n"
            f"{indented_query}"
        )
    else:
        # Legacy fallback — inline workspace_id / resource_id
        block = (
            f"\n"
            f"  - name: {proposal['rule_name']}\n"
            f"    description: >\n"
            f"      Auto-proposed by Glorfindel after detection_missed (TTP: {proposal['ttp']}).\n"
            f"      {proposal['explanation'][:120]}\n"
            f"    enabled: true\n"
            f"    source: {proposal['source']}\n"
            f"    workspace_id: \"{proposal['workspace_id']}\"\n"
            f"    ttp: {proposal['ttp']}\n"
            f"    resource_id: \"{proposal['resource_id']}\"\n"
            f"    interval_s: {proposal['interval_s']}\n"
            f"    query: |\n"
            f"{indented_query}"
        )

    with open(rules_path, "a") as f:
        f.write(block)
