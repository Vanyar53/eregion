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


def all_proposals() -> list[dict]:
    """Return every proposal (any status), oldest first.

    Used by campaign replay to find the rule proposed for a missed scenario's
    run_id (the proposal may already be approved/rejected, so pending() is too narrow).
    """
    if not _STORE.exists():
        return []
    out = []
    for line in _STORE.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def pending() -> list[dict]:
    """Return all unapproved proposals, oldest first."""
    return [p for p in all_proposals() if p["status"] == "pending"]


def approve(proposal_id: str, rules_yaml_path: str | Path) -> dict:
    """Mark a proposal as approved and write its rule to the client's layer (P1).

    `rules_yaml_path` is the shipped base (detection_rules.yaml): read to resolve the
    rule's asset, NEVER written — an update of Glorfindel replaces the base, and an
    approved rule written there was lost (or stopped H0's deployment, M-3). The rule goes
    to `~/.glorfindel/client_rules.yaml` (`rule_layers.write_client_rule`), loaded over
    the base. The rule is written first: a layer that cannot be read leaves the proposal
    pending, never approved without its rule. Returns the proposal, with `rules_file` (the
    layer written) and `rule_write` ('added' | 'replaced' | 'same').
    """
    from glorfindel import rule_layers

    if not _STORE.exists():
        raise ValueError(f"Proposal {proposal_id} not found")

    lines = _STORE.read_text().splitlines()
    proposal: dict | None = None
    updated: list[dict] = []
    for line in lines:
        if not line.strip():
            continue
        p = json.loads(line)
        if p["id"] == proposal_id and p["status"] == "pending" and proposal is None:
            proposal = p
        updated.append(p)

    if proposal is None:
        raise ValueError(f"Proposal {proposal_id} not found or already approved")

    rule = rule_from_proposal(proposal, Path(rules_yaml_path))
    how = rule_layers.write_client_rule(rule)

    proposal["status"] = "approved"
    proposal["approved_at"] = datetime.now(timezone.utc).isoformat()
    _STORE.write_text("\n".join(json.dumps(p) for p in updated) + "\n")
    return {**proposal, "rules_file": str(rule_layers.client_rules_path()), "rule_write": how}


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


def rule_from_proposal(proposal: dict, rules_path: Path) -> dict:
    """The rule an approved proposal becomes (a dict, as in a rules file).

    The asset reference when possible, by reverse-looking up which asset matches the
    proposal's resource_id in the rules loaded from `rules_path` (base + client layer);
    falls back to inline workspace_id/resource_id. Same rule as before P1 — only where it
    is written changed.
    """
    from glorfindel.detection_rules import load_config

    # Try to resolve asset and backend names from existing config
    asset_name = proposal.get("asset_name", "")
    backend_name = proposal.get("monitoring_backend_name", "")

    if not asset_name:
        try:
            try:
                from glorfindel.config import load_glorfindel_config
                gcfg = load_glorfindel_config()
            except Exception:
                gcfg = None
            cfg = load_config(rules_path, glorfindel_cfg=gcfg)
            match = cfg.asset_for_resource(proposal.get("resource_id", ""))
            if match:
                asset_name = match.name
                if match.monitoring_backends:
                    backend_name = match.monitoring_backends[0]
            else:
                # No static asset — borrow backend from first existing rule, use auto discovery
                for r in cfg.rules:
                    if r.monitoring_backends:
                        asset_name = "auto"
                        backend_name = r.monitoring_backends[0]
                        break
        except Exception:
            pass

    rule: dict = {
        "name": proposal["rule_name"],
        "description": (f"Auto-proposed by Glorfindel after detection_missed "
                        f"(TTP: {proposal['ttp']}). {proposal['explanation'][:120]}"),
        "enabled": True,
    }
    if asset_name:
        rule["ttp"] = proposal["ttp"]
        if backend_name:
            rule["monitoring_backends"] = [backend_name]
        rule["assets"] = [asset_name]
    else:
        # Legacy fallback — inline workspace and target
        rule.update({
            "source": proposal["source"],
            "workspace_id": proposal["workspace_id"],
            "ttp": proposal["ttp"],
            "resource_id": proposal["resource_id"],
        })
    rule["interval_s"] = int(proposal["interval_s"])
    query = proposal["query"]
    rule["query"] = query if query.endswith("\n") else query + "\n"
    return rule
