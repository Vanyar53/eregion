from __future__ import annotations

import contextlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

_STORE = Path.home() / ".glorfindel" / "proposed_rules.jsonl"


# SEC4b (as SEC3 for the escalations, V-10): the watch records, the console and the CLI
# approve and reject. Each read-modify-write holds an flock on `<store>.lock`, and the store
# is rewritten whole (temporary file + os.replace): no proposal lost between two writers, no
# reader ever sees half a file.
@contextlib.contextmanager
def _locked():
    from glorfindel.response.locks import _file_lock      # read at call time: the invariant
    with _file_lock(_STORE.with_name(_STORE.name + ".lock")):   # machine's scheduler drives it
        yield


def _lines() -> list[str]:
    return [ln for ln in _STORE.read_text().splitlines() if ln.strip()] if _STORE.exists() else []


def _write(lines: list[str]) -> None:
    from glorfindel.response.state import _atomic_write_text
    _atomic_write_text(_STORE, "\n".join(lines) + "\n")

# A proposal named like a shipped rule gets this suffix (SEC2): approved, it would have
# replaced the shipped rule in the client's layer, in silence.
_PROPOSED_SUFFIX = "-proposed"


def own_name(rule_name: str, shipped: set[str] | None = None) -> str:
    """`rule_name`, or — when it is a shipped rule's name — that name suffixed, never one
    a shipped rule has (SEC2). `shipped`: the names (default: the shipped base's)."""
    from glorfindel.detection_rules import shipped_rule_names
    taken = shipped_rule_names() if shipped is None else shipped
    if rule_name not in taken:
        return rule_name
    name, n = f"{rule_name}{_PROPOSED_SUFFIX}", 2
    while name in taken:
        name, n = f"{rule_name}{_PROPOSED_SUFFIX}-{n}", n + 1
    return name


def _min_interval(interval_s) -> float:
    """The proposal's interval, never under the rules' floor (SEC2)."""
    from glorfindel.detection_rules import MIN_INTERVAL_S
    try:
        value = float(interval_s)
    except (TypeError, ValueError):
        return MIN_INTERVAL_S
    return value if value >= MIN_INTERVAL_S else MIN_INTERVAL_S


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
    """Append a proposed detection rule and return its id.

    The model names the rule: a shipped rule's name is suffixed (`own_name`, SEC2) and the
    name it asked for kept (`renamed_from`) — approved, it would have replaced the shipped
    rule. Its interval is raised to the rules' floor (`MIN_INTERVAL_S`)."""
    name = own_name(rule_name)
    proposal = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "signal_id": signal_id,
        "ttp": ttp,
        "resource_id": resource_id,
        "rule_name": name,
        **({"renamed_from": rule_name} if name != rule_name else {}),
        "source": source,
        "workspace_id": workspace_id,
        "query": query,
        "interval_s": _min_interval(interval_s),
        "explanation": explanation,
        "confidence": confidence,
        "analysis": analysis,
        "status": "pending",
        "approved_at": None,
    }
    with _locked():
        _write(_lines() + [json.dumps(proposal)])
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
    """Return all unapproved proposals, oldest first — each with `replaces` (SEC2): the
    layer of the rule its approval would replace ("client"), "" when none."""
    out = [p for p in all_proposals() if p["status"] == "pending"]
    if out:
        from glorfindel.detection_rules import shipped_rule_names
        shipped, names = shipped_rule_names(), {r["name"] for r in _client_layer_rules()}
        for p in out:
            p["replaces"] = "client" if own_name(p["rule_name"], shipped) in names else ""
    return out


def approve(proposal_id: str, rules_yaml_path: str | Path) -> dict:
    """Mark a proposal as approved and write its rule to the client's layer (P1).

    `rules_yaml_path` is the shipped base (detection_rules.yaml): read to resolve the
    rule's asset, NEVER written — an update of Glorfindel replaces the base, and an
    approved rule written there was lost (or stopped H0's deployment, M-3). The rule goes
    to `~/.glorfindel/client_rules.yaml` (`rule_layers.write_client_rule`), loaded over
    the base. The rule is written first: a layer that cannot be read leaves the proposal
    pending, never approved without its rule. Returns the proposal, with `rules_file` (the
    layer written) and `rule_write` ('added' | 'replaced' | 'same').

    Never in the place of a shipped rule (SEC2): a proposal recorded under a shipped rule's
    name (before the suffix) is approved under its own (`renamed_from` says it). Replacing
    a client rule of the same name is said: `replaces` = "client", the rule it replaced in
    `replaced_rule`.
    """
    from glorfindel import rule_layers

    if not _STORE.exists():
        raise ValueError(f"Proposal {proposal_id} not found")
    with _locked():
        return _approve(proposal_id, rules_yaml_path, rule_layers)


def _approve(proposal_id: str, rules_yaml_path: str | Path, rule_layers) -> dict:
    """approve(), under the store's lock: read, rule written, proposal marked, rewritten."""
    lines = _lines()
    proposal: dict | None = None
    at = -1
    for i, line in enumerate(lines):
        p = json.loads(line)
        if p["id"] == proposal_id and p["status"] == "pending" and proposal is None:
            proposal, at = p, i

    if proposal is None:
        raise ValueError(f"Proposal {proposal_id} not found or already approved")

    name = own_name(proposal["rule_name"])
    if name != proposal["rule_name"]:
        proposal.setdefault("renamed_from", proposal["rule_name"])
        proposal["rule_name"] = name
    replaced = next((r for r in _client_layer_rules() if r.get("name") == name), None)
    rule = rule_from_proposal(proposal, Path(rules_yaml_path))
    how = rule_layers.write_client_rule(rule)

    proposal["status"] = "approved"
    proposal["approved_at"] = datetime.now(timezone.utc).isoformat()
    lines[at] = json.dumps(proposal)
    _write(lines)
    bound = "assets" in rule
    reason = "" if bound else (
        "aucun backend unique de glorfindel-config.yaml ne surveille son workspace"
        if proposal.get("workspace_id") else "aucun backend de glorfindel-config.yaml")
    return {**proposal, "rules_file": str(rule_layers.client_rules_path()), "rule_write": how,
            "rule_bound": bound, "rule_unbound_reason": reason,
            "replaces": "client" if how == "replaced" else "",
            **({"replaced_rule": replaced} if how == "replaced" else {})}


def _client_layer_rules() -> list[dict]:
    from glorfindel import rule_layers
    from glorfindel.detection_rules import _named
    try:
        return _named(rule_layers.read_client_layer().get("rules"))
    except Exception:
        return []


def reject(proposal_id: str) -> dict:
    """Mark a proposal as rejected without touching detection_rules.yaml."""
    if not _STORE.exists():
        raise ValueError(f"Proposal {proposal_id} not found")

    with _locked():
        lines = _lines()
        proposal: dict | None = None
        for i, line in enumerate(lines):
            p = json.loads(line)
            if p["id"] == proposal_id and p["status"] == "pending":
                p["status"] = "rejected"
                proposal = p
                lines[i] = json.dumps(p)

        if proposal is None:
            raise ValueError(f"Proposal {proposal_id} not found or not pending")

        _write(lines)
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
                # No static asset: every discovered VM of the backend that watches the
                # proposal's workspace — or, none matching, the first rule's backend. This
                # read `r.monitoring_backends`, which DetectionRule does not have: the error
                # was swallowed, every approved rule took the inline form below, and loaded
                # as auto-apply on no backend it applied to no VM, silently (P1 review).
                # The first rule's backend only when the proposal names no workspace: one
                # that names another would be bound to a workspace it does not watch.
                from glorfindel.rule_layers import backend_for_workspace
                workspace = proposal.get("workspace_id", "")
                backend_name = backend_for_workspace(workspace, cfg.backends) if workspace else next(
                    (r.monitoring_backend_name for r in cfg.rules if r.monitoring_backend_name), "")
                if backend_name:
                    asset_name = "auto"
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
        # Legacy fallback — inline workspace and target: no backend to bind to (no
        # monitoring_backends in glorfindel-config.yaml). Said by approve and at load.
        rule.update({
            "source": proposal["source"],
            "workspace_id": proposal["workspace_id"],
            "ttp": proposal["ttp"],
            "resource_id": proposal["resource_id"],
        })
    rule["interval_s"] = int(_min_interval(proposal["interval_s"]))
    query = proposal["query"]
    rule["query"] = query if query.endswith("\n") else query + "\n"
    return rule
