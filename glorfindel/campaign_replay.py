"""Campaign replay — auto-activation + replay, the blue closing of the generative purple
loop (étape 5, collab/design_generative_purple_loop.md §5).

After a campaign, for every scenario the deterministic RulePoller MISSED, re-run the
LLM-proposed detection rule against the attack's traces and record whether it WOULD have
caught it ("aurait-elle chopé ?"). That turns each miss into a measured, regression-safe
verdict — the loop's "raté → appris → rejoué → chopé" in one pass.

Contract (see collab/design_campaign_manifest.md):
  - Reads Annatar's manifest.json POST-HOC, READ-ONLY — never before/during execution, so
    the blind measurement stays honest. Reuses annatar.campaign.manifest (single source of
    the format; glorfindel already depends on annatar.signals).
  - Re-reads the materialized artifact / proposal — NEVER regenerates (generation is
    non-deterministic; regenerating would break the regression test).
  - Writes its verdict to a SEPARATE runs/campaigns/<id>/replay.json. One writer per file:
    Annatar owns manifest.json, Glorfindel owns replay.json (no double-writer race on a
    file Annatar rewrites atomically).

Invariant: replay only READS detection data and re-runs a query; it activates nothing
permanent. A replayed rule that would have caught the attack is still a PROPOSAL until a
human (or the sandbox auto-activation path) ratifies it into detection_rules.yaml.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from annatar.campaign.manifest import CampaignManifest, campaign_dir

logger = logging.getLogger("glorfindel.campaign_replay")

REPLAY_SCHEMA_VERSION = "1.0"


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def proposal_for_scenario(scenario: Any, proposals: list[dict]) -> dict | None:
    """Find the rule proposed for a missed scenario.

    Matches on run_id first (the strong key — a proposal records the run it came from),
    then falls back to ttp. Returns the most recent match, or None when the miss produced
    no proposal (e.g. propose was suppressed because the RulePoller matched late).
    """
    by_run = [p for p in proposals if scenario.run_id and p.get("run_id") == scenario.run_id]
    if by_run:
        return by_run[-1]
    by_ttp = [p for p in proposals if scenario.ttp and p.get("ttp") == scenario.ttp]
    return by_ttp[-1] if by_ttp else None


def would_have_caught(detector: Any, query: str) -> tuple[bool, str]:
    """Re-run a proposed query; True if it returns ≥1 row.

    v1 runs the query as-is over the detector's default window — sound for the IMMEDIATE
    in-campaign replay (option A: data is still fresh). A windowed replay scoped to the
    original run's T0 is a refinement for replaying older campaigns.
    Returns (caught, detail). Raises nothing — query failure → (False, error) so one bad
    scenario never aborts the whole replay.
    """
    try:
        rows = detector.run_query(query)
    except Exception as e:
        return False, f"query failed: {e}"
    n = len(rows or [])
    return (n > 0), (f"{n} row(s) in window" if n else "0 rows in window")


def replay_campaign(
    campaign_id: str,
    *,
    runs_dir: str | Path = "runs",
    detector: Any = None,
    proposals: list[dict] | None = None,
    write: bool = True,
) -> dict:
    """Replay every missed scenario of a campaign and return (and optionally persist) the
    verdict document. Pure except for the optional replay.json write — detector and
    proposals are injected so this is unit-testable with zero Azure/disk dependency.
    """
    cdir = campaign_dir(campaign_id, runs_dir)
    manifest = CampaignManifest.load(cdir)
    proposals = proposals if proposals is not None else []

    replays: list[dict] = []
    for s in manifest.scenarios:
        if s.detection != "missed":
            continue  # only misses are worth replaying
        proposal = proposal_for_scenario(s, proposals)
        entry: dict[str, Any] = {
            "seq": s.seq,
            "run_id": s.run_id,
            "ttp": s.ttp,
            "proposed_rule_id": None,
            "would_have_caught": None,
            "replayed_at": _utcnow(),
            "detail": "",
        }
        if proposal is None:
            entry["detail"] = "no proposed rule for this miss"
        elif detector is None:
            entry["proposed_rule_id"] = proposal.get("id")
            entry["detail"] = "no detector (offline / dry-run) — not replayed"
        else:
            entry["proposed_rule_id"] = proposal.get("id")
            caught, detail = would_have_caught(detector, proposal.get("query", ""))
            entry["would_have_caught"] = caught
            entry["detail"] = detail
        replays.append(entry)

    doc = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "campaign_id": manifest.campaign_id,
        "replayed_at": _utcnow(),
        "replays": replays,
    }
    if write:
        _write_replay(cdir, doc)
    return doc


def _write_replay(cdir: str | Path, doc: dict) -> Path:
    """Atomically write replay.json (tmp + rename) — mirrors manifest.save so a reader
    never sees a half-written file."""
    d = Path(cdir)
    d.mkdir(parents=True, exist_ok=True)
    target = d / "replay.json"
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".replay-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target
