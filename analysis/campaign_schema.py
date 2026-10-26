"""H-1: the shape H0 accepts of what the exercise channel carries for a campaign — its
manifest and the report of each of its runs, written on another host (Orodruin) and read on
H0 (analysis/hosted_report.py). Whoever can write in the channel writes these files: they
are read against the fields the campaign report uses, never taken as they come.

The same shapes as JSON Schema: schemas/campaign_manifest.schema.json and
schemas/run_report.schema.json, checked against these functions in the tests — the watch's
image has no jsonschema (pyproject: a dev dependency), so this is what runs on H0. Each
function says why a file is refused, "" when it is accepted.
"""
from __future__ import annotations

import math

from eregion_core.exercise_channel import safe_part

# annatar/campaign/manifest.py, CAMPAIGN_STATES and SCENARIO_STATES.
CAMPAIGN_STATES = ("planned", "ratified", "running", "done", "aborted")
SCENARIO_STATES = ("pending", "running", "executed", "skipped", "error")
DETECTIONS = ("detected", "missed", "unknown")


def _finite(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def manifest_refusal(manifest) -> str:
    """The manifest as a whole: an object, a plain campaign id, a known state, a list of
    scenarios (each checked by ``scenario_refusal``)."""
    if not isinstance(manifest, dict):
        return "the manifest is not a JSON object"
    cid = manifest.get("campaign_id")
    if not isinstance(cid, str) or not safe_part(cid):
        return "its campaign_id is not a plain name"
    if manifest.get("state") not in CAMPAIGN_STATES:
        return f"its state {str(manifest.get('state'))[:20]!r} is not one of {', '.join(CAMPAIGN_STATES)}"
    if not isinstance(manifest.get("scenarios"), list):
        return "its scenarios are not a list"
    return ""


def scenario_refusal(scenario) -> str:
    """One scenario of the manifest: what the report reads of it, typed."""
    if not isinstance(scenario, dict):
        return "not a JSON object"
    seq = scenario.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return "its seq is not a whole number"
    if not isinstance(scenario.get("ttp"), str) or not scenario["ttp"]:
        return "its ttp is not a string"
    if scenario.get("status") not in SCENARIO_STATES:
        return f"its status {str(scenario.get('status'))[:20]!r} is not one of {', '.join(SCENARIO_STATES)}"
    rid = scenario.get("run_id")
    if rid is not None and (not isinstance(rid, str) or (rid and not safe_part(rid))):
        return "its run_id is not a plain name"
    if not isinstance(scenario.get("target_resource_id"), str):
        return "its target_resource_id is not a string"
    if scenario.get("detection") is not None and scenario["detection"] not in DETECTIONS:
        return f"its detection is not one of {', '.join(DETECTIONS)}"
    latency = scenario.get("detection_latency_s")
    if latency is not None and not (_finite(latency) and latency >= 0):
        return "its detection_latency_s is not a number of seconds"
    for key in ("name", "error", "finished_at"):
        if scenario.get(key) is not None and not isinstance(scenario[key], str):
            return f"its {key} is not a string"
    return ""


def run_report_refusal(report, run_id: str) -> str:
    """The report of one run (annatar/runner/report.py): its own run id, and an attack time
    that is a number of seconds when there is one."""
    if not isinstance(report, dict):
        return "not a JSON object"
    if report.get("run_id") != run_id:
        return f"its run_id is not {run_id}"
    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        return "its metrics are not an object"
    attack = metrics.get("attack_time")
    if attack is not None and not _finite(attack):
        return "its attack_time is not a number of seconds"
    return ""
