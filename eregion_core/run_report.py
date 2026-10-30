"""The run, unified (C1, #80): one report for an attack and a fault, one way to read it.

An Annatar run and a Gothmog run write ``runs/<run_id>.json`` with the same keys —
``scenario``, ``run_id``, ``mitre``, ``result``, ``metrics``, ``thresholds``, ``checks`` —
since G0, Gothmog records its run « as Annatar's ». The class was written twice, once per
injector (D1: neither imports the other); it lives here, in the shared core, and each injector
keeps only how it prints it (``annatar/runner/report.py``, ``gothmog/runner/report.py``).

What C1 adds to the format, compatibly — every key optional, an older report reads the same,
``schemas/run_report.schema.json`` allows other fields, and the signal contract
(``eregion_core/signals.py``) does not change:

- ``metrics.run_format``: ``1``;
- ``metrics.kind``: ``technique`` (an attack) or ``fault``;
- ``metrics.injector``: ``annatar`` or ``gothmog`` (Gothmog already wrote it);
- ``metrics.experiment_id``: the technique's ATT&CK id, or the fault's id (as the catalog and
  the exercise windows name it — Gothmog's ``metrics.experiment`` is the Chaos Studio
  experiment, kept as it was).

A report without them is told apart as before: ``metrics.injector == "gothmog"`` is a fault,
anything else an attack; its technique is ``mitre``, its fault ``metrics.fault``.

``read_run`` gives the view every reader shares — the console's indicators and its coverage
matrix (``eregion_console/indicators.py``, ``eregion_console/coverage.py``): one dict per run,
dated (``at``, seconds since the epoch: the attack's T0, or the fault's start), with what the
run measured itself (``detection``, its ``latency``). ``timeline`` joins to it the record of
Glorfindel's watch that decided on its detection (found by the console's ``decision_of``)
and gives the times of the incident: attack, detection, decision, verified action — what the
time to contain is measured on (BL1). Nothing is invented: a time not measured is None.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

RUN_FORMAT = 1
KINDS = ("technique", "fault")
# The actions that contain an incident: Glorfindel's isolations and blocks. Contained alone =
# one of them executed AND verified (docs/design/console.md, the five indicators).
CONTAINING = ("isolate_vm", "block_suspicious_ip")


@dataclass
class RunReport:
    """``runs/<run_id>.json``: what an injector writes at the end of a run, attack or fault."""
    scenario: str
    run_id: str
    mitre: str
    result: str
    metrics: dict
    thresholds: dict
    checks: dict

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, runs_dir: str | Path = "runs") -> Path:
        path = Path(runs_dir) / f"{self.run_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


def identity(kind: str, injector: str, experiment: str) -> dict:
    """What every run writes in its ``metrics`` so that a reader tells it apart without
    guessing: the format, an attack or a fault, who ran it, and what."""
    if kind not in KINDS:
        raise ValueError(f"a run is a technique or a fault, not {kind!r}")
    return {"run_format": RUN_FORMAT, "kind": kind, "injector": injector,
            "experiment_id": str(experiment or "")}


def epoch(value) -> float | None:
    """Seconds since the epoch from a number or an ISO time; None otherwise (NaN, infinity
    and booleans included)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def iso(ts: float | None) -> str | None:
    """The ISO time of seconds since the epoch; None for None, or a number no date holds."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def kind_of(report: dict) -> str:
    """``technique`` or ``fault``: the report's own word, else as before C1 (Gothmog's)."""
    m = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    if m.get("kind") in KINDS:
        return m["kind"]
    return "fault" if m.get("injector") == "gothmog" else "technique"


def read_run(report, run_id: str = "", campaign: str = "") -> dict | None:
    """The unified view of one report (a dict as loaded), or None when it is not one or has no
    date: an attack is dated by its attack time (T0), a fault by its start.

    Keys: ``run_id``, ``kind``, ``injector``, ``experiment`` (the technique or the fault),
    ``ttp`` (``mitre``, as the indicators always read it), ``name``, ``at``, ``result``,
    ``detection`` (``detected`` | ``missed`` | ``unknown``), ``latency`` (seconds from ``at``
    to the detection the run counted, or None), ``detected_at``, ``without_glorfindel``,
    ``campaign`` (the campaign it was published with, or ''), ``run_format`` (0 before C1);
    for a fault, ``ended_at`` and its ``targets`` (BL1)."""
    if not isinstance(report, dict):
        return None
    m = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    kind = kind_of(report)
    at = epoch(m.get("fault_start") if kind == "fault" else m.get("attack_time"))
    if at is None or iso(at) is None:   # a date no calendar holds is no date
        return None
    latency = m.get("detection_latency_s")
    latency = float(latency) if _number(latency) and 0 <= latency < 10 * 365 * 86400 else None
    mitre = str(report.get("mitre") or "")
    experiment = m.get("experiment_id") if isinstance(m.get("experiment_id"), str) and m.get("experiment_id") \
        else (str(m.get("fault") or "") if kind == "fault" else mitre)
    fmt = m.get("run_format")
    return {
        "run_id": str(report.get("run_id") or run_id), "kind": kind,
        "injector": str(m.get("injector") or ("gothmog" if kind == "fault" else "annatar")),
        "experiment": experiment, "ttp": mitre, "name": str(report.get("scenario") or ""),
        "at": at, "result": str(report.get("result") or ""),
        "detection": m.get("detection") or "unknown", "latency": latency,
        "detected_at": at + latency if latency is not None else None,
        "without_glorfindel": m.get("without_glorfindel") is True,
        "campaign": campaign,
        "run_format": fmt if isinstance(fmt, int) and not isinstance(fmt, bool) else 0,
        # BL1: a fault's end and its targets — a decision to isolate or to block on them during
        # it is a fault taken for an attack (analysis/containment.py). None / [] for an attack.
        "ended_at": epoch(m.get("fault_end")) if kind == "fault" else None,
        "targets": [str(x) for x in m.get("targets") or [] if x and isinstance(x, str)]
        if kind == "fault" and isinstance(m.get("targets"), list) else [],
    }


def read_reports(reports: dict[str, Path]) -> list[dict]:
    """Every run of ``reports`` (run id → path), unified, whatever its date — a report that
    cannot be read, or has no date, is left out. A report under ``campaigns/<id>/runs/`` is
    given its campaign."""
    runs = []
    for run_id, path in reports.items():
        try:
            r = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        parent = Path(path).parent
        campaign = parent.parent.name if parent.name == "runs" and parent.parent.parent.name == "campaigns" else ""
        run = read_run(r, run_id, campaign)
        if run is not None:
            runs.append(run)
    return runs


def timeline(run: dict, decision: dict | None) -> dict:
    """The times of one incident: the attack (``attack_at``), the detection the run counted,
    Glorfindel's decision on it, and the verified action that contained it — each in seconds
    since the epoch, and as a duration from the attack (``detect_s``, ``decide_s``,
    ``contain_s``). ``decision`` is the watch's record (a cycle as the console slims it:
    ``at``, ``action``, ``confidence``, ``escalate``, ``executed``, ``verified``, ``mode``, and
    ``verified_at`` when the watch writes one). Contained: an isolation or a block executed
    AND verified — its time is the verification's when written, else the record's, which the
    watch writes once the action is verified. A time before the attack is no time (None)."""
    at = run["at"]
    detected = run.get("detected_at")
    out = {"attack_at": at, "detected_at": detected, "decided_at": None, "contained_at": None,
           "action": "", "confidence": None, "escalated": None, "executed": None,
           "verified": None, "mode": ""}
    if decision:
        decided = epoch(decision.get("at"))
        out["decided_at"] = decided if decided is not None and decided >= at else None
        conf = decision.get("confidence")
        out.update(action=str(decision.get("action") or ""),
                   confidence=float(conf) if _number(conf) else None,
                   escalated=decision.get("escalate") if isinstance(decision.get("escalate"), bool) else None,
                   executed=decision.get("executed") if isinstance(decision.get("executed"), bool) else None,
                   verified=decision.get("verified") if isinstance(decision.get("verified"), bool) else None,
                   mode=str(decision.get("mode") or ""))
        if out["action"] in CONTAINING and out["executed"] is True and out["verified"] is True:
            verified_at = epoch(decision.get("verified_at"))
            contained = verified_at if verified_at is not None else out["decided_at"]
            out["contained_at"] = contained if contained is not None and contained >= at else None

    def since(t):
        return round(t - at, 1) if t is not None else None
    out.update(detect_s=since(detected), decide_s=since(out["decided_at"]),
               contain_s=since(out["contained_at"]))
    return out
