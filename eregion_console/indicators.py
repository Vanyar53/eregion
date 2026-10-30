"""The five indicators of the finality (ROADMAP, « Vers la 1.0 »), shown on the console's overview.

Computed from what this host keeps: the run reports (``runs/<id>.json``, under a published
campaign too), the watch's cycles (``runs/*_debug.jsonl``), the cards (their verdicts) and the
catalog — never from the exercise windows, emptied 7 days after they end (H-1), so 30 days hold.
Nothing is invented: what cannot be measured is ``None``, and the page says why.

Definitions decided by Jonathan on 27/10 (docs/design/console.md, §3):
- time to contain: the median time to detect and to decide, over the detected attacks of the
  last 30 days; to contain, only over what was contained alone (nothing, in human-only) — from
  the attack to the read-back on Azure (BL1: ``outcome.verified_at``, else the cycle's line);
- contained alone: the real share (executed in the cycle, verified, and held — the definition of
  analysis/containment.py, BL1), and the shadow one — the detected attacks on which Glorfindel
  recommended to isolate or to block at or above the confidence gate, and that no verdict says
  was wrong; beside them, every attack run of the period (missed ones included: the campaign's
  denominator, BL1) and the faults taken for an attack (a decision to isolate or to block on a
  fault's target during it);
- disruptive actions judged wrong: over 30 days, the 7 days aside (``glorfindel report``);
- coverage: the techniques detected by a run in 30 days, over the implemented ones and over the
  whole catalog; the faults aside;
- last proof: the most recent attack detected with a decision of Glorfindel attached.

A run's decision is the watch's record of the detection the run counted: same technique, seen
at the run's attack time plus the latency the run measured, to a few seconds — the run report
names no VM, and its window is gone after a week.
"""
from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eregion_core import run_report
from eregion_core.run_report import CONTAINING as DISRUPTIVE
from eregion_core.run_report import epoch as _ts

WINDOW_DAYS = 30
# The detection a run counted was measured from the watch's own record (annatar/runner/
# detection.py): its signal time is the run's attack time plus that latency, to rounding.
MATCH_SLACK_S = 5.0


def read_runs(reports: dict[str, Path], since: float) -> list[dict]:
    """The runs of the period, from their reports, in the unified view of C1
    (``eregion_core.run_report.read_run``): an attack (``technique``) is dated by its attack
    time, a fault by its start. A report without a date in the period is left out."""
    runs = []
    for run in run_report.read_reports(reports):
        at = run["at"]
        if at is None or at < since:
            continue
        runs.append(run)
    return runs


class Detections:
    """The watch's detection records with a decision, indexed once by technique and sorted by
    their signal's time — so that a run's decision is found by bisection, not by reading every
    cycle for every run (C1: the matrix reads the whole history at every refresh). A run's
    decision is kept by run id for the life of the index (one computation)."""

    def __init__(self, cycles: list[dict]):
        by_ttp: dict[str, list[tuple[float, dict]]] = {}
        for c in cycles:
            if c.get("event") == "detection" and c.get("action") \
                    and (t := _ts(c.get("signal_at"))) is not None:
                by_ttp.setdefault(str(c.get("ttp") or ""), []).append((t, c))
        self.by_ttp = {ttp: ([t for t, _ in rows], [c for _, c in rows])
                       for ttp, rows in ((k, sorted(v, key=lambda x: x[0])) for k, v in by_ttp.items())}
        self.memo: dict[str, dict | None] = {}
        # BL1: every cycle as given — a release on a recovery, a decision on a fault's VM.
        self.cycles = list(cycles)


def detections(cycles) -> Detections:
    return cycles if isinstance(cycles, Detections) else Detections(cycles)


def decision_of(run: dict, cycles) -> dict | None:
    """The watch's decision on the detection the run counted, or None: a run not detected, or
    without its latency, has none that can be told apart. ``cycles``: the watch's cycles, or
    their ``Detections`` index.

    The record of the run's own technique (its experiment, which for an attack is its
    ``mitre``), seen at the run's attack time plus its latency to a few seconds, on the run's
    VM when its report names one (``metrics.resource_id``, C1); among several, the closest to
    that time."""
    if run["kind"] != "technique" or run["detection"] != "detected" or run["latency"] is None:
        return None
    if run.get("experiment", run["ttp"]) != run["ttp"]:
        return None
    index = detections(cycles)
    if run["run_id"] in index.memo:
        return index.memo[run["run_id"]]
    seen_at = run["at"] + run["latency"]
    times, cands = index.by_ttp.get(run["ttp"], ([], []))
    lo = bisect_left(times, seen_at - MATCH_SLACK_S)
    hi = bisect_right(times, seen_at + MATCH_SLACK_S)
    vm = str(run.get("resource_id") or "").lower()
    found = [(t, c) for t, c in zip(times[lo:hi], cands[lo:hi])
             if not vm or str(c.get("resource_id") or "").lower() == vm]
    best = min(found, key=lambda tc: (abs(tc[0] - seen_at), tc[0]))[1] if found else None
    index.memo[run["run_id"]] = best
    return best


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def compute(runs: list[dict], cycles: list[dict], cards: list[dict], catalog: list[dict],
            wrong_30: dict, wrong_7: dict, threshold: float, now: float,
            all_cards: list[dict] | None = None, liftings=()) -> dict:
    """The five indicators, from what ``read_runs`` and the watch's files give (the API reads
    them). ``wrong_*``: ``glorfindel.escalations.observation_report``'s ``disruptive``.
    ``all_cards``: every card of the host — an isolation that did not hold is one (BL1)."""
    from analysis import containment
    attacks = [r for r in runs if r["kind"] == "technique"]
    detected = [r for r in attacks if r["detection"] == "detected"]
    cycles = detections(cycles)
    every_cycle = cycles.cycles
    judged_wrong = {c.get("exercise_run") for c in cards if c.get("verdict") == "wrong"}
    detect, decide, contain = [], [], []
    alone = shadow = 0
    proofs = []
    taken: set[str] = set()
    # The lifts of a containment the watch's cycles show (a release on a recovery); the
    # operator's own are in runs/manual_actions.jsonl, passed by the API.
    liftings = [x for c in every_cycle if (x := containment.lifting_of(c)) is not None] + list(liftings or ())
    for r in detected:
        if r["latency"] is not None:
            detect.append(r["latency"])
        d = decision_of(r, cycles)
        if d is None:
            continue
        proofs.append(r)
        decided_at = _ts(d.get("at"))
        if decided_at is not None and decided_at >= r["at"]:
            decide.append(decided_at - r["at"])
        disruptive = d.get("action") in DISRUPTIVE
        # The one definition of the time to contain on the overview (C1 and BL1 merged): BL1's
        # (analysis/containment.py) — executed in the cycle, read back on Azure, held — whose
        # time is run_report.timeline's, the matrix's. The VM: the run's own (C1), else the
        # decision's.
        inc = containment.incident(r["run_id"], r["ttp"], r.get("resource_id") or d.get("resource_id", ""),
                                   r["at"], "detected", d, cards=all_cards or (), liftings=liftings)
        if inc.outcome == containment.CONTAINED:
            alone += 1
            if inc.time_to_contain_s is not None:
                contain.append(inc.time_to_contain_s)
        taken.add(d.get("signal_id") or "")
        conf = d.get("confidence")
        if (disruptive and isinstance(conf, (int, float)) and conf >= threshold
                and r["run_id"] not in judged_wrong):
            shadow += 1

    techniques = [e for e in catalog if e.get("kind") == "technique"]
    implemented = {e["id"] for e in techniques if e.get("status") == "implemented"}
    covered = {r["ttp"] for r in detected}
    faults = [r for r in runs if r["kind"] == "fault"]
    checked = [containment.fault_run(f["run_id"], f.get("experiment", ""), f.get("targets") or [],
                                     f["at"], f.get("ended_at"), every_cycle, taken=taken - {""},
                                     without_glorfindel=f.get("without_glorfindel") is True)
               for f in faults]

    last = max(proofs, key=lambda r: r["at"]) if proofs else None
    proven_at = {}
    for r in proofs:
        proven_at[r["ttp"]] = max(proven_at.get(r["ttp"], 0.0), r["at"])
    stale = sorted(implemented, key=lambda t: (proven_at.get(t, 0.0), t))   # never proven first

    def rate(d: dict) -> dict:
        judged = (d.get("right") or 0) + (d.get("wrong") or 0)
        return {"rate": d.get("false_rate"), "judged": judged, "wrong": d.get("wrong") or 0}

    return {
        "window_days": WINDOW_DAYS,
        "contain": {"detect_s": _median(detect), "decide_s": _median(decide),
                    "contain_s": _median(contain), "detected": len(detected),
                    "decided": len(decide), "contained": len(contain)},
        "alone": {"contained": alone, "shadow": shadow, "of": len(detected),
                  "threshold": threshold if threshold != float("inf") else None,
                  "attacks": len(attacks),
                  "faults_mistaken": sum(1 for f in checked if f.mistaken),
                  "disruptive_on_faults": sum(f.executed for f in checked),
                  "faults_unchecked": sum(1 for f in checked if f.why)},
        "wrong": {"days_30": rate(wrong_30), "days_7": rate(wrong_7)},
        "coverage": {"implemented": len(implemented), "implemented_detected": len(implemented & covered),
                     "catalog": len(techniques),
                     "catalog_detected": len({e["id"] for e in techniques} & covered),
                     "faults": len(faults),
                     "faults_pass": sum(1 for r in faults if r["result"] == "PASS")},
        "last_proof": ({"run_id": last["run_id"], "ttp": last["ttp"],
                        "at": datetime.fromtimestamp(last["at"], timezone.utc).isoformat(),
                        "age_s": round(now - last["at"])} if last else None),
        "stalest": [{"ttp": t, "at": datetime.fromtimestamp(proven_at[t], timezone.utc).isoformat()
                     if t in proven_at else None} for t in stale],
    }


def since_window(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) - timedelta(days=WINDOW_DAYS)
