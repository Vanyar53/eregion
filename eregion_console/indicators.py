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

import json
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW_DAYS = 30
# The detection a run counted was measured from the watch's own record (annatar/runner/
# detection.py): its signal time is the run's attack time plus that latency, to rounding.
MATCH_SLACK_S = 5.0
DISRUPTIVE = ("isolate_vm", "block_suspicious_ip")


def _ts(value) -> float | None:
    """Epoch seconds from a number or an ISO time; None otherwise (NaN included)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if value == value and abs(value) != float("inf") else None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def read_runs(reports: dict[str, Path], since: float) -> list[dict]:
    """The runs of the period, from their reports: an attack (``technique``) is dated by its
    attack time, a fault by its start. A report without a date in the period is left out."""
    runs = []
    for run_id, path in reports.items():
        try:
            r = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(r, dict):
            continue
        m = r.get("metrics") if isinstance(r.get("metrics"), dict) else {}
        fault = m.get("injector") == "gothmog"
        at = _ts(m.get("fault_start") if fault else m.get("attack_time"))
        if at is None or at < since:
            continue
        latency = m.get("detection_latency_s")
        runs.append({"run_id": str(r.get("run_id") or run_id), "kind": "fault" if fault else "technique",
                     "ttp": str(r.get("mitre") or ""), "at": at, "result": r.get("result", ""),
                     "detection": m.get("detection") or "unknown",
                     "latency": float(latency) if _ts(latency) is not None and latency >= 0 else None,
                     # A fault's targets and end (BL1: a decision on them during it was one taken
                     # for an attack); without Glorfindel, its reaction was not measured.
                     **({"fault": str(m.get("fault") or ""), "end": m.get("fault_end"),
                         "targets": [str(x) for x in m.get("targets") or [] if x],
                         "without_glorfindel": m.get("without_glorfindel") is True} if fault else {})})
    return runs


def decision_of(run: dict, cycles: list[dict]) -> dict | None:
    """The watch's decision on the detection the run counted, or None: a run not detected, or
    without its latency, has none that can be told apart."""
    if run["kind"] != "technique" or run["detection"] != "detected" or run["latency"] is None:
        return None
    seen_at = run["at"] + run["latency"]
    found = [c for c in cycles
             if c.get("event") == "detection" and c.get("action") and c.get("ttp") == run["ttp"]
             and (t := _ts(c.get("signal_at"))) is not None and abs(t - seen_at) <= MATCH_SLACK_S]
    return min(found, key=lambda c: _ts(c["signal_at"])) if found else None


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def compute(runs: list[dict], cycles: list[dict], cards: list[dict], catalog: list[dict],
            wrong_30: dict, wrong_7: dict, threshold: float, now: float,
            all_cards: list[dict] | None = None) -> dict:
    """The five indicators, from what ``read_runs`` and the watch's files give (the API reads
    them). ``wrong_*``: ``glorfindel.escalations.observation_report``'s ``disruptive``.
    ``all_cards``: every card of the host — an isolation that did not hold is one (BL1)."""
    from analysis import containment
    attacks = [r for r in runs if r["kind"] == "technique"]
    detected = [r for r in attacks if r["detection"] == "detected"]
    judged_wrong = {c.get("exercise_run") for c in cards if c.get("verdict") == "wrong"}
    detect, decide, contain = [], [], []
    alone = shadow = 0
    proofs = []
    taken: set[str] = set()
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
        # BL1: one definition with the campaign report's (analysis/containment.py) — executed in
        # the cycle, read back on Azure, held; the time ends at the read-back.
        inc = containment.incident(r["run_id"], r["ttp"], d.get("resource_id", ""), r["at"],
                                   "detected", d, cards=all_cards or ())
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
    checked = [containment.fault_run(f["run_id"], f.get("fault", ""), f.get("targets") or [], f["at"],
                                     f.get("end"), cycles, taken=taken - {""},
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
