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
    from eregion_console import runs_reader
    for run in run_report.read_reports(reports, runs_reader.read_json):   # SEC15
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


def liftings_of(cycles, manual=()) -> list[tuple]:
    """The lifts of a containment: those the watch's cycles show (a release on a recovery), and
    the operator's own (``manual``: runs/manual_actions.jsonl, read by the API)."""
    from analysis import containment
    every = detections(cycles).cycles
    return [x for c in every if (x := containment.lifting_of(c)) is not None] + list(manual or ())


def incident_of(run: dict, decision: dict | None, cards=(), liftings=(), t0_refused: str = ""):
    """How an attack run ended, by BL1's definition (``analysis/containment.py``: executed in its
    cycle, read back on Azure, held) — the one call the overview and Dagorlad's follow make
    (DG-c: a run is not measured otherwise there). The VM: the run's own (C1), else the
    decision's. ``t0_refused``: why its T0 is not believed (``t0_confronted``) — no time is
    counted from it."""
    from analysis import containment
    d = decision or {}
    return containment.incident(run["run_id"], run["ttp"], run.get("resource_id") or d.get("resource_id", ""),
                                run["at"], run["detection"], decision, cards=cards, liftings=liftings,
                                t0_refused=t0_refused)


def t0_confronted(run: dict, decision: dict | None, window: dict | None, cycles,
                  requests=None) -> tuple[str, str]:
    """``(why its T0 is not believed, why the request is unread)`` — "" for each when it is
    (SEC9, SEC15): an attack run's T0 is its injector's word, confronted as the campaign report
    confronts it (``containment.t0_refusal``) with its exercise window as this host holds it
    (``window``: believed, refused or purged — None when it holds none), the Dagorlad request
    that launched it (``requests``: the console's own store, ``containment.request_at``), the
    decision attached, the attack time the watch received in the run and its first sight of the
    VM there (``cycles``: the watch's, slimmed; a run's own files, the poll of its
    ``attack_started``, are no sight of the watch's)."""
    from analysis import containment
    every = detections(cycles).cycles
    asked, unread = containment.request_at(window, requests)
    vm = run.get("resource_id") or (decision or {}).get("resource_id", "")
    refused = containment.t0_refusal(
        run["at"], window, [c for c in every if not c.get("own")], vm, request_at=asked,
        decision_seen=containment.view(decision)["seen_at"] if decision else None,
        received=containment.received_t0(every, run["run_id"]))
    return refused, unread


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 1) if values else None


def compute(runs: list[dict], cycles: list[dict], cards: list[dict], catalog: list[dict],
            wrong_30: dict, wrong_7: dict, threshold: float, now: float,
            all_cards: list[dict] | None = None, liftings=(), windows: dict | None = None,
            requests=None) -> dict:
    """The five indicators, from what ``read_runs`` and the watch's files give (the API reads
    them). ``wrong_*``: ``glorfindel.escalations.observation_report``'s ``disruptive``.
    ``all_cards``: every card of the host — an isolation that did not hold is one (BL1).
    ``windows``: run id → its exercise window as this host holds it (believed, refused or
    purged): each run's T0 is confronted with it (``t0_confronted``, SEC15) — a T0 refused gives
    no time (to detect, to decide, to contain), and is counted as such (``t0_refused``; of them,
    ``t0_purged``: its window purged, a week after its end). None: not confronted (the API always
    gives them)."""
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
    liftings = liftings_of(cycles, liftings)
    refused_t0 = purged_t0 = 0
    for r in detected:
        d = decision_of(r, cycles)
        # SEC15: the T0 is the injector's word, confronted as the campaign report confronts it —
        # refused, no time is counted from it, and it is said; a window purged (a week after its
        # end) is said apart: the older runs of the 30 days are no longer timed.
        held = windows.get(r["run_id"]) if windows is not None else None
        refused = t0_confronted(r, d, held, cycles, requests)[0] if windows is not None else ""
        refused_t0 += bool(refused)
        purged_t0 += bool(refused) and isinstance(held, dict) and bool(held.get("purged_at"))
        if r["latency"] is not None and not refused:
            detect.append(r["latency"])
        if d is None:
            continue
        proofs.append(r)
        decided_at = _ts(d.get("at"))
        if decided_at is not None and decided_at >= r["at"] and not refused:
            decide.append(decided_at - r["at"])
        disruptive = d.get("action") in DISRUPTIVE
        # The one definition of the time to contain on the overview (C1 and BL1 merged): BL1's
        # (analysis/containment.py) — executed in the cycle, read back on Azure, held — whose
        # time is run_report.timeline's, the matrix's. The VM: the run's own (C1), else the
        # decision's.
        inc = incident_of(r, d, all_cards or (), liftings, t0_refused=refused)
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
                    "decided": len(decide), "contained": len(contain), "t0_refused": refused_t0,
                    "t0_purged": purged_t0},
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


# ── Real traffic (OV1, #399): what Glorfindel does outside any exercise ───────────────────
# The overview counts it; the exercises' indicators (``compute``, above) go to Dagorlad. An
# incident is a detection of the watch with a decision, on a VM it names (an unattributed row is
# anchored on an arbitrary one), outside any exercise. It ends as BL1 says
# (analysis/containment.py, the same ``incident``): contained alone when an isolation or a block
# is executed in its cycle, read back on Azure, and held. Its T0 is the detection's time: no rule
# gives its first malicious event yet (docs/analysis.md, « Le réel »). One attacker on one VM is one
# incident: a later cycle of the same address, technique and VM within FOLD_S of its first detection
# (the rule's own dedup lasts its window only: a block held, the attack goes on and comes back) is a
# repeat, never another incident — and a line written twice (its signal) is one.
FOLD_S = 24 * 3600

def _spans(run: dict, rid: str, ttp: str, t: float) -> bool:
    """A run report holds this moment on this VM: a fault from its start to its end, plus the
    grace; an attack from its T0 (a clock's skew before) to the most a window may last, plus the
    grace — wide on purpose: an exercise is never counted as real traffic. An attack report
    written before C1 names no VM: its technique then, over the same span, on any VM."""
    from eregion_core.exercise import FUTURE_SKEW_S, GRACE_AFTER_S, MAX_DURATION_S
    at = run.get("at")
    if at is None:
        return False
    if run.get("kind") == "fault":
        on = any(str(x).lower() == rid for x in run.get("targets") or [])
        end = run.get("ended_at") if run.get("ended_at") is not None else at + MAX_DURATION_S
        return on and at <= t <= end + GRACE_AFTER_S
    vm = str(run.get("resource_id") or "").lower()
    on = vm == rid if vm else bool(ttp) and str(run.get("ttp") or run.get("experiment") or "") == ttp
    return on and at - FUTURE_SKEW_S <= t <= at + MAX_DURATION_S + GRACE_AFTER_S


def exercise_of(cycle: dict, windows=(), runs=(), enrolled=None, attached=frozenset()) -> tuple[bool, bool]:
    """``(an exercise?, inferred?)``. Only the watch's « exercise » is final: its « real » is
    checked again, as a line it never labelled — a window can reach the host late, by the
    channel, and the Runs then attach the cycle to it. An exercise, inferred: the decision the
    overview attaches to a run of the period (``attached``: the ids of those cycles), a window
    still on this host that covers it (the watch's own rule, ``covering_runs``: an enrolled VM,
    its zone), or a run report whose span holds it on its VM. Neither: real traffic — inferred
    unless the watch said it."""
    said = cycle.get("source")
    if said == "exercise":
        return True, False
    if id(cycle) in attached:
        return True, True
    from eregion_core.exercise import covering_runs
    rid, at, ttp = str(cycle.get("resource_id") or "").lower(), cycle.get("signal_at"), str(cycle.get("ttp") or "")
    if windows and rid and covering_runs(rid, at, list(windows), enrolled=enrolled):
        return True, True
    t = _ts(at)
    if t is not None and rid and any(_spans(r, rid, ttp, t) for r in runs):
        return True, True
    return False, said != "real"


def _broken(rid: str, since: float, t: float, lifts, cards) -> bool:
    """The attacker's incident on this VM is over before ``t``: its containment lifted (a release,
    an unblock, a reset), or a card says it no longer holds — the next cycle is another incident,
    never folded into one « contained » (OV1 review)."""
    from analysis import containment
    return any((lifted := containment.first_lifting(rid, since, lifts, action)) is not None and lifted <= t
               for action in DISRUPTIVE) or containment.not_holding(rid, since, t, cards) is not None


def real(cycles, cards: list[dict], threshold: float, since: float, *, windows=(), runs=(),
         all_cards=(), liftings=(), enrolled=None, now: float | None = None) -> dict:
    """The overview's TIME TO CONTAIN and CONTAINED ALONE on real traffic, over the cycles seen
    since ``since``. ``cards``: every card (a verdict « wrong » takes a decision out of the
    shadow); ``windows``, ``runs``: what tells an older line's exercise (``exercise_of``);
    ``liftings``: the operator's lifts of a containment (runs/manual_actions.jsonl)."""
    import time as _time

    from analysis import containment
    from eregion_core.exercise import FUTURE_SKEW_S
    # A cycle dated ahead of the clock (beyond its skew) counts nowhere, as a run (C1).
    until = (now if now is not None else _time.time()) + FUTURE_SKEW_S
    index = detections(cycles)
    lifts = liftings_of(index, liftings)
    every_card = all_cards or cards
    # The decisions the overview's indicators attach to a run: an exercise's, whatever the line says.
    attached = {id(d) for r in runs if r.get("kind") == "technique" and (d := decision_of(r, index)) is not None}
    judged_wrong = {c.get("signal_id") for c in cards if c.get("verdict") == "wrong" and c.get("signal_id")}
    decide, contain = [], []
    alone = shadow = inferred = inferred_exercise = repeats = 0
    outcomes: dict[str, int] = {}
    incidents = 0
    signals: set[str] = set()
    first: dict[tuple, float] = {}       # (VM, technique, attacker) → its incident's detection
    for c in sorted(index.cycles, key=lambda c: _ts(c.get("signal_at")) or 0.0):
        t0 = _ts(c.get("signal_at"))
        if (c.get("event") != "detection" or not c.get("action") or t0 is None or not since <= t0 <= until
                or (c.get("attribution") or "asset") != "asset"):
            continue
        exercise, guessed = exercise_of(c, windows, runs, enrolled, attached)
        if exercise:
            inferred_exercise += guessed
            continue
        sid = str(c.get("signal_id") or "")
        key = (str(c.get("resource_id") or "").lower(), str(c.get("ttp") or ""), str(c.get("attacker") or ""))
        if (sid and sid in signals) or (key[2] and key in first and t0 - first[key] < FOLD_S
                                        and not _broken(key[0], first[key], t0, lifts, every_card)):
            repeats += 1
            continue
        signals.add(sid)
        if key[2]:
            first[key] = t0
        incidents += 1
        inferred += guessed
        inc = containment.incident(str(c.get("signal_id") or ""), str(c.get("ttp") or ""),
                                   str(c.get("resource_id") or ""), t0, "detected", c,
                                   cards=every_card, liftings=lifts)
        outcomes[inc.outcome] = outcomes.get(inc.outcome, 0) + 1
        decided = _ts(c.get("at"))
        if decided is not None and decided >= t0:
            decide.append(decided - t0)
        if inc.outcome == containment.CONTAINED:
            alone += 1
            contain += [inc.time_to_contain_s] if inc.time_to_contain_s is not None else []
        conf = c.get("confidence")
        if (c.get("action") in DISRUPTIVE and isinstance(conf, (int, float)) and not isinstance(conf, bool)
                and conf >= threshold and c.get("signal_id") not in judged_wrong):
            shadow += 1
    return {
        "window_days": WINDOW_DAYS, "t0": "detection",
        "contain": {"contain_s": _median(contain), "decide_s": _median(decide), "detect_s": None,
                    "detected": incidents, "decided": len(decide), "contained": len(contain)},
        "alone": {"contained": alone, "shadow": shadow, "of": incidents,
                  "threshold": threshold if threshold != float("inf") else None,
                  "by_outcome": outcomes, "inferred": inferred, "inferred_exercise": inferred_exercise,
                  "repeats": repeats},
    }


def since_window(now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)) - timedelta(days=WINDOW_DAYS)
