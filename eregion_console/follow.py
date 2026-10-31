"""Dagorlad, phase (c): a request followed live (DG-c, #349; docs/design/console.md, §7).

Each wire of a request becomes a line of the chronology, read from what already reaches this
host — no new channel, nothing written, the model never called:

- **requested**: the request, written here (``~/.eregion/console/requests/``, DG-b);
- **Orodruin**: its status, pulled by the watch (``runs/orodruin/requests/<id>.json``) — per
  wire its state, its code and its runs, never what the wire is;
- **launched**: the exercise window its injector opened on the target, which carries the
  request's id. Orodruin's status names its runs; before it does, the window's experiment and
  target name its wire (a request holds a pair once);
- **T0**: the window's start while the run goes on; the attack time (a fault's start) of the
  run's report once it is here;
- **detected, the decision**: the watch's cycle of the wire's own technique, on its target,
  inside the window (``covering_runs``, the return channel's rule) — once the report is here,
  the one ``indicators.decision_of`` attaches;
- **contained**: BL1's definition (``analysis/containment.py``) — executed in its cycle, read
  back on Azure, and held. For a fault: a decision to isolate or to block on its target during
  it (a fault taken for an attack), and its return, verified;
- **the cards** that carry the run (``exercise_run``), and **the verdict**, the run's report (#193).

**A run is measured here as on the overview.** Once its report is here, its decision, its times
and its ending are the indicators' (``indicators.decision_of``, ``run_report.timeline``,
``indicators.incident_of``). Before, the same functions on the window — its start for T0, the
first detection of its own technique inside it — and the line says so (``provisional``).

**The request's phase**: ``written`` (Orodruin not heard: the command is not carried yet; its
status there but unreadable is never that — ``status_unreadable``), ``running``, then ``over``:
Orodruin says it finished or refused it; or a window of it was closed by « Stop all »
(``orodruin-kill``); or no window of it is live and Orodruin has said nothing for longer than it
ever stays silent between two wires (``SILENT_S``) — the kill stops its runner unsaid. A window
counts as live within the bounds a window may hold only (``alive``): one forged, or on a clock
off, never keeps the wires locked. Over, the page unlocks the wires, each keeping its last result.

**What a fault is measured against**: the decisions the overview attaches to an attack — of the
request or of any run of this host since it began (``others``) — are never the fault's, as on the
overview; the techniques of the request are measured first, their live decisions taken too.

**Its reads**: those of the files of this host — and, as ``/api/exercises``, the enrollment of
each target the watch's cycles name (``covering_runs``: ``TagEnrollment``, the console's identity,
cached ten minutes), never anything else of Azure.

Pure functions over what the API reads. Glorfindel never reads what this computes (« Glorfindel
reste aveugle »).
"""
from __future__ import annotations

import math
from datetime import datetime

from analysis import containment
from eregion_console import indicators
from eregion_core import run_report
from eregion_core.exercise import FUTURE_SKEW_S, GRACE_AFTER_S, MAX_DURATION_S, covering_runs, last_moment
from eregion_core.exercise_runner import WAIT_ISOLATION_S
from eregion_core.run_report import epoch, iso

# Orodruin silent this long, and no window of the request live: the request is taken as over.
# Its runner publishes the status before and after each wire; between two, it says nothing only
# while it waits for a VM Glorfindel holds (WAIT_ISOLATION_S at most) — and a wire ended keeps its
# window live through the grace. « Stop all » between two wires closes no window: this ends it.
SILENT_S = WAIT_ISOLATION_S + GRACE_AFTER_S
KILLED_BY = "orodruin-kill"
LIVE = ("open", "grace")
OVER = ("finished", "refused")


def alive(window: dict, state: str, now: datetime) -> bool:
    """A window of the request live — by its state, within the bounds a window may hold: a start
    no later than the clocks' skew allows, a life no longer than an injector's ceiling
    (``MAX_DURATION_S``), plus the grace. A window beyond them (a clock off, a window forged with
    the request's id) never keeps the request running, nor its wires locked (DG-c review)."""
    if state not in LIVE:
        return False
    start = epoch(window.get("start"))
    if start is None or start > now.timestamp() + FUTURE_SKEW_S:
        return False
    ends = [t for t in (epoch(window.get("expires")), epoch(window.get("end")), start + MAX_DURATION_S)
            if t is not None]
    return now.timestamp() <= min(ends) + GRACE_AFTER_S


def _experiment_id(window: dict) -> str:
    return str(window.get("experiment") or "").split(" ")[0]


def phase(status: dict | None, mine: list[dict], states: dict[str, str], now: datetime, *,
          begun: float | None = None, unreadable: str = "") -> tuple[str, str]:
    """``(phase, why)``: ``written``, ``running`` (why: Orodruin's state, ``launched`` when only a
    window says it, ``status_unreadable``), or ``over`` (``finished``, ``refused``, ``stopped``,
    ``silent``). ``begun``: the request's time (epoch); ``unreadable``: why Orodruin's status is
    there but not read — never « not carried yet » (A0: Orodruin may be running it)."""
    if status and status.get("state") in OVER:
        return "over", status["state"]
    # A window that cannot have started yet (beyond the clocks' skew) says nothing of the request.
    mine = [w for w in mine if (s := epoch(w.get("start"))) is not None and s <= now.timestamp() + FUTURE_SKEW_S]
    # « Stop all » ends the request: the kill stops Orodruin's runner, no other wire leaves.
    if any(w.get("closed_by") == KILLED_BY for w in mine):
        return "over", "stopped"
    if any(alive(w, states.get(w["run_id"], ""), now) for w in mine):
        return "running", (status or {}).get("state") or ("status_unreadable" if unreadable else "launched")
    # A time ahead of the clock (beyond its skew) is no time: it never keeps a request running.
    heard = [t for t in [begun, epoch((status or {}).get("at"))] + [epoch(w.get("end") or w.get("start")) for w in mine]
             if t is not None and t <= now.timestamp() + FUTURE_SKEW_S]
    if heard and now.timestamp() - max(heard) > SILENT_S:
        return "over", "silent"
    if status:
        return "running", status.get("state") or ""
    if unreadable:
        return "running", "status_unreadable"
    return ("running", "launched") if mine else ("written", "")


def _first_own(window: dict, ttp: str, cycles: list[dict], enrolled) -> dict | None:
    """The first record of the wire's own technique with a decision on a target of the window,
    inside it — what the run's detection will be. A row anchored on an arbitrary VM names none."""
    found = [c for c in cycles if c.get("event") == "detection" and c.get("action")
             and ttp and c.get("ttp") == ttp
             and (not c.get("attribution") or c.get("attribution") == "asset")
             and window["run_id"] in covering_runs(c.get("resource_id") or "", c.get("signal_at"),
                                                   [window], enrolled=enrolled)]
    return min(found, key=lambda c: (epoch(c.get("signal_at")) or 0.0)) if found else None


def _decision(t: dict, decision: dict | None) -> dict | None:
    if not decision:
        return None
    return {**{k: t[k] for k in ("action", "confidence", "executed", "verified", "mode", "decide_s")},
            "status": str(decision.get("status") or ""),
            "guard": str(decision.get("escalation_type") or ""),
            "at": iso(t["decided_at"])}


def _technique(line: dict, run_id: str, window: dict | None, rep: dict | None, ctx: dict) -> None:
    """The times and the ending of an attack run: the report's, measured as the overview measures
    them; else the window's, provisional."""
    if rep is not None:
        decision = indicators.decision_of(rep, ctx["index"])
        t = run_report.timeline(rep, decision)
        inc = indicators.incident_of(rep, decision, ctx["cards"], ctx["liftings"])
        line.update(t0=iso(rep["at"]), t0_from="attack", provisional=False,
                    detection=rep["detection"])
    else:
        start = epoch((window or {}).get("start"))
        if start is None:
            return
        decision = _first_own(window, line["experiment"] or _experiment_id(window), ctx["cycles"],
                              ctx["enrolled"])
        t = run_report.timeline({"at": start, "detected_at": epoch(decision.get("signal_at")) if decision else None},
                                decision)
        inc = containment.incident(run_id, line["experiment"], line["target"], start, "detected", decision,
                                   cards=ctx["cards"], liftings=ctx["liftings"]) if decision else None
        line.update(t0=iso(start), t0_from="window start", provisional=True,
                    detection="detected" if decision else "")
    line.update(detected_at=iso(t["detected_at"]), detect_s=t["detect_s"], decision=_decision(t, decision))
    if inc is not None:
        if decision:
            ctx["taken"].add(str(decision.get("signal_id") or ""))
        line.update(outcome=inc.outcome, outcome_why=inc.why, contain_s=inc.time_to_contain_s)


def _fault(line: dict, run_id: str, window: dict | None, rep: dict | None, raw: dict | None,
           ctx: dict, now: datetime) -> None:
    """A fault expects nothing disruptive: the decisions to isolate or to block on its targets
    during it, as the overview counts them; and its return, verified (its report)."""
    if rep is not None:
        fr = containment.fault_run(run_id, rep["experiment"], rep["targets"], rep["at"], rep["ended_at"],
                                   ctx["cycles"], taken=ctx["taken"] - {""},
                                   without_glorfindel=rep["without_glorfindel"])
        checks = raw.get("checks") if isinstance(raw.get("checks"), dict) else {}
        metrics = raw.get("metrics") if isinstance(raw.get("metrics"), dict) else {}
        restore = metrics.get("time_to_restore_s")
        line.update(t0=iso(rep["at"]), t0_from="fault start", provisional=False,
                    returned={"PASS": True, "FAIL": False}.get(checks.get("revert_verified")),
                    restore_s=float(restore) if isinstance(restore, (int, float))
                    and not isinstance(restore, bool) and math.isfinite(restore) else None)
    else:
        start = epoch((window or {}).get("start"))
        if start is None:
            return
        until = now if ctx["states"].get(run_id) == "open" else last_moment(window)
        fr = containment.fault_run(run_id, line["experiment"], window.get("targets") or [line["target"]], start,
                                   window.get("end"), ctx["cycles"], window_until=until,
                                   taken=ctx["taken"] - {""})
        line.update(t0=iso(start), t0_from="window start", provisional=True)
    line.update(mistaken=[{"action": m["action"], "executed": m["executed"], "at": iso(m["seen_at"]),
                           "confidence": m["confidence"]} for m in fr.mistaken],
                unchecked=fr.why)


def follow(request_id: str, wires: list[dict], status: dict | None, windows: list[dict],
           states: dict[str, str], cycles: list[dict], reports: dict[str, dict], cards: list[dict],
           to_judge: set[str], *, now: datetime, catalog: dict | None = None, liftings=(),
           enrolled=None, others=(), begun: float | None = None, unreadable: str = "") -> dict:
    """The chronology of a request. ``wires``: the request's, as written here (rank, experiment,
    target) — [] when it was not, then the ranks Orodruin names; ``windows``: every window
    (``_read_windows``), ``states`` their state; ``cycles``: the watch's, slimmed; ``reports``:
    run id → its report as loaded; ``cards``: every card; ``to_judge``: the ids of the cards
    waiting for a verdict; ``liftings``: the operator's lifts of a containment; ``others``: every
    run of this host since the request began (``indicators.read_runs``) — the decisions the
    overview attaches to an attack are never a fault's, as there; ``begun``: the request's time;
    ``unreadable``: why Orodruin's status is there but not read."""
    mine = sorted((w for w in windows if w.get("request") == request_id),
                  key=lambda w: str(w.get("start") or ""))
    by_rank = {w["rank"]: w for w in (status or {}).get("wires") or []}
    if not wires:
        wires = [{"rank": r, "experiment": "", "target": ""} for r in sorted(by_rank)]
    index = indicators.detections(cycles)
    # As the overview: a decision attached to an attack run is that run's, never a fault's.
    taken = {str((indicators.decision_of(r, index) or {}).get("signal_id") or "") for r in others
             if r.get("kind") == "technique"}
    ctx = {"cycles": cycles, "index": index, "cards": cards, "states": states,
           "liftings": indicators.liftings_of(cycles, liftings), "enrolled": enrolled, "taken": taken}
    by_run = {w["run_id"]: w for w in mine}
    claimed = {r for sw in by_rank.values() for r in sw.get("runs") or []}
    # First each wire's run, its window, its report, what it is (the catalogue's word, else its
    # window's, else its report's)…
    found = []
    for w in wires:
        sw = by_rank.get(w["rank"])
        runs = list((sw or {}).get("runs") or [])
        for win in mine:   # before Orodruin names them: the window's experiment and target
            if (win["run_id"] not in runs and win["run_id"] not in claimed and w["experiment"]
                    and _experiment_id(win) == w["experiment"] and w["target"].lower() in win.get("targets", [])):
                runs.append(win["run_id"])
        runs.sort(key=lambda r: str(by_run.get(r, {}).get("start") or ""))
        run_id = runs[-1] if runs else ""
        window = by_run.get(run_id)
        raw = reports.get(run_id) if run_id else None
        rep = run_report.read_run(raw, run_id) if isinstance(raw, dict) else None
        kind = (getattr((catalog or {}).get(w["experiment"]), "kind", "") or str((window or {}).get("kind") or "")
                or (rep or {}).get("kind", ""))
        found.append((w, sw, runs, run_id, window, raw, rep, kind))
    # …then the techniques before the faults: a decision attached to an attack of the request,
    # live, is not the fault's either.
    lines = []
    for w, sw, runs, run_id, window, raw, rep, kind in sorted(found, key=lambda f: (f[7] == "fault", f[0]["rank"])):
        wstate = states.get(run_id, "") if window else ""
        line = {"rank": w["rank"], "experiment": w["experiment"], "kind": kind, "target": w["target"],
                "target_name": str(w["target"]).rstrip("/").rsplit("/", 1)[-1],
                "state": (sw or {}).get("state") or ("running" if wstate == "open" else "launched" if runs else "queued"),
                "heard": sw is not None, "code": (sw or {}).get("code") or "", "runs": runs, "run": run_id,
                "window": ({k: window.get(k) for k in ("start", "end", "closed_by", "refusal")} | {"state": wstate})
                if window else None,
                "t0": None, "t0_from": "", "provisional": False, "detection": "", "detected_at": None,
                "detect_s": None, "decision": None, "outcome": "", "outcome_why": "", "contain_s": None,
                "mistaken": [], "unchecked": "", "returned": None, "restore_s": None,
                "cards": [], "verdict": None}
        if run_id:
            if kind == "fault":
                _fault(line, run_id, window, rep, raw, ctx, now)
            else:
                _technique(line, run_id, window, rep, ctx)
            line["cards"] = [{"id": str(c.get("id") or ""), "type": str(c.get("escalation_type") or ""),
                              "action": str(c.get("action") or ""), "to_judge": c.get("id") in to_judge}
                             for c in cards if c.get("exercise_run") == run_id]
        if rep is not None:
            line["verdict"] = {"result": rep["result"], "detection": rep["detection"] if rep["kind"] == "technique" else "",
                               "without_glorfindel": rep["without_glorfindel"]}
        lines.append(line)
    p, why = phase(status, mine, states, now, begun=begun, unreadable=unreadable)
    return {"phase": p, "why": why, "wires": sorted(lines, key=lambda x: x["rank"])}
