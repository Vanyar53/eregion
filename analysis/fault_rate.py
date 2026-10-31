"""G1 (#76) — the rate of faults taken for an attack, over every Gothmog run: not only those
of a campaign (BL1, analysis/containment.py), the benign noise of G1 first — disk writes, load,
a restart, a shutdown — on which Glorfindel must neither isolate nor block.

    python -m analysis.fault_rate [--runs-dir runs] [--days 30] [--json]

Definitions (docs/analysis.md, « Le taux des pannes prises pour une attaque », decided with
Jonathan on 31/10):

- **A measured fault** is a Gothmog run that started, whose effect was seen in the telemetry
  Glorfindel reads (``checks.fault_effective`` PASS, gothmog/probes.py), run with a live
  Glorfindel watch, with its start, end and targets known. Every other run is **not measured**,
  and says why: noise Glorfindel never saw, or a run where its reaction was not measured by
  choice (``--without-glorfindel``), is never « Glorfindel did nothing ».
- **Taken for an attack**: at least one decision to isolate or to block one of its targets during
  it, recommended or executed — BL1's ``fault_run``, unchanged: a decision on a technique run on
  that VM in that technique's window is the technique's, never the fault's.
- **The rate** is the faults taken for an attack over the measured ones, per run; None when none
  is measured — never 0. Beside it: the disruptive recommendations (every such decision) and the
  executed ones (a disruptive action wrongly taken), and the same by fault.

Pure over the unified run view (``eregion_core.run_report.read_run``) and the watch's records:
no Azure, no model, no component imported (D1) — the console's indicators can feed it what they
already read (``eregion_console/indicators.py``), and the CLI reads this host's files.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from analysis import containment
from analysis.containment import FaultRun
from eregion_core import run_report

NOT_STARTED = "rien n'a été injecté"
NOT_SEEN = "son effet n'a pas été vu dans la télémétrie de Glorfindel : il ne mesure rien de sa réaction"
EFFECT_UNSAID = "son rapport ne dit pas si son effet a été vu"
WINDOW_DAYS = 30


def unmeasured(run: dict) -> str:
    """Why a fault run (a ``read_run`` view) measures nothing of Glorfindel, before its
    decisions are read — "" when it may. The rest (no watch, no start, end or target) is
    ``fault_run``'s own."""
    if run.get("started") is False:
        return NOT_STARTED
    if run.get("effective") is False:
        return NOT_SEEN
    if run.get("effective") is None:
        return EFFECT_UNSAID
    return ""


def played_of(runs) -> list[tuple]:
    """``(technique, VM, from, until)`` of the technique runs among ``runs``: a decision on that
    technique, on that VM, from its attack to the grace after it, is the technique's."""
    return [(r["ttp"], r.get("resource_id") or "", r["at"], r["at"] + containment.HOLD_WATCH_S)
            for r in runs if r.get("kind") == "technique" and r.get("at") is not None]


def measure(runs, records, *, taken=frozenset(), played=None) -> list[FaultRun]:
    """Each fault among ``runs`` (``read_run`` views), checked against the watch's ``records``.
    ``played``: the technique runs' windows, else those of ``runs``; ``taken``: the signal ids
    already attached to an incident (never counted twice)."""
    runs = list(runs)
    played = played_of(runs) if played is None else list(played)
    out = []
    for f in runs:
        if f.get("kind") != "fault":
            continue
        why = unmeasured(f)
        if why:
            out.append(FaultRun(f["run_id"], f.get("experiment") or "", list(f.get("targets") or []),
                                f.get("at"), f.get("ended_at"), why=why))
            continue
        out.append(containment.fault_run(
            f["run_id"], f.get("experiment") or "", f.get("targets") or [], f.get("at"),
            f.get("ended_at"), records, taken=taken,
            without_glorfindel=f.get("without_glorfindel") is True, played=played))
    return out


def _counts(checked: list[FaultRun]) -> dict:
    measured = [f for f in checked if not f.why]
    taken = sum(1 for f in measured if f.mistaken)
    return {"faults": len(checked), "measured": len(measured), "taken": taken,
            "rate": taken / len(measured) if measured else None,
            "recommended": sum(len(f.mistaken) for f in measured),
            "executed": sum(f.executed for f in measured)}


def rate(checked: list[FaultRun]) -> dict:
    """The rate, its counts, by fault, and the runs not measured with why."""
    by: dict[str, list[FaultRun]] = {}
    for f in checked:
        by.setdefault(f.fault or "?", []).append(f)
    return {**_counts(checked),
            "by_fault": {k: _counts(v) for k, v in sorted(by.items())},
            "unmeasured": [{"run_id": f.run_id, "fault": f.fault, "why": f.why}
                           for f in checked if f.why],
            "taken_runs": [{"run_id": f.run_id, "fault": f.fault, "mistaken": f.mistaken}
                           for f in checked if not f.why and f.mistaken]}


def _reports(runs_dir: Path) -> dict[str, Path]:
    """As the console finds them: ``runs/<run_id>.json``, else under its campaign."""
    found = {p.stem: p for p in runs_dir.glob("campaigns/*/runs/*.json")}
    found.update({p.stem: p for p in runs_dir.glob("*.json")})
    return found


def load(runs_dir: Path, *, days: int = WINDOW_DAYS, now: float | None = None) -> dict:
    """The rate over this host's runs of the last ``days``, from their reports and the watch's
    debug files."""
    from analysis import campaign_report as cr
    now = time.time() if now is None else now
    since = now - days * 86400
    runs = [r for r in run_report.read_reports(_reports(Path(runs_dir))) if since <= r["at"] <= now]
    records = cr._watch_files(Path(runs_dir))(since)
    return {"days": days, **rate(measure(runs, records))}


def render(summary: dict) -> str:
    """French, as the reports: the rate first, then what it is made of."""
    r = summary.get("rate")
    head = (f"Pannes prises pour une attaque : **{summary['taken']} sur {summary['measured']}** "
            f"mesurée(s)" + (f" ({r:.0%})" if r is not None else " (aucune mesurée : taux inconnu)"))
    lines = [head,
             f"- recommandation(s) d'isoler ou de bloquer : {summary['recommended']} ; "
             f"exécutée(s) : {summary['executed']}"]
    for fid, c in (summary.get("by_fault") or {}).items():
        lines.append(f"- `{fid}` : {c['taken']} sur {c['measured']} mesurée(s), "
                     f"{c['faults'] - c['measured']} non mesurée(s)")
    for u in summary.get("unmeasured") or []:
        lines.append(f"- non mesurée : `{u['run_id']}` ({u['fault'] or 'panne'}) — {u['why']}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m analysis.fault_rate", description=__doc__.split("\n")[0])
    ap.add_argument("--runs-dir", default="runs")
    ap.add_argument("--days", type=int, default=WINDOW_DAYS)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    summary = load(Path(args.runs_dir), days=args.days)
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False, default=lambda o: asdict(o)))
    else:
        print(render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
