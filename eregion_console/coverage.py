"""The coverage matrix (C1, #80): for each technique of the catalog and each declared fault,
its last proof — and what changed since.

Computed from what this host keeps, never from the cloud: the run reports (``runs/<id>.json``,
and those of the campaigns published, ``runs/campaigns/<id>/runs/``), read in the run format
both injectors share (``eregion_core/run_report.py``); the watch's cycles
(``runs/*_debug.jsonl``); the catalog (``technique_catalog.yaml``). Over the whole history the
host keeps, not 30 days: the age of a proof older than 30 days must be said, not hidden.

**A row** is an entry of the catalog, technique or fault (planned ones too) — and a run of an
experiment the catalog does not hold gets its own row, said outside the catalog. Each row
gives its runs, oldest first (``history``: the last ten outcomes, the matrix's evolution
for that row), its last run (date, detected or not, time to detect, Glorfindel's decision,
time to contain when an action was executed and verified) and its last proof.

**A proof**, for a technique, is a run detected AND whose decision is attached — the watch's
record of the detection the run counted (``indicators.decision_of``), detection and response;
for a fault, a run PASS (steady state before and after, return verified) with Glorfindel's
watch running — one run ``--without-glorfindel`` measured nothing of Glorfindel.

**The state of a row**, the first that holds:

- ``regressed`` — the non-regression: its last measured run failed (missed, or a fault FAIL)
  after an earlier one succeeded (detected, or PASS). A run that measured nothing
  (``unknown``, ``--without-glorfindel``, a fault REFUSED) neither proves nor regresses;
- ``proven`` (last proof under 21 days), ``aging`` (21 to 30), ``stale`` (over 30 days: the
  alert of the indicator « age of the last proof »);
- ``unproven`` — runs, none a proof;
- ``never`` — no run.

**The evolution** of the coverage: every week over the last twelve, the techniques detected
by a run of the 30 days before (the indicator, as it read that day — over today's catalog),
the faults PASS, and the rows regressed that day.

It feeds two indicators of the finality (``feed``): the coverage (the regressed techniques
beside the detected ones) and the age of the last proof (over the whole history).
"""
from __future__ import annotations

from eregion_console.indicators import WINDOW_DAYS, decision_of
from eregion_core.run_report import iso, timeline

DAY = 86400.0
AGING_DAYS = 21
STALE_DAYS = 30
HISTORY = 10
EVOLUTION_WEEKS = 12
GOOD = {"technique": "detected", "fault": "pass"}
BAD = {"technique": "missed", "fault": "fail"}


def outcome(run: dict) -> str:
    """What a run measured: an attack ``detected`` | ``missed`` | ``unknown`` |
    ``not_measured`` (--without-glorfindel); a fault ``pass`` | ``fail`` | ``refused`` |
    ``not_measured``."""
    if run["kind"] == "fault":
        if run["result"] == "REFUSED":
            return "refused"
        if run["without_glorfindel"]:
            return "not_measured"
        return "pass" if run["result"] == "PASS" else "fail"
    if run["without_glorfindel"]:
        return "not_measured"
    return run["detection"] if run["detection"] in ("detected", "missed") else "unknown"


def is_proof(run: dict, cycles: list[dict]) -> bool:
    if run["kind"] == "fault":
        return outcome(run) == "pass"
    return outcome(run) == "detected" and decision_of(run, cycles) is not None


def regression(runs: list[dict]) -> dict | None:
    """The run that lost what an earlier one had proven: the last measured run is a failure,
    and an earlier measured run a success. ``runs`` oldest first."""
    measured = [r for r in runs if outcome(r) in (GOOD[r["kind"]], BAD[r["kind"]])]
    if not measured or outcome(measured[-1]) != BAD[measured[-1]["kind"]]:
        return None
    good = [r for r in measured if outcome(r) == GOOD[r["kind"]]]
    if not good:
        return None
    # The first failure after the last success, by position (two runs may share a time).
    first_bad = measured[max(i for i, r in enumerate(measured) if r is good[-1]) + 1]
    return {"held_by": good[-1]["run_id"], "held_at": iso(good[-1]["at"]),
            "lost_by": first_bad["run_id"], "lost_at": iso(first_bad["at"]),
            "last": measured[-1]["run_id"]}


def _view(run: dict, cycles: list[dict]) -> dict:
    """One run as a row shows it: when, what it measured, and Glorfindel's times on it."""
    decision = decision_of(run, cycles)
    t = timeline(run, decision)
    return {
        "run_id": run["run_id"], "at": iso(run["at"]), "campaign": run["campaign"],
        "name": run["name"], "result": run["result"], "outcome": outcome(run),
        "detection": run["detection"], "without_glorfindel": run["without_glorfindel"],
        "detect_s": t["detect_s"], "decide_s": t["decide_s"], "contain_s": t["contain_s"],
        "decision": ({k: t[k] for k in ("action", "confidence", "escalated", "executed",
                                        "verified", "mode")} if decision else None),
    }


def state(runs: list[dict], proof: dict | None, regressed: dict | None, now: float) -> str:
    if regressed:
        return "regressed"
    if proof:
        age = now - proof["at"]
        return "proven" if age < AGING_DAYS * DAY else "aging" if age <= STALE_DAYS * DAY else "stale"
    return "unproven" if runs else "never"


def row(entry: dict, runs: list[dict], cycles: list[dict], now: float) -> dict:
    """One row of the matrix: an entry of the catalog and its runs (any order)."""
    runs = sorted(runs, key=lambda r: r["at"])
    proofs = [r for r in runs if is_proof(r, cycles)]
    proof = proofs[-1] if proofs else None
    lost = regression(runs)
    last_proof = None
    if proof:
        last_proof = {**_view(proof, cycles), "age_s": round(now - proof["at"])}
    return {
        **{k: entry.get(k) for k in ("id", "kind", "name", "tactic", "status", "resource_type",
                                     "engine", "destructive")},
        "in_catalog": entry.get("in_catalog", True),
        "runs": len(runs),
        "history": [{"run_id": r["run_id"], "at": iso(r["at"]), "outcome": outcome(r)}
                    for r in runs[-HISTORY:]],
        "last_run": _view(runs[-1], cycles) if runs else None,
        "last_proof": last_proof,
        "regression": lost,
        "state": state(runs, proof, lost, now),
    }


def _summary(rows: list[dict]) -> dict:
    """The rows by state — over those the bench can play or has played: an implemented entry,
    or one with runs (a planned entry never run is no gap of the proof). ``regressed``: their
    ids."""
    catalog = [r for r in rows if r["in_catalog"]]
    counted = [r for r in rows if r["status"] == "implemented" or r["runs"]]
    out = {"catalog": len(catalog),
           "implemented": sum(1 for r in catalog if r["status"] == "implemented")}
    for s in ("proven", "aging", "stale", "unproven", "never"):
        out[s] = sum(1 for r in counted if r["state"] == s)
    out["regressed"] = [r["id"] for r in counted if r["state"] == "regressed"]
    return out


def evolution(runs: list[dict], catalog: list[dict], now: float,
              weeks: int = EVOLUTION_WEEKS) -> list[dict]:
    """The coverage as the indicator read it at the end of each of the last ``weeks`` weeks,
    oldest first (the last point is now): techniques detected by a run of the 30 days before,
    over the implemented ones and over the catalog (today's statuses), faults PASS in those 30
    days, and the rows regressed that day."""
    techniques = {e["id"] for e in catalog if e["kind"] == "technique"}
    implemented = {e["id"] for e in catalog if e["kind"] == "technique" and e.get("status") == "implemented"}
    points = []
    for k in range(weeks - 1, -1, -1):
        t = now - k * 7 * DAY
        seen = [r for r in runs if r["at"] <= t]
        window = [r for r in seen if r["at"] > t - WINDOW_DAYS * DAY]
        detected = {r["experiment"] for r in window if r["kind"] == "technique" and outcome(r) == "detected"}
        by_row: dict[tuple, list[dict]] = {}
        for r in seen:
            by_row.setdefault((r["kind"], r["experiment"]), []).append(r)
        regressed = sorted(e for (_, e), rs in by_row.items()
                           if regression(sorted(rs, key=lambda r: r["at"])))
        points.append({"at": iso(t), "implemented_detected": len(implemented & detected),
                       "catalog_detected": len(techniques & detected),
                       "faults_pass": sum(1 for r in window if r["kind"] == "fault" and outcome(r) == "pass"),
                       "runs": len(window), "regressed": regressed})
    return points


def matrix(runs: list[dict], cycles: list[dict], catalog: list[dict], now: float) -> dict:
    """The matrix: a row per entry of the catalog (``/api/catalog``'s entries), techniques and
    faults apart, a row more per experiment run outside it; their summaries; the last proof
    of an attack over the whole history; the evolution of the coverage."""
    by_key: dict[tuple, list[dict]] = {}
    for r in runs:
        by_key.setdefault((r["kind"], r["experiment"]), []).append(r)
    entries = [e for e in catalog if e.get("kind") in GOOD and e.get("id")]
    known = {(e["kind"], e["id"]) for e in entries}
    outside = [{"id": exp, "kind": kind, "name": rs[-1]["name"], "status": "", "in_catalog": False}
               for (kind, exp), rs in sorted(by_key.items()) if (kind, exp) not in known and exp]
    rows = [row(e, by_key.get((e["kind"], e["id"]), []), cycles, now) for e in entries + outside]
    techniques = [r for r in rows if r["kind"] == "technique"]
    faults = [r for r in rows if r["kind"] == "fault"]
    proven = [r for r in techniques if r["last_proof"]]
    newest = max(proven, key=lambda r: r["last_proof"]["at"]) if proven else None
    last = ({"run_id": newest["last_proof"]["run_id"], "ttp": newest["id"],
             "at": newest["last_proof"]["at"], "age_s": newest["last_proof"]["age_s"]}
            if newest else None)
    # The implemented techniques, the least recently proven first (never proven before all).
    stalest = sorted((r for r in techniques if r["status"] == "implemented"),
                     key=lambda r: (r["last_proof"]["at"] if r["last_proof"] else "", r["id"]))
    return {
        "generated_at": iso(now), "aging_days": AGING_DAYS, "stale_days": STALE_DAYS,
        "window_days": WINDOW_DAYS,
        "techniques": techniques, "faults": faults,
        "summary": {"techniques": _summary(techniques), "faults": _summary(faults)},
        "last_proof": last,
        "stalest": [{"ttp": r["id"], "at": r["last_proof"]["at"] if r["last_proof"] else None}
                    for r in stalest],
        "evolution": evolution(runs, entries, now),
    }


def feed(indicators: dict, m: dict) -> dict:
    """The two indicators the matrix feeds: the coverage (its regressed and stale techniques
    beside the 30 days' detected ones) and the age of the last proof — over the whole history,
    so that a proof older than 30 days is said, red, and not « none »."""
    s = m["summary"]["techniques"]
    indicators["coverage"] = {**indicators["coverage"], "regressed": s["regressed"],
                              "stale": s["stale"], "unproven": s["unproven"] + s["never"],
                              "faults_regressed": m["summary"]["faults"]["regressed"]}
    indicators["last_proof"] = m["last_proof"]
    indicators["stalest"] = m["stalest"]
    return indicators

