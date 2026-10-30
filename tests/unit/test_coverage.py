"""The coverage matrix (C1, #80; eregion_console/coverage.py): for each technique of the
catalog and each declared fault, its last proof — detected or not, time to detect, decision,
time to contain — its evolution, and the non-regression: a technique proven before and failed
since is said, red. Fed to two indicators: coverage, age of the last proof.

Everything replays fake runs: runs/ is a tmp directory holding run reports in the format the
injectors write and the watch's debug records. No Azure, no LLM.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from click.testing import CliRunner  # noqa: E402

from .console_client import console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_console import coverage as cov  # noqa: E402
from eregion_core import run_report as rr  # noqa: E402

NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    global NOW
    NOW = datetime.now(timezone.utc)


VM = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
CATALOG = [
    {"kind": "technique", "id": "T1110.001", "status": "implemented", "name": "SSH brute force",
     "resource_type": "azure_vm"},
    {"kind": "technique", "id": "T1136.001", "status": "implemented", "name": "Local account",
     "resource_type": "azure_vm"},
    {"kind": "technique", "id": "T1486", "status": "implemented", "name": "Ransomware",
     "resource_type": "azure_vm"},
    {"kind": "technique", "id": "T1530", "status": "planned", "name": "Blob read",
     "resource_type": "storage"},
    {"kind": "fault", "id": "vm-shutdown", "status": "implemented", "name": "VM shutdown",
     "resource_type": "azure_vm"},
]


@pytest.fixture()
def runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    api._cycle_cache.clear()
    api._matrix_cache.update(key=None, at=0.0, value=None)
    d = tmp_path / "runs"
    d.mkdir()
    return d


def _attack(runs, run_id, ttp, days_ago, detection="detected", latency=90.0, where=None, **metrics):
    """An Annatar run's report, in the unified format; returns its attack time."""
    at = NOW - timedelta(days=days_ago)
    path = (where or runs) / f"{run_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "scenario": f"scenario {ttp}", "run_id": run_id, "mitre": ttp, "result": "PASS",
        "metrics": {**rr.identity("technique", "annatar", ttp), "attack_time": at.timestamp(),
                    "detection": detection, "detection_latency_s": latency, **metrics},
        "thresholds": {}, "checks": {}}))
    return at


def _decision(runs, at, ttp, action="snapshot", confidence=0.6, latency=90.0, decided_after=20,
              executed=False, verified=None, vm=VM, offset=0.0):
    """The watch's record of the detection the run counted (seen at attack + latency, plus
    ``offset`` seconds), on ``vm``."""
    seen = at + timedelta(seconds=latency + offset)
    rec = {"timestamp": (seen + timedelta(seconds=decided_after)).isoformat(),
           "signal": {"event": "detection", "ttp": ttp, "resource_id": vm, "timestamp": seen.isoformat(),
                      "context": {"rule_name": "r", "attribution": "asset"}},
           "action": action, "confidence": confidence, "escalate": not executed,
           "outcome": {"status": "executed" if executed else "escalated", "executed": executed,
                       "verified": verified},
           "resolved_autonomy_mode": "non_disruptive" if executed else "human_only"}
    with open(runs / "watch-1_debug.jsonl", "a") as f:
        f.write(json.dumps(rec) + "\n")


def _proven(runs, run_id, ttp, days_ago, **kw):
    at = _attack(runs, run_id, ttp, days_ago)
    _decision(runs, at, ttp, **kw)
    return at


def _fault(runs, run_id, days_ago, result="PASS", **metrics):
    start = NOW - timedelta(days=days_ago)
    (runs / f"{run_id}.json").write_text(json.dumps({
        "scenario": "VM shutdown", "run_id": run_id, "mitre": "", "result": result,
        "metrics": {**rr.identity("fault", "gothmog", "vm-shutdown"), "fault": "vm-shutdown",
                    "fault_start": start.isoformat(), **metrics},
        "thresholds": {}, "checks": {}}))


def _matrix(runs, catalog=CATALOG):
    return cov.matrix(rr.read_reports(api._run_reports()), api._watch_cycles(None), catalog,
                      NOW.timestamp())


def _row(m, rid):
    return next(r for r in m["techniques"] + m["faults"] if r["id"] == rid)


# ── A row: the last run, the last proof ─────────────────────────────────────────────────

def test_a_row_gives_its_last_run_and_its_last_proof(runs):
    """For each technique: the run, its date, detected or not, the time to detect, the
    decision; the last proof is a detection AND a decision attached (detection and response)."""
    _proven(runs, "r1", "T1110.001", 3, action="block_suspicious_ip", confidence=0.82)
    r = _row(_matrix(runs), "T1110.001")
    assert r["state"] == "proven" and r["runs"] == 1 and r["in_catalog"] is True
    last = r["last_run"]
    assert (last["run_id"], last["outcome"], last["detect_s"], last["decide_s"]) == ("r1", "detected", 90.0, 110.0)
    assert last["decision"]["action"] == "block_suspicious_ip" and last["decision"]["confidence"] == 0.82
    assert last["contain_s"] is None                          # held, never executed: not contained
    assert r["last_proof"]["run_id"] == "r1"
    assert r["last_proof"]["age_s"] == pytest.approx(3 * 86400, abs=5)
    assert [h["outcome"] for h in r["history"]] == ["detected"]


def test_a_contained_incident_gives_its_time_to_contain(runs):
    """M1805: an isolation executed and verified — the time to contain is in the row."""
    _proven(runs, "r1", "T1486", 1, action="isolate_vm", confidence=0.9, decided_after=40,
            executed=True, verified=True)
    last = _row(_matrix(runs), "T1486")["last_run"]
    assert last["contain_s"] == 130.0 and last["decision"]["verified"] is True


def test_the_verification_time_ends_the_containment(runs):
    """M1823: when the watch writes the verification's own time (``outcome.verified_at``,
    BL1), the time to contain ends there, not at the record's."""
    at = _attack(runs, "r1", "T1486", 1)
    _decision(runs, at, "T1486", action="isolate_vm", confidence=0.9, decided_after=40,
              executed=True, verified=True)
    lines = (runs / "watch-1_debug.jsonl").read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["outcome"]["verified_at"] = (at + timedelta(seconds=120)).isoformat()
    (runs / "watch-1_debug.jsonl").write_text(json.dumps(rec) + "\n")
    assert _row(_matrix(runs), "T1486")["last_run"]["contain_s"] == 120.0


def test_a_detection_without_a_decision_is_no_proof(runs):
    """M1806: detected per its report, no record of the watch to attach — unproven."""
    _attack(runs, "r1", "T1136.001", 2)
    r = _row(_matrix(runs), "T1136.001")
    assert r["state"] == "unproven" and r["last_proof"] is None
    assert r["last_run"]["outcome"] == "detected" and r["last_run"]["decision"] is None


def test_a_technique_never_run_and_a_planned_one(runs):
    m = _matrix(runs)
    assert _row(m, "T1486")["state"] == "never" and _row(m, "T1530")["state"] == "never"
    s = m["summary"]["techniques"]
    # A planned technique never run is no gap of the proof: only the implemented are counted.
    assert (s["catalog"], s["implemented"], s["never"]) == (4, 3, 3)


# ── The age of the last proof ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("days, state", [(20, "proven"), (25, "aging"), (40, "stale")])
def test_the_age_of_the_last_proof_sets_the_state(runs, days, state):
    """M1807: under 21 days proven, up to 30 aging, over 30 stale — the alert."""
    _proven(runs, "r1", "T1110.001", days)
    assert _row(_matrix(runs), "T1110.001")["state"] == state


def test_a_proof_older_than_30_days_is_said_not_hidden(runs):
    """M1808: the matrix reads the whole history — the indicator says 40 days, red, never
    « none in 30 days » — and the stalest are told in order, never proven first."""
    _proven(runs, "r1", "T1110.001", 40)
    _proven(runs, "r2", "T1136.001", 5)
    m = _matrix(runs)
    assert m["last_proof"]["run_id"] == "r2" and m["last_proof"]["ttp"] == "T1136.001"
    assert [s["ttp"] for s in m["stalest"]] == ["T1486", "T1110.001", "T1136.001"]
    out = cov.feed({"coverage": {"implemented": 3}, "last_proof": None, "stalest": []}, m)
    assert out["coverage"]["stale"] == 1 and out["last_proof"]["ttp"] == "T1136.001"


# ── The non-regression ──────────────────────────────────────────────────────────────────

def test_a_technique_proven_before_and_missed_since_is_regressed(runs):
    """M1809: detected ten days ago, missed yesterday — red, with the run that held and the
    run that lost; the last proof stays, dated."""
    _proven(runs, "r-old", "T1110.001", 10)
    _attack(runs, "r-new", "T1110.001", 1, detection="missed", latency=None)
    m = _matrix(runs)
    r = _row(m, "T1110.001")
    assert r["state"] == "regressed"
    assert (r["regression"]["held_by"], r["regression"]["lost_by"]) == ("r-old", "r-new")
    assert r["last_proof"]["run_id"] == "r-old"
    assert [h["outcome"] for h in r["history"]] == ["detected", "missed"]
    assert m["summary"]["techniques"]["regressed"] == ["T1110.001"]


def test_a_regression_between_two_runs_of_the_same_second(runs):
    """M1888: two runs may share a time (a forged or a copied report): ordered by (time, run
    id), whatever the order they are read in — r-a detected, then r-b missed: regressed."""
    _proven(runs, "r-a", "T1110.001", 3)
    _attack(runs, "r-b", "T1110.001", 3, detection="missed", latency=None)
    read = sorted(rr.read_reports(api._run_reports()), key=lambda r: r["run_id"], reverse=True)
    m = cov.matrix(read, api._watch_cycles(None), CATALOG, NOW.timestamp())
    r = _row(m, "T1110.001")
    assert r["state"] == "regressed" and r["regression"]["lost_by"] == "r-b"


@pytest.mark.parametrize("since", [
    {"detection": "unknown", "latency": None},                    # nothing measured
    {"detection": "unknown", "latency": None, "without_glorfindel": True},   # not measured, by choice
])
def test_a_run_that_measured_nothing_neither_proves_nor_regresses(runs, since):
    """M1810: an unknown detection, or a run --without-glorfindel, after a proof — no regression."""
    _proven(runs, "r-old", "T1110.001", 10)
    _attack(runs, "r-new", "T1110.001", 1, **since)
    r = _row(_matrix(runs), "T1110.001")
    assert r["state"] == "proven" and r["regression"] is None
    assert r["last_run"]["outcome"] in ("unknown", "not_measured")


def test_detected_again_after_a_miss_is_no_regression(runs):
    """M1811: the last measured run decides — missed, then detected again, holds."""
    _proven(runs, "r1", "T1110.001", 10)
    _attack(runs, "r2", "T1110.001", 5, detection="missed", latency=None)
    _proven(runs, "r3", "T1110.001", 1)
    assert _row(_matrix(runs), "T1110.001")["state"] == "proven"


def test_never_detected_is_no_regression(runs):
    """M1812: a regression needs a success before — missed twice is unproven, not regressed."""
    _attack(runs, "r1", "T1486", 10, detection="missed", latency=None)
    _attack(runs, "r2", "T1486", 1, detection="missed", latency=None)
    assert _row(_matrix(runs), "T1486")["state"] == "unproven"


def test_a_campaign_run_counts_like_any_other(runs):
    """The campaigns Orodruin published (runs/campaigns/<id>/runs/) are read too."""
    _proven(runs, "r1", "T1136.001", 8)
    _attack(runs, "c-r1", "T1136.001", 2, detection="missed", latency=None,
            where=runs / "campaigns" / "c1" / "runs")
    r = _row(_matrix(runs), "T1136.001")
    assert r["state"] == "regressed" and r["last_run"]["campaign"] == "c1"


# ── The faults ──────────────────────────────────────────────────────────────────────────

def test_a_fault_is_proven_by_a_pass_with_the_watch_running(runs):
    """M1813: PASS with Glorfindel watching is a proof; PASS --without-glorfindel is not."""
    _fault(runs, "g1", 3, without_glorfindel=True)
    assert _row(_matrix(runs), "vm-shutdown")["state"] == "unproven"
    _fault(runs, "g2", 2)
    r = _row(_matrix(runs), "vm-shutdown")
    assert r["state"] == "proven" and r["last_proof"]["run_id"] == "g2"


def test_a_fault_pass_then_fail_is_regressed_a_refusal_is_not(runs):
    """M1814: PASS then FAIL regresses; PASS then REFUSED (nothing ran) does not."""
    _fault(runs, "g1", 5)
    _fault(runs, "g2", 1, result="REFUSED")
    assert _row(_matrix(runs), "vm-shutdown")["state"] == "proven"
    _fault(runs, "g3", 0.5, result="FAIL")
    m = _matrix(runs)
    assert _row(m, "vm-shutdown")["state"] == "regressed"
    assert m["summary"]["faults"]["regressed"] == ["vm-shutdown"]


def test_a_run_outside_the_catalog_gets_its_own_row(runs):
    """Nothing hidden: a technique the catalog does not hold is a row, said outside it."""
    _attack(runs, "r1", "T9999", 1)
    r = _row(_matrix(runs), "T9999")
    assert r["in_catalog"] is False and r["runs"] == 1


def test_a_report_before_c1_reads_into_the_matrix(runs):
    """An older report (no run_format, no kind): Annatar's by its mitre, Gothmog's by its
    injector — the matrix reads the history written before C1."""
    at = NOW - timedelta(days=2)
    (runs / "old.json").write_text(json.dumps({
        "scenario": "s", "run_id": "old", "mitre": "T1110.001", "result": "PASS",
        "metrics": {"attack_time": at.timestamp(), "detection": "detected", "detection_latency_s": 90.0}}))
    _decision(runs, at, "T1110.001")
    (runs / "gold.json").write_text(json.dumps({
        "scenario": "VM shutdown", "run_id": "gold", "mitre": "", "result": "PASS",
        "metrics": {"injector": "gothmog", "fault": "vm-shutdown",
                    "fault_start": (NOW - timedelta(days=1)).isoformat()}}))
    m = _matrix(runs)
    assert _row(m, "T1110.001")["state"] == "proven" and _row(m, "vm-shutdown")["state"] == "proven"


# ── The evolution ───────────────────────────────────────────────────────────────────────

def test_the_evolution_week_by_week(runs):
    """M1815: twelve points, oldest first, the last one now; each counts the techniques
    detected in the 30 days before it — and the rows regressed that day."""
    _proven(runs, "r1", "T1110.001", 50)
    _proven(runs, "r2", "T1136.001", 3)
    _attack(runs, "r3", "T1110.001", 1, detection="missed", latency=None)
    pts = _matrix(runs)["evolution"]
    assert len(pts) == 12 and pts[-1]["at"] == rr.iso(NOW.timestamp())
    assert pts[-1]["implemented_detected"] == 1 and pts[-1]["regressed"] == ["T1110.001"]
    seven_weeks_ago = pts[-8]                       # 49 days ago: r1 (50 days) in its 30 days
    assert seven_weeks_ago["implemented_detected"] == 1 and seven_weeks_ago["regressed"] == []
    assert pts[0]["implemented_detected"] == 0      # 77 days ago: nothing yet


# ── The routes, the indicators, the command ─────────────────────────────────────────────

def test_the_route_gives_one_half_per_injector(runs):
    """GET /api/coverage: the real catalog, read only; ``kind`` keeps Annatar's or Gothmog's."""
    _proven(runs, "r1", "T1110.001", 2)
    body = console().get("/api/coverage?kind=technique").json()
    assert "faults" not in body and _row({"techniques": body["techniques"], "faults": []}, "T1110.001")["state"] == "proven"
    body = console().get("/api/coverage?kind=fault").json()
    assert "techniques" not in body and any(r["id"] == "vm-shutdown" for r in body["faults"])
    assert console().get("/api/coverage?kind=../x").json() == {"error": "kind: technique or fault"}
    route = next(r for r in api.app.routes if getattr(r, "path", "") == "/api/coverage")
    assert route.methods == {"GET"}


def test_the_indicators_are_fed_by_the_matrix(runs):
    """M1816: the coverage says what regressed, the last proof its age over the whole history
    — 40 days, not « none in 30 days »."""
    _proven(runs, "r-old", "T1110.001", 40)
    _attack(runs, "r-new", "T1110.001", 1, detection="missed", latency=None)
    body = console().get("/api/indicators").json()
    assert body["coverage"]["regressed"] == ["T1110.001"]
    assert body["last_proof"]["run_id"] == "r-old"
    assert body["last_proof"]["age_s"] == pytest.approx(40 * 86400, abs=60)


def test_the_command_fails_on_a_regression_only(runs):
    """M1817: `eregion coverage --check`, the non-regression after a replay: exit 1 on a
    technique proven before and missed since, 0 otherwise (a stale proof is said, not failed)."""
    from eregion_console.cli import cli
    _proven(runs, "r1", "T1136.001", 40)
    ok = CliRunner().invoke(cli, ["coverage", "--check"])
    assert ok.exit_code == 0, ok.output
    assert "T1136.001" in ok.output and "regressed: none" in ok.output
    _proven(runs, "r2", "T1110.001", 10)
    _attack(runs, "r3", "T1110.001", 1, detection="missed", latency=None)
    bad = CliRunner().invoke(cli, ["coverage", "--check"])
    assert bad.exit_code == 1 and "regressed: T1110.001" in bad.output
    as_json = CliRunner().invoke(cli, ["coverage", "--json"])
    assert as_json.exit_code == 0 and json.loads(as_json.output)["summary"]["techniques"]["regressed"] == ["T1110.001"]


def test_the_pages_show_the_matrix():
    """The console shows it: Annatar's and Gothmog's side column reads /api/coverage, and the
    overview's coverage says what regressed (C1, « Fini quand »)."""
    from pathlib import Path
    static = Path(api.__file__).parent / "static"
    injector = (static / "injector.js").read_text(encoding="utf-8")
    assert "/api/coverage?kind=" in injector and "/api/catalog?kind=" not in injector
    assert "REGRESSED" in injector and "evolutionLine()" in injector
    assert "cov.regressed" in (static / "overview.js").read_text(encoding="utf-8")


# ── Review (C1, 30/10): the future, the decision attached, the faults that never started ─

def test_a_run_dated_in_the_future_is_left_out_and_said(runs):
    """M1829: a ``missed`` dated 2076 would keep the row regressed for ever (and --check at
    1); a proof dated in the future would never age. Left out of every row, and said."""
    from eregion_console.cli import cli
    _proven(runs, "r1", "T1110.001", 3)
    _attack(runs, "r-2076", "T1110.001", -50 * 365, detection="missed", latency=None)
    _proven(runs, "r-ahead", "T1136.001", -2)
    m = _matrix(runs)
    assert _row(m, "T1110.001")["state"] == "proven"
    assert _row(m, "T1136.001")["state"] == "never"
    assert [f["run_id"] for f in m["future"]] == ["r-ahead", "r-2076"]
    out = CliRunner().invoke(cli, ["coverage", "--check"])
    assert out.exit_code == 0 and "dated in the future, left out: r-ahead, r-2076" in out.output


def test_a_run_a_few_minutes_ahead_is_kept():
    """Clocks drift: under FUTURE_SKEW_S ahead, a run is a run."""
    run = rr.read_run({"run_id": "r", "mitre": "T1486", "result": "PASS",
                       "metrics": {"attack_time": NOW.timestamp() + 60, "detection": "missed"}})
    m = cov.matrix([run], [], CATALOG, NOW.timestamp())
    assert m["future"] == [] and _row(m, "T1486")["runs"] == 1


def test_the_decision_is_the_one_on_the_runs_vm(runs):
    """M1826: the run's report names its VM (metrics.resource_id): a decision of the same
    technique on another VM, even closer in time, is not its decision."""
    other = VM.replace("vm-a", "vm-b")
    at = _attack(runs, "r1", "T1110.001", 2, resource_id=VM.upper())   # the watch writes lower case
    _decision(runs, at, "T1110.001", action="isolate_vm", vm=other)
    _decision(runs, at, "T1110.001", action="block_suspicious_ip", vm=VM, offset=3)
    last = _row(_matrix(runs), "T1110.001")["last_run"]
    assert last["decision"]["action"] == "block_suspicious_ip"


def test_among_several_the_decision_closest_to_the_detection(runs):
    """M1827: two records of the technique within the slack — the one seen closest to the
    detection the run counted, not the oldest."""
    at = _attack(runs, "r1", "T1110.001", 2)
    _decision(runs, at, "T1110.001", action="snapshot", offset=-4)
    _decision(runs, at, "T1110.001", action="block_suspicious_ip", offset=1)
    assert _row(_matrix(runs), "T1110.001")["last_run"]["decision"]["action"] == "block_suspicious_ip"


def test_a_run_whose_experiment_is_not_its_technique_has_no_decision(runs):
    """M1828: the matrix files a run under its experiment id; the decision is sought by its
    mitre — both must be the same technique, or no decision is attached."""
    at = _attack(runs, "r1", "T1110.001", 2, experiment_id="T1136.001")
    _decision(runs, at, "T1110.001")
    r = _row(_matrix(runs), "T1136.001")
    assert r["runs"] == 1 and r["last_run"]["decision"] is None and r["state"] == "unproven"


def _gothmog_start_failed(runs, run_id, days_ago=None):
    """The report Gothmog writes when the fault's start failed (gothmog/runner/engine.py,
    _inject): FAIL, ``checks.fault_started`` not PASS, its metrics the gate's only — no
    ``fault_start`` (nothing started). ``days_ago`` dates it anyway, as a later Gothmog might."""
    metrics = {**rr.identity("fault", "gothmog", "vm-shutdown"), "fault": "vm-shutdown",
               "targets": [VM], "experiment": {"name": "exp", "duration_s": 300.0}}
    if days_ago is not None:
        metrics["fault_start"] = (NOW - timedelta(days=days_ago)).isoformat()
    (runs / f"{run_id}.json").write_text(json.dumps({
        "scenario": "VM shutdown", "run_id": run_id, "mitre": "", "result": "FAIL",
        "metrics": metrics, "thresholds": {},
        "checks": {"targets": "PASS", "steady_state_before": "PASS", "fault_started": "FAIL (cap reached)"}}))


def test_a_fault_whose_start_failed_is_neutral(runs):
    """M1880, M1889: a FAIL whose ``fault_started`` is not PASS injected nothing — neither
    proof nor regression, explicitly (``not_started``), dated or not."""
    _fault(runs, "g1", 5)
    _gothmog_start_failed(runs, "g2")                  # Gothmog's real shape: no date, not read
    assert _row(_matrix(runs), "vm-shutdown")["state"] == "proven"
    _gothmog_start_failed(runs, "g3", days_ago=1)      # dated: read, and still neutral
    r = _row(_matrix(runs), "vm-shutdown")
    assert r["state"] == "proven" and r["history"][-1]["outcome"] == "not_started"


# ── The cost: indexed once, cached by file ──────────────────────────────────────────────

def test_the_matrix_scales_with_the_history():
    """The decisions are found by bisection over an index built once, each run's once — not
    runs × cycles. 2 000 runs and 40 000 cycles (6.4 s before, measured at the review): an
    order of magnitude, never a stopwatch — the bound is generous."""
    import time
    t0 = NOW.timestamp() - 200 * 86400
    techniques = ["T1110.001", "T1136.001", "T1486"]
    reports, cycles = [], []
    for i in range(2000):
        at = t0 + i * 3600
        ttp = techniques[i % 3]
        reports.append(rr.read_run({"run_id": f"r{i}", "mitre": ttp, "result": "PASS", "metrics": {
            "attack_time": at, "detection": "detected", "detection_latency_s": 90.0}}))
        for k in range(20):
            cycles.append({"event": "detection", "ttp": ttp, "action": "snapshot", "resource_id": VM,
                           "signal_at": rr.iso(at + 90 + k * 60), "at": rr.iso(at + 100 + k * 60)})
    start = time.perf_counter()
    m = cov.matrix(reports, cycles, CATALOG, NOW.timestamp())
    elapsed = time.perf_counter() - start
    assert elapsed < 4.0, elapsed
    r = _row(m, "T1110.001")
    assert r["runs"] == 667 and r["last_proof"]["run_id"] == "r1998"


def test_the_matrix_is_computed_again_only_when_a_file_changed(runs, monkeypatch):
    """M1883: the same files, a second call within the TTL — the cached matrix; a new report
    — computed again, at once."""
    calls = []
    real = cov.matrix
    monkeypatch.setattr(cov, "matrix", lambda *a, **k: calls.append(1) or real(*a, **k))
    _proven(runs, "r1", "T1110.001", 3)
    api.coverage_matrix()
    api.coverage_matrix()
    assert len(calls) == 1
    _attack(runs, "r2", "T1110.001", 1, detection="missed", latency=None)
    assert _row(api.coverage_matrix(), "T1110.001")["state"] == "regressed" and len(calls) == 2


def test_the_caches_forget_a_deleted_file(runs):
    """M1881, M1882: a report or a debug file deleted is dropped from its cache — the console
    runs for weeks, its runs/ is cleaned."""
    _proven(runs, "r1", "T1110.001", 3)
    api.coverage_matrix()
    report = (runs / "r1.json").absolute()
    debug = Path("runs") / "watch-1_debug.jsonl"
    assert report in rr._report_cache and debug in api._cycle_cache
    (runs / "r1.json").unlink()
    (runs / "watch-1_debug.jsonl").unlink()
    api.coverage_matrix()
    assert report not in rr._report_cache and debug not in api._cycle_cache


def test_the_command_prints_no_control_character(runs):
    """M1886: a run report comes from another host; an id with an ANSI escape is printed as
    text, never as the terminal's command."""
    from eregion_console.cli import cli
    _attack(runs, "r1", "T9999\x1b[2J\x07", 1)
    out = CliRunner().invoke(cli, ["coverage"])
    assert out.exit_code == 0 and "\x1b" not in out.output and "\x07" not in out.output
    assert "T9999[2J" in out.output


def test_the_indicators_leave_a_future_run_out(runs):
    """M1885: a run detected and dated next year counts in no indicator either."""
    _proven(runs, "r-next-year", "T1486", -365)
    body = console().get("/api/indicators").json()
    assert body["contain"]["detected"] == 0 and body["coverage"]["implemented_detected"] == 0
