"""The run, unified (C1, #80; eregion_core/run_report.py): one report for an attack and a
fault, read the same way — the format both injectors write, older reports included — and the
times of an incident joined from the watch's record.

The shared core alone (scripts/component_check.py, ``core``): no injector, no console. No
Azure, no LLM.
"""
from __future__ import annotations

import json

import pytest

from eregion_core import run_report as rr

T0 = 1_790_000_000.0   # an attack time, seconds since the epoch


def _attack(**metrics) -> dict:
    return {"scenario": "account creation", "run_id": "r1", "mitre": "T1136.001", "result": "PASS",
            "metrics": {"attack_time": T0, "detection": "detected", "detection_latency_s": 90.0, **metrics},
            "thresholds": {}, "checks": {}}


def _fault(**metrics) -> dict:
    return {"scenario": "VM shutdown", "run_id": "g1", "mitre": "", "result": "PASS",
            "metrics": {"injector": "gothmog", "fault": "vm-shutdown",
                        "fault_start": "2026-10-19T20:01:34+00:00", **metrics},
            "thresholds": {}, "checks": {}}


def test_the_report_class_saves_the_same_keys(tmp_path):
    """One class for both injectors: the seven keys, ``runs/<run_id>.json``."""
    r = rr.RunReport(scenario="s", run_id="r1", mitre="T1", result="PASS", metrics={"a": 1},
                     thresholds={}, checks={})
    path = r.save(tmp_path / "runs")
    assert path == tmp_path / "runs" / "r1.json"
    assert set(json.loads(path.read_text())) == {"scenario", "run_id", "mitre", "result", "metrics",
                                                 "thresholds", "checks"}


def test_identity_says_what_a_run_is():
    assert rr.identity("fault", "gothmog", "vm-shutdown") == {
        "run_format": rr.RUN_FORMAT, "kind": "fault", "injector": "gothmog", "experiment_id": "vm-shutdown"}
    with pytest.raises(ValueError):
        rr.identity("attack", "annatar", "T1")


def test_a_report_before_c1_reads_as_before():
    """An older report — no kind, no experiment id: Gothmog's injector says a fault, anything
    else an attack; the technique is ``mitre``, the fault ``metrics.fault``."""
    a, f = rr.read_run(_attack()), rr.read_run(_fault())
    assert (a["kind"], a["experiment"], a["injector"], a["run_format"]) == ("technique", "T1136.001", "annatar", 0)
    assert a["at"] == T0 and a["latency"] == 90.0 and a["detected_at"] == T0 + 90.0
    assert (f["kind"], f["experiment"], f["injector"]) == ("fault", "vm-shutdown", "gothmog")
    assert f["at"] == rr.epoch("2026-10-19T20:01:34+00:00") and f["detection"] == "unknown"


def test_the_unified_format_is_read_first():
    """M1803: the run's own word wins over the guess — a fault run by another injector than
    Gothmog (a later engine, G4) is a fault because its report says so."""
    report = _attack(**rr.identity("fault", "chaos-toolkit", "vm-shutdown"), fault_start="2026-10-19T20:01:34Z")
    run = rr.read_run(report)
    assert (run["kind"], run["experiment"], run["run_format"]) == ("fault", "vm-shutdown", 1)
    assert run["injector"] == "chaos-toolkit" and run["at"] == rr.epoch("2026-10-19T20:01:34Z")


@pytest.mark.parametrize("metrics", [
    {"attack_time": None}, {"attack_time": "never"}, {"attack_time": float("nan")},
    {"attack_time": True}, {"attack_time": 1e20},
])
def test_a_run_without_a_date_is_left_out(metrics):
    assert rr.read_run(_attack(**metrics)) is None
    assert rr.read_run("not a report") is None


@pytest.mark.parametrize("latency", [-1, "90", True, float("inf"), None])
def test_a_latency_that_is_not_seconds_is_none(latency):
    run = rr.read_run(_attack(detection_latency_s=latency))
    assert run["latency"] is None and run["detected_at"] is None


def test_without_glorfindel_and_the_campaign_are_carried(tmp_path):
    cdir = tmp_path / "campaigns" / "c-7" / "runs"
    cdir.mkdir(parents=True)
    (cdir / "r1.json").write_text(json.dumps(_attack(without_glorfindel=True, detection="unknown")))
    (tmp_path / "r2.json").write_text(json.dumps({**_attack(), "run_id": "r2"}))
    (tmp_path / "broken.json").write_text("{")
    runs = {r["run_id"]: r for r in rr.read_reports({"r1": cdir / "r1.json", "r2": tmp_path / "r2.json",
                                                     "broken": tmp_path / "broken.json"})}
    assert set(runs) == {"r1", "r2"}
    assert runs["r1"]["campaign"] == "c-7" and runs["r1"]["without_glorfindel"] is True
    assert runs["r2"]["campaign"] == ""


def _cycle(at: float, action="isolate_vm", executed=True, verified=True, **extra) -> dict:
    return {"at": rr.iso(at), "action": action, "confidence": 0.9, "escalate": not executed,
            "executed": executed, "verified": verified, "mode": "non_disruptive", **extra}


def test_the_timeline_of_a_contained_incident():
    """M1804: attack → detection → decision → verified action; contained only when an isolation
    or a block was executed AND verified, at the verification's own time when written."""
    run = rr.read_run(_attack())
    t = rr.timeline(run, _cycle(T0 + 130, verified_at=rr.iso(T0 + 125)))
    assert (t["detect_s"], t["decide_s"], t["contain_s"]) == (90.0, 130.0, 125.0)
    t = rr.timeline(run, _cycle(T0 + 130))
    assert t["contain_s"] == 130.0 and t["action"] == "isolate_vm" and t["verified"] is True


@pytest.mark.parametrize("cycle", [
    _cycle(T0 + 130, verified=False),                  # the verification failed
    _cycle(T0 + 130, executed=False, verified=None),   # recommended, held (human-only)
    _cycle(T0 + 130, action="snapshot"),               # not a containment
])
def test_nothing_contained_unless_executed_and_verified(cycle):
    t = rr.timeline(rr.read_run(_attack()), cycle)
    assert t["contained_at"] is None and t["contain_s"] is None and t["decide_s"] == 130.0


def test_no_decision_no_time_and_a_time_before_the_attack_is_none():
    run = rr.read_run(_attack())
    t = rr.timeline(run, None)
    assert t["decided_at"] is None and t["action"] == "" and t["detect_s"] == 90.0
    t = rr.timeline(run, _cycle(T0 - 10))
    assert t["decided_at"] is None and t["contained_at"] is None
