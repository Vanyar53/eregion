"""The five indicators of the finality (UI-2, #206; eregion_console/indicators.py): computed from
the run reports, the watch's cycles, the cards and the catalog over 30 days — never from the
exercise windows (emptied after 7 days) — and nothing invented in observation.

No Azure, no LLM: runs/ is a tmp directory.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_console import indicators as ind  # noqa: E402

NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    """NOW is the clock when each test starts, not when this file was imported: a long suite
    (the CI's) no longer ages it past the windows and heartbeats the code under test compares
    with its own clock (SEC6, P-08)."""
    global NOW
    NOW = datetime.now(timezone.utc)
VM = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
CATALOG = [{"kind": "technique", "id": "T1110.001", "status": "implemented"},
           {"kind": "technique", "id": "T1136.001", "status": "implemented"},
           {"kind": "technique", "id": "T1486", "status": "implemented"},
           {"kind": "technique", "id": "T1530", "status": "planned"},
           {"kind": "fault", "id": "vm-shutdown", "status": "implemented"}]


@pytest.fixture()
def runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    api._cycle_cache.clear()
    d = tmp_path / "runs"
    d.mkdir()
    return d


def _report(runs, run_id, ttp, attack, detection="detected", latency=90.0, where=None):
    path = (where or runs) / f"{run_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"run_id": run_id, "mitre": ttp, "result": "PASS", "scenario": "s",
                                "metrics": {"attack_time": attack.timestamp(), "detection": detection,
                                            "detection_latency_s": latency}}))


def _fault(runs, run_id, start, result="PASS"):
    (runs / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "mitre": "", "result": result, "scenario": "VM shutdown",
        "metrics": {"injector": "gothmog", "fault_start": start.isoformat()}}))


def _cycle(runs, seen, ttp, action, confidence, decided_after=20, executed=False, verified=None):
    rec = {"timestamp": (seen + timedelta(seconds=decided_after)).isoformat(),
           "signal": {"event": "detection", "ttp": ttp, "resource_id": VM, "timestamp": seen.isoformat(),
                      "context": {"rule_name": "r", "attribution": "asset"}},
           "action": action, "confidence": confidence, "escalate": not executed,
           "outcome": {"status": "executed" if executed else "escalated", "executed": executed,
                       "verified": verified},
           "resolved_autonomy_mode": "non_disruptive" if executed else "human_only"}
    with open(runs / "watch-1_debug.jsonl", "a") as f:
        f.write(json.dumps(rec) + "\n")


def _compute(runs, cards=(), wrong_30=None, wrong_7=None, threshold=0.7):
    since = ind.since_window(NOW)
    found = ind.read_runs(api._run_reports(), since.timestamp())
    return ind.compute(found, api._watch_cycles(since.timestamp()), list(cards), CATALOG,
                       wrong_30 or {}, wrong_7 or {}, threshold, NOW.timestamp())


def test_a_detected_attack_gives_its_times_and_its_proof(runs):
    """M560: the decision is the watch's record of the detection the run counted — same
    technique, seen at attack time + latency — not any record of that technique."""
    a = NOW - timedelta(days=2)
    _report(runs, "r1", "T1110.001", a, latency=100.0)
    _cycle(runs, a + timedelta(seconds=40), "T1110.001", "snapshot", 0.9)        # another one, earlier
    _cycle(runs, a + timedelta(seconds=100), "T1110.001", "block_suspicious_ip", 0.82, decided_after=25)
    out = _compute(runs)
    assert out["contain"] == {"detect_s": 100.0, "decide_s": 125.0, "contain_s": None,
                              "detected": 1, "decided": 1, "contained": 0}
    assert out["last_proof"]["run_id"] == "r1" and out["last_proof"]["ttp"] == "T1110.001"
    assert out["alone"] == {"contained": 0, "shadow": 1, "of": 1, "threshold": 0.7}


def test_nothing_contained_alone_in_human_only_and_the_shadow_is_bounded(runs):
    """M561, M562: in human-only, contained is 0 and its time None — never invented; the shadow
    share counts isolate/block at or above the gate, not snapshots, not below the gate, not a
    run whose card was judged wrong."""
    for i, (action, conf) in enumerate([("isolate_vm", 0.9), ("isolate_vm", 0.5), ("snapshot", 0.95),
                                        ("block_suspicious_ip", 0.8)]):
        a = NOW - timedelta(days=1, hours=i)
        _report(runs, f"r{i}", "T1136.001", a, latency=60.0)
        _cycle(runs, a + timedelta(seconds=60), "T1136.001", action, conf)
    cards = [{"exercise_run": "r3", "verdict": "wrong"}, {"exercise_run": "r0", "verdict": "right"}]
    out = _compute(runs, cards=cards)
    assert out["alone"]["contained"] == 0 and out["contain"]["contain_s"] is None
    assert out["alone"]["shadow"] == 1 and out["alone"]["of"] == 4      # r0 only


def test_contained_alone_counts_an_executed_and_verified_containment(runs):
    a = NOW - timedelta(hours=5)
    _report(runs, "r1", "T1110.001", a, latency=80.0)
    _cycle(runs, a + timedelta(seconds=80), "T1110.001", "isolate_vm", 0.9, decided_after=40,
           executed=True, verified=True)
    out = _compute(runs)
    assert out["alone"]["contained"] == 1 and out["contain"]["contain_s"] == 120.0


def test_thirty_days_from_the_reports_without_any_window(runs, tmp_path):
    """M563: windows are emptied after 7 days — the indicators read the reports, kept, and a
    campaign's too; a run older than 30 days is left out."""
    assert not (tmp_path / "exercises").exists()
    a = NOW - timedelta(days=20)
    _report(runs, "c-r1", "T1136.001", a, latency=70.0, where=runs / "campaigns" / "c1" / "runs")
    _cycle(runs, a + timedelta(seconds=70), "T1136.001", "snapshot", 0.4)
    _report(runs, "old", "T1110.001", NOW - timedelta(days=40), latency=70.0)
    out = _compute(runs)
    assert out["contain"]["detected"] == 1 and out["last_proof"]["run_id"] == "c-r1"
    assert out["last_proof"]["age_s"] == pytest.approx(20 * 86400, abs=5)


def test_a_detected_run_without_its_decision_is_no_proof(runs):
    """M564: a proof is a detection AND a decision — a run detected per its report, with no
    record of the watch to attach, proves the detection only."""
    a = NOW - timedelta(days=1)
    _report(runs, "r1", "T1110.001", a, latency=90.0)
    _report(runs, "r2", "T1136.001", a, detection="missed", latency=None)
    out = _compute(runs)
    assert out["last_proof"] is None and out["contain"]["detect_s"] == 90.0
    assert out["contain"]["decided"] == 0


def test_coverage_over_the_implemented_and_over_the_catalog(runs):
    """M565: detected techniques over the implemented ones and over every technique of the
    catalog (planned too); a missed technique is not covered; faults counted aside."""
    a = NOW - timedelta(days=3)
    _report(runs, "r1", "T1110.001", a)
    _report(runs, "r2", "T1136.001", a, detection="missed", latency=None)
    _fault(runs, "g1", NOW - timedelta(days=1))
    _fault(runs, "g2", NOW - timedelta(days=2), result="FAIL")
    cov = _compute(runs)["coverage"]
    assert cov == {"implemented": 3, "implemented_detected": 1, "catalog": 4, "catalog_detected": 1,
                   "faults": 2, "faults_pass": 1}


def test_the_stalest_technique_is_never_proven_first(runs):
    a = NOW - timedelta(days=5)
    _report(runs, "r1", "T1110.001", a, latency=50.0)
    _cycle(runs, a + timedelta(seconds=50), "T1110.001", "snapshot", 0.4)
    stale = _compute(runs)["stalest"]
    assert [s["ttp"] for s in stale] == ["T1136.001", "T1486", "T1110.001"]
    assert stale[0]["at"] is None and stale[-1]["at"] is not None


def test_wrong_disruptive_over_30_days_and_7_days(runs):
    out = _compute(runs, wrong_30={"right": 9, "wrong": 1, "false_rate": 0.1},
                   wrong_7={"right": 3, "wrong": 0, "false_rate": 0.0})
    assert out["wrong"] == {"days_30": {"rate": 0.1, "judged": 10, "wrong": 1},
                            "days_7": {"rate": 0.0, "judged": 3, "wrong": 0}}


def test_a_malformed_gate_holds_every_shadow_containment(runs):
    """The gate read as infinite (G2: a malformed threshold fails closed): nothing would have
    been contained alone, and the page shows no threshold."""
    a = NOW - timedelta(days=1)
    _report(runs, "r1", "T1110.001", a, latency=60.0)
    _cycle(runs, a + timedelta(seconds=60), "T1110.001", "isolate_vm", 0.99)
    out = _compute(runs, threshold=float("inf"))
    assert out["alone"]["shadow"] == 0 and out["alone"]["threshold"] is None


def test_the_route_reads_this_host(runs):
    """GET /api/indicators: behind the token like every route, read only."""
    a = NOW - timedelta(days=1)
    _report(runs, "r1", "T1110.001", a, latency=60.0)
    _cycle(runs, a + timedelta(seconds=60), "T1110.001", "block_suspicious_ip", 0.85)
    body = console().get("/api/indicators").json()
    assert body["window_days"] == 30 and body["last_proof"]["run_id"] == "r1"
    assert body["coverage"]["implemented"] >= 1 and body["alone"]["shadow"] == 1
    route = next(r for r in api.app.routes if getattr(r, "path", "") == "/api/indicators")
    assert route.methods == {"GET"}
