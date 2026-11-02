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


def _window(run_id, start, end):
    """The run's exercise window, as the watch keeps it (eregion_core/exercise.py)."""
    from eregion_core.exercise import exercises_dir
    d = exercises_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "injector": "annatar", "kind": "technique", "experiment": "T1110.001 ssh",
        "targets": [VM], "start": start.isoformat(), "end": end.isoformat(),
        "expires": (start + timedelta(hours=2)).isoformat()}))


def _received(runs, run_id, attack):
    """The watch's poll of the run's ``attack_started``, in the run's own debug file: the attack
    time it received from the injector."""
    with open(runs / f"{run_id}_debug.jsonl", "a") as f:
        f.write(json.dumps({"timestamp": attack.isoformat(), "action": "",
                            "signal": {"event": "attack_started", "ttp": "T1110.001", "resource_id": VM,
                                       "timestamp": attack.isoformat(), "context": {"run_id": run_id},
                                       "raw_signal": {"attack_time": attack.timestamp()}}}) + "\n")


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
                              "detected": 1, "decided": 1, "contained": 0, "t0_refused": 0,
                              "t0_purged": 0}
    assert out["last_proof"]["run_id"] == "r1" and out["last_proof"]["ttp"] == "T1110.001"
    assert out["alone"] == {"contained": 0, "shadow": 1, "of": 1, "threshold": 0.7, "attacks": 1,
                            "faults_mistaken": 0, "disruptive_on_faults": 0, "faults_unchecked": 0}


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
    # OV1: the overview's two tiles are real traffic's — this line is the decision the overview
    # attaches to the run r1 (its last proof): an exercise, inferred, never real traffic, even
    # written before the watch said its source and from a report that names no VM.
    assert body["coverage"]["implemented"] >= 1 and body["alone"]["shadow"] == 0
    assert body["alone"]["of"] == 0 and body["alone"]["inferred"] == 0
    assert body["alone"]["inferred_exercise"] == 1 and body["t0"] == "detection"
    route = next(r for r in api.app.routes if getattr(r, "path", "") == "/api/indicators")
    assert route.methods == {"GET"}


def test_the_time_to_contain_has_one_definition(runs):
    """M1884 (C1): the overview's median goes through run_report.timeline, as the matrix does —
    the verification's own time when the watch writes it (``outcome.verified_at``)."""
    a = NOW - timedelta(hours=5)
    _report(runs, "r1", "T1110.001", a, latency=80.0)
    _cycle(runs, a + timedelta(seconds=80), "T1110.001", "isolate_vm", 0.9, decided_after=40,
           executed=True, verified=True)
    path = runs / "watch-1_debug.jsonl"
    rec = json.loads(path.read_text())
    rec["outcome"]["verified_at"] = (a + timedelta(seconds=100)).isoformat()
    path.write_text(json.dumps(rec) + "\n")
    out = _compute(runs)
    assert out["alone"]["contained"] == 1 and out["contain"]["contain_s"] == 100.0


# ── BL1 (#280): one definition with the campaign report's (analysis/containment.py) ──────────

def _contained(runs, seen, verified_after, written_after, signal_id="s-1"):
    """A cycle of the watch that isolated alone, read back ``verified_after`` s after the signal,
    its line written later (memory, notification)."""
    rec = {"timestamp": (seen + timedelta(seconds=written_after)).isoformat(),
           "signal": {"event": "detection", "ttp": "T1136.001", "resource_id": VM, "signal_id": signal_id,
                      "timestamp": seen.isoformat(), "context": {"rule_name": "r", "attribution": "asset"}},
           "action": "isolate_vm", "confidence": 0.9, "escalate": False,
           "outcome": {"status": "isolated", "executed": True, "verified": True,
                       "verified_at": (seen + timedelta(seconds=verified_after)).isoformat()},
           "resolved_autonomy_mode": "non_disruptive"}
    with open(runs / "watch-1_debug.jsonl", "a") as f:
        f.write(json.dumps(rec) + "\n")


def test_the_time_to_contain_ends_at_the_read_back_on_azure(runs):
    """M1789: the overview's time to contain ends at the read-back (verified_at), as the
    campaign's — not at the cycle's line, written after it."""
    a = NOW - timedelta(hours=3)
    _report(runs, "r1", "T1136.001", a, latency=60.0)
    _contained(runs, a + timedelta(seconds=60), verified_after=20, written_after=45)
    out = _compute(runs)
    assert out["alone"]["contained"] == 1 and out["contain"]["contain_s"] == 80.0


def test_an_isolation_that_did_not_hold_is_not_contained_alone(runs):
    a = NOW - timedelta(hours=3)
    _report(runs, "r1", "T1136.001", a, latency=60.0)
    _contained(runs, a + timedelta(seconds=60), verified_after=20, written_after=45)
    card = {"escalation_type": "verification_failed", "resource_id": VM, "action": "isolate_vm",
            "timestamp": (a + timedelta(minutes=5)).isoformat()}
    since = ind.since_window(NOW)
    out = ind.compute(ind.read_runs(api._run_reports(), since.timestamp()),
                      api._watch_cycles(since.timestamp()), [], CATALOG, {}, {}, 0.7, NOW.timestamp(),
                      all_cards=[card])
    assert out["alone"]["contained"] == 0 and out["contain"]["contain_s"] is None
    # The operator released it before the card: the card is no longer this containment's.
    (runs / "manual_actions.jsonl").write_text(json.dumps(
        {"timestamp": (a + timedelta(minutes=3)).isoformat(), "action": "release_isolation",
         "signal": {"resource_id": VM}, "outcome": {"status": "released"}}) + "\n")
    out = ind.compute(ind.read_runs(api._run_reports(), since.timestamp()),
                      api._watch_cycles(since.timestamp()), [], CATALOG, {}, {}, 0.7, NOW.timestamp(),
                      all_cards=[card], liftings=api._manual_liftings(since.timestamp()))
    assert out["alone"]["contained"] == 1


def test_a_fault_taken_for_an_attack_is_counted_apart_never_an_attack(runs):
    """A decision to isolate on a fault's VM during the fault: counted apart, never among the
    attacks; the attacks of the period, missed ones included, beside the detected."""
    start = NOW - timedelta(hours=6)
    (runs / "g1.json").write_text(json.dumps({
        "run_id": "g1", "mitre": "", "result": "PASS", "scenario": "VM shutdown",
        "metrics": {"injector": "gothmog", "fault": "vm-shutdown", "targets": [VM],
                    "fault_start": start.isoformat(),
                    "fault_end": (start + timedelta(minutes=5)).isoformat()}}))
    _contained(runs, start + timedelta(minutes=2), verified_after=10, written_after=20, signal_id="f-1")
    _report(runs, "r2", "T1136.001", NOW - timedelta(hours=1), detection="missed", latency=None)
    out = _compute(runs)
    assert out["alone"]["faults_mistaken"] == 1 and out["alone"]["disruptive_on_faults"] == 1
    assert out["alone"]["contained"] == 0 and out["alone"]["of"] == 0 and out["alone"]["attacks"] == 1


# ── OV1 (#399): the overview counts real traffic, Dagorlad the exercises ───────────────────────

def _real(runs, seen, *, action="block_suspicious_ip", confidence=0.92, executed=True, verified=True,
          verified_after=None, decided_after=25, source="real", exercise_run="", attribution="asset",
          sid="rule-ssh-brute-force-aaaa0001", guard="", vm=VM, attacker=""):
    """A line of the watch's debug file as it writes it since OV1 (``source``; None: before)."""
    out = {"status": "blocked" if executed else "escalated", "executed": executed, "verified": verified}
    if verified_after is not None:
        out["verified_at"] = (seen + timedelta(seconds=verified_after)).isoformat()
    if guard:
        out["escalation_type"] = guard
    rec = {"timestamp": (seen + timedelta(seconds=decided_after)).isoformat(),
           "signal": {"signal_id": sid, "event": "detection", "ttp": "T1110.001", "resource_id": vm,
                      "timestamp": seen.isoformat(),
                      "context": {"rule_name": "ssh-brute-force", "attribution": attribution},
                      "raw_signal": {"first_result_row": {"SourceIP": attacker, "FailedAttempts": 12}
                                     if attacker else {}}},
           "action": action, "confidence": confidence, "escalate": not executed, "outcome": out,
           "resolved_autonomy_mode": "non_disruptive"}
    if source is not None:
        rec["source"], rec["exercise_run"] = source, exercise_run
    with open(runs / "watch-ssh-brute-force-1_debug.jsonl", "a") as f:
        f.write(json.dumps(rec) + "\n")


def _overview_real(runs, cards=(), threshold=0.7, windows=(), liftings=()):
    since = ind.since_window(NOW)
    found = ind.read_runs(api._run_reports(), since.timestamp())
    return ind.real(api._watch_cycles(since.timestamp()), list(cards), threshold, since.timestamp(),
                    windows=list(windows), runs=found, liftings=liftings, enrolled=lambda rid: True)


def test_a_block_glorfindel_executed_alone_verified_and_held_is_contained_on_real_traffic(runs):
    """The week-end of 01/11: bree in non_disruptive, a brute force from five addresses, each
    blocked by Glorfindel alone — the overview counts them, from the detection to the read-back."""
    for i in range(5):
        _real(runs, NOW - timedelta(hours=10 + i), sid=f"rule-ssh-brute-force-{i:08x}", verified_after=40 + i)
    out = _overview_real(runs)
    assert out["alone"]["contained"] == 5 and out["alone"]["of"] == 5 and out["alone"]["inferred"] == 0
    assert out["contain"]["contain_s"] == 42.0 and out["contain"]["decide_s"] == 25.0
    assert out["contain"]["detect_s"] is None and out["t0"] == "detection"
    assert out["alone"]["by_outcome"] == {"contained_alone": 5}


def test_an_exercise_is_never_real_traffic(runs):
    """What the watch wrote (``source``) — and, for a line written before, a window still here
    or a run report on the VM: never counted on the overview."""
    a = NOW - timedelta(hours=3)
    _real(runs, a, source="exercise", exercise_run="r-annatar-1", sid="rule-x-00000001")
    # Written before OV1 (no source), inside a fault run on the VM: an exercise, inferred.
    (runs / "gothmog-f1.json").write_text(json.dumps({
        "run_id": "gothmog-f1", "mitre": "", "result": "PASS", "scenario": "VM shutdown",
        "metrics": {"injector": "gothmog", "kind": "fault", "fault_start": (a - timedelta(minutes=5)).isoformat(),
                    "fault_end": (a + timedelta(minutes=5)).isoformat(), "targets": [VM]}}))
    _real(runs, a, source=None, sid="rule-x-00000002")
    # Written before, inside a window still on this host: an exercise.
    win = {"run_id": "w1", "injector": "annatar", "kind": "technique", "experiment": "T1110.001 x",
           "targets": [VM.replace("vm-a", "vm-b")], "start": (NOW - timedelta(minutes=90)).isoformat(), "end": None,
           "expires": (NOW + timedelta(minutes=30)).isoformat(), "destructive": False}
    _real(runs, NOW - timedelta(hours=1), source=None, sid="rule-x-00000003", vm=VM.replace("vm-a", "vm-b"))
    out = _overview_real(runs, windows=[win])
    assert out["alone"]["of"] == 0 and out["contain"]["detected"] == 0
    # Neither — real traffic, inferred, and said.
    _real(runs, NOW - timedelta(days=2), source=None, sid="rule-x-00000004")
    out = _overview_real(runs, windows=[win])
    assert (out["alone"]["of"], out["alone"]["inferred"], out["alone"]["contained"]) == (1, 1, 1)


def test_a_decision_held_or_a_containment_that_did_not_hold_is_not_contained_alone(runs):
    a = NOW - timedelta(hours=6)
    _real(runs, a, executed=False, verified=None, guard="mode_hold", sid="rule-x-0000000a")
    _real(runs, a + timedelta(minutes=5), verified_after=30, sid="rule-x-0000000b")
    cards = [{"escalation_type": "verification_failed", "action": "block_suspicious_ip", "resource_id": VM,
              "timestamp": (a + timedelta(minutes=8)).isoformat(), "reason": "gone"}]
    out = _overview_real(runs, cards=cards)
    assert out["alone"]["contained"] == 0 and out["alone"]["of"] == 2
    assert out["alone"]["by_outcome"] == {"held_by_guard": 1, "not_holding": 1}
    assert out["contain"]["contain_s"] is None
    # Both recommended a block at or above the gate: the shadow counts them, not one judged wrong.
    assert out["alone"]["shadow"] == 2
    cards.append({"signal_id": "rule-x-0000000a", "verdict": "wrong"})
    assert _overview_real(runs, cards=cards)["alone"]["shadow"] == 1


def test_an_unattributed_row_a_cycle_without_a_decision_or_too_old_is_no_incident(runs):
    _real(runs, NOW - timedelta(hours=1), attribution="unattributed", sid="rule-x-00000011")
    _real(runs, NOW - timedelta(hours=1), action="", sid="rule-x-00000012")
    _real(runs, NOW - timedelta(days=31), sid="rule-x-00000013")
    _real(runs, NOW + timedelta(days=365), sid="rule-x-00000014")     # ahead of the clock: nowhere
    assert _overview_real(runs)["alone"]["of"] == 0


def test_the_overview_counts_real_traffic_and_dagorlad_the_exercises(runs):
    """The routes: the overview's two tiles on real traffic; Dagorlad's, the runs' as before."""
    a = NOW - timedelta(days=1)
    _report(runs, "r1", "T1110.001", a, latency=60.0)
    _window("r1", a - timedelta(minutes=1), a + timedelta(minutes=5))   # its T0 believed (SEC15)
    _cycle(runs, a + timedelta(seconds=60), "T1110.001", "block_suspicious_ip", 0.85)
    _real(runs, NOW - timedelta(hours=2), verified_after=33, sid="rule-x-00000021")
    c = console()
    over, ex = c.get("/api/indicators").json(), c.get("/api/dagorlad/indicators").json()
    assert over["alone"]["contained"] == 1 and over["contain"]["contain_s"] == 33.0
    assert ex["alone"]["of"] == 1 and ex["alone"]["contained"] == 0 and ex["contain"]["detect_s"] == 60.0
    assert set(ex) == {"window_days", "contain", "alone"}
    route = next(r for r in api.app.routes if getattr(r, "path", "") == "/api/dagorlad/indicators")
    assert route.methods == {"GET"}


@pytest.mark.parametrize("t0_after, window, why", [
    (0, True, ""),
    # Moved later than the attack time the watch received in the run: the time would shrink.
    (50, True, "postérieur à l'heure d'attaque que la watch a reçue de l'injecteur"),
    # Before its window opened.
    (-1800, True, "antérieur à l'ouverture de sa fenêtre d'exercice"),
    # No window on this host: nothing to confront it with.
    (0, False, "fenêtre d'exercice inconnue"),
    # Its window purged, a week after its end: no longer timed, said apart.
    (0, "purged", "fenêtre d'exercice purgée"),
])
def test_an_exercise_runs_t0_is_confronted_refused_never_counted_and_said(runs, t0_after, window, why):
    """SEC15 (#425): the T0 of an exercise's run is its injector's word — Dagorlad's indicators
    confront it as the campaign report does (SEC9). Refused: no time (to detect, to decide, to
    contain) is counted from it, the run is still counted contained alone, and the refusal is
    counted apart."""
    a = NOW - timedelta(days=1)
    t0 = a + timedelta(seconds=t0_after)
    seen = a + timedelta(seconds=60)
    if window == "purged":
        from eregion_core.exercise import exercises_dir
        exercises_dir().mkdir(parents=True, exist_ok=True)
        (exercises_dir() / "r1.json").write_text(json.dumps({"run_id": "r1", "purged_at": NOW.isoformat()}))
    elif window:
        _window("r1", a - timedelta(minutes=1), a + timedelta(minutes=5))
    _received(runs, "r1", a)
    _report(runs, "r1", "T1110.001", t0, latency=(seen - t0).total_seconds())
    _cycle(runs, seen, "T1110.001", "isolate_vm", 0.95, executed=True, verified=True)
    ex = console().get("/api/dagorlad/indicators").json()
    assert ex["alone"]["contained"] == 1 and ex["contain"]["t0_refused"] == (1 if why else 0)
    assert ex["contain"]["t0_purged"] == (1 if window == "purged" else 0)
    times = (ex["contain"]["detect_s"], ex["contain"]["decide_s"], ex["contain"]["contain_s"])
    assert times == ((None, None, None) if why else (60.0, 80.0, 80.0))
    found = ind.read_runs(api._run_reports(), 0.0)
    cycles = api._watch_cycles(None)
    refused, unread = ind.t0_confronted(found[0], ind.decision_of(found[0], ind.detections(cycles)),
                                        api._held_windows().get("r1"), cycles)
    assert why in refused and bool(refused) == bool(why) and unread == ""


def test_the_exercises_tile_says_a_t0_not_believed():
    from pathlib import Path
    js = (Path(api.__file__).parent / "static" / "injector.js").read_text()
    assert "T0 not believed: no time counted" in js and "c.t0_refused" in js
    assert "window purged, a week after its end" in js and "Number(c.t0_purged)" in js


def test_dagorlad_runs_shows_the_exercises_indicators_and_the_overview_says_real():
    """The page reads Dagorlad's route at its start and then every minute; the overview's two
    tiles say real traffic, the coverage and the last proof the exercises."""
    from pathlib import Path
    static = Path(api.__file__).parent / "static"
    js, ov = (static / "injector.js").read_text(), (static / "overview.js").read_text()
    assert "load('ind', '/api/dagorlad/indicators', renderIndicators)" in js
    assert "refreshCatalog(); refreshFast(); refreshSlow(); refreshIndicators();" in js
    assert '<section id="ind"' in (static / "injector.html").read_text()
    for label in ("'TIME TO CONTAIN · REAL'", "'CONTAINED ALONE · REAL'", "`COVERAGE · EXERCISES · ${days} d`",
                  "'LAST PROOF · EXERCISE'"):
        assert label in ov, label


def test_one_attacker_on_one_vm_is_one_incident_whatever_its_cycles(runs):
    """A block held (human_only): the brute force goes on, the rule's dedup ends with its window,
    the same address comes back — one incident, not two. Another address is another; the same one a
    day later, another too; a line written twice (its signal), one."""
    a = NOW - timedelta(hours=30)
    _real(runs, a, executed=False, verified=None, guard="mode_hold", sid="rule-x-a1", attacker="203.0.113.7")
    _real(runs, a + timedelta(minutes=12), executed=False, verified=None, guard="mode_hold", sid="rule-x-a2",
          attacker="203.0.113.7")
    _real(runs, a + timedelta(minutes=13), verified_after=40, sid="rule-x-b1", attacker="198.51.100.9")
    _real(runs, a + timedelta(minutes=13), verified_after=40, sid="rule-x-b1", attacker="198.51.100.9")
    _real(runs, a + timedelta(hours=25), verified_after=35, sid="rule-x-a3", attacker="203.0.113.7")
    # A rule's row without an address column, its line written twice: one incident still.
    _real(runs, a + timedelta(hours=2), verified_after=50, sid="rule-x-c1")
    _real(runs, a + timedelta(hours=2), verified_after=50, sid="rule-x-c1")
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["repeats"]) == (4, 3)
    assert out["alone"]["by_outcome"] == {"held_by_guard": 1, "contained_alone": 3}
    assert out["alone"]["contained"] == 3


def test_a_run_on_another_vm_never_makes_a_real_incident_an_exercise(runs):
    """Both ways of the fallback: a run on gondolin — an attack or a fault — at the same time
    leaves a real incident on bree real (inferred, and said)."""
    gondolin, bree = VM.replace("vm-a", "vm-celebrimbor-gondolin"), VM.replace("vm-a", "vm-celebrimbor-bree")
    a = NOW - timedelta(hours=4)
    (runs / "r-g.json").write_text(json.dumps({
        "run_id": "r-g", "mitre": "T1110.001", "result": "PASS", "scenario": "s",
        "metrics": {"kind": "technique", "attack_time": a.timestamp(), "detection": "detected",
                    "detection_latency_s": 30, "resource_id": gondolin}}))
    (runs / "gothmog-g.json").write_text(json.dumps({
        "run_id": "gothmog-g", "mitre": "", "result": "PASS", "scenario": "VM shutdown",
        "metrics": {"injector": "gothmog", "kind": "fault", "fault_start": (a - timedelta(minutes=5)).isoformat(),
                    "fault_end": (a + timedelta(minutes=5)).isoformat(), "targets": [gondolin]}}))
    _real(runs, a + timedelta(seconds=30), source=None, vm=bree, verified_after=40, sid="rule-x-bree")
    _real(runs, a + timedelta(seconds=30), source=None, vm=gondolin, verified_after=40, sid="rule-x-gondolin")
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["inferred"], out["alone"]["contained"]) == (1, 1, 1)


# ── OV1, its review: the exercises that hid as real traffic, the fold that hid a failure ──────

def test_an_old_attack_report_without_its_vm_never_makes_its_exercise_real(runs):
    """Q8: a report written before C1 names no VM. Its cycle — the decision the overview attaches
    to it — is the run's; another cycle of its technique inside its span, on any VM, too."""
    a = NOW - timedelta(days=3)
    _report(runs, "r-old", "T1110.001", a, latency=60.0)                          # no resource_id
    _real(runs, a + timedelta(seconds=60), source=None, sid="rule-x-q8a")          # its decision
    _real(runs, a + timedelta(minutes=40), source=None, sid="rule-x-q8b",          # its technique, its span
          vm=VM.replace("vm-a", "vm-b"))
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["inferred_exercise"]) == (0, 2)


def test_the_watch_saying_real_is_checked_again_a_window_late_by_the_channel_wins(runs):
    """Q9: the window reached the hosted watch after its cycle — the watch wrote « real », the
    Runs attach the cycle to the window. Only « exercise » is final."""
    win = {"run_id": "w-late", "injector": "annatar", "kind": "technique", "experiment": "T1110.001 x",
           "targets": [VM], "start": (NOW - timedelta(minutes=60)).isoformat(), "end": None,
           "expires": (NOW + timedelta(minutes=30)).isoformat(), "destructive": False}
    _real(runs, NOW - timedelta(minutes=30), source="real", sid="rule-x-q9")
    out = _overview_real(runs, windows=[win])
    assert (out["alone"]["of"], out["alone"]["inferred_exercise"], out["alone"]["inferred"]) == (0, 1, 0)
    # Said real and nothing contradicts it: real, not inferred.
    _real(runs, NOW - timedelta(days=2), source="real", sid="rule-x-q9b")
    out = _overview_real(runs, windows=[win])
    assert (out["alone"]["of"], out["alone"]["inferred"]) == (1, 0)


def test_an_attack_report_on_the_vm_alone_makes_a_line_an_exercise(runs):
    """The attack branch of the span, decisive alone: no window, not the run's decision (another
    technique, half an hour later), the report naming the VM."""
    a = NOW - timedelta(hours=6)
    (runs / "r-vm.json").write_text(json.dumps({
        "run_id": "r-vm", "mitre": "T1486", "result": "FAIL", "scenario": "s",
        "metrics": {"kind": "technique", "attack_time": a.timestamp(), "detection": "missed", "resource_id": VM}}))
    _real(runs, a + timedelta(minutes=30), source=None, sid="rule-x-span")
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["inferred_exercise"]) == (0, 1)


@pytest.mark.parametrize("ends", ["lifted", "drift"])
def test_a_containment_lifted_or_gone_ends_the_attackers_incident(runs, ends):
    """Q3, Q4: blocked, then unblocked an hour later (or a card saying the block is gone) — the
    address coming back and only escalated is another incident, never folded into a contained one."""
    a = NOW - timedelta(hours=10)
    _real(runs, a, verified_after=40, sid="rule-x-f1", attacker="203.0.113.7")
    _real(runs, a + timedelta(hours=2), executed=False, verified=None, sid="rule-x-f2", attacker="203.0.113.7",
          guard="")
    lifts, cards = (), []
    if ends == "lifted":
        lifts = [(VM, (a + timedelta(hours=1)).timestamp(), ("block_suspicious_ip",))]
    else:
        cards = [{"escalation_type": "verification_failed", "action": "block_suspicious_ip", "resource_id": VM,
                  "timestamp": (a + timedelta(minutes=30)).isoformat(), "reason": "gone"}]
    out = _overview_real(runs, cards=cards, liftings=lifts)
    assert (out["alone"]["of"], out["alone"]["repeats"]) == (2, 0)
    assert out["alone"]["by_outcome"].get("escalated") == 1
    # Neither: the second cycle is a repeat of a contained incident.
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["repeats"]) == (1, 1)


def test_the_debug_line_of_a_failed_cycle_is_written_whatever_its_label(tmp_path, monkeypatch):
    """OV1 review: the label read from a signal that is not what it should be (its raw_signal a
    list) never costs the failed cycle its debug line — the last trace of a detection."""
    from glorfindel.agent import record_cycle_failure
    monkeypatch.chdir(tmp_path)
    sig = {"signal_id": "s1", "event": "detection", "ttp": "T1110.001", "resource_id": VM,
           "timestamp": NOW.isoformat(), "context": {"run_id": "watch-x-1"}, "raw_signal": ["not", "a dict"]}
    record_cycle_failure(sig, RuntimeError("boom"), stage="decide", dry_run=True)
    line = json.loads((tmp_path / "runs" / "watch-x-1_debug.jsonl").read_text().splitlines()[-1])
    assert (line["source"], line["exercise_run"]) == ("unknown", "")


def test_the_decision_the_overview_attaches_to_a_run_is_never_real_wherever_its_time(runs):
    """The overview's last proof and the overview's real traffic never share a cycle: a run whose
    detection the overview attaches three hours after its attack — past the span of any window —
    keeps it an exercise, by the attachment alone."""
    a = NOW - timedelta(days=2)
    _report(runs, "r-late", "T1110.001", a, latency=3 * 3600.0)
    _real(runs, a + timedelta(hours=3), source=None, sid="rule-x-late")
    out = _overview_real(runs)
    assert (out["alone"]["of"], out["alone"]["inferred_exercise"]) == (0, 1)
