"""H-1 — an exercise window is no longer believed on its word.

Whoever can write a file in ``runs/exercises/``, or a blob in the exercise channel, could
pass a real attack off as an exercise. The reader now refuses a window that lasts longer
than MAX_DURATION_S, starts more than FUTURE_SKEW_S after it was declared, or takes the
RulePoller's run name; marks a VM only if the VM is enrolled (its tags, read by the watch:
eregion_core/inscription.py ``TagEnrollment``); takes the run_id shortcut only on a VM the
window names; purges windows a week past their last moment. An exercise card stays in the
operator's list, flagged. On H0, a campaign that came through the channel is checked against
its shape, its runs kept only with a known window naming an enrolled VM, and its report says
which facts came through the channel.

No Azure call: the tag reads go through a fake ``get``; the container is in memory
(tests/unit/fake_container.py). Mutants M57 and M220–M238 (scripts/mutation_check.py) are
measured here.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from eregion_core import exercise
from eregion_core import exercise_channel as channel
from eregion_core.exercise import (FUTURE_SKEW_S, MAX_DURATION_S, PURGE_AFTER_S, covering_runs,
                                   load_windows, open_window, source_of, window_refusal)
from tests.unit.fake_container import CRED, URL, FakeContainer

VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
LOAD = VM.replace("gondolin", "bree")           # the VM carrying a real load: never enrolled
NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    """NOW is the clock when each test starts, not when this file was imported: a long suite
    (the CI's) no longer ages it past the windows and heartbeats the code under test compares
    with its own clock (SEC6, P-08)."""
    global NOW
    NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _window(rid="r1", *, start=None, lasts=MAX_DURATION_S, end=None, targets=(VM,)):
    start = start or NOW - timedelta(minutes=10)
    return {"run_id": rid, "injector": "annatar", "kind": "technique", "experiment": "T1486",
            "targets": [t.lower() for t in targets], "start": start.isoformat(),
            "end": end.isoformat() if end else None,
            "expires": (start + timedelta(seconds=lasts)).isoformat()}


def _put(window, *, mtime=None):
    d = exercise.exercises_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{window['run_id']}.json"
    path.write_text(json.dumps(window))
    if mtime is not None:
        os.utime(path, (mtime.timestamp(), mtime.timestamp()))
    return path


# ── 1. A window is refused, not believed ───────────────────────────────────────

def test_a_window_longer_than_max_duration_is_refused():
    """M220: a window of a day would make every detection of that day an exercise."""
    assert window_refusal(_window(lasts=MAX_DURATION_S)) == ""
    assert "MAX_DURATION_S" in window_refusal(_window(lasts=MAX_DURATION_S + 1))
    assert "MAX_DURATION_S" in window_refusal(_window(lasts=24 * 3600))
    assert window_refusal(_window(lasts=0)) and window_refusal(_window(lasts=-60))
    _put(_window(lasts=24 * 3600))
    assert load_windows() == []
    assert source_of(VM, NOW) == ("real", "")


def test_a_window_that_starts_far_after_it_was_declared_is_refused():
    """M221: a window written now for later would cover what comes then."""
    later = NOW + timedelta(seconds=FUTURE_SKEW_S + 60)
    assert "FUTURE_SKEW_S" in window_refusal(_window(start=later), NOW)
    assert window_refusal(_window(start=NOW + timedelta(seconds=FUTURE_SKEW_S - 30)), NOW) == ""
    _put(_window(start=later), mtime=NOW)
    assert load_windows(now=NOW) == []


def test_a_window_written_today_for_tomorrow_is_refused_tomorrow_too():
    """M229: its file's mtime is when it was declared — when tomorrow comes, it still
    starts a day after it was written."""
    tomorrow = NOW + timedelta(days=1)
    _put(_window(start=tomorrow), mtime=NOW)
    assert load_windows(now=tomorrow + timedelta(minutes=5)) == []
    assert source_of(VM, tomorrow + timedelta(minutes=5),
                     windows=load_windows(now=tomorrow + timedelta(minutes=5))) == ("real", "")


def test_a_window_never_takes_the_rulepollers_run_name():
    """M226: the RulePoller's detections carry run ids ``watch-<rule>-<ts>``; a window of
    that name would make the detection an exercise by its run id."""
    rid = "watch-ssh-brute-force-20261026T100000Z"
    assert "RulePoller" in window_refusal(_window(rid))
    _put(_window(rid))
    assert source_of(VM, NOW, run_id=rid) == ("real", "")


@pytest.mark.parametrize("change, why", [
    ({"run_id": "../escape"}, "plain name"),
    ({"targets": VM}, "targets"),
    ({"start": "yesterday"}, "unreadable"),
    ({"end": (NOW - timedelta(hours=1)).isoformat()}, "before its start"),
])
def test_a_malformed_window_is_refused(change, why):
    assert why in window_refusal({**_window(), **change})


def test_a_refused_window_is_said_once(capsys):
    _put(_window(lasts=24 * 3600))
    load_windows()
    load_windows()
    assert capsys.readouterr().out.count("window r1.json refused") == 1


# ── 2. A window marks an enrolled VM only ─────────────────────────────────────

def test_a_target_not_enrolled_is_never_in_an_exercise(monkeypatch):
    """M222: a window naming the VM that carries a real load (never enrolled) marks
    nothing — the enrollment is read by the watch, never from the window."""
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: rid.lower() != LOAD.lower())
    open_window("r1", injector="annatar", kind="technique", experiment="T1486",
                targets=[VM, LOAD], now=NOW - timedelta(minutes=10))
    assert source_of(VM, NOW) == ("exercise", "r1")
    assert source_of(LOAD, NOW) == ("real", "")
    assert source_of(LOAD, NOW, run_id="r1") == ("real", "")
    assert covering_runs(LOAD, NOW, load_windows()) == []
    assert covering_runs(VM, NOW, load_windows()) == ["r1"]


def test_without_an_enrollment_check_no_window_marks_anything(monkeypatch):
    """M227: a reader that cannot check the enrollment labels every cycle real."""
    monkeypatch.setattr(exercise, "_enrollment_check", None)
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM],
                now=NOW - timedelta(minutes=10))
    assert source_of(VM, NOW) == ("real", "")
    assert source_of(VM, NOW, run_id="r1") == ("real", "")


def test_a_check_that_fails_enrolls_nothing(monkeypatch):
    def boom(rid):
        raise RuntimeError("HTTP 403")
    monkeypatch.setattr(exercise, "_enrollment_check", boom)
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM],
                now=NOW - timedelta(minutes=10))
    assert source_of(VM, NOW) == ("real", "")


def test_the_run_id_shortcut_needs_the_vm_among_the_targets():
    """M223: a signal carrying a window's run_id is an exercise only on a VM it names."""
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM],
                now=NOW - timedelta(minutes=10))
    assert source_of(VM, NOW - timedelta(days=2), run_id="r1") == ("exercise", "r1")
    assert source_of(LOAD, NOW, run_id="r1") == ("real", "")


# ── 3. The tags, read by the watch (eregion_core/inscription.py) ────────────────

def _arm(tags_by_url, status=200):
    calls = []

    def get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        if status != 200:
            return SimpleNamespace(ok=False, status_code=status, json=lambda: {})
        return SimpleNamespace(ok=True, status_code=200,
                               json=lambda: {"tags": tags_by_url.get(url, {})})
    return get, calls


ENROLLED = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}
ARM_RG = "https://management.azure.com/subscriptions/s/resourceGroups/rg-celebrimbor"


def test_tag_enrollment_reads_the_vm_and_its_resource_group():
    """Measured on the bench on 26/10: gondolin enrolled, bree (the real load) not."""
    from eregion_core.inscription import ARM, TagEnrollment
    get, calls = _arm({ARM_RG: ENROLLED, f"{ARM}{VM}": ENROLLED, f"{ARM}{LOAD}": {"eregion": "x"}})
    check = TagEnrollment(bench="celebrimbor", credential=CRED, get=get)
    assert check(VM) is True and check(LOAD) is False
    assert check(VM) is True and len(calls) == 4               # cached: no new read


def test_a_tag_read_that_fails_is_not_enrolled_and_retried_later():
    """M228: a 403, a VM gone, no credential — never « enrolled »."""
    from eregion_core.inscription import TagEnrollment
    clock = [0.0]
    get, calls = _arm({}, status=403)
    check = TagEnrollment(bench="celebrimbor", credential=CRED, get=get, clock=lambda: clock[0])
    assert check(VM) is False
    assert check(VM) is False and len(calls) == 1              # failure cached FAIL_TTL_S
    clock[0] += TagEnrollment.FAIL_TTL_S + 1
    check(VM)
    assert len(calls) == 2
    assert TagEnrollment(credential=CRED, get=get)("vm-celebrimbor-gondolin") is False


# ── 4. Purge ───────────────────────────────────────────────────────────────────

def test_a_window_a_week_past_its_last_moment_is_purged():
    """M225: emptied — its run_id no longer takes the shortcut, its times are gone."""
    old = NOW - timedelta(seconds=PURGE_AFTER_S + 4 * 3600)
    path = _put(_window(start=old, end=old + timedelta(minutes=5)), mtime=old)
    recent = _put(_window("r2"))
    assert [w["run_id"] for w in load_windows()] == ["r2"]
    assert json.loads(path.read_text()).keys() == {"run_id", "purged_at"}
    assert source_of(VM, old + timedelta(minutes=2), run_id="r1") == ("real", "")
    assert recent.exists() and load_windows() == [json.loads(recent.read_text())]


def test_a_purged_window_is_not_pulled_again():
    """M230: its tombstone keeps its file's mtime — the channel's copy, not newer, is not
    downloaded again at every pull (thirty seconds)."""
    c = FakeContainer()
    old = NOW - timedelta(seconds=PURGE_AFTER_S + 4 * 3600)
    channel.publish(_window(start=old, end=old + timedelta(minutes=5)),
                    channel=URL, credential=CRED, put=c.put)
    d = exercise.exercises_dir()
    channel.pull(d, channel=URL, credential=CRED, get=c.get)
    os.utime(d / "r1.json", (old.timestamp(), old.timestamp()))
    assert load_windows() == []
    c.gets.clear()
    assert channel.pull(d, channel=URL, credential=CRED, get=c.get) == 0
    assert c.gets == []


# ── 5. The operator's list keeps the exercise cards, flagged ────────────────────

def test_an_exercise_card_stays_in_the_list_to_judge_flagged():
    """M224: hidden, a real attack labelled exercise by a forged window would never reach
    the operator."""
    from glorfindel import escalations
    kw = dict(action="isolate_vm", escalation_type="mode_hold", reason="r")
    drill = escalations.record("rule-x-0123abcd", VM, **kw, source="exercise", exercise_run="r1")
    real = escalations.record("rule-y-0123abcd", LOAD, **kw, source="real")
    cards = {c["id"]: c for c in escalations.to_judge()}
    assert set(cards) == {drill, real}
    assert (cards[drill]["exercise"], cards[drill]["exercise_run"]) == (True, "r1")
    assert cards[real]["exercise"] is False
    assert escalations.observation_report()["exercises"] == 1    # still counted apart


# ── 6. A campaign that came through the channel (H0) ────────────────────────────

@pytest.fixture()
def h0(monkeypatch):
    import requests

    from analysis import hosted_report as hr

    def refuse(*a, **kw):
        raise AssertionError("a call left the process")
    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "put", refuse)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    monkeypatch.setattr(hr, "_said", {})
    monkeypatch.setattr(hr, "_failures", {})


def _campaign(tmp_path, *, scenarios=None, pulled=True, windows=None, reports=None):
    from tests.unit.test_hosted_report import _h0, _scen, _window as _hwindow
    cdir, runs = _h0(tmp_path, scenarios=scenarios or [_scen(1, "R1"), _scen(2, "R2")],
                     pulled=pulled)
    for rid, w in (windows or {}).items():
        path = runs / "exercises" / f"{rid}.json"
        if w is None:
            path.unlink()
        else:
            path.write_text(json.dumps(w(_hwindow) if callable(w) else w))
    for rid, r in (reports or {}).items():
        (cdir / "runs" / f"{rid}.json").write_text(json.dumps(r))
    return cdir, runs


def _facts(cdir):
    from analysis import campaign_report as cr
    skipped = []
    facts = cr.collect_facts(cdir, warn=skipped.append)
    return [f.run_id for f in facts], " ; ".join(skipped)


def test_a_channel_run_without_a_known_window_is_left_out(tmp_path, h0):
    """M232: a run the injectors' host says it played, with no window H0 knows of."""
    cdir, _ = _campaign(tmp_path, windows={"R2": None})
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : fenêtre d'exercice inconnue" in skipped


def test_a_local_run_without_a_window_stays_an_unknown_decision(tmp_path, h0):
    """Beside the watch (no ``.pulled``), nothing came through the channel: as before."""
    from analysis import campaign_report as cr
    cdir, _ = _campaign(tmp_path, pulled=False, windows={"R2": None})
    facts = {f.run_id: f for f in cr.collect_facts(cdir, warn=lambda m: None)}
    assert set(facts) == {"R1", "R2"} and cr.NO_WINDOW in facts["R2"].decision_unknown


def test_a_channel_run_whose_window_was_purged_says_so(tmp_path, h0):
    cdir, _ = _campaign(tmp_path, windows={"R2": {"run_id": "R2", "purged_at": "2026-10-09T10:00:00+00:00"}})
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : fenêtre purgée" in skipped


def test_a_channel_run_with_a_window_too_long_is_left_out(tmp_path, h0):
    cdir, _ = _campaign(tmp_path, windows={"R2": lambda w: {**w("R2"), "expires": "2026-10-09T10:00:00+00:00"}})
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : fenêtre refusée" in skipped


def test_a_channel_run_whose_vm_is_not_enrolled_is_left_out(tmp_path, h0, monkeypatch):
    """M233."""
    from tests.unit.test_hosted_report import OTHER_VM, _scen
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: rid.lower() != OTHER_VM.lower())
    cdir, _ = _campaign(tmp_path, scenarios=[_scen(1, "R1"), _scen(2, "R2", vm=OTHER_VM)])
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : sa VM n'est pas inscrite" in skipped


def test_a_channel_run_whose_vm_its_window_does_not_name_is_left_out(tmp_path, h0):
    """M234."""
    from tests.unit.test_hosted_report import OTHER_VM
    cdir, _ = _campaign(tmp_path, windows={"R2": lambda w: w("R2", vm=OTHER_VM)})
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : sa VM n'est pas une cible de sa fenêtre" in skipped


def test_a_channel_scenario_of_the_wrong_shape_is_left_out(tmp_path, h0):
    """M236."""
    from tests.unit.test_hosted_report import _scen
    bad = {**_scen(2, "R2"), "detection_latency_s": "fast"}
    cdir, _ = _campaign(tmp_path, scenarios=[_scen(1, "R1"), bad])
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "scénario refusé (its detection_latency_s" in skipped


def test_a_channel_run_report_of_another_run_is_left_out(tmp_path, h0):
    """M237: the report of a run must be that run's."""
    cdir, _ = _campaign(tmp_path, reports={"R2": {"run_id": "R1", "metrics": {"attack_time": 1.0}}})
    ids, skipped = _facts(cdir)
    assert ids == ["R1"] and "R2 refusé : rapport du run" in skipped


def test_a_manifest_of_the_wrong_shape_gets_no_report(tmp_path, h0):
    """M231: H0 reads the manifest against its shape before anything else."""
    from analysis import hosted_report as hr
    cdir, runs = _campaign(tmp_path)
    m = json.loads((cdir / "manifest.json").read_text())
    (cdir / "manifest.json").write_text(json.dumps({**m, "scenarios": "all of them"}))
    said = []
    assert hr.ready(runs / "campaigns", say=said.append) == []
    hr.ready(runs / "campaigns", say=said.append)
    assert len([s for s in said if "manifest refused" in s]) == 1


def test_the_report_says_which_facts_came_through_the_channel(tmp_path, h0):
    """M235."""
    from analysis import campaign_report as cr
    cdir, _ = _campaign(tmp_path)
    report = cr.Report(campaign_id="C1", facts=cr.collect_facts(cdir, warn=lambda m: None),
                       channel=cr.from_channel(cdir))
    assert cr.CHANNEL_NOTE in cr.render(report)
    local = cr.Report(campaign_id="C1", facts=report.facts, channel=False)
    assert cr.CHANNEL_NOTE not in cr.render(local)


def test_a_window_too_long_bounds_no_decision(tmp_path, h0):
    """M238: a window of three days would attach any detection of those days to the run."""
    from analysis import campaign_report as cr
    from tests.unit.test_hosted_report import T, _attach
    cdir, runs = _campaign(tmp_path, pulled=False,
                           windows={"R1": lambda w: {**w("R1", end=None),
                                                     "expires": (T + timedelta(days=3)).isoformat()}})
    dec, why, until = _attach(cdir, runs)
    assert (dec, until) == ({}, None) and why == cr.NO_WINDOW


# ── 7. The schemas and their runtime check agree ───────────────────────────────

_SCEN = {"seq": 1, "ttp": "T1136.001", "status": "executed", "run_id": "R1",
         "target_resource_id": VM, "detection": "detected", "detection_latency_s": 98.2,
         "name": "account", "error": None, "finished_at": "2026-10-23T08:20:00Z"}


@pytest.mark.parametrize("manifest", [
    {"campaign_id": "C1", "state": "done", "scenarios": [_SCEN]},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "run_id": None, "detection": None}]},
    {"campaign_id": "../C1", "state": "done", "scenarios": []},
    {"campaign_id": "C1", "state": "finished", "scenarios": []},
    {"campaign_id": "C1", "state": "done", "scenarios": {}},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "seq": "1"}]},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "status": "won"}]},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "run_id": "a/b"}]},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "detection": "maybe"}]},
    {"campaign_id": "C1", "state": "done", "scenarios": [{**_SCEN, "detection_latency_s": -1}]},
    # V1 (#214): a campaign run --without-glorfindel says so, typed.
    {"campaign_id": "C1", "state": "done", "scenarios": [], "without_glorfindel": True},
    {"campaign_id": "C1", "state": "done", "scenarios": [], "without_glorfindel": "yes"},
])
def test_the_manifest_schema_and_its_runtime_check_agree(manifest):
    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path

    from analysis.campaign_schema import manifest_refusal, scenario_refusal
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas"
                         / "campaign_manifest.schema.json").read_text())
    by_schema = not list(jsonschema.Draft7Validator(schema).iter_errors(manifest))
    by_code = not manifest_refusal(manifest) and all(
        not scenario_refusal(s) for s in manifest["scenarios"])
    assert by_schema == by_code


@pytest.mark.parametrize("report, ok", [
    ({"run_id": "R1", "metrics": {"attack_time": 1761200000.5}}, True),
    ({"run_id": "R1", "metrics": {"attack_time": None}}, True),
    ({"run_id": "R1", "metrics": {"attack_time": "soon"}}, False),
    ({"run_id": "R1", "metrics": []}, False),
    ({"metrics": {}}, False),
    # V1 (#214): a run --without-glorfindel, accepted — never with a verdict.
    ({"run_id": "R1", "metrics": {"without_glorfindel": True, "detection": "unknown"}}, True),
    ({"run_id": "R1", "metrics": {"without_glorfindel": False, "detection": "missed"}}, True),
    ({"run_id": "R1", "metrics": {"without_glorfindel": True, "detection": "detected"}}, False),
    ({"run_id": "R1", "metrics": {"without_glorfindel": "yes"}}, False),
])
def test_the_run_report_schema_and_its_runtime_check_agree(report, ok):
    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path

    from analysis.campaign_schema import run_report_refusal
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas"
                         / "run_report.schema.json").read_text())
    assert (not list(jsonschema.Draft7Validator(schema).iter_errors(report))) is ok
    assert (not run_report_refusal(report, "R1")) is ok
