"""Dagorlad, phase (c) (DG-c, #349; docs/design/console.md §7): a request followed live.

Each wire's chronology is read from what already reaches the console's host — the request, the
status Orodruin publishes, the exercise windows, the watch's cycles, the cards, the run's report
— and a run is measured there as on the overview (BL1, C1). Nothing is written, the watch is told
nothing. No Azure, no model: windows, cycles, cards and reports are written by the test.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from eregion_console import follow, indicators
from eregion_core.exercise_plan import load_catalog

RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, SENTINEL = RG + "vm-celebrimbor-gondolin", RG + "vm-sentinel"
RID = "r-20261031T080000Z-abcdef"
T = datetime(2026, 10, 31, 8, 1, tzinfo=timezone.utc)
CATALOG = load_catalog()


def _iso(d: datetime) -> str:
    return d.isoformat()


def _window(run_id, *, start=T, end=None, kind="technique", experiment="T1110.001 ssh-brute",
            targets=(GONDOLIN,), request=RID, **extra) -> dict:
    return {"run_id": run_id, "injector": "gothmog" if kind == "fault" else "annatar", "kind": kind,
            "experiment": experiment, "targets": [t.lower() for t in targets], "start": _iso(start),
            "end": _iso(end) if end else None, "expires": _iso(start + timedelta(hours=2)),
            "destructive": False, "request": request, **extra}


def _cycle(*, seen, ttp="T1110.001", vm=GONDOLIN, action="isolate_vm", executed=True, verified=True,
           decided_after=20, verified_after=None, status="isolated", guard="", mode="non_disruptive",
           sid="rule-ssh-1", event="detection", attribution="asset") -> dict:
    """A cycle as the console slims it (eregion_console/api.py ``_slim_cycle``)."""
    return {"at": _iso(seen + timedelta(seconds=decided_after)), "signal_at": _iso(seen), "event": event,
            "ttp": ttp, "resource_id": vm, "rule": "ssh-brute-force", "attribution": attribution,
            "action": action, "confidence": 0.92, "escalate": not executed, "status": status,
            "executed": executed, "verified": verified, "mode": mode,
            "verified_at": _iso(seen + timedelta(seconds=verified_after)) if verified_after else None,
            "cycle_error": False, "signal_id": sid, "escalation_type": guard, "unverified": False}


def _report(run_id, *, at=T, detection="detected", latency=60.0, kind="technique", result="PASS",
            checks=None, **metrics) -> dict:
    m = {"run_format": 1, "kind": kind, "injector": "gothmog" if kind == "fault" else "annatar",
         "request": RID}
    if kind == "technique":
        m.update(attack_time=at.timestamp(), detection=detection, detection_latency_s=latency,
                 experiment_id="T1110.001", resource_id=GONDOLIN)
    else:
        m.update(fault_start=_iso(at), fault="vm-shutdown", experiment_id="vm-shutdown",
                 targets=[GONDOLIN])
    m.update(metrics)
    return {"scenario": "x", "run_id": run_id, "mitre": "T1110.001" if kind == "technique" else "",
            "result": result, "metrics": m, "thresholds": {}, "checks": checks or {}}


def _status(*wires, state="running", at=T) -> dict:
    return {"request": RID, "state": state, "at": _iso(at), "codes": [],
            "wires": [{"rank": i, "state": s, "code": c, "runs": list(r), "result": ""}
                      for i, (s, c, r) in enumerate(wires, 1)]}


WIRE = {"rank": 1, "experiment": "T1110.001", "target": GONDOLIN}
FAULT = {"rank": 2, "experiment": "vm-shutdown", "target": GONDOLIN}


def _follow(*, wires=(WIRE,), status=None, windows=(), states=None, cycles=(), reports=None, cards=(),
            to_judge=(), now=T + timedelta(minutes=5), liftings=()):
    windows = list(windows)
    states = states if states is not None else {w["run_id"]: "open" for w in windows}
    return follow.follow(RID, list(wires), status, windows, states, list(cycles), reports or {}, list(cards),
                         set(to_judge), now=now, catalog=CATALOG, liftings=liftings,
                         enrolled=lambda rid: True)


# ── The phase of a request ─────────────────────────────────────────────────────────────

def test_a_request_not_carried_yet_is_written_its_wires_queued():
    out = _follow()
    assert out["phase"] == "written"
    [w] = out["wires"]
    assert (w["state"], w["heard"], w["run"], w["decision"]) == ("queued", False, "", None)
    assert w["target_name"] == "vm-celebrimbor-gondolin" and w["kind"] == "technique"


@pytest.mark.parametrize("state", ["finished", "refused"])
def test_orodruin_saying_it_finished_or_refused_ends_the_request(state):
    out = _follow(status=_status(("done", "", ()), state=state))
    assert (out["phase"], out["why"]) == ("over", state)


def test_a_request_runs_while_a_window_of_it_lives_even_unheard_from_orodruin():
    out = _follow(windows=[_window("run-1")])
    assert (out["phase"], out["why"]) == ("running", "launched")
    assert out["wires"][0]["state"] == "running" and out["wires"][0]["heard"] is False


def test_stop_all_ends_the_request_once_no_window_of_it_lives():
    """« Stop all » kills Orodruin's runner unsaid: its status stays « running »; the window it
    closed says it (closed_by orodruin-kill)."""
    win = _window("run-1", end=T + timedelta(minutes=2), closed_by="orodruin-kill")
    status = _status(("running", "", ("run-1",)), ("queued", "", ()))
    assert _follow(status=status, windows=[win], states={"run-1": "grace"})["phase"] == "running"
    out = _follow(status=status, windows=[win], states={"run-1": "closed"})
    assert (out["phase"], out["why"]) == ("over", "stopped")


def test_orodruin_silent_longer_than_a_request_may_last_ends_it():
    status = _status(("queued", "", ()), at=T)
    within = T + timedelta(seconds=follow.SILENT_S - 60)
    assert _follow(status=status, now=within)["phase"] == "running"
    out = _follow(status=status, now=T + timedelta(seconds=follow.SILENT_S + 60))
    assert (out["phase"], out["why"]) == ("over", "silent")


# ── A technique's wire ─────────────────────────────────────────────────────────────────

def test_a_live_wire_is_followed_from_its_window_before_the_report():
    """Orodruin has not named its run yet: the window of the request, of its experiment, on its
    target, is the wire's. T0 is the window's start; the detection, the first of its own
    technique on its target inside the window — provisional."""
    win = _window("run-1")
    c = _cycle(seen=T + timedelta(seconds=90), verified_after=40)
    out = _follow(status=_status(("running", "", ())), windows=[win], cycles=[c])
    [w] = out["wires"]
    assert (w["run"], w["state"], w["provisional"], w["t0_from"]) == ("run-1", "running", True, "window start")
    assert w["t0"] == _iso(T) and w["detect_s"] == 90.0
    assert w["decision"]["action"] == "isolate_vm" and w["decision"]["decide_s"] == 110.0
    assert (w["outcome"], w["contain_s"]) == ("contained_alone", 130.0)
    assert w["window"]["state"] == "open"


def test_a_cycle_of_another_technique_another_vm_or_outside_the_window_is_not_the_wires():
    win = _window("run-1", end=T + timedelta(minutes=3))
    cycles = [_cycle(seen=T + timedelta(seconds=30), ttp="T1486"),
              _cycle(seen=T + timedelta(seconds=30), vm=SENTINEL),
              _cycle(seen=T - timedelta(minutes=10)),
              _cycle(seen=T + timedelta(seconds=30), attribution="unattributed")]
    [w] = _follow(windows=[win], cycles=cycles)["wires"]
    assert w["decision"] is None and w["outcome"] == "" and w["detection"] == ""


def test_a_window_of_another_request_or_another_wire_is_not_the_wires():
    wins = [_window("other-req", request="r-20261031T070000Z-000000"),
            _window("other-wire", experiment="T1486 ransom")]
    [w] = _follow(windows=wins)["wires"]
    assert w["run"] == "" and w["runs"] == []


def test_once_the_report_is_here_the_run_is_measured_as_on_the_overview():
    """The decision the indicators attach, their timeline, BL1's ending — not the window's."""
    win = _window("run-1", start=T - timedelta(seconds=40), end=T + timedelta(minutes=4))
    c = _cycle(seen=T + timedelta(seconds=60), verified_after=50)
    rep = _report("run-1", latency=60.0)
    [w] = _follow(status=_status(("done", "", ("run-1",)), state="finished"), windows=[win], cycles=[c],
                  reports={"run-1": rep}, states={"run-1": "grace"})["wires"]
    assert (w["provisional"], w["t0_from"], w["t0"]) == (False, "attack", _iso(T))
    assert (w["detect_s"], w["outcome"], w["contain_s"]) == (60.0, "contained_alone", 110.0)
    assert w["verdict"] == {"result": "PASS", "detection": "detected", "without_glorfindel": False}
    from eregion_core import run_report
    run = run_report.read_run(rep, "run-1")
    overview = indicators.compute([run], [c], [], [], {}, {}, 0.7, (T + timedelta(hours=1)).timestamp())
    assert overview["contain"]["contain_s"] == w["contain_s"]
    assert overview["contain"]["detect_s"] == w["detect_s"]


def test_an_isolation_that_did_not_hold_is_not_contained():
    """BL1: a card of the reassertion on the VM after the read-back — the isolation gone."""
    win = _window("run-1")
    c = _cycle(seen=T + timedelta(seconds=60), verified_after=30)
    card = {"id": "esc-9", "escalation_type": "verification_failed", "action": "isolate_vm",
            "resource_id": GONDOLIN, "timestamp": _iso(T + timedelta(minutes=3)), "reason": "gone"}
    [w] = _follow(windows=[win], cycles=[c], cards=[card])["wires"]
    assert w["outcome"] == "not_holding" and w["contain_s"] is None


def test_a_decision_held_by_a_guard_says_which():
    win = _window("run-1")
    c = _cycle(seen=T + timedelta(seconds=60), executed=False, verified=None, status="escalated",
               guard="mode_hold", mode="human_only")
    [w] = _follow(windows=[win], cycles=[c])["wires"]
    assert (w["outcome"], w["outcome_why"]) == ("held_by_guard", "mode_hold")
    assert w["decision"]["guard"] == "mode_hold" and w["contain_s"] is None


def test_a_missed_run_says_missed():
    win = _window("run-1", end=T + timedelta(minutes=5))
    [w] = _follow(windows=[win], reports={"run-1": _report("run-1", detection="missed", latency=None,
                                                             result="FAIL")})["wires"]
    assert (w["outcome"], w["detection"], w["verdict"]["detection"]) == ("missed", "missed", "missed")


def test_the_cards_carrying_the_run_and_whether_they_wait_for_a_verdict():
    win = _window("run-1")
    cards = [{"id": "esc-1", "escalation_type": "mode_hold", "action": "isolate_vm", "exercise_run": "run-1"},
             {"id": "esc-2", "escalation_type": "low_confidence", "action": "snapshot", "exercise_run": "other"}]
    [w] = _follow(windows=[win], cards=cards, to_judge={"esc-1"})["wires"]
    assert w["cards"] == [{"id": "esc-1", "type": "mode_hold", "action": "isolate_vm", "to_judge": True}]


def test_orodruins_word_on_a_wire_passes_through():
    status = _status(("done", "", ("run-1",)), ("skipped", "isolated", ()))
    out = _follow(wires=[WIRE, {"rank": 2, "experiment": "T1486", "target": GONDOLIN}], status=status,
                  windows=[_window("run-1", end=T + timedelta(minutes=2))], states={"run-1": "grace"})
    assert [(w["state"], w["code"]) for w in out["wires"]] == [("done", ""), ("skipped", "isolated")]


def test_a_request_not_written_here_is_followed_by_orodruins_ranks_and_the_windows():
    status = _status(("running", "", ("run-1",)))
    out = _follow(wires=(), status=status, windows=[_window("run-1")],
                  cycles=[_cycle(seen=T + timedelta(seconds=45))])
    [w] = out["wires"]
    assert (w["rank"], w["experiment"], w["run"], w["kind"]) == (1, "", "run-1", "technique")
    assert w["decision"]["action"] == "isolate_vm"


# ── A fault's wire: nothing disruptive, its return verified ─────────────────────────────

def test_a_fault_taken_for_an_attack_is_said():
    win = _window("fault-1", kind="fault", experiment="vm-shutdown Arrêt")
    c = _cycle(seen=T + timedelta(seconds=30), ttp="T1499", verified_after=20)
    [w] = _follow(wires=[FAULT], windows=[win], cycles=[c])["wires"]
    assert w["kind"] == "fault" and w["provisional"] is True
    assert [(m["action"], m["executed"]) for m in w["mistaken"]] == [("isolate_vm", True)]


def test_a_fault_with_nothing_disruptive_and_its_return_verified():
    win = _window("fault-1", kind="fault", experiment="vm-shutdown Arrêt", end=T + timedelta(minutes=6))
    rep = _report("fault-1", kind="fault", time_to_restore_s=150.0, fault_end=_iso(T + timedelta(minutes=5)),
                  checks={"revert_verified": "PASS"})
    c = _cycle(seen=T + timedelta(seconds=30), action="snapshot", executed=True)
    [w] = _follow(wires=[FAULT], windows=[win], cycles=[c], reports={"fault-1": rep},
                  states={"fault-1": "grace"})["wires"]
    assert (w["mistaken"], w["returned"], w["restore_s"], w["t0_from"]) == ([], True, 150.0, "fault start")
    assert w["verdict"]["result"] == "PASS" and w["verdict"]["detection"] == ""


def test_an_attacks_decision_is_never_counted_against_the_next_fault():
    """A technique then a fault on one VM (one after the other): the attack's isolation, seen in
    the fault's span, is the attack's — never « a fault taken for an attack »."""
    t_win = _window("run-1", end=T + timedelta(minutes=3))
    f_win = _window("fault-1", kind="fault", experiment="vm-shutdown Arrêt", start=T + timedelta(seconds=10))
    c = _cycle(seen=T + timedelta(seconds=30), verified_after=20)
    out = _follow(wires=[WIRE, FAULT], windows=[t_win, f_win], cycles=[c],
                  states={"run-1": "grace", "fault-1": "open"})
    tech, fault = out["wires"]
    assert tech["outcome"] == "contained_alone" and fault["mistaken"] == []


# ── The route: the console's own reads, nothing written ─────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")   # the console's extra
    pytest.importorskip("httpx")
    from eregion_core import watch_gate
    from .console_client import console
    import eregion_console.api as api
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,gothmog")
    monkeypatch.delenv("EREGION_BENCH", raising=False)
    vms = [{"resource_id": GONDOLIN, "name": "vm-celebrimbor-gondolin", "resource_group": "rg-celebrimbor",
            "rg_tags": {"eregion-target": "celebrimbor"},
            "tags": {"eregion-target": "celebrimbor", "eregion-zone": "bench"}}]
    monkeypatch.setattr(api, "READ_TARGETS", lambda subscription: vms)
    api._targets_cache.update(at=0.0, value=None)
    monkeypatch.setattr(api, "_board_rules", lambda: [])
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None: "")
    return console()


def _write_window(win: dict) -> None:
    from eregion_core.exercise import exercises_dir
    d = exercises_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{win['run_id']}.json").write_text(json.dumps(win))


def _tree(*roots: Path) -> dict:
    out = {}
    for root in roots:
        for p in sorted(root.rglob("*")) if root.exists() else []:
            if p.is_file():
                out[str(p)] = p.read_bytes()
    return out


def test_the_route_gives_the_wires_and_their_chronology(client, tmp_path):
    r = client.post("/api/dagorlad/requests", json={"wires": [{"experiment": "T1110.001", "target": GONDOLIN}]})
    assert r.status_code == 200, r.text
    rid = r.json()["request"]
    now = datetime.now(timezone.utc)
    win = _window("run-live", start=now - timedelta(minutes=2), request=rid)
    _write_window(win)
    rec = {"timestamp": _iso(now - timedelta(seconds=40)),
           "signal": {"signal_id": "rule-ssh-9", "event": "detection", "ttp": "T1110.001",
                      "resource_id": GONDOLIN, "timestamp": _iso(now - timedelta(seconds=60)),
                      "context": {"rule_name": "ssh-brute-force", "attribution": "asset"}},
           "confidence": 0.9, "action": "isolate_vm", "escalate": True,
           "outcome": {"status": "escalated", "executed": False, "escalation_type": "mode_hold"},
           "resolved_autonomy_mode": "human_only"}
    (tmp_path / "runs" / "watch-1_debug.jsonl").write_text(json.dumps(rec) + "\n")
    d = client.get(f"/api/dagorlad/requests/{rid}").json()
    assert d["written_here"] is True and d["phase"] == "running" and d["at"]
    [w] = d["wires"]
    assert (w["experiment"], w["target"], w["run"]) == ("T1110.001", GONDOLIN, "run-live")
    assert w["decision"]["action"] == "isolate_vm" and w["outcome"] == "held_by_guard"


def test_following_a_request_writes_nothing_and_tells_the_watch_nothing(client, tmp_path):
    """« Glorfindel reste aveugle » (§7): the follow is a read — no file changes, and the route is
    a GET. Every path the console and the watch write is under tmp (the conftest: runs/, the
    windows, ~/.glorfindel, the console's requests)."""
    import eregion_console.api as api
    from eregion_core import exercise_request as xr
    from eregion_core.exercise import exercises_dir
    rid = client.post("/api/dagorlad/requests",
                      json={"wires": [{"experiment": "T1110.001", "target": GONDOLIN}]}).json()["request"]
    _write_window(_window("run-live", start=datetime.now(timezone.utc) - timedelta(minutes=1), request=rid))
    roots = (tmp_path, xr.requests_dir(), exercises_dir())
    assert all(tmp_path in p.parents for p in roots[1:])
    before = _tree(*roots)
    for _ in range(2):
        assert client.get(f"/api/dagorlad/requests/{rid}").status_code == 200
    assert _tree(*roots) == before
    [route] = [r for r in api.app.routes if getattr(r, "path", "") == "/api/dagorlad/requests/{request_id}"]
    assert route.methods == {"GET"}


def test_a_request_file_holding_another_id_is_not_this_request(client):
    from eregion_core import exercise_request as xr
    rid = client.post("/api/dagorlad/requests",
                      json={"wires": [{"experiment": "T1110.001", "target": GONDOLIN}]}).json()["request"]
    other = "r-20261031T090000Z-123456"
    (xr.requests_dir() / f"{other}.json").write_text((xr.requests_dir() / f"{rid}.json").read_text())
    d = client.get(f"/api/dagorlad/requests/{other}").json()
    assert d["written_here"] is False and d["wires"] == []


def test_a_fault_whose_return_was_not_verified_says_it():
    win = _window("fault-1", kind="fault", experiment="vm-shutdown Arrêt", end=T + timedelta(minutes=6))
    rep = _report("fault-1", kind="fault", result="FAIL", fault_end=_iso(T + timedelta(minutes=5)),
                  checks={"revert_verified": "FAIL"})
    [w] = _follow(wires=[FAULT], windows=[win], reports={"fault-1": rep}, states={"fault-1": "grace"})["wires"]
    assert (w["returned"], w["restore_s"], w["verdict"]["result"]) == (False, None, "FAIL")


# ── The page: the life of a wire while it is followed (§7, « La vie d'un fil ») ─────────────

def _js() -> str:
    return (Path(__file__).resolve().parents[2] / "eregion_console" / "static" / "dagorlad.js").read_text()


def _body(js: str, head: str) -> str:
    start = js.index(head)
    return js[start:js.index("\n}\n", start) + 2] if head.startswith(("function", "async function")) \
        else js[start:js.index("\n  },\n", start)]


def test_the_wires_stay_locked_while_the_request_runs():
    """Requested, running: nothing on a wire — no ✕, no wire drawn, nothing cleared; only « Stop
    all » acts (Jonathan, 30/10)."""
    js = _js()
    assert "if (S.request || k < 0 || k >= S.wires.length) return;" in _body(js, "  unwire(k) {")
    assert "if (S.request) return;" in _body(js, "  clear() {")
    assert "if (S.request) S.note = `locked:" in _body(js, "function addWire(")
    assert "(S.request ? '' : `<button type=\"button\" class=\"px\" ${_on('click', 'unwire', k)}" in js
    assert "if (S.request) { box.innerHTML = followView(); return; }" in _body(js, "function renderPlan(")


def test_new_plan_drops_only_a_request_orodruin_has_not_heard_of():
    """Once Orodruin runs it, the console has no way to tell it to stop a wire: « New plan » is
    for a request not carried yet."""
    assert "if (!S.request || phaseOf() !== 'written') return;" in _body(_js(), "  newPlan() {")


def test_over_the_wires_unlock_each_keeping_its_last_result():
    js = _js()
    follow_ = _body(js, "async function refreshFollow(")
    assert "if (S.request && d.phase === 'over') {" in follow_
    assert "S.last = S.request; S.request = null;" in follow_
    # A request kept by the browser that is not over locks its wires again.
    assert "} else if (!S.request && d.phase !== 'over') {" in follow_
    assert "last: ${esc(r.text)}" in _body(js, "function planRow(")
    assert "const l = lineOf(w), r = l ? lineResult(l) : null" in _body(js, "function drawWires(")


def test_run_again_sends_the_same_wires_as_a_new_request():
    js = _js()
    assert "${again ? 'Run again' : 'Request run from Orodruin'}" in js
    assert "request() { if (!S.request) sendRequest(); }" in js
    # The page writes nothing else: the follow is a GET, the one POST is the request (DG-b).
    assert js.count("method: 'POST'") == 1
    assert "getJSON('/api/dagorlad/requests/' + encodeURIComponent(q.request))" in js


def test_a_request_kept_by_the_browser_is_read_against_its_shape():
    body = _body(_js(), "function storedRequest(")
    assert "REQ_ID.test(String(q.request))" in body and "return ok ? q : null;" in body


def test_a_blue_card_says_what_the_running_request_does_never_an_old_one():
    """Over, the target's card says what /api/state says of the VM, not what a past request did."""
    assert "const f = followOf(S.request);" in _body(_js(), "function followedOn(")


def test_an_id_of_its_shape_whose_date_no_calendar_holds_is_read_not_a_500(client):
    d = client.get("/api/dagorlad/requests/r-20261399T996099Z-abcdef")
    assert d.status_code == 200 and d.json()["phase"] == "written" and d.json()["wires"] == []
