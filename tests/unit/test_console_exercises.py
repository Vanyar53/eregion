"""Annatar's and Gothmog's sections of the Eregion console: what they ran and what Glorfindel
made of it, read only (until 26/10, the atelier's routes).

No Azure, no LLM: the windows, campaigns and debug files are written to tmp, the return
channel's reads are stubbed. Requires the console extra.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import console  # noqa: E402

import eregion_console.api as api  # noqa: E402

VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a"
OTHER = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b"
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    """NOW is the clock when each test starts, not when this file was imported: a long suite
    (the CI's) no longer ages it past the windows and heartbeats the code under test compares
    with its own clock (SEC6, P-08)."""
    global NOW
    NOW = datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest.fixture()
def runs(tmp_path, monkeypatch):
    """A runs directory in tmp, the War Room's working directory."""
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    api._cycle_cache.clear()
    api._heartbeat_cache.update(at=0.0, value=None)
    d = tmp_path / "runs"
    (d / "exercises").mkdir(parents=True)
    return d


@pytest.fixture()
def client(runs):
    return console()


def _window(runs, run_id, *, injector="annatar", kind="technique", experiment="T1110.001 ssh",
            targets=(VM,), start, end=None, expires=None):
    w = {"run_id": run_id, "injector": injector, "kind": kind, "experiment": experiment,
         "targets": [t.lower() for t in targets], "start": _iso(start),
         "end": _iso(end) if end else None,
         "expires": _iso(expires or start + timedelta(hours=2))}
    (runs / "exercises" / f"{run_id}.json").write_text(json.dumps(w))
    return w


def _cycle(runs, name, *, at, resource_id=VM, ttp="T1110.001", action="block_suspicious_ip",
           executed=False, escalate=True, event="detection"):
    rec = {"timestamp": _iso(at + timedelta(seconds=20)),
           "signal": {"signal_id": f"rule-x-{name}", "event": event, "ttp": ttp,
                      "resource_id": resource_id, "timestamp": _iso(at),
                      "context": {"rule_name": "ssh-brute-force", "attribution": "asset",
                                  "run_id": name}},
           "past_cycles": [{"summary": "x" * 500}], "reasoning": "r", "confidence": 0.92,
           "action": action, "escalate": escalate, "escalation_reason": "",
           "outcome": {"status": "escalated" if escalate else "blocked", "executed": executed},
           "resolved_autonomy_mode": "human_only"}
    path = runs / f"{name}_debug.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


INJECTOR_ROUTES = ("/api/exercises", "/api/campaigns", "/api/catalog", "/api/channel",
                   "/api/atelier", "/atelier", "/annatar", "/gothmog", "/runs/", "/api/dagorlad", "/dagorlad")


def test_every_injector_route_is_a_read():
    """The console never launches: a run starts from Orodruin, armed — a button, later,
    goes through that contract, never through a console route (M403)."""
    routes = [r for r in api.app.routes if getattr(r, "path", "").startswith(INJECTOR_ROUTES)]
    assert len(routes) >= 11
    for r in routes:
        assert r.methods == {"GET"}, r.path


def test_the_page_is_served_behind_the_token(client, monkeypatch):
    page = client.get("/dagorlad?view=runs").text
    assert "injector.html" not in page  # the page itself, not a listing
    assert '<script src="/static/injector.js"></script>' in page        # its script, a file (#257)
    assert "INJECTOR" in client.get("/static/injector.js").text
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "s3cret")
    assert client.get("/api/exercises").status_code == 401
    assert client.get("/dagorlad?view=runs", headers={"accept": "application/json"}).status_code == 401


def test_catalog_lists_techniques_and_faults(client):
    entries = client.get("/api/catalog").json()["entries"]
    by_id = {e["id"]: e for e in entries}
    assert by_id["T1486"]["kind"] == "technique" and by_id["T1486"]["destructive"] is True
    assert by_id["vm-shutdown"]["kind"] == "fault"
    assert by_id["vm-shutdown"]["engine"] == "chaos-studio"
    assert by_id["T1136.001"]["engine"] == "atomic"
    assert any(e["status"] == "planned" for e in entries)


def test_a_window_carries_what_glorfindel_did_inside_it(runs, client):
    """A cycle counts for a window when its VM is a target and its signal falls between the
    window's start and its last moment — the return channel's rule (covering_runs)."""
    start = NOW - timedelta(minutes=10)
    _window(runs, "run-a", start=start, end=start + timedelta(minutes=2))
    _cycle(runs, "watch-ssh-1", at=start + timedelta(minutes=3))            # in grace
    _cycle(runs, "watch-ssh-2", at=start + timedelta(minutes=3), resource_id=OTHER)
    _cycle(runs, "watch-ssh-3", at=start - timedelta(minutes=5))            # before it
    from glorfindel import escalations
    escalations.record("rule-x-1", VM, "block_suspicious_ip", "mode_hold", "held",
                       source="exercise", exercise_run="run-a")
    escalations.record("rule-x-2", VM, "snapshot", "low_confidence", "real one")

    w = client.get("/api/exercises").json()["exercises"][0]
    assert w["run_id"] == "run-a" and w["state"] == "grace"
    assert w["experiment_id"] == "T1110.001"
    assert [c["signal_at"] for c in w["cycles"]] == [_iso(start + timedelta(minutes=3))]
    c = w["cycles"][0]
    assert (c["rule"], c["action"], c["mode"], c["executed"]) == \
        ("ssh-brute-force", "block_suspicious_ip", "human_only", False)
    assert "past_cycles" not in c                       # slimmed
    assert [k["action"] for k in w["cards"]] == ["block_suspicious_ip"]
    assert w["run"] is None                             # its report stayed on Orodruin


def test_window_states(runs, client):
    _window(runs, "open", start=NOW - timedelta(minutes=1))
    _window(runs, "grace", start=NOW - timedelta(minutes=10), end=NOW - timedelta(minutes=5))
    _window(runs, "closed", start=NOW - timedelta(hours=3), end=NOW - timedelta(hours=2))
    _window(runs, "lapsed", start=NOW - timedelta(hours=5), expires=NOW - timedelta(hours=3))
    killed = _window(runs, "killed", start=NOW - timedelta(hours=4), end=NOW - timedelta(hours=3))
    killed["closed_by"] = "orodruin-kill"         # M-1: the kill closes what was left open
    (runs / "exercises" / "killed.json").write_text(json.dumps(killed))
    ws = {w["run_id"]: w for w in client.get("/api/exercises").json()["exercises"]}
    assert {r: w["state"] for r, w in ws.items()} == \
        {"open": "open", "grace": "grace", "closed": "closed", "lapsed": "lapsed", "killed": "closed"}
    assert ws["killed"]["closed_by"] == "orodruin-kill" and ws["closed"]["closed_by"] is None


def test_since_bounds_the_windows_but_keeps_the_live_ones(runs, client):
    _window(runs, "old", start=NOW - timedelta(days=10), end=NOW - timedelta(days=10))
    _window(runs, "new", start=NOW - timedelta(hours=1), end=NOW - timedelta(minutes=50))
    ids = [w["run_id"] for w in client.get("/api/exercises?since=7d").json()["exercises"]]
    assert ids == ["new"]
    assert len(client.get("/api/exercises?since=all").json()["exercises"]) == 2
    assert "error" in client.get("/api/exercises?since=7x").json()


def test_a_run_report_is_found_beside_its_campaign(runs, client):
    """On H0 a run's report arrives with its campaign (#167), under runs/campaigns/<id>/runs/;
    a Gothmog report keeps its probes and its return."""
    start = NOW - timedelta(minutes=40)
    _window(runs, "run-c", start=start, end=start + timedelta(minutes=2))
    _window(runs, "gothmog-1", injector="gothmog", kind="fault",
            experiment="vm-shutdown VM shutdown", start=start, end=start + timedelta(minutes=8))
    (runs / "campaigns" / "camp1" / "runs").mkdir(parents=True)
    (runs / "campaigns" / "camp1" / "runs" / "run-c.json").write_text(json.dumps(
        {"scenario": "ssh", "run_id": "run-c", "mitre": "T1110.001", "result": "PASS",
         "metrics": {"attack_time": start.timestamp(), "detection": "detected",
                     "detection_latency_s": 84}, "thresholds": {}, "checks": {"attack": "PASS"}}))
    probes = [{"name": "vm-running", "ok": True, "observed": "PowerState/running",
               "expect": "PowerState/running"},
              {"name": "heartbeat", "ok": True, "observed": _iso(start), "expect": "fresh 10m"}]
    (runs / "gothmog-1.json").write_text(json.dumps(
        {"scenario": "VM shutdown", "run_id": "gothmog-1", "mitre": "", "result": "PASS",
         "metrics": {"injector": "gothmog", "time_to_restore_s": 133, "execution_id": "x",
                     "before": {"vm-a": probes}, "after": {"vm-a": probes}},
         "thresholds": {}, "checks": {"fault_effective": "PASS", "revert_verified": "PASS"}}))
    ws = {w["run_id"]: w for w in client.get("/api/exercises").json()["exercises"]}
    assert ws["run-c"]["run"]["metrics"]["detection"] == "detected"
    assert "before" not in ws["run-c"]["run"]["metrics"]
    g = ws["gothmog-1"]["run"]
    assert g["checks"]["revert_verified"] == "PASS"
    assert g["metrics"] == {"injector": "gothmog", "time_to_restore_s": 133,
                            "before": {"vm-a": probes}, "after": {"vm-a": probes}}


def test_a_fault_report_keeps_its_probes_only_in_their_shape(runs, client):
    """Before and after come from Orodruin and the pull checks neither (run_report_refusal):
    a probe out of shape is dropped, ``ok`` is true only when it says true."""
    start = NOW - timedelta(minutes=20)
    _window(runs, "gothmog-2", injector="gothmog", kind="fault",
            experiment="vm-shutdown VM shutdown", start=start, end=start + timedelta(minutes=8))
    (runs / "gothmog-2.json").write_text(json.dumps(
        {"scenario": "VM shutdown", "run_id": "gothmog-2", "mitre": "", "result": "FAIL",
         "metrics": {"injector": "gothmog",
                     "before": {"vm-a": [{"name": "heartbeat", "ok": "true", "observed": None,
                                          "expect": "fresh 10m"}, "not a probe"],
                                "vm-b": "not a list"},
                     "after": ["not", "an", "object"]},
         "thresholds": {}, "checks": {"revert_verified": "FAIL"}}))
    m = client.get("/api/exercises").json()["exercises"][0]["run"]["metrics"]
    assert m["before"] == {"vm-a": [{"name": "heartbeat", "ok": False, "observed": "",
                                     "expect": "fresh 10m"}]}
    assert m["after"] == {}


def _manifest(runs, cid, *, created, scenarios, state="done"):
    cdir = runs / "campaigns" / cid
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "manifest.json").write_text(json.dumps({
        "campaign_id": cid, "created_at": _iso(created), "created_by": "annatar-planner",
        "objective": "kill-chain", "state": state, "kill_switch": False,
        "scope": {"sandbox": "celebrimbor"},
        "budget": {"max_scenarios": 5, "allow_destructive": False, "max_cost_usd": 5.0},
        "scenarios": scenarios}))
    return cdir


def test_campaigns_list_and_detail(runs, client):
    """A campaign as Orodruin publishes it: its run's report and window are there, in the shape
    H0 accepts from another host (H-1, analysis/campaign_schema.py)."""
    attack = NOW - timedelta(hours=2)
    cdir = _manifest(runs, "c-new", created=attack - timedelta(minutes=1), scenarios=[
        {"seq": 1, "ttp": "T1136.001", "name": "Create Account", "status": "executed",
         "run_id": "r1", "detection": "detected", "detection_latency_s": 90,
         "target_resource_id": VM},
        {"seq": 2, "ttp": "T1486", "name": "Ransomware", "status": "skipped",
         "run_id": None, "detection": None, "destructive": True, "target_resource_id": VM}])
    (cdir / "runs").mkdir()
    (cdir / "runs" / "r1.json").write_text(json.dumps(
        {"scenario": "acct", "run_id": "r1", "mitre": "T1136.001", "result": "PASS",
         "metrics": {"attack_time": attack.timestamp(), "detection": "detected"},
         "thresholds": {}, "checks": {}}))
    _window(runs, "r1", start=attack, end=attack + timedelta(minutes=3))
    (cdir / ".pulled").write_text("")
    (cdir / "report.md").write_text("# Campagne c-new\n")
    _manifest(runs, "c-old", created=NOW - timedelta(days=40), scenarios=[])
    (runs / "campaigns" / "broken").mkdir()
    (runs / "campaigns" / "broken" / "manifest.json").write_text("{not json")

    camps = client.get("/api/campaigns?since=30d").json()["campaigns"]
    good = [c for c in camps if not c.get("error")]
    assert [c["campaign_id"] for c in good] == ["c-new"]
    assert good[0]["pulled"] is True and good[0]["report"] is True
    assert "max_cost_usd" not in good[0]["budget"]
    assert [s["seq"] for s in good[0]["scenarios"]] == [1, 2]
    assert any(c.get("error") == "manifest unreadable" for c in camps)

    detail = client.get("/api/campaigns/c-new").json()
    assert detail["report_md"].startswith("# Campagne")
    assert [f["seq"] for f in detail["facts"]] == [1, 2]
    assert detail["facts"][0]["detection"] == "detected"
    assert detail["skipped"] == []


def test_campaign_detail_says_what_it_left_out(runs, client):
    """The facts leave out what they cannot read safely — a run id that is not a plain name
    (it comes from another host) — and the console says so, as the report does."""
    _manifest(runs, "c-bad", created=NOW - timedelta(hours=1), scenarios=[
        {"seq": 1, "ttp": "T1110.001", "name": "ssh", "status": "executed", "run_id": "a/b",
         "detection": "detected", "target_resource_id": VM}])
    detail = client.get("/api/campaigns/c-bad").json()
    assert detail["facts"] == []
    assert len(detail["skipped"]) == 1 and "run_id" in detail["skipped"][0]


def test_the_console_never_writes_a_window(runs, client):
    """The watch pulls the windows and may purge an old one (H-1, load_windows): the War Room
    only reads — an old window stays as it is, a tombstone is skipped, odd targets ignored."""
    old = _window(runs, "old", start=NOW - timedelta(days=10), end=NOW - timedelta(days=10))
    (runs / "exercises" / "gone.json").write_text(json.dumps(
        {"run_id": "gone", "purged_at": _iso(NOW - timedelta(days=1))}))
    odd = dict(old, run_id="odd", targets="not-a-list")
    (runs / "exercises" / "odd.json").write_text(json.dumps(odd))
    before = {p.name: (p.read_text(), p.stat().st_mtime_ns) for p in (runs / "exercises").iterdir()}

    ws = {w["run_id"]: w for w in client.get("/api/exercises?since=all").json()["exercises"]}
    client.get("/api/channel")
    assert set(ws) == {"old", "odd"}
    assert ws["odd"]["targets"] == []
    after = {p.name: (p.read_text(), p.stat().st_mtime_ns) for p in (runs / "exercises").iterdir()}
    assert after == before


def test_campaign_detail_refuses_a_path(client):
    assert "plain name" in client.get("/api/campaigns/a..b").json()["error"]
    assert "unknown" in client.get("/api/campaigns/nope").json()["error"]


def test_channel_without_a_return_channel(runs, client):
    _window(runs, "live", start=NOW - timedelta(minutes=1))
    c = client.get("/api/channel").json()
    assert c["return_channel"] == {"configured": False}
    assert c["exercise_channel"]["configured"] is False
    assert c["exercise_channel"]["newest_window_at"]
    assert c["live_windows"] == ["live"]
    assert c["watch"]["status"] == "stopped"


def test_channel_reads_the_published_heartbeat(runs, client, monkeypatch):
    """The heartbeat a run on Orodruin reads — and the live windows it does not list yet: a run
    of such a window cannot conclude to a miss (watch_channel.miss_unprovable)."""
    from eregion_core import watch_channel
    monkeypatch.setenv("EREGION_WATCH_CHANNEL", "https://acct.blob.core.windows.net/watch")
    _window(runs, "known", start=NOW - timedelta(minutes=2))
    _window(runs, "unknown", start=NOW - timedelta(minutes=1))
    reads = []

    def _read():
        reads.append(1)
        # Read when the console reads it: 30 s old by its own clock, however long the suite.
        now = datetime.now(timezone.utc)
        return {"at": _iso(now - timedelta(seconds=30)), "since": _iso(now - timedelta(hours=1)),
                "windows": ["known"]}
    monkeypatch.setattr(watch_channel, "read_heartbeat", _read)
    rc = client.get("/api/channel").json()["return_channel"]
    assert rc["configured"] is True and rc["alive"] is True
    assert rc["unlisted_windows"] == ["unknown"]
    client.get("/api/channel")
    assert len(reads) == 1                              # cached, not read on every poll


def test_channel_unreadable_is_said_never_raised(runs, client, monkeypatch):
    from eregion_core import watch_channel
    monkeypatch.setenv("EREGION_WATCH_CHANNEL", "https://acct.blob.core.windows.net/watch")

    def _fail():
        raise RuntimeError("HTTP 403 reading the watch channel")
    monkeypatch.setattr(watch_channel, "read_heartbeat", _fail)
    rc = client.get("/api/channel").json()["return_channel"]
    assert "403" in rc["error"] and "alive" not in rc


def test_delivered_detections(runs, client, monkeypatch):
    from eregion_core import watch_channel
    assert client.get("/api/channel/detections/run-a").json() == \
        {"configured": False, "detections": []}
    monkeypatch.setenv("EREGION_WATCH_CHANNEL", "https://acct.blob.core.windows.net/watch")
    monkeypatch.setattr(watch_channel, "read_detections",
                        lambda rid: [{"signal_id": "s1", "exercise_run": rid}])
    assert client.get("/api/channel/detections/run-a").json()["detections"] == \
        [{"signal_id": "s1", "exercise_run": "run-a"}]

    def _unsafe(rid):
        raise ValueError(rid)
    monkeypatch.setattr(watch_channel, "read_detections", _unsafe)
    assert "plain name" in client.get("/api/channel/detections/x..y").json()["error"]


def test_the_war_room_reads_enrollment_as_the_watch_does(runs, monkeypatch):
    """H-1: without the check, no window marks anything — the atelier would attach no cycle and
    keep no run of a published campaign. The test suite enrolls every VM (conftest), so only
    this test sees the War Room's own startup."""
    from eregion_core import exercise
    from eregion_core.inscription import TagEnrollment
    monkeypatch.setattr(exercise, "_enrollment_check", None)
    with console():
        assert isinstance(exercise._enrollment_check, TagEnrollment)


def test_a_window_on_a_vm_not_enrolled_marks_nothing(runs, client, monkeypatch):
    from eregion_core import exercise
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: False)
    start = NOW - timedelta(minutes=10)
    _window(runs, "run-x", start=start, end=start + timedelta(minutes=2))
    _cycle(runs, "watch-ssh-x", at=start + timedelta(minutes=3))
    w = client.get("/api/exercises").json()["exercises"][0]
    assert w["cycles"] == [] and w["enrolled"] == {VM.lower(): False}


def test_a_window_not_believed_is_shown_with_why(runs, client):
    _window(runs, "too-long", start=NOW - timedelta(hours=1), expires=NOW + timedelta(hours=5))
    w = client.get("/api/exercises").json()["exercises"][0]
    assert w["run_id"] == "too-long" and "MAX_DURATION_S" in w["refusal"]
