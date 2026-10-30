"""Dagorlad, phase (b) in the console (DG-b, docs/design/console.md §7): « Request run » writes a
request for Orodruin — behind SEC1, judged by the shared core before it is written, in the
console's own directory only — and gives the command that carries it. The page never takes a name.

No Azure, no model: the bench's VMs are a list handed to the route, the watch's gate is stubbed,
the catalogue is the shipped one, the requests' directory is the conftest's tmp. Requires the
console extra.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import ORIGIN, TOKEN, console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_core import exercise_request as xr  # noqa: E402
from eregion_core import watch_gate  # noqa: E402

RG = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, SENTINEL, BREE = RG + "vm-celebrimbor-gondolin", RG + "vm-sentinel", RG + "vm-celebrimbor-bree"
BENCH_RG = {"eregion-target": "celebrimbor"}


def _vm(rid, tags):
    return {"resource_id": rid, "name": rid.rsplit("/", 1)[-1], "resource_group": "rg-celebrimbor",
            "rg_tags": dict(BENCH_RG), "tags": tags}


VMS = [_vm(GONDOLIN, {"eregion-target": "celebrimbor", "eregion-zone": "bench"}),
       _vm(SENTINEL, {"eregion-target": "celebrimbor", "eregion-zone": "production"}),
       _vm(BREE, {})]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,gothmog")
    monkeypatch.delenv("EREGION_BENCH", raising=False)
    monkeypatch.setattr(api, "READ_TARGETS", lambda subscription: VMS)
    api._targets_cache.update(at=0.0, value=None)
    monkeypatch.setattr(api, "_board_rules", lambda: [])
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None: "")
    return console()


def _requests() -> list[Path]:
    d = xr.requests_dir()
    return sorted(d.glob("*.json")) if d.exists() else []


def _post(client, *wires, **extra):
    body = {"wires": [{"experiment": e, "target": t} for e, t in wires], **extra}
    return client.post("/api/dagorlad/requests", json=body)


def test_a_request_is_judged_then_written_in_the_consoles_directory_only(client, tmp_path):
    r = _post(client, ("T1110.001", GONDOLIN), ("vm-shutdown", GONDOLIN), ("T1486", GONDOLIN))
    assert r.status_code == 200, r.text
    out = r.json()
    [path] = _requests()
    assert path.parent == tmp_path / "console-requests"           # the conftest's requests dir
    assert path.name == f"{out['request']}.json"
    doc = json.loads(path.read_text())
    assert set(doc) == {"id", "at", "wires"}
    assert [set(w) for w in doc["wires"]] == [{"experiment", "target", "rank"}] * 3
    assert [(w["experiment"], w["rank"]) for w in doc["wires"]] == [
        ("T1110.001", 1), ("vm-shutdown", 2), ("T1486", 3)]
    assert xr.load(path).id == out["request"]
    # Nothing under runs/ (where the watch reads), nor any expected result anywhere in it.
    assert not any((tmp_path / "runs").rglob("*"))
    assert "expected" not in path.read_text() and "zone" not in path.read_text()


def test_the_answer_gives_the_command_and_what_will_be_typed_there(client):
    out = _post(client, ("T1110.001", GONDOLIN), ("T1486", GONDOLIN)).json()
    assert re.fullmatch(r"make orodruin-exercise REQUEST=r-\d{8}T\d{6}Z-[0-9a-f]{6}", out["command"])
    assert [(w["experiment"], w["typed_name"]) for w in out["wires"]] == [("T1110.001", False), ("T1486", True)]
    assert out["wires"][1]["target_name"] == "vm-celebrimbor-gondolin"


@pytest.mark.parametrize("wire, code", [
    (("T1486", SENTINEL), "zone_forbids"),          # destructive, in production
    (("vm-shutdown", SENTINEL), "zone_forbids"),     # a fault, in production
    (("T1110.001", BREE), "not_enrolled"),           # the VM with a real load
    (("T9999", GONDOLIN), "unknown_experiment"),
])
def test_a_request_with_a_refused_wire_is_never_written(client, wire, code):
    r = _post(client, ("T1110.001", GONDOLIN), wire)
    assert r.status_code == 409
    assert code in {w["code"] for w in r.json()["plan"]["wires"]}
    assert _requests() == []


def test_no_live_watch_no_request(client, monkeypatch):
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None: "no heartbeat")
    r = _post(client, ("T1110.001", GONDOLIN))
    assert r.status_code == 409
    assert {w["code"] for w in r.json()["plan"]["wires"]} == {"no_watch"}
    assert _requests() == []


@pytest.mark.parametrize("body", [
    {"wires": [{"experiment": "T1486", "target": GONDOLIN, "typed_name": "vm-celebrimbor-gondolin"}]},
    {"wires": [{"experiment": "T1486", "target": GONDOLIN, "zone": "bench"}]},
    {"wires": [{"experiment": "T1486", "target": GONDOLIN, "destructive": False}]},
    {"wires": [{"experiment": "T1486", "target": GONDOLIN}], "typed": {"1": "vm-celebrimbor-gondolin"}},
    {"wires": [{"experiment": "T1486", "target": GONDOLIN}], "verdict": "ok"},
    {"wires": []},
    {"wires": [["T1486", GONDOLIN]]},
    {"wires": [{"experiment": "T1110.001", "target": GONDOLIN}] * 2},
])
def test_the_browser_sends_two_identifiers_per_wire_nothing_else(client, body):
    """Never a name typed, never a verdict, a zone or a destructiveness from the browser."""
    r = client.post("/api/dagorlad/requests", json=body)
    assert r.status_code == 400, r.text
    assert _requests() == []


def test_a_request_goes_through_the_consoles_boundary(client):
    """SEC1: the token, the origin, a JSON body."""
    body = {"wires": [{"experiment": "T1110.001", "target": GONDOLIN}]}
    assert console(token=None).post("/api/dagorlad/requests", json=body).status_code == 401
    other = client.post("/api/dagorlad/requests", json=body, headers={"Origin": "http://evil.example"})
    assert other.status_code == 403
    raw = client.post("/api/dagorlad/requests", content=json.dumps(body),
                      headers={"Content-Type": "text/plain"})
    assert raw.status_code == 415
    assert _requests() == []
    ok = client.post("/api/dagorlad/requests", json=body, headers={"Origin": ORIGIN})
    assert ok.status_code == 200 and len(_requests()) == 1
    assert TOKEN not in _requests()[0].read_text()


def test_an_unwritable_directory_is_said_never_a_request_claimed(client, tmp_path, monkeypatch):
    blocker = tmp_path / "blocked"
    blocker.write_text("a file where the directory should be")
    monkeypatch.setenv(xr.REQUESTS_ENV, str(blocker / "requests"))
    r = _post(client, ("T1110.001", GONDOLIN))
    assert r.status_code == 503 and "not written" in r.json()["error"]


def test_the_only_post_among_the_injectors_routes_is_the_request():
    posts = sorted(r.path for r in api.app.routes
                   if getattr(r, "path", "").startswith(("/api/dagorlad", "/dagorlad"))
                   and "POST" in (getattr(r, "methods", None) or set()))
    assert posts == ["/api/dagorlad/requests"]


def test_the_page_sends_two_identifiers_per_wire_and_takes_no_name():
    """The page shows what will be typed; it never collects it (§7: a name the console kept would
    prove nothing). Its request is the wires' two identifiers, nothing else."""
    static = Path(api.__file__).parent / "static"
    js = (static / "dagorlad.js").read_text(encoding="utf-8")
    html = (static / "dagorlad.html").read_text(encoding="utf-8")
    assert "<input" not in js and "<input" not in html and "<textarea" not in js + html
    assert "wires: S.wires.map(w => ({ experiment: w[0], target: w[1] }))" in js
    assert "fetch('/api/dagorlad/requests', { method: 'POST'" in js


# ── What Orodruin says (part 6): its verdict, the request's status — pulled by the watch ──────

def _plan_check(client) -> dict:
    r = client.get("/api/dagorlad/plan", params=[("wire", f"T1110.001@{GONDOLIN}")]).json()
    [check] = [c for c in r["checks"] if c["text"].startswith("Orodruin")]
    return check


def _contract(tmp_path, doc):
    d = tmp_path / "runs" / "orodruin"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(doc))


def test_without_orodruins_verdict_the_page_says_unknown_here(client):
    check = _plan_check(client)
    assert check["ok"] is None and check["text"].startswith("Orodruin: unknown here")


def test_orodruins_verdict_as_it_published_it(client, tmp_path):
    _contract(tmp_path, {"verdict": "armed", "codes": [], "at": "2026-10-30T08:00:00+00:00"})
    assert _plan_check(client)["ok"] is True
    _contract(tmp_path, {"verdict": "passive", "codes": ["network_open"], "at": "2026-10-30T08:00:00+00:00"})
    check = _plan_check(client)
    assert check["ok"] is False and "network_open" in check["text"]


@pytest.mark.parametrize("doc", [
    {"verdict": "armed", "codes": [], "at": "2026-10-30T08:00:00+00:00", "subscription": "0000"},
    {"verdict": "armed", "codes": ["network_open"], "at": "2026-10-30T08:00:00+00:00"},
    "armed",
])
def test_a_verdict_not_of_its_shape_is_unknown_here(client, tmp_path, doc):
    _contract(tmp_path, doc)
    assert _plan_check(client)["ok"] is None


def test_the_requests_status_is_what_orodruin_published(client, tmp_path):
    rid = _post(client, ("T1110.001", GONDOLIN)).json()["request"]
    first = client.get(f"/api/dagorlad/requests/{rid}").json()
    assert first["written_here"] is True and first["status"] is None
    d = tmp_path / "runs" / "orodruin" / "requests"
    d.mkdir(parents=True)
    status = {"request": rid, "state": "running", "at": "2026-10-30T08:00:00+00:00", "codes": [],
              "wires": [{"rank": 1, "state": "running", "code": "", "runs": [], "result": ""}]}
    (d / f"{rid}.json").write_text(json.dumps(status))
    assert client.get(f"/api/dagorlad/requests/{rid}").json()["status"] == status
    (d / f"{rid}.json").write_text(json.dumps({**status, "target": GONDOLIN}))
    assert client.get(f"/api/dagorlad/requests/{rid}").json()["status"] is None
    assert client.get("/api/dagorlad/requests/..%2Fx").status_code in (400, 404)
    assert client.get("/api/dagorlad/requests/r-1").status_code == 400


# ── « Stop all » (part 7): the command, what it stops, what stays in flight ───────────────────

def _window(run_id, *, start, end=None, expires, targets=(GONDOLIN,), **extra):
    from eregion_core.exercise import exercises_dir
    d = exercises_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "injector": "annatar", "kind": "technique", "experiment": "T1110.001 ssh",
        "targets": [t.lower() for t in targets], "start": start, "end": end, "expires": expires,
        "destructive": False, **extra}))


def test_stop_all_gives_the_kill_what_it_stops_and_what_stays_in_flight(client):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    iso = lambda d: (now + d).isoformat()  # noqa: E731
    _window("open-1", start=iso(timedelta(minutes=-5)), expires=iso(timedelta(hours=1)),
            request="r-20261030T080000Z-abcdef")
    _window("grace-1", start=iso(timedelta(minutes=-30)), end=iso(timedelta(minutes=-5)),
            expires=iso(timedelta(hours=1)))
    _window("old-1", start=iso(timedelta(days=-2)), end=iso(timedelta(days=-2, minutes=10)),
            expires=iso(timedelta(days=-1)))
    s = client.get("/api/dagorlad/stop").json()
    assert s["command"] == "make orodruin-kill"
    assert [(w["run_id"], w["targets"], w["request"]) for w in s["stops"]] == [
        ("open-1", ["vm-celebrimbor-gondolin"], "r-20261030T080000Z-abcdef")]
    assert [w["run_id"] for w in s["grace"]] == ["grace-1"]
    assert len(s["in_flight"]) == 3 and "revokes nothing" in s["never"]


def test_stop_all_is_a_read_the_console_revokes_nothing():
    [route] = [r for r in api.app.routes if getattr(r, "path", "") == "/api/dagorlad/stop"]
    assert route.methods == {"GET"}
    js = (Path(api.__file__).parent / "static" / "dagorlad.js").read_text(encoding="utf-8")
    assert "stopAll()" in js and "getJSON('/api/dagorlad/stop')" in js
