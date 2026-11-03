"""Dagorlad's drills in the console (DG-d, docs/design/console.md §7, « Les drills »): « Save as
drill » keeps the wires drawn under a name, by the names of their VMs — behind SEC1, in the
console's own directory only; the list; a drill laid again on the board, a shipped drill's wires
waiting for the VMs the operator gives — never one chosen in their place (Jonathan, 03/11); the
YAML export. Loading starts nothing.

No Azure, no model: the bench's VMs are a list handed to the route, the drills' directory is the
conftest's tmp. Requires the console extra.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import ORIGIN, TOKEN, console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_core import drill as dr  # noqa: E402
from eregion_core import exercise_request as xr  # noqa: E402
from eregion_core import watch_gate  # noqa: E402

RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, RIVENDELL, SENTINEL, BREE = (RG + "vm-celebrimbor-gondolin", RG + "vm-celebrimbor-rivendell",
                                       RG + "vm-sentinel", RG + "vm-celebrimbor-bree")
BENCH_RG = {"eregion-target": "celebrimbor"}


def _vm(rid, tags):
    return {"resource_id": rid, "name": rid.rsplit("/", 1)[-1], "resource_group": "rg-celebrimbor",
            "rg_tags": dict(BENCH_RG), "tags": tags}


VMS = [_vm(GONDOLIN, {"eregion-target": "celebrimbor", "eregion-zone": "bench"}),
       _vm(RIVENDELL, {"eregion-target": "celebrimbor", "eregion-zone": "bench"}),
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


def _kept() -> list[Path]:
    d = dr.instance_dir()
    return sorted(d.glob("*.yaml")) if d.exists() else []


def _save(client, name, *wires, **extra):
    body = {"name": name, "wires": [{"experiment": e, "target": t} for e, t in wires], **extra}
    return client.post("/api/dagorlad/drills", json=body)


# ── « Save as drill » ─────────────────────────────────────────────────────────────────

def test_save_as_drill_keeps_the_names_of_the_vms_in_the_consoles_directory_only(client, tmp_path):
    r = _save(client, "ssh-and-fault", ("T1110.001", GONDOLIN), ("vm-shutdown", GONDOLIN), description="the chain")
    assert r.status_code == 200, r.text
    [path] = _kept()
    assert path == tmp_path / "console-drills" / "ssh-and-fault.yaml"           # the conftest's tmp
    text = path.read_text()
    assert "subscriptions" not in text and "resourceGroups" not in text            # never a resource id
    d = dr.load_file(path, dr.INSTANCE)
    assert (d.author, d.description) == ("operator", "the chain") and d.updated
    assert [(w.experiment, w.name) for w in d.wires] == [("T1110.001", "vm-celebrimbor-gondolin"),
                                                         ("vm-shutdown", "vm-celebrimbor-gondolin")]
    # Nothing under runs/, where the watch reads; no request written: saving launches nothing.
    assert not any((tmp_path / "runs").rglob("*"))
    assert not (xr.requests_dir().exists() and any(xr.requests_dir().iterdir()))


def test_a_target_that_is_not_an_enrolled_vm_read_now_keeps_nothing(client):
    r = _save(client, "x", ("T1110.001", GONDOLIN), ("T1110.001", BREE))
    assert r.status_code == 409 and "not an enrolled VM" in r.json()["error"]
    assert _kept() == []


def test_a_drill_of_the_same_name_is_replaced_only_when_asked(client):
    assert _save(client, "ssh", ("T1110.001", GONDOLIN)).status_code == 200
    again = _save(client, "ssh", ("T1136.001", RIVENDELL))
    assert again.status_code == 409 and again.json()["exists"] is True
    assert dr.find("ssh").wires[0].experiment == "T1110.001"                       # untouched
    assert _save(client, "ssh", ("T1136.001", RIVENDELL), replace=True).status_code == 200
    assert [(w.experiment, w.name) for w in dr.find("ssh").wires] == [("T1136.001", "vm-celebrimbor-rivendell")]


@pytest.mark.parametrize("body", [
    {"wires": [{"experiment": "T1110.001", "target": GONDOLIN}]},                                  # no name
    {"name": "x", "wires": [{"experiment": "T1110.001", "target": GONDOLIN}], "author": "eregion"},
    {"name": "x", "wires": [{"experiment": "T1110.001", "target": GONDOLIN, "zone": "bench"}]},
    {"name": "x", "wires": []},
    {"name": "x", "wires": [{"experiment": "T1110.001", "target": GONDOLIN}], "replace": "yes"},
    {"name": "../x", "wires": [{"experiment": "T1110.001", "target": GONDOLIN}]},
])
def test_the_browser_sends_a_name_and_two_identifiers_per_wire_nothing_else(client, body):
    r = client.post("/api/dagorlad/drills", json=body)
    assert r.status_code == 400 and _kept() == []


def test_save_as_drill_goes_through_the_consoles_boundary(client):
    """SEC1: the token, the origin, a JSON body."""
    body = {"name": "ssh", "wires": [{"experiment": "T1110.001", "target": GONDOLIN}]}
    assert console(token=None).post("/api/dagorlad/drills", json=body).status_code == 401
    assert client.post("/api/dagorlad/drills", json=body, headers={"Origin": "http://evil.example"}).status_code == 403
    raw = client.post("/api/dagorlad/drills", content=json.dumps(body), headers={"Content-Type": "text/plain"})
    assert raw.status_code == 415
    assert _kept() == []
    ok = client.post("/api/dagorlad/drills", json=body, headers={"Origin": ORIGIN})
    assert ok.status_code == 200 and TOKEN not in _kept()[0].read_text()


# ── The list, the load, the export ─────────────────────────────────────────────────────

def test_the_list_holds_eregions_drills_and_this_instances(client):
    _save(client, "ssh-and-fault", ("T1110.001", GONDOLIN))
    listed = {d["name"]: d for d in client.get("/api/dagorlad/drills").json()["drills"]}
    assert listed["ssh-and-fault"]["layer"] == "instance" and listed["ssh-and-fault"]["author"] == "operator"
    assert listed["bl1-reponse"]["layer"] == "shipped" and listed["bl1-reponse"]["author"] == "eregion"
    assert listed["sentinelle"]["wires"] == [{"experiment": "T1136.001", "target": {"zone": "production"}}]


def test_an_instances_drill_lays_again_on_its_vms(client):
    _save(client, "ssh-and-fault", ("T1110.001", GONDOLIN), ("T1136.001", RIVENDELL))
    d = client.get("/api/dagorlad/drills/ssh-and-fault").json()
    assert d["layer"] == "instance"
    assert [(p["experiment"], [c["resource_id"] for c in p["targets"]]) for p in d["placed"]] == [
        ("T1110.001", [GONDOLIN]), ("T1136.001", [RIVENDELL])]


def test_a_shipped_drill_lays_its_wires_without_a_vm_with_their_candidates_and_a_hint(client, tmp_path):
    """Jonathan, 03/11: a selector's wire takes no VM by itself — its zone's candidates, and when
    each last ran the technique here (a hint, never a choice)."""
    (tmp_path / "runs" / "run-old.json").write_text(json.dumps({
        "scenario": "acct", "run_id": "run-old", "mitre": "T1136.001", "result": "PASS",
        "metrics": {"run_format": 1, "kind": "technique", "injector": "annatar", "experiment_id": "T1136.001",
                    "attack_time": 1_700_000_000.0, "detection": "detected", "resource_id": RIVENDELL}}))
    d = client.get("/api/dagorlad/drills/bl1-reponse").json()
    assert d["layer"] == "shipped"
    assert all(p["targets"] == [] and p["zone"] == "bench" and p["why"].startswith("to place") for p in d["placed"])
    cands = {c["name"]: c for c in d["placed"][1]["candidates"]}
    assert set(cands) == {"vm-celebrimbor-gondolin", "vm-celebrimbor-rivendell"}           # bree never enrolled
    assert cands["vm-celebrimbor-rivendell"]["last_run_at"] == 1_700_000_000.0
    assert cands["vm-celebrimbor-gondolin"]["last_run_at"] is None
    assert not any((tmp_path / "console-requests").glob("*")) if (tmp_path / "console-requests").exists() else True


def test_an_unknown_drill_is_said(client):
    assert client.get("/api/dagorlad/drills/nothing").status_code == 404
    assert client.get("/api/dagorlad/drills/..%2Fx").status_code in (400, 404)


def test_the_export_is_the_drills_yaml_read_back_whole(client):
    _save(client, "ssh-and-fault", ("T1110.001", GONDOLIN))
    r = client.get("/api/dagorlad/drills/ssh-and-fault/yaml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/yaml")
    assert 'filename="ssh-and-fault.yaml"' in r.headers["content-disposition"]
    assert dr.read(yaml.safe_load(r.text), dr.INSTANCE) == dr.find("ssh-and-fault")
    shipped = client.get("/api/dagorlad/drills/bl1-reponse/yaml")
    assert dr.read(yaml.safe_load(shipped.text), dr.SHIPPED).name == "bl1-reponse"


# ── The page ──────────────────────────────────────────────────────────────────────────

def test_the_page_lays_a_drill_and_never_writes_a_request_while_a_wire_waits():
    """A loaded drill's wire without its VMs: a button per candidate and « all », the request's
    button disabled until each has its VMs — the page never picks one."""
    js = (Path(api.__file__).parent / "static" / "dagorlad.js").read_text()
    assert "const may = Number(t.allowed) > 0 && Number(t.refused) === 0 && !S.pending.length;" in js
    assert "_on('click', 'place', p, j)" in js and "_on('click', 'placeAll', p)" in js
    assert "fetch('/api/dagorlad/drills', { method: 'POST'" in js
    assert "getJSON(`/api/dagorlad/drills/${encodeURIComponent(name)}`)" in js
    assert 'id="drills"' in (Path(api.__file__).parent / "static" / "dagorlad.html").read_text()
    # Loading lays wires, it writes no request: the only request is the button's.
    assert js.count("fetch('/api/dagorlad/requests'") == 1
