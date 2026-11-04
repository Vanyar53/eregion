"""DG-e (#351): Annatar proposes drills in Dagorlad — « Ask Annatar for a drill » and « Import YAML »
(docs/design/console.md §7, decision 3 of 30/10; Jonathan's decision A of 04/11).

« Ask Annatar for a drill » lays Annatar's chain on the VM the operator chose: read only, the
catalogue and the target, never Glorfindel's rules nor its modes, the model never called.
« Import YAML » lays a drill's YAML — the one `annatar campaign plan` writes beside its campaign on
Orodruin — read by the drill's one exact reader, placed as « Load » places it, nothing written.
« Save as drill » keeps it as Annatar's. Then the end to end, on the fake: a campaign planned, its
drill imported, read, kept, and launched by the operator's command — `make orodruin-exercise
DRILL=` against a fake ssh and scp.

No Azure, no model: the bench's VMs are a list handed to the routes, the drills' and the
requests' directories the conftest's tmp. Requires the console extra.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import console  # noqa: E402
from .test_makefile_exercise import (  # noqa: E402,F401 — the fake hosts and the command, DG-b/DG-d's
    VMS as CMD_VMS, _drill_env, _make, _sent, _vms, fake_hosts, needs_make)

import eregion_console.api as api  # noqa: E402
from eregion_core import drill as dr  # noqa: E402
from eregion_core import exercise_request as xr  # noqa: E402
from eregion_core import proposal, watch_gate  # noqa: E402
from eregion_core.exercise_plan import load_catalog  # noqa: E402

RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
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
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None, **kw: "")
    return console()


def _written() -> list[Path]:
    """Every file under the console's drills and requests: what a read-only gesture never adds."""
    out = []
    for d in (dr.instance_dir(), xr.requests_dir()):
        out += sorted(p for p in d.rglob("*") if p.is_file()) if d.exists() else []
    return out


def _propose(client, target, **params):
    return client.get("/api/dagorlad/propose", params={"target": target, **params})


# ── « Ask Annatar for a drill » ─────────────────────────────────────────────────────────────

def test_annatar_proposes_its_chain_on_the_vm_chosen_and_writes_nothing(client):
    r = _propose(client, GONDOLIN)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["author"] == "annatar" and d["target"]["name"] == "vm-celebrimbor-gondolin"
    assert [w["experiment"] for w in d["wires"]] == proposal.chain(load_catalog())
    assert {w["target"] for w in d["wires"]} == {GONDOLIN}, "the VM given, never another"
    assert _written() == []


def test_a_proposal_holds_nothing_destructive_in_production_or_anywhere(client):
    catalog = load_catalog()
    for target in (GONDOLIN, SENTINEL):
        wires = _propose(client, target, wires=50).json()["wires"]
        assert wires and all(catalog[w["experiment"]].destructive is False for w in wires), target


@pytest.mark.parametrize("target", ["", BREE, RG + "vm-elsewhere", GONDOLIN.replace("rg-celebrimbor", "rg-other")])
def test_annatar_proposes_only_on_an_enrolled_vm_read_now(client, target):
    r = _propose(client, target)
    assert r.status_code == 404 and "enrolled VM" in r.json()["error"]


def test_without_annatar_set_up_here_nothing_is_proposed(client, monkeypatch):
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "gothmog")
    r = _propose(client, GONDOLIN)
    assert r.status_code == 409 and "Annatar is not set up here" in r.json()["error"]


def test_the_proposal_is_blind_to_glorfindels_rules_and_modes(client, monkeypatch):
    """Decision 3: the catalogue and the target — never Glorfindel's rules nor its modes."""
    def never(*a, **k):
        raise AssertionError("the proposal read Glorfindel")
    monkeypatch.setattr(api, "_board_rules", never)
    monkeypatch.setattr(api, "state", never)
    monkeypatch.setattr(api, "_load_config", never, raising=False)
    assert _propose(client, GONDOLIN).status_code == 200


# ── « Import YAML » ─────────────────────────────────────────────────────────────────────────

def _campaign_yaml(*pairs, cid="20261104T101500Z") -> str:
    return dr.to_yaml(proposal.campaign_drill(cid, list(pairs) or [("T1136.001", "vm-celebrimbor-gondolin")]))


def _import(client, text):
    return client.post("/api/dagorlad/drills/import", json={"yaml": text})


def test_a_campaigns_drill_is_imported_placed_and_nothing_is_written(client):
    r = _import(client, _campaign_yaml(("vm-shutdown", "vm-celebrimbor-gondolin"), ("T1136.001", "vm-celebrimbor-gondolin")))
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["name"], d["author"], d["layer"]) == ("annatar-20261104t101500z", "annatar", "import")
    assert [(p["experiment"], [c["resource_id"] for c in p["targets"]]) for p in d["placed"]] == [
        ("vm-shutdown", [GONDOLIN]), ("T1136.001", [GONDOLIN])]
    assert _written() == []


def test_an_imported_name_not_enrolled_here_waits_never_placed_on_another(client):
    d = _import(client, _campaign_yaml(("T1136.001", "vm-elsewhere"))).json()
    [p] = d["placed"]
    assert p["targets"] == [] and "not an enrolled VM" in p["why"]


@pytest.mark.parametrize("body, said", [
    ({"yaml": "name: [unclosed"}, "not YAML"),
    ({"yaml": "[" * 500 + "]" * 500}, "not YAML"),          # nested past the parser's depth: never a 500
    ({"yaml": (Path(dr.shipped_dir()) / "bl1-reponse.yaml").read_text()}, "never Eregion's"),
    ({"yaml": "name: x\nauthor: operator\nupdated: '2026-11-04T10:00:00+00:00'\nwires:\n"
              "  - experiment: T1136.001\n    target: {resource_id: /subscriptions/x}\n"}, "target is exactly"),
    ({"yaml": "a: 1", "replace": True}, "nothing else"),
    ({"yaml": 3}, "nothing else"),
])
def test_an_import_the_drills_reader_refuses_lays_nothing(client, body, said):
    r = client.post("/api/dagorlad/drills/import", json=body)
    assert r.status_code == 400 and said in r.json()["error"], r.text
    assert _written() == []


def test_an_import_past_a_drills_size_is_refused(client, monkeypatch):
    """SEC1 refuses it first: a body past _MAX_BODY (64 KB) is a 413 before any route. The route's
    own bound stays, in depth — reached here with the boundary's raised."""
    assert _import(client, "#" * (dr.MAX_BYTES + 1)).status_code == 413 and _written() == []
    monkeypatch.setattr(api, "_MAX_BODY", 4 * dr.MAX_BYTES)
    r = _import(client, "#" * (dr.MAX_BYTES + 1))
    assert r.status_code == 400 and "larger than a drill's" in r.json()["error"] and _written() == []


# ── « Save as drill »: kept as Annatar's ────────────────────────────────────────────────────

def _save(client, name, *wires, **extra):
    return client.post("/api/dagorlad/drills", json={"name": name, "wires": [
        {"experiment": e, "target": t} for e, t in wires], **extra})


def test_a_proposal_kept_is_annatars(client):
    assert _save(client, "annatar-ssh", ("T1136.001", GONDOLIN), author="annatar").status_code == 200
    assert dr.find("annatar-ssh").author == "annatar"
    assert _save(client, "mine", ("T1136.001", GONDOLIN)).status_code == 200
    assert dr.find("mine").author == "operator"


@pytest.mark.parametrize("author", ["eregion", "glorfindel", "", 1])
def test_a_drill_kept_here_is_never_eregions_nor_anothers(client, author):
    r = _save(client, "x", ("T1136.001", GONDOLIN), author=author)
    assert r.status_code == 400 and "author" in r.json()["error"] and _written() == []


# ── The page ────────────────────────────────────────────────────────────────────────────────

JS = (Path(api.__file__).parent / "static" / "dagorlad.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    i = JS.index(f"function {name}(")
    return JS[i:JS.index("\n}\n", i)]


def test_the_page_asks_annatar_on_the_vm_the_operator_chose_and_lays_a_draft():
    form = _fn("askForm")
    assert "_on('click', 'askAnnatar', j)" in form, "one button per enrolled VM: the operator's choice"
    ask = _fn("askAnnatar")
    assert "/api/dagorlad/propose?target=${encodeURIComponent(t.resource_id)}" in ask
    assert "S.author = 'annatar'" in ask and "method: 'POST'" not in ask, "read only"
    actions = JS[JS.index("const ACTIONS = {"):JS.index("\n};", JS.index("const ACTIONS = {"))]
    assert "S.asking.ask !== t.resource_id" in actions, "over the wires drawn, only once asked"


def test_the_page_imports_through_the_one_reader_and_keeps_only_by_save():
    imp = _fn("importYaml")
    assert "fetch('/api/dagorlad/drills/import', { method: 'POST'" in imp
    assert "body: JSON.stringify({ yaml: text })" in imp and "layDrill(d, " in imp
    assert "(S.wires.length || S.pending.length) && !f.ask" in imp, "over the wires drawn, only once asked"
    assert "if (S.author === 'annatar') body.author = 'annatar';" in _fn("saveDrill")
    assert "S.author = AUTHORS.includes(d.author) ? d.author : 'operator';" in _fn("layDrill")
    assert "const AUTHORS = ['operator', 'annatar'];" in JS
    assert re.search(r"S\.wires = \[\]; S\.picked = null;[^\n]*\n\s*S\.author = 'operator';", JS), "a cleared board is the operator's"
    unwire = JS[JS.index("  unwire(k) {"):JS.index("  clear() {")]
    assert "if (!S.wires.length && !S.pending.length) S.author = 'operator';" in unwire, "its last wire removed too"
    # « Save as drill » offers again the description of the drill loaded or imported.
    assert "desc: own ? S.loadedDesc : ''" in JS and "S.loadedDesc = String(d.description || '');" in _fn("layDrill")


# ── The end to end, on the fake: proposed as a drill, read, kept, launched by the operator ──────

@needs_make
def test_a_campaign_proposed_as_a_drill_is_read_kept_and_launched_by_the_operator(client, fake_hosts, tmp_path):  # noqa: F811
    """« Fini quand » of #351: `annatar campaign plan --declared` (BL1's, on gondolin) writes its
    drill on Orodruin; the operator imports it in Dagorlad (read, placed, nothing written), keeps it
    (« Save as drill »: Annatar's), and launches it by the command — its request carried to the fake
    Orodruin, the campaign's chain on gondolin, in its order."""
    from annatar.campaign import declared
    from annatar.cli import cli
    oro_runs = tmp_path / "orodruin-runs"
    res = CliRunner().invoke(cli, ["campaign", "plan", "--target", GONDOLIN, "--runs-dir", str(oro_runs),
                                   "--declared", str(declared.DECLARED_DIR / "bl1-reponse.yaml")])
    assert res.exit_code == 0, res.output
    [path] = list(oro_runs.glob("campaigns/*/annatar-*.yaml"))

    placed = _import(client, path.read_text(encoding="utf-8")).json()
    wires = [(p["experiment"], c["resource_id"]) for p in placed["placed"] for c in p["targets"]]
    assert wires == [("vm-shutdown", GONDOLIN), ("T1136.001", GONDOLIN)] and _written() == []
    name = placed["name"]
    r = _save(client, name, *wires, author="annatar")
    assert r.status_code == 200, r.text
    kept = dr.instance_dir() / f"{name}.yaml"
    assert yaml.safe_load(kept.read_text())["author"] == "annatar"

    bindir, h0, oro, calls = fake_hosts
    (h0 / "drills").mkdir()
    shutil.copy(kept, h0 / "drills" / kept.name)            # H0's console holds it
    out = _make(fake_hosts, f"DRILL={name}", _vms(tmp_path), stdin="y\n", env_extra=_drill_env(tmp_path))
    assert out.returncode == 0, out.stdout + out.stderr
    gondolin = next(v["resource_id"] for v in CMD_VMS if v["name"] == "vm-celebrimbor-gondolin")
    sent = _sent(oro)
    assert [(w["experiment"], w["target"]) for w in sent["wires"]] == [("vm-shutdown", gondolin), ("T1136.001", gondolin)]
    assert f"drill {name} (instance, 2 wire(s))" in out.stderr
    assert xr.read(sent).id == sent["id"]
