"""Dagorlad's drills (DG-d, eregion_core/drill.py): the format and its one reader, the layers
(Eregion's shipped drills, the instance's), the save, the placing of a drill's wires on targets —
never one chosen in the operator's place (Jonathan, 03/11) — and a drill made a request, judged,
then played again on Orodruin's fake.

No Azure, no model: the bench's VMs are a listing written here. The oracles are written here.
"""
from __future__ import annotations

import json
import os
import stat

import pytest
import yaml

from eregion_core import drill as dr
from eregion_core import exercise_request as xr
from eregion_core.exercise_plan import load_catalog

from .test_exercise_runner import GONDOLIN, SENTINEL, T0, _runner

SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
BENCH_RG = {"eregion-target": "celebrimbor"}


def _vm(name: str, zone: str | None = "bench", enrolled: bool = True) -> dict:
    tags = {"eregion-target": "celebrimbor", "eregion-zone": zone} if enrolled else {}
    if enrolled and zone is None:
        tags.pop("eregion-zone")
    return {"name": name, "resource_id": RG + name, "tags": tags, "rg_tags": BENCH_RG}


VMS = [_vm("vm-celebrimbor-gondolin"), _vm("vm-celebrimbor-rivendell"), _vm("vm-sentinel", "production"),
       _vm("vm-celebrimbor-bree", enrolled=False)]


@pytest.fixture(autouse=True)
def _bench(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EREGION_BENCH", "celebrimbor")


def _doc(layer=dr.INSTANCE, **over) -> dict:
    doc = ({"name": "ssh-and-fault", "author": "operator", "updated": "2026-11-03T10:12:00+00:00",
            "wires": [{"experiment": "T1110.001", "target": {"name": "vm-celebrimbor-gondolin"}},
                      {"experiment": "vm-shutdown", "target": {"name": "vm-celebrimbor-gondolin"}}]}
           if layer == dr.INSTANCE else
           {"name": "ssh", "author": "eregion",
            "wires": [{"experiment": "T1136.001", "target": {"zone": "bench"}}]})
    doc.update(over)
    return doc


# ── The one reader ──────────────────────────────────────────────────────────────────────

def test_a_drill_reads_whole_and_writes_back_as_it_was_read():
    d = dr.read(_doc(), dr.INSTANCE)
    assert (d.name, d.author, d.layer) == ("ssh-and-fault", "operator", dr.INSTANCE)
    assert [(w.experiment, w.name) for w in d.wires] == [("T1110.001", "vm-celebrimbor-gondolin"),
                                                         ("vm-shutdown", "vm-celebrimbor-gondolin")]
    assert dr.read(yaml.safe_load(dr.to_yaml(d)), dr.INSTANCE) == d          # the export, read back


@pytest.mark.parametrize("layer, over, said", [
    (dr.INSTANCE, {"extra": 1}, "a field it never holds"),
    (dr.INSTANCE, {"name": "../x"}, "its name is not"),
    (dr.INSTANCE, {"name": "SSH"}, "its name is not"),
    (dr.INSTANCE, {"author": "mallory"}, "its author is not one of"),
    (dr.INSTANCE, {"author": "eregion"}, "never Eregion's"),
    (dr.SHIPPED, {"author": "operator"}, "a shipped drill is Eregion's"),
    (dr.INSTANCE, {"updated": "yesterday"}, "not an ISO time"),
    (dr.INSTANCE, {"updated": "2026-11-03T10:12:00"}, "not an ISO time"),
    (dr.INSTANCE, {"description": "two\nlines"}, "one line"),
    (dr.INSTANCE, {"wires": []}, "1 to"),
    # Never a resource id: it changes when Celebrimbor rebuilds the bench.
    (dr.INSTANCE, {"wires": [{"experiment": "T1110.001", "target": {"name": RG + "vm-a"}}]}, "not a VM's name"),
    # A shipped drill aims by selector, an instance's by name.
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001", "target": {"name": "vm-a"}}]}, "never names a VM"),
    (dr.INSTANCE, {"wires": [{"experiment": "T1110.001", "target": {"zone": "bench"}}]}, "never a selector"),
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001", "target": {"zone": "staging"}}]}, "its zone is not"),
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001", "target": {"zone": "bench", "name": "x"}}]}, "exactly"),
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001", "target": {"zone": "bench"}, "rank": 1}]}, "never holds"),
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001; id", "target": {"zone": "bench"}}]}, "catalogue id"),
    (dr.SHIPPED, {"wires": [{"experiment": "T1110.001", "target": {"zone": "bench"}}] * 2}, "the same pair twice"),
])
def test_the_one_reader_refuses_what_a_drill_never_holds(layer, over, said):
    with pytest.raises(dr.DrillRefused, match=said):
        dr.read(_doc(layer, **over), layer)


def test_a_file_names_its_drill_and_is_read_bounded_never_through_a_link(tmp_path):
    (tmp_path / "other.yaml").write_text(yaml.safe_dump(_doc()))
    with pytest.raises(dr.DrillRefused, match="a drill's file is <its name>.yaml"):
        dr.load_file(tmp_path / "other.yaml", dr.INSTANCE)
    (tmp_path / "big.yaml").write_text("#" * (dr.MAX_BYTES + 1))
    with pytest.raises(dr.DrillRefused, match="larger than"):
        dr.load_file(tmp_path / "big.yaml", dr.INSTANCE)
    (tmp_path / "elsewhere.yaml").write_text(yaml.safe_dump(_doc(name="linked")))
    (tmp_path / "linked.yaml").symlink_to(tmp_path / "elsewhere.yaml")
    with pytest.raises(dr.DrillRefused, match="unreadable"):
        dr.load_file(tmp_path / "linked.yaml", dr.INSTANCE)
    os.mkfifo(tmp_path / "pipe.yaml")
    with pytest.raises(dr.DrillRefused, match="not a regular file"):
        dr.load_file(tmp_path / "pipe.yaml", dr.INSTANCE)


# ── The layers ──────────────────────────────────────────────────────────────────────────

def test_the_shipped_drills_are_eregions_by_selector_and_each_wire_may_run_in_its_zone():
    """drills/ (the repository): every drill reads as a shipped one, names only experiments the
    catalogue implements — a public engine (BL1b: a declared exercise plays nothing home-grown) —
    and none the production rule forbids in its zone."""
    from eregion_core.inscription import check_zone
    catalog = load_catalog()
    shipped = sorted(dr.shipped_dir().glob("*.yaml"))
    assert {p.stem for p in shipped} >= {"bl1-reponse", "sentinelle"}
    for path in shipped:
        d = dr.load_file(path, dr.SHIPPED)
        for w in d.wires:
            e = catalog[w.experiment]
            assert e.status == "implemented" and e.engine in ("atomic", "chaos-studio"), (d.name, e.id)
            assert w.zone and check_zone(w.zone, kind=e.kind, destructive=e.destructive).allowed, (d.name, e.id)


def test_the_instance_lists_over_the_shipped_drills_and_says_what_it_replaces(tmp_path):
    shipped, own = tmp_path / "shipped", tmp_path / "own"
    shipped.mkdir()
    own.mkdir()
    (shipped / "ssh.yaml").write_text(yaml.safe_dump(_doc(dr.SHIPPED)))
    (shipped / "broken.yaml").write_text("name: [")
    (own / "ssh.yaml").write_text(yaml.safe_dump(_doc(name="ssh")))
    (own / "ssh-and-fault.yaml").write_text(yaml.safe_dump(_doc()))
    listed = {d["name"]: d for d in dr.listing(shipped, own)}
    assert listed["ssh"]["layer"] == dr.INSTANCE and listed["ssh"]["replaces"] == dr.SHIPPED
    assert listed["ssh-and-fault"]["layer"] == dr.INSTANCE and not listed["ssh-and-fault"]["replaces"]
    assert listed["broken"]["error"] and listed["broken"]["layer"] == dr.SHIPPED   # said, never left out
    assert dr.find("ssh", shipped, own).layer == dr.INSTANCE
    (own / "ssh.yaml").write_text("{not: [yaml")
    with pytest.raises(dr.DrillRefused):        # the instance's, unreadable: never the shipped one in its place
        dr.find("ssh", shipped, own)
    with pytest.raises(dr.DrillRefused, match="no drill"):
        dr.find("nothing", shipped, own)


def test_the_instance_lives_in_the_consoles_own_directory_never_where_the_watch_reads(tmp_path, monkeypatch):
    monkeypatch.delenv(dr.DRILLS_ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    where = dr.instance_dir()
    assert where == tmp_path / ".eregion" / "console" / "drills"
    assert "runs" not in where.parts and ".glorfindel" not in where.parts


def test_a_drill_is_saved_whole_never_over_another_unless_replaced(tmp_path):
    d = dr.new("ssh-and-fault", [("T1110.001", "vm-celebrimbor-gondolin")], description="the chain")
    path = dr.save(d, tmp_path / "drills")
    assert dr.load_file(path, dr.INSTANCE) == d
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    other = dr.new("ssh-and-fault", [("T1136.001", "vm-celebrimbor-gondolin")])
    with pytest.raises(dr.DrillRefused, match="exists already"):
        dr.save(other, tmp_path / "drills")
    assert dr.load_file(path, dr.INSTANCE) == d                     # untouched
    dr.save(other, tmp_path / "drills", replace=True)
    assert dr.load_file(path, dr.INSTANCE) == other
    assert sorted(p.name for p in (tmp_path / "drills").iterdir()) == ["ssh-and-fault.yaml"]   # no tmp left
    with pytest.raises(dr.DrillRefused, match="only an instance's drill"):
        dr.save(dr.read(_doc(dr.SHIPPED), dr.SHIPPED), tmp_path / "drills")


# ── Placing a drill (Jonathan, 03/11): never a VM chosen in the operator's place ──────────

def test_a_named_wire_takes_its_vm_when_it_is_enrolled_here():
    cands = dr.candidates(VMS)
    assert [(c.name, c.zone) for c in cands] == [("vm-celebrimbor-gondolin", "bench"),
                                                ("vm-celebrimbor-rivendell", "bench"), ("vm-sentinel", "production")]
    d = dr.new("x", [("T1110.001", "VM-CELEBRIMBOR-GONDOLIN"), ("T1136.001", "vm-celebrimbor-bree")])
    placed = dr.place(d, cands)
    assert [c.name for c in placed[0].targets] == ["vm-celebrimbor-gondolin"] and not placed[0].why
    assert placed[1].targets == [] and "not an enrolled VM" in placed[1].why       # bree: never enrolled


def test_a_selectors_wire_takes_no_vm_until_the_operator_gives_them():
    d = dr.read({"name": "s", "author": "eregion", "wires": [
        {"experiment": "T1136.001", "target": {"zone": "bench"}},
        {"experiment": "T1136.001", "target": {"zone": "production"}}]}, dr.SHIPPED)
    cands = dr.candidates(VMS)
    nothing = dr.place(d, cands)
    assert [p.targets for p in nothing] == [[], []]
    assert [[c.name for c in p.candidates] for p in nothing] == [
        ["vm-celebrimbor-gondolin", "vm-celebrimbor-rivendell"], ["vm-sentinel"]]
    assert nothing[0].why == "to place: zone bench, 2 candidate(s)"
    every = dr.place(d, cands, "all")
    assert dr.pairs(every) == [("T1136.001", RG + "vm-celebrimbor-gondolin"),
                               ("T1136.001", RG + "vm-celebrimbor-rivendell"), ("T1136.001", RG + "vm-sentinel")]
    # Each wire takes the VMs of its zone among those given.
    given = dr.place(d, cands, ["vm-celebrimbor-rivendell", "vm-sentinel"])
    assert dr.pairs(given) == [("T1136.001", RG + "vm-celebrimbor-rivendell"), ("T1136.001", RG + "vm-sentinel")]
    assert dr.unknown_targets(given, ["vm-celebrimbor-rivendell", "vm-sentinel"]) == []
    assert dr.unknown_targets(given, ["vm-celebrimbor-bree"]) == ["vm-celebrimbor-bree"]


# Review (03/11): a twin copied from a bench keeps its names — vm-celebrimbor-gondolin twice.
TWIN_RG = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor-twin/providers/Microsoft.Compute/virtualMachines/"
TWINNED = [*VMS, {"name": "vm-celebrimbor-gondolin", "resource_id": TWIN_RG + "vm-celebrimbor-gondolin",
                  "tags": {"eregion-target": "celebrimbor", "eregion-zone": "twin"}, "rg_tags": BENCH_RG}]


def test_a_name_that_several_enrolled_vms_bear_takes_none_never_one_unsaid():
    d = dr.new("x", [("T1110.001", "vm-celebrimbor-gondolin"), ("T1136.001", "vm-celebrimbor-rivendell")])
    placed = dr.place(d, dr.candidates(TWINNED))
    assert placed[0].targets == [] and placed[0].why == "vm-celebrimbor-gondolin names 2 enrolled VMs here"
    assert {c.resource_id for c in placed[0].candidates} == {RG + "vm-celebrimbor-gondolin",
                                                             TWIN_RG + "vm-celebrimbor-gondolin"}
    assert [c.resource_id for c in placed[1].targets] == [RG + "vm-celebrimbor-rivendell"]   # one bearer: taken
    with pytest.raises(dr.DrillRefused) as refused:
        dr.request_from(d, TWINNED, None, catalog=load_catalog())
    said = str(refused.value)
    assert "names 2 enrolled VMs here" in said and "group rg-celebrimbor-twin, zone twin" in said
    assert "group rg-celebrimbor, zone bench" in said
    # The board chooses among them, the drill loaded (CON-K): saved again, it would name the VM
    # the same way, as ambiguous as before.
    assert said.endswith("vm-celebrimbor-gondolin (group rg-celebrimbor-twin, zone twin): "
                         "load it on the board and choose the VM there"), said


def test_a_layer_past_its_bound_says_how_many_are_not_listed(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "MAX_DRILLS", 2)
    own = tmp_path / "own"
    own.mkdir()
    for k in range(3):
        (own / f"d{k}.yaml").write_text(yaml.safe_dump(_doc(name=f"d{k}")))
    listed = dr.listing(tmp_path / "none", own)
    assert sorted(d["name"] for d in listed if not d["error"]) == ["d0", "d1"]
    [cut] = [d for d in listed if d["error"]]
    assert cut["layer"] == dr.INSTANCE and cut["error"].startswith("1 more drill(s) in this layer")


@pytest.mark.parametrize("value, parsed", [("", None), ("  ", None), ("all", "all"),
                                           ("vm-a, vm-b", ["vm-a", "vm-b"])])
def test_targets_is_nothing_all_or_names(value, parsed):
    assert dr.parse_targets(value) == parsed


@pytest.mark.parametrize("value", ["vm-a;id", "$(id)", RG + "vm-a", "../x"])
def test_targets_never_takes_anything_but_names(value):
    with pytest.raises(dr.DrillRefused, match="not a VM's name"):
        dr.parse_targets(value)


# ── A drill made a request, judged, then played again on Orodruin's fake ─────────────────

def _shipped(*wires) -> dr.Drill:
    return dr.read({"name": "s", "author": "eregion",
                    "wires": [{"experiment": e, "target": {"zone": z}} for e, z in wires]}, dr.SHIPPED)


def test_a_shipped_drill_without_its_vms_is_refused_with_its_candidates():
    with pytest.raises(dr.DrillRefused) as refused:
        dr.request_from(_shipped(("T1136.001", "bench")), VMS, None, catalog=load_catalog())
    said = str(refused.value)
    assert "choose: vm-celebrimbor-gondolin | vm-celebrimbor-rivendell" in said and "TARGETS=all" in said


def test_a_target_given_that_no_wire_can_take_is_refused():
    with pytest.raises(dr.DrillRefused, match="the candidate of no wire"):
        dr.request_from(_shipped(("T1136.001", "bench")), VMS, ["vm-sentinel"], catalog=load_catalog())


def test_a_wire_the_plan_refuses_refuses_the_drill_nothing_sent():
    """The same verdict as a wire drawn (exercise_plan): a fault in production is refused."""
    with pytest.raises(dr.DrillRefused, match="zone_forbids"):
        dr.request_from(_shipped(("vm-shutdown", "production")), VMS, "all", catalog=load_catalog())


def test_a_drill_kept_reloaded_judged_and_played_again_on_orodruins_fake(tmp_path):
    """« Fini quand »: a drill saved, read back from its file, made a request on the VMs read now,
    judged as Orodruin judges, then played by Orodruin's runner on its fake — twice, each play
    a new request."""
    d = dr.new("ssh-and-fault", [("T1110.001", "vm-celebrimbor-gondolin")])
    kept = dr.load_file(dr.save(d, tmp_path / "drills"), dr.INSTANCE)
    vms = [{"name": "vm-celebrimbor-gondolin", "resource_id": GONDOLIN, "rg_tags": BENCH_RG,
            "tags": {"eregion-target": "celebrimbor", "eregion-zone": "bench"}},
           {"name": "vm-sentinel", "resource_id": SENTINEL, "rg_tags": BENCH_RG,
            "tags": {"eregion-target": "celebrimbor", "eregion-zone": "production"}}]
    plays = []
    for k in range(2):
        req = dr.request_from(kept, vms, None, catalog=load_catalog(), now=T0)
        assert [(w.experiment, w.target) for w in req.wires] == [("T1110.001", GONDOLIN)]
        r, inj, _, _ = _runner(tmp_path / f"play-{k}")
        status = r.run(req, {})
        assert status.state == "finished" and [w.state for w in status.wires] == ["done"]
        assert inj.launched[0][0][-2:] == ["--request", req.id]
        plays.append(req.id)
    assert plays[0] != plays[1]


def test_the_command_writes_the_request_and_prints_its_id(tmp_path, capsys):
    """The VMs from a listing given on the command line only (``--vms``: the tests, a machine
    without Azure access), said — never an environment variable."""
    (tmp_path / "vms.json").write_text(json.dumps(VMS))
    vms = ["--vms", str(tmp_path / "vms.json")]
    (tmp_path / "s.yaml").write_text(yaml.safe_dump(_doc(dr.SHIPPED, name="s")))
    out = tmp_path / "req.json"
    assert dr.main(["request", str(tmp_path / "s.yaml"), str(out), "--layer", dr.SHIPPED, "--name", "s", *vms]) == 1
    assert "TARGETS=all" in capsys.readouterr().err and not out.exists()
    assert dr.main(["request", str(tmp_path / "s.yaml"), str(out), "--layer", dr.SHIPPED, "--name", "s",
                    "--targets", "vm-celebrimbor-rivendell", *vms]) == 0
    said = capsys.readouterr()
    rid = said.out.strip().splitlines()[-1]
    assert "the bench's VMs read from" in said.err and "not from Azure" in said.err
    req = xr.load(out)
    assert req.id == rid and [w.target for w in req.wires] == [RG + "vm-celebrimbor-rivendell"]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    # The drill read is the one asked for.
    assert dr.main(["request", str(tmp_path / "s.yaml"), str(out), "--layer", dr.SHIPPED, "--name", "t",
                    "--targets", "all", *vms]) == 1
    assert not hasattr(dr, "VMS_ENV")


@pytest.mark.parametrize("name, code", [("bl1-reponse", 0), ("../x", 1), ("A", 1), ("x;id", 1), ("", 1)])
def test_a_drills_name_is_checked_before_anything(name, code):
    assert dr.main(["check-name", name]) == code
