"""Dagorlad, phase (b) — the request for Orodruin (DG-b, docs/design/console.md §7): its format,
read by one function that refuses any field more; where the console writes it. No Azure, no
model: files in tmp. The oracles are written here."""
from __future__ import annotations

import json
import stat
from datetime import datetime, timezone

import pytest

from eregion_core import exercise_request as xr

VM = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-gondolin"
VM2 = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-bree"
NOW = datetime(2026, 10, 30, 7, 52, tzinfo=timezone.utc)


def _doc(**over) -> dict:
    doc = {"id": "r-20261030T075200Z-a1b2c3", "at": NOW.isoformat(),
           "wires": [{"experiment": "T1136.001", "target": VM, "rank": 1},
                     {"experiment": "vm-shutdown", "target": VM, "rank": 2}]}
    doc.update(over)
    return doc


def test_a_request_is_an_id_a_time_and_its_wires_ranked():
    r = xr.read(_doc())
    assert r.id == "r-20261030T075200Z-a1b2c3"
    assert [(w.experiment, w.target_name, w.rank) for w in r.wires] == [
        ("T1136.001", "vm-gondolin", 1), ("vm-shutdown", "vm-gondolin", 2)]
    assert xr.read(r.to_dict()) == r


@pytest.mark.parametrize("field", ["zone", "destructive", "expected", "mode", "typed", "typed_name", "note"])
def test_a_field_more_is_refused_at_the_top(field):
    with pytest.raises(xr.RequestRefused, match="never holds"):
        xr.read(_doc(**{field: "x"}))


@pytest.mark.parametrize("field", ["zone", "destructive", "expected", "mode", "typed_name", "name"])
def test_a_field_more_is_refused_on_a_wire(field):
    doc = _doc()
    doc["wires"][0][field] = "bench"
    with pytest.raises(xr.RequestRefused, match="never holds"):
        xr.read(doc)


@pytest.mark.parametrize("over, said", [
    ({"id": "../x"}, "id"), ({"id": "r-2026-a1b2c3"}, "id"), ({"at": "yesterday"}, "time"),
    ({"at": "2026-10-30T07:52:00"}, "time"), ({"wires": []}, "1 to"), ({"wires": "T1486"}, "1 to"),
])
def test_a_malformed_request_is_refused(over, said):
    with pytest.raises(xr.RequestRefused, match=said):
        xr.read(_doc(**over))


def test_a_missing_field_is_refused():
    doc = _doc()
    del doc["wires"][1]["rank"]
    with pytest.raises(xr.RequestRefused, match="lacks rank"):
        xr.read(doc)


@pytest.mark.parametrize("wire, said", [
    ({"experiment": "T1486; rm", "target": VM, "rank": 1}, "catalogue id"),
    ({"experiment": "T1486", "target": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
      "Microsoft.Storage/storageAccounts/a", "rank": 1}, "VM's resource id"),
    ({"experiment": "T1486", "target": VM, "rank": 2}, "rank is not 1"),
    ({"experiment": "T1486", "target": VM, "rank": True}, "rank is not 1"),
    ({"experiment": "T1486", "target": VM, "rank": "1"}, "rank is not 1"),
])
def test_a_wire_of_the_wrong_kind_is_refused(wire, said):
    with pytest.raises(xr.RequestRefused, match=said):
        xr.read(_doc(wires=[wire]))


def test_the_same_pair_twice_is_refused():
    with pytest.raises(xr.RequestRefused, match="same pair"):
        xr.read(_doc(wires=[{"experiment": "T1486", "target": VM, "rank": 1},
                            {"experiment": "T1486", "target": VM.upper(), "rank": 2}]))


def test_never_more_wires_than_orodruins_ceiling():
    wires = [{"experiment": f"T{1000 + i}", "target": VM, "rank": i} for i in range(1, xr.MAX_WIRES + 2)]
    with pytest.raises(xr.RequestRefused, match="1 to 20"):
        xr.read(_doc(wires=wires))
    assert len(xr.read(_doc(wires=wires[:-1])).wires) == 20


def test_new_ranks_the_pairs_in_their_order():
    r = xr.new([("vm-shutdown", VM), ("T1486", VM2)], now=NOW)
    assert xr.valid_id(r.id) and r.id.startswith("r-20261030T075200Z-")
    assert [(w.rank, w.experiment) for w in r.wires] == [(1, "vm-shutdown"), (2, "T1486")]


def test_the_console_writes_in_its_own_directory_never_in_runs(tmp_path, monkeypatch):
    monkeypatch.delenv(xr.REQUESTS_ENV)
    monkeypatch.setenv("HOME", str(tmp_path))
    where = xr.requests_dir()
    assert where == tmp_path / ".eregion" / "console" / "requests"
    assert "runs" not in where.parts and ".glorfindel" not in where.parts


def test_a_request_is_written_once_mode_600(tmp_path):
    r = xr.new([("T1486", VM)], now=NOW)
    path = xr.write(r, tmp_path / "requests")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert xr.load(path) == r
    with pytest.raises(FileExistsError):
        xr.write(r, tmp_path / "requests")


def test_a_file_too_large_or_not_json_is_refused(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(" " * (xr.MAX_BYTES + 1))
    with pytest.raises(xr.RequestRefused, match="larger"):
        xr.load(big)
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    with pytest.raises(xr.RequestRefused, match="not JSON"):
        xr.load(bad)


def test_the_names_typed_are_read_apart_and_strictly():
    r = xr.read(_doc())
    assert xr.read_typed({"request": r.id, "typed": {"1": "vm-gondolin"}}, r) == {1: "vm-gondolin"}
    for doc, said in [
        ({"request": "r-20261030T075200Z-ffffff", "typed": {}}, "another request"),
        ({"request": r.id, "typed": {"3": "vm-gondolin"}}, "does not hold"),
        ({"request": r.id, "typed": {"1": "vm gondolin; x"}}, "VM's name"),
        ({"request": r.id, "typed": {}, "zone": "bench"}, "never holds"),
    ]:
        with pytest.raises(xr.RequestRefused, match=said):
            xr.read_typed(doc, r)


def test_no_typed_file_is_nothing_typed(tmp_path):
    r = xr.read(_doc())
    assert xr.load_typed(tmp_path / "absent.json", r) == {}
    (tmp_path / "t.json").write_text(json.dumps({"request": r.id, "typed": {"2": "vm-gondolin"}}))
    assert xr.load_typed(tmp_path / "t.json", r) == {2: "vm-gondolin"}


# ── On the operator's machine (make orodruin-exercise): shown, then the names typed ────────

def _confirm(doc, answers):
    from eregion_core.exercise_plan import load_catalog
    said, asked = [], []

    def ask(prompt):
        asked.append(prompt)
        return answers.pop(0)
    out = xr.confirm(xr.read(doc), load_catalog(), ask=ask, say=said.append)
    return out, "\n".join(said), asked


def test_a_destructive_wire_asks_its_targets_name_a_harmless_one_does_not():
    doc = _doc(wires=[{"experiment": "T1110.001", "target": VM, "rank": 1},
                      {"experiment": "T1486", "target": VM, "rank": 2}])
    out, said, asked = _confirm(doc, ["vm-gondolin", "y"])
    assert out == {"request": doc["id"], "typed": {"2": "vm-gondolin"}}
    assert [a.split(":")[0] for a in asked] == ["Wire 2", "Run these 2 wire(s) from Orodruin? [y/N] "]
    assert "DESTRUCTIVE" in said and "vm-gondolin" in said


def test_an_experiment_this_catalogue_does_not_know_asks_a_name_too():
    """A0: unknown is never taken for harmless."""
    out, said, asked = _confirm(_doc(wires=[{"experiment": "T9999", "target": VM, "rank": 1}]),
                                ["vm-gondolin", "y"])
    assert out["typed"] == {"1": "vm-gondolin"} and "not in this catalogue" in said


@pytest.mark.parametrize("answers", [["vm-bree", "y"], ["VM-GONDOLIN", "y"], ["vm-gondolin", "n"],
                                     ["vm-gondolin", ""]])
def test_another_name_or_no_sends_nothing(answers):
    doc = _doc(wires=[{"experiment": "T1486", "target": VM, "rank": 1}])
    out, said, _ = _confirm(doc, answers)
    assert out is None


def test_check_id_says_a_bad_id(capsys):
    assert xr.main(["check-id", "r-20261030T075200Z-a1b2c3"]) == 0
    assert xr.main(["check-id", "../etc"]) == 1
    assert "not a request id" in capsys.readouterr().err


# ── The review of DG-b, point 3: the one reader is strict ───────────────────────────────────

GUID = "00000000-0000-0000-0000-000000000000"
_RG = f"/subscriptions/{GUID}/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"


@pytest.mark.parametrize("target", [
    _RG + "vm\x1b[6Dbench1",                         # an escape: printed as « bench1 »
    _RG + "vm-gondolin\n",                           # « $ » took a trailing newline
    _RG + "vm‮gondolin",                        # a bidirectional override
    _RG + "vm١",                                # another script's digit
    _RG.replace("rg-celebrimbor", "rg-celebrimbor?x=") + "vm-gondolin",   # a query in the URL
    _RG.replace("rg-celebrimbor", "rg-celebrimbor#") + "vm-gondolin",
    _RG.replace("rg-celebrimbor", "rg%2Fcelebrimbor") + "vm-gondolin",
    _RG.replace("rg-celebrimbor", "..") + "vm-gondolin",
    _RG + "vm..x",
    _RG.replace(GUID, "s") + "vm-gondolin",          # a subscription is a GUID
])
def test_a_target_outside_azures_characters_is_refused(target):
    with pytest.raises(xr.RequestRefused, match="VM's resource id"):
        xr.read(_doc(wires=[{"experiment": "T1486", "target": target, "rank": 1}]))


@pytest.mark.parametrize("rid", ["r-20261030T075200Z-a1b2c3\n", "r-２０２６1030T075200Z-a1b2c3",
                                 "r-20261030T075200Z-A1B2C3"])
def test_an_id_matched_whole_ascii_only(rid):
    assert not xr.valid_id(rid)
    with pytest.raises(xr.RequestRefused, match="id"):
        xr.read(_doc(id=rid))


@pytest.mark.parametrize("name", ["vm-gondolin\n", "vm\x1b]0;x\x07", "vm‮"])
def test_a_typed_name_matched_whole(name):
    r = xr.read(_doc())
    with pytest.raises(xr.RequestRefused, match="VM's name"):
        xr.read_typed({"request": r.id, "typed": {"1": name}}, r)


def test_what_the_operator_reads_is_printable_only():
    assert xr.shown("vm\x1b[6Dbench1‮") == "vm\\u001b[6Dbench1\\u202e"
    said = []
    from eregion_core.exercise_plan import load_catalog
    xr.confirm(xr.read(_doc()), load_catalog(), ask=lambda p: "n", say=said.append)
    assert all(line.isprintable() for line in said)


def test_the_arm_reader_never_sends_a_query_a_fragment_or_an_escape():
    from eregion_core.inscription import TagEnrollment
    asked = []
    reader = TagEnrollment(credential=type("C", (), {"get_token": lambda self, s: type("T", (), {"token": "t"})()})(),
                           get=lambda *a, **k: asked.append(a))
    for path in (f"/subscriptions/{GUID}/resourceGroups/rg-celebrimbor?x=", f"/subscriptions/{GUID}/resourceGroups/rg#x",
                 f"/subscriptions/{GUID}/resourceGroups/rg%2F..", "https://evil.example/x"):
        with pytest.raises(ValueError):
            reader.arm_get(path, "2021-04-01")
    assert asked == []


def test_the_request_pulled_is_the_one_asked_for():
    """DG-b review, point 4: H0 answers REQUEST=<id> with another request — nothing is asked, nothing sent."""
    asked = []
    from eregion_core.exercise_plan import load_catalog
    out = xr.confirm(xr.read(_doc()), load_catalog(), ask=lambda p: asked.append(p) or "y",
                     say=lambda *_: None, expect="r-20261030T075200Z-ffffff")
    assert out is None and asked == []
