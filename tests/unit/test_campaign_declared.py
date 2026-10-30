"""BL1 (#280) — the declared campaign: a public technique and a declared fault, on a bench VM in
non_disruptive, checked against the catalog before anything is planned
(annatar/campaign/declared.py), and planned exactly — never by the planner
(`annatar campaign plan --declared`).

No Azure, no model: the plan writes under tmp. Mutants M1785–M1788.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from annatar.campaign import declared
from annatar.campaign.catalog import load_catalog

BL1 = declared.DECLARED_DIR / "bl1-reponse.yaml"
VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    return path


GOOD = """id: c
zone: bench
autonomy: non_disruptive
targets: [vm-celebrimbor-gondolin]
steps:
  - {kind: fault, ref: vm-shutdown, expect: no_disruptive_action}
  - {kind: technique, ref: T1136.001, expect: contain}
  - {kind: recovery, expect: release}
"""


def test_bl1_is_declared_a_public_technique_and_a_fault_on_the_bench():
    """The campaign of BL1, as shipped: valid against the catalog and the fault's experiment."""
    d = declared.load(BL1)
    assert declared.problems(d) == []
    assert d.zone == "bench" and d.autonomy == "non_disruptive"
    assert d.techniques == ["T1136.001"] and d.faults == ["vm-shutdown"]
    catalog = load_catalog()
    assert all(catalog[t].get("engine") == "atomic" for t in d.techniques)


@pytest.mark.parametrize("change, said", [
    (("zone: bench", "zone: production"), "production rule"),
    (("autonomy: non_disruptive", "autonomy: human_only"), "non_disruptive"),
    (("ref: T1136.001", "ref: T1110.001"), "home-grown script"),           # local-script
    (("ref: T1136.001", "ref: T1486"), "destructive"),                     # and home-grown
    (("ref: T1136.001", "ref: T1053.003"), "not implemented"),
    (("ref: T1136.001", "ref: T9999"), "not in the catalog"),
    (("ref: vm-shutdown", "ref: vm-wipe"), "no experiment file"),
    (("[vm-celebrimbor-gondolin]", "[vm-celebrimbor-bree]"), "not the campaign's"),
    (("expect: contain", "expect: nothing"), "expect must be contain"),
    (("  - {kind: technique, ref: T1136.001, expect: contain}\n", ""), "no technique"),
])
def test_what_keeps_a_declaration_from_being_played(tmp_path, change, said):
    """M1785, M1786, M1787: the bench only, the response mode, a public library's technique (never
    a home-grown script), not destructive, implemented; a fault declared on the same targets."""
    d = declared.load(_write(tmp_path, GOOD.replace(*change)))
    found = declared.problems(d)
    assert any(said in p for p in found), found


def test_a_file_that_is_not_a_declaration_is_refused(tmp_path):
    with pytest.raises(ValueError):
        declared.load(_write(tmp_path, "- a list\n"))
    with pytest.raises(ValueError):
        declared.load(tmp_path / "absent.yaml")


def test_the_plan_takes_exactly_the_declared_techniques(tmp_path):
    """M1788: `campaign plan --declared` plans the declaration's techniques, in its order — not
    the planner's kill chain (which would add the home-grown ones) — and says its fault."""
    from annatar.cli import cli
    res = CliRunner().invoke(cli, ["campaign", "plan", "--target", VM, "--declared", str(BL1),
                                   "--runs-dir", str(tmp_path)])
    assert res.exit_code == 0, res.output
    [manifest] = list(tmp_path.glob("campaigns/*/manifest.json"))
    m = json.loads(manifest.read_text())
    assert [s["ttp"] for s in m["scenarios"]] == ["T1136.001"]
    assert m["objective"] == "declared: bl1-reponse"
    assert "vm-shutdown" in res.output


@pytest.mark.parametrize("change, target", [
    (("ref: T1136.001", "ref: T1110.001"), VM),
    (None, VM.replace("gondolin", "bree")),
])
def test_the_plan_refuses_a_declaration_with_a_problem_or_another_target(tmp_path, change, target):
    from annatar.cli import cli
    path = _write(tmp_path, GOOD.replace(*change) if change else GOOD)
    res = CliRunner().invoke(cli, ["campaign", "plan", "--target", target, "--declared", str(path),
                                   "--runs-dir", str(tmp_path / "runs")])
    assert res.exit_code == 1 and "refused" in res.output
    assert not list((tmp_path / "runs").glob("campaigns/*/manifest.json"))
