"""DG-e (#351): a campaign of Annatar becomes a drill whose author is Annatar.

`annatar campaign plan` writes the campaign's drill beside its manifest — Orodruin never writes
the console's drills; the operator brings it to Dagorlad (« Import YAML », Jonathan's decision A
of 04/11). Its chain is the scenarios synthesized; a declared campaign keeps its faults too, in
its declaration's order. A drill refused or not written is said, the campaign planned all the
same. The kill-chain order has one definition, the shared core's.

No Azure, no model: the plan writes under tmp.
"""
from __future__ import annotations

import json
import stat
from types import SimpleNamespace

from click.testing import CliRunner

from annatar.campaign import declared
from eregion_core import drill as dr
from eregion_core import proposal

VM = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
BL1 = declared.DECLARED_DIR / "bl1-reponse.yaml"


def _plan(tmp_path, *args):
    from annatar.cli import cli
    res = CliRunner().invoke(cli, ["campaign", "plan", "--target", VM, "--runs-dir", str(tmp_path), *args])
    assert res.exit_code == 0, res.output
    [cdir] = [p.parent for p in tmp_path.glob("campaigns/*/manifest.json")]
    return cdir, res.output


def _drill_of(cdir):
    [path] = list(cdir.glob("annatar-*.yaml"))
    return path, dr.load_file(path, dr.INSTANCE)


def test_a_declared_campaign_is_planned_with_its_drill_its_fault_and_technique_in_order(tmp_path):
    cdir, out = _plan(tmp_path, "--declared", str(BL1))
    path, d = _drill_of(cdir)
    assert d.name == proposal.drill_name(cdir.name) and d.author == "annatar"
    assert [(w.experiment, w.name) for w in d.wires] == [("vm-shutdown", "vm-celebrimbor-gondolin"),
                                                         ("T1136.001", "vm-celebrimbor-gondolin")]
    assert d.description == "declared: bl1-reponse"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "Import YAML" in out and d.name in out


def test_a_planned_campaigns_drill_is_its_scenarios_in_order(tmp_path):
    cdir, _ = _plan(tmp_path, "--max-scenarios", "3")
    manifest = json.loads((cdir / "manifest.json").read_text())
    _, d = _drill_of(cdir)
    assert [w.experiment for w in d.wires] == [s["ttp"] for s in manifest["scenarios"]]
    assert {w.name for w in d.wires} == {"vm-celebrimbor-gondolin"}, "never a resource id: its name"


def test_a_campaign_whose_drill_is_refused_is_planned_all_the_same(tmp_path, monkeypatch):
    def refuse(*a, **k):
        raise dr.DrillRefused("its wires are not a list of 1 to 50")
    monkeypatch.setattr(proposal, "campaign_drill", refuse)
    cdir, out = _plan(tmp_path, "--declared", str(BL1))
    assert (cdir / "manifest.json").exists() and not list(cdir.glob("annatar-*.yaml"))
    assert "No drill for this campaign" in out


def test_the_kill_chain_order_has_one_definition_the_cores():
    from annatar.campaign import catalog, planner
    assert catalog.tactic_rank is proposal.tactic_rank and planner.tactic_rank is proposal.tactic_rank
    assert catalog.CANONICAL_TACTIC_ORDER is proposal.CANONICAL_TACTIC_ORDER


def test_a_declared_drill_leaves_out_a_technique_the_synthesizer_left_out(tmp_path, monkeypatch):
    """The review of e3d60cc9: the drill was the declaration's steps — a technique the
    synthesizer skipped stayed in it, a wire the campaign never played. Now the scenarios kept,
    with the declaration's faults, in its order."""
    import annatar.campaign.synthesizer as synth
    path = tmp_path / "c.yaml"
    path.write_text("id: c\nzone: bench\nautonomy: non_disruptive\ntargets: [vm-celebrimbor-gondolin]\nsteps:\n"
                    "  - {kind: fault, ref: vm-shutdown, expect: no_disruptive_action}\n"
                    "  - {kind: technique, ref: T1110.001, expect: contain}\n"
                    "  - {kind: technique, ref: T1136.001, expect: contain}\n", encoding="utf-8")
    monkeypatch.setattr(declared, "problems", lambda d, catalog=None, **k: [])
    real = synth.synthesize
    monkeypatch.setattr(synth, "synthesize", lambda entry, **kw: SimpleNamespace(ok=False, reason="left out", path=None)
                        if entry["ttp"] == "T1110.001" else real(entry=entry, **kw))
    cdir, out = _plan(tmp_path / "runs", "--declared", str(path))
    _, d = _drill_of(cdir)
    assert [w.experiment for w in d.wires] == ["vm-shutdown", "T1136.001"], out


def test_a_drill_that_cannot_be_written_is_said_the_campaign_planned(tmp_path, monkeypatch):
    """The review of e3d60cc9: a disk full, a file there already — `campaign plan` fell on a trace
    with its manifest written. Now said, the campaign planned."""
    def full(d):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(dr, "to_yaml", full)
    cdir, out = _plan(tmp_path, "--declared", str(BL1))
    assert (cdir / "manifest.json").exists() and not list(cdir.glob("annatar-*.yaml"))
    assert "drill not written" in out and "No space left on device" in out
