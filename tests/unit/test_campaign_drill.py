"""DG-e (#351): a campaign of Annatar becomes a drill whose author is Annatar.

`annatar campaign plan` writes the campaign's drill beside its manifest — Orodruin never writes
the console's drills; the operator brings it to Dagorlad (« Import YAML », Jonathan's decision A
of 04/11). A declared campaign's chain is its declaration's (its fault and its technique, in its
order); a planned one's, its scenarios. `annatar campaign run` writes, once, the request
equivalent to the campaign in Dagorlad's format. The kill-chain order has one definition, the
shared core's.

No Azure, no model: the plan writes under tmp, the runner is a stub.
"""
from __future__ import annotations

import json
import stat
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from annatar.campaign import declared
from eregion_core import drill as dr
from eregion_core import exercise_request as xr
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


# ── `campaign run`: the request equivalent to the campaign, once ────────────────────────────

def _campaign(tmp_path):
    runs = tmp_path / "runs" / "annatar"
    cdir = runs / "campaigns" / "C1"
    cdir.mkdir(parents=True)
    scen = [{"seq": i, "ttp": ttp, "tactic": "x", "name": ttp, "scenario_file": f"scenarios/{i:02d}.yaml",
             "target_resource_id": VM} for i, ttp in enumerate(("T1136.001", "T1110.001"), 1)]
    (cdir / "manifest.json").write_text(json.dumps({"campaign_id": "C1", "state": "ratified", "scenarios": scen}))
    return cdir, runs


@pytest.fixture()
def run(monkeypatch):
    import annatar.campaign.runner as runner_mod
    from annatar import cli
    done = SimpleNamespace(campaign_id="C1", state="done", without_glorfindel=False, results={
        "executed": 2, "detected": 2, "missed": 0, "skipped": 0, "errors": 0})
    monkeypatch.setattr(runner_mod, "CampaignRunner",
                        lambda cdir, dry_run=False, **kw: SimpleNamespace(run=lambda: done))
    monkeypatch.setattr(cli, "_write_campaign_report", lambda cdir: None)

    def invoke(runs, *args):
        res = CliRunner().invoke(cli.cli, ["campaign", "run", "C1", "--runs-dir", str(runs), "--no-report", *args])
        assert res.exit_code == 0, res.output
        return res.output
    return invoke


def test_a_campaign_run_writes_its_request_once_in_dagorlads_format(tmp_path, run):
    cdir, runs = _campaign(tmp_path)
    run(runs)
    run(runs)
    [path] = list(cdir.glob("r-*.json"))
    req = xr.read(json.loads(path.read_text()))
    assert path.name == f"{req.id}.json"
    assert [(w.experiment, w.target, w.rank) for w in req.wires] == [("T1136.001", VM, 1), ("T1110.001", VM, 2)]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_preview_writes_no_request(tmp_path, run):
    cdir, runs = _campaign(tmp_path)
    run(runs, "--dry-run")
    assert not list(cdir.glob("r-*.json"))


def test_a_request_not_written_never_stops_the_campaign(tmp_path, run, monkeypatch):
    cdir, runs = _campaign(tmp_path)

    def refuse(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(xr, "write", refuse)
    assert "request not written: disk full" in run(runs)
