"""Campaign runner — sequential execution, budget, scope re-check, kill switch.

Engine + NSG reset are injected (no Azure, no LLM, no subprocess).
"""

import pytest

from annatar.campaign.manifest import (
    Budget,
    CampaignManifest,
    ScenarioEntry,
    Scope,
    campaign_dir,
    new_campaign_id,
)
from annatar.campaign.runner import CampaignRunner
from annatar.runner.engine import RunOutcome

SANDBOX_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
    "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
PROD_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-prod/providers/"
    "Microsoft.Compute/virtualMachines/vm-prod"
)


class FakeEngine:
    """Returns canned outcomes in order; records the paths it was asked to run."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def run(self, path, skip_confirm=False):
        self.calls.append(path)
        return self.outcomes.pop(0)


def _entry(seq, ttp, target=SANDBOX_VM, destructive=False, tactic="impact"):
    return ScenarioEntry(
        seq=seq, ttp=ttp, tactic=tactic, name=ttp,
        scenario_file=f"scenarios/{seq:02d}-{ttp}.yaml",
        target_resource_id=target, destructive=destructive,
    )


def _make_campaign(tmp_path, scenarios, *, budget=None, state="ratified", kill=False):
    cid = new_campaign_id()
    m = CampaignManifest(
        campaign_id=cid,
        objective="t",
        scope=Scope(allowed_resource_groups=["rg-celebrimbor"]),
        budget=budget or Budget(),
        scenarios=scenarios,
        state=state,
        kill_switch=kill,
    )
    cdir = campaign_dir(cid, runs_dir=tmp_path)
    m.save(cdir)
    return cdir


def test_happy_path_sequential(tmp_path):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1486")])
    engine = FakeEngine([
        RunOutcome("run-1", "detected"),
        RunOutcome("run-2", "missed"),
    ])
    resets = []
    r = CampaignRunner(
        cdir, reset_fn=resets.append, engine_factory=lambda: engine,
    ).run()
    assert r.state == "done"
    res = r.results
    assert (res["executed"], res["detected"], res["missed"]) == (2, 1, 1)
    assert len(engine.calls) == 2
    assert resets == [SANDBOX_VM, SANDBOX_VM]  # reset between each
    assert r.scenarios[0].run_id == "run-1"
    assert r.scenarios[1].detection == "missed"


def test_budget_ceiling_skips_rest(tmp_path):
    cdir = _make_campaign(
        tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1486")],
        budget=Budget(max_scenarios=1),
    )
    engine = FakeEngine([RunOutcome("run-1", "detected")])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "executed"
    assert r.scenarios[1].status == "skipped"
    assert "budget" in r.scenarios[1].error
    assert len(engine.calls) == 1


def test_kill_switch_aborts(tmp_path):
    cdir = _make_campaign(
        tmp_path, [_entry(1, "T1110.001")], kill=True,
    )
    engine = FakeEngine([RunOutcome("run-1", "detected")])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.state == "aborted"
    assert engine.calls == []  # nothing ran
    assert r.scenarios[0].status == "pending"


def test_out_of_scope_scenario_errors(tmp_path):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1486", target=PROD_VM)])
    engine = FakeEngine([])  # must never be called
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "error"
    assert "out of scope" in r.scenarios[0].error
    assert engine.calls == []


def test_destructive_skipped_without_budget(tmp_path):
    cdir = _make_campaign(
        tmp_path, [_entry(1, "T1486", destructive=True)],
        budget=Budget(allow_destructive=False),
    )
    engine = FakeEngine([])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "skipped"
    assert "destructive" in r.scenarios[0].error
    assert engine.calls == []


def test_destructive_runs_with_budget(tmp_path):
    cdir = _make_campaign(
        tmp_path, [_entry(1, "T1486", destructive=True)],
        budget=Budget(allow_destructive=True),
    )
    engine = FakeEngine([RunOutcome("run-1", "detected")])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "executed"


def test_refuses_unratified_campaign(tmp_path):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")], state="planned")
    with pytest.raises(ValueError, match="ratify"):
        CampaignRunner(cdir, reset_fn=lambda x: None).run()


def test_engine_error_marks_error_continues(tmp_path):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1486")])
    engine = FakeEngine([
        RunOutcome("run-1", "unknown", error="preflight failed"),
        RunOutcome("run-2", "detected"),
    ])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "error"
    assert r.scenarios[0].error == "preflight failed"
    assert r.scenarios[1].status == "executed"  # campaign continued
    assert r.state == "done"
