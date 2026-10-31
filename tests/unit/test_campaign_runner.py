"""Campaign runner — sequential execution, budget, scope re-check, kill switch.

Engine + NSG reset are injected (no Azure, no LLM, no subprocess).
"""

import subprocess

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
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1041")])
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
        tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1041")],
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


def test_refuses_done_campaign_with_replan_hint(tmp_path):
    # A 'done' campaign is terminal — ratify does not unblock it; the message
    # must point to re-planning, not ratifying (2026-07-30 CLI hygiene finding).
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")], state="done")
    with pytest.raises(ValueError, match="re-plan"):
        CampaignRunner(cdir, reset_fn=lambda x: None).run()


def test_multi_scenario_warns_human_only(tmp_path, capsys):
    cdir = _make_campaign(
        tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1041")],
    )
    engine = FakeEngine([
        RunOutcome("run-1", "detected"),
        RunOutcome("run-2", "detected"),
    ])
    CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert "human_only" in capsys.readouterr().out


def test_single_scenario_no_human_only_warning(tmp_path, capsys):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")])
    engine = FakeEngine([RunOutcome("run-1", "detected")])
    CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert "human_only" not in capsys.readouterr().out


def test_engine_error_marks_error_continues(tmp_path):
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001"), _entry(2, "T1041")])
    engine = FakeEngine([
        RunOutcome("run-1", "unknown", error="preflight failed"),
        RunOutcome("run-2", "detected"),
    ])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert r.scenarios[0].status == "error"
    assert r.scenarios[0].error == "preflight failed"
    assert r.scenarios[1].status == "executed"  # campaign continued
    assert r.state == "done"


def test_atomic_run_records_detection_and_latency_in_manifest(tmp_path):
    # An atomic run's outcome (detection + latency, #157) reaches the manifest exactly as a
    # local-script run's does — the campaign reads it post-hoc, and the report uses it.
    cdir = _make_campaign(tmp_path, [_entry(1, "T1136.001", tactic="persistence")])
    engine = FakeEngine([RunOutcome("run-atomic", "detected", detection_latency_s=44.7)])
    r = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    entry = r.scenarios[0]
    assert entry.status == "executed"
    assert entry.detection == "detected"
    assert entry.detection_latency_s == 44.7
    # and it survives a reload from disk (the manifest is the audit artifact)
    reloaded = CampaignManifest.load(cdir)
    assert reloaded.scenarios[0].detection == "detected"
    assert reloaded.scenarios[0].detection_latency_s == 44.7


def test_reset_status_recorded_in_manifest(tmp_path):
    # Whatever the reset did is written on the entry — here a quiet skip the runner records.
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")])
    engine = FakeEngine([RunOutcome("run-1", "detected")])
    r = CampaignRunner(
        cdir,
        reset_fn=lambda x: "skipped: glorfindel absent (reset is not in the Orodruin image)",
        engine_factory=lambda: engine,
    ).run()
    assert "skipped" in r.scenarios[0].reset
    assert "skipped" in CampaignManifest.load(cdir).scenarios[0].reset


def _no_shell_out(*a, **k):  # the reset must NOT shell out when glorfindel cannot run
    raise AssertionError("subprocess.run must not be called when glorfindel is absent")


def test_default_reset_skips_quietly_in_the_orodruin_image(tmp_path, monkeypatch):
    # The Orodruin image as it is (annatar/Dockerfile, `pip install -e ".[annatar]"`): the
    # `glorfindel` launcher IS on PATH (every [project.scripts] entry is installed) but the
    # glorfindel package is not copied, so `glorfindel reset` would exit 1 on
    # ModuleNotFoundError. _default_reset must test the package and skip — no subprocess, no
    # raise, no write — and say so (recorded in the manifest), never "failed: exit 1" (M125).
    import annatar.campaign.runner as runner_mod

    monkeypatch.setattr(runner_mod, "find_spec", lambda name: None)
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _name: "/usr/local/bin/glorfindel")
    monkeypatch.setattr(runner_mod.subprocess, "run", _no_shell_out)
    status = runner_mod._default_reset("/subscriptions/s/…/vm")
    assert status.startswith("skipped")
    assert "glorfindel absent" in status


def test_default_reset_skips_quietly_without_launcher(tmp_path, monkeypatch):
    # Package importable but no launcher on PATH: skipped as well, without shelling out.
    import annatar.campaign.runner as runner_mod

    monkeypatch.setattr(runner_mod, "find_spec", lambda name: object())
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _name: None)
    monkeypatch.setattr(runner_mod.subprocess, "run", _no_shell_out)
    status = runner_mod._default_reset("/subscriptions/s/…/vm")
    assert status.startswith("skipped")
    assert "glorfindel absent" in status


def test_default_reset_runs_when_glorfindel_present(tmp_path, monkeypatch):
    import annatar.campaign.runner as runner_mod

    monkeypatch.setattr(runner_mod, "find_spec", lambda name: object())
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _name: "/usr/bin/glorfindel")
    calls = []

    def _run(*a, **k):
        calls.append(a)
        return subprocess.CompletedProcess(a[0], 0)

    monkeypatch.setattr(runner_mod.subprocess, "run", _run)
    status = runner_mod._default_reset("/subscriptions/s/…/vm")
    assert status == "reset"
    assert len(calls) == 1  # it did shell out


def test_default_reset_failing_exit_is_recorded_as_failed(tmp_path, monkeypatch):
    # `glorfindel reset` exiting non-zero did NOT reset: the manifest must say "failed",
    # never "reset" (review #165 point 5, M123).
    import annatar.campaign.runner as runner_mod

    monkeypatch.setattr(runner_mod, "find_spec", lambda name: object())
    monkeypatch.setattr(runner_mod.shutil, "which", lambda _name: "/usr/bin/glorfindel")
    monkeypatch.setattr(
        runner_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 2)
    )
    status = runner_mod._default_reset("/subscriptions/s/…/vm")
    assert status == "failed: exit 2"


# ── #358: a campaign launched by hand on Orodruin takes the request's lock ────────────────────

def _cli_campaign(tmp_path, monkeypatch, *args, state="planned"):
    """`annatar campaign run` on a campaign of tmp, its runner replaced: what it was asked."""
    from types import SimpleNamespace

    from click.testing import CliRunner

    import annatar.campaign.runner as runner_mod
    from annatar.cli import cli
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")], state=state)
    ran = []

    def runner(cdir, dry_run=False, without_glorfindel=False):
        def run():
            ran.append(dry_run)
            return SimpleNamespace(campaign_id=cdir.name, state="done", without_glorfindel=False,
                                   results={"executed": 0, "detected": 0, "missed": 0, "skipped": 0,
                                            "errors": 0})
        return SimpleNamespace(run=run)
    monkeypatch.setattr(runner_mod, "CampaignRunner", runner)
    res = CliRunner().invoke(cli, ["campaign", "run", cdir.name, "--runs-dir", str(tmp_path),
                                   "--no-report", *args])
    return res, ran, cdir


def test_a_campaign_by_hand_during_a_request_is_refused_and_ratifies_nothing(tmp_path, monkeypatch):
    from eregion_core.exercise_runner import request_lock
    with request_lock(tmp_path, "request r-20261031T080000Z-abcdef"):
        res, ran, cdir = _cli_campaign(tmp_path, monkeypatch, "--yes")
    assert res.exit_code == 1, res.output
    said = " ".join(res.output.split())   # rich folds the line
    assert "refused — busy: request r-20261031T080000Z-abcdef runs on this Orodruin" in said
    assert ran == [] and CampaignManifest.load(cdir).state == "planned"


def test_a_preview_of_a_campaign_takes_no_lock(tmp_path, monkeypatch):
    from eregion_core.exercise_runner import request_lock
    with request_lock(tmp_path, "request r-20261031T080000Z-abcdef"):
        res, ran, _ = _cli_campaign(tmp_path, monkeypatch, "--dry-run")
    assert res.exit_code == 0, res.output
    assert ran == [True]


def test_a_request_during_a_campaign_by_hand_is_refused_naming_the_campaign(tmp_path, monkeypatch):
    """While the campaign runs, the lock is its own: a request is refused, and told why."""
    from types import SimpleNamespace

    from click.testing import CliRunner

    import annatar.campaign.runner as runner_mod
    from annatar.cli import cli
    from eregion_core.exercise_runner import Busy, request_lock
    cdir = _make_campaign(tmp_path, [_entry(1, "T1110.001")])
    seen = []

    def runner(cdir, dry_run=False, without_glorfindel=False):
        def run():
            with pytest.raises(Busy) as e:
                with request_lock(tmp_path, "request r-20261031T080000Z-abcdef"):
                    pass
            seen.append(str(e.value))
            return SimpleNamespace(campaign_id=cdir.name, state="done", without_glorfindel=False,
                                   results={"executed": 1, "detected": 1, "missed": 0, "skipped": 0,
                                            "errors": 0})
        return SimpleNamespace(run=run)
    monkeypatch.setattr(runner_mod, "CampaignRunner", runner)
    res = CliRunner().invoke(cli, ["campaign", "run", cdir.name, "--runs-dir", str(tmp_path), "--no-report"])
    assert res.exit_code == 0, res.output
    assert seen == [f"campaign {cdir.name} runs on this Orodruin: one at a time — wait for its end, "
                    "or stop it (make orodruin-kill)"]
    with request_lock(tmp_path, "request r-20261031T080000Z-abcdef"):   # let go once it is over
        pass


def test_a_holder_whose_name_looks_like_markup_is_said_as_it_is(tmp_path, monkeypatch):
    """#388's review: rich never reads the holder's name, nor the campaign's id, as markup."""
    from eregion_core.exercise_runner import request_lock
    with request_lock(tmp_path, "request [/red][bold]x"):
        res, ran, _ = _cli_campaign(tmp_path, monkeypatch, "--yes")
    assert res.exit_code == 1 and isinstance(res.exception, SystemExit), res.exception
    assert "busy: request [/red][bold]x runs" in " ".join(res.output.split()) and ran == []
