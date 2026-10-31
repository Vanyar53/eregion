"""V1 (#214): Annatar and Gothmog do not act without Glorfindel.

Before every run — each run of a campaign too — and before any call to the cloud, an
injector reads the watch's heartbeat (the return channel when it is set, the local file
~/.glorfindel/watch_heartbeat), and refuses without a live one, saying how old the last one
is, or that there was never one. ``--without-glorfindel`` runs anyway: the report says so,
H0 accepts that report, the console shows it apart from ``unknown``.

The cloud here fails if it is called: Orodruin's contract, the target's executor and the
network all raise. A throwaway HOME, no Azure, no LLM. Gothmog's side is in
tests/unit/test_gothmog.py. Mutants M720–M739 (scripts/mutation_check.py) are measured here
and there.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from click.testing import CliRunner

import annatar.runner.engine as engine_module
import eregion_core.exercise_channel as channel
import eregion_core.watch_channel as wc
import eregion_core.watch_gate as gate
from analysis.campaign_schema import run_report_refusal
from annatar.campaign.manifest import Budget, CampaignManifest, ScenarioEntry, Scope, campaign_dir
from annatar.campaign.runner import CampaignRunner
from annatar.cli import cli
from annatar.runner.engine import Engine, RunOutcome
from tests.unit.fake_container import CRED, URL, FakeContainer
from tests.unit.test_annatar_run_exit import ATOMIC_YAML, EXFIL_YAML, _executor

ROOT = Path(__file__).resolve().parents[2]
SUB = "00000000-0000-0000-0000-00000000aaaa"   # a placeholder, never a real subscription


def _beat(at: datetime, subscription: str | None = None) -> str:
    """The heartbeat a watch of this subscription writes for the injectors (SEC5, N-03)."""
    return json.dumps(gate.beat_body(at, subscription))
WATCH = "https://storodruin.blob.core.windows.net/watch"
NOW = datetime(2026, 10, 27, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def real_gate(tmp_path, monkeypatch):
    """The gate's real readers (conftest sees a live watch everywhere else), a throwaway
    HOME, no channel, a placeholder subscription; returns the local heartbeat file to write."""
    monkeypatch.setattr(gate, "READERS", {"channel": gate.channel_beat, "local": gate.local_beat,
                                          "own": gate.perimeter})
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv(gate.SUBSCRIPTION_ENV, SUB)
    monkeypatch.delenv(wc.CHANNEL_ENV, raising=False)
    hb = tmp_path / "home" / ".glorfindel" / "watch_heartbeat"
    hb.parent.mkdir(parents=True)
    return hb


@pytest.fixture
def cloud(monkeypatch):
    """A cloud that fails if it is called — and says so: Orodruin's contract, the target's
    executor, any HTTP request. ``cloud.calls`` lists what was attempted."""
    calls: list[str] = []

    def arm(run_id, injector, *a, **kw):
        calls.append(f"arm {injector}")
        raise AssertionError("the cloud was called: Orodruin's contract")

    def executor(self, scenario, session=None):
        calls.append("executor")
        raise AssertionError("the cloud was called: the target")

    def http(*a, **kw):
        calls.append("http")
        raise AssertionError("the cloud was called: HTTP")

    monkeypatch.setattr(engine_module, "arm", arm)
    monkeypatch.setattr(Engine, "_get_executor_collector", executor)
    monkeypatch.setattr(requests, "get", http)
    monkeypatch.setattr(requests, "put", http)
    monkeypatch.setattr(requests, "post", http)
    return SimpleNamespace(calls=calls)


def _run(tmp_path, monkeypatch, *args):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANNATAR_DEBUG", raising=False)
    return CliRunner().invoke(cli, ["run", *args, "--yes"])


# ── The gate: what it reads, what it says ────────────────────────────────────────────

def test_no_heartbeat_anywhere_is_never(real_gate):
    why = gate.refusal(NOW)
    assert why.startswith(f"{gate.LOCAL}: last heartbeat never")
    assert "no file" in why


def test_a_stale_local_heartbeat_says_how_old_it_is(real_gate):
    """M731: a heartbeat two hours old is no watch, and the refusal says since when."""
    real_gate.write_text((NOW - timedelta(hours=2, minutes=3)).isoformat())
    why = gate.refusal(NOW)
    assert why == f"{gate.LOCAL}: last heartbeat 2 h 03 min ago (2026-10-27 06:57:00 UTC)"


def test_a_fresh_local_heartbeat_is_a_live_watch(real_gate):
    real_gate.write_text(_beat(NOW - timedelta(seconds=30)))
    assert gate.refusal(NOW) == ""


def test_a_heartbeat_just_past_fresh_is_none(real_gate):
    real_gate.write_text((NOW - timedelta(seconds=wc.FRESH_S)).isoformat())
    assert gate.refusal(NOW).startswith(f"{gate.LOCAL}: last heartbeat 1 min 30 s ago")


def test_an_unreadable_local_file_is_no_watch(real_gate):
    real_gate.write_text("yesterday")
    assert "never (not a date" in gate.refusal(NOW)


def _channel(monkeypatch, beat):
    monkeypatch.setenv(wc.CHANNEL_ENV, WATCH)

    def read(**_):
        if isinstance(beat, Exception):
            raise beat
        return beat
    monkeypatch.setattr(wc, "read_heartbeat", read)


def test_the_hosted_watch_through_the_channel_is_a_live_watch(real_gate, monkeypatch):
    """M732: on Orodruin, no local file — the channel's heartbeat is the watch."""
    _channel(monkeypatch, json.loads(_beat(NOW - timedelta(seconds=40))))
    assert gate.refusal(NOW) == ""


def test_a_stale_channel_says_how_old_and_where(real_gate, monkeypatch):
    _channel(monkeypatch, {"at": (NOW - timedelta(days=2, hours=1)).isoformat()})
    why = gate.refusal(NOW)
    assert why.startswith(f"{gate.CHANNEL}: last heartbeat 2 d 1 h ago")
    assert gate.LOCAL not in why          # the channel decides: the local file is not read


def test_an_unreadable_channel_is_said_never_raised(real_gate, monkeypatch):
    """M733: a channel the run cannot read is no watch — said in the refusal."""
    _channel(monkeypatch, RuntimeError("HTTP 403 reading the watch channel"))
    assert gate.refusal(NOW).startswith(
        f"{gate.CHANNEL}: last heartbeat never (unreadable: HTTP 403 reading the watch channel)")
    _channel(monkeypatch, RuntimeError("HTTP 404 reading the watch channel"))
    assert gate.refusal(NOW).startswith(
        f"{gate.CHANNEL}: last heartbeat never (no heartbeat.json in the channel)")


def test_with_a_channel_a_live_local_file_does_not_count(real_gate, monkeypatch):
    """M758: the channel decides when it is set — a file on this host says nothing of the
    hosted watch the run depends on."""
    _channel(monkeypatch, RuntimeError("HTTP 403 reading the watch channel"))
    real_gate.write_text((NOW - timedelta(seconds=5)).isoformat())
    assert gate.refusal(NOW).startswith(f"{gate.CHANNEL}: last heartbeat never (unreadable")
    _channel(monkeypatch, {"at": (NOW - timedelta(hours=1)).isoformat()})
    assert gate.refusal(NOW).startswith(f"{gate.CHANNEL}: last heartbeat 1 h 00 min ago")


@pytest.mark.parametrize("ahead_s, fresh", [(5, True), (10, True), (11, False), (3600, False)])
def test_a_heartbeat_dated_in_the_future_is_fresh_only_within_the_clocks_skew(
        real_gate, monkeypatch, ahead_s, fresh):
    """M756: a heartbeat dated an hour ahead would stay « fresh » for ever. A few seconds
    ahead is two hosts' clocks (H0, Orodruin); beyond CLOCK_SKEW_S, no watch — and said."""
    at = NOW + timedelta(seconds=ahead_s)
    real_gate.write_text(_beat(at))
    why = gate.refusal(NOW)
    assert (why == "") is fresh
    if not fresh:
        assert "in the future" in why and "a clock is wrong" in why
    _channel(monkeypatch, json.loads(_beat(at)))
    assert (gate.refusal(NOW) == "") is fresh
    assert wc.alive({"at": at.isoformat()}, now=NOW) is fresh   # the wait's test too (#159)


# ── Annatar: refused before any call to the cloud ────────────────────────────────────

@pytest.mark.parametrize("scenario", [ATOMIC_YAML, EXFIL_YAML])
def test_annatar_refuses_without_a_live_watch_before_any_cloud_call(
        scenario, real_gate, cloud, tmp_path, monkeypatch):
    """M720, M721: no live watch → `annatar run` exits non-zero, says since when, and
    nothing reached the cloud — no contract, no target, no window."""
    real_gate.write_text((datetime.now(timezone.utc) - timedelta(hours=3)).isoformat())
    res = _run(tmp_path, monkeypatch, scenario)
    assert res.exit_code != 0
    assert "no live Glorfindel watch" in res.output
    assert "last heartbeat 3 h" in res.output
    assert "--without-glorfindel" in res.output          # the hint says the way out
    assert cloud.calls == []
    # No report, no window, no signal — only the lock of « one run at a time » on Orodruin
    # (#358), its holder's name erased at the exit.
    left = [q for q in (tmp_path / "runs").rglob("*") if q.is_file()]
    assert [q.relative_to(tmp_path / "runs").as_posix() for q in left] in ([], ["orodruin/requests/.lock"])
    assert all(q.read_text() == "" for q in left)


def test_annatar_refuses_and_says_never(real_gate, cloud, tmp_path, monkeypatch):
    real_gate.unlink(missing_ok=True)
    res = _run(tmp_path, monkeypatch, ATOMIC_YAML)
    assert res.exit_code != 0 and "last heartbeat never" in res.output
    assert cloud.calls == []


def test_the_old_warning_is_gone(real_gate, cloud, tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, ATOMIC_YAML)
    assert "no active glorfindel watch detected" not in res.output


def test_a_dry_run_needs_no_watch(real_gate, tmp_path, monkeypatch):
    res = _run(tmp_path, monkeypatch, ATOMIC_YAML, "--dry-run")
    assert res.exit_code == 0, res.output


# ── Annatar --without-glorfindel: it runs, and its report says so ────────────────────

def _without(tmp_path, monkeypatch, scenario, executor):
    """`annatar run --without-glorfindel --yes`, no watch at all, the wait recorded."""
    waited = []
    monkeypatch.chdir(tmp_path)
    with patch.object(Engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(Engine, "_wait_and_emit_feedback", lambda *a, **k: waited.append(a)):
        res = CliRunner().invoke(cli, ["run", scenario, "--without-glorfindel", "--yes"])
    reports = list((tmp_path / "runs").glob("2*Z.json"))
    return res, waited, json.loads(reports[0].read_text()) if reports else None


@pytest.mark.parametrize("scenario", [ATOMIC_YAML, EXFIL_YAML])
def test_annatar_without_glorfindel_runs_and_its_report_says_so(
        scenario, real_gate, tmp_path, monkeypatch):
    """M722, M723, M736, M737: the run goes through with no watch; its report carries the
    explicit field and the phrase; the detection is not waited for — unknown, never missed."""
    executor = _executor()
    res, waited, report = _without(tmp_path, monkeypatch, scenario, executor)
    assert res.exit_code == 0, res.output
    assert executor.run_command.called or executor.run_script.called   # it did run
    m = report["metrics"]
    assert m["without_glorfindel"] is True
    assert m["detection_note"] == "detection not measured, by choice"
    assert m["detection"] == "unknown" and m["detection_latency_s"] is None
    assert waited == []                                    # no wait, no detection_missed
    assert "not measured, by choice" in res.output
    assert "no live Glorfindel watch" not in res.output


def test_a_run_with_glorfindel_says_nothing_of_it(tmp_path, monkeypatch):
    """The conftest's live watch: the report has no without_glorfindel field at all."""
    monkeypatch.chdir(tmp_path)
    with patch.object(Engine, "_get_executor_collector", return_value=(_executor(), None)), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        outcome = Engine().run(ATOMIC_YAML, skip_confirm=True)
    m = json.loads((tmp_path / "runs" / f"{outcome.run_id}.json").read_text())["metrics"]
    assert "without_glorfindel" not in m and "detection_note" not in m


# ── H0 accepts the report of a run without Glorfindel ────────────────────────────────

@pytest.fixture
def container(monkeypatch):
    c = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", c.put)
    monkeypatch.setattr(requests, "get", c.get)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    return c


def test_h0_pulls_the_report_of_a_run_without_glorfindel(real_gate, tmp_path, monkeypatch,
                                                          container):
    """`annatar run --without-glorfindel` from Orodruin: its report goes to H0 at its end,
    and H0 accepts it (run_report_refusal) — the flag intact."""
    orodruin = tmp_path / "orodruin"
    orodruin.mkdir()
    res, _, report = _without(orodruin, monkeypatch, ATOMIC_YAML, _executor())
    assert res.exit_code == 0, res.output
    rid = report["run_id"]
    assert f"runs/{rid}.json" in container.puts
    h0 = tmp_path / "h0" / "runs"
    h0.mkdir(parents=True)
    pulled = channel.pull_runs(h0, refusal=run_report_refusal, channel=URL, credential=CRED,
                               get=container.get)
    assert pulled == (1, {})
    assert json.loads((h0 / f"{rid}.json").read_text())["metrics"]["without_glorfindel"] is True


@pytest.mark.parametrize("metrics, refused", [
    ({"without_glorfindel": True, "detection": "unknown"}, False),
    ({"without_glorfindel": True}, False),
    ({"without_glorfindel": False, "detection": "detected"}, False),
    ({"without_glorfindel": True, "detection": "detected"}, True),
    ({"without_glorfindel": True, "detection": "missed"}, True),
    ({"without_glorfindel": "yes"}, True),
])
def test_h0_refuses_a_run_without_glorfindel_that_claims_a_verdict(metrics, refused):
    """M734: a run without a watch cannot have been detected or missed."""
    report = {"run_id": "R1", "metrics": {"attack_time": 1.0, **metrics}}
    assert bool(run_report_refusal(report, "R1")) is refused


# ── Campaigns ─────────────────────────────────────────────────────────────────────────

class FakeEngine:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), []

    def run(self, path, skip_confirm=False):
        self.calls.append(path)
        return self.outcomes.pop(0)


VM = ("/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
      "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")


def _campaign(tmp_path, n=2):
    m = CampaignManifest(
        campaign_id="C1", objective="t", scope=Scope(allowed_resource_groups=["rg-celebrimbor"]),
        budget=Budget(), state="ratified",
        scenarios=[ScenarioEntry(seq=i, ttp="T1110.001", tactic="impact", name="t",
                                 scenario_file=f"scenarios/{i:02d}.yaml", target_resource_id=VM)
                   for i in range(1, n + 1)])
    cdir = campaign_dir("C1", runs_dir=tmp_path)
    m.save(cdir)
    return cdir


def test_a_campaign_without_a_live_watch_is_refused_before_its_first_run(real_gate, tmp_path):
    """M728: refused whole, its state left 'ratified' (it can run once the watch is up), no
    run started."""
    cdir = _campaign(tmp_path)
    engine = FakeEngine([])
    with pytest.raises(ValueError, match="no live Glorfindel watch: .*last heartbeat never"):
        CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert engine.calls == []
    m = CampaignManifest.load(cdir)
    assert m.state == "ratified" and {s.status for s in m.scenarios} == {"pending"}


def test_a_watch_that_dies_mid_campaign_stops_it(tmp_path):
    """M729: the next run is refused by the engine (glorfindel:): the campaign stops there
    — never a chain of refusals marked as errors."""
    cdir = _campaign(tmp_path, n=3)
    engine = FakeEngine([RunOutcome("run-1", "detected"),
                         RunOutcome("run-2", "unknown", error="glorfindel: local file …: never")])
    m = CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert m.state == "aborted"
    assert [s.status for s in m.scenarios] == ["executed", "error", "pending"]
    assert len(engine.calls) == 2


def test_a_campaign_without_glorfindel_reaches_each_run(real_gate, tmp_path):
    """M730: --without-glorfindel is not refused, and each run's engine gets it."""
    runner = CampaignRunner(_campaign(tmp_path), without_glorfindel=True)
    assert runner.engine_factory().without_glorfindel is True
    assert CampaignRunner(_campaign(tmp_path / "x")).engine_factory().without_glorfindel is False


def test_campaign_run_cli_passes_the_flag(tmp_path, monkeypatch):
    import annatar.campaign.runner as runner_mod
    cdir = _campaign(tmp_path)
    seen = {}

    def fake(cdir, dry_run=False, without_glorfindel=False):
        seen["without"] = without_glorfindel
        return SimpleNamespace(run=lambda: SimpleNamespace(
            campaign_id="C1", state="done", without_glorfindel=without_glorfindel,
            results={"executed": 0, "detected": 0, "missed": 0, "skipped": 0, "errors": 0}))
    monkeypatch.setattr(runner_mod, "CampaignRunner", fake)
    res = CliRunner().invoke(cli, ["campaign", "run", "C1", "--yes", "--no-report",
                                   "--runs-dir", str(tmp_path), "--without-glorfindel"])
    assert res.exit_code == 0, res.output
    assert seen == {"without": True}
    assert cdir.exists()


def test_a_campaign_records_how_it_started_and_resumes_only_the_same_way(real_gate, tmp_path):
    """M750, M751: the manifest says the campaign runs without Glorfindel; resumed with the
    watch required (or the other way round), it is refused, its manifest left as it was."""
    from annatar.campaign.runner import CampaignRefused
    cdir = _campaign(tmp_path, n=2)
    engine = FakeEngine([RunOutcome("run-1", "unknown"), RunOutcome("run-2", "unknown")])
    CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine,
                   without_glorfindel=True).run()
    m = CampaignManifest.load(cdir)
    assert m.without_glorfindel is True
    assert json.loads((cdir / "manifest.json").read_text())["without_glorfindel"] is True
    # Left 'running' by a crash: resumed with the watch required → refused, whatever the watch.
    m.set_state("running")
    m.scenarios[1].status = "pending"
    m.save(cdir)
    real_gate.write_text(_beat(datetime.now(timezone.utc)))   # a live watch, even
    with pytest.raises(CampaignRefused, match="started without Glorfindel — resume it the same way"):
        CampaignRunner(cdir, reset_fn=lambda x: None, engine_factory=lambda: engine).run()
    assert CampaignManifest.load(cdir).state == "running" and len(engine.calls) == 2
    # And a campaign started with Glorfindel is not resumed without it.
    cdir2 = _campaign(tmp_path / "b")
    m2 = CampaignManifest.load(cdir2)
    m2.set_state("running")
    m2.save(cdir2)
    with pytest.raises(CampaignRefused, match="started with Glorfindel"):
        CampaignRunner(cdir2, reset_fn=lambda x: None, engine_factory=lambda: engine,
                       without_glorfindel=True).run()


def test_campaign_run_cli_refuses_in_one_line_and_exits_one(real_gate, tmp_path, monkeypatch):
    """M755: no watch → the reason and the hint, no traceback, exit 1, the campaign untouched."""
    monkeypatch.delenv("ANNATAR_DEBUG", raising=False)
    cdir = _campaign(tmp_path)
    res = CliRunner().invoke(cli, ["campaign", "run", "C1", "--yes", "--no-report",
                                   "--runs-dir", str(tmp_path)])
    assert res.exit_code == 1
    assert "no live Glorfindel watch" in res.output and "--without-glorfindel" in res.output
    assert "Traceback" not in res.output and "ValueError" not in res.output
    assert CampaignManifest.load(cdir).state == "ratified"


def _cli_campaign(tmp_path, monkeypatch, *, state="done", without=False, args=()):
    import annatar.campaign.runner as runner_mod
    from annatar import cli as cli_mod
    _campaign(tmp_path)
    done = SimpleNamespace(campaign_id="C1", state=state, without_glorfindel=without, results={
        "executed": 1, "detected": 0, "missed": 0, "skipped": 0, "errors": 0})
    monkeypatch.setattr(runner_mod, "CampaignRunner",
                        lambda cdir, dry_run=False, **kw: SimpleNamespace(run=lambda: done))
    written = []
    monkeypatch.setattr(cli_mod, "_write_campaign_report", written.append)
    res = CliRunner().invoke(cli, ["campaign", "run", "C1", "--runs-dir", str(tmp_path), *args])
    return res, written


def test_an_aborted_campaign_exits_one(tmp_path, monkeypatch):
    """M755: the watch gone mid-campaign (or the kill switch): `make orodruin-campaign-run`
    must fail."""
    res, _ = _cli_campaign(tmp_path, monkeypatch, state="aborted")
    assert res.exit_code == 1
    res, _ = _cli_campaign(tmp_path / "ok", monkeypatch, state="done")
    assert res.exit_code == 0, res.output


def test_a_campaign_without_glorfindel_writes_no_report_and_says_so(tmp_path, monkeypatch):
    res, written = _cli_campaign(tmp_path, monkeypatch, without=True)
    assert res.exit_code == 0, res.output
    assert written == []
    assert gate.NO_CAMPAIGN_REPORT in res.output


def _done_manifest(cdir, **extra):
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "manifest.json").write_text(json.dumps({
        "campaign_id": cdir.name, "state": "done", "created_at": "2026-10-27T08:00:00Z",
        "scenarios": [{"seq": 1, "ttp": "T1110.001", "status": "executed", "run_id": "R1",
                       "target_resource_id": VM, "detection": "unknown",
                       "started_at": "2026-10-27T08:00:00Z"}], **extra}))
    return cdir


def test_a_campaign_without_glorfindel_has_no_analysis_report(tmp_path, capsys):
    """M752: no detection measured — no report, nothing indexed (so never a previous
    campaign), said; `make campaign-report` writes nothing and does not fail."""
    from analysis import campaign_report as cr
    cdir = _done_manifest(tmp_path / "runs" / "campaigns" / "C1", without_glorfindel=True)
    with pytest.raises(cr.NoReport, match="campaign without Glorfindel: no detection report, by choice"):
        cr.build(cdir, llm=lambda *a, **k: pytest.fail("the model was called"))
    assert cr.main([str(cdir)]) == 0
    assert not (cdir / "report.md").exists()
    assert gate.NO_CAMPAIGN_REPORT in capsys.readouterr().out
    assert cr.no_report(_done_manifest(tmp_path / "runs" / "campaigns" / "C2")) == ""


def test_h0_writes_no_report_for_a_campaign_without_glorfindel(tmp_path):
    """M753: pulled from the channel, done, its runs here — still not due; said once."""
    from analysis import hosted_report as hr
    from eregion_core.exercise_channel import PULLED
    root = tmp_path / "runs" / "campaigns"
    said = []
    for name, extra in (("C1", {"without_glorfindel": True}), ("C2", {})):
        cdir = _done_manifest(root / name, **extra)
        (cdir / PULLED).touch()
        (cdir / "runs").mkdir()
        (cdir / "runs" / "R1.json").write_text(json.dumps({"run_id": "R1", "metrics": {}}))
    assert [p.name for p in hr.ready(root, say=said.append)] == ["C2"]
    assert said == [f"C1: {gate.NO_CAMPAIGN_REPORT}"]
    assert hr.write_report(root / "C1", llm=lambda *a, **k: pytest.fail("model"),
                           say=said.append) == "without"
    assert not (root / "C1" / "report.md").exists() and not (root / "C1" / hr.ERROR).exists()


def test_a_campaign_without_glorfindel_never_enters_the_index(tmp_path):
    """M754: `campaign_index` leaves it, and says why — it is never a previous campaign."""
    from analysis import campaign_index as ci
    cdir = _done_manifest(tmp_path / "runs" / "campaigns" / "C1", without_glorfindel=True)
    versed = ci.verse(cdir, path=tmp_path / "index")
    assert versed.left == gate.NO_CAMPAIGN_REPORT
    assert not (tmp_path / "index").exists()


@pytest.mark.parametrize("value, refused", [(True, False), (False, False), (None, False),
                                            ("yes", True), (1, True)])
def test_h0_reads_the_manifest_s_flag_typed(value, refused):
    from analysis.campaign_schema import manifest_refusal
    m = {"campaign_id": "C1", "state": "done", "scenarios": [], "without_glorfindel": value}
    assert bool(manifest_refusal(m)) is refused


# ── The console shows it apart from unknown ──────────────────────────────────────────

def test_the_console_keeps_the_flag_of_a_run_without_glorfindel(tmp_path):
    """M735: the run's slim form, read by the injectors' pages, keeps the flag."""
    api = pytest.importorskip("eregion_console.api")
    path = tmp_path / "R1.json"
    path.write_text(json.dumps({"run_id": "R1", "result": "PASS", "metrics": {
        "detection": "unknown", "without_glorfindel": True, "detection_note": gate.NOT_MEASURED}}))
    assert api._slim_run(path)["metrics"] == {"detection": "unknown", "without_glorfindel": True}
    path.write_text(json.dumps({"run_id": "R1", "metrics": {"without_glorfindel": "yes"}}))
    assert "without_glorfindel" not in api._slim_run(path)["metrics"]
    js = (ROOT / "eregion_console" / "static" / "exercises.js").read_text()
    assert "without_glorfindel === true" in js and "not measured, by choice" in js


def test_the_console_counts_a_campaign_without_glorfindel_apart(tmp_path, monkeypatch):
    """M759: the campaigns' API carries the manifest's flag; the overview and Annatar's page
    show « not measured, by choice » in place of the unknown count."""
    import asyncio
    api = pytest.importorskip("eregion_console.api")
    runs = tmp_path / "runs"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for name, extra in (("C1", {"without_glorfindel": True}), ("C2", {})):
        _done_manifest(runs / "campaigns" / name, **extra)
        m = json.loads((runs / "campaigns" / name / "manifest.json").read_text())
        (runs / "campaigns" / name / "manifest.json").write_text(json.dumps({**m, "created_at": now}))
    monkeypatch.setattr(api, "_RUNS", runs)
    got = {c["dir"]: c["without_glorfindel"] for c in asyncio.run(api.campaigns())["campaigns"]}
    assert got == {"C1": True, "C2": False}
    for page in ("overview.js", "injector.js"):
        html = (ROOT / "eregion_console" / "static" / page).read_text()
        assert "c.without_glorfindel" in html and "not measured, by choice" in html, page


# ── Orodruin's Make targets: the flag goes through, the refusal comes back ───────────

def _make(tmp_path, target, *args, exit_code=0):
    if shutil.which("make") is None:
        pytest.skip("make not installed")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "ssh.log"
    log.write_text("")
    ssh = bin_dir / "ssh"
    ssh.write_text('#!/bin/sh\nfor a in "$@"; do last="$a"; done\n'
                   'echo "$last" >> "$FAKE_SSH_LOG"\nexit "$FAKE_SSH_EXIT"\n')
    ssh.chmod(0o755)
    tf = bin_dir / "terraform"
    tf.write_text("#!/bin/sh\nexit 1\n")
    tf.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "FAKE_SSH_LOG": str(log), "FAKE_SSH_EXIT": str(exit_code)}
    env.pop("WITHOUT_GLORFINDEL", None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target,
                          "ORO_IP=203.0.113.9", *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res.returncode, log.read_text().splitlines()


@pytest.mark.parametrize("target, args, command", [
    ("gothmog-run", (), "gothmog run vm-shutdown --yes"),
    ("gothmog-preflight", (), "gothmog preflight vm-shutdown"),
    ("orodruin-campaign-run", ("CAMPAIGN=C1",), "annatar campaign run C1 --yes"),
])
def test_orodruin_targets_pass_the_flag_and_return_the_refusal(tmp_path, target, args, command):
    """M738, M739: WITHOUT_GLORFINDEL=1 reaches the injector on Orodruin; without it, nothing
    is added; a refusal there (exit != 0) fails the make target."""
    code, calls = _make(tmp_path, target, *args)
    assert code == 0 and calls[-1].endswith(command) and "--without-glorfindel" not in calls[-1]
    for value in ("1", "yes", "true"):
        code, calls = _make(tmp_path, target, *args, f"WITHOUT_GLORFINDEL={value}")
        assert code == 0 and calls[-1].endswith(f"{command} --without-glorfindel"), value
    for value in ("0", "no", "false"):   # M757: only 1, yes, true waive the watch
        code, calls = _make(tmp_path, target, *args, f"WITHOUT_GLORFINDEL={value}")
        assert code == 0 and "--without-glorfindel" not in calls[-1], value
    code, _ = _make(tmp_path, target, *args, exit_code=1)
    assert code != 0
