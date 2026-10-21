"""#167, Orodruin's side and the channel: a finished campaign goes to H0 over the exercise
container — its manifest and its runs' reports, nothing else, no right more than the
windows' — and H0 pulls it into ``runs/campaigns/<id>/`` without touching the windows. The
end of ``campaign run`` says where the report will be written. Never the network: the
container is in memory (tests/unit/fake_container.py), and a call that would leave the
process fails the test. Mutants M130, M136, M138, M139 and M149 (scripts/mutation_check.py)
are measured here."""
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from click.testing import CliRunner
from rich.console import Console

import eregion_core.exercise as exercise
import eregion_core.exercise_channel as channel
import eregion_core.orodruin as orodruin
from tests.unit.fake_container import CRED, URL, FakeContainer

VM = "/subscriptions/s/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm-bench-01"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The channel's credential is a fake one, and requests never leaves the process."""
    def refuse(*a, **kw):
        raise AssertionError("a call left the process")
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", refuse)
    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)


@pytest.fixture
def container(monkeypatch):
    """The channel set, and requests answered by the container in memory."""
    c = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(requests, "put", c.put)
    monkeypatch.setattr(requests, "get", c.get)
    return c


def _scenario(seq, rid, *, status="executed", detection="detected"):
    return {"seq": seq, "ttp": "T1136.001", "tactic": "persistence", "name": f"step {seq}",
            "scenario_file": f"scenarios/{seq:02d}.yaml", "target_resource_id": VM,
            "status": status, "run_id": rid, "detection": detection}


def _orodruin(tmp_path, *, state="done", scenarios=None, reports=("R1", "R2"), cid="C1"):
    """A finished campaign on Orodruin: its directory, its runs' reports — and beside them
    what must never leave: the runs' debug and signal files, another run, the campaign's
    scenarios and an older report."""
    runs = tmp_path / "orodruin" / "runs"
    cdir = runs / "campaigns" / "C1"
    (cdir / "scenarios").mkdir(parents=True)
    (cdir / "scenarios" / "01.yaml").write_text("name: step 1\n")
    (cdir / "report.md").write_text("# an earlier report\n")
    scenarios = scenarios if scenarios is not None else [
        _scenario(1, "R1"), _scenario(2, "R2", detection="missed")]
    (cdir / "manifest.json").write_text(json.dumps(
        {"campaign_id": cid, "state": state, "scenarios": scenarios}))
    for rid in reports:
        (runs / f"{rid}.json").write_text(json.dumps(
            {"run_id": rid, "metrics": {"attack_time": 1_790_000_000.0}}))
    for rid in ("R1", "R2"):
        (runs / f"{rid}_debug.jsonl").write_text("{}\n")
        (runs / f"{rid}_signals.jsonl").write_text("{}\n")
    (runs / "R9.json").write_text(json.dumps({"run_id": "R9"}))
    return cdir, runs


# ── What Orodruin publishes ──────────────────────────────────────────────────────

def test_a_campaign_publishes_its_runs_reports_then_its_manifest_and_nothing_else(tmp_path):
    """M130: the runs' reports and the manifest, last — not the runs' debug or signal files,
    not another run, not the campaign's scenarios or report."""
    cdir, runs = _orodruin(tmp_path)
    c = FakeContainer()
    cid, names = channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)
    expected = ["campaigns/C1/runs/R1.json", "campaigns/C1/runs/R2.json", "campaigns/C1/manifest.json"]
    assert (cid, names) == ("C1", expected)
    assert c.puts == expected and sorted(c.blobs) == sorted(expected)
    assert c.body("campaigns/C1/runs/R1.json") == (runs / "R1.json").read_bytes()
    assert c.body("campaigns/C1/manifest.json") == (cdir / "manifest.json").read_bytes()


def test_without_a_channel_nothing_is_published(tmp_path):
    cdir, runs = _orodruin(tmp_path)
    put = MagicMock()
    assert channel.publish_campaign(cdir, runs, channel="", credential=CRED, put=put) == ("", [])
    put.assert_not_called()


def test_a_refused_write_raises_to_its_caller(tmp_path):
    cdir, runs = _orodruin(tmp_path)
    c = FakeContainer()
    c.refused.add("campaigns/C1/manifest.json")
    with pytest.raises(RuntimeError, match="403"):
        channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)


def test_names_that_are_not_plain_never_name_a_blob(tmp_path):
    """A run id read from the manifest is a plain name or left out; a campaign id that is
    not a plain name refuses the publication."""
    for part in ("a/b", "..", "x..y", ".hidden", ""):
        assert not channel.safe_part(part)
    assert channel.safe_part("20261021T101500Z")
    scenarios = [_scenario(1, "R1"), _scenario(2, "a/b"), _scenario(3, "x..y")]
    cdir, runs = _orodruin(tmp_path, scenarios=scenarios)
    c = FakeContainer()
    _, names = channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)
    assert names == ["campaigns/C1/runs/R1.json", "campaigns/C1/manifest.json"]
    cdir2, runs2 = _orodruin(tmp_path / "other", cid="a/b")
    with pytest.raises(ValueError, match="unsafe campaign id"):
        channel.publish_campaign(cdir2, runs2, channel=URL, credential=CRED, put=c.put)


def test_the_publication_asks_nothing_more_of_orodruins_contract(tmp_path):
    """The campaign goes where the windows go — the one container the contract allows
    outside the bench — with the same storage token: no new action, no new scope."""
    cdir, runs = _orodruin(tmp_path)
    c, scopes = FakeContainer(), []
    cred = SimpleNamespace(get_token=lambda scope: scopes.append(scope) or SimpleNamespace(token="tok"))
    channel.publish({"run_id": "R1"}, channel=URL, credential=cred, put=c.put)
    channel.publish_campaign(cdir, runs, channel=URL, credential=cred, put=c.put)
    assert set(scopes) == {channel.STORAGE}        # every write inside the container: fake_container
    assert not [a for a in orodruin.REQUIRED_ACTIONS if "storage" in a.lower()]
    sub = "sub-123"
    bench = f"/subscriptions/{sub}/resourceGroups/rg-bench"
    container_scope = (f"/subscriptions/{sub}/resourceGroups/rg-orodruin/providers/Microsoft.Storage"
                       "/storageAccounts/exampleaccount/blobServices/default/containers/exercises")
    assignments = [{"properties": {"scope": s, "roleDefinitionId": "/r/blob-data-contributor"}}
                   for s in (bench, container_scope)]
    declared = orodruin.channel_scope({orodruin.CHANNEL_SCOPE_ENV: container_scope})
    assert orodruin.assess_identity(assignments, lambda _: ["*"],
                                    [{"actions": list(orodruin.REQUIRED_ACTIONS)}], bench,
                                    sees_subscription=True, channel=declared) == []


def test_unpublished_runs_names_the_executed_runs_without_a_report(tmp_path):
    scenarios = [_scenario(1, "R1"), _scenario(2, "R2"), _scenario(3, "R3", status="error")]
    cdir, runs = _orodruin(tmp_path, scenarios=scenarios, reports=("R1",))
    assert channel.unpublished_runs(cdir, runs) == ["R2"]


# ── H0 pulls the campaigns ───────────────────────────────────────────────────────

def _published(tmp_path, **kw):
    cdir, runs = _orodruin(tmp_path, **kw)
    c = FakeContainer()
    channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)
    return c, tmp_path / "h0" / "runs" / "campaigns"


def _pull(c, root):
    return channel.pull_campaigns(root, channel=URL, credential=CRED, get=c.get)


def test_a_campaign_is_pulled_under_its_id_runs_first_manifest_last(tmp_path):
    c, root = _published(tmp_path)
    assert [b for b in sorted(c.blobs)][0] == "campaigns/C1/manifest.json"   # listed first
    assert _pull(c, root) == (3, set())
    assert c.gets == ["campaigns/C1/runs/R1.json", "campaigns/C1/runs/R2.json",
                      "campaigns/C1/manifest.json"]
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()) == [
        "C1/.pulled", "C1/manifest.json", "C1/runs/R1.json", "C1/runs/R2.json"]
    assert (root / "C1" / "manifest.json").read_bytes() == c.body("campaigns/C1/manifest.json")
    assert c.listings[0]["prefix"] == "campaigns/"


def test_a_pulled_file_is_written_whole(tmp_path, monkeypatch):
    """Written beside, then moved in place: the report never reads half a manifest."""
    c, root = _published(tmp_path)
    written = []
    real = Path.write_bytes
    monkeypatch.setattr(Path, "write_bytes", lambda self, data: written.append(self.name) or real(self, data))
    _pull(c, root)
    assert written and all(n.endswith(".json.tmp") for n in written)
    assert not list(root.rglob("*.tmp"))


def test_only_what_is_new_or_changed_is_downloaded_again(tmp_path):
    c, root = _published(tmp_path)
    _pull(c, root)
    c.gets.clear()
    assert _pull(c, root) == (0, set())
    assert c.gets == []
    local = root / "C1" / "manifest.json"
    (root / "C1" / channel.PULLED).unlink()
    assert _pull(c, root) == (0, set()) and (root / "C1" / channel.PULLED).exists()
    older = c.clock.timestamp()
    os.utime(local, (older, older))
    c.put(f"{URL}/campaigns/C1/manifest.json", data=b'{"campaign_id": "C1", "state": "done"}')
    assert _pull(c, root) == (1, set())
    assert c.gets == ["campaigns/C1/manifest.json"]
    assert json.loads(local.read_text())["state"] == "done"


def test_a_campaign_whose_run_did_not_come_waits_for_the_next_pull(tmp_path):
    """M139: its manifest stays on the channel — a manifest here says its runs are here."""
    c, root = _published(tmp_path)
    c.refused.add("campaigns/C1/runs/R2.json")
    assert _pull(c, root) == (1, {"C1"})
    assert not (root / "C1" / "manifest.json").exists()
    assert not (root / "C1" / channel.PULLED).exists()
    c.refused.clear()
    assert _pull(c, root) == (2, set())
    assert (root / "C1" / "manifest.json").exists() and (root / "C1" / channel.PULLED).exists()


def test_a_blob_of_another_shape_is_never_pulled(tmp_path):
    c, root = _published(tmp_path)
    for name in ("campaigns/a..b/manifest.json", "campaigns/a/b/manifest.json",
                 "campaigns/C2/runs/x..y.json", "campaigns/C2/report.md",
                 "campaigns/C2/runs/sub/R1.json"):
        c.put(f"{URL}/{name}", data=b"{}")
    _pull(c, root)
    assert sorted(p.name for p in root.iterdir()) == ["C1"]
    assert not any("C2" in g or ".." in g or "/a/" in g for g in c.gets)


def test_without_a_channel_no_campaign_is_pulled(tmp_path):
    assert channel.pull_campaigns(tmp_path, channel="", credential=CRED, get=MagicMock()) == (0, set())


# ── The windows stay the windows ─────────────────────────────────────────────────

def test_the_windows_pull_takes_the_windows_only_page_after_page(tmp_path):
    """M138: the listing comes in pages; every window is pulled, never a campaign blob."""
    c = FakeContainer(page_size=2)
    for rid in ("R1", "R2", "R3"):
        channel.publish({"run_id": rid, "start": "2026-10-01T10:00:00+00:00"},
                        channel=URL, credential=CRED, put=c.put)
    cdir, runs = _orodruin(tmp_path)
    channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)
    windows = tmp_path / "h0" / "runs" / "exercises"
    assert channel.pull(windows, channel=URL, credential=CRED, get=c.get) == 3
    assert sorted(os.listdir(windows)) == ["R1.json", "R2.json", "R3.json"]
    assert len(c.listings) == 3 and [bool(p.get("marker")) for p in c.listings] == [False, True, True]
    assert not [g for g in c.gets if g.startswith("campaigns/")]


def test_a_published_campaign_never_takes_a_windows_place(tmp_path):
    """M136: a run's window is ``<run_id>.json`` at the container's root — the run's report,
    published with its campaign, never lands there, nor in ``runs/exercises/``."""
    c = FakeContainer()
    window = exercise.open_window("R1", injector="annatar", kind="technique", experiment="T1136.001",
                                  targets=[VM], directory=tmp_path / "orodruin" / "exercises")
    channel.publish(window, channel=URL, credential=CRED, put=c.put)
    cdir, runs = _orodruin(tmp_path)
    channel.publish_campaign(cdir, runs, channel=URL, credential=CRED, put=c.put)
    windows = tmp_path / "h0" / "runs" / "exercises"
    channel.pull(windows, channel=URL, credential=CRED, get=c.get)
    assert sorted(os.listdir(windows)) == ["R1.json"]
    assert exercise.load_windows(windows) == [window]


# ── The end of `campaign run` ────────────────────────────────────────────────────

@pytest.fixture
def said(monkeypatch):
    from annatar import cli
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=500, color_system=None))
    return out


def test_a_done_campaign_says_its_report_is_written_on_h0(tmp_path, container, said):
    from annatar import cli
    cdir, runs = _orodruin(tmp_path)
    assert cli._publish_campaign(cdir, str(runs), "done") is True
    assert "campaigns/C1/manifest.json" in container.blobs
    text = said.getvalue()
    assert "Campaign published to H0 (3 file(s))" in text
    assert "runs/campaigns/C1/report.md on H0" in text


def test_an_aborted_campaign_says_its_report_is_to_write_by_hand(tmp_path, container, said):
    from annatar import cli
    cdir, runs = _orodruin(tmp_path, state="aborted")
    assert cli._publish_campaign(cdir, str(runs), "aborted") is True
    text = said.getvalue()
    assert "'aborted': no report is written on its own" in text
    assert "make campaign-report CAMPAIGN=C1" in text and "report.md on H0" not in text


def test_runs_without_a_report_say_h0_will_not_write_it(tmp_path, container, said):
    from annatar import cli
    cdir, runs = _orodruin(tmp_path, reports=("R1",))
    assert cli._publish_campaign(cdir, str(runs), "done") is True
    text = said.getvalue()
    assert "1 executed run(s) without a report" in text
    assert "H0 will not write its report on its own" in text and "report.md on H0" not in text


def test_without_a_channel_nothing_is_said_nor_sent(tmp_path, said):
    from annatar import cli
    cdir, runs = _orodruin(tmp_path)
    assert cli._publish_campaign(cdir, str(runs), "done") is False
    assert said.getvalue() == ""


def test_a_failed_publication_is_said_never_raised(tmp_path, container, said):
    """M149: the campaign has run; its report can be written later."""
    from annatar import cli
    cdir, runs = _orodruin(tmp_path)
    container.refused.add("campaigns/C1/manifest.json")
    try:
        published = cli._publish_campaign(cdir, str(runs), "done")
    except Exception as e:
        pytest.fail(f"the failed publication raised into the campaign: {type(e).__name__}: {e}")
    assert published is False
    assert "Campaign not published to H0 (RuntimeError: HTTP 403" in said.getvalue()


@pytest.mark.parametrize("with_channel", [True, False])
def test_campaign_run_writes_the_report_here_only_without_the_channel(tmp_path, monkeypatch,
                                                                     with_channel, said):
    """With the channel the report is H0's; without it (or when the publication failed),
    the campaign writes it here, as before #167."""
    import annatar.campaign.runner as runner_mod
    from annatar import cli
    cdir, runs = _orodruin(tmp_path)
    if with_channel:
        c = FakeContainer()
        monkeypatch.setenv(channel.CHANNEL_ENV, URL)
        monkeypatch.setattr(requests, "put", c.put)
    done = SimpleNamespace(campaign_id="C1", state="done", results={
        "executed": 2, "detected": 1, "missed": 1, "skipped": 0, "errors": 0})
    monkeypatch.setattr(runner_mod, "CampaignRunner",
                        lambda cdir, dry_run=False: SimpleNamespace(run=lambda: done))
    local = []
    monkeypatch.setattr(cli, "_write_campaign_report", local.append)
    result = CliRunner().invoke(cli.cli, ["campaign", "run", "C1", "--runs-dir", str(runs)])
    assert result.exit_code == 0, result.output
    assert local == ([] if with_channel else [cdir])
