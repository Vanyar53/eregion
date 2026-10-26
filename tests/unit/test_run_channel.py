"""#193: the report of a run launched alone — ``annatar run``, ``gothmog run`` — goes from
Orodruin to H0 over the exercise container, as ``runs/<run_id>.json``: its report only, at
the end of the run, beside its closed window, a failure said and never raised. H0 pulls it
into its own ``runs/<run_id>.json``, where the console of the atelier reads its verdict —
once it has the shape H0 accepts (H-1), and never over a report of a run of its own. A
campaign is unchanged: it carries its runs' reports itself, at its end. Never the network:
the container is in memory (tests/unit/fake_container.py). Mutants M240–M245
(scripts/mutation_check.py) are measured here; M246 (Gothmog's side) in test_gothmog.py."""
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

import eregion_core.exercise_channel as channel
from analysis import hosted_report as hr
from analysis.campaign_schema import run_report_refusal
from annatar.runner.engine import Engine
from tests.unit.fake_container import CRED, URL, FakeContainer
from tests.unit.test_annatar_run_exit import ATOMIC_YAML, _executor, _invoke

RID = "20261026T101500Z"
OLD = (1_000_000_000, 1_000_000_000)   # 2001: older than any blob of the fake container


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a call left the process")
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", refuse)
    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    monkeypatch.setattr(hr, "_said", {})


@pytest.fixture
def container(monkeypatch):
    c = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(requests, "put", c.put)
    monkeypatch.setattr(requests, "get", c.get)
    return c


def _report(rid=RID, **metrics):
    return {"scenario": "Local account creation", "run_id": rid, "mitre": "T1136.001",
            "result": "PASS", "checks": {"attack": "PASS"},
            "metrics": {"attack_time": 1_790_000_000.0, "detection": "detected",
                        "detection_latency_s": 44.7, **metrics}, "thresholds": {}}


def _on_orodruin(tmp_path, report=None, rid=RID):
    runs = tmp_path / "orodruin" / "runs"
    runs.mkdir(parents=True)
    (runs / f"{rid}.json").write_text(json.dumps(report or _report(rid)))
    (runs / f"{rid}_debug.jsonl").write_text("{}\n")
    (runs / f"{rid}_signals.jsonl").write_text("{}\n")
    return runs


def _h0(tmp_path):
    runs = tmp_path / "h0" / "runs"
    runs.mkdir(parents=True)
    return runs


def _pull(runs, container):
    return channel.pull_runs(runs, refusal=run_report_refusal, channel=URL, credential=CRED,
                             get=container.get)


# ── What Orodruin publishes ──────────────────────────────────────────────────────

def test_a_run_publishes_its_report_only(tmp_path, container):
    runs = _on_orodruin(tmp_path)
    assert channel.publish_run(RID, runs) == f"runs/{RID}.json"
    assert container.puts == [f"runs/{RID}.json"]
    assert container.body(f"runs/{RID}.json") == (runs / f"{RID}.json").read_bytes()
    assert container.tokens == ["Bearer tok"]


def test_without_a_channel_or_a_report_nothing_is_published(tmp_path):
    put = MagicMock()
    runs = _on_orodruin(tmp_path)
    assert channel.publish_run(RID, runs, channel="", put=put) == ""
    assert channel.publish_run("20261026T999999Z", runs, channel=URL, credential=CRED, put=put) == ""
    put.assert_not_called()


def test_a_run_id_that_is_not_a_plain_name_never_names_a_blob(tmp_path):
    put = MagicMock()
    with pytest.raises(ValueError):
        channel.publish_run("../campaigns/C1/manifest", tmp_path, channel=URL, credential=CRED, put=put)
    put.assert_not_called()


def test_a_failed_publication_is_said_never_raised(tmp_path, container, capsys):
    """M242: the run is over; its report stays on Orodruin, and the operator is told."""
    runs = _on_orodruin(tmp_path)
    container.refused.add(f"runs/{RID}.json")
    assert channel.carry_run(RID, runs) is False
    assert f"run report {RID} not published: HTTP 403" in capsys.readouterr().out
    assert channel.carry_run(RID, runs) is False  # again: still never raised


def test_annatar_run_publishes_its_report_after_its_last_save(tmp_path, monkeypatch, container):
    """M240: `annatar run` alone sends its report — the one saved after the wait for the
    detection, beside its closed window."""
    res = _invoke(tmp_path, monkeypatch, _executor(), ATOMIC_YAML)
    assert res.exit_code == 0, res.output
    published = [n for n in container.puts if n.startswith("runs/")]
    assert len(published) == 1
    rid = published[0][len("runs/"):-len(".json")]
    report = json.loads(container.body(published[0]))
    assert report["run_id"] == rid and report["result"] == "PASS"
    assert "detection" in report["metrics"]                 # the last save, after the wait
    assert report == json.loads((tmp_path / "runs" / f"{rid}.json").read_text())
    window = container.puts.index(f"{rid}.json", 1)        # the window, once closed
    assert container.puts.index(published[0]) > window
    assert f"run report published to H0: runs/{rid}.json" in res.output


def test_an_atomic_that_raised_still_publishes_its_failed_report(tmp_path, monkeypatch, container):
    res = _invoke(tmp_path, monkeypatch, _executor(command_raises=True), ATOMIC_YAML)
    assert res.exit_code != 0
    published = [n for n in container.puts if n.startswith("runs/")]
    assert len(published) == 1
    report = json.loads(container.body(published[0]))
    assert report["result"] == "FAIL" and report["checks"]["attack"] == "ERROR"


def test_a_refused_run_publishes_nothing(tmp_path, monkeypatch, container):
    res = _invoke(tmp_path, monkeypatch, _executor(tags={}), ATOMIC_YAML)
    assert res.exit_code != 0
    assert container.puts == []


def test_a_campaign_run_leaves_its_report_to_the_campaign(tmp_path, monkeypatch, container):
    """The campaign runner's Engine (publish_report left False): a campaign carries its
    runs' reports itself, under campaigns/<id>/ — never twice."""
    monkeypatch.chdir(tmp_path)
    with patch.object(Engine, "_get_executor_collector", return_value=(_executor(), None)), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        outcome = Engine().run(ATOMIC_YAML, skip_confirm=True)
    assert outcome.error is None and (tmp_path / "runs" / f"{outcome.run_id}.json").exists()
    assert [n for n in container.puts if n.startswith("runs/")] == []


# ── H0 pulls the reports ─────────────────────────────────────────────────────────

def test_a_published_report_is_pulled_as_its_run_id(tmp_path, container):
    channel.publish_run(RID, _on_orodruin(tmp_path))
    h0 = _h0(tmp_path)
    assert _pull(h0, container) == (1, {})
    assert json.loads((h0 / f"{RID}.json").read_text()) == _report()
    assert (h0 / channel.PULLED_RUNS / RID).exists()
    assert sorted(p.name for p in h0.iterdir()) == [channel.PULLED_RUNS, f"{RID}.json"]


@pytest.mark.parametrize("body, why", [
    (json.dumps(_report("20261026T000000Z")).encode(), "its run_id is not"),
    (json.dumps({"run_id": RID, "metrics": []}).encode(), "its metrics are not an object"),
    (json.dumps(_report(attack_time="soon")).encode(), "its attack_time is not"),
    (b"<html>not a report</html>", "not JSON"),
])
def test_a_report_of_the_wrong_shape_is_refused_at_the_pull(tmp_path, container, body, why):
    """M243: a malformed report published in the channel never reaches the console."""
    container.put(f"{URL}/runs/{RID}.json", data=body)
    h0 = _h0(tmp_path)
    written, skipped = _pull(h0, container)
    assert written == 0 and why in skipped[RID]
    assert not (h0 / f"{RID}.json").exists() and not (h0 / channel.PULLED_RUNS).exists()


def test_a_report_of_this_host_is_never_written_over(tmp_path, container):
    """M244: a run of H0's own (no marker) keeps its report, whatever the channel holds."""
    channel.publish_run(RID, _on_orodruin(tmp_path))
    h0 = _h0(tmp_path)
    mine = h0 / f"{RID}.json"
    mine.write_text('{"run_id": "%s", "metrics": {}, "result": "MINE"}' % RID)
    os.utime(mine, OLD)                                  # older than the blob
    written, skipped = _pull(h0, container)
    assert written == 0 and "kept" in skipped[RID]
    assert json.loads(mine.read_text())["result"] == "MINE"
    assert f"runs/{RID}.json" not in container.gets       # not even downloaded


def test_a_pulled_report_is_written_again_only_when_it_changed(tmp_path, container):
    runs = _on_orodruin(tmp_path)
    channel.publish_run(RID, runs)
    h0 = _h0(tmp_path)
    _pull(h0, container)
    assert _pull(h0, container) == (0, {})               # the local copy is newer
    (runs / f"{RID}.json").write_text(json.dumps(_report(detection="missed")))
    channel.publish_run(RID, runs)
    os.utime(h0 / f"{RID}.json", OLD)                    # the new blob is the later one
    assert _pull(h0, container) == (1, {})
    assert json.loads((h0 / f"{RID}.json").read_text())["metrics"]["detection"] == "missed"


def test_a_newer_report_of_the_wrong_shape_keeps_the_last_good_one(tmp_path, container):
    channel.publish_run(RID, _on_orodruin(tmp_path))
    h0 = _h0(tmp_path)
    _pull(h0, container)
    container.put(f"{URL}/runs/{RID}.json", data=b"[]")
    os.utime(h0 / f"{RID}.json", OLD)
    written, skipped = _pull(h0, container)
    assert written == 0 and "not a JSON object" in skipped[RID]
    assert json.loads((h0 / f"{RID}.json").read_text()) == _report()


def test_only_the_runs_prefix_is_pulled_and_a_path_never_names_a_file(tmp_path, container):
    for name in (f"{RID}.json", f"campaigns/C1/runs/{RID}.json", f"runs/x/{RID}.json",
                 f"runs/..{RID}.json", f"runs/{RID}.txt", "runs/.hidden.json"):
        container.put(f"{URL}/{name}", data=json.dumps(_report()).encode())
    h0 = _h0(tmp_path)
    assert _pull(h0, container) == (0, {})
    assert list(h0.iterdir()) == [] and container.gets == []
    assert container.listings[-1]["prefix"] == "runs/"


def test_the_windows_pull_never_takes_a_run_report(tmp_path, container):
    channel.publish_run(RID, _on_orodruin(tmp_path))
    windows = tmp_path / "h0" / "runs" / "exercises"
    assert channel.pull(windows, channel=URL, credential=CRED, get=container.get) == 0
    assert list(windows.iterdir()) == []


def test_without_a_channel_no_report_is_pulled(tmp_path):
    assert channel.pull_runs(_h0(tmp_path), refusal=run_report_refusal, channel="") == (0, {})


# ── On H0, the pass of the hosted watch ───────────────────────────────────────────

def test_each_pass_pulls_the_run_reports(tmp_path, container):
    """M245: the thread the hosted watch starts pulls them — the console's only source."""
    channel.publish_run(RID, _on_orodruin(tmp_path))
    h0 = _h0(tmp_path)
    hr.tick(h0, say=lambda m: None)
    assert json.loads((h0 / f"{RID}.json").read_text())["run_id"] == RID


def test_a_refusal_is_said_once_and_never_stops_the_pass(tmp_path, container):
    container.put(f"{URL}/runs/{RID}.json", data=b"[]")
    h0 = _h0(tmp_path)
    said = []
    hr.tick(h0, say=said.append)
    hr.tick(h0, say=said.append)
    assert said == [f"run report {RID} not pulled: refused: not a JSON object"]


def test_a_listing_that_fails_is_said_once_and_the_campaigns_are_still_pulled(tmp_path, container):
    def get(url, headers=None, params=None, timeout=None):
        if params and params.get("prefix") == "runs/":
            return SimpleNamespace(ok=False, status_code=503, content=b"")
        return container.get(url, headers=headers, params=params, timeout=timeout)
    h0 = _h0(tmp_path)
    said = []
    for _ in range(2):
        assert hr.tick(h0, channel=URL, credential=CRED, get=get, say=said.append) == {}
    assert said == ["run reports not pulled: HTTP 503 listing the channel"]
    assert {"restype": "container", "comp": "list", "prefix": "campaigns/"} in container.listings


# ── The console of the atelier, on H0 ─────────────────────────────────────────────

def test_the_console_shows_the_verdict_of_a_run_pulled_from_the_channel(tmp_path, monkeypatch,
                                                                         container):
    """« Fini quand », in code: an `annatar run` on Orodruin, its window and its report pulled
    on H0, and the console's exercise carries its verdict."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    import eregion_console.api as api

    orodruin = tmp_path / "orodruin"
    orodruin.mkdir()
    res = _invoke(orodruin, monkeypatch, _executor(), ATOMIC_YAML)
    assert res.exit_code == 0, res.output

    h0 = _h0(tmp_path)
    channel.pull(h0 / "exercises", channel=URL, credential=CRED, get=container.get)
    hr.tick(h0, say=lambda m: None)
    monkeypatch.chdir(h0.parent)
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    api._cycle_cache.clear()
    exercises = TestClient(api.app).get("/api/exercises").json()["exercises"]
    assert len(exercises) == 1
    run = exercises[0]["run"]
    assert run["result"] == "PASS" and run["mitre"] == "T1136.001"
    assert run["checks"]["initial_state_after"] == "PASS"
    assert run["metrics"]["detection"] == "unknown"     # the wait is mocked: no watch
