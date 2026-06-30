"""Unit tests for campaign replay (étape 5 — auto-activation + replay verdict).

Builds real campaign manifests via annatar.campaign.manifest, injects a fake detector
and proposals → zero Azure, zero LLM, zero ~/.glorfindel writes.
"""
import json
from unittest.mock import patch

from annatar.campaign.manifest import (
    Budget, CampaignManifest, ScenarioEntry, Scope, campaign_dir,
)
from glorfindel import campaign_replay as cr


class _Detector:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def run_query(self, query):
        self.queries.append(query)
        return self.rows


def _scenario(seq, ttp, *, detection, run_id, status="executed"):
    return ScenarioEntry(
        seq=seq, ttp=ttp, tactic="t", name=f"s{seq}",
        scenario_file=f"scenarios/{seq:02d}.yaml", target_resource_id="/sub/rg/vm",
        status=status, run_id=run_id, detection=detection,
    )


def _campaign(tmp_path, scenarios):
    m = CampaignManifest(
        campaign_id="20260630T200000Z", objective="test",
        scope=Scope(), budget=Budget(), scenarios=scenarios,
    )
    m.save(campaign_dir(m.campaign_id, tmp_path))
    return m.campaign_id


def _proposal(run_id, ttp, query="Syslog | take 1", pid="p1"):
    return {"id": pid, "run_id": run_id, "ttp": ttp, "query": query, "status": "pending"}


# ── proposal matching ─────────────────────────────────────────────────────────

def test_proposal_for_scenario_matches_run_id_first():
    s = _scenario(1, "T1486", detection="missed", run_id="r1")
    props = [_proposal("rX", "T1486", pid="bad"), _proposal("r1", "T9999", pid="good")]
    assert cr.proposal_for_scenario(s, props)["id"] == "good"  # run_id beats ttp


def test_proposal_for_scenario_falls_back_to_ttp():
    s = _scenario(1, "T1486", detection="missed", run_id="r1")
    props = [_proposal("rX", "T1486", pid="byttp")]
    assert cr.proposal_for_scenario(s, props)["id"] == "byttp"


def test_proposal_for_scenario_none_when_no_match():
    s = _scenario(1, "T1486", detection="missed", run_id="r1")
    assert cr.proposal_for_scenario(s, [_proposal("rX", "T9999")]) is None


# ── replay ───────────────────────────────────────────────────────────────────

def test_replay_only_missed_scenarios(tmp_path):
    cid = _campaign(tmp_path, [
        _scenario(1, "T1486", detection="detected", run_id="r1"),
        _scenario(2, "T1041", detection="missed", run_id="r2"),
    ])
    doc = cr.replay_campaign(
        cid, runs_dir=tmp_path, detector=_Detector([{"x": 1}]),
        proposals=[_proposal("r2", "T1041")], write=False,
    )
    assert [r["seq"] for r in doc["replays"]] == [2]  # detected one skipped


def test_replay_would_have_caught_true(tmp_path):
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    det = _Detector([{"PutBlobCount": 3}])
    doc = cr.replay_campaign(
        cid, runs_dir=tmp_path, detector=det,
        proposals=[_proposal("r2", "T1041", query="StorageBlobLogs | take 1")], write=False,
    )
    r = doc["replays"][0]
    assert r["would_have_caught"] is True
    assert r["proposed_rule_id"] == "p1"
    assert "StorageBlobLogs | take 1" in det.queries[0]


def test_replay_still_misses_when_query_returns_nothing(tmp_path):
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    doc = cr.replay_campaign(
        cid, runs_dir=tmp_path, detector=_Detector([]),
        proposals=[_proposal("r2", "T1041")], write=False,
    )
    assert doc["replays"][0]["would_have_caught"] is False


def test_replay_no_proposal_for_miss(tmp_path):
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    doc = cr.replay_campaign(cid, runs_dir=tmp_path, detector=_Detector([{"x": 1}]),
                             proposals=[], write=False)
    r = doc["replays"][0]
    assert r["would_have_caught"] is None
    assert "no proposed rule" in r["detail"]


def test_replay_no_detector_is_not_replayed(tmp_path):
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    doc = cr.replay_campaign(cid, runs_dir=tmp_path, detector=None,
                             proposals=[_proposal("r2", "T1041")], write=False)
    r = doc["replays"][0]
    assert r["would_have_caught"] is None
    assert r["proposed_rule_id"] == "p1"  # still recorded which rule it would replay


def test_replay_query_failure_is_caught(tmp_path):
    class Boom:
        def run_query(self, q):
            raise RuntimeError("workspace unreachable")
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    doc = cr.replay_campaign(cid, runs_dir=tmp_path, detector=Boom(),
                             proposals=[_proposal("r2", "T1041")], write=False)
    r = doc["replays"][0]
    assert r["would_have_caught"] is False
    assert "query failed" in r["detail"]


def test_replay_writes_replay_json(tmp_path):
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])
    cr.replay_campaign(cid, runs_dir=tmp_path, detector=_Detector([{"x": 1}]),
                       proposals=[_proposal("r2", "T1041")], write=True)
    path = campaign_dir(cid, tmp_path) / "replay.json"
    assert path.exists()
    saved = json.loads(path.read_text())
    assert saved["campaign_id"] == cid
    assert saved["replays"][0]["would_have_caught"] is True


def test_runner_to_replay_end_to_end(tmp_path):
    """Red→blue handoff in-process (zero Azure): Annatar's CampaignRunner fills the
    manifest with a missed scenario → Glorfindel's replay consumes it and verdicts the
    proposed rule. Guards against format drift between the two sessions' code."""
    from annatar.campaign.runner import CampaignRunner
    from annatar.runner.engine import RunOutcome

    target = ("/subscriptions/s/resourceGroups/rg-celebrimbor/providers/"
              "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
    scen = ScenarioEntry(
        seq=1, ttp="T1041", tactic="exfiltration", name="exfil",
        scenario_file="scenarios/01.yaml", target_resource_id=target, status="pending",
    )
    m = CampaignManifest(
        campaign_id="20260630T210000Z", objective="e2e",
        scope=Scope(allowed_resource_groups=["rg-celebrimbor"],
                    allowed_resource_ids=[target]),
        budget=Budget(reset_nsg_between=False), scenarios=[scen], state="ratified",
    )
    cdir = campaign_dir(m.campaign_id, tmp_path)
    m.save(cdir)

    class _FakeEngine:  # returns a MISSED outcome — no Azure, no real attack
        def run(self, path, skip_confirm=False):
            return RunOutcome(run_id="rc-e2e", detection="missed")

    CampaignRunner(
        cdir, reset_fn=lambda rid: None, engine_factory=lambda: _FakeEngine(),
    ).run()

    # The runner persisted the miss with its run_id — the bridge my replay reads.
    s = CampaignManifest.load(cdir).scenarios[0]
    assert s.detection == "missed" and s.run_id == "rc-e2e"

    doc = cr.replay_campaign(
        m.campaign_id, runs_dir=tmp_path, detector=_Detector([{"x": 1}]),
        proposals=[_proposal("rc-e2e", "T1041")], write=False,
    )
    assert doc["replays"][0]["run_id"] == "rc-e2e"
    assert doc["replays"][0]["would_have_caught"] is True


def test_replay_campaign_cli_dry_run(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from glorfindel.cli import cli
    from glorfindel import proposed_rules as _pr

    monkeypatch.setattr(_pr, "_STORE", tmp_path / "proposed_rules.jsonl")
    cid = _campaign(tmp_path, [_scenario(1, "T1041", detection="missed", run_id="r2")])

    # Stub the detector so the CLI makes zero Azure calls.
    with patch("glorfindel.detectors.detector_for",
               return_value=_Detector([{"x": 1}])), \
         patch("glorfindel.proposed_rules.all_proposals",
               return_value=[_proposal("r2", "T1041")]):
        result = CliRunner().invoke(
            cli, ["replay-campaign", cid, "--runs-dir", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "T1041" in result.output
    assert not (campaign_dir(cid, tmp_path) / "replay.json").exists()  # dry-run wrote nothing
