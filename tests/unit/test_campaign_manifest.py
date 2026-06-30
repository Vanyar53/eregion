"""Campaign manifest — serialization, atomic save/load, results aggregation."""

import json

import pytest

from annatar.campaign.manifest import (
    Budget,
    CampaignManifest,
    ScenarioEntry,
    Scope,
    campaign_dir,
    new_campaign_id,
)


def _manifest():
    return CampaignManifest(
        campaign_id=new_campaign_id(),
        objective="test kill-chain",
        scope=Scope(allowed_resource_groups=["rg-celebrimbor"]),
        budget=Budget(max_scenarios=3),
        scenarios=[
            ScenarioEntry(
                seq=1, ttp="T1110.001", tactic="credential-access",
                name="bf", scenario_file="scenarios/01.yaml",
                target_resource_id="/subscriptions/s/rg/vm",
            ),
        ],
    )


def test_roundtrip_save_load(tmp_path):
    m = _manifest()
    d = campaign_dir(m.campaign_id, runs_dir=tmp_path)
    path = m.save(d)
    assert path.exists()
    loaded = CampaignManifest.load(d)
    assert loaded.campaign_id == m.campaign_id
    assert loaded.objective == "test kill-chain"
    assert loaded.budget.max_scenarios == 3
    assert loaded.scenarios[0].ttp == "T1110.001"


def test_results_aggregation(tmp_path):
    m = _manifest()
    m.scenarios.append(
        ScenarioEntry(
            seq=2, ttp="T1486", tactic="impact", name="ransom",
            scenario_file="scenarios/02.yaml",
            target_resource_id="/subscriptions/s/rg/vm",
            status="executed", detection="detected",
        )
    )
    m.scenarios[0].status = "executed"
    m.scenarios[0].detection = "missed"
    r = m.results
    assert r["executed"] == 2
    assert r["detected"] == 1
    assert r["missed"] == 1


def test_save_is_atomic_valid_json(tmp_path):
    m = _manifest()
    d = campaign_dir(m.campaign_id, runs_dir=tmp_path)
    path = m.save(d)
    # No stray tmp files left behind
    assert not list(d.glob(".manifest-*"))
    json.loads(path.read_text())  # parses cleanly


def test_set_state_validates():
    m = _manifest()
    m.set_state("ratified")
    assert m.state == "ratified"
    with pytest.raises(ValueError):
        m.set_state("bogus")
