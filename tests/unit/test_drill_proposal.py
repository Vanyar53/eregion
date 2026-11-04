"""DG-e (#351): Annatar's proposals as drills, in the shared core (eregion_core/proposal.py) — the
chain « Ask Annatar for a drill » lays, and a campaign's drill.

The chain: the catalogue's implemented techniques that say they destroy nothing, in kill-chain
order, at most the bound — never a destructive one, never one whose catalogue does not say
(an undeclared entry is never taken as harmless), never a fault, never another resource's.
A campaign's drill: Annatar its author, named after the campaign, read by the drill's one reader.

The core alone: no Annatar, no console, no Azure, no model.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from eregion_core import drill as dr
from eregion_core import proposal
from eregion_core.exercise_plan import Experiment, load_catalog


def _e(eid, tactic, *, destructive=False, status="implemented", kind="technique", rtype="azure_vm"):
    return Experiment(id=eid, kind=kind, name=eid, resource_type=rtype, status=status,
                      destructive=destructive, engine="local-script", tactic=tactic)


CATALOG = {e.id: e for e in (
    _e("T1486", "impact", destructive=True),                       # destroys data: never
    _e("T1041", "exfiltration"),
    _e("T1110.001", "credential-access"),
    _e("T1136.001", "persistence"),
    _e("T1548.003", "privilege-escalation"),
    _e("T1059.004", "execution"),
    _e("T1070.002", "defense-evasion", destructive=None),          # undeclared: never harmless
    _e("T1078", "initial-access", status="planned"),               # nothing runs it yet
    _e("vm-shutdown", "", kind="fault"),                           # Gothmog's
    _e("T1530", "collection", rtype="azure_storage"),              # not a VM's
)}


def test_the_chain_is_the_kill_chain_of_what_runs_and_destroys_nothing():
    assert proposal.chain(CATALOG, max_wires=10) == ["T1059.004", "T1136.001", "T1548.003", "T1110.001", "T1041"]


def test_the_chain_takes_the_first_of_the_kill_chain_within_its_bound():
    assert proposal.chain(CATALOG, max_wires=2) == ["T1059.004", "T1136.001"]
    assert proposal.chain(CATALOG, max_wires=0) == ["T1059.004"], "one at least"
    assert len(proposal.chain({f"T9{i:03d}": _e(f"T9{i:03d}", "execution") for i in range(150)},
                              max_wires=10_000)) == dr.MAX_WIRES


def test_the_chain_takes_only_what_runs_here_when_said():
    assert proposal.chain(CATALOG, max_wires=10, available={"T1041", "T1486", "T1136.001"}) == ["T1136.001", "T1041"]


@pytest.mark.parametrize("eid", ["T1486", "T1070.002", "T1078", "vm-shutdown", "T1530"])
def test_the_chain_never_takes_a_destructive_an_undeclared_a_planned_a_fault_or_another_resource(eid):
    assert eid not in proposal.chain(CATALOG, max_wires=100)


def test_the_shipped_catalogue_gives_a_chain_of_harmless_vm_techniques():
    catalog = load_catalog()
    ids = proposal.chain(catalog)
    assert 1 <= len(ids) <= proposal.DEFAULT_WIRES
    assert all(catalog[i].destructive is False and catalog[i].kind == "technique"
               and catalog[i].resource_type == "azure_vm" for i in ids)
    ranks = [proposal.tactic_rank(catalog[i].tactic) for i in ids]
    assert ranks == sorted(ranks)


NOW = datetime(2026, 11, 4, 10, 15, tzinfo=timezone.utc)


def test_a_campaigns_drill_is_annatars_named_after_it_and_read_as_any_drill(tmp_path):
    d = proposal.campaign_drill("20261104T101500Z", [("vm-shutdown", "vm-celebrimbor-gondolin"),
                                                     ("T1136.001", "vm-celebrimbor-gondolin")],
                                objective="declared: bl1-reponse\nsecond line", now=NOW)
    assert (d.name, d.author, d.layer) == ("annatar-20261104t101500z", "annatar", dr.INSTANCE)
    assert d.description == "declared: bl1-reponse second line"
    assert [(w.experiment, w.name) for w in d.wires] == [("vm-shutdown", "vm-celebrimbor-gondolin"),
                                                         ("T1136.001", "vm-celebrimbor-gondolin")]
    path = tmp_path / f"{d.name}.yaml"
    path.write_text(dr.to_yaml(d), encoding="utf-8")
    assert dr.load_file(path, dr.INSTANCE) == d


def test_a_campaign_past_the_drills_ceiling_is_no_drill():
    with pytest.raises(dr.DrillRefused):
        proposal.campaign_drill("20261104T101500Z", [(f"T9{i:03d}", "vm-a") for i in range(dr.MAX_WIRES + 1)])
