"""BL1 (#280) — the time to contain and the share contained alone, computed from a campaign's
traces (analysis/containment.py), published in the campaign report and the console.

Two parts:
- the definitions, edge case by edge case, on hand-written debug lines and cards: no
  detection, an action a guard held, an escalation, an action that failed, a verification that
  failed, an isolation that did not hold, a decision unknown, a fault taken for an attack;
- a campaign replayed end to end: the injectors simulated (their run reports, their exercise
  windows, the campaign's manifest, as Annatar and Gothmog write them), Glorfindel's real graph
  deciding (the model mocked) and acting on the in-memory Azure of the invariant machine
  (tests/unit/fake_azure.py), its reassertion seeing an isolation removed — then the two
  indicators read back from the files, by the report and by the console.

No Azure, no model: runs/ under tmp, every store redirected (conftest). Mutants M1770–M1789.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from analysis import containment as ct

VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
OTHER = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"
T0 = 1_800_000_000.0     # an attack time (epoch)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _line(action="isolate_vm", *, seen=T0 + 60, at=T0 + 90, verified_at=T0 + 85, executed=True,
          verified=True, status="isolated", escalation_type="", escalate=False, resource=VM,
          ttp="T1136.001", signal_id="sig-1", unverified=False, mode="non_disruptive",
          confidence=0.9) -> dict:
    """A debug line of the watch, as store_cycle writes it."""
    outcome = {"status": status, "executed": executed, "verified": verified}
    if verified_at is not None:
        outcome["verified_at"] = _iso(verified_at)
    if escalation_type:
        outcome["escalation_type"] = escalation_type
    if unverified:
        outcome["unverified"] = True
    return {"timestamp": _iso(at), "action": action, "confidence": confidence, "escalate": escalate,
            "resolved_autonomy_mode": mode, "outcome": outcome,
            "signal": {"event": "detection", "ttp": ttp, "resource_id": resource,
                       "signal_id": signal_id, "timestamp": _iso(seen)}}


def _held(kind, action="isolate_vm"):
    return _line(action, executed=False, verified=None, verified_at=None, status="escalated",
                 escalation_type=kind, escalate=True)


def _card(kind="verification_failed", at=T0 + 300, resource=VM):
    return {"escalation_type": kind, "resource_id": resource, "timestamp": _iso(at),
            "signal_id": "reassert-vm-celebrimbor-gondolin-x", "action": "isolate_vm"}


def _inc(decision, detection="detected", t0=T0, until=None, cards=(), why=""):
    return ct.incident("r1", "T1136.001", VM, t0, detection, decision, why, until, cards)


# ── 1. Contained alone, and its time ─────────────────────────────────────────────────────

def test_contained_alone_is_executed_in_the_cycle_verified_and_timed_to_the_read_back():
    """M1770, M1771: the end is the read-back on Azure (verified_at), not the cycle's line written
    after it (memory, notification) — and the time starts at T0, the injector's attack time."""
    i = _inc(_line(verified_at=T0 + 85, at=T0 + 140))
    assert i.outcome == ct.CONTAINED and i.time_to_contain_s == 85.0
    assert i.contained_at == T0 + 85


def test_a_line_without_verified_at_ends_at_the_cycle_line():
    """Records written before BL1: the cycle's own line, written just after the check."""
    i = _inc(_line(verified_at=None, at=T0 + 140))
    assert i.outcome == ct.CONTAINED and i.time_to_contain_s == 140.0


def test_a_block_contains_as_an_isolation_does():
    i = _inc(_line("block_suspicious_ip", status="blocked"))
    assert i.outcome == ct.CONTAINED


def test_a_read_back_before_the_attack_says_the_time_is_unknown():
    """Two hosts' clocks: never a negative time, never a guessed one."""
    i = _inc(_line(verified_at=T0 - 5, at=T0 - 1))
    assert i.outcome == ct.CONTAINED and i.time_to_contain_s is None and "horloges" in i.why


def test_without_attack_time_contained_but_untimed():
    i = _inc(_line(), t0=None)
    assert i.outcome == ct.CONTAINED and i.time_to_contain_s is None and "attack_time" in i.why


# ── 2. Every other ending, said ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("decision, outcome", [
    (_line(verified=False), ct.VERIFICATION_FAILED),                       # read back false
    (_line(verified=None, unverified=True), ct.VERIFICATION_FAILED),       # could not be read
    (_line(verified=True, unverified=True), ct.VERIFICATION_FAILED),
    (_held("mode_hold"), ct.HELD),                                          # human_only
    (_held("readiness_hold"), ct.HELD),
    (_held("uncharacterized_signal"), ct.HELD),                             # signal guard
    (_held("telemetry_gap"), ct.HELD),
    (_held("low_confidence"), ct.ESCALATED),
    (_held("cycle_failed"), ct.ESCALATED),
    (_line(executed=False, verified=None, status="write_blocked", escalation_type="write_blocked",
           escalate=True), ct.ACTION_FAILED),
    (_line(executed=False, verified=None, status="action_failed", escalation_type="action_failed",
           escalate=True), ct.ACTION_FAILED),
    (_line("snapshot", status="snapshot_created", verified=None), ct.NOT_CONTAINING),
    (_held("low_confidence", action="snapshot"), ct.NOT_CONTAINING),
    (_line(status="dry_run", verified=None), ct.DRY_RUN),
])
def test_every_other_ending_is_not_contained_alone(decision, outcome):
    """M1772, M1773, M1774, M1775: an action held by a guard or escalated is a human's; one that
    failed, or whose check failed or could not be read, contained nothing that can be said; a
    snapshot contains nothing; a dry run acted on nothing."""
    i = _inc(decision)
    assert i.outcome == outcome and i.time_to_contain_s is None


def test_a_missed_run_is_an_incident_never_contained():
    """M1776: missed — nobody contained it, even if a decision lies around."""
    i = _inc(_line(), detection="missed")
    assert i.outcome == ct.MISSED and i.time_to_contain_s is None


def test_a_decision_not_found_is_unknown_and_makes_the_share_a_lower_bound():
    """M1777: an unknown is not « not contained »: the share says « at least »."""
    unknown = _inc({}, why="fenêtre absente")
    assert unknown.outcome == ct.UNKNOWN and unknown.why == "fenêtre absente"
    c = ct.compute([_inc(_line()), unknown])
    assert c.share == 0.5 and c.lower_bound is True
    assert "au moins 1 sur 2" in "\n".join(ct.render(c))


# ── 3. An isolation that did not hold ─────────────────────────────────────────────────────

def test_a_reassertion_card_after_the_read_back_means_it_did_not_hold():
    """M1778: rules removed (re-applied once or not) or bypassed — not contained alone."""
    for kind in ("verification_failed", "bypassed"):
        i = _inc(_line(), cards=[_card(kind)])
        assert i.outcome == ct.NOT_HOLDING and i.why == kind and i.time_to_contain_s is None


@pytest.mark.parametrize("card, until", [
    (_card(at=T0 + 50), None),                 # before the read-back
    (_card(resource=OTHER), None),             # another VM
    (_card(at=T0 + 85 + ct.HOLD_WATCH_S + 60), None),   # after the watch, no window
    (_card(at=T0 + 600), T0 + 500),            # after the window (or the next run on the VM)
    (_card(kind="mode_hold"), None),           # not a card of the reassertion
])
def test_a_card_elsewhere_or_later_does_not_undo_a_containment(card, until):
    """M1779: only that VM, from the read-back to the end of the window."""
    assert _inc(_line(), until=until, cards=[card]).outcome == ct.CONTAINED


def test_resource_ids_compare_without_case():
    i = _inc(_line(resource=VM.lower()), cards=[_card(resource=VM.upper())])
    assert i.outcome == ct.NOT_HOLDING


# ── 4. The campaign's figures ─────────────────────────────────────────────────────────────

def test_the_share_is_over_every_incident_and_the_time_a_median_of_the_contained():
    """M1780, M1781: missed and held runs count in the share; only the contained in the time."""
    c = ct.compute([
        _inc(_line(verified_at=T0 + 60)), _inc(_line(verified_at=T0 + 100)),
        _inc(_line(verified_at=T0 + 200)), _inc(_held("mode_hold")),
        _inc(_line(), detection="missed"),
    ])
    assert len(c.contained) == 3 and c.share == pytest.approx(3 / 5) and c.lower_bound is False
    assert c.median_s == 100.0
    s = c.summary()
    assert s["by_outcome"] == {ct.CONTAINED: 3, ct.HELD: 1, ct.MISSED: 1}


def test_nothing_contained_says_none_never_zero():
    c = ct.compute([_inc(_held("mode_hold"))])
    assert c.median_s is None and c.share == 0.0
    assert "aucun incident contenu seul" in "\n".join(ct.render(c))
    assert ct.compute([]).share is None


# ── 5. A fault taken for an attack ────────────────────────────────────────────────────────

FS, FE = T0 - 3000, T0 - 2700           # the fault, before the technique


def _fault(records, **kw):
    return ct.fault_run("g1", "vm-shutdown", [VM], _iso(FS), _iso(FE), records, **kw)


def test_a_disruptive_decision_on_a_fault_target_during_it_is_counted_apart():
    """M1782, M1783: recommended or executed, an isolation on the faulted VM during the fault
    is a fault taken for an attack — never an incident; executed, a disruptive action wrongly
    taken."""
    rec = _line(seen=FS + 120, at=FS + 150, verified_at=FS + 140, signal_id="sig-f")
    held = _held("low_confidence")
    held["signal"].update(timestamp=_iso(FS + 200), signal_id="sig-g")
    f = _fault([rec, held])
    assert [m["signal_id"] for m in f.mistaken] == ["sig-f", "sig-g"] and f.executed == 1
    c = ct.compute([_inc(_line())], [f])
    assert c.share == 1.0 and len(c.incidents) == 1
    assert c.summary()["faults_mistaken"] == 1 and c.summary()["disruptive_on_faults"] == 1
    assert "prise pour une attaque" in "\n".join(ct.render(c))


@pytest.mark.parametrize("rec", [
    _line(seen=FS + 120, resource=OTHER),                     # another VM
    _line(seen=FS - 60),                                      # before the fault
    _line(seen=FE + ct.HOLD_WATCH_S + 60),                    # after it and its grace
    _line("snapshot", seen=FS + 120, verified=None),          # nothing disruptive
    _line(seen=FS + 120, signal_id="sig-1"),                  # an incident's own decision
])
def test_what_is_not_a_fault_taken_for_an_attack(rec):
    """M1784: the faulted VMs only, during the fault's window, a decision to isolate or to block,
    never one an incident already took."""
    assert _fault([rec], taken={"sig-1"}).mistaken == []


def test_a_fault_that_cannot_be_checked_says_why():
    assert "début inconnu" in ct.fault_run("g1", "f", [VM], None, _iso(FE), []).why
    assert "Glorfindel" in _fault([], without_glorfindel=True).why
    assert _fault([_line(seen=FS + 60)], window_until=_iso(FS + 30)).mistaken == []   # the window bounds


# ── 6. A campaign replayed end to end ──────────────────────────────────────────────────────

class _Memory:
    def __init__(self, path=None):
        pass

    def retrieve_similar(self, signal, n=3):
        return []

    def store(self, cycle):
        pass


class _Law:
    def run_query(self, query, timespan=None):
        return []


def _llm(action: str, confidence: float):
    call = MagicMock()
    call.function.arguments = json.dumps({
        "reasoning": f"{action}.", "confidence": confidence, "action": action, "reversible": True,
        "explanation": f"{action} recommended.", "escalate": False, "escalation_reason": "",
        "suggested_steps": []})
    resp = MagicMock()
    resp.choices[0].message.tool_calls = [call]
    resp.usage = None
    return resp


@pytest.fixture()
def bench(tmp_path, monkeypatch):
    """The bench: gondolin in the in-memory Azure, a real connector on it, the watch's runs/ in
    tmp, no webhook, no bot, no model endpoint."""
    for var in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "GLORFINDEL_LLM_BASE_URL",
                "GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_READ_ONLY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    import glorfindel.agent as agent
    import glorfindel.escalations as escalations
    from glorfindel.actions import AzureConnector
    from tests.unit.fake_azure import FakeAzure
    monkeypatch.setattr(agent, "CycleMemory", _Memory)
    monkeypatch.setattr(escalations, "notify_action", lambda **kw: None)
    fake = FakeAzure()
    nsg = fake.add_nsg("rg-celebrimbor", "nsg-gondolin")
    subnet = fake.add_subnet("rg-celebrimbor", "vnet-celebrimbor", "default", None)
    vm = fake.add_vm("rg-celebrimbor", "vm-celebrimbor-gondolin",
                     [{"rg": "rg-celebrimbor", "name": "nic-gondolin", "ips": ["10.0.0.4"],
                       "subnet": subnet, "nsg": nsg}])
    conn = AzureConnector(dry_run=False)
    conn._network, conn._compute = fake.network, fake.compute
    conn._subscription_id = "s"
    conn.recent_changes = lambda *a, **k: []
    (tmp_path / "runs" / "campaigns" / "C1").mkdir(parents=True)
    return {"fake": fake, "conn": conn, "vm": vm, "runs": tmp_path / "runs",
            "cdir": tmp_path / "runs" / "campaigns" / "C1", "nsg": nsg}


def _watch(conn, mode="non_disruptive"):
    from glorfindel.agent import GlorfindelAgent
    from glorfindel.config import AutonomyConfig
    return GlorfindelAgent(connector=conn, memory_path="unused", incidents_path="incidents.jsonl",
                           model="anthropic/claude-test", dry_run=False,
                           autonomy=AutonomyConfig(default=mode),
                           readiness_gate=lambda vm, rid, configured: (configured, {}))


def _detect(agent, vm, *, action="isolate_vm", confidence=0.9, ttp="T1136.001", n=[0]):
    """The RulePoller's detection of a new local account on gondolin, decided by the graph."""
    n[0] += 1
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%S") + f"{n[0]:03d}Z"
    signal = {
        "signal_id": f"rule-t1136-{n[0]:04d}", "event": "detection", "ttp": ttp,
        "severity": "high", "resource_id": vm, "resource_type": "vm", "timestamp": now.isoformat(),
        "context": {"workspace_id": "ws-bench", "attribution": "asset",
                    "rule_name": "t1136-001-local-account-creation-linux-v1",
                    "run_id": f"watch-t1136-001-local-account-creation-linux-v1-{stamp}"},
        "raw_signal": {"first_result_row": {
            "Computer": "vm-celebrimbor-gondolin", "_ResourceId": vm.lower(), "Facility": "authpriv",
            "ProcessName": "useradd",
            "SyslogMessage": "new user: name=evil_user, UID=999, GID=999, home=/home/evil_user, shell=/bin/bash"}},
    }
    with patch("litellm.completion", return_value=_llm(action, confidence)), \
            patch("glorfindel.detectors.detector_for", return_value=_Law()):
        return agent.respond(signal)


def _technique_run(b, rid, seq, detect=None):
    """Annatar's side, simulated: its window, its T0, the attack, its report — and, with
    ``detect``, the watch's detection of it while the window is open."""
    from eregion_core import exercise
    exercise.open_window(rid, injector="annatar", kind="technique", experiment="account-creation-atomic",
                         targets=[b["vm"]], destructive=False)
    started = datetime.now(timezone.utc)
    t0 = time.time()
    time.sleep(0.01)
    final = detect() if detect else None
    exercise.close_window(rid)
    (b["runs"] / f"{rid}.json").write_text(json.dumps({
        "scenario": "account-creation-atomic", "run_id": rid, "mitre": "T1136.001", "result": "PASS",
        "metrics": {"attack_time": t0, "detection": "detected" if detect else "missed",
                    "detection_latency_s": 1.0 if detect else None},
        "thresholds": {}, "checks": {}}))
    return {"seq": seq, "ttp": "T1136.001", "tactic": "persistence", "name": "Create Account",
            "scenario_file": f"scenarios/{seq:02d}.yaml", "target_resource_id": b["vm"],
            "status": "executed", "run_id": rid, "detection": "detected" if detect else "missed",
            "detection_latency_s": 1.0 if detect else None, "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat()}, final


def test_a_campaign_replayed_gives_both_indicators_and_the_fault_apart(bench):
    """BL1 on the in-memory bench: a fault Glorfindel takes for an attack (low confidence, held),
    then three runs of the technique — one contained alone (isolated, read back, released by the
    recovery), one whose isolation someone removes (the reassertion says it, re-applies it once:
    not contained alone), one missed. Read back by the report and the console: 1 of 3, the time
    to the read-back, the fault counted apart and said."""
    from eregion_core import exercise
    from gothmog.runner.report import RunReport
    from glorfindel.reassert import reassert_pass
    from glorfindel.config import AutonomyConfig
    b = bench
    agent = _watch(b["conn"])
    vm = b["vm"]

    # The fault (Gothmog, simulated): its window, a detection on the stopped VM decided at low
    # confidence (escalated, nothing executed) — taken for an attack all the same.
    exercise.open_window("gothmog-1", injector="gothmog", kind="fault", experiment="vm-shutdown",
                         targets=[vm], destructive=False)
    f_start = datetime.now(timezone.utc)
    time.sleep(0.01)
    noise = _detect(agent, vm, action="isolate_vm", confidence=0.3)
    assert noise["outcome"]["executed"] is False
    f_end = datetime.now(timezone.utc)
    exercise.close_window("gothmog-1")
    RunReport(scenario="VM shutdown", run_id="gothmog-1", mitre="", result="PASS",
              metrics={"injector": "gothmog", "fault": "vm-shutdown", "targets": [vm],
                       "fault_start": f_start.isoformat(), "fault_end": f_end.isoformat()},
              thresholds={}, checks={}).save(b["runs"])

    # Incident 1: isolated alone, read back on Azure, then the recovery releases it.
    s1, final1 = _technique_run(b, "r1", 1, detect=lambda: _detect(agent, vm))
    assert final1["outcome"]["executed"] is True and final1["outcome"]["verified"] is True
    assert b["conn"].release_isolation(vm)["status"] != "release_partial"

    # Incident 2: isolated alone (the quarantine NSG on its NIC), then someone puts the NIC's
    # own NSG back; the watch's reassertion says the isolation is gone.
    def isolate_then_tampered():
        final = _detect(agent, vm)
        for nic in b["fake"].nics.values():
            nic["nsg"] = nic["design_nsg"]
        reassert_pass(b["conn"], autonomy=AutonomyConfig(default="non_disruptive"))
        return final
    s2, final2 = _technique_run(b, "r2", 2, detect=isolate_then_tampered)
    assert final2["outcome"]["verified"] is True
    b["conn"].release_isolation(vm)

    # Incident 3: missed.
    s3, _ = _technique_run(b, "r3", 3)

    (b["cdir"] / "manifest.json").write_text(json.dumps({
        "campaign_id": "C1", "objective": "declared: bl1-reponse", "state": "done",
        "scenarios": [s1, s2, s3]}))

    c = ct.load(b["cdir"])
    by = {i.run_id: i for i in c.incidents}
    assert by["r1"].outcome == ct.CONTAINED and by["r1"].action == "isolate_vm"
    # The end is the graph's own read-back stamp (verify_action), not the line written after it.
    assert by["r1"].contained_at == ct._ts(final1["outcome"]["verified_at"])
    assert 0 < by["r1"].time_to_contain_s < 60
    assert by["r2"].outcome == ct.NOT_HOLDING
    assert by["r3"].outcome == ct.MISSED
    assert c.share == pytest.approx(1 / 3) and c.median_s == by["r1"].time_to_contain_s
    assert len(c.faults) == 1 and c.faults[0].attached == ct.AROUND
    assert [m["action"] for m in c.faults[0].mistaken] == ["isolate_vm"] and c.faults[0].executed == 0

    # The report (IA0) renders it, computed — the model mocked out.
    from analysis import campaign_report as cr
    with patch.object(cr, "write_claims", return_value=([], "fake/model")):
        report = cr.build(b["cdir"])
    md = cr.render(report)
    assert "**Part contenue seule : 1 sur 3**" in md and "prise pour une attaque" in md
    assert "contenu, puis l'isolation n'a pas tenu" in md

    # The console's campaign page reads the same.
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import eregion_console.api as api
    from .console_client import console
    monkeypatch_runs = patch.object(api, "_RUNS", b["runs"])
    with monkeypatch_runs:
        body = console().get("/api/campaigns/C1").json()
    s = body["containment"]["summary"]
    assert (s["contained"], s["incidents"], s["faults_mistaken"]) == (1, 3, 1)
    assert s["median_s"] == by["r1"].time_to_contain_s
