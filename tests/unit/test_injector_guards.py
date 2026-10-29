"""SEC5 (#276): the injectors held at their edges — Annatar's side.

- V-18: a run refused before it touched its target (zone, inscription, production rule) is
  never reset, and the campaign stops there for that target — the manifest says so;
- V-19: destructive is the catalog's word (the technique, its pinned source), never the
  scenario's; unknown is destructive;
- N-03: the gate « never without Glorfindel » is read again before each action of a run, and
  `annatar clean` goes through it;
- N-04: `--without-glorfindel` is refused in zone production, and written to Orodruin's journal;
- V-30: a vendored atomic is checked against its sha256 at run time, not only in CI.

No Azure, no LLM: the executor is a mock, Orodruin's contract the conftest's (armed), the
watch the conftest's (live) unless a test says otherwise. Mutants M1260–M1279
(scripts/mutation_check.py) are measured here and in test_injector_channels.py.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

import eregion_core.orodruin as orodruin
import eregion_core.watch_gate as gate
from annatar.campaign.catalog import catalog_destructive
from annatar.campaign.manifest import Budget, CampaignManifest, ScenarioEntry, Scope, campaign_dir
from annatar.campaign.runner import REFUSED_NO_RESET, CampaignRunner
from annatar.engines.atomic import ATOMICS_DIR, AtomicError, resolve_ref
from annatar.runner.engine import Engine, RunOutcome

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "annatar" / "scenarios" / "azure"
EXFIL = SCENARIOS / "data-exfiltration.yaml"
RANSOM = SCENARIOS / "ransomware-vm.yaml"
ATOMIC = SCENARIOS / "account-creation-atomic.yaml"
GUID = "40d8eabd-e394-46f6-8785-b9bfa1d011d2"
RID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor"
       "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
BENCH_TAGS = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}
PROD_TAGS = {"eregion-target": "celebrimbor", "eregion-zone": "production"}


def _executor(tags=BENCH_TAGS):
    ex = MagicMock()
    ex.resource_id = RID
    ex.get_resource_group_tags.return_value = dict(tags)
    ex.get_vm_tags.return_value = dict(tags)
    ex.check_preflight.return_value = []
    ex.verify_restore_integrity.return_value = True
    ex.run_script.return_value = ""

    def run_command(cmd, label=""):
        if "(effect)" in label:
            return "USER_PRESENT"
        return "USER_ABSENT"
    ex.run_command.side_effect = run_command
    return ex


def _run(tmp_path, monkeypatch, scenario, executor, **engine_kw):
    monkeypatch.chdir(tmp_path)
    engine = Engine(**engine_kw)
    with patch.object(Engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        return engine.run(str(scenario), skip_confirm=True)


def _variant(tmp_path, source: Path, name="variant.yaml", **changes) -> Path:
    doc = yaml.safe_load(source.read_text())
    doc.update(changes)
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc))
    return path


def _audit() -> list[dict]:
    path = orodruin.audit_path()
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ── V-18: a refused target is never reset ─────────────────────────────────────────────

class _Engine:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), []

    def run(self, path, skip_confirm=False):
        self.calls.append(path)
        return self.outcomes.pop(0)


def _campaign(tmp_path, entries, budget=None):
    m = CampaignManifest(campaign_id="C1", objective="t",
                         scope=Scope(allowed_resource_groups=["rg-celebrimbor"]),
                         budget=budget or Budget(max_scenarios=5), scenarios=entries,
                         state="ratified")
    cdir = campaign_dir("C1", runs_dir=tmp_path)
    m.save(cdir)
    return cdir


def _entry(seq, ttp="T1041", target=RID, destructive=False, scenario_file=None):
    return ScenarioEntry(seq=seq, ttp=ttp, tactic="exfiltration", name=ttp,
                         scenario_file=scenario_file or f"scenarios/{seq:02d}.yaml",
                         target_resource_id=target, destructive=destructive)


def test_a_target_the_engine_refuses_is_never_reset_and_never_run_again(tmp_path):
    """M1260: the target's zone refused the run — no reset after it, and the next
    scenarios on that target are skipped, the manifest saying why."""
    cdir = _campaign(tmp_path, [_entry(1), _entry(2), _entry(3)])
    engine = _Engine([RunOutcome("r1", "unknown", error="safety: a destructive technique never "
                                 "runs in production", refused=True)])
    resets = []
    m = CampaignRunner(cdir, reset_fn=lambda rid: resets.append(rid) or "reset",
                       engine_factory=lambda: engine).run()
    assert resets == []
    assert len(engine.calls) == 1
    first, *rest = m.scenarios
    assert first.status == "error" and first.reset == REFUSED_NO_RESET
    for e in rest:
        assert e.status == "skipped" and e.reset == REFUSED_NO_RESET
        assert e.error.startswith("target refused earlier in this campaign: safety:")
    saved = json.loads((cdir / "manifest.json").read_text())
    assert saved["scenarios"][0]["reset"] == REFUSED_NO_RESET


def test_a_run_that_touched_its_target_is_still_reset(tmp_path):
    """The control: an error after the target was touched keeps its reset."""
    cdir = _campaign(tmp_path, [_entry(1), _entry(2)])
    engine = _Engine([RunOutcome("r1", "unknown", error="initial state not restored"),
                      RunOutcome("r2", "detected")])
    resets = []
    m = CampaignRunner(cdir, reset_fn=lambda rid: resets.append(rid) or "reset",
                       engine_factory=lambda: engine).run()
    assert resets == [RID, RID] and m.scenarios[1].status == "executed"


def test_the_real_engine_marks_its_refusal_and_the_campaign_resets_nothing(tmp_path, monkeypatch):
    """The engine's own refusal (a VM not enrolled) reaches the campaign as one."""
    cdir = _campaign(tmp_path, [_entry(1, scenario_file="scenarios/exfil.yaml")])
    (cdir / "scenarios").mkdir()
    shutil.copy(EXFIL, cdir / "scenarios" / "exfil.yaml")
    executor = _executor(tags={})
    resets = []
    monkeypatch.chdir(tmp_path)
    with patch.object(Engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        m = CampaignRunner(cdir, reset_fn=lambda rid: resets.append(rid) or "reset").run()
    assert m.scenarios[0].error.startswith("safety:") and resets == []
    executor.run_script.assert_not_called()


# ── V-19: the catalog decides what is destructive ─────────────────────────────────────

def test_a_scenario_that_calls_a_destructive_technique_harmless_is_refused(tmp_path, monkeypatch):
    """M1262: T1486 is destructive in the catalog; a scenario saying `destructive: false`
    does not make it run in production — and it is refused on the bench too: it lies."""
    lying = _variant(tmp_path, RANSOM, destructive=False)
    for tags in (PROD_TAGS, BENCH_TAGS):
        executor = _executor(tags)
        out = _run(tmp_path, monkeypatch, lying, executor)
        assert out.refused and out.error.startswith("safety:") and "the catalog decides" in out.error
        executor.run_script.assert_not_called()


def test_a_script_the_catalog_does_not_name_is_destructive(tmp_path, monkeypatch):
    """M1263: a scenario that says T1041 (harmless in the catalog) but runs T1486's script is
    not what the catalog vouched for: unknown, so destructive — never in production."""
    doc = yaml.safe_load(EXFIL.read_text())
    doc["steps"][0]["script"] = "scripts/vm/ransomware_sim.sh"
    doc.pop("destructive", None)
    path = tmp_path / "swapped.yaml"
    path.write_text(yaml.safe_dump(doc))
    executor = _executor(PROD_TAGS)
    out = _run(tmp_path, monkeypatch, path, executor)
    assert out.refused and "destructive technique never runs in production" in out.error
    executor.run_script.assert_not_called()


def test_an_atomic_the_catalog_does_not_pin_is_unknown():
    assert catalog_destructive("T1136.001", engine="atomic",
                               engine_ref=f"T1136.001/{GUID}") is False
    assert catalog_destructive("T1136.001", engine="atomic", engine_ref="T1136.001/other") is None
    assert catalog_destructive("T1136.001", engine="stratus", engine_ref=f"T1136.001/{GUID}") is None
    assert catalog_destructive("T9999") is None
    assert catalog_destructive("T1041", scripts=["scripts/vm/exfil_sim.sh"]) is False
    assert catalog_destructive("T1041", scripts=["scripts/vm/other.sh"]) is None


def _scenario_file(cdir: Path, name: str, source: Path) -> str:
    (cdir / "scenarios").mkdir(exist_ok=True)
    shutil.copy(source, cdir / "scenarios" / name)
    return f"scenarios/{name}"


def test_a_hand_edited_manifest_cannot_call_a_destructive_technique_harmless(tmp_path):
    """M1264: the campaign's destructive policy reads the scenario the run will play — not the
    manifest's flag, nor its ttp. Here the manifest says T1041, not destructive; the file is
    T1486's ransomware: skipped without allow_destructive."""
    cdir = _campaign(tmp_path, [])
    m = CampaignManifest.load(cdir)
    m.scenarios = [_entry(1, ttp="T1041", destructive=False,
                          scenario_file=_scenario_file(cdir, "01.yaml", RANSOM))]
    m.save(cdir)
    engine = _Engine([RunOutcome("r1", "detected")])
    m = CampaignRunner(cdir, reset_fn=lambda rid: "reset", engine_factory=lambda: engine).run()
    assert engine.calls == []
    assert m.scenarios[0].status == "skipped" and "allow_destructive" in m.scenarios[0].error


def test_the_campaign_runs_what_its_file_says_is_harmless(tmp_path):
    """The control: the file is T1041's exfiltration — it runs, whatever the manifest's ttp."""
    cdir = _campaign(tmp_path, [])
    m = CampaignManifest.load(cdir)
    m.scenarios = [_entry(1, ttp="T1486", scenario_file=_scenario_file(cdir, "01.yaml", EXFIL))]
    m.save(cdir)
    engine = _Engine([RunOutcome("r1", "detected")])
    m = CampaignRunner(cdir, reset_fn=lambda rid: "reset", engine_factory=lambda: engine).run()
    assert len(engine.calls) == 1 and m.scenarios[0].status == "executed"


def test_an_engine_that_raised_resets_nothing_and_says_so(tmp_path):
    """M1450 (V-18): an engine that raised gives no proof it touched the target, nor that its
    zone allows a reset — none, and the manifest says to do it by hand if needed."""
    class Raises:
        def run(self, path, skip_confirm=False):
            raise RuntimeError("tags unreadable")
    cdir = _campaign(tmp_path, [_entry(1), _entry(2)])
    resets = []
    m = CampaignRunner(cdir, reset_fn=lambda rid: resets.append(rid) or "reset",
                       engine_factory=lambda: Raises()).run()
    assert resets == []
    assert all(e.status == "error" and e.reset.startswith("not run: the engine raised") for e in m.scenarios)


def test_a_passive_contract_is_a_refusal(tmp_path, monkeypatch):
    """Orodruin passive: nothing touched — RunOutcome.refused, so a campaign resets nothing."""
    import annatar.runner.engine as engine_module
    monkeypatch.setattr(engine_module, "arm", lambda run_id, injector: (
        orodruin.Verdict(orodruin.PASSIVE, [orodruin._miss("network_open", "1.1.1.1:443")]), None))
    executor = _executor()
    out = _run(tmp_path, monkeypatch, EXFIL, executor)
    assert out.refused is True and out.error.startswith("passive:")
    executor.get_vm_tags.assert_not_called()


def test_the_window_says_what_the_catalog_says(tmp_path, monkeypatch):
    """The exercise window carries the catalog's destructiveness (read by the watch, V-20)."""
    _run(tmp_path, monkeypatch, EXFIL, _executor())
    from eregion_core.exercise import exercises_dir
    (window,) = [json.loads(p.read_text()) for p in exercises_dir().glob("*.json")]
    assert window["destructive"] is False


# ── N-03: the gate read again before each action; `annatar clean` behind it ──────────

def _dying_watch(monkeypatch, live_reads: int):
    """The conftest's live watch for the first ``live_reads`` reads, then none."""
    live, reads = gate.READERS["local"], []

    def local():
        reads.append(1)
        return live() if len(reads) <= live_reads else gate.Beat(gate.LOCAL, None, "stopped")
    monkeypatch.setitem(gate.READERS, "local", local)
    return reads


def test_a_watch_that_dies_between_two_steps_stops_the_run(tmp_path, monkeypatch):
    """M1265: read at the start and before each step — gone after the first step, the second
    never runs; the outcome is a « glorfindel: » error, which aborts a campaign."""
    doc = yaml.safe_load(EXFIL.read_text())
    doc["steps"] = [doc["steps"][0], {**doc["steps"][0], "name": "second"}]
    path = tmp_path / "two-steps.yaml"
    path.write_text(yaml.safe_dump(doc))
    _dying_watch(monkeypatch, live_reads=2)   # the start, the first step
    executor = _executor()
    out = _run(tmp_path, monkeypatch, path, executor)
    assert executor.run_script.call_count == 1
    assert out.error.startswith("glorfindel: lost during the run")
    assert not list((tmp_path / "runs").glob("*_signals.jsonl")) or \
        "attack_started" not in next((tmp_path / "runs").glob("*_signals.jsonl")).read_text()


def test_a_watch_gone_before_the_atomic_s_command_runs_nothing(tmp_path, monkeypatch):
    """The atomic's command waits for the gate too — nothing ran, nothing to clean."""
    _dying_watch(monkeypatch, live_reads=1)
    executor = _executor()
    out = _run(tmp_path, monkeypatch, ATOMIC, executor)
    assert out.error.startswith("glorfindel: lost during the run")
    labels = [c.kwargs.get("label", "") for c in executor.run_command.call_args_list]
    assert not [label for label in labels if label.startswith("atomic ")]


def test_clean_goes_through_the_gate_before_the_cloud(monkeypatch):
    """M1267: `annatar clean` rewrites a disk — no live watch, no clean, nothing armed."""
    from annatar.runner import initializer
    monkeypatch.setitem(gate.READERS, "local", lambda: gate.Beat(gate.LOCAL, None, "no file"))
    armed, executor = [], _executor()
    monkeypatch.setattr(orodruin, "arm", lambda *a, **k: armed.append(a))
    monkeypatch.setattr("annatar.executors.azure_vm.AzureVMExecutor",
                        lambda target, session=None: executor)
    with pytest.raises(RuntimeError, match="no live Glorfindel watch"):
        initializer.InitRunner().clean(str(RANSOM))
    assert armed == []
    executor.run_script.assert_not_called()


def test_clean_without_glorfindel_runs_and_is_journaled(monkeypatch):
    from annatar.runner import initializer
    monkeypatch.setitem(gate.READERS, "local", lambda: gate.Beat(gate.LOCAL, None, "no file"))
    executor = _executor()
    monkeypatch.setattr("annatar.executors.azure_vm.AzureVMExecutor",
                        lambda target, session=None: executor)
    initializer.InitRunner().clean(str(RANSOM), without_glorfindel=True)
    executor.run_script.assert_called_once()
    assert [r["action"] for r in _audit() if r["outcome"] == "declared"] == ["without_glorfindel"]


def test_a_live_watch_of_another_subscription_is_no_watch(tmp_path, monkeypatch):
    """M1268: fresh, but its perimeter is another subscription's — refused before the cloud."""
    other = gate.perimeter("00000000-0000-0000-0000-0000000000ff")
    beat = gate.READERS["local"]()
    monkeypatch.setitem(gate.READERS, "local",
                        lambda: gate.Beat(gate.LOCAL, beat.at, perimeter=other))
    executor = _executor()
    out = _run(tmp_path, monkeypatch, EXFIL, executor)
    assert out.refused and "another subscription" in out.error
    executor.get_vm_tags.assert_not_called()


# ── N-04: --without-glorfindel never in production, and in Orodruin's journal ────────

def test_a_run_without_glorfindel_is_refused_in_production(tmp_path, monkeypatch):
    """M1269: T1041 is allowed in production — but not as a development run."""
    executor = _executor(PROD_TAGS)
    out = _run(tmp_path, monkeypatch, EXFIL, executor, without_glorfindel=True)
    assert out.refused and "never runs in zone production" in out.error
    executor.run_script.assert_not_called()
    executor = _executor(PROD_TAGS)
    assert not _run(tmp_path, monkeypatch, EXFIL, executor).error   # with Glorfindel: it runs
    executor.run_script.assert_called()


def test_a_run_without_glorfindel_is_written_to_orodruins_journal(tmp_path, monkeypatch):
    """M1270: in the journal, before the first call — not only in the run's report."""
    out = _run(tmp_path, monkeypatch, EXFIL, _executor(), without_glorfindel=True)
    records = [r for r in _audit() if r["run_id"] == out.run_id]
    assert records[0]["outcome"] == "declared" and records[0]["action"] == "without_glorfindel"
    assert records[0]["detail"] == gate.NOT_MEASURED
    assert not [r for r in _audit() if r["outcome"] == "declared"
                and r["run_id"] != out.run_id]


# ── V-30: the atomics' sha256, checked at run time ────────────────────────────────────

def _vendored(tmp_path) -> Path:
    d = tmp_path / "atomics"
    shutil.copytree(ATOMICS_DIR, d)
    return d


def test_the_vendored_atomic_resolves_against_its_pin(tmp_path):
    assert resolve_ref(f"T1136.001/{GUID}", atomics_dir=_vendored(tmp_path)).guid == GUID


def test_an_edited_atomic_is_refused_at_run_time(tmp_path):
    """M1271: one byte changed in the image — the PIN no longer matches: refused."""
    d = _vendored(tmp_path)
    path = d / "T1136.001" / "T1136.001.yaml"
    path.write_text(path.read_text() + "\n# edited\n")
    with pytest.raises(AtomicError, match="does not match its sha256"):
        resolve_ref(f"T1136.001/{GUID}", atomics_dir=d)


def test_an_atomic_the_pin_does_not_list_is_refused(tmp_path):
    d = _vendored(tmp_path)
    pin = d / "PIN"
    pin.write_text("\n".join(line for line in pin.read_text().splitlines()
                             if "T1136.001/T1136.001.yaml" not in line))
    with pytest.raises(AtomicError, match="has no sha256"):
        resolve_ref(f"T1136.001/{GUID}", atomics_dir=d)


def test_an_edited_atomic_never_reaches_the_target(tmp_path, monkeypatch):
    d = _vendored(tmp_path)
    path = d / "T1136.001" / "T1136.001.yaml"
    path.write_text(path.read_text().replace("useradd", "userdel"))
    monkeypatch.setattr("annatar.engines.atomic.ATOMICS_DIR", d)
    executor = _executor()
    out = _run(tmp_path, monkeypatch, ATOMIC, executor)
    assert out.refused and out.error.startswith("atomic:") and "sha256" in out.error
    executor.run_command.assert_not_called()
