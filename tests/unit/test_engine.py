from __future__ import annotations

import pytest

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from annatar.runner.engine import Engine

_SCENARIOS = Path(__file__).parent.parent.parent / "annatar" / "scenarios" / "azure"
EXFIL_YAML = str(_SCENARIOS / "data-exfiltration.yaml")
RANSOMWARE_YAML = str(_SCENARIOS / "ransomware-vm.yaml")
LATERAL_YAML = str(_SCENARIOS / "lateral-movement.yaml")


def test_parse_duration_seconds():
    assert Engine._parse_duration("300s") == 300.0


def test_parse_duration_minutes():
    assert Engine._parse_duration("10m") == 600.0


def test_parse_duration_hours():
    assert Engine._parse_duration("2h") == 7200.0


def test_parse_duration_plain():
    assert Engine._parse_duration("120") == 120.0


# ── Signal emission integration ───────────────────────────────────────────────

RESOURCE_ID = (
    "/subscriptions/sub-123/resourceGroups/rg-celebrimbor"
    "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)


def _make_executor(tags=None, vm_tags=None):
    executor = MagicMock()
    executor.get_resource_group_tags.return_value = tags or {"annatar-test": "true"}
    executor.get_vm_tags.return_value = vm_tags if vm_tags is not None else {"annatar-test": "true"}
    executor.resource_id = RESOURCE_ID
    executor.run_script.return_value = "INTEGRITY_PASS"
    executor.verify_restore_integrity.return_value = True
    executor.check_preflight.return_value = []
    return executor


def _make_collector():
    return MagicMock()


def test_engine_emits_attack_started_exfil(tmp_path, monkeypatch):
    """data-exfiltration: Annatar emits attack_started — Glorfindel owns detection."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)

    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    assert len(files) == 1
    signals = [json.loads(ln) for ln in files[0].read_text().strip().splitlines() if ln.strip()]
    signal = next(s for s in signals if s["event"] == "attack_started")
    assert signal["ttp"] == "T1041"
    assert signal["severity"] == "high"
    assert signal["provider"] == "azure"
    assert signal["resource_type"] == "vm"
    assert signal["resource_id"] == RESOURCE_ID
    assert "attack_time" in signal["raw_signal"]
    assert "detection_timeout_s" in signal["raw_signal"]
    # detection_query removed — Glorfindel resolves via detection_rules.yaml by TTP


def test_engine_emits_attack_started_ransomware(tmp_path, monkeypatch):
    """ransomware-vm: Annatar emits attack_started — detection and RTO owned by Glorfindel."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    signals = [json.loads(ln) for ln in files[0].read_text().strip().splitlines() if ln.strip()]
    signal = next(s for s in signals if s["event"] == "attack_started")
    assert signal["ttp"] == "T1486"
    raw = signal["raw_signal"]
    assert "attack_time" in raw
    assert "detection_timeout_s" in raw
    # detection_source/workspace_id removed — Glorfindel resolves via detection_rules.yaml


def test_engine_aborts_if_precheck_fails(tmp_path, monkeypatch):
    """Pre-run integrity check failure → engine aborts, no signals emitted."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    executor.verify_restore_integrity.return_value = False
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    assert files == []


def test_engine_aborts_if_preflight_fails(tmp_path, monkeypatch):
    """Preflight issue (VM stopped or isolated) → engine aborts before setup."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    executor.check_preflight.return_value = [
        "VM 'vm-annatar-victim' is not running (PowerState/deallocated)\n"
        "  → az vm start -g annatar -n vm-annatar-victim"
    ]
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    assert files == []
    executor.run_script.assert_not_called()


def test_engine_skip_preflight_bypasses_check(tmp_path, monkeypatch):
    """--skip-preflight lets the run proceed even if the VM would fail the check."""
    monkeypatch.chdir(tmp_path)
    engine = Engine(skip_preflight=True)
    executor = _make_executor()
    executor.check_preflight.return_value = ["VM is not running"]
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)

    executor.check_preflight.assert_not_called()
    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    assert len(files) == 1


# ── SEC3 (#274): no watcher of Glorfindel's state ─────────────────────────────────────

def test_the_injectors_read_nothing_of_glorfindels_state():
    """N-05: the red team's measure stays blind to the blue's — no code of Annatar or Gothmog
    opens a path under ~/.glorfindel (the blocks watcher, `attack_adapted`, is gone). The
    watch's heartbeat is read through eregion_core/watch_gate.py, from the copy the watch
    writes for them (~/.glorfindel/injectors, mounted as their ~/.glorfindel)."""
    root = Path(__file__).resolve().parents[2]
    found = [f"{f.relative_to(root)}:{n}" for d in ("annatar", "gothmog") for f in (root / d).rglob("*.py")
             for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1)
             if '".glorfindel"' in line or "'.glorfindel'" in line or "/.glorfindel/" in line]
    assert found == []
    assert 'event="attack_adapted"' not in (root / "annatar" / "runner" / "engine.py").read_text(encoding="utf-8")


def test_the_injectors_never_read_the_watchs_directory():
    """SEC18 (N-05): no code of Annatar or Gothmog names the watch's directory of runs/, nor the
    console's, nor opens a cycle file of the watch — a run's detection comes through the return
    channel only (the RulePoller watch files were read here until SEC18)."""
    root = Path(__file__).resolve().parents[2]
    words = ("runs_layout.GLORFINDEL", "runs_layout.CONSOLE", '"_debug.jsonl"', "_debug.jsonl\"",
             '"watch-*', "_check_watch_files", '"runs/glorfindel', '"runs/console')
    found = [f"{f.relative_to(root)}:{n}" for d in ("annatar", "gothmog") for f in (root / d).rglob("*.py")
             for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1)
             if any(w in line for w in words)]
    assert found == []


# ── Revue 2026-09 : la porte de sécurité refuse vraiment (RG ET VM) ───────────

def _run_and_list_signals(tmp_path, monkeypatch, executor):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    files = list((tmp_path / "runs" / "annatar").glob("*_signals.jsonl"))
    return outcome, files


def test_engine_refuses_an_untagged_resource_group_and_emits_nothing(tmp_path, monkeypatch):
    executor = _make_executor(tags={"env": "production"})
    outcome, files = _run_and_list_signals(tmp_path, monkeypatch, executor)
    assert outcome.error and "safety" in outcome.error
    assert files == []
    executor.run_script.assert_not_called()


def test_engine_refuses_an_untagged_vm_in_a_tagged_group(tmp_path, monkeypatch):
    """The RG tag alone used to authorize EVERY VM of the group — including an untagged
    production VM sharing it (check_vm existed but had no call site)."""
    executor = _make_executor(vm_tags={"env": "production"})
    outcome, files = _run_and_list_signals(tmp_path, monkeypatch, executor)
    assert outcome.error and "VM missing tag" in outcome.error
    assert files == []
    executor.run_script.assert_not_called()


def test_clean_refuses_an_untagged_vm(monkeypatch):
    """`annatar clean` rewrites the data disk: same gate as `run`."""
    import pytest
    from annatar.runner import initializer

    executor = _make_executor(vm_tags={})
    monkeypatch.setattr("annatar.executors.azure_vm.AzureVMExecutor", lambda target, session=None: executor)
    with pytest.raises(RuntimeError, match="Safety check failed"):
        initializer.InitRunner().clean(EXFIL_YAML)
    executor.run_script.assert_not_called()


# ── O0 : inscription, zone et règle de production à l'exécution ──────────────

PROD_TAGS = {"eregion-target": "celebrimbor", "eregion-zone": "production"}


def _run(tmp_path, monkeypatch, executor, scenario):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        return engine.run(scenario, skip_confirm=True)


def test_engine_refuses_a_destructive_scenario_in_production(tmp_path, monkeypatch):
    """T1486 is destructive in the catalog: never on a production target."""
    executor = _make_executor(tags=PROD_TAGS, vm_tags=PROD_TAGS)
    outcome = _run(tmp_path, monkeypatch, executor, RANSOMWARE_YAML)
    assert outcome.error and "destructive technique never runs in production" in outcome.error
    executor.run_script.assert_not_called()


def test_engine_runs_a_non_destructive_scenario_in_production(tmp_path, monkeypatch):
    """T1041 is declared non-destructive: detection-only in production is allowed (J1)."""
    executor = _make_executor(tags=PROD_TAGS, vm_tags=PROD_TAGS)
    _run(tmp_path, monkeypatch, executor, EXFIL_YAML)
    executor.run_script.assert_called()


def test_engine_refuses_a_target_outside_the_bench_groups(tmp_path, monkeypatch):
    """Enrolled by its tags, but the resource group is not the bench's."""
    executor = _make_executor()
    executor.resource_id = RESOURCE_ID.replace("rg-celebrimbor", "rg-prod-payments")
    outcome = _run(tmp_path, monkeypatch, executor, EXFIL_YAML)
    assert outcome.error and "outside Celebrimbor" in outcome.error
    executor.run_script.assert_not_called()


def test_clean_refuses_a_production_target(monkeypatch):
    """`clean` rewrites the data disk: destructive, never in production."""
    from annatar.runner import initializer

    executor = _make_executor(tags=PROD_TAGS, vm_tags=PROD_TAGS)
    monkeypatch.setattr("annatar.executors.azure_vm.AzureVMExecutor", lambda target, session=None: executor)
    import pytest
    with pytest.raises(RuntimeError, match="never runs in production"):
        initializer.InitRunner().clean(EXFIL_YAML)
    executor.run_script.assert_not_called()


def test_scenario_destructive_is_the_catalog_s_word():
    """SEC5 (V-19): the catalog decides, unknown is destructive, and a scenario may only make
    itself stricter — saying « not destructive » against the catalog is refused."""
    from types import SimpleNamespace

    from annatar.runner.engine import scenario_destructive

    def sc(raw, mitre):
        return SimpleNamespace(raw=raw, mitre=mitre)

    destructive, lie = scenario_destructive(sc({"destructive": False}, "T1486"))
    assert destructive is True and "the catalog decides" in lie
    assert scenario_destructive(sc({}, "T1486")) == (True, "")
    assert scenario_destructive(sc({}, "T1041")) == (False, "")
    assert scenario_destructive(sc({"destructive": True}, "T1041")) == (True, "")
    assert scenario_destructive(sc({}, "T9999")) == (True, "")
    assert scenario_destructive(sc({"destructive": "no"}, "T9999")) == (True, "")
    destructive, lie = scenario_destructive(sc({"destructive": False}, "T9999"))
    assert destructive is True and "unknown is destructive" in lie


def test_a_local_script_run_writes_the_unified_run_format(tmp_path, monkeypatch):
    """C1 (M1800): the run's report says it is an attack, by Annatar, of its technique — the
    format Gothmog shares (eregion_core/run_report.py), read the same by the console."""
    from eregion_core.run_report import RUN_FORMAT, read_run
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_make_executor(), _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    m = report["metrics"]
    assert (m["run_format"], m["kind"], m["injector"], m["experiment_id"]) == (RUN_FORMAT, "technique", "annatar", "T1041")
    assert m["resource_id"] == RESOURCE_ID      # M1887: the VM the watch's decision is attached on
    run = read_run(report)
    assert run["kind"] == "technique" and run["experiment"] == "T1041" and run["at"] == m["attack_time"]


# SEC11 (R-19): the bench's scope names its subscription (Scope.for_bench reads it) — the one of
# this file's targets; conftest removes the operator's.
@pytest.fixture(autouse=True)
def _bench_subscription(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")
