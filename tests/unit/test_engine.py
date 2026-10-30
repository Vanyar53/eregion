from __future__ import annotations

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

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
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

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
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

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
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

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
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
    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1


# ── RulePoller watch-file detection ──────────────────────────────────────────

def _watch_record(ttp: str, seen: float, rid: str = RESOURCE_ID) -> dict:
    from datetime import datetime, timezone

    return {"signal": {"event": "detection", "ttp": ttp, "resource_id": rid,
                       "timestamp": datetime.fromtimestamp(seen, timezone.utc).isoformat()}}


def test_check_watch_files_finds_matching_detection(tmp_path):
    """_check_watch_files returns the latency when a watch file has a match after the attack."""
    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-sudo-privilege-escalation-20260601T134025Z_debug.jsonl"
    watch_file.write_text(json.dumps(_watch_record("T1548.003", 1000.0 + 42)) + "\n")

    engine = Engine()
    result = engine._check_watch_files("T1548.003", RESOURCE_ID, 1000.0, runs_dir=runs)
    assert result == 42.0


def test_check_watch_files_matches_the_watch_lower_case_resource_id(tmp_path):
    """The watch writes Log Analytics' _ResourceId in lower case; Annatar emits ARM's
    casing. Measured on the bench (20/10): compared as is, every RulePoller detection was
    a miss (M98). Both casings, both ways."""
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "watch-a_debug.jsonl").write_text(
        json.dumps(_watch_record("T1136.001", 1000.0 + 10, rid=RESOURCE_ID.lower())) + "\n")
    assert Engine._check_watch_files("T1136.001", RESOURCE_ID, 1000.0, runs_dir=runs) == 10.0
    assert Engine._check_watch_files("T1136.001", RESOURCE_ID.lower(), 1000.0, runs_dir=runs) == 10.0
    assert Engine._check_watch_files("T1136.001", RESOURCE_ID.upper(), 1000.0, runs_dir=runs) == 10.0


def test_check_watch_files_ignores_wrong_ttp(tmp_path):
    """_check_watch_files ignores files whose TTP does not match."""
    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-something-20260601T000000Z_debug.jsonl"
    watch_file.write_text(json.dumps(_watch_record("T1041", 1000.0 + 5)) + "\n")

    engine = Engine()
    result = engine._check_watch_files("T1548.003", RESOURCE_ID, 1000.0, runs_dir=runs)
    assert result is None


def test_check_watch_files_ignores_files_older_than_the_attack(tmp_path):
    """A file last written before the attack holds no detection of it."""
    import time as _time

    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-old-20260101T000000Z_debug.jsonl"
    attack = _time.time() + 120  # beyond the file system clock's slack
    watch_file.write_text(json.dumps(_watch_record("T1548.003", attack + 5)) + "\n")

    engine = Engine()
    result = engine._check_watch_files("T1548.003", RESOURCE_ID, attack, runs_dir=runs)
    assert result is None


def test_check_watch_files_ignores_a_detection_before_the_attack(tmp_path):
    """Same TTP, same VM, but seen before the attack: an earlier run's (M99)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "watch-a_debug.jsonl").write_text(json.dumps(_watch_record("T1548.003", 900.0)) + "\n")
    assert Engine._check_watch_files("T1548.003", RESOURCE_ID, 1000.0, runs_dir=runs) is None


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


# ── Revue 2026-09 : la porte de sécurité refuse vraiment (RG ET VM) ───────────

def _run_and_list_signals(tmp_path, monkeypatch, executor):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
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
    report = json.loads(next((tmp_path / "runs").glob("2*.json")).read_text())
    m = report["metrics"]
    assert (m["run_format"], m["kind"], m["injector"], m["experiment_id"]) == (RUN_FORMAT, "technique", "annatar", "T1041")
    assert m["resource_id"] == RESOURCE_ID      # M1887: the VM the watch's decision is attached on
    run = read_run(report)
    assert run["kind"] == "technique" and run["experiment"] == "T1041" and run["at"] == m["attack_time"]
