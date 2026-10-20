"""R1 — the Atomic Red Team adapter: the vendored definitions are read faithfully, anything
the adapter cannot run faithfully is refused, and a run verifies the initial state before and
after the atomic's own cleanup. No Azure, no LLM (dry_run / mocked executor)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from annatar.engines.atomic import AtomicError, parse_ref, resolve_ref
from annatar.runner.engine import Engine
from annatar.runner.parser import ScenarioParser

_SCENARIOS = Path(__file__).parent.parent.parent / "annatar" / "scenarios" / "azure"
ATOMIC_YAML = str(_SCENARIOS / "account-creation-atomic.yaml")
LINUX_GUID = "40d8eabd-e394-46f6-8785-b9bfa1d011d2"   # Create a user account on a Linux system
MACOS_GUID = "01993ba5-1da3-4e15-a719-b690d4f0f0b2"   # dscl — platform macos
WINDOWS_GUID = "6657864e-0323-4206-9344-ac9cd7265a4f"  # net user — platform windows
KUBECTL_GUID = "d9efa6c7-6518-42b2-809a-4f2a8e242b9b"  # has dependencies

RESOURCE_ID = (
    "/subscriptions/sub-123/resourceGroups/rg-celebrimbor"
    "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)


# ── A temp atomics tree, to exercise the guards deterministically ─────────────────────

def _atomics_dir(tmp_path: Path, tests: list[dict]) -> Path:
    d = tmp_path / "atomics" / "T9999"
    d.mkdir(parents=True)
    (d.parent / "T9999" / "T9999.yaml").write_text(
        yaml.safe_dump({"attack_technique": "T9999", "atomic_tests": tests}),
        encoding="utf-8",
    )
    return tmp_path / "atomics"


def _shell_test(guid="g1", **executor) -> dict:
    ex = {"name": "bash", "command": "echo hi\n", "cleanup_command": "echo bye\n"}
    ex.update(executor)
    return {
        "name": "t",
        "auto_generated_guid": guid,
        "supported_platforms": ["linux"],
        "input_arguments": {},
        "executor": ex,
    }


# ── parse_ref / resolve_ref on the vendored definition ────────────────────────────────

def test_parse_ref_requires_technique_and_guid():
    assert parse_ref("T1136.001/" + LINUX_GUID) == ("T1136.001", LINUX_GUID)
    for bad in ("", "T1136.001", "T1136.001/", "/guid", "a/b/c"):
        with pytest.raises(AtomicError):
            parse_ref(bad)


def test_resolve_vendored_linux_test():
    r = resolve_ref("T1136.001/" + LINUX_GUID)
    assert r.guid == LINUX_GUID
    assert r.executor == "bash"
    assert r.command == "useradd -M -N -r -s /bin/bash -c evil_account evil_user"
    assert r.cleanup_command == "userdel evil_user"
    assert r.args == {"username": "evil_user"}


def test_resolve_overrides_input_argument():
    r = resolve_ref("T1136.001/" + LINUX_GUID, args={"username": "mallory"})
    assert r.command.endswith("mallory")
    assert r.cleanup_command == "userdel mallory"
    assert r.substitute("id #{username}") == "id mallory"


def test_unknown_guid_lists_known():
    with pytest.raises(AtomicError) as e:
        resolve_ref("T1136.001/does-not-exist")
    assert LINUX_GUID in str(e.value)


def test_missing_technique_file():
    with pytest.raises(AtomicError):
        resolve_ref("T0000/whatever")


def test_refuses_non_linux():
    """A macOS / Windows test is not ours to run on gondolin (M75)."""
    for guid in (MACOS_GUID, WINDOWS_GUID):
        with pytest.raises(AtomicError):
            resolve_ref("T1136.001/" + guid)


def test_refuses_dependencies():
    """A test with prereqs is out of scope for R1 (M-guard)."""
    with pytest.raises(AtomicError):
        resolve_ref("T1136.001/" + KUBECTL_GUID)


def test_refuses_non_shell_executor(tmp_path):
    d = _atomics_dir(tmp_path, [_shell_test(guid="ps", name="powershell")])
    with pytest.raises(AtomicError):
        resolve_ref("T9999/ps", atomics_dir=d)


def test_refuses_without_cleanup(tmp_path):
    """No cleanup_command → refused: R1 never leaves the target changed (M77)."""
    t = _shell_test(guid="noclean")
    t["executor"]["cleanup_command"] = ""
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError):
        resolve_ref("T9999/noclean", atomics_dir=d)


def test_refuses_unresolved_placeholder(tmp_path):
    """A #{var} with no default and no override is refused, never sent raw (M76)."""
    t = _shell_test(guid="ph")
    t["executor"]["command"] = "useradd #{username} #{extra}\n"
    t["input_arguments"] = {"username": {"default": "evil_user"}}
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError):
        resolve_ref("T9999/ph", atomics_dir=d)


# ── The shipped experiment resolves (the engine_ref points at a vendored test) ─────────

def test_shipped_atomic_experiment_resolves():
    s = ScenarioParser().load(ATOMIC_YAML)
    assert s.engine == "atomic"
    assert s.steps == []
    r = resolve_ref(s.engine_ref)
    assert r.guid == LINUX_GUID


# ── Engine integration (mocked executor, armed by hermetic_orodruin) ──────────────────

def _atomic_executor(probe_outputs=("USER_ABSENT", "USER_ABSENT")):
    """A MagicMock executor whose run_command returns the probe outputs in order (before,
    after); the atomic command and cleanup outputs are ignored."""
    from unittest.mock import MagicMock

    executor = MagicMock()
    executor.get_resource_group_tags.return_value = {"annatar-test": "true"}
    executor.get_vm_tags.return_value = {"annatar-test": "true"}
    executor.resource_id = RESOURCE_ID
    executor.check_preflight.return_value = []
    before, after = probe_outputs
    # Order of run_command: before-probe, atomic command, cleanup, after-probe.
    executor.run_command.side_effect = [before, "", "", after]
    return executor


def _run_atomic(tmp_path, monkeypatch, executor):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        return engine.run(ATOMIC_YAML, skip_confirm=True)


def _commands_run(executor) -> list[str]:
    return [c.args[0] for c in executor.run_command.call_args_list]


def test_atomic_run_emits_attack_started(tmp_path, monkeypatch):
    executor = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, executor)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1
    signals = [json.loads(ln) for ln in files[0].read_text().splitlines() if ln.strip()]
    started = next(s for s in signals if s["event"] == "attack_started")
    assert started["ttp"] == "T1136.001"
    assert started["resource_id"] == RESOURCE_ID
    assert "attack_time" in started["raw_signal"]


def test_atomic_runs_command_then_cleanup(tmp_path, monkeypatch):
    """The atomic's own command and cleanup_command are both run, in order (M78)."""
    executor = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, executor)

    cmds = _commands_run(executor)
    assert "useradd -M -N -r -s /bin/bash -c evil_account evil_user" in cmds
    assert "userdel evil_user" in cmds
    assert cmds.index("useradd -M -N -r -s /bin/bash -c evil_account evil_user") < cmds.index(
        "userdel evil_user"
    )


def test_atomic_records_initial_state_restored(tmp_path, monkeypatch):
    executor = _atomic_executor(probe_outputs=("USER_ABSENT", "USER_ABSENT"))
    _run_atomic(tmp_path, monkeypatch, executor)

    report = json.loads(
        next((tmp_path / "runs").glob("2*.json")).read_text()
    )
    assert report["checks"]["initial_state_before"] == "PASS"
    assert report["checks"]["initial_state_after"] == "PASS"
    assert report["metrics"]["initial_state_restored"] is True


def test_atomic_flags_return_not_restored(tmp_path, monkeypatch):
    """Cleanup left the user behind → the return is reported FAIL, never assumed (M79)."""
    executor = _atomic_executor(probe_outputs=("USER_ABSENT", "USER_PRESENT"))
    _run_atomic(tmp_path, monkeypatch, executor)

    report = json.loads(next((tmp_path / "runs").glob("2*.json")).read_text())
    assert report["checks"]["initial_state_after"] == "FAIL"
    assert report["result"] == "FAIL"


def test_atomic_refuses_dirty_start(tmp_path, monkeypatch):
    """The user already exists before the run → nothing attacked, no attack_started (M80)."""
    executor = _atomic_executor(probe_outputs=("USER_PRESENT", "USER_ABSENT"))
    _run_atomic(tmp_path, monkeypatch, executor)

    assert "useradd -M -N -r -s /bin/bash -c evil_account evil_user" not in _commands_run(executor)
    assert list((tmp_path / "runs").glob("*_signals.jsonl")) == []


def test_atomic_refuses_when_cap_too_low(tmp_path, monkeypatch):
    """A cap below the calls a run needs (command + cleanup + probes) is refused."""
    from types import SimpleNamespace

    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _atomic_executor()
    scenario = ScenarioParser().load(ATOMIC_YAML)
    session = SimpleNamespace(max_injections=1)
    outcome = engine._run_atomic_enrolled(scenario, executor, "runid", session)
    assert outcome.error and "cap" in outcome.error
    executor.run_command.assert_not_called()


def test_atomic_dry_run_shows_command_and_cleanup(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Engine(dry_run=True).run(ATOMIC_YAML, skip_confirm=True)
    out = capsys.readouterr().out
    assert "useradd" in out and "userdel" in out
    assert list((tmp_path / "runs").glob("*_signals.jsonl")) == []
