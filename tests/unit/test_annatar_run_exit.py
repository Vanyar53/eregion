"""#158 — `annatar run` exits non-zero on every refusal and on every error after the target
was touched; 0 only for a run that went through. Driven through the real CLI and the real
Engine (mocked executor, contract armed by the hermetic_orodruin fixture). No Azure, no LLM.

Each refusal of the issue is covered: Orodruin passive, target not enrolled, dirty start,
an atomic the adapter will not run faithfully — plus the « initial state not restored »
error, which is never a success. Mutants M103–M108 (scripts/mutation_check.py).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

import eregion_core.orodruin as orodruin
from annatar.cli import EXIT_OK, cli, run_exit_code
from annatar.runner.engine import Engine, RunOutcome

_SCENARIOS = Path(__file__).parent.parent.parent / "annatar" / "scenarios" / "azure"
ATOMIC_YAML = str(_SCENARIOS / "account-creation-atomic.yaml")
EXFIL_YAML = str(_SCENARIOS / "data-exfiltration.yaml")
MACOS_GUID = "01993ba5-1da3-4e15-a719-b690d4f0f0b2"   # dscl — platform macos

RESOURCE_ID = (
    "/subscriptions/sub-123/resourceGroups/rg-celebrimbor"
    "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
ENROLLED = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}


def _executor(before="USER_ABSENT", effect="USER_PRESENT", after="USER_ABSENT",
              tags=ENROLLED, preflight=(), command_raises=False):
    """A MagicMock executor: probes answer per phase (before / effect / after), the atomic
    command and its cleanup return "" (or the command raises)."""
    executor = MagicMock()
    executor.get_resource_group_tags.return_value = dict(tags)
    executor.get_vm_tags.return_value = dict(tags)
    executor.resource_id = RESOURCE_ID
    executor.check_preflight.return_value = list(preflight)
    executor.verify_restore_integrity.return_value = True
    executor.run_script.return_value = ""

    def side_effect(cmd, label=""):
        if label.startswith("atomic ") and not label.endswith("cleanup") and command_raises:
            raise RuntimeError("RunCommand failed after all retries")
        for phase, answer in (("(before)", before), ("(effect)", effect), ("(after)", after)):
            if phase in label:
                return answer
        return ""

    executor.run_command.side_effect = side_effect
    return executor


def _invoke(tmp_path, monkeypatch, executor, *args):
    """`annatar run <args> --yes` through Click, the Engine's target and wait mocked."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANNATAR_DEBUG", raising=False)
    with patch.object(Engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        return CliRunner().invoke(cli, ["run", *args, "--yes"])


def _variant(tmp_path, **changes) -> str:
    doc = yaml.safe_load(Path(ATOMIC_YAML).read_text())
    doc.update(changes)
    p = tmp_path / "experiment.yaml"
    p.write_text(yaml.safe_dump(doc))
    return str(p)


def _attacked(executor) -> bool:
    return any("useradd" in c.args[0] for c in executor.run_command.call_args_list)


# ── The control: a run that went through exits 0 ──────────────────────────────────────

def test_a_clean_atomic_run_exits_zero(tmp_path, monkeypatch):
    executor = _executor()
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code == 0, res.output
    assert _attacked(executor)
    assert "✗ run" not in res.output


def test_a_dry_run_exits_zero(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(cli, ["run", ATOMIC_YAML, "--dry-run", "--yes"])
    assert res.exit_code == 0, res.output


# ── Each refusal of the issue → non-zero ──────────────────────────────────────────────

def test_passive_orodruin_exits_nonzero(tmp_path, monkeypatch):
    """Orodruin's contract passive (an operator's laptop): nothing touched, exit != 0 (M104)."""
    monkeypatch.setattr(orodruin, "READERS", {
        "identity": lambda: [], "cap": lambda: ([], {"max_injections": 20, "max_run_s": 3600}),
        "network": lambda: [orodruin._miss("network_open", "x")]})
    executor = _executor()
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code != 0
    assert "passive" in res.output
    executor.run_command.assert_not_called()
    assert "Traceback" not in res.output


def test_target_not_enrolled_exits_nonzero(tmp_path, monkeypatch):
    """A VM without its inscription tags is refused, exit != 0 (M105)."""
    executor = _executor(tags={})
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code != 0
    assert "safety" in res.output
    assert not _attacked(executor)


def test_dirty_start_exits_nonzero(tmp_path, monkeypatch):
    """The before-probe is broken (the user already exists): nothing run, exit != 0 (M106)."""
    executor = _executor(before="USER_PRESENT")
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code != 0
    assert "not clean" in res.output
    assert not _attacked(executor)


def test_unfaithful_atomic_exits_nonzero(tmp_path, monkeypatch):
    """An atomic the adapter refuses (a macOS test on a Linux VM), exit != 0 (M107)."""
    path = _variant(tmp_path, engine_ref=f"T1136.001/{MACOS_GUID}")
    executor = _executor()
    res = _invoke(tmp_path, monkeypatch, executor, path)
    assert res.exit_code != 0
    assert "not linux" in res.output
    executor.run_command.assert_not_called()


def test_atomic_without_probes_exits_nonzero(tmp_path, monkeypatch):
    """No steady_state probe: the run refuses (the adapter's other refusal), exit != 0."""
    path = _variant(tmp_path, steady_state={"probes": []})
    executor = _executor()
    res = _invoke(tmp_path, monkeypatch, executor, path)
    assert res.exit_code != 0
    executor.run_command.assert_not_called()


def test_invalid_scenario_exits_nonzero(tmp_path, monkeypatch):
    """An engine Annatar cannot run: the scenario is invalid, exit != 0 (it raised before R1)."""
    path = _variant(tmp_path, engine="atomc")
    res = _invoke(tmp_path, monkeypatch, _executor(), path)
    assert res.exit_code != 0


def test_preflight_failure_exits_nonzero(tmp_path, monkeypatch):
    """local-script path: a stopped or isolated VM is refused, exit != 0."""
    executor = _executor(preflight=["VM is deallocated"])
    res = _invoke(tmp_path, monkeypatch, executor, EXFIL_YAML)
    assert res.exit_code != 0
    assert "--skip-preflight" in res.output
    executor.run_script.assert_not_called()


# ── Errors after the target was touched → non-zero, never a success ───────────────────

def test_initial_state_not_restored_exits_nonzero(tmp_path, monkeypatch):
    """The after-probe still broken: the VM may be dirty — an error, never 0 (M108)."""
    executor = _executor(after="USER_PRESENT")
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code != 0
    assert "initial state not restored" in res.output
    assert _attacked(executor)


def test_no_observable_effect_exits_nonzero(tmp_path, monkeypatch):
    """The atomic ran but broke nothing: no attack_started, an error, exit != 0."""
    executor = _executor(effect="USER_ABSENT")
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code != 0


def test_a_command_that_raises_exits_nonzero_in_one_line(tmp_path, monkeypatch):
    """The atomic's command raises: _AnnatarCli renders one line, exit 1, no traceback."""
    executor = _executor(command_raises=True)
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert res.exit_code == 1
    assert "Traceback" not in res.output
    assert "ANNATAR_DEBUG" in res.output


# ── The rule itself (M103) ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("outcome, nonzero", [
    (None, False),                                     # dry run / operator said no
    (RunOutcome("r", "detected"), False),
    (RunOutcome("r", "missed"), False),                # a miss is a measure, not a failure
    (RunOutcome("r", "unknown"), False),
    (RunOutcome("r", "unknown", error="passive: x"), True),
    (RunOutcome("r", "unknown", error="initial state not restored"), True),
])
def test_run_exit_code(outcome, nonzero):
    assert (run_exit_code(outcome) != EXIT_OK) is nonzero


def test_the_refusal_line_carries_a_hint(tmp_path, monkeypatch):
    """One red line plus a hint, like _AnnatarCli — not a raw traceback."""
    executor = _executor(tags={})
    res = _invoke(tmp_path, monkeypatch, executor, ATOMIC_YAML)
    assert "✗ run" in res.output
    assert "eregion-target" in res.output


# ── #358: nothing launched by hand runs during a Dagorlad request ─────────────────────────────

def test_a_run_by_hand_during_a_request_is_refused_and_touches_nothing(tmp_path, monkeypatch):
    from eregion_core.exercise_runner import request_lock
    monkeypatch.chdir(tmp_path)
    ran = []
    monkeypatch.setattr(Engine, "run", lambda self, path, skip_confirm=False: ran.append(path))
    with request_lock(tmp_path / "runs", "request r-20261031T080000Z-abcdef"):
        res = CliRunner().invoke(cli, ["run", EXFIL_YAML, "--yes"])
        assert res.exit_code == 1, res.output
        assert ran == []
        said = " ".join(res.output.split())
        assert "busy: request r-20261031T080000Z-abcdef runs on this Orodruin" in said
        # A dry run touches nothing: no lock.
        assert CliRunner().invoke(cli, ["run", EXFIL_YAML, "--dry-run"]).exit_code == 0
    assert ran == [EXFIL_YAML]
    # The request over, the run goes — and holds the lock while it runs.
    from eregion_core.exercise_runner import Busy

    def holding(self, path, skip_confirm=False):
        with pytest.raises(Busy, match="^run data-exfiltration.yaml runs on this Orodruin"):
            with request_lock(tmp_path / "runs", "request r-20261031T080000Z-abcdef"):
                pass
        ran.append(path)
    monkeypatch.setattr(Engine, "run", holding)
    assert CliRunner().invoke(cli, ["run", EXFIL_YAML, "--yes"]).exit_code == 0
    assert ran == [EXFIL_YAML, EXFIL_YAML]


def test_a_run_refused_busy_says_the_holder_as_it_is(tmp_path, monkeypatch):
    from eregion_core.exercise_runner import request_lock
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Engine, "run", lambda self, path, skip_confirm=False: None)
    with request_lock(tmp_path / "runs", "campaign [/x]"):
        res = CliRunner().invoke(cli, ["run", EXFIL_YAML, "--yes"])
    assert res.exit_code == 1 and isinstance(res.exception, SystemExit), res.exception
    assert "busy: campaign [/x] runs" in " ".join(res.output.split())
