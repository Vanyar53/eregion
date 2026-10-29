"""R1 — the Atomic Red Team adapter: the vendored definitions are read faithfully, anything
the adapter cannot run faithfully is refused, a run verifies the initial state before and
after the atomic's own cleanup, proves the attack had an effect, and always cleans up. No
Azure, no LLM (dry_run / mocked executor).

The P-probes are the review's (collab/review-r1/test_r1_review_probes.py), ported here and
adapted to the fixed code; each asserts the behaviour a fix guarantees.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml

from annatar.engines.atomic import AtomicError, parse_ref, resolve_ref
from annatar.runner.engine import Engine
from annatar.runner.parser import Scenario, ScenarioParser

_ATOMICS = Path(__file__).parent.parent.parent / "annatar" / "atomics"
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
USERADD = "useradd -M -N -r -s /bin/bash -c evil_account evil_user"


# ── A temp atomics tree, to exercise the guards deterministically ─────────────────────

def _atomics_dir(tmp_path: Path, tests: list[dict]) -> Path:
    d = tmp_path / "atomics" / "T9999"
    d.mkdir(parents=True)
    path = d.parent / "T9999" / "T9999.yaml"
    path.write_text(
        yaml.safe_dump({"attack_technique": "T9999", "atomic_tests": tests}),
        encoding="utf-8",
    )
    # Pinned like the vendored ones: the adapter checks the sha256 at run time (SEC5, V-30).
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (d.parent / "PIN").write_text(f"#   {digest}  T9999/T9999.yaml\n", encoding="utf-8")
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
    # The declared executor is applied as an explicit shebang (review R1 point 5).
    assert r.command == "#!/bin/bash\n" + USERADD
    assert r.cleanup_command == "#!/bin/bash\nuserdel evil_user"
    assert r.args == {"username": "evil_user"}


def test_resolve_overrides_input_argument():
    r = resolve_ref("T1136.001/" + LINUX_GUID, args={"username": "mallory"})
    assert r.command.endswith("mallory")
    assert r.cleanup_command == "#!/bin/bash\nuserdel mallory"
    # substitute() fills probe text only — no shebang there.
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
        with pytest.raises(AtomicError, match="not linux"):
            resolve_ref("T1136.001/" + guid)


def test_refuses_dependencies(tmp_path):
    """A test with prereqs is out of scope for R1 — and the refusal is the dependencies
    guard, not the platform guard (X3): a linux/sh test with dependencies."""
    t = _shell_test(guid="deps", name="sh")
    t["dependencies"] = [{"description": "needs a thing", "prereq_command": "true"}]
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match="dependencies"):
        resolve_ref("T9999/deps", atomics_dir=d)


def test_refuses_non_shell_executor(tmp_path):
    d = _atomics_dir(tmp_path, [_shell_test(guid="ps", name="powershell")])
    with pytest.raises(AtomicError, match="executor"):
        resolve_ref("T9999/ps", atomics_dir=d)


def test_refuses_without_cleanup(tmp_path):
    """No cleanup_command → refused: R1 never leaves the target changed (M77)."""
    t = _shell_test(guid="noclean")
    t["executor"]["cleanup_command"] = ""
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match="cleanup_command"):
        resolve_ref("T9999/noclean", atomics_dir=d)


def test_refuses_unresolved_placeholder(tmp_path):
    """A #{var} with no default and no override is refused, never sent raw (M76)."""
    t = _shell_test(guid="ph")
    t["executor"]["command"] = "useradd #{username} #{extra}\n"
    t["input_arguments"] = {"username": {"default": "evil_user"}}
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match="unresolved"):
        resolve_ref("T9999/ph", atomics_dir=d)


# ── Fidelity of the adapter (review R1 point 5) ───────────────────────────────────────

# P6 — a #{...} placeholder the regex does not match (hyphen) is refused, not sent raw.
def test_p6_unmatched_placeholder_shape_refused(tmp_path):
    t = _shell_test(guid="g", name="sh")
    t["input_arguments"] = {"user-name": {"default": "x"}}
    t["executor"]["command"] = "useradd #{user-name}\n"
    t["executor"]["cleanup_command"] = "userdel #{user-name}\n"
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match=r"#\{"):
        resolve_ref("T9999/g", atomics_dir=d)


# P7 — upstream's PathToAtomicsFolder (not on the VM) is refused.
def test_p7_path_to_atomics_folder_refused(tmp_path):
    t = _shell_test(guid="g", name="bash")
    t["input_arguments"] = {"script": {"default": "PathToAtomicsFolder/T9999/src/x.sh"}}
    t["executor"]["command"] = "bash #{script}\n"
    t["executor"]["cleanup_command"] = "rm -f /tmp/x\n"
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match="PathToAtomicsFolder"):
        resolve_ref("T9999/g", atomics_dir=d)


def test_refuses_elevation_not_required(tmp_path):
    """Run Command runs as root — a test written for an unprivileged user is refused (M94)."""
    t = _shell_test(guid="noelev")
    t["executor"]["elevation_required"] = False
    d = _atomics_dir(tmp_path, [t])
    with pytest.raises(AtomicError, match="elevation_required"):
        resolve_ref("T9999/noelev", atomics_dir=d)


# P8 — a bash test runs under bash (the declared executor), whatever Run Command's default.
def test_p8_bash_executor_is_honoured():
    sent = resolve_ref("T1136.001/" + LINUX_GUID).command
    assert sent.startswith("#!/bin/bash") or sent.startswith("bash ")


# ── The shipped experiment resolves (the engine_ref points at a vendored test) ─────────

def test_shipped_atomic_experiment_resolves():
    s = ScenarioParser().load(ATOMIC_YAML)
    assert s.engine == "atomic"
    assert s.steps == []
    r = resolve_ref(s.engine_ref)
    assert r.guid == LINUX_GUID


# ── PIN: the sha256 of each vendored file is recorded and matches (review R1 point 9) ──

def test_pin_records_vendored_sha256():
    pin_text = (_ATOMICS / "PIN").read_text(encoding="utf-8")
    for rel in ("T1136.001/T1136.001.yaml", "LICENSE.atomic-red-team"):
        digest = hashlib.sha256((_ATOMICS / rel).read_bytes()).hexdigest()
        assert digest in pin_text, f"{rel}: sha256 {digest} is not pinned in PIN"


# ── Engine integration (mocked executor, armed by hermetic_orodruin) ──────────────────

def _atomic_executor(before="USER_ABSENT", effect="USER_PRESENT", after="USER_ABSENT",
                     command_raises=False, cleanup_raises=False, after_raises=False):
    """A MagicMock executor. run_command returns per the probe phase in its label
    (before / effect / after); the atomic command and cleanup return "" (or raise)."""
    executor = MagicMock()
    executor.get_resource_group_tags.return_value = {"annatar-test": "true"}
    executor.get_vm_tags.return_value = {"annatar-test": "true"}
    executor.resource_id = RESOURCE_ID
    executor.check_preflight.return_value = []

    def side_effect(cmd, label=""):
        if label.endswith("cleanup"):
            if cleanup_raises:
                raise RuntimeError("cleanup failed")
            return ""
        if label.startswith("atomic "):  # the atomic's own command
            if command_raises:
                raise RuntimeError("RunCommand failed after all retries")
            return ""
        if "(before)" in label:
            return before
        if "(effect)" in label:
            return effect
        if "(after)" in label:
            if after_raises:
                raise RuntimeError("RunCommand failed after all retries")
            return after
        return ""

    executor.run_command.side_effect = side_effect
    return executor


def _run_atomic(tmp_path, monkeypatch, executor, path=ATOMIC_YAML):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        return engine.run(path, skip_confirm=True)


def _commands_run(executor) -> list[str]:
    return [c.args[0] for c in executor.run_command.call_args_list]


def _signals(tmp_path):
    out = []
    for f in (tmp_path / "runs").glob("*_signals.jsonl"):
        out += [json.loads(x)["event"] for x in f.read_text().splitlines() if x.strip()]
    return out


def _report(tmp_path):
    return json.loads(next((tmp_path / "runs").glob("2*.json")).read_text())


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
    useradd = next(i for i, c in enumerate(cmds) if "useradd" in c)
    userdel = next(i for i, c in enumerate(cmds) if "userdel" in c)
    assert useradd < userdel


def test_atomic_records_initial_state_restored(tmp_path, monkeypatch):
    executor = _atomic_executor(before="USER_ABSENT", effect="USER_PRESENT", after="USER_ABSENT")
    _run_atomic(tmp_path, monkeypatch, executor)

    report = _report(tmp_path)
    assert report["checks"]["initial_state_before"] == "PASS"
    assert report["checks"]["initial_state_after"] == "PASS"
    assert report["metrics"]["initial_state_restored"] is True


def test_atomic_records_detection_in_the_run(tmp_path, monkeypatch):
    """#65 'Fini quand': the detection result is written in runs/<run_id>.json."""
    executor = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, executor)
    # _wait_and_emit_feedback is patched → detection stays 'unknown', but it IS recorded.
    assert _report(tmp_path)["metrics"]["detection"] == "unknown"


# P9 — the attack's effect is observed; no effect → attack FAIL, no attack_started (M96).
def test_p9_attack_effect_is_observed(tmp_path, monkeypatch):
    # useradd "ran" but did nothing: the probe stays USER_ABSENT throughout.
    executor = _atomic_executor(before="USER_ABSENT", effect="USER_ABSENT", after="USER_ABSENT")
    outcome = _run_atomic(tmp_path, monkeypatch, executor)

    report = _report(tmp_path)
    assert report["checks"].get("attack") != "PASS"
    assert "attack_started" not in _signals(tmp_path)
    assert outcome.error  # a no-op atomic is an error, never a silent 'executed'


# P5 — a return NOT restored reaches the caller (the campaign) as an error (M91).
def test_p5_unrestored_state_surfaces_in_outcome(tmp_path, monkeypatch):
    executor = _atomic_executor(before="USER_ABSENT", effect="USER_PRESENT", after="USER_PRESENT")
    outcome = _run_atomic(tmp_path, monkeypatch, executor)

    assert _report(tmp_path)["checks"]["initial_state_after"] == "FAIL"
    assert _report(tmp_path)["result"] == "FAIL"
    assert outcome.error == "initial state not restored"


# P11 — the after-probe RAISES: the return is unverified (restored is None) → the caller
# must still see an error, never a silent 'executed' over an unknown VM (recheck, M91).
def test_p11_after_probe_raises_is_an_error(tmp_path, monkeypatch):
    executor = _atomic_executor(after_raises=True)
    outcome = _run_atomic(tmp_path, monkeypatch, executor)

    assert _report(tmp_path)["checks"]["initial_state_after"] == "ERROR"
    assert outcome.error == "initial state not verified after cleanup"


# P11b — cleanup AND the after-probe raise: still an error (a dirty-or-unknown VM).
def test_p11b_cleanup_and_after_probe_raise(tmp_path, monkeypatch):
    executor = _atomic_executor(cleanup_raises=True, after_raises=True)
    outcome = _run_atomic(tmp_path, monkeypatch, executor)

    assert _report(tmp_path)["checks"]["cleanup"] == "ERROR"
    assert outcome.error  # never a silent 'executed'


# P12 — the detection latency is measured from the attack, not from the start of the wait
# (which on the atomic path begins only after cleanup — the old measure was always ~0).
# Since #157 it is written: detection time − attack_time (tests/unit/test_annatar_detection.py).
def test_p12_detection_latency_is_measured_from_the_attack(tmp_path, monkeypatch):
    import datetime as _dt
    import time as _time

    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    attack_time = _time.time() - 90  # attacked 90 s ago, detected 30 s after it
    # The watch's record of the run's attack_started: its timestamp is the attack_started
    # emission (63 s after the command, after the effect proof), not the detection.
    emitted_ts = _dt.datetime.fromtimestamp(attack_time + 63, _dt.timezone.utc).isoformat()
    (tmp_path / "runs" / "rid_debug.jsonl").write_text(json.dumps({"signal": {
        "event": "detection", "ttp": "T1136.001", "resource_id": RESOURCE_ID,
        "timestamp": emitted_ts,
        "raw_signal": {"attack_time": attack_time, "detection_time_s": 30},
    }}) + "\n")
    engine = Engine()
    scenario = SimpleNamespace(mitre="T1136.001", detection={}, detection_hints={})
    emitter = SimpleNamespace(resource_id=RESOURCE_ID, emit=lambda **k: None)
    engine._wait_and_emit_feedback("rid", emitter, scenario, 600.0, attack_time)

    assert engine._detection_result == "detected"
    assert engine._detection_latency_s == 30.0


# P1 — the cleanup runs even when the atomic's command raises; the report is still written
# and the exception reaches the caller (the campaign marks it an error) (M87).
def test_p1_cleanup_runs_when_command_raises(tmp_path, monkeypatch):
    executor = _atomic_executor(command_raises=True)
    with pytest.raises(RuntimeError):
        _run_atomic(tmp_path, monkeypatch, executor)

    cmds = _commands_run(executor)
    assert any("userdel evil_user" in c for c in cmds), f"cleanup never attempted: {cmds}"
    assert "attack_started" not in _signals(tmp_path)  # the command raised
    report = _report(tmp_path)  # the report is written even though the command raised
    assert report["checks"]["attack"] == "ERROR"


def test_atomic_report_written_even_when_cleanup_raises(tmp_path, monkeypatch):
    """A cleanup that raises still leaves a saved report (review R1 point 1)."""
    executor = _atomic_executor(cleanup_raises=True)
    _run_atomic(tmp_path, monkeypatch, executor)
    assert _report(tmp_path)["checks"]["cleanup"] == "ERROR"


# P3 — a probe without `expect` is refused (never a vacuous pass over a dirty VM).
def test_p3_probe_without_expect_is_refused(tmp_path, monkeypatch):
    doc = yaml.safe_load(Path(ATOMIC_YAML).read_text())
    doc["steady_state"]["probes"][0].pop("expect")
    p = tmp_path / "exp.yaml"
    p.write_text(yaml.safe_dump(doc))
    executor = _atomic_executor(before="USER_PRESENT")  # a dirty VM
    outcome = _run_atomic(tmp_path, monkeypatch, executor, path=str(p))
    assert not any("useradd" in c for c in _commands_run(executor))
    assert outcome.error and "verify and expect" in outcome.error


# P4 — an atomic experiment without steady_state is refused.
def test_p4_atomic_without_probes_is_refused(tmp_path, monkeypatch):
    doc = yaml.safe_load(Path(ATOMIC_YAML).read_text())
    doc.pop("steady_state")
    p = tmp_path / "exp.yaml"
    p.write_text(yaml.safe_dump(doc))
    executor = _atomic_executor()
    outcome = _run_atomic(tmp_path, monkeypatch, executor, path=str(p))
    assert not any("useradd" in c for c in _commands_run(executor))
    assert outcome.error and "at least one steady_state probe" in outcome.error


def test_atomic_refuses_dirty_start(tmp_path, monkeypatch):
    """The user already exists before the run → nothing attacked, no attack_started (M80)."""
    executor = _atomic_executor(before="USER_PRESENT")
    _run_atomic(tmp_path, monkeypatch, executor)

    assert not any("useradd" in c for c in _commands_run(executor))
    assert list((tmp_path / "runs").glob("*_signals.jsonl")) == []


# X7 — probes reach the VM substituted, never with a raw #{var} (M86).
def test_probes_are_substituted_before_being_sent(tmp_path, monkeypatch):
    executor = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, executor)
    probe_cmds = [c.args[0] for c in executor.run_command.call_args_list
                  if c.kwargs.get("label", "").startswith("probe")]
    assert probe_cmds
    for cmd in probe_cmds:
        assert "#{" not in cmd and "evil_user" in cmd


# X5 — the atomic run happens inside its exercise window (opened AND closed) (M84).
def test_atomic_run_is_wrapped_in_an_exercise_window(tmp_path, monkeypatch):
    executor = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, executor)
    windows = list((tmp_path / "exercises").glob("*.json"))
    assert len(windows) == 1
    window = json.loads(windows[0].read_text())
    assert window["injector"] == "annatar"
    assert RESOURCE_ID.lower() in window["targets"]
    assert window["end"] is not None  # the window was closed


# ── Cap: a run needs 2 + 3·probes Run Commands (command, cleanup, probes ×3) ──────────

def test_atomic_refuses_when_cap_too_low(tmp_path, monkeypatch):
    """cap=3 with one probe: a run needs 5 (command + cleanup + 3 probe passes) > 3 (X4)."""
    import eregion_core.orodruin as orodruin

    monkeypatch.setattr(orodruin, "READERS", {
        "identity": lambda: [], "network": lambda: [],
        "cap": lambda: ([], {"max_injections": 3, "max_run_s": 3600})})
    executor = _atomic_executor()
    outcome = _run_atomic(tmp_path, monkeypatch, executor)
    assert outcome.error and "cap" in outcome.error
    executor.run_command.assert_not_called()


def test_atomic_calls_needed_counts_three_probe_passes():
    assert Engine._atomic_calls_needed(1) == 5
    assert Engine._atomic_calls_needed(0) == 2


# ── The engine table: an unknown engine is refused, never a bogus attack_started ──────

# P2 — an unknown engine (typo) is refused at authoring, so run() never emits attack_started.
def test_p2_unknown_engine_is_refused(tmp_path, monkeypatch):
    doc = yaml.safe_load(Path(ATOMIC_YAML).read_text())
    doc["engine"] = "atomc"
    p = tmp_path / "exp.yaml"
    p.write_text(yaml.safe_dump(doc))
    executor = _atomic_executor()
    outcome = _run_atomic(tmp_path, monkeypatch, executor, path=str(p))
    assert outcome.error and "engine" in outcome.error
    assert "attack_started" not in _signals(tmp_path)


def test_validate_refuses_an_unknown_engine(tmp_path):
    """The enum in the parser (M89): an engine Annatar cannot run fails validation."""
    doc = yaml.safe_load(Path(ATOMIC_YAML).read_text())
    doc["engine"] = "atomc"
    p = tmp_path / "exp.yaml"
    p.write_text(yaml.safe_dump(doc))
    result = ScenarioParser().validate(str(p))
    assert not result.valid
    assert any("engine" in e for e in result.errors)


def test_unknown_engine_reaching_the_runner_never_runs_as_local_script(tmp_path, monkeypatch):
    """Defence in depth (M88): even if an unknown engine reached the runner, the explicit
    table refuses it — it never falls through to the local-script path (zero steps +
    attack_started)."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    scen = Scenario(
        name="x", description="", mitre="T1136.001", version="1.0.0",
        target={"type": "azure_vm", "resource_group": "rg-celebrimbor",
                "vm_name": "vm-celebrimbor-gondolin"},
        setup=[], steps=[], detection={"timeout": "60s"}, detection_hints={},
        raw={}, engine="weird-engine", engine_ref=None,
    )
    executor = _atomic_executor()
    with patch.object(engine.parser, "load", return_value=scen), \
         patch.object(engine, "_get_executor_collector", return_value=(executor, None)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run("ignored", skip_confirm=True)
    assert outcome.error and "engine" in outcome.error
    assert "attack_started" not in _signals(tmp_path)


# ── Dry run ───────────────────────────────────────────────────────────────────────────

def test_atomic_dry_run_shows_command_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Engine(dry_run=True).run(ATOMIC_YAML, skip_confirm=True)
    assert list((tmp_path / "runs").glob("*_signals.jsonl")) == []
