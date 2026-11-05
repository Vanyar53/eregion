"""VM3b (#568) — the follow-ups of VM3's second review: the catalog decides a scenario's probes
(S1), T1053.003's revert waits on a probe, not on the call (S2), an engine_args value never
starts with '-' (S3), and log_tamper's python3 set-aside tightened, its limit written (S4).

No Azure, no LLM: the scenarios run against a mocked executor or a VM simulated by a real
shell (tests/unit/test_vm3_pairs.py, _ShellVM), the rule over lines the test writes, through
the KQL subset. Mutants M4100–M4109 (scripts/mutants/VM3b.py).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from annatar.campaign.catalog import catalog_destructive, load_catalog
from annatar.engines.atomic import AtomicError, resolve_ref, revert_commands
from annatar.runner.engine import scenario_destructive
from annatar.runner.parser import ScenarioParser

from .test_injector_guards import PROD_TAGS, _executor, _run
from .test_vm3_pairs import (PAIRS, ROOT_CRONTAB, SCENARIOS, TAMPER_RULE, _labels, _probe_executor,
                             _run_rule, _shell_executor, _ShellVM, _tamper)

ROOT = Path(__file__).resolve().parents[2]
CRON = "T1053.003"
CRON_REF = PAIRS[CRON][1]
ATOMIC_SCENARIOS = sorted(p for p in SCENARIOS.glob("*.yaml")
                          if yaml.safe_load(p.read_text()).get("engine") == "atomic")


@pytest.fixture(autouse=True)
def _subscription(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")


def _doc(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _write(tmp_path: Path, doc: dict, name="variant.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(doc))
    return path


def _report(tmp_path: Path) -> dict:
    return json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())


# ── S1: the catalog decides the probes of an atomic scenario too ──────────────────────

def test_the_shipped_atomic_scenarios_are_the_four_atomics():
    names = {p.stem for p in ATOMIC_SCENARIOS}
    assert names == {"account-creation-atomic", *(scn for scn, _ref, _rule in PAIRS.values())}


@pytest.mark.parametrize("path", ATOMIC_SCENARIOS, ids=lambda p: p.stem)
def test_every_shipped_atomic_scenario_has_its_entry_probes(path):
    """R1's account creation included: the probes the scenario runs are its entry's, exactly —
    so the catalog vouches for it (its own flag, never 'unknown')."""
    s = ScenarioParser().load(str(path))
    entry = load_catalog()[s.mitre]
    assert s.raw["steady_state"]["probes"] == entry["steady_state"]["probes"], path.stem
    said = catalog_destructive(s.mitre, engine=s.engine, engine_ref=s.engine_ref,
                               engine_args=s.engine_args or None, revert=s.raw.get("revert"),
                               probes=s.raw["steady_state"]["probes"])
    assert said is entry["destructive"], path.stem
    assert scenario_destructive(s) == (entry["destructive"], ""), path.stem


def test_the_catalog_decides_the_probes():
    ttp, ref = "T1136.001", "T1136.001/40d8eabd-e394-46f6-8785-b9bfa1d011d2"
    own = load_catalog()[ttp]["steady_state"]["probes"]
    assert catalog_destructive(ttp, engine="atomic", engine_ref=ref, probes=own) is False
    changed_verify = [{**own[0], "verify": own[0]["verify"] + "; touch /tmp/x"}]
    changed_expect = [{**own[0], "expect": "USER"}]
    one_more = own + [{"name": "extra", "verify": "id", "expect": "uid"}]
    for other in (None, [], changed_verify, changed_expect, one_more, own[0], "id"):
        assert catalog_destructive(ttp, engine="atomic", engine_ref=ref, probes=other) is None
    # The order is the catalog's too: two probes swapped are another run.
    cron = load_catalog()[CRON]
    probes, revert = cron["steady_state"]["probes"], cron["revert"]
    assert catalog_destructive(CRON, engine="atomic", engine_ref=CRON_REF, revert=revert,
                               probes=probes) is True
    assert catalog_destructive(CRON, engine="atomic", engine_ref=CRON_REF, revert=revert,
                               probes=list(reversed(probes))) is None


def test_a_probe_changed_under_its_own_name_is_another_run():
    """The verify is what Run Command runs as root: a name kept is not a probe kept."""
    ttp, ref = "T1136.001", "T1136.001/40d8eabd-e394-46f6-8785-b9bfa1d011d2"
    own = load_catalog()[ttp]["steady_state"]["probes"]
    other = [{"name": own[0]["name"], "verify": "rm -f /tmp/x; echo USER_ABSENT",
              "expect": own[0]["expect"]}]
    assert catalog_destructive(ttp, engine="atomic", engine_ref=ref, probes=other) is None


def _with_probe(path: Path, verify: str, keep_destructive: bool) -> dict:
    doc = _doc(path)
    doc["steady_state"]["probes"][0]["verify"] = verify
    if not keep_destructive:
        doc.pop("destructive", None)
    return doc


@pytest.mark.parametrize("scn,verify", [
    ("account-creation-atomic", "id evil_user >/dev/null 2>&1 && echo USER_PRESENT || echo USER_ABSENT; true"),
    ("shell-execution-atomic", "test -f #{script_path} && echo PRESENT || echo ABSENT; true"),
])
def test_a_scenario_with_other_probes_is_destructive_never_in_production(tmp_path, monkeypatch,
                                                                         scn, verify):
    path = _write(tmp_path, _with_probe(SCENARIOS / f"{scn}.yaml", verify, keep_destructive=False))
    executor = _executor(PROD_TAGS)
    out = _run(tmp_path, monkeypatch, path, executor)
    assert out.refused and "destructive technique never runs in production" in out.error
    executor.run_command.assert_not_called()


def test_a_scenario_calling_other_probes_harmless_is_refused_everywhere(tmp_path, monkeypatch):
    verify = "id evil_user >/dev/null 2>&1 && echo USER_PRESENT || echo USER_ABSENT; true"
    path = _write(tmp_path, _with_probe(SCENARIOS / "account-creation-atomic.yaml", verify,
                                        keep_destructive=True))   # destructive: false kept
    executor = _executor()
    out = _run(tmp_path, monkeypatch, path, executor)
    assert out.refused and "the catalog decides" in out.error
    executor.run_command.assert_not_called()


# ── S2: T1053.003's revert waits on a probe, not on the call ─────────────────────────

class _CleanupFailsVM(_ShellVM):
    """A VM whose `crontab` refuses to reinstall /tmp/notevil, exiting 1 — Run Command does not
    raise on a script that failed, so the cleanup's call 'passes' and the evil line stays."""

    def __init__(self, root: Path):
        super().__init__(root)
        fake = self.bin / "crontab"
        fake.write_text(
            "#!/bin/sh\n"
            f'STORE="{self.store}"\n'
            'if [ "$1" = "-l" ]; then\n'
            '  [ -f "$STORE" ] || { echo "no crontab for root" >&2; exit 1; }\n'
            '  cat "$STORE"; exit 0\n'
            "fi\n"
            'case "$1" in */notevil) echo "errors in crontab file, can\'t install." >&2; exit 1;; esac\n'
            'cp "$1" "$STORE"\n'
        )


def test_the_revert_is_skipped_when_the_cleanup_call_passed_but_its_probe_did_not(tmp_path,
                                                                                    monkeypatch):
    """The cleanup's call did not raise, yet root's crontab still holds the evil line: the
    revert is skipped, /tmp/notevil (root's crontab) stays for the operator, and the run says so."""
    vm = _CleanupFailsVM(tmp_path)
    ex = _shell_executor(vm)
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    assert not any(" revert " in x for x in _labels(ex))
    assert "notevil" in vm.left() and (vm.tmp / "notevil").read_text() == ROOT_CRONTAB
    assert "evil.sh" in vm.store.read_text()   # the cleanup did not restore it
    assert out.error.startswith("initial state not restored — revert skipped: ")
    assert "root-crontab-restored" in out.error and "/tmp/notevil" in out.error
    report = _report(tmp_path)
    assert report["checks"]["cleanup"] == "PASS" and report["checks"]["revert"] == "SKIPPED"
    assert "left in place" in report["metrics"]["revert_skipped"]
    assert report["result"] == "FAIL"


class _CleanupEmptiesVM(_ShellVM):
    """A VM whose cleanup empties root's crontab instead of restoring it (m1): the evil line is
    gone — cron-entry-absent holds —, yet /tmp/notevil is then the only copy of root's crontab."""

    def __init__(self, root: Path):
        super().__init__(root)
        fake = self.bin / "crontab"
        fake.write_text(
            "#!/bin/sh\n"
            f'STORE="{self.store}"\n'
            'if [ "$1" = "-l" ]; then\n'
            '  [ -f "$STORE" ] || { echo "no crontab for root" >&2; exit 1; }\n'
            '  cat "$STORE"; exit 0\n'
            "fi\n"
            'case "$1" in */notevil) : > "$STORE"; exit 0;; esac\n'
            'cp "$1" "$STORE"\n'
        )


def test_a_cleanup_that_empties_root_crontab_keeps_its_only_copy(tmp_path, monkeypatch):
    """m1: the evil line gone is not root's crontab back. The revert waits on
    root-crontab-restored — an emptied crontab breaks it: skipped, /tmp/notevil kept."""
    vm = _CleanupEmptiesVM(tmp_path)
    ex = _shell_executor(vm)
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    assert vm.store.read_text() == ""   # emptied, the evil line gone too
    assert not any(" revert " in x for x in _labels(ex))
    assert "notevil" in vm.left() and (vm.tmp / "notevil").read_text() == ROOT_CRONTAB
    assert "revert skipped" in out.error and "root-crontab-restored" in out.error
    assert _report(tmp_path)["checks"]["revert"] == "SKIPPED"


@pytest.mark.parametrize("crontab", [ROOT_CRONTAB, None], ids=["root-crontab", "no-crontab"])
def test_the_restored_probe_holds_before_breaks_after_the_command_holds_after_cleanup(
        tmp_path, monkeypatch, crontab):
    """With a crontab for root or none at all: clean start, the effect seen, the return held."""
    vm = _ShellVM(tmp_path, crontab=crontab)
    outputs: dict[str, str] = {}

    def run_command(cmd, label=""):
        outputs[label] = vm.run_command(cmd, label)
        return outputs[label]
    ex = _executor()
    ex.run_command.side_effect = run_command
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    assert not out.error, out.error
    assert "CRONTAB_RESTORED" in outputs["probe root-crontab-restored (before)"]
    assert "CRONTAB_CHANGED" in outputs["probe root-crontab-restored (effect)"]
    assert "CRONTAB_RESTORED" in outputs["probe root-crontab-restored (before revert)"]
    assert "CRONTAB_RESTORED" in outputs["probe root-crontab-restored (after)"]
    assert vm.left() == []


def test_the_revert_runs_once_its_probe_holds_after_the_cleanup(tmp_path, monkeypatch):
    vm = _ShellVM(tmp_path)
    ex = _shell_executor(vm)
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    assert not out.error, out.error
    assert vm.store.read_text() == ROOT_CRONTAB and vm.left() == []
    labels = _labels(ex)
    cleanup = next(i for i, x in enumerate(labels) if x.endswith(" cleanup"))
    gate = next(i for i, x in enumerate(labels) if x == "probe root-crontab-restored (before revert)")
    revert = next(i for i, x in enumerate(labels) if " revert " in x)
    first_after = next(i for i, x in enumerate(labels) if "(after)" in x)
    assert cleanup < gate < revert < first_after
    assert "metrics" in _report(tmp_path) and "revert_skipped" not in _report(tmp_path)["metrics"]


def test_a_gate_probe_that_raises_is_no_proof(tmp_path, monkeypatch):
    ex = _probe_executor()
    base = ex.run_command.side_effect

    def run_command(cmd, label=""):
        if "(before revert)" in label:
            raise RuntimeError("Run Command failed")
        return base(cmd, label)
    ex.run_command.side_effect = run_command
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    assert not any(" revert " in x for x in _labels(ex))
    assert out.error == "revert skipped after the cleanup"
    assert _report(tmp_path)["checks"]["revert"] == "SKIPPED"


def test_a_revert_step_needs_the_probe_it_waits_on():
    r = resolve_ref(CRON_REF)
    step = dict(load_catalog()[CRON]["revert"][0])
    step.pop("requires_probe")
    with pytest.raises(AtomicError, match="needs requires_probe"):
        revert_commands([step], r)
    with pytest.raises(AtomicError, match="needs requires_probe"):
        revert_commands([{**step, "requires_probe": " "}], r)


@pytest.mark.parametrize("gate", ["no-such-probe", None])
def test_a_revert_waiting_on_no_probe_of_the_scenario_touches_nothing(tmp_path, monkeypatch, gate):
    doc = _doc(SCENARIOS / "cron-persistence-atomic.yaml")
    if gate is None:
        doc["revert"][0].pop("requires_probe")
    else:
        doc["revert"][0]["requires_probe"] = gate
    ex = MagicMock()
    out = _run(tmp_path, monkeypatch, _write(tmp_path, doc), ex)
    assert out.refused and "requires_probe" in out.error
    ex.run_command.assert_not_called()


def test_the_catalog_revert_waits_on_the_cron_probe():
    entry = load_catalog()[CRON]
    [step] = entry["revert"]
    assert step["requires_probe"] == "root-crontab-restored"
    assert step["requires_probe"] in {p["name"] for p in entry["steady_state"]["probes"]}
    schema = json.loads((ROOT / "schemas/technique_catalog.schema.json").read_text())
    revert = schema["definitions"]["entry"]["properties"]["revert"]
    assert "requires_probe" in revert["items"]["required"]


@pytest.mark.parametrize("cap,refused", [(12, True), (13, False)])
def test_the_cap_counts_the_probe_each_revert_step_waits_on(tmp_path, monkeypatch, cap, refused):
    import eregion_core.orodruin as orodruin

    monkeypatch.setitem(orodruin.READERS, "cap",
                        lambda: ([], {"max_injections": cap, "max_run_s": 3600}))
    ex = _probe_executor()
    out = _run(tmp_path, monkeypatch, SCENARIOS / "cron-persistence-atomic.yaml", ex)
    if refused:
        assert out.refused and "this atomic needs 13" in out.error
        ex.run_command.assert_not_called()
    else:
        assert not out.error, out.error
        assert "probe root-crontab-restored (before revert)" in _labels(ex)


# ── S3: an engine_args value never starts with '-' ───────────────────────────────────

@pytest.mark.parametrize("value", ["-rf", "--help", "-c", "-", "-1", -1, "-127.0.0.1"])
def test_an_engine_arg_starting_with_a_dash_is_refused(value):
    """In an argument's place, '-x' is an option of the command it lands in, not a value."""
    with pytest.raises(AtomicError, match="never a leading '-'"):
        resolve_ref(PAIRS["T1059.004"][1], {"host": value})


@pytest.mark.parametrize("value", ["127.0.0.1", "a-b", "/tmp/x-y.sh", 3])
def test_a_dash_inside_a_value_is_still_a_value(value):
    resolve_ref(PAIRS["T1059.004"][1], {"host": value})


def test_the_engine_never_sends_a_dash_argument(tmp_path, monkeypatch):
    doc = _doc(SCENARIOS / "shell-execution-atomic.yaml")
    doc["engine_args"]["host"] = "-f"
    ex = MagicMock()
    out = _run(tmp_path, monkeypatch, _write(tmp_path, doc), ex)
    assert out.refused and "never a leading '-'" in out.error
    ex.run_command.assert_not_called()


# ── S4: log_tamper's python3 set-aside, tightened; its limit written ─────────────────

@pytest.mark.parametrize("exe,path", [
    # a program named like the interpreter is not the interpreter
    ("/usr/bin/python3-evil", "/var/log/waagent.log"),
    ("/usr/bin/python3x", "/var/log/unattended-upgrades/unattended-upgrades.log"),
    ("/usr/bin/python3.10.bak", "/var/log/azure/x/extension.log"),
    ("/tmp/usr/bin/python3", "/var/log/waagent.log"),
    # the agent's binaries on the agent's own directory only
    ("/opt/microsoft/azuremonitoragent/bin/mdsd", "/var/log/waagent.log"),
    ("/var/lib/waagent/Microsoft.CPlat.Core.RunCommandLinux-1.0.5/bin/run-command-extension",
     "/var/log/unattended-upgrades/unattended-upgrades.log"),
    # the interpreter, outside its files
    ("/usr/bin/python3", "/var/log/syslog"),
])
def test_log_tamper_sets_the_agent_aside_on_its_own_files_only(exe, path):
    rows = _tamper(4101, exe, path, comm="python3", nametype="NORMAL")
    assert len(_run_rule(TAMPER_RULE, rows)) == 1, (exe, path)


@pytest.mark.parametrize("exe,path", [
    ("/usr/bin/python3", "/var/log/waagent.log"),
    ("/usr/bin/python3.12", "/var/log/azure/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent/extension.log"),
    ("/usr/bin/python3.10", "/var/log/unattended-upgrades/unattended-upgrades-dpkg.log"),
    ("/var/lib/waagent/Microsoft.CPlat.Core.RunCommandLinux-1.0.5/bin/run-command-extension",
     "/var/log/azure/run-command/handler.log"),
    ("/opt/microsoft/azuremonitoragent/bin/mdsd",
     "/var/log/azure/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent/mdsd.info"),
])
def test_log_tamper_keeps_the_agents_real_noise_aside(exe, path):
    assert _run_rule(TAMPER_RULE, _tamper(4102, exe, path, nametype="NORMAL")) == []


def test_log_tamper_limit_is_written_in_the_rule_and_the_doc():
    """What cannot be tightened without losing the real noise is said, where it is read."""
    rules = yaml.safe_load((ROOT / "glorfindel/rules/azure/detection_rules.yaml").read_text())
    [rule] = [r for r in rules["rules"] if r["name"] == TAMPER_RULE]
    desc = " ".join(rule["description"].split())
    assert "LIMITES (VM3b)" in desc and "un script python3 quelconque" in desc
    assert "logrotate lancé avec une configuration choisie" in desc
    doc = " ".join((ROOT / "docs/azure.md").read_text().split())
    assert "leur `exe` est l'interpréteur" in doc and "logrotate" in doc
