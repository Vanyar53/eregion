"""DG-b end to end, on fakes (docs/design/console.md §7, phase b): a request goes from the console to
Orodruin and to its injectors — the console writes it (POST, behind SEC1), the operator's command
shows it and has the destructive target's name typed, Orodruin judges it again and runs its wires
one after the other, each by its own injector (Annatar's `wire`, Gothmog's `run`), the request's id
in every window and every report.

No Azure, no model, no SSH: the console's bench is a list, Annatar's executor a mock, Gothmog's
bench the in-memory one of test_gothmog.py, Orodruin's contract and the watch the conftest's. The
injectors run in this process instead of their own (the runner's ``launch``). Crosses components
on purpose: TOGETHER (scripts/component_check.py).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from click.testing import CliRunner  # noqa: E402

import eregion_console.api as api  # noqa: E402
import gothmog.runner.engine as gothmog_engine  # noqa: E402
from annatar.cli import cli as annatar_cli  # noqa: E402
from annatar.runner.engine import Engine as AnnatarEngine  # noqa: E402
from eregion_core import exercise_request as xr  # noqa: E402
from eregion_core import exercise_runner as er  # noqa: E402
from eregion_core.exercise import exercises_dir  # noqa: E402
from eregion_core.exercise_plan import Target, load_catalog  # noqa: E402
from gothmog.engines.chaos_studio import ChaosStudio  # noqa: E402

from .console_client import console  # noqa: E402
from .test_gothmog import Clock, Cred, World, _experiment  # noqa: E402

SUB = "00000000-0000-0000-0000-000000000000"

VM = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
ENROLLED = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}


@pytest.fixture
def stage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,gothmog")
    monkeypatch.delenv("EREGION_BENCH", raising=False)
    vms = [{"resource_id": VM, "name": "vm-celebrimbor-gondolin", "resource_group": "rg-celebrimbor",
            "rg_tags": {"eregion-target": "celebrimbor"}, "tags": dict(ENROLLED)}]
    monkeypatch.setattr(api, "READ_TARGETS", lambda subscription: vms)
    api._targets_cache.update(at=0.0, value=None)
    monkeypatch.setattr(api, "_board_rules", lambda: [])
    clock = Clock()
    world = World(clock, experiment=_experiment(
        targets=(f"{VM}/providers/Microsoft.Chaos/targets/Microsoft-VirtualMachine",)))
    executor = MagicMock()
    executor.resource_id = VM
    executor.get_resource_group_tags.return_value = dict(ENROLLED)
    executor.get_vm_tags.return_value = dict(ENROLLED)
    executor.get_vm_name.return_value = "vm-celebrimbor-gondolin"
    executor.check_preflight.return_value = []
    executor.verify_restore_integrity.return_value = True
    executor.run_script.return_value = ""

    def launch(argv, env):
        """The injector of a wire, in this process (Orodruin starts it as its own)."""
        if argv[0] == "annatar":
            with patch.object(AnnatarEngine, "_get_executor_collector", return_value=(executor, MagicMock())), \
                 patch.object(AnnatarEngine, "_wait_and_emit_feedback"):
                return CliRunner().invoke(annatar_cli, argv[1:], catch_exceptions=False).exit_code
        assert argv[:2] == ["gothmog", "run"]
        factory = lambda session: ChaosStudio(session, credential=Cred(), http=world, subscription_id=SUB)  # noqa: E731
        out = gothmog_engine.Engine(bench_factory=factory, runs_dir=tmp_path / "runs", sleep=clock.sleep,
                                    now=clock.now).run(argv[2], skip_confirm=True,
                                                       request=argv[argv.index("--request") + 1],
                                                       target=argv[argv.index("--target") + 1])
        return 0 if out.result == "PASS" else 1

    def runner(**kw):
        return er.Runner(read_target=lambda rid: (Target(rid, {"eregion-target": "celebrimbor"}, dict(ENROLLED)),
                                                  "vm-celebrimbor-gondolin"),
                         fault_targets=gothmog_engine.declared_targets, isolated=lambda rid: "",
                         launch=launch, runs_dir=tmp_path / "runs", say=lambda *_: None, **kw)
    return console(), runner, executor, world, tmp_path


def _request(client, *wires) -> xr.Request:
    r = client.post("/api/dagorlad/requests",
                    json={"wires": [{"experiment": e, "target": t} for e, t in wires]})
    assert r.status_code == 200, r.text
    return xr.load(xr.requests_dir() / f"{r.json()['request']}.json")


def _typed(req, answers):
    doc = xr.confirm(req, load_catalog(), ask=lambda _p: answers.pop(0), say=lambda *_: None)
    return None if doc is None else xr.read_typed(doc, req)


def test_a_request_goes_from_the_console_to_orodruin_and_its_injectors(stage):
    client, runner, executor, world, tmp = stage
    req = _request(client, ("T1110.001", VM), ("vm-shutdown", VM), ("T1486", VM))
    typed = _typed(req, ["vm-celebrimbor-gondolin", "y"])
    status = runner().run(req, typed)
    assert status.state == "finished"
    assert [w.state for w in status.wires] == ["done", "done", "done"], status.to_dict()
    # Each wire's run, linked by the request's id in its window and its report.
    windows = {w["run_id"]: w for w in (json.loads(p.read_text()) for p in exercises_dir().glob("*.json"))}
    assert {w["request"] for w in windows.values()} == {req.id} and len(windows) == 3
    runs = [r for w in status.wires for r in w.runs]
    assert sorted(runs) == sorted(windows)
    reports = [json.loads((tmp / "runs" / f"{r}.json").read_text()) for r in runs]
    assert [r["metrics"]["request"] for r in reports] == [req.id] * 3
    assert [r["metrics"]["kind"] for r in reports] == ["technique", "fault", "technique"]
    # The fault came back, verified, before the destructive technique went.
    assert reports[1]["checks"]["revert_verified"] == "PASS"
    assert [x for x, _ in world.writes] == ["start"]


def test_a_destructive_wire_typed_wrong_on_the_operators_machine_never_leaves_it(stage):
    client, runner, *_ = stage
    req = _request(client, ("T1486", VM))
    assert _typed(req, ["vm-celebrimbor-bree", "y"]) is None


def test_a_request_forged_on_the_console_host_without_a_name_is_refused_by_orodruin(stage):
    """The names typed never travel in the request: a request carried without them (or written by
    a compromised H0 and run by hand) is refused at Orodruin, nothing launched."""
    client, runner, executor, world, tmp = stage
    req = _request(client, ("T1110.001", VM), ("T1486", VM))
    status = runner().run(req, {})
    assert status.state == "refused" and status.wire(2).code == "typed_name"
    assert not exercises_dir().exists() or not list(exercises_dir().glob("*.json"))
    executor.run_script.assert_not_called()
