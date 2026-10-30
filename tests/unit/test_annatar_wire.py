"""`annatar wire` (DG-b): one wire of a Dagorlad request, run by Orodruin — its scenario made from
the catalogue, every guard of `annatar run`, the request's id in its window, its journal and its
report; a destructive technique only with the target's name typed, compared to the VM's.

No Azure, no LLM: the executor is a mock, Orodruin's contract the conftest's (armed), the watch
the conftest's (live). The oracles are written here.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import eregion_core.orodruin as orodruin
from annatar.cli import cli
from annatar.runner.engine import Engine
from eregion_core.exercise import exercises_dir

RID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor"
       "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
REQ = "r-20261030T080000Z-abcdef"
BENCH = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}


def _executor(name="vm-celebrimbor-gondolin", tags=BENCH):
    ex = MagicMock()
    ex.resource_id = RID
    ex.get_resource_group_tags.return_value = dict(tags)
    ex.get_vm_tags.return_value = dict(tags)
    ex.get_vm_name.return_value = name
    ex.check_preflight.return_value = []
    ex.verify_restore_integrity.return_value = True
    ex.run_script.return_value = ""
    return ex


ARMED: list[dict] = []


def _wire(tmp_path, monkeypatch, *args, executor=None):
    import annatar.runner.engine as engine_module
    monkeypatch.chdir(tmp_path)
    executor = executor or _executor()
    real = engine_module.arm
    ARMED.clear()

    def arm(run_id, injector, *a, **kw):
        ARMED.append(kw)
        return real(run_id, injector, *a, **kw)
    monkeypatch.setattr(engine_module, "arm", arm)
    with patch.object(Engine, "_get_executor_collector", return_value=(executor, MagicMock())), \
         patch.object(Engine, "_wait_and_emit_feedback"):
        res = CliRunner().invoke(cli, ["wire", *args], catch_exceptions=False)
    res.flat = " ".join(res.output.split())
    return res, executor


def _windows():
    d = exercises_dir()
    return [json.loads(p.read_text()) for p in d.glob("*.json")] if d.exists() else []


def _audit():
    p = orodruin.audit_path()
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_a_wire_runs_with_its_requests_id_in_its_window_its_journal_and_its_report(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T1110.001", RID, "--request", REQ)
    assert res.exit_code == 0, res.output
    [window] = _windows()
    assert window["request"] == REQ and window["targets"] == [RID.lower()]
    assert window["kind"] == "technique" and window["experiment"].startswith("T1110.001")
    assert ARMED == [{"request": REQ}]                 # its session names the request
    [report] = [json.loads(p.read_text()) for p in (tmp_path / "runs").glob("*.json")]
    assert report["metrics"]["request"] == REQ and report["metrics"]["experiment_id"] == "T1110.001"
    # The scenario lived only for the run: nothing of it under runs/.
    assert not list((tmp_path / "runs").rglob("*.yaml"))


def test_a_destructive_wire_without_a_name_typed_runs_nothing(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T1486", RID, "--request", REQ)
    assert res.exit_code != 0 and "allow_destructive" in res.flat
    ex.run_script.assert_not_called()
    assert _windows() == [] and _audit() == []


def test_a_destructive_wire_with_another_name_runs_nothing(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T1486", RID, "--request", REQ, "--typed-name", "vm-celebrimbor-bree")
    assert res.exit_code != 0 and "is not the target's" in res.flat
    ex.run_script.assert_not_called()
    assert _windows() == []


def test_the_name_typed_is_compared_to_the_vms_name_read_on_azure(tmp_path, monkeypatch):
    """The request names gondolin and the operator typed it; Azure calls the VM otherwise."""
    res, ex = _wire(tmp_path, monkeypatch, "T1486", RID, "--request", REQ, "--typed-name",
                    "vm-celebrimbor-gondolin", executor=_executor(name="vm-renamed"))
    assert res.exit_code != 0 and "is not the target's (vm-renamed)" in res.flat
    ex.run_script.assert_not_called()


def test_a_destructive_wire_with_its_name_typed_passes_the_name_guard(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T1486", RID, "--request", REQ, "--typed-name",
                    "vm-celebrimbor-gondolin")
    assert "is not the target's" not in res.output
    [window] = _windows()
    assert window["request"] == REQ and window["destructive"] is True


def test_production_refuses_a_destructive_wire_even_named(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T1486", RID, "--request", REQ, "--typed-name",
                    "vm-celebrimbor-gondolin",
                    executor=_executor(tags={"eregion-target": "celebrimbor", "eregion-zone": "production"}))
    assert res.exit_code != 0 and "never runs in production" in res.flat
    assert _windows() == []


@pytest.mark.parametrize("request_id", ["", "x", "../r", "r-20261030T080000Z-abcdef;id"])
def test_a_wire_takes_a_request_id_only(tmp_path, monkeypatch, request_id):
    res, ex = _wire(tmp_path, monkeypatch, "T1110.001", RID, "--request", request_id)
    assert res.exit_code != 0
    assert _windows() == []


def test_a_technique_not_in_the_catalogue_runs_nothing(tmp_path, monkeypatch):
    res, ex = _wire(tmp_path, monkeypatch, "T9999", RID, "--request", REQ)
    assert res.exit_code != 0 and "not a technique of the catalogue" in res.flat
    assert _windows() == []
