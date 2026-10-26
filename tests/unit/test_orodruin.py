"""O1: Orodruin arms itself only if its contract holds — otherwise the injector touches
nothing; every injector call is journaled before it runs; the kill revokes before it
stops. Mutants M64–M66 (scripts/mutation_check.py) are measured here."""
import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import eregion_core.orodruin as orodruin
from annatar.runner.engine import Engine
from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor

SUB = "sub-123"
BENCH = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor"
HOLDS = {
    "identity": lambda: [],
    "network": lambda: [],
    "cap": lambda: ([], {"max_injections": 20, "max_run_s": 3600}),
}


def _readers(**overrides):
    return {**HOLDS, **overrides}


# ── check: armed only if every guarantee holds, fail closed ─────────────────────

def test_a_contract_that_holds_is_armed():
    verdict = orodruin.check(HOLDS)
    assert verdict.armed and verdict.missing == []
    assert verdict.cap["max_injections"] == 20


@pytest.mark.parametrize("name, result, code", [
    ("identity", [orodruin._miss("identity_outside_bench", "x")], "identity_outside_bench"),
    ("network", [orodruin._miss("network_open", "1.1.1.1:443")], "network_open"),
    ("cap", ([orodruin._miss("cap_missing", "x")], {}), "cap_missing"),
])
def test_one_missing_guarantee_makes_it_passive(name, result, code):
    verdict = orodruin.check(_readers(**{name: lambda: result}))
    assert verdict.verdict == orodruin.PASSIVE
    assert [m["code"] for m in verdict.missing] == [code]


@pytest.mark.parametrize("name", ["identity", "network", "cap"])
def test_a_contract_that_cannot_be_read_is_passive(name):
    def boom():
        raise RuntimeError("API unreachable")
    verdict = orodruin.check(_readers(**{name: boom}))
    assert not verdict.armed
    assert verdict.missing[0]["code"] == f"{name}_unreadable"


# ── identity: inside the bench, and the rights the injectors need ───────────────

ALL_RIGHTS = [{"actions": list(orodruin.REQUIRED_ACTIONS), "notActions": []}]


def _assignment(scope, role="/providers/Microsoft.Authorization/roleDefinitions/r1"):
    return {"properties": {"scope": scope, "roleDefinitionId": role}}


def test_assignments_inside_the_bench_with_the_rights_hold():
    missing = orodruin.assess_identity(
        [_assignment(BENCH), _assignment(BENCH + "/providers/Microsoft.Compute/virtualMachines/v")],
        lambda _: ["*"], ALL_RIGHTS, BENCH, sees_subscription=True)
    assert missing == []


@pytest.mark.parametrize("scope", [
    f"/subscriptions/{SUB}",
    f"/subscriptions/{SUB}/resourceGroups/rg-glorfindel",
    BENCH + "-other",  # a prefix of the name is not the group
])
def test_an_assignment_outside_the_bench_is_missing(scope):
    missing = orodruin.assess_identity([_assignment(scope)], lambda _: ["*"], ALL_RIGHTS, BENCH, sees_subscription=True)
    assert [m["code"] for m in missing] == ["identity_outside_bench"]


def test_only_a_role_assignment_read_may_sit_outside_the_bench():
    read_only = ["Microsoft.Authorization/roleAssignments/read"]
    assert orodruin.assess_identity(
        [_assignment(f"/subscriptions/{SUB}")], lambda _: read_only, ALL_RIGHTS, BENCH, sees_subscription=True) == []
    write = read_only + ["Microsoft.Authorization/roleAssignments/write"]
    assert orodruin.assess_identity(
        [_assignment(f"/subscriptions/{SUB}")], lambda _: write, ALL_RIGHTS, BENCH, sees_subscription=True)
    # an unreadable role definition proves nothing: outside
    assert orodruin.assess_identity(
        [_assignment(f"/subscriptions/{SUB}")], lambda _: [], ALL_RIGHTS, BENCH, sees_subscription=True)


def test_a_right_the_injectors_need_is_missing():
    perms = [{"actions": ["*"], "notActions": ["Microsoft.Compute/virtualMachines/runCommand/action"]}]
    missing = orodruin.assess_identity([_assignment(BENCH)], lambda _: ["*"], perms, BENCH, sees_subscription=True)
    assert [m["code"] for m in missing] == ["identity_missing_right"]
    assert "runCommand" in missing[0]["detail"]


def test_a_listing_the_identity_cannot_fully_read_proves_nothing():
    """Measured 19/10: with read rights on the workspace only, Azure listed that
    assignment and hid the bench's — an assignment elsewhere would hide the same way."""
    missing = orodruin.assess_identity([_assignment(BENCH)], lambda _: ["*"], ALL_RIGHTS, BENCH,
                                       sees_subscription=False)
    assert [m["code"] for m in missing] == ["identity_unprovable"]


def _token(oid):
    payload = base64.urlsafe_b64encode(json.dumps({"oid": oid}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


def test_read_identity_asks_for_its_own_assignments_at_every_scope(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    credential = MagicMock()
    credential.get_token.return_value.token = _token("oid-orodruin")
    calls = []

    def get(url, headers, params, timeout):
        calls.append((url, params))
        r = MagicMock(ok=True)
        if url.endswith("/roleAssignments"):
            r.json.return_value = {"value": [_assignment(BENCH)], "nextLink": url + "?page=2"}
        elif "page=2" in url:
            r.json.return_value = {"value": [_assignment(f"/subscriptions/{SUB}")]}
        elif url.endswith(f"/subscriptions/{SUB}/providers/Microsoft.Authorization/permissions"):
            r.json.return_value = {"value": [{"actions": ["Microsoft.Authorization/roleAssignments/read"]}]}
        elif url.endswith("/permissions"):
            r.json.return_value = {"value": ALL_RIGHTS}
        else:  # the role definition of the subscription-wide assignment
            r.json.return_value = {"properties": {"permissions": [{"actions": ["*"]}]}}
        return r

    missing = orodruin.read_identity(credential=credential, get=get)
    assert calls[0][1]["$filter"] == "assignedTo('oid-orodruin')"
    assert calls[0][0] == f"{orodruin.ARM}/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments"
    assert [m["code"] for m in missing] == ["identity_outside_bench"]  # page 2 counted


# ── network and cap ────────────────────────────────────────────────────────────

def test_a_probe_that_connects_means_the_egress_is_open():
    def connect(addr, timeout):
        if addr[0] == "1.1.1.1":
            return MagicMock()
        raise TimeoutError
    missing = orodruin.read_network(connect=connect)
    assert [m["detail"] for m in missing] == ["1.1.1.1:443 reachable"]


def test_probes_that_fail_hold():
    def connect(addr, timeout):
        raise ConnectionRefusedError
    assert orodruin.read_network(connect=connect) == []


def test_the_cap_is_read_and_compared_to_its_ceiling():
    assert orodruin.read_cap({})[0][0]["code"] == "cap_missing"
    missing, _ = orodruin.read_cap({"EREGION_MAX_INJECTIONS": "500", "EREGION_MAX_RUN_S": "60"})
    assert [m["code"] for m in missing] == ["cap_exceeded"]
    assert orodruin.read_cap({"EREGION_MAX_INJECTIONS": "5", "EREGION_MAX_RUN_S": "60"}) == (
        [], {"max_injections": 5, "max_run_s": 60})


# ── M64: contract not verified → the run stays passive ─────────────────────────

def test_a_passive_contract_touches_no_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(orodruin, "READERS",
                        _readers(network=lambda: [orodruin._miss("network_open", "x")]))
    executor = _make_executor()
    engine = Engine()
    with patch.object(engine, "_get_executor_collector",
                      return_value=(executor, _make_collector())) as build, \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    assert outcome.error.startswith("passive:") and "network_open" in outcome.error
    build.assert_not_called()          # not even read: no executor built
    executor.run_script.assert_not_called()
    assert not (tmp_path / "runs").exists()  # no signal, no exercise window


def test_an_armed_contract_hands_its_session_to_the_executor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector",
                      return_value=(_make_executor(), _make_collector())) as build, \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)
    session = build.call_args.args[1]
    assert isinstance(session, orodruin.Session) and session.injector == "annatar"


def test_clean_stays_passive_without_the_contract(monkeypatch):
    from annatar.runner import initializer
    monkeypatch.setattr(orodruin, "READERS",
                        _readers(identity=lambda: [orodruin._miss("identity_outside_bench", "x")]))
    built = MagicMock()
    monkeypatch.setattr("annatar.executors.azure_vm.AzureVMExecutor", built)
    with pytest.raises(RuntimeError, match="Orodruin passive"):
        initializer.InitRunner().clean(EXFIL_YAML)
    built.assert_not_called()


# ── M65: the journal precedes the call ─────────────────────────────────────────

TARGET = {"resource_group": "rg-celebrimbor", "vm_name": "vm-celebrimbor-gondolin",
          "subscription_id": SUB}


def _executor(session, tmp_path):
    from annatar.executors.azure_vm import AzureVMExecutor
    ex = AzureVMExecutor(TARGET, session)
    ex._compute = MagicMock()
    running = MagicMock(code="PowerState/running")
    ex._compute.virtual_machines.get.return_value.instance_view.statuses = [running]
    script = tmp_path / "s.sh"
    script.write_text("echo hi\n")
    return ex, str(script)


def _lines(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def test_the_journal_is_on_disk_before_run_command(tmp_path):
    audit = tmp_path / "audit.jsonl"
    session = orodruin.Session("r1", "annatar", 5, path=audit)
    ex, script = _executor(session, tmp_path)
    seen_at_call = []

    def run_command(*a, **k):
        seen_at_call.append(_lines(audit))
        return MagicMock()

    ex._compute.virtual_machines.begin_run_command.side_effect = run_command
    ex.run_script(script)
    assert seen_at_call and len(seen_at_call[0]) == 1
    rec = seen_at_call[0][0]
    assert rec["action"] == "run_script" and rec["outcome"] == "about_to_call"
    assert rec["target"].endswith("/virtualMachines/vm-celebrimbor-gondolin")
    assert rec["run_id"] == "r1" and rec["injector"] == "annatar"


def test_the_journal_precedes_even_the_start_of_a_stopped_vm(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ex, script = _executor(orodruin.Session("r1", "annatar", 5, path=audit), tmp_path)
    ex._compute.virtual_machines.get.return_value.instance_view.statuses = []
    seen = []
    ex._compute.virtual_machines.begin_start.side_effect = lambda *a: seen.append(_lines(audit)) or MagicMock()
    ex.run_script(script)
    assert seen and len(seen[0]) == 1


def test_an_executor_without_a_session_writes_nothing(tmp_path):
    ex, script = _executor(None, tmp_path)
    with pytest.raises(orodruin.Passive):
        ex.run_script(script)
    ex._compute.virtual_machines.begin_run_command.assert_not_called()
    ex._compute.virtual_machines.begin_start.assert_not_called()


def test_the_cap_refuses_the_call_past_it(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ex, script = _executor(orodruin.Session("r1", "annatar", 1, path=audit), tmp_path)
    ex.run_script(script)
    with pytest.raises(orodruin.CapReached):
        ex.run_script(script)
    assert ex._compute.virtual_machines.begin_run_command.call_count == 1
    assert [r["outcome"] for r in _lines(audit)] == ["about_to_call", "refused_cap"]


# ── run_command (R1 atomic adapter): the same gate as run_script (X1, X6) ──────────

def test_run_command_journals_before_calling(tmp_path):
    """R1's run_command goes through _before_call too — journalled before Azure (X1)."""
    audit = tmp_path / "audit.jsonl"
    ex, _ = _executor(orodruin.Session("r1", "annatar", 5, path=audit), tmp_path)
    seen = []
    ex._compute.virtual_machines.begin_run_command.side_effect = (
        lambda *a: seen.append(_lines(audit)) or MagicMock())
    ex.run_command("id", label="atomic g1")
    assert seen and len(seen[0]) == 1
    rec = seen[0][0]
    assert rec["action"] == "run_command" and rec["outcome"] == "about_to_call"
    assert rec["detail"] == "atomic g1"
    assert rec["target"].endswith("/virtualMachines/vm-celebrimbor-gondolin")


def test_run_command_journals_before_starting_a_stopped_vm(tmp_path):
    """The journal precedes even the start of a stopped VM on the run_command path (X6)."""
    audit = tmp_path / "audit.jsonl"
    ex, _ = _executor(orodruin.Session("r1", "annatar", 5, path=audit), tmp_path)
    ex._compute.virtual_machines.get.return_value.instance_view.statuses = []
    seen = []
    ex._compute.virtual_machines.begin_start.side_effect = (
        lambda *a: seen.append(_lines(audit)) or MagicMock())
    ex.run_command("id")
    assert seen and len(seen[0]) == 1


def test_run_command_is_passive_without_a_session(tmp_path):
    ex, _ = _executor(None, tmp_path)
    with pytest.raises(orodruin.Passive):
        ex.run_command("id")
    ex._compute.virtual_machines.begin_run_command.assert_not_called()
    ex._compute.virtual_machines.begin_start.assert_not_called()


# ── M66: the kill revokes first, then cancels, stops, closes ─────────────────────

def _step(order, name, error=None):
    def step():
        order.append(name)
        if error:
            raise error
    return step


def test_kill_revokes_then_cancels_stops_and_closes():
    order = []
    failures = orodruin.kill(*(_step(order, n) for n in ("revoke", "cancel", "stop", "close")))
    assert order == ["revoke", "cancel", "stop", "close"] and failures == []


def test_a_failed_revocation_still_runs_the_rest_and_is_reported():
    order = []
    failures = orodruin.kill(_step(order, "revoke", RuntimeError("403")),
                             *(_step(order, n) for n in ("cancel", "stop", "close")))
    assert order == ["revoke", "cancel", "stop", "close"]
    assert len(failures) == 1 and failures[0].startswith("revoke:")


# ── The Terraform module (the kill script: test_orodruin_kill.py) ─────────────

import re  # noqa: E402

ORODRUIN = Path(__file__).resolve().parents[2] / "infra" / "orodruin"


def _tf() -> str:
    return (ORODRUIN / "main.tf").read_text(encoding="utf-8")


def test_the_injector_role_grants_exactly_what_the_contract_checks():
    block = _tf().split('resource "azurerm_role_definition" "injector"')[1].split("\n}\n")[0]
    actions = re.findall(r'"(Microsoft\.[^"]+)"', block.split("actions = [")[1].split("]")[0])
    assert tuple(actions) == orodruin.REQUIRED_ACTIONS


def test_the_host_acts_on_the_bench_only_and_is_no_target():
    tf = _tf()
    scopes = re.findall(r'resource "azurerm_role_assignment" "(\w+)" \{\n(?:.*\n)*?\s+scope\s+=\s+(\S+)', tf)
    assert dict(scopes) == {
        "bench_injector": "data.azurerm_resource_group.bench.id",
        "bench_logs_reader": "data.azurerm_log_analytics_workspace.bench.id",
        "contract_reader": "data.azurerm_subscription.current.id",
        "channel_writer": "azurerm_storage_container.exercises.id",
        "channel_watch_reader": "azurerm_storage_container.exercises.id",
        "channel_operator": "azurerm_storage_container.exercises.id",
        "watch_channel_reader": "azurerm_storage_container.watch.id",
        "watch_channel_writer": "azurerm_storage_container.watch.id",
    }
    # The return channel (#159): Orodruin reads it, the hosted watch writes it.
    reader_of_watch = tf.split('resource "azurerm_role_assignment" "watch_channel_reader"')[1].split("\n}\n")[0]
    assert '"Storage Blob Data Reader"' in reader_of_watch
    assert "azurerm_linux_virtual_machine.host.identity[0].principal_id" in reader_of_watch
    writer_of_watch = tf.split('resource "azurerm_role_assignment" "watch_channel_writer"')[1].split("\n}\n")[0]
    assert "var.watch_principal_id" in writer_of_watch
    # The kill (M-1) closes the open windows as the operator: writer on `exercises` alone.
    operator = tf.split('resource "azurerm_role_assignment" "channel_operator"')[1].split("\n}\n")[0]
    assert '"Storage Blob Data Contributor"' in operator
    assert "data.azurerm_client_config.operator.object_id" in operator
    reader = tf.split('resource "azurerm_role_definition" "contract_reader"')[1].split("\n}\n")[0]
    assert set(re.findall(r'"(Microsoft\.[^"]+)"', reader)) <= {
        "Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleDefinitions/read"}
    assert "count       = var.contract_reader ? 1 : 0" in reader
    assert "eregion-target" not in tf.replace("PAS de `eregion-target`", "")


def test_the_egress_is_closed_by_default_and_the_state_is_its_own():
    tf = _tf()
    deny = tf.split('resource "azurerm_network_security_rule" "egress_deny_internet"')[1].split("\n}\n")[0]
    assert 'access                      = "Deny"' in deny
    assert 'destination_address_prefix  = "Internet"' in deny
    variables = (ORODRUIN / "variables.tf").read_text(encoding="utf-8")
    locked = variables.split('variable "egress_locked"')[1].split("\n}\n")[0]
    assert "default     = true" in locked
    assert "backend" not in tf  # local state in infra/orodruin, never Celebrimbor's
