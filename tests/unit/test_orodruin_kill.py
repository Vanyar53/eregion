"""M-1: orodruin-kill stops what runs, whatever the operator's CLI context — it revokes on
the contract's subscription and never concludes « nothing to revoke » from a listing of
another one; it cancels the chaos experiments still running, closes the exercise windows
still open, and says what is left in flight. Mutants M191–M193
(scripts/mutation_check.py) are measured here; the order of the steps (M66) in
test_orodruin.py."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import eregion_core.orodruin as orodruin

KILL = Path(__file__).resolve().parents[2] / "infra" / "orodruin" / "kill.py"
CONTRACT, ELSEWHERE = "sub-contract-0001", "sub-elsewhere-0002"
VM = (f"/subscriptions/{CONTRACT}/resourceGroups/rg-orodruin/providers/Microsoft.Compute"
      "/virtualMachines/vm-orodruin")
GONDOLIN = (f"/subscriptions/{CONTRACT}/resourceGroups/rg-celebrimbor/providers"
            "/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
ASSIGNMENTS = [
    f"/subscriptions/{CONTRACT}/resourceGroups/rg-celebrimbor/providers/Microsoft.Authorization/roleAssignments/a1",
    f"/subscriptions/{CONTRACT}/providers/Microsoft.Authorization/roleAssignments/a2",
]
CHANNEL = "https://storodruin.blob.core.windows.net/exercises"
CRED = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="tok"))
NOW = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def kill_script():
    spec = importlib.util.spec_from_file_location("orodruin_kill", KILL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeAz:
    """`az` as the operator's CLI sees it: a current subscription — the wrong one by
    default — role assignments per subscription, and the bench's chaos experiments."""

    def __init__(self, current=ELSEWHERE, experiments=None, cancel_to="Cancelled"):
        self.current = current
        self.assignments = {CONTRACT: list(ASSIGNMENTS), ELSEWHERE: []}
        self.experiments = experiments or {}  # name -> statuses of its executions
        self.cancel_to = cancel_to
        self.vm_principal = "oid-1"
        self.deletes = True
        self.calls = []

    def _sub(self, args):
        return args[args.index("--subscription") + 1] if "--subscription" in args else self.current

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["role", "assignment", "list"]:
            return json.dumps(self.assignments.get(self._sub(args), []))
        if args[:3] == ["role", "assignment", "delete"]:
            ids = args[args.index("--ids") + 1:]
            if self.deletes:
                for sub in self.assignments:
                    self.assignments[sub] = [i for i in self.assignments[sub] if i not in ids]
            return ""
        if args[:2] == ["vm", "show"]:
            return self.vm_principal + "\n"
        if args[:2] == ["vm", "deallocate"]:
            return ""
        url = args[args.index("--url") + 1] if "--url" in args else ""
        path = url.split("?")[0]
        if args[:3] == ["rest", "--method", "get"] and path.endswith("/experiments"):
            if f"/subscriptions/{CONTRACT}/resourceGroups/rg-celebrimbor/" not in path:
                return json.dumps({"value": []})
            return json.dumps({"value": [_experiment(n) for n in self.experiments]})
        name = path.split("/experiments/")[1].split("/")[0] if "/experiments/" in path else ""
        if args[:3] == ["rest", "--method", "get"] and path.endswith("/executions"):
            return json.dumps({"value": [{"properties": {"status": s}} for s in self.experiments[name]]})
        if args[:3] == ["rest", "--method", "post"] and path.endswith("/cancel"):
            self.experiments[name] = [self.cancel_to if s == "Running" else s
                                      for s in self.experiments[name]]
            return ""
        raise AssertionError(f"unexpected az call: {args}")


def _experiment(name):
    return {"id": f"/subscriptions/{CONTRACT}/resourceGroups/rg-celebrimbor/providers/Microsoft.Chaos/experiments/{name}",
            "name": name,
            "properties": {"selectors": [{"type": "List", "targets": [
                {"id": f"{GONDOLIN}/providers/Microsoft.Chaos/targets/Microsoft-VirtualMachine"}]}]}}


class FakeChannel:
    """The exercises container, as exercise_channel's pull and publish reach it."""

    def __init__(self, windows, status=200):
        self.blobs = {f"{w['run_id']}.json": json.dumps(w).encode() for w in windows}
        self.status = status
        self.puts = {}

    def get(self, url, headers=None, params=None, timeout=None):
        if self.status != 200:
            return SimpleNamespace(ok=False, status_code=self.status, content=b"")
        if params and params.get("comp") == "list":
            items = "".join(f"<Blob><Name>{n}</Name><Properties><Last-Modified>"
                            "Mon, 26 Oct 2026 09:00:00 GMT</Last-Modified></Properties></Blob>"
                            for n in self.blobs)
            body = f"<EnumerationResults><Blobs>{items}</Blobs><NextMarker/></EnumerationResults>"
            return SimpleNamespace(ok=True, status_code=200, content=body.encode())
        return SimpleNamespace(ok=True, status_code=200, content=self.blobs[url.rsplit("/", 1)[1]])

    def put(self, url, headers=None, data=None, timeout=None):
        self.puts[url.rsplit("/", 1)[1]] = json.loads(data)
        return SimpleNamespace(ok=True, status_code=201)


def _window(run_id, injector="annatar", end=None, expires=NOW + timedelta(hours=1)):
    return {"run_id": run_id, "injector": injector, "kind": "technique",
            "experiment": "T1136.001 create-local-account", "targets": [GONDOLIN.lower()],
            "start": (NOW - timedelta(minutes=5)).isoformat(), "end": end,
            "expires": expires.isoformat()}


def _kill(kill_script, az, *, subscription=CONTRACT, channel=None, vm_id=VM, **kw):
    channel = channel or FakeChannel([])
    inflight, said = [], []
    failures = orodruin.kill(*kill_script.steps(
        "oid-1", vm_id, subscription=subscription, channel=CHANNEL, run=az, credential=CRED,
        get=channel.get, put=channel.put, say=said.append, inflight=inflight, now=NOW, **kw))
    return failures, inflight, said


# ── M191: revoke on the contract's subscription, never the CLI's context ───────────

def test_a_wrong_cli_context_never_concludes_nothing_to_revoke(kill_script):
    """The bug of M-1: in another subscription's context, `--all` listed nothing, and the
    kill said « no role assignment left » and exited 0 with every right intact."""
    az = FakeAz(current=ELSEWHERE)
    failures, _, _ = _kill(kill_script, az)
    assert failures == []
    assert az.assignments[CONTRACT] == []
    listings = [c for c in az.calls if c[:3] == ["role", "assignment", "list"]]
    assert listings and all(c[c.index("--subscription") + 1] == CONTRACT for c in listings)


def test_without_a_declared_subscription_the_vms_own_is_checked(kill_script):
    az = FakeAz(current=ELSEWHERE)
    failures, _, _ = _kill(kill_script, az, subscription="")
    assert failures == [] and az.assignments[CONTRACT] == []


def test_a_declared_subscription_and_the_vms_are_both_checked(kill_script):
    """orodruin.env names a subscription the VM is not in: both are listed, so a wrong
    declaration cannot hide the VM's own assignments."""
    az = FakeAz(current=ELSEWHERE)
    failures, _, _ = _kill(kill_script, az, subscription=ELSEWHERE)
    assert failures == [] and az.assignments[CONTRACT] == []
    listed = {c[c.index("--subscription") + 1] for c in az.calls if c[:3] == ["role", "assignment", "list"]}
    assert listed == {CONTRACT, ELSEWHERE}


def test_assignments_still_listed_after_the_deletion_are_a_failure(kill_script):
    az = FakeAz()
    az.deletes = False
    failures, _, _ = _kill(kill_script, az)
    assert len(failures) == 1 and failures[0].startswith("revoke:") and "still listed" in failures[0]


def test_nothing_listed_proves_nothing_for_a_principal_that_is_not_the_vms(kill_script):
    """PRINCIPAL= mistyped: nothing is listed for it — not « already revoked »."""
    az = FakeAz()
    az.assignments[CONTRACT] = []
    az.vm_principal = "oid-someone-else"
    failures, _, _ = _kill(kill_script, az)
    assert len(failures) == 1 and "nothing proven" in failures[0]


def test_nothing_listed_for_the_vms_identity_is_already_revoked(kill_script):
    az = FakeAz()
    az.assignments[CONTRACT] = []
    failures, _, said = _kill(kill_script, az)
    assert failures == []
    assert any("no role assignment left" in s for s in said)


def test_no_subscription_at_all_proves_nothing(kill_script):
    az = FakeAz()
    failures, _, _ = _kill(kill_script, az, subscription="", vm_id="vm-orodruin")
    assert {f.split(":")[0] for f in failures} == {"revoke", "cancel"}


# ── M192: a chaos experiment still running is cancelled ─────────────────────────────

def test_a_running_experiment_is_cancelled_and_its_vm_named(kill_script):
    """An experiment acts with its own identity: revoking Orodruin's does not stop it."""
    az = FakeAz(experiments={"exp-vm-shutdown": ["Success", "Running"], "exp-old": ["Success"]})
    failures, inflight, _ = _kill(kill_script, az)
    assert failures == []
    cancels = [c for c in az.calls if c[:3] == ["rest", "--method", "post"]]
    assert len(cancels) == 1 and "/experiments/exp-vm-shutdown/cancel" in cancels[0][-1]
    assert any("exp-vm-shutdown" in line and "vm-celebrimbor-gondolin" in line for line in inflight)


def test_an_execution_still_cancelling_is_said_in_flight(kill_script):
    az = FakeAz(experiments={"exp-vm-shutdown": ["Running"]}, cancel_to="Cancelling")
    failures, inflight, _ = _kill(kill_script, az)
    assert failures == []
    assert any("still Cancelling" in line for line in inflight)


def test_the_cancel_comes_after_the_revocation(kill_script):
    az = FakeAz(experiments={"exp-vm-shutdown": ["Running"]})
    _kill(kill_script, az)
    kinds = [" ".join(c[:3]) for c in az.calls]
    assert kinds.index("role assignment delete") < kinds.index("rest --method post")
    assert kinds.index("rest --method post") < kinds.index("vm deallocate --ids")


# ── M193: the windows still open are closed, and what ran is said ───────────────────

def test_the_open_windows_are_closed_and_what_ran_is_said(kill_script):
    channel = FakeChannel([
        _window("r-open"),
        _window("r-fault", injector="gothmog"),
        _window("r-done", end=(NOW - timedelta(minutes=1)).isoformat()),
        _window("r-lapsed", expires=NOW - timedelta(minutes=1)),
    ])
    failures, inflight, _ = _kill(kill_script, FakeAz(), channel=channel)
    assert failures == []
    assert set(channel.puts) == {"r-open.json", "r-fault.json"}
    for w in channel.puts.values():
        assert w["end"] == NOW.isoformat() and w["closed_by"] == "orodruin-kill"
    text = "\n".join(inflight)
    assert "r-open: a Run Command already sent runs to its end on vm-celebrimbor-gondolin" in text
    assert "r-fault: the fault may leave vm-celebrimbor-gondolin down" in text
    assert "until 10:15 UTC" in text  # the grace after the close


def test_a_channel_the_operator_cannot_read_is_a_failure_that_says_when_windows_lapse(kill_script):
    failures, _, _ = _kill(kill_script, FakeAz(), channel=FakeChannel([], status=403))
    assert len(failures) == 1 and failures[0].startswith("close:")
    assert "403" in failures[0] and "at most 2 h after it opened" in failures[0]


def test_no_channel_given_proves_nothing_about_the_windows(kill_script):
    inflight = []
    failures = orodruin.kill(*kill_script.steps(
        "oid-1", VM, subscription=CONTRACT, channel="", run=FakeAz(), say=lambda _: None,
        inflight=inflight))
    assert len(failures) == 1 and failures[0].startswith("close:")


# ── Dry run, exit code, and what is printed ─────────────────────────────────────────

def test_the_kill_dry_run_calls_nothing(kill_script, capsys):
    run = MagicMock()
    assert orodruin.kill(*kill_script.steps("oid-1", VM, subscription=CONTRACT,
                                            channel=CHANNEL, run=run, dry_run=True)) == []
    run.assert_not_called()
    out = capsys.readouterr().out
    assert out.index("role assignment list") < out.index("Microsoft.Chaos/experiments")
    assert out.index("Microsoft.Chaos/experiments") < out.index("vm deallocate")
    assert out.index("vm deallocate") < out.index("close the open windows")
    assert CONTRACT not in out  # never the subscription on screen


def test_an_incomplete_kill_exits_1_and_never_prints_the_subscription(kill_script, monkeypatch, capsys):
    az = FakeAz()
    az.deletes = False
    monkeypatch.setattr(kill_script, "az", az)
    code = kill_script.main(["oid-1", VM, "--subscription", CONTRACT, "--channel", ""])
    out = capsys.readouterr()
    assert code == 1 and "kill INCOMPLETE" in out.err
    assert CONTRACT not in out.out + out.err
