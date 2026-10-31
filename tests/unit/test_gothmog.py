"""G0: a declared fault runs only from an armed Orodruin, on targets read from the Chaos
Studio experiment and enrolled; normal is checked before (else no fault), during and after;
the return is verified by a probe, never by the engine's word. Mutants M71–M73
(scripts/mutation_check.py) are measured here.

The real client (gothmog/engines/chaos_studio.py) runs against a bench in memory behind
ARM's paths, driven by the test's clock: the journal, the refusals and the writes are the
code's own, not a mock's."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
import yaml

import eregion_core.exercise_channel as channel
import eregion_core.orodruin as orodruin
import gothmog.runner.engine as engine_mod
from eregion_core.exercise import exercises_dir
from eregion_core.experiment import validate_experiment_file
from gothmog.engines.chaos_studio import (
    ChaosStudio, experiment_targets, fault_duration_s, latest_execution)
from gothmog.probes import declared_errors
from gothmog.runner.engine import Engine, fault_errors, load_fault
from tests.unit.fake_container import CRED, URL, FakeContainer

ROOT = Path(__file__).resolve().parents[2]
SUB = "sub-123"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
OTHER_VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"
TARGET = f"{VM}/providers/Microsoft.Chaos/targets/Microsoft-VirtualMachine"
ENROLLED = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}
EXPERIMENT = "exp-celebrimbor-gondolin-shutdown"
T0 = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)


def _experiment(targets=(TARGET,), duration="PT5M", abrupt="false", selector="List", name=EXPERIMENT):
    return {"name": name, "properties": {
        "selectors": [{"id": "gondolin", "type": selector,
                       "targets": [{"id": t, "type": "ChaosTarget"} for t in targets]}],
        "steps": [{"name": "shutdown", "branches": [{"name": "gondolin", "actions": [{
            "type": "continuous", "name": "urn:csci:microsoft:virtualMachine:shutdown/1.0",
            "duration": duration, "selectorId": "gondolin",
            "parameters": [{"key": "abruptShutdown", "value": abrupt}]}]}]}]}}


class Clock:
    def __init__(self):
        self.t = T0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += timedelta(seconds=seconds)


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body if body is not None else {}

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body


class Cred:
    def get_token(self, *_):
        return type("T", (), {"token": "test-token"})()


class World:
    """The bench in memory, behind ARM's paths. Once started, the experiment holds the VM
    down for its duration, then the engine brings it back — unless the test says not."""

    def __init__(self, clock, *, experiment=None, vm_tags=ENROLLED, rg_tags=ENROLLED,
                 running=True, effect=True, comes_back=True, revive_works=True,
                 heartbeat="ok", never_ends=False, fail=None):
        self.clock = clock
        self._experiment = experiment or _experiment()
        self.name = self._experiment["name"]
        self.vm_tags, self.rg_tags = vm_tags, rg_tags
        self.running0, self.effect, self.comes_back = running, effect, comes_back
        self.revive_works, self.heartbeat, self.never_ends = revive_works, heartbeat, never_ends
        self.fail = fail or {}                  # path suffix → HTTP status
        self.started_at = self.cancelled_at = self.revived_at = None
        self.calls: list[tuple[str, str]] = []  # every (method, path)
        self.writes: list[tuple[str, int]] = []  # (what, audit lines already on disk)

    # the bench's state at the clock's time
    def _duration(self):
        return timedelta(seconds=fault_duration_s(self._experiment))

    def _end(self):
        if self.cancelled_at:
            return self.cancelled_at
        return None if self.never_ends else self.started_at + self._duration()

    def running(self):
        t = self.clock.t
        if self.revived_at and self.revive_works:
            return True
        if self.started_at is None or not self.effect:
            return self.running0
        end = self._end()
        if end is None or t < end:
            return False
        return self.comes_back

    def _execution(self):
        end, t = self._end(), self.clock.t
        if self.cancelled_at:
            status = "Cancelled"
        elif end is None or t < end:
            status = "Running"
        else:
            status = "Success"
        props = {"status": status, "startedAt": self.started_at.isoformat()}
        if status != "Running":
            props["stoppedAt"] = end.isoformat()
        return {"name": "exec-1", "properties": props}

    def _heartbeat(self):
        t = self.clock.t
        if self.heartbeat == "stale" or (not self.running0 and self.started_at is None):
            return t - timedelta(hours=3)
        if self.started_at is None:
            return t
        if self.running() and (self.heartbeat == "ok" or self.revived_at):
            return t
        return self.started_at

    # ARM
    def _query(self, kql):
        # The shape ARM answers (measured 19/10): Tables / Columns / ColumnName / Rows.
        return {"Tables": [{"TableName": "Table_0", "Columns": [{"ColumnName": "LastSeen"}],
                            "Rows": [[self._heartbeat().isoformat()]]}]}

    def _route(self, method, url, params, body=None):
        path = url[len("https://management.azure.com"):]
        self.calls.append((method, path))
        for suffix, status in self.fail.items():
            if path.endswith(suffix):
                return Resp(status, {"error": {"code": "AuthorizationFailed"}})
        low = path.lower()
        if method == "post":
            audited = len(orodruin.audit_path().read_text().splitlines()) if orodruin.audit_path().exists() else 0
            if low.endswith("/api/query"):
                return Resp(200, self._query((body or {}).get("query") or ""))
            if low.endswith(f"/experiments/{self.name}/start"):
                self.writes.append(("start", audited))
                self.started_at = self.clock.t
            elif low.endswith(f"/experiments/{self.name}/cancel"):
                self.writes.append(("cancel", audited))
                self.cancelled_at = self.clock.t
            elif low.endswith("/virtualmachines/vm-celebrimbor-gondolin/start"):
                self.writes.append(("start_vm", audited))
                self.revived_at = self.clock.t
            else:
                raise AssertionError(f"unexpected POST {path}")
            return Resp(202)
        if low.endswith(f"/experiments/{self.name}"):
            return Resp(200, self._experiment)
        if low.endswith(f"/experiments/{self.name}/executions"):
            return Resp(200, {"value": [self._execution()] if self.started_at else []})
        if low.endswith("/virtualmachines/vm-celebrimbor-gondolin"):
            state = "PowerState/running" if self.running() else "PowerState/stopped"
            return Resp(200, {"name": "vm-celebrimbor-gondolin", "tags": self.vm_tags, "properties": {"instanceView": {
                "statuses": [{"code": "ProvisioningState/succeeded"}, {"code": state}],
                "vmAgent": {"statuses": [{"displayStatus": "Ready" if self.running() else "Not Ready"}]}}}})
        if low.endswith("/resourcegroups/rg-celebrimbor"):
            return Resp(200, {"tags": self.rg_tags})
        raise AssertionError(f"unexpected GET {path}")

    def get(self, url, headers=None, params=None, json=None, timeout=None):
        return self._route("get", url, params)

    def post(self, url, headers=None, params=None, json=None, timeout=None):
        return self._route("post", url, params, json)


def _armed(max_injections=10, max_run_s=3600):
    def fake(run_id, injector, verdict=None, request=""):
        v = orodruin.Verdict(orodruin.ARMED, cap={"max_injections": max_injections, "max_run_s": max_run_s})
        return v, orodruin.Session(run_id, injector, max_injections, request=request)
    return fake


def _passive(run_id, injector, verdict=None, request=""):
    return orodruin.Verdict(orodruin.PASSIVE, [orodruin._miss("network_open", "1.1.1.1:443 reachable")]), None


@pytest.fixture
def bench(tmp_path, monkeypatch):
    """(clock, world factory, engine factory) — the run's files under tmp_path."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(engine_mod, "arm", _armed())
    clock = Clock()
    state = {}

    def world(**kw):
        state["world"] = World(clock, **kw)
        return state["world"]

    def engine(**kw):
        factory = lambda session: ChaosStudio(session, credential=Cred(), http=state["world"],  # noqa: E731
                                              subscription_id=SUB)
        return Engine(bench_factory=factory, runs_dir=tmp_path / "runs", sleep=clock.sleep,
                      now=clock.now, **kw)
    return clock, world, engine


def _audit():
    path = orodruin.audit_path()
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _signals(tmp_path, run_id):
    path = tmp_path / "runs" / "gothmog" / f"{run_id}_signals.jsonl"
    return [json.loads(line)["event"] for line in path.read_text().splitlines()]


def _window(run_id):
    return json.loads((exercises_dir() / f"{run_id}.json").read_text())


def _no_window():
    return not exercises_dir().exists() or not list(exercises_dir().iterdir())


# ── The whole run ─────────────────────────────────────────────────────────────────────

def test_a_fault_runs_and_its_return_is_verified(bench, tmp_path):
    clock, world, engine = bench
    w = world()
    out = engine().run("vm-shutdown", skip_confirm=True)

    assert out.result == "PASS", out.report["checks"]
    assert set(out.report["checks"].values()) == {"PASS"}
    assert [x for x, _ in w.writes] == ["start"]
    assert _signals(tmp_path, out.run_id) == ["fault_started", "fault_ended", "steady_state_restored"]
    m = out.report["metrics"]
    assert m["seen_down_at"] and m["execution_status"] == "Success" and not m["fallback_used"]
    assert 0 < m["time_to_restore_s"] <= 600
    # Recorded like Annatar's run: runs/<run_id>.json, the same keys.
    saved = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())
    assert set(saved) == {"scenario", "run_id", "mitre", "result", "metrics", "thresholds", "checks"}
    # An exercise window of kind fault, on the target, closed.
    window = _window(out.run_id)
    assert window["kind"] == "fault" and window["injector"] == "gothmog"
    assert window["targets"] == [VM.lower()] and window["end"]


def test_the_probes_values_before_the_fault_are_in_the_report(bench, tmp_path):
    """M246 (#193): the console shows the steady state before the fault as it shows it
    after — the same form, by VM, each probe's observed value."""
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    m = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())["metrics"]
    assert set(m["before"]) == set(m["after"]) == {"vm-celebrimbor-gondolin"}
    before = {p["name"]: p for p in m["before"]["vm-celebrimbor-gondolin"]}
    assert set(before) == {p["name"] for p in m["after"]["vm-celebrimbor-gondolin"]}
    assert all(set(p) == {"name", "ok", "observed", "expect"} and p["ok"] for p in before.values())
    assert before["vm-running"]["observed"] == "PowerState/running"
    assert before["guest-agent-ready"]["observed"] == "Ready"


def test_the_report_goes_to_h0_with_its_window(bench, tmp_path, monkeypatch):
    """M241 (#193): with an exercise channel, the report is published at the end of the run,
    after its window closes — the last write of the run."""
    container = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", container.put)
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    # Orodruin's journal goes to the channel too (SEC5, V-29), under audit/.
    assert [p for p in container.puts if not p.startswith("audit/")] == [
        f"{out.run_id}.json", f"{out.run_id}.json", f"runs/{out.run_id}.json"]
    assert f"audit/{out.run_id}.jsonl" in container.puts
    published = json.loads(container.body(f"runs/{out.run_id}.json"))
    assert published == json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())
    assert published["checks"]["revert_verified"] == "PASS" and published["metrics"]["before"]


def test_the_start_is_journaled_before_it_is_sent(bench):
    clock, world, engine = bench
    w = world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    records = _audit()
    assert [r["action"] for r in records] == ["chaos_start"]
    assert records[0]["run_id"] == out.run_id and records[0]["injector"] == "gothmog"
    assert w.writes == [("start", 1)]  # one journal line on disk when the POST arrived


def test_signals_stay_out_of_what_glorfindel_watch_reads(bench, tmp_path):
    """The watch sends every runs/*_signals.jsonl event but attack_started to decide."""
    clock, world, engine = bench
    world()
    engine().run("vm-shutdown", skip_confirm=True)
    assert list((tmp_path / "runs").glob("*_signals.jsonl")) == []
    assert list((tmp_path / "runs" / "gothmog").glob("*_signals.jsonl"))


# ── Nothing before the contract, the targets, the steady state ────────────────────────

def test_a_passive_contract_reads_nothing(bench, monkeypatch):
    clock, world, engine = bench
    w = world()
    monkeypatch.setattr(engine_mod, "arm", _passive)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "PASSIVE" and "network_open" in out.error
    assert w.calls == [] and _audit() == []


def test_a_cap_too_low_to_cancel_and_revert_is_refused(bench, monkeypatch):
    clock, world, engine = bench
    w = world()
    monkeypatch.setattr(engine_mod, "arm", _armed(max_injections=2))
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED" and "cap" in out.error
    assert w.calls == []


@pytest.mark.parametrize("vm_tags, rg_tags, why", [
    ({}, ENROLLED, "missing tag"),                                              # not enrolled
    ({"eregion-target": "celebrimbor"}, ENROLLED, "without a zone"),            # no zone
    ({"eregion-target": "celebrimbor", "eregion-zone": "production"},
     {"eregion-target": "celebrimbor"}, "never runs in production"),           # production
    (ENROLLED, {}, "resource group missing tag"),                               # group not enrolled
])
def test_an_experiment_target_not_enrolled_for_a_fault_is_refused(bench, vm_tags, rg_tags, why):
    """M72: the experiment's own targets go through the inscription (O0, kind fault)."""
    clock, world, engine = bench
    w = world(vm_tags=vm_tags, rg_tags=rg_tags)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED" and why in out.error
    assert w.writes == [] and w.started_at is None


@pytest.mark.parametrize("experiment, why", [
    (_experiment(targets=(TARGET, f"{OTHER_VM}/providers/Microsoft.Chaos/targets/Microsoft-VirtualMachine")),
     "the fault declares"),                                    # a target nobody declared
    (_experiment(selector="Query"), "only a fixed list"),       # dynamic: unknowable targets
    (_experiment(targets=()), "names no target"),
    (_experiment(abrupt="true"), "abruptly"),                   # not what the fault declares
    (_experiment(duration="PT2H"), "the cap"),                  # outlives the run's cap
])
def test_an_experiment_unlike_its_declaration_is_refused(bench, experiment, why):
    clock, world, engine = bench
    w = world(experiment=experiment)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED" and why in out.error
    assert w.writes == []


@pytest.mark.parametrize("kw", [
    {"running": False},          # deallocated (the nightly shutdown): not normal
    {"heartbeat": "stale"},      # running, but the telemetry Glorfindel reads is silent
    {"fail": {"/api/query": 403}},  # a probe that cannot be read is not normal
])
def test_no_fault_without_the_steady_state_verified_before(bench, tmp_path, kw):
    """M71: the fault starts only once every probe holds."""
    clock, world, engine = bench
    w = world(**kw)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED" and "steady state not verified" in out.error
    assert w.writes == [] and _audit() == []
    assert out.report["checks"] == {"targets": "PASS", "steady_state_before": "FAIL"}
    assert _no_window()


# ── During and after ──────────────────────────────────────────────────────────────────

def test_a_vm_the_engine_does_not_bring_back_is_started_by_the_declared_revert(bench):
    clock, world, engine = bench
    w = world(comes_back=False)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert [x for x, _ in w.writes] == ["start", "start_vm"]
    assert [r["action"] for r in _audit()] == ["chaos_start", "start_vm"]
    assert out.report["metrics"]["fallback_used"] is True
    assert out.report["checks"]["revert_verified"] == "PASS"


@pytest.mark.parametrize("kw", [
    {"comes_back": False, "revive_works": False},   # the VM stays down
    {"heartbeat": "never_after"},                   # up, but its monitoring agent never returns
])
def test_a_return_no_probe_confirms_is_not_verified(bench, tmp_path, kw):
    """M73: the engine's success is not the return — only a probe is."""
    clock, world, engine = bench
    world(**kw)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.report["checks"]["revert_verified"] == "FAIL"
    assert out.result == "FAIL"
    assert _signals(tmp_path, out.run_id)[-1] == "revert_failed"


def test_an_execution_that_outlives_its_duration_is_cancelled(bench):
    clock, world, engine = bench
    w = world(never_ends=True)
    out = engine(abort_margin_s=300).run("vm-shutdown", skip_confirm=True)
    assert [x for x, _ in w.writes] == ["start", "cancel"]
    assert w.cancelled_at - w.started_at >= timedelta(seconds=600)
    assert out.report["checks"]["execution"].startswith("FAIL")
    assert out.report["checks"]["revert_verified"] == "PASS"   # the cancel brought it back
    assert out.result == "FAIL"


def test_a_fault_never_seen_is_not_effective(bench):
    clock, world, engine = bench
    world(effect=False)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.report["checks"]["fault_effective"] == "FAIL" and out.result == "FAIL"


def test_a_start_refused_injects_nothing_and_is_recorded(bench, tmp_path):
    clock, world, engine = bench
    w = world(fail={f"/experiments/{EXPERIMENT}/start": 403})
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "FAIL" and "AuthorizationFailed" in out.error
    assert w.started_at is None
    assert (tmp_path / "runs" / f"{out.run_id}.json").exists()
    assert _window(out.run_id)["end"]  # the window opened for the start is closed


def test_an_interrupted_run_cancels_the_experiment_and_closes_its_window(bench):
    clock, world, engine = bench
    w = world()
    ticks = []

    def sleep(seconds):
        ticks.append(seconds)
        if len(ticks) == 2:
            raise KeyboardInterrupt
        clock.sleep(seconds)

    e = engine()
    e._sleep = sleep
    with pytest.raises(KeyboardInterrupt):
        e.run("vm-shutdown", skip_confirm=True)
    assert [x for x, _ in w.writes] == ["start", "cancel"]
    run_id = _audit()[0]["run_id"]
    assert _window(run_id)["end"]


# ── Preflight, writes without a session ────────────────────────────────────────────────

def test_preflight_reads_and_writes_nothing(bench, tmp_path):
    clock, world, engine = bench
    w = world()
    out = engine().preflight("vm-shutdown")
    assert out.result == "OK" and out.report["targets"] == [VM]
    assert all(m == "get" or p.endswith("/api/query") for m, p in w.calls)
    assert w.writes == [] and _audit() == []
    assert _no_window()


@pytest.mark.parametrize("write", ["start", "cancel", "start_vm"])
def test_a_write_without_a_session_is_refused_before_any_call(write):
    calls = []

    class Http:
        def post(self, *a, **k):
            calls.append(a)
            return Resp(202)
    studio = ChaosStudio(None, credential=Cred(), http=Http(), subscription_id=SUB)
    with pytest.raises(orodruin.Passive):
        getattr(studio, write)(VM if write == "start_vm" else EXPERIMENT)
    assert calls == []


# ── What an experiment says ────────────────────────────────────────────────────────────

def test_the_targets_are_the_vms_behind_the_chaos_targets():
    assert experiment_targets(_experiment()) == [VM]
    with pytest.raises(ValueError, match="not a VM"):
        experiment_targets(_experiment(targets=(f"{RG}/providers/Microsoft.Network/networkSecurityGroups/n"
                                                "/providers/Microsoft.Chaos/targets/Microsoft-NetworkSecurityGroup",)))


def test_steps_add_up_and_branches_run_side_by_side():
    exp = {"properties": {"steps": [
        {"branches": [{"actions": [{"duration": "PT5M"}, {"duration": "PT1M"}]},
                      {"actions": [{"duration": "PT2M"}]}]},
        {"branches": [{"actions": [{"duration": "PT30S"}, {"name": "discrete"}]}]}]}}
    assert fault_duration_s(exp) == 6 * 60 + 30


def test_the_run_follows_its_own_execution():
    old = {"name": "old", "properties": {"startedAt": (T0 - timedelta(hours=1)).isoformat()}}
    mine = {"name": "mine", "properties": {"startedAt": (T0 + timedelta(seconds=5)).isoformat()}}
    assert latest_execution([old, mine], T0)["name"] == "mine"
    assert latest_execution([old], T0) is None


def test_a_fault_gothmog_cannot_run_or_check_is_refused_at_load():
    assert any("engine" in e for e in fault_errors({"kind": "fault", "engine": "local-script"}))
    assert any("destructive" in e for e in fault_errors({"kind": "fault", "engine": "chaos-studio"}))
    assert declared_errors([]) and declared_errors(None)
    assert declared_errors([{"name": "hb", "verify": "Heartbeat", "expect": "recent"}])
    assert declared_errors([{"name": "vm", "verify": "power_state", "expect": "PowerState/running"}]) == []


# ── The declaration, the catalog, the bench's code ────────────────────────────────────

def test_the_declared_fault_matches_the_schema_and_the_catalog():
    path = ROOT / "gothmog" / "experiments" / "vm-shutdown.yaml"
    assert validate_experiment_file(path) == []
    fault = load_fault(str(path))
    catalog = yaml.safe_load((ROOT / "technique_catalog.yaml").read_text())
    entry = {f["id"]: f for f in catalog["resource_types"]["azure_vm"]["faults"]}[fault["id"]]
    assert (entry["engine"], entry["engine_ref"], entry["destructive"]) == \
        (fault["engine"], fault["engine_ref"], fault["destructive"])
    assert any(r["action"] == "start_vm" for r in fault["revert"])


def _chaos_tf() -> str:
    return (ROOT / "infra" / "terraform" / "chaos.tf").read_text(encoding="utf-8")


def test_chaos_studio_never_targets_an_unenrolled_vm():
    """On since the bench got it (19/10): the repo keeps the deployed state, or the next
    celebrimbor-up would destroy the experiment. What must hold is who it may target."""
    cfg = yaml.safe_load((ROOT / "infra" / "terraform" / "config.yaml").read_text())
    assert all(cfg["vms"][k] is None or cfg["vms"][k].get("enrolled", True) for k in cfg["chaos"]["shutdown_vms"])
    tf = _chaos_tf()
    assert "condition     = try(each.value.enrolled, true)" in tf


def test_the_experiment_is_the_declared_one_and_shuts_down_gracefully():
    tf = _chaos_tf()
    name = re.search(r'name\s+=\s+"(exp-[^"]+)"', tf).group(1)
    rendered = name.replace("${local.project}", "celebrimbor").replace("${each.key}", "gondolin").replace("${local.ns}", "")
    assert rendered == load_fault("vm-shutdown")["engine_ref"]
    assert 'abruptShutdown = "false"' in tf and '"true"' not in tf


def test_the_experiment_identity_acts_on_its_vm_only_and_cannot_delete_it():
    tf = _chaos_tf()
    role = tf.split('resource "azurerm_role_definition" "chaos_vm_shutdown"')[1].split("\n}\n")[0]
    assert set(re.findall(r'"(Microsoft\.[^"]+)"', role)) == {
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/powerOff/action",
        "Microsoft.Compute/virtualMachines/start/action",
    }
    assignment = tf.split('resource "azurerm_role_assignment" "chaos_vm_shutdown"')[1].split("\n}\n")[0]
    assert "scope              = azurerm_linux_virtual_machine.baseline[each.key].id" in assignment


def test_orodruin_may_start_follow_and_cancel_an_experiment():
    for action in ("Microsoft.Chaos/experiments/read", "Microsoft.Chaos/experiments/start/action",
                   "Microsoft.Chaos/experiments/cancel/action", "Microsoft.Chaos/experiments/executions/read"):
        assert action in orodruin.REQUIRED_ACTIONS


def test_gothmog_ships_in_orodruins_image():
    assert "COPY gothmog/ gothmog/" in (ROOT / "annatar" / "Dockerfile").read_text()


# ── V1 (#214): no live Glorfindel watch, no fault ─────────────────────────────────────

@pytest.fixture
def no_watch(tmp_path, monkeypatch):
    """The gate's real readers (conftest sees a live watch elsewhere), a throwaway HOME with
    no heartbeat, no channel; Orodruin's contract recorded — the first call to the cloud."""
    import eregion_core.watch_gate as gate
    monkeypatch.setattr(gate, "READERS", {"channel": gate.channel_beat, "local": gate.local_beat})
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("EREGION_WATCH_CHANNEL", raising=False)
    armed = []
    real = engine_mod.arm

    def arm(run_id, injector, *a, **kw):
        armed.append(run_id)
        return real(run_id, injector, *a, **kw)
    monkeypatch.setattr(engine_mod, "arm", arm)
    return armed


def test_a_fault_without_a_live_watch_is_refused_before_any_cloud_call(bench, no_watch, tmp_path):
    """M724, M725: refused, says since when — and nothing reached the cloud: no contract, no
    read of the bench, no window, no report."""
    clock, world, engine = bench
    w = world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED"
    assert out.error.startswith(
        "glorfindel: local file ~/.glorfindel/watch_heartbeat: last heartbeat never")
    assert no_watch == [] and w.calls == [] and w.writes == []
    assert _no_window() and not (tmp_path / "runs").exists()


def test_gothmog_cli_refuses_without_a_watch_and_exits_nonzero(bench, no_watch):
    from click.testing import CliRunner

    from gothmog.cli import cli
    clock, world, engine = bench
    w = world()
    res = CliRunner().invoke(cli, ["run", "vm-shutdown", "--yes"])
    assert res.exit_code != 0
    assert "no live Glorfindel watch" in res.output and "last heartbeat never" in res.output
    assert no_watch == [] and w.calls == []


def test_a_fault_without_glorfindel_runs_and_its_report_says_so(bench, no_watch, tmp_path):
    """M726: --without-glorfindel runs with no watch, and the report carries it."""
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True, without_glorfindel=True)
    assert out.result == "PASS", out.report["checks"]
    m = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())["metrics"]
    assert m["without_glorfindel"] is True
    assert m["detection_note"] == "detection not measured, by choice"


def test_a_refused_fault_without_glorfindel_still_says_so(bench, no_watch, tmp_path):
    """A refusal after the contract (here: the target not enrolled) is recorded with the flag."""
    clock, world, engine = bench
    world(vm_tags={})
    out = engine().run("vm-shutdown", skip_confirm=True, without_glorfindel=True)
    assert out.result == "REFUSED"
    m = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())["metrics"]
    assert m["without_glorfindel"] is True


def test_a_fault_with_glorfindel_says_nothing_of_it(bench, tmp_path):
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    m = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())["metrics"]
    assert "without_glorfindel" not in m


def test_preflight_without_a_live_watch_is_refused_before_the_contract(bench, no_watch):
    """M727: the preflight answers « could the run start? » — not without a watch."""
    clock, world, engine = bench
    w = world()
    out = engine().preflight("vm-shutdown")
    assert out.result == "REFUSED" and out.error.startswith("glorfindel: ")
    assert no_watch == [] and w.calls == []
    assert engine().preflight("vm-shutdown", without_glorfindel=True).result == "OK"


def test_gothmog_cli_passes_without_glorfindel(monkeypatch):
    from click.testing import CliRunner

    from gothmog.cli import cli
    seen = {}

    class Fake:
        def run(self, fault, skip_confirm=False, without_glorfindel=False):
            seen["run"] = without_glorfindel
            return type("O", (), {"result": "PASS"})()

        def preflight(self, fault, without_glorfindel=False):
            seen["preflight"] = without_glorfindel
            return type("O", (), {"result": "OK"})()
    monkeypatch.setattr(engine_mod, "Engine", Fake)
    assert CliRunner().invoke(cli, ["run", "x", "--yes", "--without-glorfindel"]).exit_code == 0
    assert CliRunner().invoke(cli, ["preflight", "x", "--without-glorfindel"]).exit_code == 0
    assert seen == {"run": True, "preflight": True}


# ── SEC5: the watch read again before the fault, the dev run in Orodruin's journal ──────

def test_a_watch_gone_before_the_start_stops_the_fault(bench, monkeypatch):
    """SEC5 (N-03): the watch is read before the run and again right before the fault starts
    — the targets and the steady state took minutes. Gone by then: nothing is started."""
    import eregion_core.watch_gate as gate
    clock, world, engine = bench
    w = world()
    reads = []
    live = gate.READERS["local"]

    def local():
        reads.append(1)
        return live() if len(reads) == 1 else gate.Beat(gate.LOCAL, None, "the watch stopped")
    monkeypatch.setitem(gate.READERS, "local", local)
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "REFUSED" and out.error.startswith("glorfindel: lost before the fault")
    assert [x for x, _ in w.writes] == [] and len(reads) == 2
    assert not [r for r in _audit() if r.get("action") == "chaos_start"]


def test_a_fault_without_glorfindel_is_written_to_orodruins_journal(bench, no_watch):
    """SEC5 (N-04): not only in the run's report — in Orodruin's journal too, before the
    first call."""
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True, without_glorfindel=True)
    records = _audit()
    declared = [r for r in records if r["outcome"] == "declared"]
    assert [(r["run_id"], r["action"]) for r in declared] == [(out.run_id, "without_glorfindel")]
    assert records.index(declared[0]) < next(i for i, r in enumerate(records)
                                             if r["outcome"] == "about_to_call")


def test_a_fault_run_writes_the_unified_run_format(bench, tmp_path):
    """C1 (M1802): a fault's report says it is a fault, by Gothmog, of its declared id — the
    run format Annatar shares, so the coverage matrix gives it its row."""
    from eregion_core.run_report import RUN_FORMAT, read_run
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    saved = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())
    m = saved["metrics"]
    assert (m["run_format"], m["kind"], m["injector"], m["experiment_id"]) == (RUN_FORMAT, "fault", "gothmog", "vm-shutdown")
    run = read_run(saved)
    assert run["kind"] == "fault" and run["experiment"] == "vm-shutdown" and run["result"] == "PASS"


# ── DG-b: a wire of a Dagorlad request; the VMs each experiment aims at, read without Orodruin ──

REQ = "r-20261030T080000Z-abcdef"


def test_a_fault_from_a_request_writes_its_id_in_the_window_the_journal_and_the_report(bench, tmp_path):
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True, request=REQ, target=VM)
    assert out.result == "PASS", out.report["checks"]
    assert _window(out.run_id)["request"] == REQ
    assert {line["request"] for line in _audit()} == {REQ}
    saved = json.loads((tmp_path / "runs" / f"{out.run_id}.json").read_text())
    assert saved["metrics"]["request"] == REQ and saved["metrics"]["experiment_id"] == "vm-shutdown"


def test_a_wire_on_a_vm_the_fault_does_not_declare_is_refused_before_anything(bench, monkeypatch):
    clock, world, engine = bench
    w = world()

    def no_arm(*a, **k):
        raise AssertionError("armed for a VM the fault does not aim at")
    monkeypatch.setattr(engine_mod, "arm", no_arm)
    out = engine().run("vm-shutdown", skip_confirm=True, request=REQ, target=OTHER_VM)
    assert out.result == "REFUSED" and out.error.startswith("no_engine:")
    assert w.writes == [] and _audit() == [] and _no_window()


def test_the_targets_of_each_fault_are_read_without_orodruin(monkeypatch):
    from click.testing import CliRunner

    from gothmog.cli import cli

    def no_arm(*a, **k):
        raise AssertionError("Orodruin armed to read declared targets")
    monkeypatch.setattr(engine_mod, "arm", no_arm)
    res = CliRunner().invoke(cli, ["targets", "--json"], catch_exceptions=False)
    assert res.exit_code == 0
    every = {f: ["vm-celebrimbor-gondolin"] for f in ("vm-cpu-pressure", "vm-disk-write", "vm-restart", "vm-shutdown")}
    assert json.loads(res.output) == every
    assert engine_mod.declared_targets() == every


def test_a_request_id_is_checked_and_never_goes_without_glorfindel():
    from click.testing import CliRunner

    from gothmog.cli import cli
    for args in (["--request", "../x"], ["--request", REQ, "--without-glorfindel"]):
        res = CliRunner().invoke(cli, ["run", "vm-shutdown", "--yes", *args])
        assert res.exit_code != 0 and "--request takes a request id" in res.output


def test_a_wire_on_a_vm_of_the_same_name_in_another_group_is_refused_before_the_fault(bench):
    """DG-b review, point 2: the twin's VM shares its name with the bench's. The wire names the
    twin's; the experiment acts on the bench's — compared by full id, never by name."""
    clock, world, engine = bench
    w = world()
    twin = VM.replace("/resourceGroups/rg-celebrimbor/", "/resourceGroups/rg-celebrimbor-twin/")
    out = engine().run("vm-shutdown", skip_confirm=True, request=REQ, target=twin)
    assert out.result == "REFUSED" and out.error.startswith("no_engine:")
    assert w.writes == [] and _no_window()


def _destructive_fault(tmp_path):
    doc = yaml.safe_load((engine_mod.EXPERIMENTS_DIR / "vm-shutdown.yaml").read_text())
    doc["destructive"] = True
    path = tmp_path / "vm-wipe.yaml"
    path.write_text(yaml.safe_dump(doc))
    return str(path)


@pytest.mark.parametrize("typed", ["", "vm-celebrimbor-bree"])
def test_a_destructive_fault_from_a_request_runs_only_on_the_vm_typed(bench, tmp_path, typed):
    """§7, DG-b review: the name typed for a destructive fault, compared to the name Azure gives
    the VM, before the fault starts."""
    clock, world, engine = bench
    w = world()
    out = engine().run(_destructive_fault(tmp_path), skip_confirm=True, request=REQ, target=VM,
                       typed_name=typed)
    assert out.result == "REFUSED" and out.error.startswith("typed_name:")
    assert w.writes == [] and _no_window()


def test_a_destructive_fault_with_its_name_typed_starts(bench, tmp_path):
    clock, world, engine = bench
    w = world()
    out = engine().run(_destructive_fault(tmp_path), skip_confirm=True, request=REQ, target=VM,
                       typed_name="vm-celebrimbor-gondolin")
    assert out.result == "PASS", out.error
    assert [x for x, _ in w.writes] == ["start"]
