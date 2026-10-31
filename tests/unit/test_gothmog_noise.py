"""G1: benign noise — load, disk writes, a restart — run as G0's faults are, and measured only if
Glorfindel could have seen it. The fault's effect is read in the telemetry Glorfindel reads,
between the fault's start and end; noise never seen there fails the run, never passing for
noise Glorfindel ignored. The VM serves throughout: noise that takes it down is cancelled.
Mutants M2400–M2409 (scripts/mutation_check.py) are measured here.

The bench in memory is G0's (tests/unit/test_gothmog.py), with the Chaos agent's samples in
Perf: every 10 s (the bench's DCR, ``perf_sampling_frequency``), each shown ``lag_s`` after it
was taken (ingestion). It answers the disk effect's query as ransomware-disk-write computes its
``Rate`` — the mode read from the step — which a test keeps equal to the rule's text."""
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from eregion_core.experiment import validate_experiment_file
from gothmog.engines.chaos_studio import ChaosStudio, experiment_targets
from gothmog.probes import declared_errors, effect_errors
from gothmog.runner.engine import Engine, fault_errors, load_fault
from tests.unit.test_gothmog import (  # noqa: F401  (bench: the fixture, by its name)
    SUB, TARGET, VM, Cred, World, _audit, _experiment, _signals, bench)

ROOT = Path(__file__).resolve().parents[2]
AGENT = f"{VM}/providers/Microsoft.Chaos/targets/Microsoft-Agent"
DISK = "exp-celebrimbor-gondolin-disk"
CPU = "exp-celebrimbor-gondolin-cpu"
MB = 1_000_000
NOISE = ("vm-disk-write", "vm-cpu-pressure")


def _noise(name=DISK, duration="PT10M", targets=(AGENT,),
           urn="urn:csci:microsoft:agent:linuxDiskIOPressure/1.1"):
    return {"name": name, "properties": {
        "selectors": [{"id": "gondolin", "type": "List",
                       "targets": [{"id": t, "type": "ChaosTarget"} for t in targets]}],
        "steps": [{"name": "noise", "branches": [{"name": "gondolin", "actions": [{
            "type": "continuous", "name": urn, "duration": duration, "selectorId": "gondolin",
            "parameters": [{"key": "workerCount", "value": "2"}]}]}]}]}}


class Noise(World):
    """A noise fault: the VM keeps running while it runs; the agent's samples carry ``level``,
    every ``step_s``. ``extra``: samples outside the fault, ``(seconds from its start, value)``.
    ``down_after_s``: the noise takes the VM down that long in, until the fault ends."""

    def __init__(self, clock, *, level=60 * MB, step_s=10, lag_s=120, down_after_s=None, extra=(),
                 throttled=None, **kw):
        super().__init__(clock, experiment=kw.pop("experiment", None) or _noise(), effect=False, **kw)
        self.level, self.step_s, self.lag_s = level, step_s, lag_s
        self.down_after_s, self.extra = down_after_s, list(extra)
        self.throttled = throttled      # (from, to) seconds after the start: the Heartbeat query 429s
        self.windows: list[tuple[datetime, datetime]] = []   # every effect query's bounds

    def running(self):
        if self.down_after_s is not None and self.started_at is not None and not self.revived_at:
            end = self._end()
            if self.clock.t >= self.started_at + timedelta(seconds=self.down_after_s) \
                    and (end is None or self.clock.t < end):
                return False
        return super().running()

    def _samples(self):
        if self.started_at is None:
            return []
        out, t = [], self.started_at + timedelta(seconds=5)
        end = min(self._end() or self.clock.t, self.clock.t)
        while t <= end:
            out.append((t, self.level))
            t += timedelta(seconds=self.step_s)
        out += [(self.started_at + timedelta(seconds=s), v) for s, v in self.extra]
        return [(t, v) for t, v in out if t + timedelta(seconds=self.lag_s) <= self.clock.t]

    def _query(self, kql):
        if self.throttled and self.started_at is not None and "Heartbeat" in kql:
            since = (self.clock.t - self.started_at).total_seconds()
            if self.throttled[0] <= since < self.throttled[1]:
                raise RuntimeError("HTTP 429 TooManyRequests on POST …/query")
        if "Peak" not in kql:
            return super()._query(kql)
        lo, hi = (datetime.fromisoformat(x.replace("Z", "+00:00"))
                  for x in re.findall(r"datetime\(([^)]+)\)", kql))
        self.windows.append((lo, hi))
        seen = sorted((t, v) for t, v in self._samples() if lo <= t <= hi)
        if "Rate - 45000000" in kql:   # the rule's Rate: two samples averaged when fine, else one
            gaps = [(b[0] - a[0]).total_seconds() for a, b in zip(seen, seen[1:])]
            step = min((g for g in gaps if g >= 1), default=None)
            if step is not None and step <= 25:
                over = [(a[1] + b[1]) / 2 - 45 * MB for (a, b), g in zip(zip(seen, seen[1:]), gaps) if g <= 25]
            else:
                over = [v - 25 * MB for _, v in seen]
        else:
            over = [v for _, v in seen]
        # summarize without by: one row, its value null when nothing matched.
        return {"Tables": [{"TableName": "Table_0", "Columns": [{"ColumnName": "Peak"}],
                            "Rows": [[max(over) if over else None]]}]}


@pytest.fixture
def noise(bench, tmp_path):  # noqa: F811  (the imported fixture)
    """(clock, noise world factory, engine factory), on G0's bench (its clock, contract, cwd)."""
    clock, _, _ = bench
    state = {}

    def make(**kw):
        state["world"] = Noise(clock, **kw)
        return state["world"]

    def engine(**kw):
        factory = lambda session: ChaosStudio(session, credential=Cred(), http=state["world"],  # noqa: E731
                                              subscription_id=SUB)
        return Engine(bench_factory=factory, runs_dir=tmp_path / "runs", sleep=clock.sleep,
                      now=clock.now, **kw)
    return clock, make, engine


# ── The run ───────────────────────────────────────────────────────────────────────────

def test_benign_noise_runs_seen_by_glorfindels_telemetry_the_vm_serving_throughout(noise, tmp_path):
    clock, world, engine = noise
    w = world()
    out = engine().run("vm-disk-write", skip_confirm=True)

    assert out.result == "PASS", out.report["checks"]
    checks = out.report["checks"]
    assert checks["fault_effective"] == checks["steady_state_during"] == checks["revert_verified"] == "PASS"
    assert [x for x, _ in w.writes] == ["start"]          # nothing cancelled, no VM to start
    assert _signals(tmp_path, out.run_id) == ["fault_started", "fault_ended", "steady_state_restored"]
    m = out.report["metrics"]
    seen = m["effect"]["vm-celebrimbor-gondolin"][0]
    # 10-s samples at 60 MB/s: the rule's two-sample average, 15 MB/s above its 45.
    assert seen["ok"] and float(seen["observed"]) == 15 * MB and seen["seen_at"]
    assert m["seen_down_at"] is None and "steady_state_lost" not in m
    # Every effect query is bounded by the fault: from its start, never past its end.
    start, end = datetime.fromisoformat(m["fault_start"]), datetime.fromisoformat(m["fault_end"])
    assert w.windows and all(lo == start.replace(microsecond=0) and hi <= end for lo, hi in w.windows)


def test_noise_below_what_glorfindel_reads_is_not_effective(noise):
    """M2400, M2404: under the rule's threshold, Glorfindel's rule never fires — the run measures
    nothing of it, and says so."""
    clock, world, engine = noise
    world(level=20 * MB)
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.report["checks"]["fault_effective"] == "FAIL" and out.result == "FAIL"
    reading = out.report["metrics"]["effect"]["vm-celebrimbor-gondolin"][0]
    assert not reading["ok"] and reading["seen_at"] is None and float(reading["observed"]) == -25 * MB


@pytest.mark.parametrize("step_s, level, effective", [
    (10, 30 * MB, False),   # review 1, point 2: above 25 but the bench's rule, fine, wants 45 on two
    (10, 50 * MB, True),
    (60, 30 * MB, True),    # a coarse DCR: one sample above 25 is what fires the rule
    (60, 20 * MB, False),
])
def test_the_effect_is_the_rules_threshold_at_the_step_the_data_shows(noise, step_s, level, effective):
    """M2408: the effect is « the rule would have fired », as it computes its Rate — not one
    sample above 25 MB/s, which at the bench's 10-s step the rule never sees as an attack."""
    clock, world, engine = noise
    world(step_s=step_s, level=level)
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert (out.report["checks"]["fault_effective"] == "PASS") is effective


def test_noise_the_telemetry_shows_only_after_the_fault_is_still_its_effect(noise):
    """M2406: Perf lands minutes late — the run keeps looking after the fault, and the return
    is still dated when the probes first held."""
    clock, world, engine = noise
    world(lag_s=900)
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.result == "PASS", out.report["checks"]
    m = out.report["metrics"]
    assert m["time_to_restore_s"] <= 60
    assert datetime.fromisoformat(m["effect"]["vm-celebrimbor-gondolin"][0]["seen_at"]) \
        > datetime.fromisoformat(m["fault_end"])


def test_writes_before_or_after_the_fault_are_not_its_effect(noise):
    """M2401: a burst outside the fault — another job, before it or once it ended — is not
    what the fault did: the query stops at its end, even when read later."""
    clock, world, engine = noise
    burst = lambda at: [(at + 10 * i, 90 * MB) for i in range(4)]  # noqa: E731  (40 s, at the step)
    world(level=10 * MB, extra=burst(-150) + burst(700))
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.report["checks"]["fault_effective"] == "FAIL" and out.result == "FAIL"


def test_noise_that_takes_the_vm_down_is_cancelled(noise, tmp_path):
    """M2402, M2403: benign noise leaves the VM serving. Down during it, it is no longer
    benign: the experiment is cancelled, the run fails, and its return is still verified."""
    clock, world, engine = noise
    w = world(down_after_s=180)
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert [x for x, _ in w.writes] == ["start", "cancel"]
    assert w.cancelled_at - w.started_at <= timedelta(seconds=240)
    checks = out.report["checks"]
    assert checks["steady_state_during"] == "FAIL" and checks["execution"].startswith("FAIL")
    assert checks["revert_verified"] == "PASS" and out.result == "FAIL"
    m = out.report["metrics"]
    assert m["aborted"].startswith("steady state lost during the fault")
    lost = {r["name"]: r for r in m["steady_state_lost"]["vm-celebrimbor-gondolin"]}
    assert lost["vm-running"]["observed"] == "PowerState/stopped" and not lost["vm-running"]["ok"]
    assert [r["action"] for r in _audit()] == ["chaos_start", "chaos_cancel"]


def test_an_agent_target_on_a_vm_not_enrolled_is_refused(noise):
    """M72 for the agent: its VM goes through the inscription (O0, kind fault) as G0's does."""
    clock, world, engine = noise
    w = world(vm_tags={})
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.result == "REFUSED" and "missing tag" in out.error
    assert w.writes == [] and w.started_at is None


def test_a_probe_unread_for_a_poll_or_two_does_not_cancel_the_noise(noise):
    """Review 1, point 5: a throttled query (429) is not the VM down — two polls unread in a row
    pass, the noise runs to its end."""
    clock, world, engine = noise
    w = world(throttled=(60, 110))                  # the polls at 60 s and 90 s
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.result == "PASS", out.report["checks"]
    assert [x for x, _ in w.writes] == ["start"]


def test_a_probe_unread_three_polls_in_a_row_cancels_the_noise(noise):
    """M2409: unread long enough, the steady state is not known — fail closed, cancelled."""
    clock, world, engine = noise
    w = world(throttled=(60, 400))
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert [x for x, _ in w.writes] == ["start", "cancel"]
    assert w.cancelled_at - w.started_at == timedelta(seconds=120)    # the third poll unread
    assert out.report["checks"]["steady_state_during"] == "FAIL" and out.result == "FAIL"
    lost = {r["name"]: r for r in out.report["metrics"]["steady_state_lost"]["vm-celebrimbor-gondolin"]}
    assert lost["heartbeat"]["observed"].startswith("unreadable: RuntimeError: HTTP 429")


def test_a_cpu_load_runs_as_the_disk_writes_do(noise):
    clock, world, engine = noise
    world(level=97.0, experiment=_noise(name=CPU, urn="urn:csci:microsoft:agent:cpuPressure/1.0"))
    out = engine().run("vm-cpu-pressure", skip_confirm=True)
    assert out.result == "PASS", out.report["checks"]
    assert float(out.report["metrics"]["effect"]["vm-celebrimbor-gondolin"][0]["observed"]) == 97.0


def test_a_restart_is_a_short_shutdown_seen_down(bench):  # noqa: F811
    clock, world, engine = bench
    w = world(experiment=_experiment(name="exp-celebrimbor-gondolin-restart", duration="PT1M"))
    out = engine().run("vm-restart", skip_confirm=True)
    assert out.result == "PASS", out.report["checks"]
    assert out.report["checks"]["fault_effective"] == "PASS"
    assert "steady_state_during" not in out.report["checks"]      # down by design
    assert out.report["metrics"]["effect"]["vm-celebrimbor-gondolin"][0]["observed"] == "PowerState/stopped"
    assert [x for x, _ in w.writes] == ["start"]


def test_a_shutdown_checks_no_steady_state_during(bench):  # noqa: F811
    clock, world, engine = bench
    world()
    out = engine().run("vm-shutdown", skip_confirm=True)
    assert out.result == "PASS" and "steady_state_during" not in out.report["checks"]


# ── What an experiment and a fault say ────────────────────────────────────────────────

def test_an_agent_target_is_its_vm_and_a_vm_named_twice_is_one():
    assert experiment_targets(_noise()) == [VM]
    assert experiment_targets(_noise(targets=(TARGET, AGENT.upper()))) == [VM]


def test_a_fault_without_a_visible_effect_is_refused_at_load():
    """M2405: an effect Gothmog cannot read would let a fault nobody saw pass for one
    Glorfindel ignored."""
    doc = yaml.safe_load((ROOT / "gothmog" / "experiments" / "vm-disk-write.yaml").read_text())
    assert fault_errors(doc) == []
    assert any("effect declares no probe" in e for e in fault_errors({**doc, "effect": None}))
    assert effect_errors([{"name": "e", "verify": "power_state", "expect": "PowerState/stopped"}])
    assert effect_errors([{"name": "e", "verify": "vm_agent", "expect": "down"}])
    assert effect_errors([{"name": "e", "verify": "Perf | summarize Peak = max(CounterValue)", "expect": "fresh 10m"}])
    assert effect_errors([{"name": "e", "verify": "Perf | summarize Peak = max(CounterValue)", "expect": "above 25"}]) == []
    assert declared_errors([{"name": "vm", "verify": "power_state", "expect": "PowerState/running", "during": "yes"}])


@pytest.mark.parametrize("fid", ("vm-disk-write", "vm-cpu-pressure", "vm-restart"))
def test_each_noise_fault_matches_the_schema_and_the_catalog(fid):
    path = ROOT / "gothmog" / "experiments" / f"{fid}.yaml"
    assert validate_experiment_file(path) == []
    fault = load_fault(str(path))
    catalog = yaml.safe_load((ROOT / "technique_catalog.yaml").read_text())
    entry = {f["id"]: f for f in catalog["resource_types"]["azure_vm"]["faults"]}[fid]
    assert (entry["engine"], entry["engine_ref"], entry["destructive"], entry["status"]) == \
        (fault["engine"], fault["engine_ref"], False, fault["status"])
    # Planned until the bench runs it: Dagorlad shows it without a handle.
    assert fault["status"] == "planned"
    assert any(r["action"] == "start_vm" for r in fault["revert"])
    during = {p["name"] for p in fault["steady_state"]["probes"] if p.get("during")}
    assert during == ({"vm-running", "guest-agent-ready", "heartbeat"} if fid in NOISE else set())


def test_the_disk_noise_is_computed_as_the_ransomware_rule_computes_it():
    """Jonathan, 31/10: above the rule's threshold, or the RulePoller filters it and nothing
    is measured — the threshold of its mode, read from the step (review 1, point 2). The rule's
    text and the effect's are kept equal here: a change to one fails until the other follows."""
    rules = (ROOT / "glorfindel" / "rules" / "azure" / "detection_rules.yaml").read_text()
    rule = rules.split("- name: ransomware-disk-write")[1].split("- name:")[0]
    for part in ('CounterName == "Disk Write Bytes/sec"', "Step = minif(Gap, Gap >= 1s)",
                 "Fine = isnotnull(Step) and Step <= 25s",
                 "Rate = iff(Fine, iff(Gap <= 25s, (CounterValue + PrevValue) / 2, real(null)), CounterValue)",
                 "(Fine and Rate > 45000000) or (not(Fine) and Rate > 25000000)"):
        assert part in rule, part
    probe = load_fault("vm-disk-write")["effect"]["probes"][0]
    q = " ".join(probe["verify"].split())
    for part in ("CounterName == 'Disk Write Bytes/sec'", "Step = minif(Gap, Gap >= 1s)",
                 "Fine = isnotnull(Step) and Step <= 25s",
                 "Rate = iff(Fine, iff(Gap <= 25s, (CounterValue + PrevValue) / 2, real(null)), CounterValue)",
                 "Over = iff(Fine, Rate - 45000000, Rate - 25000000)", "summarize Peak = max(Over)",
                 "between (datetime({start}) .. datetime({end}))", "_ResourceId =~ '{target}'"):
        assert part in q, part
    assert probe["expect"] == "above 0"
    # The bench samples finely: the rule's fine mode is the one that applies there.
    cfg = yaml.safe_load(_tf("config.yaml"))
    assert cfg["perf_sampling_frequency"] <= 25


# ── The bench's code: Celebrimbor declares the noise, off until Jonathan applies it ─────

def _tf(name: str) -> str:
    return (ROOT / "infra" / "terraform" / name).read_text(encoding="utf-8")


def _block(tf: str, head: str) -> str:
    return tf.split(head)[1].split("\n}\n")[0]


def test_the_noise_is_declared_off_and_never_on_an_unenrolled_vm():
    cfg = yaml.safe_load(_tf("config.yaml"))
    assert cfg["chaos"]["noise_vms"] == []          # not applied: nothing created
    tf = _tf("chaos.tf")
    for head in ('resource "azurerm_user_assigned_identity" "chaos_agent"',
                 'resource "azapi_resource" "chaos_agent_target"'):
        assert "condition     = try(each.value.enrolled, true)" in _block(tf, head)
    assert "contains(keys(local.chaos_vms), each.key)" in _block(tf, 'resource "azurerm_user_assigned_identity" "chaos_agent"')
    assert 'source  = "Azure/azapi"' in _tf("main.tf")
    # The variable a plan of test overrides it with defaults to null: the config decides.
    variable = _block(_tf("variables.tf"), 'variable "chaos_noise_vms"')
    assert "default     = null" in variable
    assert ("var.chaos_noise_vms != null ? var.chaos_noise_vms : try(local.cfg.chaos.noise_vms, [])" in tf)
    # Terraform's own plan of both cases (CI runs no Terraform: by hand, as ID1's).
    tftest = _tf("tests/chaos_noise.tftest.hcl")
    assert 'run "noise_off_the_bench_plan_is_unchanged"' in tftest and "chaos_noise_vms = null" in tftest
    assert 'run "noise_on_gondolin_touches_gondolin_only"' in tftest


@pytest.mark.parametrize("kind, fid, target", [
    ("disk", "vm-disk-write", "azapi_resource.chaos_agent_target"),
    ("cpu", "vm-cpu-pressure", "azapi_resource.chaos_agent_target"),
    ("restart", "vm-restart", "azurerm_chaos_studio_target.vm"),
])
def test_each_noise_experiment_is_the_declared_one_on_its_target(kind, fid, target):
    block = _block(_tf("chaos.tf"), f'resource "azurerm_chaos_studio_experiment" "{kind}"')
    name = re.search(r'name\s+=\s+"(exp-[^"]+)"', block).group(1)
    rendered = name.replace("${local.project}", "celebrimbor").replace("${each.key}", "gondolin").replace("${local.ns}", "")
    assert rendered == load_fault(fid)["engine_ref"]
    assert f"chaos_studio_target_ids = [{target}[each.key].id]" in block
    if kind == "restart":
        assert 'abruptShutdown = "false"' in block


def test_the_noise_identities_read_their_vm_only_and_the_agent_holds_no_role():
    tf = _tf("chaos.tf")
    for kind in ("disk", "cpu"):
        role = _block(tf, f'resource "azurerm_role_assignment" "chaos_{kind}_read"')
        assert 'role_definition_name = "Reader"' in role
        assert "scope                = azurerm_linux_virtual_machine.baseline[each.key].id" in role
        assert f"azurerm_chaos_studio_experiment.{kind}[each.key].identity[0].principal_id" in role
    restart = _block(tf, 'resource "azurerm_role_assignment" "chaos_restart"')
    assert "azurerm_role_definition.chaos_vm_shutdown[0]" in restart
    assert "scope              = azurerm_linux_virtual_machine.baseline[each.key].id" in restart
    # The agent's identity only authenticates it to Chaos Studio: no role, anywhere.
    assert "chaos_agent[each.key].principal_id" not in tf
    assert len(re.findall(r'resource "azurerm_role_assignment"', tf)) == 4
