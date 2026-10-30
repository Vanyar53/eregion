"""Gothmog's run (G0): a declared fault, on enrolled targets, from an armed Orodruin —
normal checked before, during and after, the return to the initial state verified.

    0  watch     a live Glorfindel watch (V1, eregion_core/watch_gate.py), its heartbeat read
                 before anything else reaches the cloud; none: refused. ``--without-glorfindel``
                 runs anyway, and the report says so (``metrics.without_glorfindel``)
    1  contract  arm(run_id, "gothmog"). Passive: nothing read, nothing touched. A cap
                 too low to cancel and revert is refused too (MIN_CALLS).
    2  targets   read from the Chaos Studio experiment itself; each one declared by the
                 fault, inside the bench, enrolled, in a zone that takes a fault (O0)
    3  before    every steady-state probe holds on every target — otherwise no fault
    4  inject    exercise window opened (kind fault), the start journaled then sent,
                 ``fault_started``
    5  during    the execution followed; the fault must be seen (the VM down). Past its
                 duration and a margin, or the run's cap, the experiment is cancelled
    6  after     the probes again, the heartbeat later than the fault's end. If the engine
                 did not bring the VM back: the declared revert (start it), then the probes
                 again. The return is verified only by a probe, never by the engine's word
    7  record    ``runs/<run_id>.json`` as Annatar's, the probes' values before and after
                 in ``metrics.before`` / ``metrics.after``; window closed, and with an
                 exercise channel the report goes to H0 with it (#193); signals in
                 ``runs/gothmog/`` (``gothmog/signals/emitter.py``)

``preflight`` runs 0–3 with no session at all: a write there is refused by construction.
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from rich.console import Console
from rich.prompt import Confirm

from eregion_core import run_report, watch_gate
from eregion_core.exercise import close_window, open_window
from eregion_core.exercise_channel import carry_run
from eregion_core.inscription import BENCH_ENV, DEFAULT_BENCH, Scope, check_target, rg_from_id
from eregion_core.orodruin import arm
from gothmog.engines.chaos_studio import (
    DOWN, ChaosStudio, _parse, experiment_targets, fault_duration_s, is_terminal,
    latest_execution, power_state)
from gothmog.probes import declared_errors, evaluate, holds
from gothmog.runner.report import RunReport
from gothmog.signals.emitter import SignalEmitter

console = Console()

EXPERIMENTS_DIR = Path(__file__).resolve().parents[1] / "experiments"
ENGINE = "chaos-studio"
# Start, cancel, start a VM: the most a run writes. A cap below cannot let it come back.
MIN_CALLS = 3
POLL_S = 30.0
ABORT_MARGIN_S = 300.0      # past the declared duration, the experiment is cancelled
RESTORE_TIMEOUT_S = 600.0   # boot + guest agent + first heartbeat ingested (1–3 min measured)
SUCCESS = frozenset({"success", "succeeded", "completed"})


@dataclass
class RunOutcome:
    run_id: str
    result: str                 # PASS, FAIL, REFUSED, PASSIVE, OK (preflight)
    error: str | None = None
    report: dict = field(default_factory=dict)


# ── The declared fault ────────────────────────────────────────────────────────────────

def fault_errors(doc) -> list[str]:
    """What Gothmog needs of a fault before it reads anything on Azure. The schema (E1)
    is checked in CI; this is what the run itself relies on."""
    if not isinstance(doc, dict):
        return ["not a mapping"]
    errors = []
    if doc.get("kind") != "fault":
        errors.append("kind must be 'fault'")
    if doc.get("engine") != ENGINE:
        errors.append(f"engine {doc.get('engine')!r}: Gothmog runs {ENGINE} only")
    if not doc.get("engine_ref"):
        errors.append("engine_ref (the Chaos Studio experiment) is required")
    if not isinstance(doc.get("destructive"), bool):
        errors.append("destructive must be declared, true or false")
    if not (doc.get("targets") or {}).get("names"):
        errors.append("targets.names: a fault declares its targets")
    return errors + declared_errors((doc.get("steady_state") or {}).get("probes"))


def find_fault(name_or_path: str) -> Path:
    path = Path(name_or_path)
    if path.exists():
        return path
    candidate = EXPERIMENTS_DIR / f"{name_or_path}.yaml"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"no fault {name_or_path!r} (a path, or a name in {EXPERIMENTS_DIR.name}/)")


def declared_targets(directory: Path = EXPERIMENTS_DIR) -> dict[str, list[str]]:
    """Each fault's VMs, as its experiment declares them (``targets.names``) — read from the
    files, without Orodruin nor Azure: what Dagorlad judges ``no_engine`` by (DG-b). The run
    still reads the experiment itself and refuses a mismatch (``_gate``)."""
    out: dict[str, list[str]] = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or doc.get("kind") != "fault":
            continue
        names = (doc.get("targets") or {}).get("names")
        if isinstance(names, list):
            out[str(doc.get("id") or path.stem)] = [str(n) for n in names]
    return out


def load_fault(name_or_path: str) -> dict:
    doc = yaml.safe_load(find_fault(name_or_path).read_text(encoding="utf-8"))
    errors = fault_errors(doc)
    if errors:
        raise ValueError("; ".join(errors))
    return doc


def _abrupt(experiment: dict) -> bool:
    for step in (experiment.get("properties") or {}).get("steps") or []:
        for branch in step.get("branches") or []:
            for action in branch.get("actions") or []:
                for p in action.get("parameters") or []:
                    if p.get("key") == "abruptShutdown" and str(p.get("value")).lower() == "true":
                        return True
    return False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Engine:
    def __init__(self, *, bench_factory=None, runs_dir: str | Path = "runs",
                 sleep=time.sleep, now=_utcnow, poll_s: float = POLL_S,
                 abort_margin_s: float = ABORT_MARGIN_S,
                 restore_timeout_s: float = RESTORE_TIMEOUT_S):
        self._bench_factory = bench_factory or (lambda session: ChaosStudio(session))
        self.runs_dir = Path(runs_dir)
        self._sleep, self._now = sleep, now
        self.poll_s = poll_s
        self.abort_margin_s = abort_margin_s
        self.restore_timeout_s = restore_timeout_s
        self._without: dict = {}   # what a run --without-glorfindel adds to its report (V1)
        self._request = ""         # the Dagorlad request a run is a wire of (DG-b)

    # ── 1–3: everything before the fault, nothing written ─────────────────────────────

    def _gate(self, fault: dict, run_id: str, bench, verdict) -> tuple[dict, str | None]:
        """Targets and steady state. Returns what was read, and the refusal if any."""
        seen: dict = {"targets": [], "experiment": {}, "before": {}}
        name = fault["engine_ref"]
        try:
            experiment = bench.experiment(name)
        except Exception as e:
            return seen, f"experiment {name} unreadable: {e}"
        try:
            vms = experiment_targets(experiment)
            duration = fault_duration_s(experiment)
        except ValueError as e:
            return seen, f"experiment {name}: {e}"
        seen["experiment"] = {"name": name, "duration_s": duration}

        declared = {n.lower() for n in fault["targets"]["names"]}
        actual = {vm.rsplit("/", 1)[-1].lower() for vm in vms}
        if actual != declared:
            return seen, f"the experiment acts on {sorted(actual)}, the fault declares {sorted(declared)}"
        if _abrupt(experiment) and fault["destructive"] is False:
            return seen, "the experiment shuts down abruptly; the fault declares itself non-destructive"
        max_run_s = verdict.cap.get("max_run_s", 0)
        if duration + self.abort_margin_s > max_run_s:
            return seen, f"the fault lasts {duration:.0f}s (+{self.abort_margin_s:.0f}s margin), the cap {max_run_s}s"

        scope = Scope(sandbox=os.environ.get(BENCH_ENV, DEFAULT_BENCH),
                      subscription_id=bench.subscription_id)
        for vm in vms:
            try:
                guard = check_target(vm, bench.resource_group_tags(rg_from_id(vm)),
                                     bench.vm(vm).get("tags") or {}, kind="fault",
                                     destructive=fault["destructive"], scope=scope)
            except Exception as e:
                return seen, f"{vm.rsplit('/', 1)[-1]}: enrollment unreadable: {e}"
            if not guard.allowed:
                return seen, f"{vm.rsplit('/', 1)[-1]}: {guard.reason}"
        seen["targets"] = vms

        probes = fault["steady_state"]["probes"]
        before = {vm: evaluate(probes, vm, bench, now=self._now()) for vm in vms}
        seen["before"] = {vm.rsplit("/", 1)[-1]: [vars(r) for r in rs] for vm, rs in before.items()}
        for vm, rs in before.items():
            for r in rs:
                mark = "[green]✓[/green]" if r.ok else "[red]✗[/red]"
                console.print(f"  {mark} {vm.rsplit('/', 1)[-1]} {r.name}: {r.observed} (expect {r.expect})")
        before_ok = all(holds(rs) for rs in before.values())
        if not before_ok:
            return seen, "steady state not verified before the fault — nothing injected"
        return seen, None

    @staticmethod
    def _no_watch(run_id: str, without_glorfindel: bool) -> RunOutcome | None:
        """Step 0 (V1, #214): the refusal when no live Glorfindel watch stands behind the run,
        else None — the watch's heartbeat read, nothing else on the cloud."""
        if without_glorfindel:
            console.print(f"[yellow]{watch_gate.FLAG}: a development run — Glorfindel's "
                          f"reaction to the fault is not measured, by choice.[/yellow]")
            return None
        no_watch = watch_gate.refusal()
        if not no_watch:
            return None
        console.print(f"[red]Refused — no live Glorfindel watch:[/red] {no_watch}")
        return RunOutcome(run_id, "REFUSED", error=f"glorfindel: {no_watch}")

    def preflight(self, name_or_path: str, *, without_glorfindel: bool = False) -> RunOutcome:
        """Steps 0–3 from where the run would start, writing nothing (no session)."""
        fault = load_fault(name_or_path)
        run_id = "preflight-" + self._now().strftime("%Y%m%dT%H%M%SZ")
        refused = self._no_watch(run_id, without_glorfindel)
        if refused:
            return refused
        verdict, session = arm(run_id, "gothmog")
        if session is None:
            console.print(f"[red]Orodruin passive — nothing read:[/red] {verdict.reasons()}")
            return RunOutcome(run_id, "PASSIVE", error=verdict.reasons())
        seen, refusal = self._gate(fault, run_id, self._bench_factory(None), verdict)
        if refusal:
            console.print(f"[red]Refused:[/red] {refusal}")
            return RunOutcome(run_id, "REFUSED", error=refusal, report=seen)
        console.print("[green]Preflight: the fault could run — nothing was written.[/green]")
        return RunOutcome(run_id, "OK", report=seen)

    # ── The run ───────────────────────────────────────────────────────────────────────

    def run(self, name_or_path: str, *, skip_confirm: bool = False,
            without_glorfindel: bool = False, request: str = "", target: str = "") -> RunOutcome:
        """``request`` and ``target``: a wire of a Dagorlad request (DG-b) — the target must be
        one the fault declares, the request's id goes to the window, the journal and the report."""
        fault = load_fault(name_or_path)
        start = self._now()
        run_id = "gothmog-" + start.strftime("%Y%m%dT%H%M%SZ")
        self._request = request
        if target and target.rstrip("/").rsplit("/", 1)[-1].lower() not in {
                n.lower() for n in fault["targets"]["names"]}:
            why = (f"no_engine: {fault.get('id')} aims at {', '.join(fault['targets']['names'])}, "
                   f"not {target.rstrip('/').rsplit('/', 1)[-1]}")
            console.print(f"[red]Refused:[/red] {why}")
            return RunOutcome(run_id, "REFUSED", error=why)
        console.rule(f"[bold red]Gothmog — {fault['name']}[/bold red]")
        console.print(f"  Engine  : {fault['engine']} / {fault['engine_ref']}")
        console.print(f"  Targets : {', '.join(fault['targets']['names'])}\n")
        # 0. A live Glorfindel watch, before anything reaches the cloud (V1).
        refused = self._no_watch(run_id, without_glorfindel)
        if refused:
            return refused
        self._without = watch_gate.without_metrics(without_glorfindel)
        if not skip_confirm and not Confirm.ask("[yellow]Run this fault?[/yellow]"):
            console.print("Aborted.")
            return RunOutcome(run_id, "REFUSED", error="not confirmed")

        # 1. The contract before the target is even read.
        verdict, session = arm(run_id, "gothmog", request=request)
        if session is None:
            console.print(f"[red]Orodruin passive — nothing touched:[/red] {verdict.reasons()}")
            return RunOutcome(run_id, "PASSIVE", error=verdict.reasons())
        if without_glorfindel:  # SEC5 (N-04): in Orodruin's journal too
            session.declare("without_glorfindel", watch_gate.NOT_MEASURED)
        if session.max_injections < MIN_CALLS:
            reason = f"cap of {session.max_injections} calls: a run needs {MIN_CALLS} to cancel and revert"
            console.print(f"[red]Refused:[/red] {reason}")
            return RunOutcome(run_id, "REFUSED", error=reason)
        bench = self._bench_factory(session)

        # 2–3. Targets, then the steady state.
        seen, refusal = self._gate(fault, run_id, bench, verdict)
        if refusal:
            console.print(f"[red]Refused:[/red] {refusal}")
            return self._record(fault, run_id, "REFUSED", {"refusal": refusal, **seen},
                                {"targets": "PASS" if seen["targets"] else "FAIL",
                                 "steady_state_before": "FAIL" if seen["targets"] else "—"},
                                error=refusal)

        # 4–6, inside an exercise window: what Glorfindel sees on the target meanwhile is
        # labelled ``exercise`` (eregion_core/exercise.py), on the hosted watch too.
        vms = seen["targets"]
        open_window(run_id, injector="gothmog", kind="fault",
                    experiment=f"{fault.get('id') or fault['name']} {fault['name']}", targets=vms,
                    request=request)
        try:
            return self._inject(fault, run_id, bench, vms, seen, verdict, start)
        finally:
            close_window(run_id)
            carry_run(run_id, self.runs_dir)  # its report, to H0 with its window (#193)

    def _inject(self, fault, run_id, bench, vms, seen, verdict, run_start) -> RunOutcome:
        name = fault["engine_ref"]
        probes = fault["steady_state"]["probes"]
        duration = seen["experiment"]["duration_s"]
        emitter = SignalEmitter(run_id, fault.get("id") or fault["name"], vms, self.runs_dir)
        checks = {"targets": "PASS", "steady_state_before": "PASS"}

        # 4. Inject — the watch read again first (SEC5, N-03): the targets and the steady
        # state took minutes; a watch gone since stops the fault before it starts.
        if not self._without:
            lost = watch_gate.refusal()
            if lost:
                console.print(f"[red]Stopped — the Glorfindel watch is gone:[/red] {lost}")
                checks["fault_started"] = "FAIL (no live Glorfindel watch)"
                return self._record(fault, run_id, "REFUSED", seen, checks,
                                    error=f"glorfindel: lost before the fault — {lost}")
        t0 = self._now()
        try:
            bench.start(name)
        except Exception as e:  # refused (cap, rights) or failed: nothing was injected
            console.print(f"[red]Start failed:[/red] {e}")
            checks["fault_started"] = f"FAIL ({e})"
            return self._record(fault, run_id, "FAIL", seen, checks, error=f"start: {e}")
        emitter.emit("fault_started", raw_signal={
            "fault_time": t0.isoformat(), "experiment": name, "duration_s": duration})
        console.print(f"[cyan]->[/cyan] fault_started — {name}, {duration:.0f}s")

        # 5. During: follow the execution, see the fault, cancel past the deadline.
        deadline = min(t0 + timedelta(seconds=duration + self.abort_margin_s),
                       run_start + timedelta(seconds=verdict.cap["max_run_s"]))
        execution, status, seen_down, aborted, cancelled_at = None, "", None, None, None
        try:
            while True:
                try:
                    execution = latest_execution(bench.executions(name), t0) or execution
                    status = ((execution or {}).get("properties") or {}).get("status") or ""
                    for vm in vms:
                        if seen_down is None and power_state(bench.vm(vm)) in DOWN:
                            seen_down = self._now()
                            console.print(f"  [dim]{vm.rsplit('/', 1)[-1]} down — the fault is effective[/dim]")
                except Exception as e:  # a read that fails is retried; the deadline still holds
                    console.print(f"  [yellow]read failed during the fault: {e}[/yellow]")
                if is_terminal(status):
                    break
                now = self._now()
                if cancelled_at is None and now >= deadline:
                    aborted = "past its duration and margin, or the run's cap"
                    console.print(f"[yellow]Cancelling the experiment — {aborted}[/yellow]")
                    bench.cancel(name)
                    cancelled_at = now
                elif cancelled_at is not None and now >= cancelled_at + timedelta(seconds=self.abort_margin_s):
                    break  # the cancel never finished: stop following, verify the return
                self._sleep(self.poll_s)
        except KeyboardInterrupt:
            self._cancel_quietly(bench, name, status)
            raise
        except Exception as e:  # a cancel refused (cap, rights): still verify the return
            aborted = f"error: {e}"
            console.print(f"[red]{aborted}[/red]")

        fault_end = _parse(((execution or {}).get("properties") or {}).get("stoppedAt")) or self._now()
        emitter.emit("fault_ended", raw_signal={"status": status, "aborted": aborted,
                                                "seen_down_at": seen_down.isoformat() if seen_down else None})
        checks["fault_effective"] = "PASS" if seen_down else "FAIL"
        checks["execution"] = "PASS" if status.lower() in SUCCESS and not aborted else f"FAIL ({status or 'unknown'})"

        # 6. After: the probes again, later than the fault's end; the declared revert if not.
        after, restored_at = self._await_steady(probes, vms, bench, since=fault_end)
        fallback = False
        if restored_at is None and any(r.get("action") == "start_vm" for r in fault.get("revert") or []):
            for vm in vms:
                try:
                    if power_state(bench.vm(vm)) != "PowerState/running":
                        bench.start_vm(vm)
                        fallback = True
                except Exception as e:
                    console.print(f"[red]revert failed on {vm.rsplit('/', 1)[-1]}: {e}[/red]")
            after, restored_at = self._await_steady(probes, vms, bench, since=fault_end)
        revert_verified = all(holds(rs) for rs in after.values())
        checks["revert_verified"] = "PASS" if revert_verified else "FAIL"
        emitter.emit("steady_state_restored" if revert_verified else "revert_failed",
                     raw_signal={"fallback_used": fallback})

        result = "PASS" if all(v == "PASS" for v in checks.values()) else "FAIL"
        metrics = {
            **seen, "execution_id": (execution or {}).get("name"), "execution_status": status,
            "fault_start": t0.isoformat(), "fault_end": fault_end.isoformat(),
            "seen_down_at": seen_down.isoformat() if seen_down else None, "aborted": aborted,
            "fallback_used": fallback,
            "time_to_restore_s": (restored_at - fault_end).total_seconds() if restored_at else None,
            "after": {vm.rsplit("/", 1)[-1]: [vars(r) for r in rs] for vm, rs in after.items()},
        }
        return self._record(fault, run_id, result, metrics, checks)

    def _await_steady(self, probes, vms, bench, *, since):
        """The probes until they all hold, within the restore timeout."""
        deadline = self._now() + timedelta(seconds=self.restore_timeout_s)
        while True:
            now = self._now()
            results = {vm: evaluate(probes, vm, bench, since=since, now=now) for vm in vms}
            if all(holds(rs) for rs in results.values()):
                return results, now
            if now >= deadline:
                return results, None
            self._sleep(self.poll_s)

    @staticmethod
    def _cancel_quietly(bench, name: str, status: str) -> None:
        if is_terminal(status):
            return
        try:
            bench.cancel(name)
            console.print("[yellow]Interrupted — experiment cancelled.[/yellow]")
        except Exception as e:
            console.print(f"[red]Interrupted — cancel failed ({e}): cancel it by hand.[/red]")

    def _record(self, fault, run_id, result, metrics, checks, error=None) -> RunOutcome:
        report = RunReport(scenario=fault["name"], run_id=run_id, mitre="", result=result,
                           metrics={**run_report.identity("fault", "gothmog", fault.get("id"),  # C1
                                                          request=self._request),
                                    "fault": fault.get("id"),
                                    **self._without, **metrics},
                           thresholds={}, checks=checks)
        path = report.save(self.runs_dir)
        report.render()
        console.print(f"\n[dim]Report saved: {path}[/dim]")
        return RunOutcome(run_id, result, error=error, report=asdict(report))
