from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from rich.console import Console
from rich.prompt import Confirm

from annatar.runner.detection import detection_latency
from annatar.runner.parser import ScenarioParser
from annatar.runner.report import RUNS_DIR, RunReport
from eregion_core.inscription import check_target
from annatar.signals.emitter import SignalEmitter
from eregion_core import run_report, watch_channel, watch_gate
from eregion_core.exercise import close_window, open_window
from eregion_core.exercise_channel import carry_run
from eregion_core.orodruin import arm

console = Console()

# SEC5 (N-04): what Orodruin's journal says of a run --without-glorfindel, and its refusal in
# production.
WITHOUT_GLORFINDEL = "without_glorfindel"
NO_WITHOUT_IN_PRODUCTION = f"{watch_gate.FLAG} never runs in zone production"


def scenario_destructive(scenario) -> tuple[bool, str]:
    """Does this scenario destroy or alter data — and, if it lies about it, why it is refused.

    The catalog decides (SEC5, V-19): the technique's entry, and its pinned source for an
    atomic (annatar/campaign/catalog.py ``catalog_destructive``). Unknown is destructive. The
    scenario's own ``destructive`` field may only make it stricter: a scenario that calls
    itself non-destructive for a technique the catalog says is destructive — or does not
    vouch for — is refused (``(True, why)``). Returns ``(destructive, "")`` otherwise.
    """
    from annatar.campaign.catalog import catalog_destructive, probes_of

    scripts = [a.get("script") for a in [*(getattr(scenario, "setup", None) or []),
                                          *(getattr(scenario, "steps", None) or [])]
               if isinstance(a, dict) and a.get("script")]
    said = catalog_destructive(scenario.mitre, engine=getattr(scenario, "engine", "") or "",
                               engine_ref=getattr(scenario, "engine_ref", "") or "",
                               engine_args=getattr(scenario, "engine_args", None) or None,
                               revert=(getattr(scenario, "raw", None) or {}).get("revert"),
                               probes=probes_of((getattr(scenario, "raw", None) or {})
                                                 .get("steady_state")),
                               scripts=scripts)
    own = scenario.raw.get("destructive")
    destructive = said is not False or own is True
    if own is False and destructive:
        what = ("says it is destructive" if said else
                "does not vouch for this source (unknown is destructive)")
        return True, (f"the scenario says destructive: false, the catalog {what} for "
                      f"{scenario.mitre} — the catalog decides")
    return destructive, ""


@dataclass
class RunOutcome:
    """Result of a single scenario run — consumed by the campaign runner.

    ``detection`` is the honest blind measure: "detected" (Glorfindel caught it),
    "missed" (active watch, no detection in window → detection_missed emitted), or
    "unknown" (detection was not measured: the watch stopped during the run, or could not
    vouch for it, or the run went --without-glorfindel — its report then says so).
    ``detection_latency_s`` is set only when detected: seconds from the attack
    (``attack_time``) to the detection Glorfindel recorded (annatar/runner/detection.py).
    """

    run_id: str
    detection: str = "unknown"
    detection_latency_s: float | None = None
    error: str | None = None
    # SEC5 (V-18): the run was refused before anything touched its target (the watch, the
    # contract, the target's inscription or zone, the scenario, the cap, the preflight). A
    # campaign then resets nothing on that target — the run never acted there.
    refused: bool = False


class Engine:
    def __init__(self, dry_run: bool = False, skip_preflight: bool = False,
                 publish_report: bool = False, without_glorfindel: bool = False,
                 request: str = "", typed_name: str = ""):
        self.dry_run = dry_run
        # DG-b: a wire of a Dagorlad request — its id goes to the window, the journal and the
        # report; a destructive technique then runs only on the target whose name was typed.
        self.request = request
        self.typed_name = typed_name
        self.skip_preflight = skip_preflight
        # V1 (#214): a development run, without a live Glorfindel watch — its report says so
        # and its detection is not measured (eregion_core/watch_gate.py).
        self.without_glorfindel = without_glorfindel
        # `annatar run` alone (#193): the report goes to H0 with the window. A campaign
        # leaves it False — it carries its runs' reports itself, at its end (annatar/cli.py).
        self.publish_report = publish_report
        self.parser = ScenarioParser()
        self._detection_result = "unknown"
        self._detection_latency_s = None
        # SEC21 (#530): the detections of the return channel refused (unsigned, another key, copied…)
        # — each said once, in the console, Orodruin's journal and the run's report.
        self._detection_refused: list[str] = []
        self._detection_refused_total = 0
        # SEC21b (#535): the detections the watch's heartbeat covers that the run could not read back.
        self._detection_missing: list[str] = []
        self._detection_missing_total = 0
        self._session = None
        self._revert_why = ""   # VM3b: why a revert step was skipped, said in the run's report

    def run(self, scenario_path: str, skip_confirm: bool = False):
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if self.request:
            # DG-b: two wires of a request may start within a second (one refused at once): each
            # run keeps its own window and report, which link it to its wire.
            import secrets
            run_id += f"-{secrets.token_hex(2)}"
        self._detection_result = "unknown"
        self._detection_latency_s = None
        self._detection_refused = []
        self._detection_refused_total = 0
        self._detection_missing = []
        self._detection_missing_total = 0
        self._session = None

        # An invalid scenario (an unknown engine among them, review R1 point 2) is a clean
        # refusal with an outcome the campaign can read, never a raw traceback.
        try:
            scenario = self.parser.load(scenario_path)
        except ValueError as e:
            from rich.markup import escape   # what the file says (AV1): never markup nor emoji
            console.print(f"[red]Invalid scenario:[/red] {escape(str(e))}", emoji=False)
            return RunOutcome(run_id, "unknown", error=f"scenario: {e}", refused=True)

        console.rule(f"[bold cyan]Annatar — {scenario.name}[/bold cyan]")
        console.print(f"  MITRE   : {scenario.mitre}")
        if scenario.engine != "local-script":
            console.print(f"  Engine  : {scenario.engine} / {scenario.engine_ref}")
        console.print(f"  Target  : {scenario.target.get('type')} / {scenario.target.get('resource_group')}")
        console.print(f"  Dry-run : {self.dry_run}\n")

        if self.dry_run:
            self._dry_run_display(scenario)
            return

        # V1 (#214): no live Glorfindel watch, no run — decided before anything reaches the
        # cloud (the contract, the target, the window), the watch's heartbeat read alone.
        if self.without_glorfindel:
            console.print(f"[yellow]{watch_gate.FLAG}: a development run — "
                          f"{watch_gate.NOT_MEASURED}.[/yellow]")
        else:
            no_watch = watch_gate.refusal()
            if no_watch:
                console.print(f"[red]Refused — no live Glorfindel watch:[/red] {no_watch}")
                return RunOutcome(run_id, "unknown", error=f"glorfindel: {no_watch}", refused=True)

        if not skip_confirm:
            if not Confirm.ask("[yellow]Execute this scenario?[/yellow]"):
                console.print("Aborted.")
                return

        # The atomic engine's pure checks run BEFORE anything is armed or opened: a bad
        # engine_ref or a bad probe set must never arm a contract or open an exercise window
        # (review R1 point 8). The resolved test is carried into the run.
        resolved = None
        revert = []
        if scenario.engine == "atomic":
            from annatar.engines.atomic import AtomicError, resolve_ref, revert_commands

            try:
                resolved = resolve_ref(
                    scenario.engine_ref, getattr(scenario, "engine_args", None) or None
                )
                # VM3: the scenario's revert, after the atomic's cleanup — held like the rest.
                revert = revert_commands(scenario.raw.get("revert"), resolved)
            except AtomicError as e:
                console.print(f"[red]Atomic unresolved:[/red] {e}")
                return RunOutcome(run_id, "unknown", error=f"atomic: {e}", refused=True)
            probe_error = self._atomic_probe_error(scenario)
            if probe_error:
                console.print(f"[red]Refused:[/red] {probe_error}")
                return RunOutcome(run_id, "unknown", error=f"atomic: {probe_error}", refused=True)

        # The Stratus engine's pure checks run BEFORE anything is armed or opened too (R2):
        # a technique off the closed allow-list, or a binary that is not the pinned one, must
        # never arm a contract or open an exercise window. The verified technique is carried in.
        stratus_resolved = None
        if scenario.engine == "stratus":
            from annatar.engines.stratus import StratusError
            from annatar.engines.stratus import resolve as stratus_resolve
            from annatar.executors.stratus_host import staged_layout

            try:
                stratus_resolved = stratus_resolve(
                    scenario.engine_ref, binary_path=staged_layout().binary
                )
            except StratusError as e:
                console.print(f"[red]Stratus unresolved:[/red] {e}")
                return RunOutcome(run_id, "unknown", error=f"stratus: {e}", refused=True)

        # Orodruin (eregion_core/orodruin.py): the contract before the target is even read.
        # Passive → the run touches nothing and says why.
        verdict, session = arm(run_id, "annatar", request=self.request)
        if session is None:
            console.print(f"[red]Orodruin passive — nothing touched:[/red] {verdict.reasons()}")
            return RunOutcome(run_id, "unknown", error=f"passive: {verdict.reasons()}", refused=True)
        self._session = session   # SEC21: a detection refused is written in its journal
        if self.without_glorfindel:
            # SEC5 (N-04): in Orodruin's journal too, not only in the run's report.
            session.declare(WITHOUT_GLORFINDEL, watch_gate.NOT_MEASURED)

        # The cap is a pure check too — comparing what this run needs to what the contract
        # still allows (max_injections minus the calls already journaled). It runs right
        # after the contract holds and before the exercise window opens.
        if scenario.engine == "atomic":
            probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
            # VM3: one call per revert step; VM3b: one more, the probe it waits on.
            needed = self._atomic_calls_needed(len(probes)) + 2 * len(revert)
            available = session.max_injections - session.calls
            if available < needed:
                reason = (
                    f"cap of {session.max_injections} calls ({session.calls} used): this "
                    f"atomic needs {needed} (command, cleanup, its revert steps and the probe "
                    "each waits on, and the steady-state probes before, right after the "
                    "command, and after cleanup)"
                )
                console.print(f"[red]Refused:[/red] {reason}")
                return RunOutcome(run_id, "unknown", error=f"cap: {reason}", refused=True)

        # Stratus (R2) attacks the Azure control plane, not a VM: it runs its own cycle from
        # the armed contract, with its own control-plane guard and window — never the VM
        # executor, the VM preflight or the VM target guard below.
        if scenario.engine == "stratus":
            from annatar.engines.stratus import PHASES

            available = session.max_injections - session.calls
            needed = len(PHASES)   # the four phases are four injector calls; the Graph probes
            if available < needed:  # are read-only (declared), never counted against the cap
                reason = (f"cap of {session.max_injections} calls ({session.calls} used): this "
                          "stratus technique needs 4 (warmup, detonate, revert, cleanup)")
                console.print(f"[red]Refused:[/red] {reason}")
                return RunOutcome(run_id, "unknown", error=f"cap: {reason}", refused=True)
            return self._run_stratus(scenario, run_id, session, stratus_resolved)

        executor, collector = self._get_executor_collector(scenario, session)

        # Inscription (eregion_core/inscription.py): the target inside the bench, it AND
        # its resource group enrolled, its zone allowing this technique — destructive as the
        # catalog says, never as the scenario says (SEC5, V-19).
        destructive, lie = scenario_destructive(scenario)
        if lie:
            console.print(f"[red]Safety check failed:[/red] {lie}")
            return RunOutcome(run_id, "unknown", error=f"safety: {lie}", refused=True)
        rg_tags = executor.get_resource_group_tags(scenario.target["resource_group"])
        guard = check_target(
            executor.resource_id, rg_tags, executor.get_vm_tags(),
            kind="technique", destructive=destructive,
        )
        if not guard.allowed:
            console.print(f"[red]Safety check failed:[/red] {guard.reason}")
            return RunOutcome(run_id, "unknown", error=f"safety: {guard.reason}", refused=True)
        if self.without_glorfindel and guard.zone == "production":
            # SEC5 (N-04): a development run has no business in production.
            console.print(f"[red]Safety check failed:[/red] {NO_WITHOUT_IN_PRODUCTION}")
            return RunOutcome(run_id, "unknown", error=f"safety: {NO_WITHOUT_IN_PRODUCTION}",
                              refused=True)
        if self.request and destructive:
            # DG-b: the operator typed the target's name on their machine; compared here to the
            # name Azure gives the VM — a request forged on H0 never runs a destructive technique.
            name = executor.get_vm_name()
            if self.typed_name != name:
                why = (f"the name typed ({self.typed_name or 'none'}) is not the target's "
                       f"({name}): a destructive wire runs only on the VM typed")
                console.print(f"[red]Safety check failed:[/red] {why}")
                return RunOutcome(run_id, "unknown", error=f"safety: {why}", refused=True)
        if guard.legacy:
            console.print(
                "[yellow]Target enrolled by the old 'annatar-test' tag (migration) — "
                "Celebrimbor now tags 'eregion-target' and 'eregion-zone'.[/yellow]"
            )

        # Preflight check — VM running + not isolated
        if not self.skip_preflight:
            console.print("[cyan]->[/cyan] Pre-flight check...")
            issues = executor.check_preflight()
            if issues:
                for issue in issues:
                    console.print(f"[red]✗[/red] {issue}")
                console.print(
                    "\n[red]Pre-flight check failed — fix the above before running.[/red]\n"
                    "[dim]Use --skip-preflight to bypass.[/dim]"
                )
                return RunOutcome(run_id, "unknown", error="preflight failed", refused=True)

        # B2: an exercise window before the first touch of the target (setup included),
        # closed whatever happens — what Glorfindel sees on this VM meanwhile is labelled
        # `exercise` (eregion_core/exercise.py).
        open_window(run_id, injector="annatar", kind="technique",
                    experiment=f"{scenario.mitre} {scenario.name}",
                    targets=[executor.resource_id], destructive=destructive,
                    request=self.request)
        try:
            if scenario.engine == "atomic":
                return self._run_atomic_enrolled(scenario, executor, run_id, session, resolved)
            if scenario.engine == "local-script":
                return self._run_enrolled(scenario, executor, run_id)
            # Unreachable once validate did its job — the explicit table refuses the rest.
            console.print(f"[red]Engine not runnable:[/red] {scenario.engine!r}")
            return RunOutcome(run_id, "unknown", error=f"engine: {scenario.engine!r} not runnable")
        finally:
            close_window(run_id, injector="annatar")
            if self.publish_report:  # its last save is done, the atomic's that raised too
                carry_run(run_id, RUNS_DIR)

    def _watch_lost(self) -> str:
        """Why the watch no longer stands behind this run — "" when it does, or when the run
        goes without it. Read before each action, not only at the start (SEC5, N-03)."""
        return "" if self.without_glorfindel else watch_gate.refusal()

    @staticmethod
    def _lost(run_id: str, why: str) -> RunOutcome:
        console.print(f"[red]Stopped — the Glorfindel watch is gone:[/red] {why}")
        return RunOutcome(run_id, "unknown", error=f"glorfindel: lost during the run — {why}")

    @staticmethod
    def _atomic_calls_needed(n_probes: int) -> int:
        """Run Command calls an atomic run needs: the command, its cleanup, and each
        steady-state probe three times (before, right after the command as the effect
        proof, and after cleanup). The scenario's revert steps (VM3) add two each: the probe
        the step waits on (VM3b), then the step."""
        return 2 + 3 * n_probes

    @staticmethod
    def _atomic_probe_error(scenario) -> str | None:
        """An atomic engine must verify the initial state before and after: at least one
        steady-state probe, each with a non-empty ``verify`` and ``expect``; and each revert
        step waits on one of them (``requires_probe``, VM3b). The check is the runner's (the
        schema only runs in CI); ``None`` when it holds."""
        probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
        if not probes:
            return ("engine 'atomic' requires at least one steady_state probe "
                    "(verify + expect) — the initial state is verified before and after")
        for probe in probes:
            if not str(probe.get("verify") or "").strip() or not str(probe.get("expect") or "").strip():
                return (f"steady_state probe {probe.get('name', '?')!r} needs a non-empty "
                        "verify and expect")
        names = {probe.get("name") for probe in probes}
        revert = scenario.raw.get("revert")
        for step in revert if isinstance(revert, list) else []:
            gate = step.get("requires_probe") if isinstance(step, dict) else None
            if not isinstance(gate, str) or gate not in names:
                return (f"revert {(step.get('name') if isinstance(step, dict) else step)!r}: "
                        f"requires_probe {gate!r} is not one of the steady_state probes — a "
                        "revert runs only once a probe says the cleanup held")
        return None

    def _revert_gate(self, executor, probe: dict, resolved) -> bool:
        """VM3b: the probe a revert step waits on, run after the cleanup — True only when it
        holds again (the cleanup did what the files were kept for). A probe that raises is no
        proof: False."""
        try:
            [(_, ok, _)] = self._check_probes(executor, [probe], resolved, "before revert")
        except Exception as e:
            console.print(f"[red]Probe {probe.get('name')} failed:[/red] {e}")
            return False
        return ok

    def _run_enrolled(self, scenario, executor, run_id: str) -> RunOutcome:
        """The run once its target is enrolled and ready: setup, integrity check, steps,
        attack_started, then the wait for Glorfindel's result."""
        emitter = SignalEmitter(
            run_id=run_id,
            scenario_name=scenario.name,
            scenario_mitre=scenario.mitre,
            target=scenario.target,
            resource_id=executor.resource_id,
        )

        metrics = watch_gate.without_metrics(self.without_glorfindel)
        # C1: the run format shared with Gothmog — an attack, by Annatar, of this technique.
        metrics.update(run_report.identity("technique", "annatar", scenario.mitre, emitter.resource_id))
        if self.request:   # DG-b: the wire's request, in the unified run
            metrics["request"] = self.request
        checks = {}

        # Setup runs first — cleans residuals from previous attack before we check state. The
        # watch is read again before each action (SEC5, N-03): one that died stops the run.
        for action in scenario.setup:
            lost = self._watch_lost()
            if lost:
                return self._lost(run_id, lost)
            self._execute_action(executor, action)

        # Integrity check — only for scenarios with setup (e.g. T1486 ransomware testdata disk)
        if scenario.setup:
            console.print("[cyan]->[/cyan] Pre-run integrity check...")
            if not executor.verify_restore_integrity():
                console.print(
                    "[red]Pre-run integrity check FAILED — VM is not in a clean state.[/red]\n"
                    "  Setup ran but disk still has artifacts. Check the data disk manually.\n"
                    "  [bold]az vm run-command invoke -g annatar -n vm-annatar-victim "
                    "--command-id RunShellScript --scripts 'lsblk && ls /mnt/testdata'[/bold]"
                )
                return RunOutcome(run_id, "unknown", error="integrity check failed")

        # SEC3 (#274): no more watcher of Glorfindel's blocks (attack_adapted). It read the
        # defender's state — the red team's measure is blind to the blue's — under a file name
        # Glorfindel no longer writes, and the injectors no longer mount that state.
        stop_event = threading.Event()

        # Steps
        T0 = time.time()
        for step in scenario.steps:
            console.print(f"[cyan]->[/cyan] {step.get('name', step.get('action'))}")
            if step.get("record") == "T0":
                T0 = time.time()
            lost = self._watch_lost()
            if lost:
                return self._lost(run_id, lost)
            self._execute_action(executor, step)

        checks["attack"] = "PASS"
        # T0 in the run's report: the campaign report on H0 bounds the run's decision with
        # it, the debug file of the run being on another host (#167).
        metrics["attack_time"] = T0

        # Emit attack_started — Glorfindel looks up its own detection rule by TTP
        # and owns the full detection + response cycle.
        detection_timeout_s = 0.0
        if scenario.detection:
            detection_timeout_s = self._parse_duration(
                scenario.detection.get("timeout", "300s")
            )
            emitter.emit(
                event="attack_started",
                raw_signal={
                    "attack_time": T0,
                    "detection_timeout_s": detection_timeout_s,
                    "detection_max_s": self._parse_duration(
                        scenario.detection.get("time_max", "9999s")
                    ),
                },
            )
            console.print(
                "[cyan]->[/cyan] Signal 'attack_started' emitted"
                " — Glorfindel will detect via detection_rules.yaml."
            )

        overall = "PASS" if all("PASS" in v for v in checks.values()) else "FAIL"
        report = RunReport(
            scenario=scenario.name,
            run_id=run_id,
            mitre=scenario.mitre,
            result=overall,
            metrics=metrics,
            thresholds={},
            checks=checks,
        )
        path = report.save()
        report.render()
        console.print(f"\n[dim]Report saved: {path}[/dim]")

        # Purple-team feedback: monitor Glorfindel's detection result in
        # Wait for Glorfindel's detection result and emit feedback if needed.
        # Non-daemon so the process stays alive until the result is known.
        # Short-circuits immediately if no glorfindel watch appears to be running.
        if scenario.detection and detection_timeout_s > 0 and not self.dry_run \
                and not self.without_glorfindel:  # not measured, by choice: no wait
            t = threading.Thread(
                target=self._wait_and_emit_feedback,
                args=(run_id, emitter, scenario, detection_timeout_s, T0, stop_event),
                daemon=False,
                name=f"annatar-feedback-{run_id}",
            )
            t.start()
            t.join()
        else:
            stop_event.set()

        # The detection result and its latency (from T0, #157) are recorded in the run
        # itself, after the wait.
        metrics["detection"] = self._detection_result
        metrics["detection_latency_s"] = self._detection_latency_s
        if self._detection_refused:   # SEC21: never counted, said in the report
            metrics["detection_refused"] = list(self._detection_refused)
            metrics["detection_refused_total"] = self._detection_refused_total
        self._missing_metrics(metrics)
        report.metrics = metrics
        report.save()
        return RunOutcome(run_id, self._detection_result, self._detection_latency_s)

    def _run_atomic_enrolled(self, scenario, executor, run_id: str, session,
                             resolved) -> RunOutcome:
        """Run an Atomic Red Team test on the enrolled target (R1).

        Verify the initial state, run the atomic's own command, confirm it broke the steady
        state (the effect proof), emit ``attack_started``, run its ``cleanup_command``, then the
        scenario's ``revert`` (VM3: what the upstream cleanup leaves, ``revert_commands`` — run
        only once the cleanup ran, which may need those files, and, VM3b, each step only once the
        probe it waits on holds again after it), then verify the initial state was restored.
        The command runs inside a ``try``; whatever it does, the ``finally`` runs the cleanup, the after-probes and writes the report (the
        atomic's command failing is ``attack: ERROR``, never a silent half-run). ``attack_started``
        is emitted only once the effect is observed — a command that raised, or that did
        nothing, never makes Glorfindel propose a rule for an attack that did not happen.
        The signals and the feedback wait are otherwise unchanged from the local-script path.
        """
        from annatar.engines.atomic import revert_commands

        probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
        # Held before the contract was armed (run): pure, so the same steps here — each with
        # the probe it waits on (VM3b; _atomic_probe_error checked it is one of them).
        by_name = {p.get("name"): p for p in probes}
        revert = [(name, command, by_name[gate])
                  for name, command, gate in revert_commands(scenario.raw.get("revert"), resolved)]
        self._revert_why = ""
        emitter = SignalEmitter(
            run_id=run_id,
            scenario_name=scenario.name,
            scenario_mitre=scenario.mitre,
            target=scenario.target,
            resource_id=executor.resource_id,
        )
        checks = {}
        metrics = {
            "engine": "atomic",
            "engine_ref": scenario.engine_ref,
            "atomic_guid": resolved.guid,
            **run_report.identity("technique", "annatar", scenario.mitre, emitter.resource_id),   # C1
            **({"request": self.request} if self.request else {}),   # DG-b
            **watch_gate.without_metrics(self.without_glorfindel),
        }

        # Initial state before the attack — a dirty start is refused (never attack over residue).
        console.print("[cyan]->[/cyan] Initial-state check (before)...")
        before = self._check_probes(executor, probes, resolved, "before")
        if not all(ok for _, ok, _ in before):
            console.print(
                "[red]Initial state not clean before the atomic — nothing run.[/red]"
            )
            return RunOutcome(
                run_id, "unknown", error="initial state not clean before the atomic"
            )
        checks["initial_state_before"] = "PASS"

        # The watch read again before the atomic's command (SEC5, N-03): nothing run yet, so
        # nothing to clean up.
        lost = self._watch_lost()
        if lost:
            return self._lost(run_id, lost)

        T0 = time.time()
        detection_timeout_s = 0.0
        attack_started = False
        attack_error = None
        restored = None
        console.print(f"[cyan]->[/cyan] {resolved.name} ({resolved.guid})")
        try:
            executor.run_command(resolved.command, label=f"atomic {resolved.guid}")
            checks["attack"] = "PASS"

            # Effect proof — the steady state must be broken right after the command, or the
            # atomic did nothing (missing binary, silent error, exit != 0 — Run Command does
            # not raise on that). No effect → no attack_started and no detection_missed: never
            # a rule proposed for an attack that did not happen (review R1 point 8).
            effect = self._check_probes(executor, probes, resolved, "effect")
            if not any(not ok for _, ok, _ in effect):
                checks["attack"] = "FAIL"
                attack_error = (
                    "atomic ran but left the steady state intact — no observable effect "
                    "(missing binary or a silent failure); no attack_started emitted"
                )
                console.print(f"[red]{attack_error}[/red]")
            elif scenario.detection:
                # attack_started — unchanged: Glorfindel looks its rule up by TTP and owns detection.
                detection_timeout_s = self._parse_duration(
                    scenario.detection.get("timeout", "300s")
                )
                emitter.emit(
                    event="attack_started",
                    raw_signal={
                        "attack_time": T0,
                        "detection_timeout_s": detection_timeout_s,
                        "detection_max_s": self._parse_duration(
                            scenario.detection.get("time_max", "9999s")
                        ),
                    },
                )
                attack_started = True
                metrics["attack_time"] = T0  # the campaign report on H0 reads it (#167)
                console.print(
                    "[cyan]->[/cyan] Signal 'attack_started' emitted"
                    " — Glorfindel will detect via detection_rules.yaml."
                )
        except Exception as e:  # the atomic's own command failed after all retries
            checks["attack"] = "ERROR"
            console.print(f"[red]Atomic command failed:[/red] {type(e).__name__}: {e}")
            raise  # re-raised after the finally cleans up — the campaign marks it an error
        finally:
            # Cleanup and the return check always run, whatever the command did (even when it
            # raised) — each guarded, so a cleanup or probe that raises still leaves a saved
            # report. The command's own exception, if any, is re-raised once this has run.
            try:
                console.print("[cyan]->[/cyan] Cleanup (atomic cleanup_command)...")
                executor.run_command(
                    resolved.cleanup_command, label=f"atomic {resolved.guid} cleanup"
                )
                checks["cleanup"] = "PASS"
            except Exception as e:
                checks["cleanup"] = "ERROR"
                console.print(f"[red]Cleanup failed:[/red] {e}")
            if revert:
                # VM3: the scenario's revert, after the cleanup and only once it ran — a
                # cleanup that failed may still need what the revert removes (T1053.003:
                # /tmp/notevil is root's crontab), so it stays, for the operator.
                checks["revert"] = self._run_revert(executor, revert, resolved) \
                    if checks.get("cleanup") == "PASS" else "SKIPPED"
                if checks["revert"] == "SKIPPED":   # VM3b: the run says why, and what is left
                    metrics["revert_skipped"] = self._revert_why or "the cleanup did not pass"
            try:
                console.print("[cyan]->[/cyan] Initial-state check (after cleanup)...")
                after = self._check_probes(executor, probes, resolved, "after")
                restored = all(ok for _, ok, _ in after)
                checks["initial_state_after"] = "PASS" if restored else "FAIL"
                metrics["initial_state_restored"] = restored
            except Exception as e:
                checks["initial_state_after"] = "ERROR"
                console.print(f"[red]After-probe failed:[/red] {e}")

            # The target may be dirty (cleanup failed, or the return left unverified) — show
            # the operator the resolved cleanup to run by hand.
            if checks.get("cleanup") != "PASS" or checks.get("revert", "PASS") != "PASS" \
                    or restored is not True:
                self._atomic_recovery_hint(scenario, resolved, revert)

            overall = "PASS" if checks and all("PASS" in v for v in checks.values()) else "FAIL"
            report = RunReport(
                scenario=scenario.name,
                run_id=run_id,
                mitre=scenario.mitre,
                result=overall,
                metrics=metrics,
                thresholds={},
                checks=checks,
            )
            path = report.save()
            report.render()
            console.print(f"\n[dim]Report saved: {path}[/dim]")

        # Reached only when the command did not raise. A command with no observable effect,
        # or a return not restored, reaches the caller (the campaign) as an error — never
        # marked 'executed' then chained over a dirty VM (review R1 points 4 and 8).
        if attack_error:  # the command ran but left the steady state intact
            return RunOutcome(run_id, "unknown", error=attack_error)
        # restored is True only when the after-probe ran and the steady state held again.
        # False (it did not) or None (the after-probe itself could not run) both mean the
        # return is not verified — the caller must see it, never chain over an unknown VM.
        if restored is not True:
            error = ("initial state not restored" if restored is False
                     else "initial state not verified after cleanup")
            if "revert_skipped" in metrics:   # VM3b: what the revert left, said with it
                error += f" — revert skipped: {metrics['revert_skipped']}"
            return RunOutcome(run_id, "unknown", error=error)
        if checks.get("revert", "PASS") != "PASS":   # VM3: never chained over its leftovers
            return RunOutcome(run_id, "unknown",
                              error=f"revert {checks['revert'].lower()} after the cleanup")

        # Purple-team feedback — only when the attack actually started (short-circuits with no watch).
        if attack_started and detection_timeout_s > 0 and not self.dry_run \
                and not self.without_glorfindel:  # not measured, by choice: no wait
            t = threading.Thread(
                target=self._wait_and_emit_feedback,
                args=(run_id, emitter, scenario, detection_timeout_s, T0, threading.Event()),
                daemon=False,
                name=f"annatar-feedback-{run_id}",
            )
            t.start()
            t.join()

        # The detection result (detected / missed / unknown) is recorded in the run itself,
        # after the wait — the "Fini quand" of #65 — with its latency (#157): measured from
        # T0 (the command's call) to the detection's own time, not from the start of the
        # wait (which begins only after cleanup) nor from attack_started (after the effect
        # proof, about a minute later).
        metrics["detection"] = self._detection_result
        metrics["detection_latency_s"] = self._detection_latency_s
        if self._detection_refused:   # SEC21: never counted, said in the atomic run's report too
            metrics["detection_refused"] = list(self._detection_refused)
            metrics["detection_refused_total"] = self._detection_refused_total
        self._missing_metrics(metrics)
        report.metrics = metrics
        report.save()
        return RunOutcome(run_id, self._detection_result, self._detection_latency_s)

    def _run_stratus(self, scenario, run_id: str, session, resolved, executor=None) -> RunOutcome:
        """Run a Stratus Red Team technique on the enrolled control plane (R2). The bench group
        is guarded: inside the bench, enrolled (``eregion-target``/``eregion-zone``) and in zone
        ``bench`` only — a Stratus technique can create real cloud resources, so it never runs in
        twin or production. ``executor`` is injected by the tests (a fake Stratus); otherwise a
        real one is built, and the cycle runs inside an exercise window.

        Whether Stratus provisions inside this group or creates its own (then outside the
        inscription and the exercise window) is a design question routed to R2b/ID1 (#281), not
        settled here; the real bench measurement of control-plane detection is ID1 too."""
        import os

        from annatar.executors.stratus_host import StratusExecutor

        sub = scenario.target.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
        rg = scenario.target.get("resource_group")
        if not sub or not rg:
            why = "stratus target needs a subscription_id and a resource_group (the bench group)"
            console.print(f"[red]Safety check failed:[/red] {why}")
            return RunOutcome(run_id, "unknown", error=f"safety: {why}", refused=True)
        rg_scope = f"/subscriptions/{sub}/resourceGroups/{rg}"

        destructive, lie = scenario_destructive(scenario)
        if lie:
            console.print(f"[red]Safety check failed:[/red] {lie}")
            return RunOutcome(run_id, "unknown", error=f"safety: {lie}", refused=True)

        if executor is None:
            executor = StratusExecutor(resolved, session, target=rg_scope, dry_run=self.dry_run)

        # Control-plane enrollment guard: the bench group's tags, read through ARM. The group
        # itself is the enrolled target here (there is no VM), so its tags stand for both the
        # group and the target of check_target — enrollment() requires both enrolled, and the
        # zone is the group's.
        try:
            rg_tags = executor.resource_group_tags(sub, rg)
        except Exception as e:
            why = f"the bench group's enrollment could not be read ({type(e).__name__}: {e})"
            console.print(f"[red]Control-plane safety check failed:[/red] {why}")
            return RunOutcome(run_id, "unknown", error=f"safety: {why}", refused=True)
        guard = check_target(rg_scope, rg_tags, rg_tags, kind="technique", destructive=destructive)
        if not guard.allowed:
            console.print(f"[red]Control-plane safety check failed:[/red] {guard.reason}")
            return RunOutcome(run_id, "unknown",
                              error=f"safety: {guard.reason} (control plane)", refused=True)
        if guard.zone != "bench":
            why = (f"a Stratus control-plane technique runs only in zone 'bench', not "
                   f"{guard.zone!r} — it can create real cloud resources")
            console.print(f"[red]Control-plane safety check failed:[/red] {why}")
            return RunOutcome(run_id, "unknown", error=f"safety: {why}", refused=True)
        if guard.legacy:
            # Stratus is a new engine (R2): the migration tag 'annatar-test=true' alone, from
            # before zones, never enrols a control-plane target — it must carry the explicit
            # 'eregion-target'/'eregion-zone' (unlike the VM path, which still accepts it).
            why = ("Stratus runs only on a target enrolled with 'eregion-target' and "
                   "'eregion-zone', not the legacy 'annatar-test' tag alone")
            console.print(f"[red]Control-plane safety check failed:[/red] {why}")
            return RunOutcome(run_id, "unknown", error=f"safety: {why}", refused=True)

        open_window(run_id, injector="annatar",
                    kind="technique", experiment=f"{scenario.mitre} {scenario.name}",
                    targets=[rg_scope], destructive=destructive, request=self.request)
        try:
            return self._run_stratus_cycle(scenario, executor, run_id, resolved)
        finally:
            close_window(run_id, injector="annatar")
            if self.publish_report:
                carry_run(run_id, RUNS_DIR)

    def _run_stratus_cycle(self, scenario, executor, run_id: str, resolved) -> RunOutcome:
        """The four phases of the Stratus cycle, from the armed contract: warmup (prerequisites),
        a read-only Graph probe of the initial state, detonate (then ``attack_started``), revert
        (best effort — not every technique supports it), cleanup (ALWAYS, even when detonate
        raised — warmup created the prerequisites), then a read-only Graph probe of the return.
        Every phase is journaled by the executor; the probes are declared reads, never counted.

        Control-plane detection (the Azure Activity Log, azure_activity/AL1) is measured at ID1
        (#281): ``attack_started`` is emitted here so that measurement has its T0; R2 does not
        wait on the result, so the detection stays ``unknown`` (said in the report)."""
        emitter = SignalEmitter(
            run_id=run_id, scenario_name=scenario.name, scenario_mitre=scenario.mitre,
            target=scenario.target, resource_id=executor.target,
        )
        checks: dict = {}
        metrics = {
            "engine": "stratus",
            "engine_ref": resolved.technique_id,
            "stratus_binary_sha256": resolved.binary_digest,
            **run_report.identity("technique", "annatar", scenario.mitre, executor.target),
            **({"request": self.request} if self.request else {}),
        }
        metrics.update(watch_gate.without_metrics(self.without_glorfindel))
        T0 = time.time()
        attack_error = None
        attempted = False   # warmup was journaled: cleanup must run, whatever happens next
        tried_detonate = False
        detonated = False
        restored = None
        try:
            lost = self._watch_lost()
            if lost:
                checks["detonate"] = "SKIPPED"   # the watch is gone: no detonation, never a PASS
                return self._lost(run_id, lost)
            console.print("[cyan]->[/cyan] Warmup (prerequisites)...")
            attempted = True   # before the call: a warmup that fails half-way is still cleaned
            executor.warmup()
            checks["warmup"] = "PASS"

            # Initial state before detonate — read-only Graph probe (None when none declared).
            before = executor.probe_initial_state("before")
            if before is False:
                checks["initial_state_before"] = "FAIL"
                attack_error = ("initial state not clean before detonate (the read-only Graph "
                                "probe found the technique's objects present) — not detonated")
                console.print(f"[red]{attack_error}[/red]")
            elif before is True:
                checks["initial_state_before"] = "PASS"

            if attack_error is None:
                lost = self._watch_lost()
                if lost:
                    checks["detonate"] = "SKIPPED"   # watch lost after warmup: no detonation
                    return self._lost(run_id, lost)
                console.print(f"[cyan]->[/cyan] Detonate {resolved.technique_id}...")
                tried_detonate = True
                executor.detonate()
                detonated = True
                checks["detonate"] = "PASS"
                if scenario.detection:
                    detection_timeout_s = self._parse_duration(
                        scenario.detection.get("timeout", "300s"))
                    emitter.emit(event="attack_started", raw_signal={
                        "attack_time": T0, "detection_timeout_s": detection_timeout_s,
                        "detection_max_s": self._parse_duration(
                            scenario.detection.get("time_max", "9999s"))})
                    metrics["attack_time"] = T0
                    console.print("[cyan]->[/cyan] Signal 'attack_started' emitted.")
        except Exception as e:
            # Label the phase that actually failed — never a bogus detonate=ERROR for a warmup
            # that raised, never initial_state_before=ERROR for a failure after a detonation.
            if checks.get("warmup") != "PASS":
                checks["warmup"] = "ERROR"
            elif tried_detonate and not detonated:
                checks["detonate"] = "ERROR"
            elif not tried_detonate:
                checks["initial_state_before"] = "ERROR"   # the before-probe raised
            else:
                checks["attack_started"] = "ERROR"          # failed after a successful detonation
            console.print(f"[red]Stratus phase failed:[/red] {type(e).__name__}: {e}")
            raise
        finally:
            if attempted:
                # cleanup ALWAYS destroys what warmup created (even when warmup or detonate
                # raised). revert runs ONLY after a detonation — reverting before detonating is
                # meaningless, and not every technique supports revert. Each guarded, so the
                # report is always saved.
                if detonated:
                    try:
                        console.print("[cyan]->[/cyan] Revert (detonation)...")
                        executor.revert()
                        checks["revert"] = "PASS"
                    except Exception as e:
                        checks["revert"] = "SKIPPED"
                        console.print(f"[yellow]Revert not applied:[/yellow] {e}")
                try:
                    console.print("[cyan]->[/cyan] Cleanup (prerequisites)...")
                    executor.cleanup()
                    checks["cleanup"] = "PASS"
                except Exception as e:
                    checks["cleanup"] = "ERROR"
                    console.print(f"[red]Cleanup failed:[/red] {e}")
                try:
                    after = executor.probe_initial_state("after")
                    if after is not None:
                        restored = after
                        checks["initial_state_after"] = "PASS" if after else "FAIL"
                        metrics["initial_state_restored"] = after
                except Exception as e:
                    checks["initial_state_after"] = "ERROR"
                    console.print(f"[red]After-probe failed:[/red] {e}")
            # The control plane may be dirty when cleanup ran but failed, or the return is not
            # restored (cleanup not attempted means warmup never ran — nothing to clean).
            if checks.get("cleanup") == "ERROR" or restored is False:
                self._stratus_recovery_hint(resolved)
            # Control-plane detection is ID1 (#281): not waited on here.
            metrics["detection"] = "unknown"
            metrics["detection_note"] = \
                "control-plane detection (azure_activity) measured at ID1 (#281)"
            # A report is PASS only after a real detonation: a BaseException (Ctrl-C, SystemExit)
            # during warmup or detonate is not caught by `except Exception` above and labels
            # nothing, but the cleanup and after-probe in this finally would otherwise leave an
            # all-PASS report — `detonated` keeps it FAIL.
            overall = ("PASS" if detonated and checks
                       and all("PASS" in v for v in checks.values()) else "FAIL")
            report = RunReport(scenario=scenario.name, run_id=run_id, mitre=scenario.mitre,
                               result=overall, metrics=metrics, thresholds={}, checks=checks)
            path = report.save()
            report.render()
            console.print(f"\n[dim]Report saved: {path}[/dim]")

        if attack_error:
            return RunOutcome(run_id, "unknown", error=attack_error)
        if checks.get("cleanup") != "PASS":
            return RunOutcome(run_id, "unknown",
                              error="cleanup did not pass — prerequisites may remain")
        if restored is False:
            return RunOutcome(run_id, "unknown", error="initial state not restored after cleanup")
        if checks.get("initial_state_after") == "ERROR":   # the after-probe itself could not run
            return RunOutcome(run_id, "unknown",
                              error="initial state not verified after cleanup")
        return RunOutcome(run_id, "unknown")

    @staticmethod
    def _stratus_recovery_hint(resolved) -> None:
        """The control plane may be dirty (cleanup failed, or the return left unverified) — show
        the operator Stratus's own cleanup, to run by hand from Orodruin."""
        console.print(
            "[yellow]The control plane may be dirty — run Stratus's cleanup by hand from "
            f"Orodruin:[/yellow]\n  [bold]stratus cleanup {resolved.technique_id}[/bold]"
        )

    def _run_revert(self, executor, revert, resolved) -> str:
        """Each revert step of the scenario (VM3), in order: PASS, or ERROR at the first that
        raises (the rest are not run — the after-probes say what is left). VM3b: a step runs
        only once the probe it waits on holds again after the cleanup — the cleanup's call not
        raising is no proof (Run Command does not raise on a script that failed). When it does
        not hold: SKIPPED, the step's files left in place for the operator, and why in
        ``self._revert_why``."""
        for name, command, probe in revert:
            if not self._revert_gate(executor, probe, resolved):
                left = command.splitlines()[-1].removeprefix("rm -f -- ")
                self._revert_why = (
                    f"probe {probe.get('name')!r} did not hold after the cleanup — {left} "
                    "left in place"
                )
                console.print(f"[red]Revert ({name}) skipped:[/red] {self._revert_why}")
                return "SKIPPED"
            console.print(f"[cyan]->[/cyan] Revert ({name})...")
            try:
                executor.run_command(command, label=f"atomic {resolved.guid} revert {name}")
            except Exception as e:
                console.print(f"[red]Revert failed:[/red] {e}")
                return "ERROR"
        return "PASS"

    @staticmethod
    def _atomic_recovery_hint(scenario, resolved, revert=()) -> None:
        """The target may be dirty — show the operator the atomic's own cleanup, resolved,
        to run by hand (``annatar clean`` runs T1486's disk setup, not an atomic's cleanup),
        then the scenario's revert, after it (VM3)."""
        import shlex

        rg = scenario.target.get("resource_group", "<rg>")
        vm = scenario.target.get("vm_name", "<vm>")
        console.print(
            "[yellow]The target may be dirty — run the atomic's cleanup by hand:[/yellow]\n"
            f"  [bold]az vm run-command invoke -g {rg} -n {vm} --command-id RunShellScript "
            f"--scripts {shlex.quote(resolved.cleanup_command)}[/bold]"
        )
        for name, command, *_ in revert:
            console.print(
                f"[yellow]then, once it held, the scenario's revert ({name}):[/yellow]\n"
                f"  [bold]az vm run-command invoke -g {rg} -n {vm} --command-id RunShellScript "
                f"--scripts {shlex.quote(command)}[/bold]"
            )

    def _check_probes(self, executor, probes, resolved, phase: str) -> list[tuple]:
        """Run each steady-state probe's ``verify`` on the VM; PASS if ``expect`` is in the
        output. ``#{var}`` in verify/expect is filled with the atomic's resolved arguments."""
        results = []
        for probe in probes:
            name = probe.get("name", "probe")
            verify = resolved.substitute(probe.get("verify", ""))
            expect = resolved.substitute(str(probe.get("expect", "")))
            output = executor.run_command(verify, label=f"probe {name} ({phase})")
            ok = expect in output if expect else True
            mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(f"  {mark} {name}: expect '{expect}' in output")
            results.append((name, ok, output))
        return results

    def _dry_run_display(self, scenario):
        console.print("[yellow]DRY RUN — no actions will be executed[/yellow]\n")
        if scenario.engine == "atomic":
            from annatar.engines.atomic import AtomicError, resolve_ref, revert_commands

            try:
                resolved = resolve_ref(
                    scenario.engine_ref, getattr(scenario, "engine_args", None) or None
                )
                revert = revert_commands(scenario.raw.get("revert"), resolved)
            except AtomicError as e:
                console.print(f"  [red]atomic unresolved:[/red] {e}")
                return
            console.print(f"  Atomic  : {resolved.name} ({resolved.guid})")
            console.print(f"  command : {resolved.command.strip()}")
            console.print(f"  cleanup : {resolved.cleanup_command.strip()}")
            for name, command, gate in revert:
                console.print(f"  revert  : {name} — {command.splitlines()[-1]} "
                              f"(once probe {gate} holds after the cleanup)")
            for p in (scenario.raw.get("steady_state") or {}).get("probes") or []:
                console.print(
                    f"  probe   : {p.get('name')} — "
                    f"{resolved.substitute(p.get('verify', ''))} (expect {p.get('expect')})"
                )
        elif scenario.engine == "stratus":
            from annatar.engines.stratus import StratusError, describe

            try:
                info = describe(scenario.engine_ref)
            except StratusError as e:
                console.print(f"  [red]stratus unresolved:[/red] {e}")
                return
            console.print(f"  Stratus : {info['name']} ({info['technique_id']})")
            console.print(f"  cycle   : {' -> '.join(info['phases'])} (each a journaled call)")
            if info["graph_probe"]:
                probe = info["graph_probe"]
                console.print(f"  probe   : {probe.name} — GET {probe.read} "
                              f"(read-only, expect_absent={probe.expect_absent})")
        else:
            for i, step in enumerate(scenario.steps, 1):
                console.print(f"  {i}. [{step.get('action')}] {step.get('name', '')}")
        if scenario.detection:
            timeout = scenario.detection.get("timeout", "?")
            console.print(f"  -> Detection timeout: {timeout} — Glorfindel uses detection_rules.yaml")

    def _get_executor_collector(self, scenario, session=None):
        target_type = scenario.target.get("type")
        if target_type == "azure_vm":
            from annatar.executors.azure_vm import AzureVMExecutor
            from annatar.collectors.azure_monitor import AzureMonitorCollector
            executor = AzureVMExecutor(scenario.target, session)
            collector = AzureMonitorCollector(scenario.target)
            return executor, collector
        raise ValueError(f"Unsupported target type: {target_type}")

    def _execute_action(self, executor, action: dict):
        action_type = action.get("action")
        if action_type == "run_script_on_vm":
            executor.run_script(action["script"])
        # More action types added as scenarios are built

    @staticmethod
    def _parse_duration(value: str) -> float:
        """Parse '300s', '10m' etc. to seconds."""
        value = str(value).strip()
        if value.endswith("s"):
            return float(value[:-1])
        if value.endswith("m"):
            return float(value[:-1]) * 60
        if value.endswith("h"):
            return float(value[:-1]) * 3600
        return float(value)

    def _wait_and_emit_feedback(
        self,
        run_id: str,
        emitter: SignalEmitter,
        scenario: object,
        detection_timeout_s: float,
        attack_time: float,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Wait for Glorfindel's detection of this run, through the return channel.

        A detection counts only if it is of the run's technique, on its resource (without
        case), and seen at or after ``attack_time`` (annatar/runner/detection.py). Its
        latency from ``attack_time`` is kept in ``_detection_latency_s``.

        SEC18 (N-05): the watch's files are not the red's to read — no injector mounts
        ``runs/glorfindel/`` (eregion_core/runs_layout.py). A run learns of its detection only
        through the return channel (eregion_core/watch_channel.py, #159): the hosted watch's
        heartbeat and its detections of the run's window — or, without a storage channel, the
        local channel of verdicts (``runs/verdicts/``, read-only to the red, its verdicts only;
        the storage channel keeps the priority). With neither, the detection is not measured:
        ``unknown``, never a miss. A miss needs a heartbeat that vouches for the whole wait —
        else the run is ``unknown``.

        A miss the watch vouches for emits a detection_missed signal enriched with the
        scenario's detection_hints, so Glorfindel can propose an improved detection rule.
        """
        channel = watch_channel.source()
        if not channel:
            console.print(
                "[yellow]Detection not measured — no return channel (EREGION_WATCH_CHANNEL) nor "
                "local verdicts (runs/verdicts/): the watch's files are not Annatar's to read "
                "(SEC18). No detection_missed.[/yellow]"
            )
            self._detection_result = "unknown"
            if stop_event is not None:
                stop_event.set()
            return

        def _watch_active() -> bool:
            # An unreadable channel shows no watch. The heartbeat's test is the gate's
            # (eregion_core/watch_gate.py, V1); the local channel's, the same (SEC18).
            now = datetime.fromtimestamp(time.time(), timezone.utc)
            if channel == watch_channel.STORAGE:
                return watch_gate.fresh(watch_gate.channel_beat(), now)
            try:
                return watch_channel.recent(watch_channel._when(watch_channel.local_heartbeat().get("at")), now)
            except Exception:
                return False

        # The run started only with a live watch (V1, eregion_core/watch_gate.py). One that
        # stopped since, and is not back within 30 s, measures nothing: unknown.
        if not _watch_active():
            # Retry for up to 30s in case the watch is restarting
            deadline_check = time.time() + 30
            while time.time() < deadline_check:
                time.sleep(5)
                if _watch_active():
                    break
            else:
                console.print(
                    "[yellow]The Glorfindel watch stopped during the run — detection not"
                    " measured (unknown).[/yellow]"
                )
                self._detection_result = "unknown"  # detection was not measured
                if stop_event is not None:
                    stop_event.set()
                return

        wait_s = detection_timeout_s + 120
        poll_interval = 5.0
        deadline = time.time() + wait_s

        console.print(
            f"\n[dim]Purple team feedback: monitoring Glorfindel response "
            f"(up to {int(wait_s)}s)…[/dim]"
        )

        result_event: str | None = None
        latency: float | None = None
        while time.time() < deadline:
            # The return channel: the hosted watch's detections of this run's window
            latency = self._channel_latency(run_id, scenario.mitre, emitter.resource_id, attack_time)
            if latency is not None:
                result_event = "detection"
                break
            time.sleep(poll_interval)

        if result_event is None:
            # Only the watch could have seen it: its silence is a miss only if a heartbeat
            # vouches for the whole wait — the storage channel's, else the local one's.
            result_event, latency, why = self._settle_through_channel(
                run_id, scenario.mitre, emitter.resource_id, attack_time)
            if result_event == "detection_timeout" and self._detection_refused_total:
                # SEC21: a detection the run could not believe is no silence — a watch older than
                # this injector, or a hand on the channel: never a miss, never seen.
                result_event, why = None, self._refused_why()
            if result_event is None:
                console.print(
                    f"[yellow]Detection not measured — the hosted watch cannot vouch for"
                    f" this run ({why}). No detection_missed.[/yellow]"
                )
                self._detection_result = "unknown"
                if stop_event is not None:
                    stop_event.set()
                return

        if result_event == "detection":
            console.print(
                f"[green]✓ Glorfindel detected the attack {latency:g} s after it"
                " — no feedback needed.[/green]"
            )
            self._detection_result = "detected"
            self._detection_latency_s = latency
            if stop_event is not None:
                stop_event.set()
            return

        console.print(
            "[yellow]⚠ Detection timeout — emitting detection_missed "
            "so Glorfindel can propose an improved rule.[/yellow]"
        )

        self._detection_result = "missed"  # timeout or no detection in window
        det = scenario.detection or {}
        emitter.emit(
            event="detection_missed",
            raw_signal={
                "failed_query": det.get("query", ""),
                "detection_source": det.get("source", "azure_monitor"),
                "detection_hints": scenario.detection_hints,
            },
            metrics={
                "workspace_id": det.get("workspace_id", ""),
                "detection_timeout_s": int(detection_timeout_s),
                "failed_query": det.get("query", ""),
            },
        )
        console.print(
            "[cyan]->[/cyan] Signal 'detection_missed' emitted"
            " — Glorfindel will propose a detection rule."
        )
        if stop_event is not None:
            stop_event.set()

    def _refused_why(self) -> str:
        return f"{self._detection_refused_total} detection(s) on the return channel refused (SEC21)"

    def _missing_metrics(self, metrics: dict) -> None:
        """SEC21b: what the heartbeat covers and the run could not read back, in its report."""
        if self._detection_missing:
            metrics["detection_missing"] = list(self._detection_missing)
            metrics["detection_missing_total"] = self._detection_missing_total

    def _covered(self, heartbeat: dict, run_id: str, found: list[dict]) -> str:
        """SEC21b (#535): why the run's silence is no miss although the watch's heartbeat vouches
        for the wait — a detection it covers missing from what the run read back after it, a watch
        older than this injector, a run it leaves out —, "" when it is one. Each missing blob said
        once — in the console, in Orodruin's journal, in the run's report —, MAX_MISSING at most."""
        why, missing, total = watch_channel.uncovered(heartbeat, run_id, found)
        self._detection_missing_total = max(self._detection_missing_total, total)
        for name in missing:
            if name in self._detection_missing or len(self._detection_missing) >= watch_channel.MAX_MISSING:
                continue
            self._detection_missing.append(name)
            console.print(f"A detection the watch's heartbeat covers is missing from the return channel "
                          f"— never a miss (SEC21b): {name}", markup=False, style="yellow")
            if self._session is not None:
                try:
                    self._session.declare("detection_missing", f"{name}: covered by the watch's heartbeat, absent")
                except Exception as e:  # the journal said its own failure; the run goes on
                    console.print(f"[yellow]Not journaled: {e}[/yellow]")
        return why

    def _vouched(self, run_id: str) -> list[dict]:
        """SEC21 (#530): the detections of this run the pinned key signed; each other refused,
        said once — in the console, in Orodruin's journal, and kept for the run's report —, up to
        MAX_REFUSED for the run: the rest only counted. ``_detection_refused_total``: the most
        refused in one read of the channel (each read lists every blob of the run). Raises when the
        channel cannot be read."""
        found, refused, total = watch_channel.vouched_detections(run_id)
        self._detection_refused_total = max(self._detection_refused_total, total)
        for why in refused:
            if why in self._detection_refused:
                continue
            if len(self._detection_refused) >= watch_channel.MAX_REFUSED:
                break   # a writer that rotates its blobs never floods the journal nor the report
            self._detection_refused.append(why)
            # What the channel holds is never read as markup.
            console.print(f"A detection on the return channel refused — never counted (SEC21): {why}",
                          markup=False, style="yellow")
            if self._session is not None:
                try:
                    self._session.declare("detection_refused", why)
                except Exception as e:  # the journal said its own failure; the run goes on
                    console.print(f"[yellow]Not journaled: {e}[/yellow]")
        return found

    def _channel_latency(self, run_id: str, ttp: str, resource_id: str,
                         attack_time: float) -> float | None:
        """The latency of this run's detection in the return channel, else None — an
        unreadable channel included: only the end of the wait decides what that means."""
        try:
            found = self._vouched(run_id)
        except Exception:
            return None
        return detection_latency(watch_channel.as_records(found), ttp, resource_id, attack_time)

    def _settle_through_channel(self, run_id: str, ttp: str, resource_id: str,
                                attack_time: float) -> tuple[str | None, float | None, str]:
        """The wait is over and the channel showed no detection. Wait (up to SETTLE_S) for a
        heartbeat written after the wait: everything the watch noted before it was then
        delivered, so a last read of the detections settles it. Returns ("detection",
        latency, "") — ("detection_timeout", None, "") for a miss the watch vouches for —
        or (None, None, why) when it cannot vouch: the run is unknown. On the storage channel the
        heartbeat that vouches is the watch's only once the pinned key signed it (SEC21): unsigned,
        another key, replayed — unknown, never a miss; and its silence a miss only once every
        detection that heartbeat covers for the run is read back, after it (SEC21b)."""
        until = time.time()
        give_up = until + watch_channel.SETTLE_S
        while True:
            try:
                heartbeat = watch_channel.read_heartbeat()
                why = watch_channel.miss_unprovable(
                    heartbeat, run_id=run_id, attack_time=attack_time, until=until)
                # SEC21: a heartbeat that would prove a miss is believed only signed by the pinned key.
                why = why or watch_gate.miss_proof(heartbeat)
                if not why:
                    # Read after the heartbeat: every detection it covers was written before it.
                    found = self._vouched(run_id)
                    latency = detection_latency(
                        watch_channel.as_records(found), ttp, resource_id, attack_time)
                    if latency is not None:
                        return "detection", latency, ""
                    # SEC21b: a silence is a miss only once all the heartbeat covers was read back.
                    if watch_channel.source() == watch_channel.STORAGE:
                        why = self._covered(heartbeat, run_id, found)
                    if why:
                        # Unknown here, whatever the caller does — the refusals (SEC21) said first.
                        if self._detection_refused_total:
                            why = f"{self._refused_why()}; {why}"
                        return None, None, why   # SEC21b: never a miss
                    return "detection_timeout", None, ""
            except Exception as e:
                why = f"channel unreadable: {e}"
            transient = why == watch_channel.STALE or why.startswith("channel unreadable")
            if not transient or time.time() >= give_up:
                return None, None, why
            time.sleep(watch_channel.TICK_S)
