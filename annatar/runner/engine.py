from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from annatar.runner.detection import detection_latency, has_timeout, read_records
from annatar.runner.parser import ScenarioParser
from annatar.runner.report import RunReport
from eregion_core.inscription import check_target
from annatar.signals.emitter import SignalEmitter
from eregion_core import watch_channel
from eregion_core.exercise import close_window, open_window
from eregion_core.orodruin import arm

console = Console()

# A watch file last written this long before the attack is not read (_check_watch_files).
_MTIME_SLACK_S = 60.0


def scenario_destructive(scenario) -> bool | None:
    """Does this scenario destroy or alter data? ``None`` when nobody says.

    The scenario's own ``destructive`` field first, then its technique in the shared
    catalog. Unknown is refused in production (inscription), never assumed safe.
    """
    own = scenario.raw.get("destructive")
    if isinstance(own, bool):
        return own
    from annatar.campaign.catalog import load_catalog

    entry = load_catalog().get(scenario.mitre) or {}
    flag = entry.get("destructive")
    return flag if isinstance(flag, bool) else None


@dataclass
class RunOutcome:
    """Result of a single scenario run — consumed by the campaign runner.

    ``detection`` is the honest blind measure: "detected" (Glorfindel caught it),
    "missed" (active watch, no detection in window → detection_missed emitted), or
    "unknown" (no active glorfindel watch — detection was not measured).
    ``detection_latency_s`` is set only when detected: seconds from the attack
    (``attack_time``) to the detection Glorfindel recorded (annatar/runner/detection.py).
    """

    run_id: str
    detection: str = "unknown"
    detection_latency_s: float | None = None
    error: str | None = None


class Engine:
    def __init__(self, dry_run: bool = False, skip_preflight: bool = False):
        self.dry_run = dry_run
        self.skip_preflight = skip_preflight
        self.parser = ScenarioParser()
        self._detection_result = "unknown"
        self._detection_latency_s = None

    def run(self, scenario_path: str, skip_confirm: bool = False):
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self._detection_result = "unknown"
        self._detection_latency_s = None

        # An invalid scenario (an unknown engine among them, review R1 point 2) is a clean
        # refusal with an outcome the campaign can read, never a raw traceback.
        try:
            scenario = self.parser.load(scenario_path)
        except ValueError as e:
            console.print(f"[red]Invalid scenario:[/red] {e}")
            return RunOutcome(run_id, "unknown", error=f"scenario: {e}")

        console.rule(f"[bold cyan]Annatar — {scenario.name}[/bold cyan]")
        console.print(f"  MITRE   : {scenario.mitre}")
        if scenario.engine != "local-script":
            console.print(f"  Engine  : {scenario.engine} / {scenario.engine_ref}")
        console.print(f"  Target  : {scenario.target.get('type')} / {scenario.target.get('resource_group')}")
        console.print(f"  Dry-run : {self.dry_run}\n")

        if self.dry_run:
            self._dry_run_display(scenario)
            return

        if not skip_confirm:
            if not Confirm.ask("[yellow]Execute this scenario?[/yellow]"):
                console.print("Aborted.")
                return

        # The atomic engine's pure checks run BEFORE anything is armed or opened: a bad
        # engine_ref or a bad probe set must never arm a contract or open an exercise window
        # (review R1 point 8). The resolved test is carried into the run.
        resolved = None
        if scenario.engine == "atomic":
            from annatar.engines.atomic import AtomicError, resolve_ref

            try:
                resolved = resolve_ref(scenario.engine_ref)
            except AtomicError as e:
                console.print(f"[red]Atomic unresolved:[/red] {e}")
                return RunOutcome(run_id, "unknown", error=f"atomic: {e}")
            probe_error = self._atomic_probe_error(scenario)
            if probe_error:
                console.print(f"[red]Refused:[/red] {probe_error}")
                return RunOutcome(run_id, "unknown", error=f"atomic: {probe_error}")

        # Orodruin (eregion_core/orodruin.py): the contract before the target is even read.
        # Passive → the run touches nothing and says why.
        verdict, session = arm(run_id, "annatar")
        if session is None:
            console.print(f"[red]Orodruin passive — nothing touched:[/red] {verdict.reasons()}")
            return RunOutcome(run_id, "unknown", error=f"passive: {verdict.reasons()}")

        # The cap is a pure check too — comparing what this run needs to what the contract
        # still allows (max_injections minus the calls already journaled). It runs right
        # after the contract holds and before the exercise window opens.
        if scenario.engine == "atomic":
            probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
            needed = self._atomic_calls_needed(len(probes))
            available = session.max_injections - session.calls
            if available < needed:
                reason = (
                    f"cap of {session.max_injections} calls ({session.calls} used): this "
                    f"atomic needs {needed} (command, cleanup, and the steady-state probes "
                    "before, right after the command, and after cleanup)"
                )
                console.print(f"[red]Refused:[/red] {reason}")
                return RunOutcome(run_id, "unknown", error=f"cap: {reason}")

        executor, collector = self._get_executor_collector(scenario, session)

        # Inscription (eregion_core/inscription.py): the target inside the bench, it AND
        # its resource group enrolled, its zone allowing this technique.
        rg_tags = executor.get_resource_group_tags(scenario.target["resource_group"])
        guard = check_target(
            executor.resource_id, rg_tags, executor.get_vm_tags(),
            kind="technique", destructive=scenario_destructive(scenario),
        )
        if not guard.allowed:
            console.print(f"[red]Safety check failed:[/red] {guard.reason}")
            return RunOutcome(run_id, "unknown", error=f"safety: {guard.reason}")
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
                return RunOutcome(run_id, "unknown", error="preflight failed")

        # B2: an exercise window before the first touch of the target (setup included),
        # closed whatever happens — what Glorfindel sees on this VM meanwhile is labelled
        # `exercise` (eregion_core/exercise.py).
        open_window(run_id, injector="annatar", kind="technique",
                    experiment=f"{scenario.mitre} {scenario.name}",
                    targets=[executor.resource_id])
        try:
            if scenario.engine == "atomic":
                return self._run_atomic_enrolled(scenario, executor, run_id, session, resolved)
            if scenario.engine == "local-script":
                return self._run_enrolled(scenario, executor, run_id)
            # Unreachable once validate did its job — the explicit table refuses the rest.
            console.print(f"[red]Engine not runnable:[/red] {scenario.engine!r}")
            return RunOutcome(run_id, "unknown", error=f"engine: {scenario.engine!r} not runnable")
        finally:
            close_window(run_id)

    @staticmethod
    def _atomic_calls_needed(n_probes: int) -> int:
        """Run Command calls an atomic run needs: the command, its cleanup, and each
        steady-state probe three times (before, right after the command as the effect
        proof, and after cleanup)."""
        return 2 + 3 * n_probes

    @staticmethod
    def _atomic_probe_error(scenario) -> str | None:
        """An atomic engine must verify the initial state before and after: at least one
        steady-state probe, each with a non-empty ``verify`` and ``expect``. The check is
        the runner's (the schema only runs in CI); ``None`` when it holds."""
        probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
        if not probes:
            return ("engine 'atomic' requires at least one steady_state probe "
                    "(verify + expect) — the initial state is verified before and after")
        for probe in probes:
            if not str(probe.get("verify") or "").strip() or not str(probe.get("expect") or "").strip():
                return (f"steady_state probe {probe.get('name', '?')!r} needs a non-empty "
                        "verify and expect")
        return None

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

        metrics = {}
        checks = {}

        # Setup runs first — cleans residuals from previous attack before we check state
        for action in scenario.setup:
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

        # Block watcher — detects if Glorfindel blocks a source IP mid-run
        stop_event = threading.Event()
        source_ips = scenario.detection_hints.get("source_ips", [])
        vm_name = scenario.target.get("vm_name", "")
        if source_ips and vm_name and not self.dry_run:
            blocks_file = (
                Path.home() / ".glorfindel" / "blocks" / f"{vm_name}.json"
            )
            threading.Thread(
                target=self._watch_blocks,
                args=(source_ips, emitter, stop_event, blocks_file),
                daemon=True,
                name=f"annatar-block-watcher-{run_id}",
            ).start()

        # Steps
        T0 = time.time()
        for step in scenario.steps:
            console.print(f"[cyan]->[/cyan] {step.get('name', step.get('action'))}")
            if step.get("record") == "T0":
                T0 = time.time()
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
        if scenario.detection and detection_timeout_s > 0 and not self.dry_run:
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
        report.metrics = metrics
        report.save()
        return RunOutcome(run_id, self._detection_result, self._detection_latency_s)

    def _run_atomic_enrolled(self, scenario, executor, run_id: str, session,
                             resolved) -> RunOutcome:
        """Run an Atomic Red Team test on the enrolled target (R1).

        Verify the initial state, run the atomic's own command, confirm it broke the steady
        state (the effect proof), emit ``attack_started``, run its ``cleanup_command``, then
        verify the initial state was restored. The command runs inside a ``try``; whatever it
        does, the ``finally`` runs the cleanup, the after-probes and writes the report (the
        atomic's command failing is ``attack: ERROR``, never a silent half-run). ``attack_started``
        is emitted only once the effect is observed — a command that raised, or that did
        nothing, never makes Glorfindel propose a rule for an attack that did not happen.
        The signals and the feedback wait are otherwise unchanged from the local-script path.
        """
        probes = (scenario.raw.get("steady_state") or {}).get("probes") or []
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
            if checks.get("cleanup") != "PASS" or restored is not True:
                self._atomic_recovery_hint(scenario, resolved)

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
            return RunOutcome(run_id, "unknown", error=error)

        # Purple-team feedback — only when the attack actually started (short-circuits with no watch).
        if attack_started and detection_timeout_s > 0 and not self.dry_run:
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
        report.metrics = metrics
        report.save()
        return RunOutcome(run_id, self._detection_result, self._detection_latency_s)

    @staticmethod
    def _atomic_recovery_hint(scenario, resolved) -> None:
        """The target may be dirty — show the operator the atomic's own cleanup, resolved,
        to run by hand (``annatar clean`` runs T1486's disk setup, not an atomic's cleanup)."""
        import shlex

        rg = scenario.target.get("resource_group", "<rg>")
        vm = scenario.target.get("vm_name", "<vm>")
        console.print(
            "[yellow]The target may be dirty — run the atomic's cleanup by hand:[/yellow]\n"
            f"  [bold]az vm run-command invoke -g {rg} -n {vm} --command-id RunShellScript "
            f"--scripts {shlex.quote(resolved.cleanup_command)}[/bold]"
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
            from annatar.engines.atomic import AtomicError, resolve_ref

            try:
                resolved = resolve_ref(scenario.engine_ref)
            except AtomicError as e:
                console.print(f"  [red]atomic unresolved:[/red] {e}")
                return
            console.print(f"  Atomic  : {resolved.name} ({resolved.guid})")
            console.print(f"  command : {resolved.command.strip()}")
            console.print(f"  cleanup : {resolved.cleanup_command.strip()}")
            for p in (scenario.raw.get("steady_state") or {}).get("probes") or []:
                console.print(
                    f"  probe   : {p.get('name')} — "
                    f"{resolved.substitute(p.get('verify', ''))} (expect {p.get('expect')})"
                )
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
        """Poll Glorfindel's debug.jsonl for the detection result.

        A detection counts only if it is of the run's technique, on its resource (without
        case), and seen at or after ``attack_time`` — the same rule on both paths (the run's
        own file and the RulePoller's ``watch-*`` files, annatar/runner/detection.py). Its
        latency from ``attack_time`` is kept in ``_detection_latency_s``.

        A watch on another host (Glorfindel hosted, the run on Orodruin) is reached through
        the return channel (eregion_core/watch_channel.py, #159): its heartbeat, its
        detections of the run's window, the same test. With no local watch, a miss needs a
        heartbeat that vouches for the whole wait — else the run is ``unknown``.

        If Glorfindel times out (detection_timeout event), emit a
        detection_missed signal enriched with the scenario's detection_hints
        so Glorfindel can propose an improved detection rule.
        """
        debug_path = Path("runs") / f"{run_id}_debug.jsonl"
        heartbeat = Path.home() / ".glorfindel" / "watch_heartbeat"
        channel = watch_channel.channel_url()

        def _local_watch() -> bool:
            if debug_path.exists():
                return True  # watch already responded
            if not heartbeat.exists():
                return False
            try:
                ts = datetime.fromisoformat(heartbeat.read_text().strip())
                return (time.time() - ts.timestamp()) < 90
            except Exception:
                return False

        def _remote_watch() -> bool:
            if not channel:
                return False
            try:
                return watch_channel.alive(watch_channel.read_heartbeat(),
                                           now=datetime.fromtimestamp(time.time(), timezone.utc))
            except Exception:
                return False  # an unreadable channel shows no watch

        # Short-circuit: skip if no active glorfindel watch.
        # Retry up to 30s to account for a watch that just started.
        def _watch_active() -> bool:
            return _local_watch() or _remote_watch()

        if not _watch_active():
            # Retry for up to 30s in case the watch just started
            deadline_check = time.time() + 30
            while time.time() < deadline_check:
                time.sleep(5)
                if _watch_active():
                    break
            else:
                console.print(
                    "[dim]Purple team feedback: no active glorfindel watch detected"
                    " — skipping.[/dim]"
                )
                self._detection_result = "unknown"  # detection was not measured
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
            # 1. Direct Annatar debug file (poll_detection path)
            records = read_records(debug_path)
            latency = detection_latency(records, scenario.mitre, emitter.resource_id, attack_time)
            if latency is not None:
                result_event = "detection"
                break
            if has_timeout(records):
                result_event = "detection_timeout"
                break
            # 2. RulePoller watch-* files (different run_id, same TTP + resource)
            latency = self._check_watch_files(scenario.mitre, emitter.resource_id, attack_time)
            if latency is not None:
                result_event = "detection"
                break
            # 3. The return channel: the hosted watch's detections of this run's window
            latency = self._channel_latency(run_id, scenario.mitre, emitter.resource_id,
                                            attack_time) if channel else None
            if latency is not None:
                result_event = "detection"
                break
            time.sleep(poll_interval)

        if result_event is None and channel and not _local_watch():
            # Only the hosted watch could have seen it: its silence is a miss only if a
            # heartbeat vouches for the whole wait.
            result_event, latency, why = self._settle_through_channel(
                run_id, scenario.mitre, emitter.resource_id, attack_time)
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

        if result_event == "detection_timeout":
            console.print(
                "[yellow]⚠ Detection timeout — emitting detection_missed "
                "so Glorfindel can propose an improved rule.[/yellow]"
            )
        else:
            console.print(
                "[dim]No Glorfindel response observed. "
                "Is 'glorfindel watch' running? Emitting detection_missed anyway.[/dim]"
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

    @staticmethod
    def _channel_latency(run_id: str, ttp: str, resource_id: str,
                         attack_time: float) -> float | None:
        """The latency of this run's detection in the return channel, else None — an
        unreadable channel included: only the end of the wait decides what that means."""
        try:
            found = watch_channel.read_detections(run_id)
        except Exception:
            return None
        return detection_latency(watch_channel.as_records(found), ttp, resource_id, attack_time)

    @staticmethod
    def _settle_through_channel(run_id: str, ttp: str, resource_id: str,
                                attack_time: float) -> tuple[str | None, float | None, str]:
        """The wait is over and the channel showed no detection. Wait (up to SETTLE_S) for a
        heartbeat written after the wait: everything the watch noted before it was then
        delivered, so a last read of the detections settles it. Returns ("detection",
        latency, "") — ("detection_timeout", None, "") for a miss the watch vouches for —
        or (None, None, why) when it cannot vouch: the run is unknown."""
        until = time.time()
        give_up = until + watch_channel.SETTLE_S
        while True:
            try:
                why = watch_channel.miss_unprovable(
                    watch_channel.read_heartbeat(), run_id=run_id,
                    attack_time=attack_time, until=until)
                if not why:
                    latency = detection_latency(
                        watch_channel.as_records(watch_channel.read_detections(run_id)),
                        ttp, resource_id, attack_time)
                    if latency is not None:
                        return "detection", latency, ""
                    return "detection_timeout", None, ""
            except Exception as e:
                why = f"channel unreadable: {e}"
            transient = why == watch_channel.STALE or why.startswith("channel unreadable")
            if not transient or time.time() >= give_up:
                return None, None, why
            time.sleep(watch_channel.TICK_S)

    @staticmethod
    def _check_watch_files(
        ttp: str,
        resource_id: str,
        attack_time: float,
        runs_dir: Path | None = None,
    ) -> float | None:
        """Scan runs/watch-*_debug.jsonl for a RulePoller detection of this run.

        Returns the latency (seconds from ``attack_time``) of the earliest detection of
        ``ttp`` on ``resource_id`` (compared without case) seen at or after the attack, else
        None. Catches the case where RulePoller detects before poll_detection runs — the
        watch file has a different run_id than the Annatar run. A file last written well
        before the attack holds no detection of it and is not read (a slack: the file
        system's clock is coarser than time.time(); the records' own times decide).
        """
        base = runs_dir if runs_dir is not None else Path("runs")
        try:
            candidates = [
                f for f in base.glob("watch-*_debug.jsonl")
                if f.stat().st_mtime >= attack_time - _MTIME_SLACK_S
            ]
        except OSError:
            return None
        found = [lat for lat in (detection_latency(read_records(path), ttp, resource_id, attack_time)
                                 for path in candidates) if lat is not None]
        return min(found) if found else None

    def _watch_blocks(
        self,
        source_ips: list[str],
        emitter: SignalEmitter,
        stop_event: threading.Event,
        blocks_file: Path | None = None,
        poll_interval: float = 5.0,
    ) -> None:
        """Poll Glorfindel's blocks file for the scenario's source IPs.

        Emits attack_adapted when a source IP is blocked mid-run so the
        event is recorded in the run's signals file.
        """
        source_set = set(source_ips)
        reported: set[str] = set()

        while not stop_event.wait(poll_interval):
            if blocks_file is not None and blocks_file.exists():
                try:
                    entries = json.loads(blocks_file.read_text())
                    for entry in entries:
                        ip = entry.get("ip", "")
                        if ip in source_set and ip not in reported:
                            reported.add(ip)
                            emitter.emit(
                                event="attack_adapted",
                                raw_signal={
                                    "blocked_ip": ip,
                                    "reason": "source_ip_blocked_by_defender",
                                },
                            )
                            console.print(
                                f"[yellow]⚡ Source IP {ip} blocked by"
                                f" Glorfindel — attack_adapted emitted.[/yellow]"
                            )
                except Exception:
                    pass
