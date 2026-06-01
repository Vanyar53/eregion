from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from annatar.runner.parser import ScenarioParser
from annatar.runner.report import RunReport
from annatar.safety.guard import check_resource_group
from annatar.signals.emitter import SignalEmitter

console = Console()


class Engine:
    def __init__(self, dry_run: bool = False, skip_preflight: bool = False):
        self.dry_run = dry_run
        self.skip_preflight = skip_preflight
        self.parser = ScenarioParser()

    def run(self, scenario_path: str, skip_confirm: bool = False):
        scenario = self.parser.load(scenario_path)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        console.rule(f"[bold cyan]Annatar — {scenario.name}[/bold cyan]")
        console.print(f"  MITRE   : {scenario.mitre}")
        console.print(f"  Target  : {scenario.target.get('type')} / {scenario.target.get('resource_group')}")
        console.print(f"  Dry-run : {self.dry_run}\n")

        if self.dry_run:
            self._dry_run_display(scenario)
            return

        if not skip_confirm:
            if not Confirm.ask("[yellow]Execute this scenario?[/yellow]"):
                console.print("Aborted.")
                return

        executor, collector = self._get_executor_collector(scenario)

        # Safety check
        rg_tags = executor.get_resource_group_tags(scenario.target["resource_group"])
        guard = check_resource_group(rg_tags)
        if not guard.allowed:
            console.print(f"[red]Safety check failed:[/red] {guard.reason}")
            return

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
                return

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
                return

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
                args=(run_id, emitter, scenario, detection_timeout_s, stop_event),
                daemon=False,
                name=f"annatar-feedback-{run_id}",
            )
            t.start()
            t.join()
        else:
            stop_event.set()

    def _dry_run_display(self, scenario):
        console.print("[yellow]DRY RUN — no actions will be executed[/yellow]\n")
        for i, step in enumerate(scenario.steps, 1):
            console.print(f"  {i}. [{step.get('action')}] {step.get('name', '')}")
        if scenario.detection:
            timeout = scenario.detection.get("timeout", "?")
            console.print(f"  -> Detection timeout: {timeout} — Glorfindel uses detection_rules.yaml")

    def _get_executor_collector(self, scenario):
        target_type = scenario.target.get("type")
        if target_type == "azure_vm":
            from annatar.executors.azure_vm import AzureVMExecutor
            from annatar.collectors.azure_monitor import AzureMonitorCollector
            executor = AzureVMExecutor(scenario.target)
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
        stop_event: threading.Event | None = None,
    ) -> None:
        """Poll Glorfindel's debug.jsonl for the detection result.

        If Glorfindel times out (detection_timeout event), emit a
        detection_missed signal enriched with the scenario's detection_hints
        so Glorfindel can propose an improved detection rule.
        """
        debug_path = Path("runs") / f"{run_id}_debug.jsonl"
        heartbeat = Path.home() / ".glorfindel" / "watch_heartbeat"

        # Short-circuit: skip if no active glorfindel watch.
        # Retry up to 30s to account for a watch that just started.
        def _watch_active() -> bool:
            if debug_path.exists():
                return True  # watch already responded
            if not heartbeat.exists():
                return False
            try:
                ts = datetime.fromisoformat(heartbeat.read_text().strip())
                return (time.time() - ts.timestamp()) < 90
            except Exception:
                return False

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
                return

        wait_s = detection_timeout_s + 120
        poll_interval = 5.0
        deadline = time.time() + wait_s

        console.print(
            f"\n[dim]Purple team feedback: monitoring Glorfindel response "
            f"(up to {int(wait_s)}s)…[/dim]"
        )

        result_event: str | None = None
        while time.time() < deadline:
            if debug_path.exists():
                for line in debug_path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        evt = rec.get("signal", {}).get("event", "")
                        if evt in ("detection", "detection_timeout"):
                            result_event = evt
                            break
                    except Exception:
                        pass
            if result_event:
                break
            time.sleep(poll_interval)

        if result_event == "detection":
            console.print("[green]✓ Glorfindel detected the attack — no feedback needed.[/green]")
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
