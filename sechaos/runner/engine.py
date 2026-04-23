from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.console import Console
from rich.prompt import Confirm

from sechaos.runner.parser import ScenarioParser
from sechaos.runner.report import RunReport
from sechaos.safety.guard import check_resource_group

console = Console()


class Engine:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.parser = ScenarioParser()

    def run(self, scenario_path: str, skip_confirm: bool = False):
        scenario = self.parser.load(scenario_path)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        console.rule(f"[bold cyan]SecurityChaos — {scenario.name}[/bold cyan]")
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

        metrics = {}
        checks = {}

        # Setup
        for action in scenario.setup:
            self._execute_action(executor, action)

        # Steps
        T0 = time.time()
        for step in scenario.steps:
            console.print(f"[cyan]->[/cyan] {step.get('name', step.get('action'))}")
            self._execute_action(executor, step)
            if step.get("record") == "T0":
                T0 = time.time()

        # Detection
        if scenario.detection:
            console.print("[cyan]->[/cyan] Waiting for detection alert...")
            detection_time = collector.poll_alert(
                query=scenario.detection["query"],
                source=scenario.detection["source"],
                timeout_s=self._parse_duration(scenario.detection.get("timeout", "300s")),
            )
            if detection_time is not None:
                metrics["detection_time_s"] = round(detection_time)
                threshold = self._parse_duration(scenario.thresholds.get("detection_time_max", "9999s"))
                ok = detection_time <= threshold
                checks["detection"] = "PASS" if ok else f"FAIL — {round(detection_time)}s vs seuil {threshold}s"
                console.print(f"  Detection: {checks['detection']}")
            else:
                metrics["detection_time_s"] = None
                checks["detection"] = "FAIL — timeout, no alert fired"
                console.print(f"  [red]Detection timeout[/red]")

        # Recovery
        if scenario.recovery:
            console.print("[cyan]->[/cyan] Triggering recovery...")
            T2 = time.time()
            executor.trigger_recovery(scenario.recovery)
            recovery_time = time.time() - T0
            metrics["recovery_time_s"] = round(recovery_time)
            threshold = self._parse_duration(scenario.thresholds.get("recovery_time_max", "9999s"))
            ok = recovery_time <= threshold
            checks["recovery"] = "PASS" if ok else f"FAIL — {round(recovery_time/60)}min vs RTO {round(threshold/60)}min"
            console.print(f"  Recovery: {checks['recovery']}")

        # Cleanup
        for action in scenario.cleanup:
            self._execute_action(executor, action)

        overall = "PASS" if all("PASS" in v for v in checks.values()) else "FAIL"
        report = RunReport(
            scenario=scenario.name,
            run_id=run_id,
            mitre=scenario.mitre,
            result=overall,
            metrics=metrics,
            thresholds={k: self._parse_duration(v) for k, v in scenario.thresholds.items()},
            checks=checks,
        )
        path = report.save()
        report.display()
        console.print(f"\n[dim]Report saved: {path}[/dim]")

    def _dry_run_display(self, scenario):
        console.print("[yellow]DRY RUN — no actions will be executed[/yellow]\n")
        for i, step in enumerate(scenario.steps, 1):
            console.print(f"  {i}. [{step.get('action')}] {step.get('name', '')}")
        if scenario.detection:
            console.print(f"  -> Poll {scenario.detection['source']} for: {scenario.detection['query']}")
        if scenario.recovery:
            console.print(f"  -> Trigger recovery: {scenario.recovery.get('action')}")

    def _get_executor_collector(self, scenario):
        target_type = scenario.target.get("type")
        if target_type == "azure_vm":
            from sechaos.executors.azure_vm import AzureVMExecutor
            from sechaos.collectors.azure_monitor import AzureMonitorCollector
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
