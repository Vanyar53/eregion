from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.console import Console
from rich.prompt import Confirm

from annatar.runner.parser import ScenarioParser
from annatar.runner.report import RunReport
from annatar.safety.guard import check_resource_group
from annatar.signals.emitter import SignalEmitter

console = Console()


class Engine:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
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

        emitter = SignalEmitter(
            run_id=run_id,
            scenario_name=scenario.name,
            scenario_mitre=scenario.mitre,
            target=scenario.target,
            resource_id=executor.resource_id,
        )

        metrics = {}
        checks = {}

        # Pre-run integrity check — VM must be clean before attacking
        # Also validates that the previous run's restore succeeded
        console.print("[cyan]->[/cyan] Pre-run integrity check...")
        if not executor.verify_restore_integrity():
            console.print(
                "[red]Pre-run integrity check FAILED — VM is not in a clean state.[/red]\n"
                "  Previous run may not have been restored. Run:\n"
                f"  [bold]glorfindel restore {executor.resource_id} --yes[/bold]"
            )
            return

        # Setup
        for action in scenario.setup:
            self._execute_action(executor, action)

        try:
            # Steps
            T0 = time.time()
            for step in scenario.steps:
                console.print(f"[cyan]->[/cyan] {step.get('name', step.get('action'))}")
                if step.get("record") == "T0":
                    T0 = time.time()
                self._execute_action(executor, step)

            checks["attack"] = "PASS"

            # Emit attack_started — Glorfindel polls detection and owns the response cycle
            if scenario.detection:
                emitter.emit(
                    event="attack_started",
                    raw_signal={
                        "attack_time": T0,
                        "detection_query": scenario.detection["query"],
                        "detection_source": scenario.detection.get("source", "azure_monitor"),
                        "detection_timeout_s": self._parse_duration(scenario.detection.get("timeout", "300s")),
                        "detection_max_s": self._parse_duration(scenario.detection.get("time_max", "9999s")),
                        "log_analytics_workspace_id": scenario.target.get("log_analytics_workspace_id"),
                    },
                )
                console.print("[cyan]->[/cyan] Signal 'attack_started' emitted — Glorfindel takes over detection.")


            overall = "PASS" if all("PASS" in v for v in checks.values()) else "FAIL"
            report = RunReport(
                scenario=scenario.name,
                run_id=run_id,
                mitre=scenario.mitre,
                result=overall,
                metrics=metrics,
                thresholds={
                    "detection_max_s": self._parse_duration(scenario.detection.get("time_max", "9999s")) if scenario.detection else None,
                    "recovery_max_s": self._parse_duration(scenario.recovery.get("time_max", "9999s")) if scenario.recovery else None,
                },
                checks=checks,
            )
            path = report.save()
            report.render()
            console.print(f"\n[dim]Report saved: {path}[/dim]")

        finally:
            # Cleanup always runs — even if the scenario crashes mid-way
            if scenario.cleanup:
                console.print("[cyan]->[/cyan] Running cleanup...")
                for action in scenario.cleanup:
                    try:
                        self._execute_action(executor, action)
                    except Exception as e:
                        console.print(f"  [yellow]Cleanup warning:[/yellow] {e}")

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
