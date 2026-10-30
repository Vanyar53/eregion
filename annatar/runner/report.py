"""An Annatar run's report: ``runs/<run_id>.json``, the run format shared with Gothmog
(``eregion_core/run_report.py``, C1). Here, only how Annatar prints it."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from eregion_core import run_report

console = Console()
RUNS_DIR = Path("runs")


class RunReport(run_report.RunReport):
    def save(self, runs_dir: str | Path | None = None) -> Path:
        return super().save(RUNS_DIR if runs_dir is None else runs_dir)

    def render(self):
        color = "green" if self.result == "PASS" else "red"
        console.print(f"\n[bold]Run:[/bold] {self.run_id}")
        console.print(f"[bold]Scenario:[/bold] {self.scenario}  [bold]MITRE:[/bold] {self.mitre}")
        console.print(f"[bold]Result:[/bold] [{color}]{self.result}[/{color}]")
        if self.metrics.get("without_glorfindel") is True:  # V1: run --without-glorfindel
            console.print("[bold]Detection:[/bold] [yellow]not measured, by choice "
                          "(--without-glorfindel)[/yellow]")
        elif "detection" in self.metrics:  # written after the wait for Glorfindel's result
            latency = self.metrics.get("detection_latency_s")
            after = f" ({latency:g} s after the attack)" if latency is not None else ""
            console.print(f"[bold]Detection:[/bold] {self.metrics['detection']}{after}")
        console.print("[dim]Detection and RTO metrics are owned by Glorfindel.[/dim]")

    @staticmethod
    def display(run_id: str):
        path = RUNS_DIR / f"{run_id}.json"
        if not path.exists():
            console.print(f"[red]Run not found:[/red] {run_id}")
            return
        with open(path) as f:
            data = json.load(f)
        r = RunReport(**data)
        r.render()
