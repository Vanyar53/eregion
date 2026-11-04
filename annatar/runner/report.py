"""An Annatar run's report: ``runs/annatar/<run_id>.json`` — its own directory (SEC18,
eregion_core/runs_layout.py) —, the run format shared with Gothmog (``eregion_core/run_report.py``,
C1). Here, only how Annatar prints it."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from eregion_core import run_report, runs_layout

console = Console()
RUNS_DIR = runs_layout.dir_of(runs_layout.ANNATAR)


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
        refused = self.metrics.get("detection_refused")
        if isinstance(refused, list) and refused:   # SEC21: never counted, said
            console.print("[bold]Refused on the return channel[/bold] (never counted, SEC21):")
            for why in refused[:20]:   # what the channel holds, never read as markup
                console.print("  - " + str(why)[:400], markup=False, style="yellow")
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
