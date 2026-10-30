"""A Gothmog run, recorded like Annatar's: ``runs/<run_id>.json``, the run format both share
(``eregion_core/run_report.py``, C1) — ``annatar report`` reads it too. What a fault adds (its
execution, its probes, its return) goes in ``metrics`` and ``checks``; a fault has no ATT&CK
id. Here, only how Gothmog prints it."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from eregion_core import run_report

console = Console()


class RunReport(run_report.RunReport):
    def render(self) -> None:
        color = {"PASS": "green", "REFUSED": "yellow"}.get(self.result, "red")
        console.print(f"\n[bold]Run:[/bold] {self.run_id}")
        console.print(f"[bold]Fault:[/bold] {self.scenario}")
        for name, value in self.checks.items():
            mark = "[green]✓[/green]" if value == "PASS" else "[red]✗[/red]"
            console.print(f"  {mark} {name}: {value}")
        if self.metrics.get("without_glorfindel") is True:  # V1: run --without-glorfindel
            console.print("[bold]Glorfindel:[/bold] [yellow]not running, by choice "
                          "(--without-glorfindel) — its reaction not measured[/yellow]")
        console.print(f"[bold]Result:[/bold] [{color}]{self.result}[/{color}]")

    @staticmethod
    def display(run_id: str, runs_dir: str | Path = "runs") -> bool:
        path = Path(runs_dir) / f"{run_id}.json"
        if not path.exists():
            console.print(f"[red]Run not found:[/red] {run_id}")
            return False
        RunReport(**json.loads(path.read_text(encoding="utf-8"))).render()
        return True
