from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
RUNS_DIR = Path("runs")


@dataclass
class RunReport:
    scenario: str
    run_id: str
    mitre: str
    result: str
    metrics: dict
    thresholds: dict
    checks: dict

    def save(self):
        RUNS_DIR.mkdir(exist_ok=True)
        path = RUNS_DIR / f"{self.run_id}.json"
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
        return path

    def render(self):
        color = "green" if self.result == "PASS" else "red"
        console.print(f"\n[bold]Run:[/bold] {self.run_id}")
        console.print(f"[bold]Scenario:[/bold] {self.scenario}  [bold]MITRE:[/bold] {self.mitre}")
        console.print(f"[bold]Result:[/bold] [{color}]{self.result}[/{color}]\n")

        table = Table()
        table.add_column("Check", style="cyan")
        table.add_column("Measured", style="white")
        table.add_column("Threshold", style="yellow")
        table.add_column("Status", style="white")

        for key, status in self.checks.items():
            measured = self.metrics.get(f"{key}_s", "—")
            threshold = self.thresholds.get(f"{key}_max_s", "—")
            ok = "PASS" in status
            table.add_row(
                key,
                f"{measured}s" if isinstance(measured, (int, float)) else str(measured),
                f"{threshold}s" if isinstance(threshold, (int, float)) else str(threshold),
                f"[green]PASS[/green]" if ok else f"[red]FAIL[/red]",
            )

        console.print(table)

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
