from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console

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
        console.print(f"[bold]Result:[/bold] [{color}]{self.result}[/{color}]")
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
