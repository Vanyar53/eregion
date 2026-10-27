"""A Gothmog run, recorded like Annatar's (``annatar/runner/report.py``): ``runs/<run_id>.json``
with the same keys — ``annatar report`` reads it too. What a fault adds (its execution, its
probes, its return) goes in ``metrics`` and ``checks``; a fault has no ATT&CK id."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from rich.console import Console

console = Console()


@dataclass
class RunReport:
    scenario: str
    run_id: str
    mitre: str
    result: str
    metrics: dict
    thresholds: dict
    checks: dict

    def save(self, runs_dir: str | Path = "runs") -> Path:
        path = Path(runs_dir) / f"{self.run_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path

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
