from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

console = Console()

REQUIRED_FIELDS = ["name", "description", "mitre", "target", "steps"]


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)


@dataclass
class Scenario:
    name: str
    description: str
    mitre: str
    version: str
    target: dict
    setup: list
    steps: list
    detection: dict
    recovery: dict | None
    cleanup: list
    prerequisites: dict
    raw: dict


class ScenarioParser:
    def load(self, path: str) -> Scenario:
        result = self.validate(path)
        if not result.valid:
            raise ValueError(f"Invalid scenario: {result.errors}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return Scenario(
            name=data["name"],
            description=data.get("description", ""),
            mitre=data.get("mitre", ""),
            version=data.get("version", "1.0.0"),
            target=data["target"],
            setup=data.get("setup", []),
            steps=data["steps"],
            detection=data.get("detection", {}),
            recovery=data.get("recovery"),
            cleanup=data.get("cleanup", []),
            prerequisites=data.get("prerequisites", {}),
            raw=data,
        )

    def validate(self, path: str) -> ValidationResult:
        errors = []
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            return ValidationResult(valid=False, errors=[f"YAML parse error: {e}"])

        for field_name in REQUIRED_FIELDS:
            if field_name not in data:
                errors.append(f"Missing required field: '{field_name}'")

        if "target" in data:
            if "type" not in data["target"]:
                errors.append("target.type is required")
            if "resource_group" not in data["target"]:
                errors.append("target.resource_group is required")

        return ValidationResult(valid=len(errors) == 0, errors=errors)


def list_available():
    scenarios_dir = Path(__file__).parent.parent.parent / "scenarios"
    files = glob.glob(str(scenarios_dir / "**" / "*.yaml"), recursive=True)

    table = Table(title="Available Scenarios")
    table.add_column("Name", style="cyan")
    table.add_column("MITRE", style="yellow")
    table.add_column("Target", style="green")
    table.add_column("Path", style="dim")

    parser = ScenarioParser()
    for f in sorted(files):
        try:
            s = parser.load(f)
            rel = os.path.relpath(f, scenarios_dir.parent)
            table.add_row(s.name, s.mitre, s.target.get("type", "?"), rel)
        except Exception:
            table.add_row("(invalid)", "", "", os.path.relpath(f))

    console.print(table)
