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
    detection: dict       # timeout, time_max, prerequisites, hints
    detection_hints: dict  # shortcut to detection["hints"] for engine convenience
    raw: dict


class ScenarioParser:
    def load(self, path: str) -> Scenario:
        result = self.validate(path)
        if not result.valid:
            raise ValueError(f"Invalid scenario: {result.errors}")

        with open(path) as f:
            data = yaml.safe_load(f)

        det = data.get("detection", {})
        return Scenario(
            name=data["name"],
            description=data.get("description", ""),
            mitre=data.get("mitre", ""),
            version=data.get("version", "1.0.0"),
            target=data["target"],
            setup=data.get("setup", []),
            steps=data["steps"],
            detection=det,
            detection_hints=det.get("hints", {}),
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


def scenarios_root() -> Path:
    """Return the annatar/scenarios/ directory."""
    return Path(__file__).parent.parent / "scenarios"


def find_scenario_by_name(name: str) -> str | None:
    """Find a scenario file by its YAML name field or stem. Returns the path or None."""
    root = scenarios_root()
    parser = ScenarioParser()
    for f in sorted(glob.glob(str(root / "**" / "*.yaml"), recursive=True)):
        # Fast check: stem matches before loading YAML
        if Path(f).stem == name or Path(f).stem == name.replace(" ", "-"):
            return f
        try:
            s = parser.load(f)
            if s.name == name:
                return f
        except Exception:
            pass
    return None


def list_available():
    root = scenarios_root()
    project_root = root.parent.parent
    files = glob.glob(str(root / "**" / "*.yaml"), recursive=True)

    table = Table(title="Available Scenarios", show_lines=False)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("MITRE", style="yellow", width=10)
    table.add_column("Target", style="green", width=10)
    table.add_column("Path (annatar run <name or path>)", style="dim")

    parser = ScenarioParser()
    for f in sorted(files):
        try:
            s = parser.load(f)
            rel = os.path.relpath(f, project_root)
            table.add_row(s.name, s.mitre, s.target.get("type", "?"), rel)
        except Exception:
            table.add_row("(invalid)", "", "", os.path.relpath(f, project_root))

    console.print(table)
