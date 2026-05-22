from __future__ import annotations

import json
from pathlib import Path

from annatar.signals.schema import Signal


def load_signals(path: str | Path) -> list[Signal]:
    """Load all signals from a JSONL file produced by Annatar."""
    signals = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            signals.append(Signal(**data))
    return signals


def load_latest_signals(run_id: str, runs_dir: str | Path = "runs") -> list[Signal]:
    path = Path(runs_dir) / f"{run_id}_signals.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"No signals file for run: {run_id}")
    return load_signals(path)
