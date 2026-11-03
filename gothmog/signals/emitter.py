"""Gothmog's signals — ``fault_started``, ``fault_ended``, ``steady_state_restored``,
``revert_failed`` — in the shape of the injectors' signal (``eregion_core/signals.py``), but in a file
Glorfindel's watch does not read: ``runs/gothmog/<run_id>_signals.jsonl``, Gothmog's own directory
(SEC18, eregion_core/runs_layout.py).

The watch sends every event of ``runs/annatar/*_signals.jsonl`` but ``attack_started`` straight to
its decision graph (``glorfindel/cli.py``, ``_dispatch``): a ``fault_started`` there would
start a decision cycle on the declaration itself. Glorfindel learns of a fault by its exercise
window (``kind: fault``) and by its own telemetry — what a real outage would give it. Written as
every writer writes ``runs/`` (SEC16): one whole line, never through a link.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from eregion_core import channel_reader, runs_layout

SIGNALS_SUBDIR = runs_layout.GOTHMOG


class SignalEmitter:
    def __init__(self, run_id: str, fault_id: str, targets: list[str],
                 runs_dir: str | Path | None = None):
        self.run_id = run_id
        self.fault_id = fault_id
        self.targets = list(targets)
        runs_dir = runs_layout.dir_of(runs_layout.GOTHMOG) if runs_dir is None else runs_dir
        self.path = Path(runs_dir) / f"{run_id}_signals.jsonl"

    def emit(self, event: str, raw_signal: dict | None = None, metrics: dict | None = None) -> dict:
        signal = {
            "signal_id": f"{self.run_id}_{event}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": "azure",
            "resource_id": self.targets[0] if len(self.targets) == 1 else "",
            "resource_type": "vm",
            "ttp": "",
            "severity": "info",
            "event": event,
            "raw_signal": raw_signal or {},
            "context": {"run_id": self.run_id, "fault": self.fault_id,
                        "targets": self.targets, **(metrics or {})},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        channel_reader.append_line(self.path, json.dumps(signal))
        return signal
