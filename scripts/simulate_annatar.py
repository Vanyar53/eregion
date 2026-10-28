#!/usr/bin/env python3
"""Simulate an Annatar run without Azure — the signals of a run, then Glorfindel's decisions.

Usage:
    python scripts/simulate_annatar.py            # normal run (detection + recovery)
    python scripts/simulate_annatar.py --ids-gap  # IDS gap run (detection_timeout)

The signals are written to a file of their own (a temporary directory, never runs/) and
handed to `glorfindel respond <file> --dry-run`: it decides on each, executes nothing. Not
through the watch: since SEC3 (#274) the watch takes from runs/ only what an injector emits
(attack_started, detection_missed) — a `detection`, a `detection_timeout` or a
`recovery_complete` written there is refused. The recovery_complete simulated here is not
Glorfindel's own (`glorfindel restore --wait` emits that one): the release it proposes is
held for a human — what the real defender does with such a line. A model key is needed
(the decisions are the model's), no Azure credential.
"""
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from annatar.signals.emitter import SignalEmitter  # noqa: E402

MODE = "--ids-gap" in sys.argv

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

TARGET = {
    "type": "azure_vm",
    "resource_group": "rg-example",
    "vm_name": "vm-example",
}

# A placeholder: dry-run, nothing reaches Azure.
RESOURCE_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example"
    "/providers/Microsoft.Compute/virtualMachines/vm-example"
)

out_dir = Path(tempfile.mkdtemp(prefix="annatar-simulate-"))
emitter = SignalEmitter(
    run_id=RUN_ID,
    scenario_name="azure-ransomware-vm",
    scenario_mitre="T1486",
    target=TARGET,
    resource_id=RESOURCE_ID,
    runs_dir=out_dir,
)
signals_file = out_dir / f"{RUN_ID}_signals.jsonl"

mode_label = "IDS GAP" if MODE else "NORMAL"
print(f"[annatar] Run {RUN_ID} — mode: {mode_label}")
print(f"[annatar] Signals → {signals_file} (not runs/: the watch refuses these events there)")
print()

print("[annatar] Attack: mass-encrypting /mnt/testdata (T0)...")
time.sleep(1)

if MODE:
    print("[annatar] Detection: polling Azure Monitor... timeout (no alert fired)")
    emitter.emit(
        event="detection_timeout",
        raw_signal={"passed": False, "reason": "Azure Monitor alert did not fire within 300s"},
    )
    print("[annatar] → signal 'detection_timeout' written (IDS gap)")
else:
    print("[annatar] Detection: disk write spike observed by Azure Monitor...")
    emitter.emit(
        event="detection",
        raw_signal={"detection_time_s": 4, "passed": True},
        metrics={"detection_s": 4},
    )
    print("[annatar] → signal 'detection' written")
    print("[annatar] Recovery: Azure Backup restore completed, VM back online...")
    emitter.emit(
        event="recovery_complete",
        raw_signal={
            "recovery_time_s": 1120,
            "integrity_ok": True,
            "heartbeat_elapsed_s": 45,
            "passed": True,
        },
        metrics={"recovery_s": 1120, "heartbeat_s": 45},
    )
    print("[annatar] → signal 'recovery_complete' written (not Glorfindel's: its release is held)")

print()
# The simulated cycles stay out of the operator's memory (ChromaDB) and out of the repository's
# runs/: a memory of their own, and the debug trace written beside the signals.
memory = out_dir / "memory"
repo = str(Path(__file__).resolve().parent.parent)
env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in (repo, os.environ.get("PYTHONPATH")) if p)}
print(f"[glorfindel] glorfindel respond {signals_file} --dry-run --memory-path {memory}")
sys.exit(subprocess.call([sys.executable, "-c", "from glorfindel.cli import cli; cli()",
                          "respond", str(signals_file), "--dry-run", "--memory-path", str(memory)],
                         cwd=out_dir, env=env))
