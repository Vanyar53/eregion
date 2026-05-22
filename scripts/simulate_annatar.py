#!/usr/bin/env python3
"""Simulate an Annatar ransomware run — writes signals to runs/ with realistic delays.

Usage (terminal 2, while glorfindel watch runs/ is open in terminal 1):
    python scripts/simulate_annatar.py
"""
import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from annatar.signals.emitter import SignalEmitter

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

TARGET = {
    "type": "azure_vm",
    "resource_group": "rg-sechaos-test",
    "vm_name": "vm-sechaos-victim",
}

RESOURCE_ID = (
    "/subscriptions/sub-sim-123/resourceGroups/rg-sechaos-test"
    "/providers/Microsoft.Compute/virtualMachines/vm-sechaos-victim"
)

emitter = SignalEmitter(
    run_id=RUN_ID,
    scenario_name="azure-ransomware-vm",
    scenario_mitre="T1486",
    target=TARGET,
    resource_id=RESOURCE_ID,
)

print(f"[annatar] Run {RUN_ID} starting...")
print(f"[annatar] Signals → runs/{RUN_ID}_signals.jsonl")
print()

print("[annatar] Setup: initializing test volume...")
time.sleep(2)

print("[annatar] Attack: mass-encrypting /mnt/testdata (T0)...")
time.sleep(3)

print("[annatar] Detection: disk write spike observed by Azure Monitor...")
time.sleep(1)
emitter.emit(
    event="detection",
    raw_signal={"detection_time_s": 4, "passed": True},
    metrics={"detection_s": 4},
)
print("[annatar] → signal 'detection' emitted")
print()

print("[annatar] Waiting 8s before recovery signal...")
time.sleep(8)

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
print("[annatar] → signal 'recovery_complete' emitted")
print()
print(f"[annatar] Run complete. Report would be saved to runs/{RUN_ID}.json")
