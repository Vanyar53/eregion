#!/usr/bin/env python3
"""Simulate Annatar runs — writes signals to runs/ with realistic delays.

Usage (terminal 2, while glorfindel watch runs/ is open in terminal 1):
    python scripts/simulate_annatar.py            # normal run (detection + recovery)
    python scripts/simulate_annatar.py --ids-gap  # IDS gap run (detection_timeout)
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from annatar.signals.emitter import SignalEmitter

MODE = "--ids-gap" in sys.argv

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

TARGET = {
    "type": "azure_vm",
    "resource_group": "annatar",
    "vm_name": "vm-annatar-victim",
}

RESOURCE_ID = (
    "/subscriptions/44a4dc83-3e79-4e4e-aa93-1b4f8e3ede80/resourceGroups/annatar"
    "/providers/Microsoft.Compute/virtualMachines/vm-annatar-victim"
)

emitter = SignalEmitter(
    run_id=RUN_ID,
    scenario_name="azure-ransomware-vm",
    scenario_mitre="T1486",
    target=TARGET,
    resource_id=RESOURCE_ID,
)

mode_label = "IDS GAP" if MODE else "NORMAL"
print(f"[annatar] Run {RUN_ID} — mode: {mode_label}")
print(f"[annatar] Signals → runs/{RUN_ID}_signals.jsonl")
print()

print("[annatar] Setup: initializing test volume...")
time.sleep(2)

print("[annatar] Attack: mass-encrypting /mnt/testdata (T0)...")
time.sleep(3)

if MODE:
    print("[annatar] Detection: polling Azure Monitor... timeout (no alert fired)")
    time.sleep(2)
    emitter.emit(
        event="detection_timeout",
        raw_signal={"passed": False, "reason": "Azure Monitor alert did not fire within 300s"},
    )
    print("[annatar] → signal 'detection_timeout' emitted (IDS gap)")
    print()
    print("[annatar] Run complete — IDS gap confirmed for T1486.")
else:
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
    print(f"[annatar] Run complete.")
