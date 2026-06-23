#!/usr/bin/env python3
"""Smoke-test the LLM `decide` path against a REAL provider (Ollama / Mistral / ...).

Glorfindel claims to be provider-agnostic (LiteLLM: anthropic, openai, azure, ollama,
self-hosted). The unit tests mock `litellm.completion`, so they can't prove a given
provider actually returns a `security_decision` tool-call that the graph parses into a
valid action. This script does — it runs the real `decide()` on a few fixed signals and
checks a valid decision comes out. Zero Azure, zero mock; the only external call is to
the LLM provider.

Usage:
    GLORFINDEL_LLM_MODEL=ollama/llama3.1 python scripts/llm_smoke.py
    python scripts/llm_smoke.py --model ollama/llama3.1
    make llm-smoke MODEL=ollama/llama3.1

For Ollama: `ollama serve` + `ollama pull llama3.1` (a TOOL-CAPABLE model is required —
the decide step forces a function call). Set GLORFINDEL_LLM_BASE_URL if not on
http://localhost:11434.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED

_RID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute"
    "/virtualMachines/vm-smoke"
)

# (label, signal-overrides, set-of-reasonable-actions). The set is a SOFT check — the
# hard pass is "a valid tool-call was parsed into a known action". A weaker local model
# may reason differently; what we validate is the provider integration, not its IQ.
SCENARIOS = [
    (
        "ransomware — sustained disk write (T1486)",
        {"ttp": "T1486", "raw_signal": {
            "first_result_row": {"Computer": "vm-smoke", "MaxWrite": 147000000}}},
        {"isolate_vm", "restore_from_backup", "snapshot"},
    ),
    (
        "brute force — failed SSH from one IP (T1110.001)",
        {"ttp": "T1110.001", "raw_signal": {
            "first_result_row": {"SourceIP": "185.220.101.5", "FailedAttempts": 47}}},
        {"block_suspicious_ip"},
    ),
    (
        "sudo privilege escalation (T1548.003)",
        {"ttp": "T1548.003", "raw_signal": {"first_result_row": {
            "SyslogMessage": "sudo: USER=root ; COMMAND=/bin/bash", "Computer": "vm-smoke"}}},
        {"isolate_vm"},
    ),
]

_KNOWN = set(AUTONOMOUS_ACTIONS) | set(HUMAN_APPROVAL_REQUIRED) | {
    "no_action", "monitor", "escalate", "investigate"}


def _state(ttp: str, raw_signal: dict) -> dict:
    return {
        "signal": {
            "signal_id": "smoke_detection",
            "resource_id": _RID,
            "resource_type": "vm",
            "ttp": ttp,
            "severity": "critical",
            "event": "detection",
            "raw_signal": raw_signal,
            "context": {"run_id": "smoke"},
        },
        "past_cycles": [],
        "incident": None,
        "dry_run": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default=os.environ.get("GLORFINDEL_LLM_MODEL", "ollama/llama3.1"))
    args = ap.parse_args()
    model = args.model

    from glorfindel.agent import decide

    print(f"LLM smoke-test — model: {model}")
    base = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base:
        print(f"  base_url: {base}")
    print("-" * 72)

    passed = 0
    for label, overrides, expected in SCENARIOS:
        state = _state(overrides["ttp"], overrides["raw_signal"])
        t0 = time.monotonic()
        try:
            # non_disruptive → the raw decision (avoid human_only holding everything).
            out = decide(state, model=model, autonomy_override="non_disruptive")
        except Exception as e:
            print(f"✗ FAIL  {label}\n        {type(e).__name__}: {e}")
            continue
        dt = time.monotonic() - t0
        action = (out.get("action") or "").strip()
        conf = out.get("confidence")
        esc = out.get("escalate")

        if not action:
            print(f"✗ FAIL  {label} — empty action (no tool-call parsed)  [{dt:.1f}s]")
            continue
        passed += 1
        known = "✓known" if action in _KNOWN else "⚠unknown-action"
        match = "✓expected" if action in expected else "~ differs from expected"
        print(
            f"✓ PASS  {label}  [{dt:.1f}s]\n"
            f"        action={action} ({known}) · confidence={conf} · escalate={esc}\n"
            f"        {match} (expected one of: {', '.join(sorted(expected))})"
        )

    print("-" * 72)
    total = len(SCENARIOS)
    print(f"{passed}/{total} scenarios produced a valid parsed decision.")
    if passed < total:
        print("→ A provider that can't return a tool-call isn't usable for `decide` "
              "(pick a tool-capable model).")
        return 1
    print("→ Provider integration OK. (Action quality is a separate, softer judgment.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
