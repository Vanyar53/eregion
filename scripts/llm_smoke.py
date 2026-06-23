#!/usr/bin/env python3
"""Smoke-test the LLM `decide` path against a REAL provider (Ollama / Mistral / ...).

Glorfindel claims to be provider-agnostic (LiteLLM: anthropic, openai, azure, ollama,
self-hosted). The unit tests mock `litellm.completion`, so they can't prove a given
provider actually returns a `security_decision` tool-call that the graph parses into a
valid action. This script does — it runs the real `decide()` on a few fixed signals and
checks a valid decision comes out. Zero Azure, zero mock; the only external call is to
the LLM provider.

Two scores: INTEGRATION (did a tool-call parse?) and JUDGMENT (act on clear threats,
stay cautious on ambiguous ones). LLMs are stochastic — use --runs N to repeat each
scenario and aggregate (a single run is a signal, not a verdict).

Usage:
    GLORFINDEL_LLM_MODEL=ollama/llama3.1 python scripts/llm_smoke.py
    python scripts/llm_smoke.py --model ollama/command-r7b --runs 5
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

# Two scenario kinds, scored separately from "integration" (did a tool-call parse?):
#   - "act"     : a clear threat → expect a specific action (escalation tolerated).
#   - "caution" : ambiguous/sparse → the model must NOT confidently take a disruptive
#                 action; escalating OR a non-disruptive choice is correct. This is the
#                 discriminator — clear cases saturate (every decent model passes), it's
#                 the ambiguous ones that separate good judgment from over-acting.
_NON_DISRUPTIVE = {"snapshot", "no_action", "monitor", "investigate", "escalate"}

SCENARIOS = [
    {"kind": "act", "label": "ransomware — sustained disk write (T1486)",
     "ttp": "T1486",
     "row": {"Computer": "vm-smoke", "MaxWrite": 147000000},
     "expected": {"isolate_vm", "restore_from_backup", "snapshot"}},
    {"kind": "act", "label": "brute force — failed SSH from one IP (T1110.001)",
     "ttp": "T1110.001",
     "row": {"SourceIP": "185.220.101.5", "FailedAttempts": 47},
     "expected": {"block_suspicious_ip"}},
    {"kind": "act", "label": "sudo privilege escalation (T1548.003)",
     "ttp": "T1548.003",
     "row": {"SyslogMessage": "sudo: USER=root ; COMMAND=/bin/bash", "Computer": "vm-smoke"},
     "expected": {"isolate_vm"}},
    # ── ambiguous — the judgment test ──
    {"kind": "caution", "label": "account creation — few indicators (T1136.001)",
     "ttp": "T1136.001",
     "row": {"SyslogMessage": "useradd: new user: name=svc-deploy, UID=1001",
             "Computer": "vm-smoke"}},
    {"kind": "caution", "label": "sparse/vague signal — no clear TTP",
     "ttp": "",
     "row": {"Activity": "anomalous login pattern", "Computer": "vm-smoke"}},
]

_KNOWN = set(AUTONOMOUS_ACTIONS) | set(HUMAN_APPROVAL_REQUIRED) | {
    "no_action", "monitor", "escalate", "investigate"}


def _judge(sc: dict, action: str, escalate: bool) -> tuple[bool, str]:
    """Did the model show good JUDGMENT (separate from parsing correctly)?"""
    if sc["kind"] == "act":
        ok = action in sc["expected"]
        return ok, ("✓ correct action" if ok
                    else f"~ chose '{action}', expected one of {sorted(sc['expected'])}")
    # caution: must not confidently take a disruptive action
    ok = escalate or action in _NON_DISRUPTIVE
    return ok, ("✓ escalated / withheld (good caution)" if ok
                else f"✗ took disruptive '{action}' on an ambiguous signal — no escalation")


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
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat each scenario N times and aggregate — LLMs are "
                         "stochastic, so a single run is a signal, not a verdict.")
    args = ap.parse_args()
    model, runs = args.model, max(1, args.runs)

    from collections import Counter
    from glorfindel.agent import decide

    print(f"LLM smoke-test — model: {model} · runs: {runs}")
    base = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base:
        print(f"  base_url: {base}")
    print("-" * 72)

    integration = judgment = slots = 0   # over all (scenario × run) slots
    for sc in SCENARIOS:
        acts: Counter = Counter()
        valid_n = good_n = 0
        lat: list[float] = []
        for _ in range(runs):
            state = _state(sc["ttp"], {"first_result_row": sc["row"]})
            t0 = time.monotonic()
            try:
                # non_disruptive → raw decision (avoid human_only holding everything).
                out = decide(state, model=model, autonomy_override="non_disruptive")
            except Exception as e:
                acts[f"<error: {type(e).__name__}>"] += 1
                continue
            lat.append(time.monotonic() - t0)
            action = (out.get("action") or "").strip()
            if not action:
                acts["<no-tool-call>"] += 1
                continue
            valid_n += 1
            acts[action] += 1
            good, _ = _judge(sc, action, bool(out.get("escalate")))
            good_n += 1 if good else 0

        slots += runs
        integration += valid_n
        judgment += good_n
        mark = "✓" if good_n == runs else ("~" if good_n else "✗")
        dist = ", ".join(f"{a}×{n}" for a, n in acts.most_common())
        avg = f"{sum(lat) / len(lat):.1f}s avg" if lat else "—"
        print(f"{mark} [{sc['kind']:>7}] {sc['label']} — good {good_n}/{runs}  [{avg}]\n"
              f"        {dist}")

    print("-" * 72)
    print(f"Integration: {integration}/{slots} valid parsed decisions "
          f"(provider can do tool-calls).")
    print(f"Judgment   : {judgment}/{slots} good calls "
          f"(act on clear threats, stay cautious on ambiguous).")
    if integration < slots:
        print("→ A provider that can't reliably return a tool-call isn't usable for "
              "`decide` (pick a tool-capable model).")
        return 1
    if judgment < slots:
        print("→ Integration OK; judgment imperfect — over-acting on ambiguity is the "
              "usual local-model failure (see the ✗/~ above).")
    else:
        print("→ Integration + judgment OK across all runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
