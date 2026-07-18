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
    {"kind": "act", "label": "data exfiltration — upload from internal IP (T1041)",
     "ttp": "T1041",
     # RFC-1918 caller → block_suspicious_ip is useless (internal), disk intact →
     # isolate the VM to sever the exfil channel (validated action, see CLAUDE.md).
     "row": {"CallerIpAddress": "10.0.0.4", "OperationName": "PutBlob", "Computer": "vm-smoke"},
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


def _launchable_ttps() -> set[str]:
    """The TTP set Annatar can actually launch — read from the scenario YAMLs.

    The eval is 'grounded' when every launchable TTP has at least one case here,
    so coverage tracks what red really does instead of drifting on its own. Add
    an Annatar scenario → this flags the missing eval case until you add it.
    """
    import re
    from pathlib import Path

    scen_dir = Path(__file__).resolve().parent.parent / "annatar/scenarios/azure"
    ttps: set[str] = set()
    for path in sorted(scen_dir.glob("*.yaml")):
        for line in path.read_text().splitlines():
            m = re.match(r"\s*mitre:\s*(\S+)", line)
            if m:
                ttps.add(m.group(1).strip())
                break
    return ttps


def _run_one(model: str, runs: int) -> dict:
    """Run all scenarios against ONE model, print its block, return its scores."""
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
    return {"model": model, "integration": integration,
            "judgment": judgment, "slots": slots}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default=os.environ.get("GLORFINDEL_LLM_MODEL", "ollama/llama3.1"))
    ap.add_argument("--models", default="",
                    help="comma-separated list of models to compare in one go — runs "
                         "each and prints a leaderboard (e.g. "
                         "ollama/qwen3,ollama/gemma3,ollama/llama3.1).")
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat each scenario N times and aggregate — LLMs are "
                         "stochastic, so a single run is a signal, not a verdict.")
    args = ap.parse_args()
    runs = max(1, args.runs)
    models = [m.strip() for m in args.models.split(",") if m.strip()] or [args.model]

    # Ground-truth coverage: does the eval cover every TTP Annatar can launch?
    covered = {sc["ttp"] for sc in SCENARIOS if sc["ttp"]}
    launchable = _launchable_ttps()
    if launchable:
        missing = sorted(launchable - covered)
        line = f"Ground truth: {len(launchable & covered)}/{len(launchable)} Annatar-launchable TTPs covered"
        line += f" — ⚠ no eval case for: {', '.join(missing)}" if missing else " ✓"
        print(line)
        print("=" * 72)

    results = []
    for i, model in enumerate(models):
        if i:
            print("\n" + "=" * 72 + "\n")
        results.append(_run_one(model, runs))

    if len(results) > 1:
        print("\n" + "=" * 72)
        print("LEADERBOARD — best judgment first (ties broken by integration)")
        print("-" * 72)
        print(f"{'model':<30} {'integration':>12} {'judgment':>12}")
        for r in sorted(results, key=lambda r: (r["judgment"], r["integration"]),
                        reverse=True):
            print(f"{r['model']:<30} {r['integration']:>7}/{r['slots']:<4} "
                  f"{r['judgment']:>7}/{r['slots']:<4}")
        print("=" * 72)

    # Exit non-zero if ANY model can't reliably return a tool-call (unusable for decide).
    if any(r["integration"] < r["slots"] for r in results):
        print("→ At least one provider can't reliably return a tool-call — not usable "
              "for `decide` (pick a tool-capable model).")
        return 1
    if any(r["judgment"] < r["slots"] for r in results):
        print("→ Integration OK; judgment imperfect on some models — over-acting on "
              "ambiguity is the usual local-model failure (see the ✗/~ above).")
    else:
        print("→ Integration + judgment OK across all runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
