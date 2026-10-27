"""IA1 harness — the triage's analysis cases against a real model.

    python scripts/analysis_eval.py [--model anthropic/claude-haiku-5-5] [--runs 3] [--only planted]

The cases are analysis/triage_cases.py: a missed technique without a rule, one whose log
source the infrastructure code does not collect, one with both a rule and its source, an
escalation sorted after a miss, and a planted line (in a rule's description and in
Glorfindel's reasoning) that asks for a rule and an approval. Per case and run: the computed
triage (the code's part), the useful proposals kept (the model's), the entries the check
removed, whether the model obeyed the planted line, whether every proposal waits for a human,
and whether anything but the triage was written. The same cases run in the unit tests with a
simulated model (tests/unit/test_analysis_triage.py). No Azure; the model is called for real
(a few cents) — never Glorfindel's model (analysis/separation.py).
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis import triage_cases as tc  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", default=None)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--only", default="", help="comma-separated case names")
    a = ap.parse_args()
    cases = [c for c in tc.CASES if not a.only or c.name in a.only.split(",")]
    failed, model = 0, ""
    totals = {"useful": 0, "expected": 0, "rejected": 0, "obeyed": 0}
    for i in range(a.runs):
        print(f"── run {i + 1}")
        for case in cases:
            with tempfile.TemporaryDirectory() as tmp:
                r = tc.run(case, Path(tmp), model=a.model)
            model = r.model or model
            print("  " + r.line())
            for d in r.detail:
                print(f"      {d}")
            failed += not (r.causes and r.pending and r.untouched)
            totals["useful"] += r.useful
            totals["expected"] += r.expected_useful
            totals["rejected"] += r.rejected
            totals["obeyed"] += r.obeyed
    print(f"\n{model}: useful {totals['useful']}/{totals['expected']} · rejected {totals['rejected']} · "
          f"obeyed the planted line {totals['obeyed']} — the triage itself never keeps a rule nor "
          "an approval (the check); every proposal waits for a human.")
    if failed:
        print(f"{failed} case run(s) where the code's part failed (causes, pending or untouched).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
