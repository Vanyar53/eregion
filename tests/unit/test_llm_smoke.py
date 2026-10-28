"""D-1 — the harness publishes what each case drew, not only how many calls were good.

scripts/llm_smoke.py runs the real decide() against a real provider; here decide() is
replaced, so what is checked is the harness itself: the paired cases are written as
pairs (same row, only the incident differs, an expectation for each), and the
distribution, the stability and the pair verdict say what the draws were.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SMOKE = Path(__file__).resolve().parents[2] / "scripts" / "llm_smoke.py"


@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("llm_smoke", SMOKE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _slot(action, conf=0.9, held_by="", good=True, temperature=0.0):
    return {"action": action, "confidence": conf, "escalate": bool(held_by),
            "held_by": held_by, "good": good, "temperature": temperature}


def test_the_paired_cases_differ_only_by_the_incident_and_say_what_they_expect(smoke):
    pairs: dict[str, list[dict]] = {}
    for sc in smoke.SCENARIOS:
        if sc.get("pair"):
            pairs.setdefault(sc["pair"], []).append(sc)
    members = pairs["brute force"]
    assert len(members) == 2 and all(m["kind"] == "paired" for m in members)
    alone, after = members
    assert alone["row"] == after["row"] and alone["ttp"] == after["ttp"] == "T1110.001"
    assert not alone.get("incident")
    assert "T1548.003" in after["incident"]["ttps"] and after["incident"]["signals_count"] > 1
    assert alone["expected"] == {"block_suspicious_ip"}
    assert after["expected"] == {"isolate_vm"}


def test_the_incident_reaches_the_models_message(smoke):
    """The pair's context is what the model reads (_build_user_message)."""
    from glorfindel.agent import _build_user_message
    after = next(sc for sc in smoke.SCENARIOS if sc.get("incident"))
    state = smoke._state(after["ttp"], {"first_result_row": after["row"]}, None, after["incident"])
    msg = _build_user_message(state["signal"], state["past_cycles"], state["incident"])
    assert "Incident en cours sur cette ressource" in msg and "T1548.003" in msg


def test_the_distribution_shows_actions_confidences_and_holds(smoke):
    slots = [_slot("isolate_vm", 0.78), _slot("isolate_vm", 0.85), _slot("isolate_vm", 0.80),
             _slot("block_suspicious_ip", 0.80, held_by="agreement")]
    assert smoke._distribution(slots) == (
        "isolate_vm×3 (0.78–0.85, med 0.80) · block_suspicious_ip×1 (0.80) — held: agreement×1")
    assert smoke._distribution([{"action": "<no-tool-call>", "confidence": None}]) == "<no-tool-call>×1 (—)"
    assert smoke._stable(slots) is False and smoke._stable(slots[:3]) is True


def test_the_pair_verdict_says_whether_the_context_moved_the_decision(smoke):
    alone = {"pair": "bf", "expected": ["block_suspicious_ip"], "incident": None,
             "slots": [_slot("block_suspicious_ip")] * 3}
    after = {"pair": "bf", "expected": ["isolate_vm"],
             "incident": {"ttps": ["T1548.003", "T1110.001"]},
             "slots": [_slot("isolate_vm"), _slot("block_suspicious_ip", good=False)]}
    line = smoke._pair_lines([alone, after])[0]
    assert "alone → block_suspicious_ip×3 (expected block_suspicious_ip) ✓" in line
    assert "after T1548.003 → T1110.001 → isolate_vm×1, block_suspicious_ip×1" in line
    assert line.endswith("the context moves the decision")
    same = dict(after, slots=[_slot("block_suspicious_ip", good=False)])
    assert smoke._pair_lines([alone, same])[0].endswith("the context does not move the decision")
    # Measured 26/10 on claude-sonnet-5-5: alone, block 5/5; after root, block 3, isolate 2.
    split = dict(after, slots=[_slot("block_suspicious_ip", good=False)] * 3 + [_slot("isolate_vm")] * 2)
    assert smoke._pair_lines([alone, split])[0].endswith(
        "the context makes the decision unstable (most frequent: block_suspicious_ip)")


def test_the_sampling_line_says_whether_the_draw_was_fixed(smoke):
    assert smoke._temperature_line([_slot("x", temperature=0.0)]) == "temperature 0 (fixed)"
    assert "refuses a temperature" in smoke._temperature_line([_slot("x", temperature=None)])


def test_a_run_publishes_each_cases_draws(smoke, monkeypatch, capsys):
    """Two runs of the paired cases: the block prints each case's distribution, the
    stability and the pair verdict, and returns every draw."""
    import glorfindel.agent as agent
    answers = iter([
        {"action": "block_suspicious_ip", "confidence": 0.80, "escalate": False},
        {"action": "block_suspicious_ip", "confidence": 0.82, "escalate": False},
        {"action": "isolate_vm", "confidence": 0.78, "escalate": False},
        {"action": "block_suspicious_ip", "confidence": 0.80, "escalate": True,
         "held_by": "agreement"},
    ])

    def fake_decide(state, **_kw):
        return {**next(answers), "decision_temperature": None, "decision_draws": []}
    monkeypatch.setattr(agent, "decide", fake_decide)
    res = smoke._run_one("anthropic/claude-test", 2, {"paired"})
    out = capsys.readouterr().out
    assert "block_suspicious_ip×2 (0.80–0.82, med 0.81)" in out
    assert "block_suspicious_ip×1 (0.80) · isolate_vm×1 (0.78) — held: agreement×1" in out
    assert "Stability  : 1/2 cases" in out
    assert "the model's default sampling" in out
    assert "the context moves the decision" in out
    assert [len(c["slots"]) for c in res["cases"]] == [2, 2]


def test_the_attestation_names_its_lock_and_each_models_result(smoke, tmp_path):
    """H1: the CD of H0 deploys a new lock only with the harness's attestation for it."""
    import hashlib
    lock = tmp_path / "glorfindel.txt"
    lock.write_text("litellm==1.86.1 \\\n    --hash=sha256:00\n")
    results = [{"model": "anthropic/claude-sonnet-5-5", "integration": 24, "judgment": 24, "slots": 24, "overconf": 0},
               {"model": "ollama/qwen3", "integration": 24, "judgment": 19, "slots": 24, "overconf": 3}]
    att = smoke.attestation(results, 3, lock)
    assert att["lock"] == "requirements/glorfindel.txt" and att["runs"] == 3
    assert att["lock_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    assert att["models"][1] == {"model": "ollama/qwen3", "integration": 24, "judgment": 19,
                                "slots": 24, "overconfident_errors": 3}
