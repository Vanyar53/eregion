"""palantir — the elrond journal: safeguard stops, model fallbacks, files written meanwhile."""
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / ".claude" / "skills" / "elrond" / "palantir.py"
_SPEC = importlib.util.spec_from_file_location("palantir", _PATH)
palantir = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(palantir)

PINNED = "claude-opus-5-5"
FALLBACK = "claude-opus-4-8"


def _tool(name, **inp):
    return {"type": "tool_use", "name": name, "input": inp}


def _turn(mid, model, ts, content, stop="tool_use", category=None):
    msg = {"id": mid, "model": model, "content": content, "stop_reason": stop}
    if category:
        msg["stop_details"] = {"type": "refusal", "category": category}
    return {"type": "assistant", "timestamp": ts, "message": msg}


def _write(path, entries, meta=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    if meta is not None:
        path.with_name(path.stem + ".meta.json").write_text(json.dumps(meta), encoding="utf-8")


# A worker that is stopped by safeguards, answered by another model for two responses
# (one of them split over two lines), then back on the pinned model.
WORKER = [
    _turn("m1", PINNED, "t1", [_tool("Read", file_path="lots/R1.md")]),
    _turn("m2", PINNED, "t2", [_tool("Edit", file_path="annatar/executors/base.py")]),
    _turn("m3", PINNED, "t3", [{"type": "thinking", "thinking": ""}], stop="refusal", category="cyber"),
    {"type": "system", "timestamp": "t3", "content": "Opus 5.5's safeguards stopped the response above"},
    _turn("m4", FALLBACK, "t4", [_tool("Write", file_path="annatar/executors/stratus.py")]),
    _turn("m4", FALLBACK, "t4", [_tool("Bash", command="pytest tests/unit -q")]),
    _turn("m5", FALLBACK, "t5", [_tool("Edit", file_path="annatar/executors/stratus.py")]),
    _turn("m6", PINNED, "t6", [_tool("Bash", command="git commit -m x")]),
]


@pytest.fixture
def projects(tmp_path, monkeypatch):
    root = tmp_path / "projects"
    monkeypatch.setattr(palantir, "PROJECTS", root)
    monkeypatch.setattr(palantir, "JOURNAL", tmp_path / "journal")
    monkeypatch.delenv("ELROND_JOURNAL_ALL", raising=False)
    return root


def _session(projects, worker_meta):
    main = projects / "-repo" / "s1.jsonl"
    _write(main, [_turn("a1", PINNED, "t0", [_tool("Agent", description="elrond R1 · Stratus")])])
    _write(main.with_suffix("") / "subagents" / "agent-w1.jsonl", WORKER, worker_meta)
    return main


def test_safeguard_stop_is_reported_with_the_step_in_progress(tmp_path):
    f = tmp_path / "w.jsonl"
    _write(f, WORKER)
    r = palantir.scan(f, PINNED)
    assert [(x["category"], x["during"]) for x in r["refusals"]] == [("cyber", "Edit annatar/executors/base.py")]
    assert r["notices"] and r["verdict"] == "review-needed"


def test_fallback_episode_lists_files_written_by_the_other_model(tmp_path):
    f = tmp_path / "w.jsonl"
    _write(f, WORKER)
    [ep] = palantir.scan(f, PINNED)["fallback_episodes"]
    assert ep["model"] == FALLBACK and (ep["from"], ep["to"]) == ("t4", "t5")
    assert ep["responses"] == 2  # a response split over two lines counts once
    assert ep["files"] == ["annatar/executors/stratus.py"]
    assert "Bash pytest tests/unit -q" in ep["actions"]


def test_pinned_model_only_needs_no_review(tmp_path):
    f = tmp_path / "w.jsonl"
    _write(f, [WORKER[0], WORKER[1], WORKER[-1]])
    r = palantir.scan(f, PINNED)
    assert r["verdict"] == "expected-model-only" and not r["fallback_episodes"]


def test_an_agent_not_pinned_by_elrond_keeps_its_own_model(projects):
    main = projects / "-repo" / "s1.jsonl"
    _write(main, [_turn("a1", PINNED, "t0", [])])
    other = [_turn("h1", "claude-haiku-4-5", "t1", []), _turn("h2", "claude-haiku-4-5", "t2", [])]
    _write(main.with_suffix("") / "subagents" / "agent-g1.jsonl", other, {"agentType": "claude-code-guide"})
    _, results = palantir.report(main, PINNED)
    assert all(v["verdict"] == "expected-model-only" for v in results.values())


def _hook(monkeypatch, payload):
    monkeypatch.setattr(sys, "argv", ["palantir.py", "hook"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    return palantir.main()


def test_hook_journals_a_session_that_used_elrond(projects, monkeypatch):
    main = _session(projects, {"agentType": "elrond-worker", "description": "elrond R1 · Stratus"})
    assert _hook(monkeypatch, json.dumps({"transcript_path": str(main)})) == 0
    md = (palantir.JOURNAL / "s1.md").read_text(encoding="utf-8")
    assert "elrond R1 · Stratus" in md and FALLBACK in md and "annatar/executors/stratus.py" in md


def test_hook_resolves_a_subagent_transcript_to_its_session(projects, monkeypatch):
    main = _session(projects, {"agentType": "elrond-worker", "description": "elrond R1 · Stratus"})
    sub = main.with_suffix("") / "subagents" / "agent-w1.jsonl"
    assert _hook(monkeypatch, json.dumps({"transcript_path": str(sub)})) == 0
    assert (palantir.JOURNAL / "s1.md").exists()


def test_hook_ignores_sessions_without_elrond_agents(projects, monkeypatch):
    main = _session(projects, {"agentType": "general-purpose"})
    assert _hook(monkeypatch, json.dumps({"transcript_path": str(main)})) == 0
    assert not palantir.JOURNAL.exists()
    monkeypatch.setenv("ELROND_JOURNAL_ALL", "1")
    assert _hook(monkeypatch, json.dumps({"transcript_path": str(main)})) == 0
    assert (palantir.JOURNAL / "s1.md").exists()


@pytest.mark.parametrize("payload", ["not json", "{}", json.dumps({"transcript_path": "/nowhere/x.jsonl"})])
def test_hook_never_fails_nor_writes_on_bad_input(projects, monkeypatch, payload):
    assert _hook(monkeypatch, payload) == 0
    assert not palantir.JOURNAL.exists()
