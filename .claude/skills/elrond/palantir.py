#!/usr/bin/env python3
"""Palantir: journal of safeguard stops and model switches in Claude Code sessions.

Reads the session transcript and its subagent transcripts, and reports, per task:
which model answered, when safeguards stopped a response, and what was being done
then. It only observes: it never re-runs or rewrites anything.

The files written during a fallback episode are those of the edit tools. An episode that
ran a shell command says so (files_complete: false, with its commands): what a shell
command wrote is not knowable from the transcript, so the review reads the whole diff.

  palantir.py hook                  hook mode: JSON on stdin, rewrites the journal, silent;
                                    only sessions with elrond agents (or ELROND_JOURNAL_ALL=1)
  palantir.py session [SESSION]     report for a session (default: the latest one)
  palantir.py agent ID|TEXT [--json] verdict for one subagent (id, or text in its description)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter
from pathlib import Path

EXPECTED = os.environ.get("ELROND_MODEL", "claude-opus-5-5")
PROJECTS = Path.home() / ".claude" / "projects"
JOURNAL = Path(os.environ.get("ELROND_JOURNAL", Path.home() / ".claude" / "elrond" / "journal"))
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
# A shell command can write any file (a heredoc, `sed -i`, a redirection): what it wrote
# is not knowable from the transcript, so an episode that ran one has an incomplete list.
SHELL_TOOLS = {"Bash", "PowerShell"}


def summarize_action(block: dict) -> str:
    """One line for a tool call: tool name and its main target."""
    name = block.get("name", "?")
    inp = block.get("input") or {}
    target = (inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
              or inp.get("pattern") or inp.get("description") or inp.get("command") or "")
    target = " ".join(str(target).split())
    return f"{name} {target[:110]}".strip()


def scan(path: Path, expected: str | None) -> dict:
    """Turns, refusals and fallback episodes of one transcript.

    With no expected model, the first one seen is the baseline (agents not pinned by elrond).
    """
    seen, models = set(), Counter()
    refusals, episodes, notices = [], [], []
    last_action, episode = "", None
    for line in path.open(encoding="utf-8", errors="replace"):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        ts = o.get("timestamp", "")
        if o.get("type") == "system" and "safeguards" in str(o.get("content", "")):
            notices.append({"at": ts, "text": str(o.get("content"))[:200]})
            continue
        msg = o.get("message")
        if o.get("type") != "assistant" or not isinstance(msg, dict):
            continue
        model = msg.get("model", "")
        if model == "<synthetic>":
            continue
        # One API response may span several lines (one per content block).
        mid = msg.get("id") or o.get("uuid")
        first = mid not in seen
        seen.add(mid)
        if first and model:
            models[model] += 1
        if expected is None and model:
            expected = model
        actions = [summarize_action(b) for b in msg.get("content") or []
                   if isinstance(b, dict) and b.get("type") == "tool_use"]
        if msg.get("stop_reason") == "refusal" and first:
            det = msg.get("stop_details") or {}
            refusals.append({"at": ts, "model": model, "category": det.get("category", ""),
                             "during": last_action or "(start of task)"})
        if model and model != expected:
            if episode is None:
                episode = {"model": model, "from": ts, "to": ts, "responses": 0,
                           "after": last_action or "(start of task)", "actions": [], "files": [],
                           "files_complete": True, "commands": []}
                episodes.append(episode)
            episode["to"] = ts
            episode["responses"] += 1 if first else 0
            for b in msg.get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    episode["actions"].append(summarize_action(b))
                    fp = (b.get("input") or {}).get("file_path")
                    if b.get("name") in WRITE_TOOLS and fp and fp not in episode["files"]:
                        episode["files"].append(fp)
                    if b.get("name") in SHELL_TOOLS:
                        episode["files_complete"] = False
                        cmd = " ".join(str((b.get("input") or {}).get("command", "")).split())
                        episode["commands"].append(cmd[:300])
        elif model:
            episode = None
        if actions:
            last_action = actions[-1]
    review = bool(refusals or episodes)
    return {"file": str(path), "expected": expected, "models": dict(models), "refusals": refusals,
            "fallback_episodes": episodes, "notices": notices,
            "verdict": "review-needed" if review else "expected-model-only"}


def meta_of(agent_file: Path) -> dict:
    m = agent_file.with_name(agent_file.stem + ".meta.json")
    try:
        return json.loads(m.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def expected_for(meta: dict, expected: str) -> str | None:
    """Elrond agents are pinned to the expected model; others keep their own."""
    return expected if str(meta.get("agentType", "")).startswith("elrond-") else None


def session_paths(transcript: Path, expected: str) -> list[tuple[str, Path, str | None]]:
    """Main transcript plus every subagent transcript of the session."""
    out = [("main", transcript, expected)]
    sub = transcript.with_suffix("") / "subagents"
    for f in sorted(sub.glob("agent-*.jsonl")):
        meta = meta_of(f)
        label = meta.get("description") or meta.get("agentType") or f.stem
        out.append((f"{f.stem.removeprefix('agent-')} · {label}", f, expected_for(meta, expected)))
    return out


def has_elrond_agents(transcript: Path) -> bool:
    sub = transcript.with_suffix("") / "subagents"
    return any(str(meta_of(f).get("agentType", "")).startswith("elrond-")
               for f in sub.glob("agent-*.jsonl"))


def latest_session() -> Path | None:
    files = glob.glob(str(PROJECTS / "*" / "*.jsonl"))
    return Path(max(files, key=os.path.getmtime)) if files else None


def find_session(arg: str | None) -> Path | None:
    if not arg:
        return latest_session()
    p = Path(arg).expanduser()
    if p.is_file():
        return p
    hits = glob.glob(str(PROJECTS / "*" / f"{arg}.jsonl"))
    return Path(hits[0]) if hits else None


def find_agent(key: str) -> Path | None:
    hits = glob.glob(str(PROJECTS / "*" / "*" / "subagents" / f"agent-{key}.jsonl"))
    if hits:
        return Path(hits[0])
    # Otherwise match the description, newest first.
    metas = sorted(glob.glob(str(PROJECTS / "*" / "*" / "subagents" / "agent-*.meta.json")),
                   key=os.path.getmtime, reverse=True)
    for m in metas[:500]:
        try:
            desc = json.loads(Path(m).read_text(encoding="utf-8")).get("description", "")
        except (OSError, ValueError):
            continue
        if key.lower() in desc.lower():
            return Path(m.replace(".meta.json", ".jsonl"))
    return None


def render(label: str, r: dict) -> str:
    lines = [f"### {label}", f"- models: {r['models'] or '—'} (expected {r['expected'] or '—'})"]
    for x in r["refusals"]:
        lines.append(f"- safeguards stop at {x['at']} [{x['category'] or '?'}] on {x['model']}, "
                     f"during: {x['during']}")
    for e in r["fallback_episodes"]:
        lines.append(f"- answered by {e['model']} from {e['from']} to {e['to']} "
                     f"({e['responses']} responses), after: {e['after']}")
        if e["files"]:
            lines.append(f"  - files written then: {', '.join(e['files'])}")
        if not e.get("files_complete", True):
            lines.append(f"  - {len(e['commands'])} shell command(s) ran then: the files they wrote are not "
                         "listed — review the whole diff, starting with the files above")
    lines.append(f"- verdict: **{r['verdict']}**")
    return "\n".join(lines)


def report(transcript: Path, expected: str) -> tuple[str, dict]:
    results = {label: scan(p, exp) for label, p, exp in session_paths(transcript, expected)}
    flagged = [k for k, v in results.items() if v["verdict"] == "review-needed"]
    head = [f"# Palantir · session {transcript.stem}",
            f"{len(results)} transcripts, {len(flagged)} to review with {expected}: "
            + (", ".join(flagged) if flagged else "none"), ""]
    body = [render(k, v) for k, v in results.items()]
    return "\n".join(head) + "\n" + "\n\n".join(body) + "\n", results


def write_journal(transcript: Path, expected: str) -> Path:
    md, results = report(transcript, expected)
    JOURNAL.mkdir(parents=True, exist_ok=True)
    out = JOURNAL / f"{transcript.stem}.md"
    out.write_text(md, encoding="utf-8")
    (JOURNAL / f"{transcript.stem}.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["hook", "session", "agent"])
    ap.add_argument("key", nargs="?")
    ap.add_argument("--expect", default=EXPECTED)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.mode == "hook":
        # Never block or disturb the session: any failure is swallowed.
        try:
            data = json.load(sys.stdin)
            t = data.get("transcript_path")
            t = Path(t) if t else find_session(data.get("session_id"))
            # A subagent's own transcript path leads back to its session.
            if t and t.parent.name == "subagents":
                t = t.parent.parent.with_suffix(".jsonl")
            wanted = t and t.is_file() and (os.environ.get("ELROND_JOURNAL_ALL") or has_elrond_agents(t))
            if wanted:
                write_journal(t, a.expect)
        except Exception:
            pass
        return 0

    if a.mode == "session":
        t = find_session(a.key)
        if not t:
            print("no session transcript found", file=sys.stderr)
            return 1
        out = write_journal(t, a.expect)
        md, results = report(t, a.expect)
        print(json.dumps(results, indent=1) if a.json else md + f"\n(journal: {out})")
        return 0

    f = find_agent(a.key or "")
    if not f:
        print(f"no subagent transcript matches {a.key!r}", file=sys.stderr)
        return 1
    meta = meta_of(f)
    r = scan(f, expected_for(meta, a.expect))
    r["description"] = meta.get("description", "")
    print(json.dumps(r, indent=1) if a.json else render(f"{f.stem} · {r['description']}", r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
