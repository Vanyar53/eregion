"""D-1 — the harness publishes what each case drew, not only how many calls were good.

scripts/llm_smoke.py runs the real decide() against a real provider; here decide() is
replaced, so what is checked is the harness itself: the paired cases are written as
pairs (same row, only the incident differs, an expectation for each), and the
distribution, the stability and the pair verdict say what the draws were.
"""
from __future__ import annotations

import importlib.util
import os
import sys
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


# ── The attestation: two passes, every case's draws (H1, H3) ────────────────────────

MODEL = "anthropic/claude-sonnet-5-5"


def _result(model, cases):
    """What _run_one returns, with what a real draw carries besides (the decision's own draws,
    their reasoning): none of it may reach the attestation."""
    def slot(good, action, conf):
        return {"action": action, "confidence": conf, "escalate": False, "held_by": "", "good": good,
                "temperature": None, "draws": [{"reasoning": "LOG LINE root@vm-smoke"}]}
    out = [{"label": lb, "kind": k, "pair": "", "expected": [], "incident": None,
            "slots": [slot(*d) for d in draws]} for lb, k, draws in cases]
    every = [s for c in out for s in c["slots"]]
    return {"model": model, "integration": sum(not s["action"].startswith("<") for s in every),
            "judgment": sum(s["good"] for s in every), "slots": len(every),
            "overconf": sum(not s["good"] and (s["confidence"] or 0) >= 0.7 for s in every), "cases": out}


RIGHT = (True, "isolate_vm", 0.85)
CASES_OK = [("ransomware — sustained disk write (T1486)", "act", [RIGHT] * 3),
            ("brute force — after root (pair 2/2)", "paired", [RIGHT] * 3)]


def test_a_pass_keeps_each_cases_draws_and_nothing_of_the_logs(smoke, tmp_path):
    import hashlib
    import json
    lock = tmp_path / "glorfindel.txt"
    lock.write_text("litellm==1.86.1 \\\n    --hash=sha256:00\n")
    draws = [RIGHT, RIGHT, (False, "block_suspicious_ip", 0.8)]
    p = smoke.harness_pass([_result("m/a", [("bf", "paired", draws)])], 3, lock, "v0.4.5")
    assert p["schema"] == smoke.PASS_SCHEMA and p["ref"] == "v0.4.5" and p["runs"] == 3 and p["kinds"] == "all"
    assert p["lock_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    (m,) = p["models"]
    assert (m["integration"], m["judgment"], m["slots"], m["overconfident_errors"]) == (3, 2, 3, 1)
    assert m["cases"] == [{"label": "bf", "kind": "paired", "draws": [
        {"good": True, "action": "isolate_vm", "confidence": 0.85},
        {"good": True, "action": "isolate_vm", "confidence": 0.85},
        {"good": False, "action": "block_suspicious_ip", "confidence": 0.8}]}]
    assert "LOG LINE" not in json.dumps(p) and "reasoning" not in json.dumps(p)
    att = smoke.attestation(p, p)
    assert att["schema"] == smoke.ATTESTATION_SCHEMA and att["candidate"] is p and att["reference"] is p
    assert smoke.harness_pass([_result("m/a", CASES_OK)], 3, lock, kinds={"paired"})["kinds"] == ["paired"]


def _main(smoke, monkeypatch, argv, result):
    import sys
    calls = []
    monkeypatch.setattr(smoke, "_launchable_ttps", lambda: set())
    monkeypatch.setattr(smoke, "_run_one", lambda model, runs, kinds: calls.append(model) or result(model))
    monkeypatch.setattr(sys, "argv", ["llm_smoke.py", *argv])
    return smoke.main(), calls


def test_the_harness_writes_both_passes_into_one_attestation(smoke, monkeypatch, tmp_path):
    """H3: the reference pass on the lock in service (--lock, --pass-out), then the candidate on
    this checkout's lock with --reference: the attestation holds both, each with its sha256."""
    import hashlib
    import json
    ref_lock, ref_pass, out = tmp_path / "ref.txt", tmp_path / "reference.json", tmp_path / "harness.json"
    ref_lock.write_text("litellm==1.86.1\n")
    code, _ = _main(smoke, monkeypatch, ["--models", MODEL, "--runs", "3", "--lock", str(ref_lock), "--ref", "v0.4.5",
                                         "--pass-out", str(ref_pass)], lambda m: _result(m, CASES_OK))
    assert code == 0 and not out.exists()
    shaky = [CASES_OK[0], ("brute force — after root (pair 2/2)", "paired",
                           [RIGHT, RIGHT, (False, "block_suspicious_ip", 0.8)])]
    code, calls = _main(smoke, monkeypatch, ["--models", MODEL, "--runs", "3", "--reference", str(ref_pass),
                                             "--attest", str(out)], lambda m: _result(m, shaky))
    assert code == 0 and calls == [MODEL]
    att = json.loads(out.read_text(encoding="utf-8"))
    assert att["schema"] == "eregion.harness/2"
    assert att["reference"]["lock_sha256"] == hashlib.sha256(ref_lock.read_bytes()).hexdigest()
    assert att["reference"]["ref"] == "v0.4.5"
    mine = (ROOT / "requirements" / "glorfindel.txt").read_bytes()
    assert att["candidate"]["lock_sha256"] == hashlib.sha256(mine).hexdigest()
    cand = att["candidate"]["models"][0]["cases"][1]["draws"]
    assert [d["good"] for d in cand] == [True, True, False] and cand[2]["confidence"] == 0.8
    assert [d["good"] for d in att["reference"]["models"][0]["cases"][1]["draws"]] == [True] * 3


def test_make_llm_compare_attest_writes_the_attestation_without_json(smoke, monkeypatch, tmp_path):
    """DEP1: `make llm-compare ATTEST=1` passes --attest without --json. A `from pathlib import
    Path` in main's --json branch made Path local to main, and the attestation of a paid run
    was lost to an UnboundLocalError at its very end (measured on 29/10, 51/51)."""
    import json
    lock, ref = tmp_path / "ref.txt", tmp_path / "reference.json"
    lock.write_text("x\n")
    ref.write_text(json.dumps(smoke.harness_pass([_result(MODEL, CASES_OK)], 3, lock)))
    out = tmp_path / "harness.json"
    code, _ = _main(smoke, monkeypatch, ["--models", MODEL, "--runs", "3", "--reference", str(ref),
                                         "--attest", str(out)], lambda m: _result(m, CASES_OK))
    assert code == 0
    att = json.loads(out.read_text(encoding="utf-8"))
    assert att["candidate"]["runs"] == 3 and att["candidate"]["models"][0]["model"] == MODEL


def test_an_attestation_without_its_reference_runs_nothing(smoke, monkeypatch, tmp_path):
    """No paid call for an attestation the CD would refuse."""
    out = tmp_path / "harness.json"
    code, calls = _main(smoke, monkeypatch, ["--models", "m/a", "--runs", "3", "--attest", str(out)],
                        lambda m: _result(m, CASES_OK))
    assert (code, calls) == (2, []) and not out.exists()


def test_a_reference_that_does_not_match_runs_nothing(smoke, monkeypatch, tmp_path):
    import json
    lock, ref = tmp_path / "ref.txt", tmp_path / "reference.json"
    lock.write_text("x\n")
    out = tmp_path / "harness.json"
    for written, argv in ((smoke.harness_pass([_result("m/a", CASES_OK)], 5, lock), ["--models", "m/a"]),
                          (smoke.harness_pass([_result("m/a", CASES_OK)], 3, lock), ["--models", "m/b"]),
                          ({"models": []}, ["--models", "m/a"])):
        ref.write_text(json.dumps(written))
        code, calls = _main(smoke, monkeypatch, [*argv, "--runs", "3", "--reference", str(ref), "--attest", str(out)],
                            lambda m: _result(m, CASES_OK))
        assert (code, calls) == (2, []) and not out.exists()


# DEP1 (#282), in H3's format: a committed attestation that no longer matches the lock fails
# here, in CI, not at H0's CD. Without the file, nothing to check.
ROOT = SMOKE.parents[1]


def _attestation_problems(att_path: Path, lock_path: Path, model: str, repo: Path = ROOT) -> list[str]:
    import hashlib
    import json
    import subprocess
    if not att_path.is_file():
        return []
    att = json.loads(att_path.read_text(encoding="utf-8"))
    if att.get("schema") != "eregion.harness/2":
        return [f"{att_path.name} à l'ancien format (sans la référence) : make llm-compare … ATTEST=1 (H3)"]
    cand, ref = att.get("candidate") or {}, att.get("reference") or {}
    problems = []
    if cand.get("lock_sha256") != hashlib.sha256(lock_path.read_bytes()).hexdigest():
        problems.append(f"{att_path.name} porte sur un autre {lock_path.name} : make llm-compare … ATTEST=1")
    if not ref:
        problems.append(f"{att_path.name} sans référence (le verrou en service)")
    for side, p in (("candidat", cand), ("référence", ref)):
        if model not in [m.get("model") for m in p.get("models") or []]:
            problems.append(f"{att_path.name} : le passage {side} ne couvre pas le modèle par défaut ({model})")
    # The reference carries its release's lock, when the checkout has the tag (in CI, often not).
    tag = ref.get("ref")
    shown = subprocess.run(["git", "show", f"{tag}:requirements/glorfindel.txt"], cwd=repo,
                           capture_output=True, check=False) if tag else None
    if shown is not None and shown.returncode == 0 and \
            ref.get("lock_sha256") != hashlib.sha256(shown.stdout).hexdigest():
        problems.append(f"{att_path.name} : la référence ne porte pas le verrou de {tag}")
    return problems


def test_the_committed_attestation_is_the_locks_and_covers_the_default_model():
    from eregion_core.models import DEFAULT_LLM_MODEL
    assert _attestation_problems(ROOT / "requirements" / "harness.json",
                                 ROOT / "requirements" / "glorfindel.txt", DEFAULT_LLM_MODEL) == []


def test_a_stale_partial_or_old_attestation_is_refused_and_none_passes(smoke, tmp_path):
    import json
    lock, ref_lock, att = tmp_path / "glorfindel.txt", tmp_path / "ref.txt", tmp_path / "harness.json"
    lock.write_text("litellm==1.100.4 \\\n    --hash=sha256:00\n")
    ref_lock.write_text("litellm==1.86.1\n")
    assert _attestation_problems(att, lock, "m/a", tmp_path) == [], "no attestation yet: nothing to check"
    cand = smoke.harness_pass([_result("m/a", CASES_OK)], 3, lock)
    ref = smoke.harness_pass([_result("m/a", CASES_OK)], 3, ref_lock, "v0.4.5")
    att.write_text(json.dumps(smoke.attestation(cand, ref)))
    assert _attestation_problems(att, lock, "m/a", tmp_path) == []
    assert len(_attestation_problems(att, lock, "m/b", tmp_path)) == 2, "another model than the default, both sides"
    att.write_text(json.dumps(smoke.attestation(cand, None)))
    assert any("sans référence" in p for p in _attestation_problems(att, lock, "m/a", tmp_path))
    att.write_text(json.dumps({"lock_sha256": cand["lock_sha256"], "runs": 3, "models": [{"model": "m/a"}]}))
    assert "ancien format" in _attestation_problems(att, lock, "m/a", tmp_path)[0]
    att.write_text(json.dumps(smoke.attestation(cand, ref)))
    lock.write_text("litellm==1.100.5 \\\n    --hash=sha256:00\n")
    assert len(_attestation_problems(att, lock, "m/a", tmp_path)) == 1, "the lock moved after the harness"


def _repo_with_tag(tmp_path, tag, lock_text):
    import subprocess
    repo = tmp_path / "repo"
    (repo / "requirements").mkdir(parents=True)
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(tmp_path),
           "PATH": "/usr/bin:/bin", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    (repo / "requirements" / "glorfindel.txt").write_text(lock_text)
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "c"], ["tag", tag]):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)
    return repo


def test_the_reference_must_carry_its_releases_lock(smoke, tmp_path):
    import json
    repo = _repo_with_tag(tmp_path, "v0.4.5", "litellm==1.86.1\n")
    lock, att = tmp_path / "glorfindel.txt", tmp_path / "harness.json"
    lock.write_text("litellm==1.100.4\n")
    cand = smoke.harness_pass([_result("m/a", CASES_OK)], 3, lock)
    good = smoke.harness_pass([_result("m/a", CASES_OK)], 3, repo / "requirements" / "glorfindel.txt", "v0.4.5")
    att.write_text(json.dumps(smoke.attestation(cand, good)))
    assert _attestation_problems(att, lock, "m/a", repo) == []
    other = tmp_path / "other.txt"
    other.write_text("litellm==1.80.0\n")
    bad = smoke.harness_pass([_result("m/a", CASES_OK)], 3, other, "v0.4.5")
    att.write_text(json.dumps(smoke.attestation(cand, bad)))
    assert "verrou de v0.4.5" in _attestation_problems(att, lock, "m/a", repo)[0]


# ── make llm-compare … ATTEST=1: the two passes, run in order (scripts/harness_attest.py) ─

@pytest.fixture
def attest():
    spec = importlib.util.spec_from_file_location("harness_attest", ROOT / "scripts" / "harness_attest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_a_venv_that_does_not_follow_the_lock_is_said_before_any_call(attest):
    lock = ("litellm==1.100.4 \\\n    --hash=sha256:00\nanthropic==2.3.0 \\\n"
            "colorama==0.4.6 ; sys_platform == 'win32' \\\nBad_Name.x==1.0\n")
    assert attest.drift(lock, {"litellm": "1.100.4", "anthropic": "2.3.0", "bad-name-x": "1.0"}) == []
    assert attest.drift(lock, {"litellm": "1.86.1", "anthropic": "2.3.0"}) == [
        "litellm: 1.86.1 ≠ 1.100.4", "bad-name-x: absent ≠ 1.0"]


def test_attest_runs_the_reference_then_the_candidate_and_never_in_the_repo(attest, monkeypatch, tmp_path):
    runs = []

    class Done:
        returncode = 0
    monkeypatch.setattr(attest, "drift", lambda text: [])
    monkeypatch.setattr(attest, "reference_tag", lambda base, fetch=True: base or "v0.4.5")
    monkeypatch.setattr(attest, "reference_lock", lambda tag: b"litellm==1.86.1\n")
    venv = tmp_path / "venv"
    monkeypatch.setattr(attest, "reference_venv", lambda lock, cache: (venv / "bin" / "python", venv / "glorfindel.txt"))

    def run(cmd, **kw):
        runs.append((cmd, kw.get("env", {}).get("PYTHONPATH", "")))
        if "--pass-out" in cmd:
            Path(cmd[cmd.index("--pass-out") + 1]).write_text("{}")
        return Done()
    monkeypatch.setattr(attest.subprocess, "run", run)
    out = tmp_path / "harness.json"
    assert attest.main(["--models", MODEL, "--runs", "3", "--cache", str(tmp_path / "c"), "--out", str(out)]) == 0
    (ref, ref_path), (cand, _) = runs
    assert ref[0] == str(venv / "bin" / "python") and str(ROOT) in ref_path.split(os.pathsep)
    assert ref[ref.index("--lock") + 1] == str(venv / "glorfindel.txt") and "--ref" in ref and "--attest" not in ref
    assert cand[0] == sys.executable and cand[cand.index("--attest") + 1] == str(out)
    assert cand[cand.index("--reference") + 1] == ref[ref.index("--pass-out") + 1]
    # Fewer than 3 runs, or the same lock as the reference: nothing run, nothing paid.
    runs.clear()
    assert attest.main(["--models", MODEL, "--runs", "1"]) == 2 and runs == []
    monkeypatch.setattr(attest, "reference_lock", lambda tag: (ROOT / "requirements" / "glorfindel.txt").read_bytes())
    assert attest.main(["--models", MODEL, "--runs", "3", "--cache", str(tmp_path / "c")]) == 0 and runs == []


def test_attest_stops_when_the_venv_does_not_follow_the_lock(attest, monkeypatch, capsys):
    monkeypatch.setattr(attest, "drift", lambda text: ["litellm: 1.86.1 ≠ 1.100.4"])
    monkeypatch.setattr(attest, "reference_tag", lambda *a, **k: pytest.fail("nothing past the drift"))
    assert attest.main(["--models", MODEL, "--runs", "3"]) == 2
    assert "make install" in capsys.readouterr().out


def test_the_reference_venv_is_installed_once_per_lock_with_hashes(attest, monkeypatch, tmp_path):
    calls = []

    def run(cmd, check=False):
        calls.append(cmd)
        if cmd[1:3] == ["-m", "venv"]:
            (Path(cmd[3]) / "bin").mkdir(parents=True)
            (Path(cmd[3]) / "bin" / "python").write_text("")
    monkeypatch.setattr(attest.subprocess, "run", run)
    py, lock = attest.reference_venv(b"litellm==1.86.1\n", tmp_path)
    assert lock.read_bytes() == b"litellm==1.86.1\n" and py.parent.parent.parent == tmp_path
    assert ["--require-hashes", "-r", str(lock)] == calls[-1][-3:]
    calls.clear()
    assert attest.reference_venv(b"litellm==1.86.1\n", tmp_path) == (py, lock) and calls == []
    with pytest.raises(SystemExit, match="dans le dépôt"):
        attest.reference_venv(b"x", ROOT / ".cache-harness")
    assert calls == [] and not (ROOT / ".cache-harness").exists()


def test_the_reference_is_the_latest_release_tag_or_base(attest, monkeypatch, tmp_path):
    repo = _repo_with_tag(tmp_path, "v0.4.5", "litellm==1.86.1\n")
    import subprocess
    for t in ("v0.4.10", "v0.5.0-rc1", "vnext"):
        subprocess.run(["git", "tag", t], cwd=repo, check=True, capture_output=True)
    monkeypatch.setattr(attest, "REPO", repo)
    assert attest.reference_tag("", fetch=False) == "v0.4.10"
    assert attest.reference_tag("v0.4.5", fetch=False) == "v0.4.5"
    assert attest.reference_lock("v0.4.5") == b"litellm==1.86.1\n"
    with pytest.raises(SystemExit, match="introuvable"):
        attest.reference_tag("v9.9.9", fetch=False)


def test_make_llm_compare_attest_runs_both_passes():
    import shutil
    import subprocess
    if shutil.which("make") is None:
        pytest.skip("make not installed")

    def dry(*args):
        return subprocess.run(["make", "-n", "--no-print-directory", "-C", str(ROOT), "llm-compare", *args],
                              capture_output=True, text=True, timeout=60).stdout
    attest = dry("MODELS=m/a", "ATTEST=1", "BASE=v0.4.5")
    assert "scripts/harness_attest.py --models m/a --runs 3 --base v0.4.5 --out requirements/harness.json" in attest
    plain = dry("MODELS=m/a")
    assert "scripts/llm_smoke.py --models m/a --runs 3" in plain and "attest" not in plain
