"""HY1: the suite fails when a test writes in the repository's folder.

tests/unit/conftest.py (`nothing_written_in_the_repository`) holds it. Here the guard itself is
measured: the conftest is copied into a throwaway repository (git, with a .gitignore as the
real one ignores runs/ and build/), a small test that writes where it must not runs there in
its own pytest, and that run must fail and say what was written — or pass, for what a test
run may leave (caches, an ignored folder, its tmp_path). Nothing is written in this
repository: the runs happen in tmp_path.
"""
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

# Each scenario: (files made before the run, the test, whether the run must fail, what it says).
SCENARIOS = {
    # A subprocess makes runs/ (ignored by git): only the check of the root sees it.
    "runs_by_a_subprocess": ((), """
        import subprocess, sys
        def test_it():
            subprocess.run([sys.executable, "-c", "import os; os.makedirs('runs');"
                            " open('runs/run001_debug.jsonl', 'w').write('{}')"], check=True)
        """, True, "runs (new at the root)"),
    # runs/ already there (an operator's checkout, the watch writing in it): the root looks
    # the same after the run; the audit of the test process sees the write, by its relative path.
    "runs_already_there": (("runs/.keep",), """
        from pathlib import Path
        def test_it():
            with open(Path("runs") / "run001_debug.jsonl", "a") as f:
                f.write("{}")
        """, True, "runs/run001_debug.jsonl (tests/unit/test_scenario.py::test_it)"),
    # A new file git does not ignore, made by a subprocess.
    "a_new_file_at_the_root": ((), """
        import subprocess, sys
        def test_it():
            subprocess.run([sys.executable, "-c", "open('notes.txt', 'w').write('x')"], check=True)
        """, True, "notes.txt (new at the root)"),
    # What a run may leave: its tmp_path, the caches, a folder git ignores.
    "what_a_run_may_leave": ((), """
        import os, subprocess, sys
        def test_it(tmp_path):
            (tmp_path / "out.json").write_text("{}")
            os.makedirs(".hypothesis/examples", exist_ok=True)
            open(".hypothesis/examples/x", "w").write("x")
            os.makedirs("tests/unit/__pycache__", exist_ok=True)
            open("tests/unit/__pycache__/m.pyc", "wb").write(b"")
            subprocess.run([sys.executable, "-c", "import os; os.makedirs('build/lib')"], check=True)
        """, False, ""),
}


def _repo(tmp: Path, made: tuple[str, ...], test: str) -> Path:
    repo = tmp / "repo"
    (repo / "tests" / "unit").mkdir(parents=True)
    shutil.copy(ROOT / "tests" / "unit" / "conftest.py", repo / "tests" / "unit" / "conftest.py")
    (repo / "tests" / "unit" / "test_scenario.py").write_text(textwrap.dedent(test))
    (repo / ".gitignore").write_text("runs/\nbuild/\n__pycache__/\n.pytest_cache/\n")
    for rel in made:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("")
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    return repo


def test_the_guard_fails_a_run_that_writes_in_the_repository_and_only_then(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    env["PYTHONPATH"] = str(ROOT)   # the conftest's redirections import the components
    runs = {}
    for name, (made, test, _, _) in SCENARIOS.items():   # at once: each is its own interpreter
        repo = _repo(tmp_path / name, made, test)
        runs[name] = subprocess.Popen(
            [sys.executable, "-m", "pytest", "tests/unit/test_scenario.py", "-q", "-p", "no:randomly"],
            cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    outcomes = {name: (proc.wait(timeout=180), proc.stdout.read()) for name, proc in runs.items()}
    for name, (_, _, fails, says) in SCENARIOS.items():
        code, out = outcomes[name]
        assert (code != 0) is fails, f"{name}:\n{out[-3000:]}"
        if fails:
            assert "wrote in the repository's folder" in out and says in out, f"{name}:\n{out[-3000:]}"
