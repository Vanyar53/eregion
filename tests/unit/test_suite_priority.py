"""NICE1 (#620): the suite yields the CPU on a workstation, never in CI (tests/unit/conftest.py,
`pytest_configure`).

Sub-agents run it side by side in their worktrees; at full priority, on 06/11, the WSL starved
VS Code until it killed its extension host seven times in a day. The hook is measured on a
fake `os.nice` that behaves as the kernel's for an unprivileged process (capped at 19, never
lowered), so a run's own niceness does not hide a defect; one real run says the hook is wired.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROBE = "EREGION_NICENESS_PROBE"


class _Niceness:
    """os.nice for an unprivileged process: an increment, capped at 19; lowering refused."""

    def __init__(self, value):
        self.value = value

    def __call__(self, increment):
        if increment < 0:
            raise PermissionError(1, "Operation not permitted")
        self.value = min(19, self.value + increment)
        return self.value


@pytest.fixture
def configure(request):
    return request.config.pluginmanager.get_plugin(
        str(Path(__file__).with_name("conftest.py"))).pytest_configure


def _run(configure, monkeypatch, start, ci=None):
    niceness = _Niceness(start)
    monkeypatch.setattr(os, "nice", niceness)
    if ci is None:
        monkeypatch.delenv("CI", raising=False)
    else:
        monkeypatch.setenv("CI", ci)
    configure(None)
    return niceness.value


@pytest.mark.parametrize("start", [0, 3, 9])
def test_a_local_run_rises_to_ten(configure, monkeypatch, start):
    assert _run(configure, monkeypatch, start) == 10


@pytest.mark.parametrize("start", [10, 15, 19])
def test_a_run_already_at_ten_or_lower_in_priority_keeps_it(configure, monkeypatch, start):
    """xdist's workers and the mutants' runs inherit 10: nothing is added on top."""
    assert _run(configure, monkeypatch, start) == start


def test_a_ci_run_keeps_the_priority_it_was_given(configure, monkeypatch):
    assert _run(configure, monkeypatch, 0, ci="true") == 0


def test_a_refused_change_never_fails_the_run(configure, monkeypatch):
    def refused(increment):
        raise OSError(1, "Operation not permitted")
    monkeypatch.setattr(os, "nice", refused)
    monkeypatch.delenv("CI", raising=False)
    configure(None)


@pytest.mark.skipif(PROBE not in os.environ, reason="runs only in its own pytest, below")
def test_probe():
    Path(os.environ[PROBE]).write_text(str(os.nice(0)))


@pytest.mark.skipif(not hasattr(os, "nice"), reason="no niceness on this platform")
def test_a_real_local_run_is_at_ten_or_lower_in_priority(tmp_path):
    out = tmp_path / "niceness"
    env = {k: v for k, v in os.environ.items() if k != "CI" and not k.startswith("PYTEST_XDIST")}
    env[PROBE] = str(out)
    subprocess.run(
        [sys.executable, "-m", "pytest", f"{__file__}::test_probe", "-q",
         "-p", "no:cacheprovider", "-o", "addopts="],
        cwd=ROOT, env=env, check=True, capture_output=True, timeout=120,
    )
    assert int(out.read_text()) >= 10
