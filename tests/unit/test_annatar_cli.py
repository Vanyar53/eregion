from __future__ import annotations

import click
from click.testing import CliRunner

from annatar.cli import _AnnatarCli


# ── _AnnatarCli error rendering (mirrors glorfindel's _GlorfindelCli) ───────────

def _group_raising(exc: Exception):
    @click.group(cls=_AnnatarCli)
    def g():
        pass

    @g.command()
    def boom():
        raise exc

    return g


def test_operational_error_renders_clean_not_traceback():
    """A ValueError (e.g. campaign in a terminal state) → one-liner + exit 1,
    NO raw Python traceback through click."""
    g = _group_raising(ValueError("campaign X is 'done' — re-plan to run again"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "re-plan to run again" in res.output
    assert "Traceback" not in res.output


def test_missing_creds_render_env_hint():
    g = _group_raising(RuntimeError("AZURE_SUBSCRIPTION_ID is not set"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "Traceback" not in res.output
    assert ".envrc" in res.output or "direnv" in res.output


def test_debug_env_restores_full_traceback(monkeypatch):
    """ANNATAR_DEBUG=1 re-raises so real bugs surface with a full stack."""
    monkeypatch.setenv("ANNATAR_DEBUG", "1")
    g = _group_raising(RuntimeError("kaboom"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code != 0
    assert isinstance(res.exception, RuntimeError)


def test_click_usage_errors_still_render_normally():
    """A real usage error (unknown command) keeps Click's own handling."""
    g = _group_raising(RuntimeError("unused"))
    res = CliRunner().invoke(g, ["does-not-exist"])
    assert res.exit_code != 0
    assert "No such command" in res.output
