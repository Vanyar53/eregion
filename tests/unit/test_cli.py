from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from glorfindel.cli import _GlorfindelCli, _resolve_resource_id


# ── _resolve_resource_id ───────────────────────────────────────────────────────

_FULL = (
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute"
    "/virtualMachines/vm-x"
)


def test_resolve_short_name_via_active_state(monkeypatch):
    """A bare VM name (what `list`/War Room show) resolves to the full ARM id from the
    active block state — the bug behind 'Nothing to reset' on a VM that IS blocked."""
    monkeypatch.setattr("glorfindel.actions.active_isolations", lambda: [])
    monkeypatch.setattr(
        "glorfindel.actions.active_blocks",
        lambda: [{"resource_id": _FULL, "ip": "1.2.3.4"}],
    )
    assert _resolve_resource_id("vm-x") == _FULL
    assert _resolve_resource_id("VM-X") == _FULL  # case-insensitive


def test_resolve_short_name_via_isolation_state(monkeypatch):
    monkeypatch.setattr(
        "glorfindel.actions.active_isolations",
        lambda: [{"resource_id": _FULL}],
    )
    monkeypatch.setattr("glorfindel.actions.active_blocks", lambda: [])
    assert _resolve_resource_id("vm-x") == _FULL


def test_resolve_full_id_passes_through_without_touching_state(monkeypatch):
    """A full ARM id is returned as-is and must NOT read the state dir."""
    def _boom():
        raise AssertionError("active state must not be read for a full id")
    monkeypatch.setattr("glorfindel.actions.active_isolations", _boom)
    monkeypatch.setattr("glorfindel.actions.active_blocks", _boom)
    assert _resolve_resource_id(_FULL) == _FULL


def test_resolve_unknown_name_passes_through(monkeypatch):
    """An unknown bare name is returned unchanged — the command reports 'nothing to
    do' rather than crashing on an unresolvable name."""
    monkeypatch.setattr("glorfindel.actions.active_isolations", lambda: [])
    monkeypatch.setattr("glorfindel.actions.active_blocks", lambda: [])
    assert _resolve_resource_id("ghost") == "ghost"


# ── _GlorfindelCli error rendering ─────────────────────────────────────────────

def _group_raising(exc: Exception):
    @click.group(cls=_GlorfindelCli)
    def g():
        pass

    @g.command()
    def boom():
        raise exc

    return g


def test_missing_creds_render_clean_not_traceback():
    """RuntimeError('AZURE_SUBSCRIPTION_ID is not set') → one-liner + env hint, exit 1,
    NO 20-line traceback (Jonathan's 'jolie stack trace' complaint)."""
    g = _group_raising(RuntimeError("AZURE_SUBSCRIPTION_ID is not set"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "AZURE_SUBSCRIPTION_ID is not set" in res.output
    assert "Traceback" not in res.output
    assert ".envrc" in res.output or "direnv" in res.output  # actionable hint


def test_permission_error_renders_container_hint():
    g = _group_raising(
        PermissionError(13, "Permission denied", "/home/u/.glorfindel/blocks/x.json")
    )
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "Traceback" not in res.output
    assert "container" in res.output  # points at the root-owned-state cause


def test_debug_env_restores_full_traceback(monkeypatch):
    """GLORFINDEL_DEBUG=1 re-raises so real bugs surface with a full stack."""
    monkeypatch.setenv("GLORFINDEL_DEBUG", "1")
    g = _group_raising(RuntimeError("kaboom"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code != 0
    assert isinstance(res.exception, RuntimeError)


def test_click_usage_errors_still_render_normally():
    """A real usage error (unknown command) must keep Click's own handling, not be
    swallowed by the operational-error wrapper."""
    g = _group_raising(RuntimeError("unused"))
    res = CliRunner().invoke(g, ["does-not-exist"])
    assert res.exit_code != 0
    assert "No such command" in res.output
