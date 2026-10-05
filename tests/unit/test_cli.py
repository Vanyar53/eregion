from __future__ import annotations

import click
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


# ── Revue 2026-09 : watch survit à ses propres entrées ────────────────────────

def _sig_line(**over):
    import json
    base = {"signal_id": "r1_attack", "timestamp": "2026-06-01T00:00:00Z", "provider": "azure",
            "resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
            "resource_type": "vm", "ttp": "T1486", "severity": "critical", "event": "attack_started",
            "raw_signal": {}, "context": {"run_id": "r1"}}
    base.update(over)
    return json.dumps(base) + "\n"


def test_read_new_signals_skips_a_corrupt_line_and_continues(tmp_path):
    """One bad line used to kill the whole watch daemon."""
    from glorfindel.cli import _read_new_signals
    f = tmp_path / "x_signals.jsonl"
    f.write_text(_sig_line(signal_id="a") + "{not json\n" + _sig_line(signal_id="b"))
    errors = []
    signals, offset = _read_new_signals(f, 0, errors.append)
    assert [s.signal_id for _, s in signals] == ["a", "b"]
    assert len(errors) == 1
    assert offset == f.stat().st_size


def test_read_new_signals_leaves_a_half_written_line_for_next_poll(tmp_path):
    """Annatar writes from another container: a line without its newline yet must be
    read whole on the next poll, not parsed half-written."""
    from glorfindel.cli import _read_new_signals
    f = tmp_path / "x_signals.jsonl"
    full, partial = _sig_line(signal_id="a"), _sig_line(signal_id="b")
    f.write_text(full + partial[:40])
    signals, offset = _read_new_signals(f, 0, lambda e: None)
    assert [s.signal_id for _, s in signals] == ["a"]
    with open(f, "a") as fh:
        fh.write(partial[40:])
    signals, _ = _read_new_signals(f, offset, lambda e: None)
    assert [s.signal_id for _, s in signals] == ["b"]


def test_parse_signal_line_ignores_unknown_fields():
    """A field added by a newer Annatar must not make Signal(**data) raise."""
    from glorfindel.cli import _parse_signal_line
    data, sig = _parse_signal_line(_sig_line(new_field_from_the_future=1).strip())
    assert sig.signal_id == "r1_attack"
    assert data["new_field_from_the_future"] == 1


def test_subcommand_help_exits_zero_without_a_fake_error():
    """click >= 8.2 raises click.exceptions.Exit (a RuntimeError) for --help: the CLI
    boundary caught it as a failure → '✗ Exit: 0' and exit code 1."""
    from click.testing import CliRunner
    from glorfindel.cli import cli
    result = CliRunner().invoke(cli, ["reset", "--help"])
    assert result.exit_code == 0
    assert "✗" not in result.output
    assert "--from-azure" in result.output


def test_list_shows_a_partial_isolation_and_a_bypassed_block():
    """Real run 2026-10-05 (topology multinic): a partial isolation printed as a plain
    ISOLATED while one NIC carried no rule — the War Room showed ⚠ partial."""
    from glorfindel.actions import _save_block_state, _save_isolation_state
    from glorfindel.cli import cli
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-x"
    _save_isolation_state("vm-x", {"resource_id": rid, "isolated_at": "2026-10-05T16:16:29+00:00",
                                   "partial": True, "failed_nic": "nic-x-1", "placements": []})
    _save_block_state("vm-x", "203.0.113.50", rid, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r",
                                   "shadowed_by": [{"rule": "allow-ssh", "priority": 100}]}])
    res = CliRunner().invoke(cli, ["list"])
    assert res.exit_code == 0, res.output
    assert "ISOLATED (PARTIAL)" in res.output
    assert "NIC nic-x-1 not covered" in res.output
    assert "bypassed: allow-ssh (priority 100)" in res.output
