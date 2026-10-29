"""SEC4c (#275) — the entries and the calls: restore, queries, timeouts, names.

1. The restore takes the newest recovery point BEFORE the attack on THIS VM: the moment is
   the earliest attack_started of this VM the runs/ channel admits (SEC3, the bounds of
   SEC4a), or --before; unknown, the command asks for it — never the newest point, never
   another VM's line. It says the point chosen and why.
2. A value read from a log line (a host name, an address) enters an investigative query as a
   KQL literal, checked for what it is first; otherwise the query is not run and the enquiry
   says so. A property: no value leaves its literal.
3. Every `requests` call of the repository has a timeout.
4. A short name is refused when two VMs hold it, the local state and the discovery together.
5. The floor of SEC4a: an isolation being lifted, or whose lifting failed, is partial.
6. The T1136.001 rule reads the account tools' own lines only.
7. The watch reads the VMs' private IPs once, for every attack_started line and the
   RulePoller alike.

No Azure call, no model call. Every identifier is made up (repository public). Mutants
M1370–M1389 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import click
import pytest
import yaml
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from glorfindel import agent, kql, signal_origin

from . import kql_subset

ROOT = Path(__file__).resolve().parents[2]
SUB = "00000000-0000-0000-0000-0000000000cc"
RG_A, RG_B = "rg-example-a", "rg-example-b"


def _vm(name: str, rg: str = RG_A) -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"


VM = _vm("vm-example-01")
OTHER = _vm("vm-example-02")


def _attack(rid: str, at: float, run_id: str = "20261029T100000Z", **over) -> dict:
    line = {"signal_id": f"{run_id}_attack_started", "timestamp": "2026-10-29T10:00:00+00:00",
            "provider": "azure", "resource_id": rid, "resource_type": "vm", "ttp": "T1486",
            "severity": "high", "event": "attack_started",
            "raw_signal": {"attack_time": at, "detection_timeout_s": 300},
            "context": {"run_id": run_id, "scenario": "s"}}
    line.update(over)
    return line


def _write_runs(runs: Path, name: str, lines: list[dict]) -> None:
    runs.mkdir(exist_ok=True)
    with open(runs / f"{name}_signals.jsonl", "a") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


# ── 1. The moment of the attack, for this VM ─────────────────────────────────────────

def test_the_moment_is_this_vm_s_earliest_admitted_attack(tmp_path):
    now = time.time()
    runs = tmp_path / "runs"
    _write_runs(runs, "20261029T090000Z", [_attack(VM, now - 1800, "20261029T090000Z")])
    _write_runs(runs, "20261029T093000Z", [_attack(VM.upper(), now - 900, "20261029T093000Z")])
    # Later, another VM's — and a line for this one written by anyone, even later:
    _write_runs(runs, "20261029T095000Z", [_attack(OTHER, now - 60, "20261029T095000Z"),
                                           _attack(VM, now - 30, "20261029T095000Z")])
    at, source = signal_origin.attack_moment(VM, runs_dir=runs)
    assert at == pytest.approx(now - 1800, abs=1) and source == "20261029T090000Z_signals.jsonl"


@pytest.mark.parametrize("line", [
    _attack(VM, 0, event="recovery_complete"),            # not an injector's event
    _attack(VM, 0, context={"run_id": "../x"}),           # a run id that is a path
    _attack(OTHER, 0),                                   # another VM
])
def test_a_line_the_channel_refuses_gives_no_moment(tmp_path, line):
    line = json.loads(json.dumps(line))
    line["raw_signal"]["attack_time"] = time.time() - 600
    _write_runs(tmp_path / "runs", "20261029T100000Z", [line])
    assert signal_origin.attack_moment(VM, runs_dir=tmp_path / "runs") is None


def test_the_moment_is_bounded_around_the_isolation(tmp_path):
    """SEC4a's bounds, around the moment the VM was isolated when it is: an attack line of
    the morning still names the moment of a restore in the evening; a line from days before
    the isolation, or written after it, does not."""
    isolated_at = time.time() - 8 * 3600
    runs = tmp_path / "runs"
    _write_runs(runs, "a", [_attack(VM, isolated_at - 3 * 86400, "a")])     # days before
    _write_runs(runs, "b", [_attack(VM, isolated_at + 3600, "b")])          # after it
    assert signal_origin.attack_moment(VM, runs_dir=runs) is None           # 8 h old: refused
    assert signal_origin.attack_moment(VM, runs_dir=runs, isolated_at=isolated_at) is None
    _write_runs(runs, "c", [_attack(VM, isolated_at - 1200, "c")])
    assert signal_origin.attack_moment(VM, runs_dir=runs, isolated_at=isolated_at) == (
        pytest.approx(isolated_at - 1200, abs=1), "c_signals.jsonl")


def _restore_env(tmp_path, monkeypatch, iso=None):
    """`glorfindel restore` with a fake connector and job starter, in tmp_path."""
    from glorfindel import cli
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_backup_vault_from_config", lambda v: ("rsv-example", "rg-backup", "stexample"))
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda dry_run=False: SimpleNamespace(dry_run=dry_run))
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: iso)
    monkeypatch.setattr(cli, "_record_manual_action", lambda *a, **k: None)
    started: list[tuple] = []

    def start_restore(resource_id, connector, vault, before, **kw):
        started.append((resource_id, before))
        return {"job_id": "j", "restore_job_name": "rj", "recovery_point_time": "2026-10-29 08:00:00+00:00",
                "recovery_point_vault_tier": True}
    monkeypatch.setattr("glorfindel.jobs.start_restore", start_restore)
    return cli, started


def test_restore_without_a_moment_asks_for_it(tmp_path, monkeypatch):
    """No attack_started of this VM: the command refuses and asks for --before — another
    VM's line, the last one in runs/, is no moment for this one."""
    cli, started = _restore_env(tmp_path, monkeypatch)
    _write_runs(tmp_path / "runs", "20261029T100000Z", [_attack(OTHER, time.time() - 300)])
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"])
    assert out.exit_code != 0 and started == []
    assert "--before" in out.output and "Moment de l'attaque inconnu" in out.output


def test_restore_says_the_isolation_when_it_asks(tmp_path, monkeypatch):
    cli, started = _restore_env(tmp_path, monkeypatch, iso={"isolated_at": "2026-10-29T06:00:00+00:00"})
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"])
    assert out.exit_code != 0 and started == []
    assert "isolée depuis 2026-10-29T06:00:00+00:00" in out.output


def test_restore_takes_this_vm_s_moment_and_says_why(tmp_path, monkeypatch):
    cli, started = _restore_env(tmp_path, monkeypatch)
    t0 = time.time() - 1200
    _write_runs(tmp_path / "runs", "20261029T100000Z", [_attack(VM, t0)])
    _write_runs(tmp_path / "runs", "20261029T101000Z", [_attack(OTHER, time.time() - 60, "20261029T101000Z")])
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"], terminal_width=200)
    assert out.exit_code == 0, out.output
    assert started == [(VM, datetime.fromtimestamp(t0, tz=timezone.utc).isoformat())]
    said = " ".join(out.output.split())
    assert "Point de restauration : 2026-10-29 08:00:00+00:00 (niveau coffre, immuable)" in said
    assert "attack_started de runs/20261029T100000Z_signals.jsonl" in said


def test_restore_before_is_read_as_utc_and_wins(tmp_path, monkeypatch):
    cli, started = _restore_env(tmp_path, monkeypatch)
    _write_runs(tmp_path / "runs", "20261029T100000Z", [_attack(VM, time.time() - 300)])
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", "2026-10-29T07:30:00"])
    assert out.exit_code == 0, out.output
    assert started == [(VM, "2026-10-29T07:30:00+00:00")]
    bad = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", "hier"])
    assert bad.exit_code != 0 and "ISO 8601" in bad.output


def test_restore_resolves_a_short_name_and_refuses_two(tmp_path, monkeypatch):
    cli, started = _restore_env(tmp_path, monkeypatch)
    monkeypatch.setattr("glorfindel.actions.active_isolations", lambda: [{"resource_id": VM}])
    monkeypatch.setattr("glorfindel.actions.active_blocks",
                        lambda: [{"resource_id": _vm("vm-example-01", RG_B), "ip": "203.0.113.5"}])
    monkeypatch.setattr("glorfindel.discovery.AssetRegistry", lambda: SimpleNamespace(all=lambda: []))
    out = CliRunner().invoke(cli.cli, ["restore", "vm-example-01", "--yes", "--before", "2026-10-29T07:30:00Z"])
    assert out.exit_code != 0 and started == [] and RG_B in out.output


def test_a_line_dated_after_the_isolation_is_never_the_moment(tmp_path):
    """The 5 min SEC4a allows ahead do not apply past an isolation: the attack came before."""
    isolated_at = time.time() - 3600
    runs = tmp_path / "runs"
    _write_runs(runs, "a", [_attack(VM, isolated_at + 290, "a")])
    assert signal_origin.attack_moment(VM, runs_dir=runs, isolated_at=isolated_at) is None
    _write_runs(runs, "b", [_attack(VM, isolated_at, "b")])
    assert signal_origin.attack_moment(VM, runs_dir=runs, isolated_at=isolated_at) == (
        pytest.approx(isolated_at, abs=1), "b_signals.jsonl")


def test_restore_finds_the_moment_of_a_vm_isolated_hours_ago(tmp_path, monkeypatch):
    """The command reads the moment around the isolation, not around now: a restore 8 h after
    the isolation still takes the attack line of 20 min before it."""
    isolated_at = datetime.now(timezone.utc) - timedelta(hours=8)
    cli, started = _restore_env(tmp_path, monkeypatch, iso={"isolated_at": isolated_at.isoformat()})
    t0 = isolated_at.timestamp() - 1200
    _write_runs(tmp_path / "runs", "20261029T020000Z", [_attack(VM, t0, "20261029T020000Z")])
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"])
    assert out.exit_code == 0, out.output
    assert started == [(VM, datetime.fromtimestamp(t0, tz=timezone.utc).isoformat())]


def test_a_long_runs_file_is_read_from_its_end(tmp_path, monkeypatch):
    """attack_moment reads the last MOMENT_TAIL_BYTES of each file, never a whole one."""
    monkeypatch.setattr(signal_origin, "MOMENT_TAIL_BYTES", 2048)
    runs = tmp_path / "runs"
    now = time.time()
    _write_runs(runs, "big", [_attack(VM, now - 1800, "big")] + [_attack(OTHER, now - 60, "big")] * 20
                + [_attack(VM, now - 600, "big")])
    assert (runs / "big_signals.jsonl").stat().st_size > 4 * 2048
    at, _ = signal_origin.attack_moment(VM, runs_dir=runs)
    assert at == pytest.approx(now - 600, abs=1)                 # the head, past the last 2 KiB, unread


def test_the_proposed_moment_is_the_exercise_s_else_the_card_s(tmp_path, monkeypatch):
    from glorfindel import restore_plan
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: None)
    card = {"first_seen": "2026-10-29T08:12:00+00:00", "timestamp": "2026-10-29T09:00:00+00:00"}
    got = restore_plan.proposed_moment(VM, card, runs_dir=tmp_path / "runs")
    assert got["before"] == "2026-10-29T08:12:00+00:00" and got["source"] == "card"
    assert "l'attaque a commencé avant" in got["why"]
    t0 = time.time() - 900
    _write_runs(tmp_path / "runs", "20261029T100000Z", [_attack(VM, t0)])
    got = restore_plan.proposed_moment(VM, card, runs_dir=tmp_path / "runs")
    assert got["source"] == "exercise" and got["before"] == datetime.fromtimestamp(t0, tz=timezone.utc).isoformat()
    assert restore_plan.proposed_moment(OTHER, {}, runs_dir=tmp_path / "runs")["before"] == ""


def test_the_points_before_a_moment_put_the_one_restored_first(monkeypatch):
    from glorfindel import restore_plan
    monkeypatch.setattr("glorfindel.config.resolve_backup_vault", lambda v=None: ("rsv-example", "rg-backup", "st"))
    asked = []

    class _Conn:
        def list_recovery_points(self, rid, vault="", vault_rg=""):
            asked.append((rid, vault, vault_rg))
            return [{"name": "rp-after", "time": "2026-10-29T09:00:00+00:00", "vault_tier": True},
                    {"name": "rp-snap", "time": "2026-10-29T07:00:00+00:00", "vault_tier": False},
                    {"name": "rp-vault", "time": "2026-10-28T22:00:00+00:00", "vault_tier": True},
                    {"name": "rp-old", "time": "2026-10-27T22:00:00+00:00", "vault_tier": True}]
    got = restore_plan.points_before(VM, "2026-10-29T08:00:00Z", connector=_Conn())
    assert [p["name"] for p in got] == ["rp-vault", "rp-snap", "rp-old"]     # never after; vault first
    assert asked == [(VM, "rsv-example", "rg-backup")]
    assert restore_plan.restore_args(VM, "2026-10-29T08:00:00") == [
        "restore", VM, "--yes", "--before", "2026-10-29T08:00:00+00:00"]


def test_the_provider_lists_its_points_read_only(monkeypatch):
    from tests.unit.test_glorfindel import _RID, _backup_env
    when = datetime(2026, 10, 29, 7, tzinfo=timezone.utc)
    connector, client, posted, now = _backup_env(monkeypatch, rps=[
        _rp("rp-1", when - timedelta(days=1)), _rp("rp-2", when, vaulted=False)], jobs=[])
    nodate = _rp("rp-x", when)
    nodate.properties.recovery_point_time = None
    client.recovery_points.list.return_value = [*client.recovery_points.list.return_value, nodate]
    got = connector.list_recovery_points(_RID, vault="rsv")
    assert got == [{"name": "rp-2", "time": when.isoformat(), "vault_tier": False},
                   {"name": "rp-1", "time": (when - timedelta(days=1)).isoformat(), "vault_tier": True}]
    assert posted == [] and not connector._compute.virtual_machines.begin_deallocate.called


def test_every_copyable_restore_command_asks_for_the_moment():
    """The commands to copy — the CLI's next steps, the bot's, the TUI's, the console's —
    show --before."""
    from glorfindel import cli
    import io
    from rich.console import Console
    buf = io.StringIO()
    monkey = Console(file=buf, width=300)
    real, cli.console = cli.console, monkey
    try:
        cli._render_next_steps({"resource_id": VM, "action": "restore_from_backup", "escalation_type": "destructive_action",
                                "id": "e1", "first_seen": "2026-10-29T08:12:00+00:00"})
    finally:
        cli.console = real
    assert f"glorfindel restore {VM} --yes --before 2026-10-29T08:12:00+00:00" in buf.getvalue()
    for rel in ("glorfindel/bot.py", "glorfindel/tui.py", "eregion_console/static/glorfindel.js"):
        text = (ROOT / rel).read_text()
        assert "--yes --before" in text, rel
        assert not re.search(r"glorfindel restore [^\n]*--yes(?! --before)[`\"\\n]", text), rel


def _rp(name: str, when: datetime, vaulted: bool = True):
    tier = [MagicMock(type="HardenedRP", status="Valid")] if vaulted else []
    rp = MagicMock(properties=MagicMock(recovery_point_time=when, recovery_point_tier_details=tier))
    rp.name = name
    return rp


def test_the_provider_refuses_without_a_moment_before_any_write(monkeypatch):
    from tests.unit.test_glorfindel import _RID, _backup_env
    connector, client, posted, now = _backup_env(monkeypatch, rps=[_rp("rp-1", datetime.now(timezone.utc))], jobs=[])
    with pytest.raises(RuntimeError, match="moment de l'attaque inconnu"):
        connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    assert posted == [] and not connector._compute.virtual_machines.begin_deallocate.called


def test_the_provider_takes_the_newest_point_before_the_attack(monkeypatch):
    from tests.unit.test_glorfindel import _RID, _backup_env, _job
    connector, client, posted, now = _backup_env(monkeypatch, rps=[], jobs=[])
    attack = now - timedelta(hours=2)
    client.recovery_points.list.return_value = [
        _rp("rp-before", attack - timedelta(hours=20)), _rp("rp-just-before", attack - timedelta(hours=1)),
        _rp("rp-after", attack + timedelta(minutes=30))]
    job = _job("restore-1", "vm", "Restore", now)
    job.name = "restore-1"
    client.backup_jobs.list.return_value = [job]
    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st",
                                        before_attack_time=attack.isoformat())
    assert out["recovery_point"] == "rp-just-before" and out["recovery_point_vault_tier"] is True
    assert "/recoveryPoints/rp-just-before/restore" in posted[0]


# ── 2. Values in a query ──────────────────────────────────────────────────────────────

def _read_literal(query: str, start: int) -> tuple[str, int]:
    """A KQL double-quoted literal starting at `start`: (its value, the index of its end)."""
    assert query[start] == '"'
    out, i = [], start + 1
    while i < len(query):
        c = query[i]
        if c == "\\":
            out.append(query[i + 1])
            i += 2
        elif c == '"':
            return "".join(out), i
        else:
            out.append(c)
            i += 1
    raise AssertionError(f"unterminated literal in {query!r}")


_HOSTILE = st.one_of(
    st.text(),
    st.sampled_from(['x" or 1==1 //', 'a\\" | union *', '"', "\\", 'vm\n| take 1', "a'b",
                     "vm-01 | take 1", 'x\\"\\', "203.0.113.5\" or true", "fe80::1%a\"b"]),
)


@settings(max_examples=400, deadline=None)
@given(_HOSTILE)
def test_no_value_leaves_its_literal(value):
    try:
        lit = kql.literal(value)
    except kql.UnsafeValue:
        assert any(not ch.isprintable() or (ch.isspace() and ch != " ") for ch in value)
        return
    read, end = _read_literal(lit, 0)
    assert read == value and end == len(lit) - 1


@settings(max_examples=300, deadline=None)
@given(_HOSTILE, _HOSTILE)
def test_an_investigative_query_keeps_its_shape_whatever_the_values(host, address):
    """The query built from hostile values reads, token by token, as the one built from
    benign ones: a value is a string, never an operator, a pipe or a second statement."""
    def shape(q):
        return [(k, "" if k == "str" else v) for k, v in kql_subset._tokens(q)]
    benign = shape(agent._IQ_SUCCESS_AUTH.format(vm=kql.literal("vm-example-01"), ip=kql.literal("198.51.100.7")))
    try:
        q = agent._IQ_SUCCESS_AUTH.format(vm=kql.literal(host), ip=kql.literal(address))
    except kql.UnsafeValue:
        return
    assert shape(q) == benign


@settings(max_examples=300, deadline=None)
@given(_HOSTILE)
def test_what_the_checks_accept_holds_nothing_that_ends_a_literal(value):
    for check in (kql.name, kql.ip, kql.resource_id):
        try:
            ok = check(value)
        except kql.UnsafeValue:
            continue
        assert ok == value and not set(value) & set('"\'\\| \t\n\r;%')


@pytest.mark.parametrize("value, check, accepted", [
    ("vm-example-01", kql.name, True), ("host.example.internal", kql.name, True),
    ('vm" or 1==1', kql.name, False), ("", kql.name, False), ("-vm", kql.name, False),
    ("198.51.100.7", kql.ip, True), ("2001:db8::7", kql.ip, True), ("010.0.0.1", kql.ip, False),
    ("fe80::1%eth0", kql.ip, False), ("198.51.100.7 ", kql.ip, False),
    (VM, kql.resource_id, True), (_vm("vm-01", "rg_(prod).x"), kql.resource_id, True),
    (VM + '" or true', kql.resource_id, False), ("/subscriptions/x", kql.resource_id, False),
])
def test_each_value_is_checked_for_what_it_is(value, check, accepted):
    if accepted:
        assert check(value) == value
    else:
        with pytest.raises(kql.UnsafeValue):
            check(value)


def _investigate(monkeypatch, row: dict):
    ran: list[str] = []
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: ran.append(q) or [])
    state = {"dry_run": False, "signal": {
        "event": "detection", "resource_id": VM, "ttp": "T1110.001",
        "raw_signal": {"log_analytics_workspace_id": "00000000-0000-0000-0000-0000000000dd",
                       "detected_data": row}}}
    return agent.investigate(state), ran


def test_a_host_name_that_is_not_one_runs_no_query(monkeypatch, capsys):
    out, ran = _investigate(monkeypatch, {"Computer": 'vm" or 1==1 | union *', "MaxWrite": 80})
    assert ran == []
    assert set(out["telemetry_gaps"]) == {"top_write_processes", "backup_agent_check", "heartbeat_gap"}
    assert "valeur refusée" in capsys.readouterr().out


def test_an_address_that_is_not_one_runs_no_login_query(monkeypatch):
    out, ran = _investigate(monkeypatch, {"Computer": "vm-example-01", "FailedAttempts": 12,
                                          "SourceIP": '203.0.113.5" or true'})
    assert ran == [] and out["telemetry_gaps"] == ["successful_auth_from_ip"]
    assert out["signal"]["raw_signal"]["investigative_context"] == {"successful_auth_from_ip": []}


def test_valid_values_run_their_queries_as_before(monkeypatch):
    out, ran = _investigate(monkeypatch, {"Computer": "vm-example-01", "FailedAttempts": 12,
                                          "SourceIP": "203.0.113.5"})
    assert len(ran) == 1 and out["telemetry_gaps"] == []
    assert 'Computer == "vm-example-01"' in ran[0] and 'has "203.0.113.5"' in ran[0]


@pytest.mark.parametrize("hostile", [VM + '" or true', _vm("vm-example-01", 'rg" or 1==1 or "')])
@pytest.mark.parametrize("check", ["_check_syslog", "_check_perf_sampling"])
def test_the_audit_runs_no_query_on_an_id_that_is_not_one(check, hostile):
    from glorfindel import audit
    det = MagicMock()
    det.run_query.return_value = [{"n": 3}]
    res = getattr(audit, check)(hostile, "ws", det)
    assert not det.run_query.called and res.status == "warn" and "non lancée" in res.message
    getattr(audit, check)(VM, "ws", det)
    assert f'_ResourceId =~ "{VM}" or Computer =~ "vm-example-01"' in det.run_query.call_args.args[0]


# ── 3. Timeouts ───────────────────────────────────────────────────────────────────────

_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "urlopen"}
_HTTP_MODULES = {"requests", "httpx", "urllib3", "urllib.request"}
_SESSIONS = {"Session", "Client", "AsyncClient", "PoolManager"}


class _HttpReader:
    """The HTTP calls of a module, as written: the modules `requests`, `httpx`, `urllib3` and
    `urllib.request` under any name (`import requests as rq`, `from requests import post`),
    their verbs and the names bound to them (`get = g or requests.get`), their sessions
    (`requests.Session()`, `httpx.Client()`, `urllib3.PoolManager()`) and the names that
    hold one (`s = …`, `self.session = …`, `with … as s`)."""

    def __init__(self, tree: ast.AST) -> None:
        self.mods = {"requests", "httpx", "urllib3", "urllib"}
        self.funcs: set[str] = set()
        self.classes: set[str] = set()
        self.sessions: set[str] = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name in _HTTP_MODULES:
                        self.mods.add(a.asname or a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module in _HTTP_MODULES:
                for a in n.names:
                    if a.name in _VERBS:
                        self.funcs.add(a.asname or a.name)
                    elif a.name in _SESSIONS:
                        self.classes.add(a.asname or a.name)
        for _ in range(2):                    # a name bound from a name bound above
            for n in ast.walk(tree):
                pairs = []
                if isinstance(n, ast.Assign):
                    pairs = [(t, n.value) for t in n.targets]
                elif isinstance(n, ast.AnnAssign) and n.value is not None:
                    pairs = [(n.target, n.value)]
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    pairs = [(i.optional_vars, i.context_expr) for i in n.items if i.optional_vars]
                for target, value in pairs:
                    name = self._name(target)
                    if name and self.verb(value):
                        self.funcs.add(name)
                    elif name and self.session(value):
                        self.sessions.add(name)

    @staticmethod
    def _name(node) -> str:
        return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""

    def module(self, node) -> bool:
        while isinstance(node, ast.Attribute):
            node = node.value
        return isinstance(node, ast.Name) and node.id in self.mods

    def verb(self, node) -> bool:
        if isinstance(node, ast.Attribute):
            return node.attr in _VERBS and self.module(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.funcs or node.id == "urlopen"
        if isinstance(node, ast.BoolOp):
            return any(self.verb(v) for v in node.values)
        return False

    def session(self, node) -> bool:
        if isinstance(node, ast.Call):
            f = node.func
            return ((isinstance(f, ast.Attribute) and f.attr in _SESSIONS and self.module(f.value))
                    or (isinstance(f, ast.Name) and f.id in self.classes))
        return self._name(node) in self.sessions

    def http_call(self, call: ast.Call) -> bool:
        f = call.func
        return (self.verb(f) or (isinstance(f, ast.Attribute) and f.attr == "urlopen")
                or (isinstance(f, ast.Attribute) and f.attr in _VERBS and self.session(f.value)))


def _calls_without_timeout(source: str) -> list[int]:
    """The lines of the HTTP calls without a timeout — none given, or `timeout=None`."""
    tree = ast.parse(source)
    reader = _HttpReader(tree)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and reader.http_call(node):
            given = [k.value for k in node.keywords if k.arg == "timeout"]
            if not given or (isinstance(given[0], ast.Constant) and given[0].value is None):
                bad.append(node.lineno)
    return sorted(bad)


def _python_files() -> list[str]:
    """The repository's Python files: git's list, or — outside a checkout (the mutants' copy)
    — the tree, the environments and caches aside."""
    listed = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True, text=True)
    if listed.returncode == 0 and listed.stdout.strip():
        return listed.stdout.split()
    skip = {".git", ".venv", "venv", ".claude", "node_modules", "site-packages", "__pycache__", "build", "dist"}
    return [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
            if not skip & set(p.relative_to(ROOT).parts)]


def test_every_http_call_of_the_repository_has_a_timeout():
    files = _python_files()
    assert "glorfindel/providers/azure/restore.py" in files
    bad = [f"{f}:{line}" for f in files if not f.startswith("tests/")
           for line in _calls_without_timeout((ROOT / f).read_text(encoding="utf-8"))]
    assert bad == []


def test_the_reader_sees_a_call_without_a_timeout():
    src = ("import requests\nrequests.post(u)\nget = g or requests.get\nget(u)\n"
           "(put or requests.put)(u, timeout=3)\nurllib.request.urlopen(r)\n")
    assert _calls_without_timeout(src) == [2, 4, 6]


def test_the_reader_follows_aliases_sessions_and_a_none_timeout():
    src = "\n".join([
        "import requests as rq",                       # 1
        "from requests import post as p",              # 2
        "import httpx, urllib3",                       # 3
        "rq.get(u)",                                   # 4  an aliased module
        "p(u)",                                        # 5  an imported verb, renamed
        "httpx.post(u, timeout=None)",                 # 6  a timeout of None
        "s = rq.Session()",                            # 7
        "s.post(u)",                                   # 8  a session
        "rq.Session().put(u)",                         # 9  a session, chained
        "with httpx.Client() as c:",                   # 10
        "    c.get(u)",                                # 11 a client
        "pool = urllib3.PoolManager()",                # 12
        "pool.request('GET', u)",                      # 13 a pool
        "self.session = requests.Session()",           # 14
        "self.session.delete(u)",                      # 15 a session held by an attribute
        "rq.get(u, timeout=5); s.post(u, timeout=(3, 9)); d.get(u)",   # 16 bounded, or not HTTP
    ])
    assert _calls_without_timeout(src) == [4, 5, 6, 8, 9, 11, 13, 15]


@pytest.mark.parametrize("call", ["snapshot", "restore"])
def test_the_backup_calls_wait_a_bounded_time(monkeypatch, call):
    import sys as _sys
    from tests.unit.test_glorfindel import _AFTER_EVERY_POINT, _RID, _backup_env, _job
    connector, client, posted, now = _backup_env(monkeypatch, rps=[_rp("rp-1", now_utc := datetime.now(timezone.utc))],
                                                 jobs=[])
    job = _job("j-1", "vm", "Restore" if call == "restore" else "Backup", now_utc)
    job.name = "j-1"
    client.backup_jobs.list.return_value = [job]
    if call == "snapshot":
        connector.snapshot(_RID, vault="rsv", wait=False)
    else:
        connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st",
                                      before_attack_time=_AFTER_EVERY_POINT)
    connect, read = _sys.modules["requests"].timeouts[0]
    assert 0 < connect <= 30 and 0 < read <= 120


def test_a_call_that_never_answers_says_whether_it_may_have_landed(monkeypatch):
    import requests

    from glorfindel.providers.azure import sdk

    def no_answer(url, **kw):
        assert kw["timeout"] == sdk.REST_TIMEOUT_S
        raise requests.ReadTimeout("read timed out")
    monkeypatch.setattr(requests, "post", no_answer)
    with pytest.raises(RuntimeError, match="a pu être prise en compte"):
        sdk.rest_post("https://example.invalid/x", "Déclenchement du restore", json={})

    def no_connection(url, **kw):
        raise requests.ConnectTimeout("connect timed out")
    monkeypatch.setattr(requests, "post", no_connection)
    with pytest.raises(RuntimeError, match="rien n'a été envoyé"):
        sdk.rest_post("https://example.invalid/x", "Déclenchement du restore", json={})


# ── 4. A short name, two VMs ──────────────────────────────────────────────────────────

def _names(monkeypatch, isolations=(), blocks=(), discovered=()):
    monkeypatch.setattr("glorfindel.actions.active_isolations", lambda: [{"resource_id": r} for r in isolations])
    monkeypatch.setattr("glorfindel.actions.active_blocks",
                        lambda: [{"resource_id": r, "ip": "203.0.113.5"} for r in blocks])
    monkeypatch.setattr("glorfindel.discovery.AssetRegistry",
                        lambda: SimpleNamespace(all=lambda: [SimpleNamespace(resource_id=r) for r in discovered]))
    from glorfindel.cli import _resolve_resource_id
    return _resolve_resource_id


@pytest.mark.parametrize("where", [
    {"isolations": [VM], "blocks": [_vm("vm-example-01", RG_B)]},          # one isolated, one blocked
    {"isolations": [VM], "discovered": [_vm("vm-example-01", RG_B)]},      # the state and the discovery
    {"discovered": [VM, _vm("vm-example-01", RG_B)]},
])
def test_two_vms_of_one_name_are_refused_wherever_they_are_known(monkeypatch, where):
    resolve = _names(monkeypatch, **where)
    with pytest.raises(click.ClickException) as exc:
        resolve("vm-example-01")
    assert VM in exc.value.message and _vm("vm-example-01", RG_B) in exc.value.message


def test_one_vm_known_twice_is_one_vm(monkeypatch):
    resolve = _names(monkeypatch, isolations=[VM], blocks=[VM.lower()], discovered=[VM])
    assert resolve("VM-EXAMPLE-01") == VM
    assert resolve(OTHER) == OTHER and resolve("vm-unknown") == "vm-unknown"


# ── 5. The floor: an isolation being lifted ───────────────────────────────────────────

_T1136 = "new user: name=svc-example, UID=2001, GID=2001, home=/home/svc-example, shell=/bin/bash"


def _floor(monkeypatch, iso):
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: iso)
    monkeypatch.setattr("glorfindel.actions._load_block_entries", lambda rid: [])
    signal = {"event": "detection", "resource_id": VM, "ttp": "T1136.001",
              "raw_signal": {"detected_data": {"SyslogMessage": _T1136, "Computer": "vm-example-01"}}}
    d = {"escalate": False, "action": "snapshot", "confidence": 0.9}
    return agent._contained_now(signal), agent._uncontained_floor(d, signal)


@pytest.mark.parametrize("iso, said", [
    ({"isolated_at": "2026-10-29T06:00:00+00:00", "releasing_at": "2026-10-29T09:00:00+00:00"},
     "levée de l'isolation en cours depuis 2026-10-29T09:00:00+00:00"),
    ({"isolated_at": "2026-10-29T06:00:00+00:00", "release_failed": ["nic-a: 409"]},
     "levée de l'isolation en échec"),
    ({"isolated_at": "2026-10-29T06:00:00+00:00", "partial": True}, "isolation partielle"),
])
def test_an_isolation_being_lifted_leaves_the_card(monkeypatch, iso, said):
    (contained, note), card = _floor(monkeypatch, iso)
    assert contained is False and said in note
    assert card and said in card


def test_an_isolation_that_holds_still_contains(monkeypatch):
    (contained, _), card = _floor(monkeypatch, {"isolated_at": "2026-10-29T06:00:00+00:00"})
    assert contained is True and card == ""


# ── 6. T1136.001: the account tools' own lines ────────────────────────────────────────

_RULE = {r["name"]: r for r in yaml.safe_load(
    (ROOT / "glorfindel" / "rules" / "azure" / "detection_rules.yaml").read_text())["rules"]}[
    "t1136-001-local-account-creation-linux-v1"]


def _syslog(message: str, process: str, facility: str = "authpriv") -> dict:
    return {"Type": "Syslog", "TimeGenerated": datetime.now(timezone.utc) - timedelta(minutes=1),
            "Facility": facility, "SeverityLevel": "info", "ProcessName": process,
            "SyslogMessage": message, "Computer": "vm-example-01", "_ResourceId": VM}


def _t1136(rows):
    return kql_subset.run(_RULE["query"], rows, now=datetime.now(timezone.utc))


# The forms measured on H0's Syslog (30 days to 29/10: 16 lines, all tagged useradd), names
# and numbers made up: with `from=` (authpriv) and without (auth), the shells seen.
_USERADD = [
    ("new user: name=svc-example, UID=2001, GID=2001, home=/home/svc-example, shell=/bin/bash, from=none",
     "authpriv"),
    ("new user: name=evil_example, UID=998, GID=100, home=/home/evil_example, shell=/bin/bash, from=none",
     "authpriv"),
    ("new user: name=svc-example2, UID=2002, GID=2002, home=/home/svc-example2, shell=/usr/sbin/nologin, from=none",
     "authpriv"),
    ("new user: name=svc-example3, UID=2003, GID=2003, home=/home/svc-example3, shell=/sbin/nologin",
     "auth"),
]


@pytest.mark.parametrize("message, facility", _USERADD)
def test_useradd_s_creation_is_detected(message, facility):
    assert len(_t1136([_syslog(message, "useradd", facility)])) == 1


def test_a_package_s_system_account_stays_out_whatever_the_form():
    line = "new user: name=svc-pkg, UID=112, GID=118, home=/nonexistent, shell=/usr/sbin/nologin"
    assert _t1136([_syslog(line, "useradd", "auth"), _syslog(line + ", from=none", "useradd")]) == []


@pytest.mark.parametrize("process", ["root", "logger", "sshd", "sudo", "cron", "", "adduser"])
def test_the_same_words_written_by_anything_else_are_no_account(process):
    """`logger -p auth.info "new user: name=…"` from any user, or a user name holding the
    words in sshd's line: no account was created."""
    assert _t1136([_syslog(_USERADD[0][0], process, facility="auth")]) == []


def test_the_bench_simulation_is_still_detected():
    script = (ROOT / "scripts" / "vm" / "account_creation_sim.sh").read_text()
    rows = [_syslog(text.replace("${USERNAME}", "svc-example"), tag, facility.split(".")[0])
            for facility, tag, text in re.findall(r'logger -p (\S+) -t (\S+) "([^"]*)"', script)]
    assert len(_t1136(rows)) == 1


# ── 7. The private IPs, read once ─────────────────────────────────────────────────────

def test_the_ip_map_is_read_once_for_every_reader():
    from glorfindel.detection_rules import IpOwners, RulePoller
    calls = []
    owners = IpOwners(lambda: calls.append(1) or {"10.0.0.4": VM})
    poller = RulePoller([], lambda s: None, dry_run=True, ip_owners=owners)
    for _ in range(3):
        agent._row_reader(VM, owners)({"CallerIpAddress": "10.0.0.4"})
    assert poller._owners() == {"10.0.0.4": VM.lower()}
    assert len(calls) == 1


def test_an_unreadable_map_keeps_the_last_one():
    from glorfindel import detection_rules
    from glorfindel.detection_rules import IpOwners
    answers = [{"10.0.0.4": VM}, RuntimeError("throttled")]

    def source():
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    owners = IpOwners(source)
    assert owners() == {"10.0.0.4": VM.lower()}
    owners._cache = (time.time() - detection_rules._IP_OWNERS_TTL_S - 1, owners._cache[1])
    assert owners() == {"10.0.0.4": VM.lower()}


_FORGER = """
import json, sys
with open(sys.argv[1], "a") as f:
    for line in json.loads(sys.argv[2]):
        f.write(json.dumps(line) + "\\n")
"""


def test_the_watch_lists_the_private_ips_once_for_its_attack_lines(tmp_path, monkeypatch):
    """Two attack_started lines, the RulePoller beside: one Azure listing, not one per line."""
    from glorfindel import cli
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cli, "_INJECTORS_DIR", home / ".glorfindel" / "injectors")
    runs = tmp_path / "runs"
    runs.mkdir()
    listed, polled = [], []

    class _Connector:
        def __init__(self, dry_run=False):
            pass

        def private_ip_owners(self):
            listed.append(1)
            return {"10.0.0.4": VM}

    class _Agent:
        def __init__(self, **kw):
            self.autonomy = SimpleNamespace(default="human_only", assets=[])
            self.config_error = ""
            self.connector = SimpleNamespace(permission_mode=lambda: "read_write")

        def respond(self, data):
            return {"action": "none", "escalate": False, "confidence": 0.0, "outcome": {}}

    def _resolve(data, ip_owners=None):
        polled.append(ip_owners() if ip_owners else None)
        return {**data, "event": "detection_timeout"}

    monkeypatch.setattr("glorfindel.actions.AzureConnector", _Connector)
    monkeypatch.setattr("glorfindel.actions.warm_up_azure_sdk", lambda: None)
    monkeypatch.setattr("glorfindel.agent.GlorfindelAgent", _Agent)
    monkeypatch.setattr("glorfindel.agent.resolve_attack_started", _resolve)
    monkeypatch.setattr(cli, "_find_rules_file", lambda: None)
    monkeypatch.setattr(cli, "_render_decision", lambda *a, **k: None)
    monkeypatch.setattr("eregion_core.inscription.TagEnrollment", lambda *a, **k: (lambda rid: True))
    import atexit
    import signal as signalmod
    monkeypatch.setattr(atexit, "register", lambda *a, **k: None)
    monkeypatch.setattr(signalmod, "signal", lambda *a, **k: None)
    real_sleep, calls = time.sleep, [0]
    lines = [_attack(VM, time.time() - 60, "20261029T100000Z"), _attack(OTHER, time.time() - 30, "20261029T100100Z")]

    def _sleep(s):
        # The watch loop's own sleep only (--interval 0): not a worker's, nor a start-up wait.
        if threading.current_thread() is not threading.main_thread() or s != 0:
            return real_sleep(s)
        calls[0] += 1
        if calls[0] == 1:
            subprocess.run([sys.executable, "-c", _FORGER, str(runs / "x_signals.jsonl"), json.dumps(lines)],
                           check=True, timeout=60)
            return
        if calls[0] == 2:
            deadline = time.monotonic() + 10
            while len(polled) < 2 and time.monotonic() < deadline:
                real_sleep(0.05)
            raise KeyboardInterrupt
        return real_sleep(0)

    monkeypatch.setattr(cli.time, "sleep", _sleep)
    result = CliRunner().invoke(cli.cli, ["watch", str(runs), "--interval", "0"])
    assert result.exit_code == 0, result.output
    assert polled == [{"10.0.0.4": VM.lower()}] * 2, result.output
    assert len(listed) == 1


# ── The second correction: one restore at a time, a moment that is one ────────────────

@pytest.mark.parametrize("text", ["2999-01-01T00:00:00Z", "0001-01-01T00:00:00+01:00",
                                  "9999-12-31T23:59:59-01:00", "hier", ""])
def test_a_moment_that_is_not_one_is_a_value_error(text):
    from glorfindel import restore_plan
    with pytest.raises(ValueError):
        restore_plan.parse_moment(text)
    assert restore_plan.parse_moment("2026-10-29T07:00:00+01:00") == "2026-10-29T06:00:00+00:00"
    soon = datetime.now(timezone.utc) + timedelta(seconds=60)          # within the margin
    assert restore_plan.parse_moment(soon.isoformat())


@pytest.mark.parametrize("text", ["2999-01-01T00:00:00Z", "0001-01-01T00:00:00+01:00",
                                  "9999-12-31T23:59:59-01:00"])
def test_the_cli_refuses_such_a_moment_without_a_trace(tmp_path, monkeypatch, text):
    cli, started = _restore_env(tmp_path, monkeypatch)
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", text])
    assert out.exit_code == 1 and started == [] and isinstance(out.exception, SystemExit)
    assert "--before" in out.output and "Traceback" not in out.output


def test_a_moment_after_the_isolation_is_said_not_refused(tmp_path, monkeypatch):
    isolated_at = datetime.now(timezone.utc) - timedelta(hours=2)
    cli, started = _restore_env(tmp_path, monkeypatch, iso={"isolated_at": isolated_at.isoformat()})
    after = (isolated_at + timedelta(minutes=30)).isoformat()
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", after], terminal_width=200)
    assert out.exit_code == 0 and started == [(VM, after)]
    assert "postérieur à l'isolation" in " ".join(out.output.split())


def test_a_restore_already_running_on_the_vm_refuses_another(tmp_path, monkeypatch):
    from glorfindel import jobs
    cli, started = _restore_env(tmp_path, monkeypatch)
    jobs.save_job("vm-example-01", {"type": "restore", "status": "InProgress", "job_id": "j1",
                                    "restore_job_name": "rj-1", "started_at": "2026-10-29T08:00:00+00:00"})
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", "2026-10-29T07:30:00Z"])
    assert out.exit_code == 1 and started == [] and "en cours" in out.output and "rj-1" in out.output
    jobs.save_job("vm-example-01", {"type": "restore", "status": "Completed"})
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", "2026-10-29T07:30:00Z"])
    assert out.exit_code == 0 and len(started) == 1


def test_a_restore_claims_its_vm_while_it_starts(tmp_path, monkeypatch):
    """Two restores of one VM at once — two tabs, a double click: the second is refused while
    the first holds the claim, and the claim goes with the first."""
    import glorfindel.jobs as jobs
    cli, started = _restore_env(tmp_path, monkeypatch)
    seen = []
    first = jobs.start_restore                           # the fake of _restore_env

    def start_and_try_another(resource_id, connector, vault, before, **kw):
        seen.append(CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", before]))
        return first(resource_id, connector, vault, before, **kw)
    monkeypatch.setattr("glorfindel.jobs.start_restore", start_and_try_another)
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes", "--before", "2026-10-29T07:30:00Z"])
    assert out.exit_code == 0, out.output
    inner = seen[0]
    assert inner.exit_code == 1 and "en train de partir" in inner.output
    assert started == [(VM, "2026-10-29T07:30:00+00:00")]                 # only the first ran
    assert not (jobs._JOBS_DIR / "vm-example-01.restore-claim").exists()
    with jobs.restore_claim("vm-example-01"):
        with pytest.raises(jobs.RestoreBusy):
            jobs.restore_claim("vm-example-01").__enter__()


def test_a_claim_left_by_a_dead_process_stops_holding(tmp_path):
    import os

    from glorfindel import jobs
    jobs._JOBS_DIR.mkdir(parents=True, exist_ok=True)
    claim = jobs._JOBS_DIR / "vm-example-01.restore-claim"
    claim.write_text("x")
    assert jobs.restore_in_progress("vm-example-01")
    old = time.time() - jobs._CLAIM_MAX_AGE_S - 10
    os.utime(claim, (old, old))
    assert jobs.restore_in_progress("vm-example-01") == ""


def test_a_claim_held_by_a_live_restore_holds_past_its_age(tmp_path):
    """SEC7: a `--wait` restore of a large disk writes no job file and lasts hours; its claim
    held the VM 2 h, then a second restore was let through while the first still ran. The claim
    is an flock now, held for the restore's length: whatever its age, a live holder refuses.
    Once its process is gone (the lock released), the age counts again."""
    import os

    from glorfindel import jobs
    claim = jobs.restore_claim("vm-example-01")
    claim.__enter__()
    try:
        old = time.time() - jobs._CLAIM_MAX_AGE_S - 600
        os.utime(claim.path, (old, old))
        busy = jobs.restore_in_progress("vm-example-01")
        assert busy and "son processus vit" in busy
        with pytest.raises(jobs.RestoreBusy):
            jobs.restore_claim("vm-example-01").__enter__()
    finally:
        claim._fh.close()                 # the process dies: the system releases its lock
        claim._fh = None
    assert jobs.restore_in_progress("vm-example-01") == ""


def test_a_claim_left_behind_says_where_it_is_until_when_and_what_to_check(tmp_path):
    from glorfindel import jobs
    jobs._JOBS_DIR.mkdir(parents=True, exist_ok=True)
    claim = jobs._JOBS_DIR / "vm-example-01.restore-claim"
    claim.write_text("20261029T080000Z host 4242 dead\n")            # nobody holds it
    said = jobs.restore_in_progress("vm-example-01")
    assert str(claim) in said and "UTC" in said and "s'est arrêté" in said
    assert "az backup job list" in said


def test_a_restore_leaving_removes_its_own_claim_only(tmp_path):
    """A claim removed by hand while its restore ran, then taken by another restore: the first
    one, leaving, must not remove the second's."""
    from glorfindel import jobs
    first = jobs.restore_claim("vm-example-01")
    first.__enter__()
    first.path.write_text("20261029T090000Z other 7 another-token\n")
    first.__exit__(None, None, None)
    assert first.path.read_text().startswith("20261029T090000Z other")
    second = jobs.restore_claim("vm-example-02")
    with second:
        assert second.path.exists()
    assert not second.path.exists()


def test_the_proposal_never_falls_after_the_isolation(tmp_path, monkeypatch):
    """The card is written after the isolation and the autonomous snapshot: the field takes
    the isolation when it came first, and a point taken after it is marked."""
    from glorfindel import restore_plan
    isolated = "2026-10-29T08:00:00+00:00"
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: {"isolated_at": isolated})
    card = {"first_seen": "2026-10-29T08:05:00+00:00"}
    got = restore_plan.proposed_moment(VM, card, runs_dir=tmp_path / "runs")
    assert got["before"] == isolated and "isolation de la VM" in got["why"]
    earlier = {"first_seen": "2026-10-29T07:55:00+00:00"}
    assert restore_plan.proposed_moment(VM, earlier, runs_dir=tmp_path / "runs")["before"] == "2026-10-29T07:55:00+00:00"
    monkeypatch.setattr("glorfindel.config.resolve_backup_vault", lambda v=None: ("rsv-example", "rg-backup", "st"))

    class _Conn:
        def list_recovery_points(self, rid, vault="", vault_rg=""):
            return [{"name": "rp-snap", "time": "2026-10-29T08:01:00+00:00", "vault_tier": False},
                    {"name": "rp-night", "time": "2026-10-29T01:00:00+00:00", "vault_tier": True}]
    got = restore_plan.points_before(VM, "2026-10-29T08:10:00Z", connector=_Conn())
    assert {p["name"]: p["during_incident"] for p in got} == {"rp-night": False, "rp-snap": True}
    assert restore_plan.moment_warning(VM, "2026-10-29T08:10:00+00:00")
    assert restore_plan.moment_warning(VM, "2026-10-29T07:10:00+00:00") == ""
