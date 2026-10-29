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
    at, source = signal_origin.attack_moment(VM, runs_dir=runs, ref=now)
    assert at == pytest.approx(now - 1800) and source == "20261029T090000Z_signals.jsonl"


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
    assert signal_origin.attack_moment(VM, runs_dir=runs, ref=isolated_at) is None
    _write_runs(runs, "c", [_attack(VM, isolated_at - 1200, "c")])
    assert signal_origin.attack_moment(VM, runs_dir=runs, ref=isolated_at) == (
        pytest.approx(isolated_at - 1200), "c_signals.jsonl")


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

_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


def _requests_verb(node) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in _VERBS and isinstance(node.value, ast.Name) and node.value.id == "requests"
    if isinstance(node, ast.BoolOp):
        return any(_requests_verb(v) for v in node.values)
    return False


def _calls_without_timeout(source: str) -> list[int]:
    tree = ast.parse(source)
    aliases = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) and _requests_verb(n.value)
               for t in n.targets if isinstance(t, ast.Name)}
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        http = (_requests_verb(f) or (isinstance(f, ast.Name) and f.id in aliases)
                or (isinstance(f, ast.Attribute) and f.attr == "urlopen")
                or (isinstance(f, ast.Name) and f.id == "urlopen"))
        if http and not any(k.arg == "timeout" for k in node.keywords):
            bad.append(node.lineno)
    return bad


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


# Lines in the form shadow's useradd writes them (account names made up).
_USERADD = [
    "new user: name=svc-example, UID=2001, GID=2001, home=/home/svc-example, shell=/bin/bash, from=/dev/pts/0",
    "new user: name=evil_example, UID=998, GID=100, home=/home/evil_example, shell=/bin/bash, from=none",
]


@pytest.mark.parametrize("message", _USERADD)
@pytest.mark.parametrize("process", ["useradd", "adduser"])
def test_an_account_tool_s_creation_is_detected(message, process):
    assert len(_t1136([_syslog(message, process)])) == 1


@pytest.mark.parametrize("process", ["root", "logger", "sshd", "sudo", "cron", ""])
def test_the_same_words_written_by_anything_else_are_no_account(process):
    """`logger -p auth.info "new user: name=…"` from any user, or a user name holding the
    words in sshd's line: no account was created."""
    assert _t1136([_syslog(_USERADD[0], process, facility="auth")]) == []


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
