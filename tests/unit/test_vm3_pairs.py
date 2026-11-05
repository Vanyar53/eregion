"""VM3 (#548) — three attack/detection pairs on VM: T1053.003 (cron), T1059.004 (Unix shell),
T1070.002 (clear Linux logs). Each is a pinned Atomic Red Team test (red) and a shipped
detection rule (blue). No Azure, no LLM: the atomics resolve from the vendored files, and the
rules run over lines the test writes, through the KQL subset (tests/unit/kql_subset.py).

Mutants M3840–M3859 (scripts/mutants/VM3.py).
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

import yaml

from annatar.engines.atomic import resolve_ref
from annatar.runner.parser import ScenarioParser
from glorfindel import auditd

from . import kql_subset
from .test_detection_rules import _Det, _make_rule, _poller

ROOT = Path(__file__).resolve().parents[2]
ATOMICS = ROOT / "annatar" / "atomics"
SCENARIOS = ROOT / "annatar" / "scenarios" / "azure"
CATALOG = yaml.safe_load((ROOT / "technique_catalog.yaml").read_text())
RULES = {r["name"]: r for r in yaml.safe_load(
    (ROOT / "glorfindel/rules/azure/detection_rules.yaml").read_text())["rules"]}

# ttp -> (scenario file, engine_ref, detection rule name)
PAIRS = {
    "T1053.003": ("cron-persistence-atomic", "T1053.003/435057fb-74b1-410e-9403-d81baf194f75",
                  "t1053-003-cron-crontab-replace"),
    "T1059.004": ("shell-execution-atomic", "T1059.004/7e7ac3ed-f795-4fa5-b711-09d6fbe9b873",
                  "t1059-004-shell-from-world-writable"),
    "T1070.002": ("log-clearing-atomic", "T1070.002/d304b2dc-90b4-4465-a650-16ddd503f7b5",
                  "t1070-002-log-tamper"),
}


def _entry(ttp: str) -> dict:
    for e in CATALOG["resource_types"]["azure_vm"]["techniques"]:
        if e.get("ttp") == ttp:
            return e
    raise AssertionError(f"{ttp} absent from the catalog")


# ── The catalog: three techniques turned implemented, each an atomic engine ───────────

def test_catalog_three_pairs_implemented_atomic():
    for ttp, (_scn, ref, _rule) in PAIRS.items():
        e = _entry(ttp)
        assert e["status"] == "implemented", ttp
        assert e["engine"] == "atomic" and e["engine_ref"] == ref, ttp
        probes = (e.get("steady_state") or {}).get("probes") or []
        assert probes and all(p.get("verify") and p.get("expect") for p in probes), ttp


def test_t1070_is_destructive_with_containment():
    e = _entry("T1070.002")
    assert e["destructive"] is True
    assert e["safe_target"] == "sandbox_disposable"
    assert _entry("T1053.003")["destructive"] is False
    assert _entry("T1059.004")["destructive"] is False


# ── The PIN: the sha256 of each newly vendored file is recorded and matches ───────────

def test_pin_records_the_three_vendored_sha256():
    pin = (ATOMICS / "PIN").read_text(encoding="utf-8")
    for ttp in PAIRS:
        rel = f"{ttp}/{ttp}.yaml"
        digest = hashlib.sha256((ATOMICS / rel).read_bytes()).hexdigest()
        assert digest in pin, f"{rel}: sha256 {digest} not pinned"
    # Same provenance line as T1136.001: the upstream commit, vendored verbatim.
    assert "9f6a1eab36d561272cf9f34c61dd80263db3ce8e" in pin


# ── The red side: the atomics resolve on Linux, clean up, no outbound dependency ──────

def test_atomics_resolve_linux_with_cleanup():
    for ttp, (_scn, ref, _rule) in PAIRS.items():
        args = _entry(ttp).get("engine_args") or None
        r = resolve_ref(ref, args)
        assert r.executor in ("sh", "bash"), ttp
        assert r.command and r.cleanup_command, ttp
        assert "PathToAtomicsFolder" not in r.command, ttp
        assert "#{" not in r.command and "#{" not in r.cleanup_command, ttp


def test_shell_atomic_has_no_outbound_dependency_after_engine_args():
    ref = PAIRS["T1059.004"][1]
    # The upstream default pings 8.8.8.8 — an outbound dependency we must not keep.
    assert "8.8.8.8" in resolve_ref(ref).command
    # engine_args point it at the loopback: the behaviour (a shell running a script) stays,
    # the egress is gone.
    with_args = resolve_ref(ref, _entry("T1059.004")["engine_args"]).command
    assert "8.8.8.8" not in with_args and "127.0.0.1" in with_args


def test_log_clearing_atomic_restores_state_via_disposable_path():
    """The cleanup removes the file only when log_path differs from the test's default — the
    disposable path makes it fire, so a real log is never destroyed and the state is restored."""
    r = resolve_ref(PAIRS["T1070.002"][1], _entry("T1070.002")["engine_args"])
    assert "/var/log/eregion-t1070-disposable.log" in r.cleanup_command
    assert "rm -f /var/log/eregion-t1070-disposable.log" in r.cleanup_command
    # Its default cleanup compares /var/log/secure to itself — a no-op that leaves the log
    # behind; the disposable path makes the condition true, so the file is removed.
    assert '"/var/log/secure" != "/var/log/secure"' in resolve_ref(PAIRS["T1070.002"][1]).cleanup_command


# ── The scenarios validate, resolve, and their probes substitute from engine_args ─────

def test_scenarios_validate_resolve_and_substitute_probes():
    for ttp, (scn, ref, _rule) in PAIRS.items():
        path = SCENARIOS / f"{scn}.yaml"
        res = ScenarioParser().validate(str(path))
        assert res.valid, (ttp, res.errors)
        s = ScenarioParser().load(str(path))
        assert s.engine == "atomic" and s.engine_ref == ref and s.steps == []
        r = resolve_ref(s.engine_ref, s.engine_args or None)
        for probe in (s.raw.get("steady_state") or {}).get("probes") or []:
            assert "#{" not in r.substitute(probe["verify"]), ttp


def test_engine_args_reach_the_resolved_atomic():
    s = ScenarioParser().load(str(SCENARIOS / "shell-execution-atomic.yaml"))
    assert s.engine_args == {"host": "127.0.0.1", "script_path": "/tmp/eregion-t1059-art.sh"}
    r = resolve_ref(s.engine_ref, s.engine_args)
    assert r.args["host"] == "127.0.0.1"
    assert r.substitute("test -f #{script_path}") == "test -f /tmp/eregion-t1059-art.sh"


# ── The blue side: each rule fires on a realistic line and not on benign noise ────────

NOW = dt.datetime.now(dt.timezone.utc)


def _row(**k):
    k.setdefault("TimeGenerated", NOW)
    k.setdefault("Computer", "gondolin")
    k.setdefault("_ResourceId", "/subs/x/gondolin")
    return k


def _run(rule_name: str, rows: list[dict]) -> list[dict]:
    return kql_subset.run(RULES[rule_name]["query"], rows, NOW)


def test_cron_rule_fires_on_crontab_replace():
    rows = [_row(Facility="cron", ProcessName="crontab", SyslogMessage="(root) REPLACE (root)")]
    assert len(_run("t1053-003-cron-crontab-replace", rows)) == 1


def test_cron_rule_ignores_benign_noise():
    benign = [
        # cron running apt's job (ProcessName CRON, a CMD line, not a crontab edit)
        _row(Facility="cron", ProcessName="CRON", SyslogMessage="(root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)"),
        # logrotate via /etc/cron.daily — a job running, same shape
        _row(Facility="cron", ProcessName="CRON", SyslogMessage="(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"),
        # a crontab read (LIST), not an edit
        _row(Facility="cron", ProcessName="crontab", SyslogMessage="(root) LIST (root)"),
        _row(Facility="cron", ProcessName="anacron", SyslogMessage="Job `cron.daily' started"),
        # the session line is authpriv, not cron
        _row(Facility="authpriv", ProcessName="CRON", SyslogMessage="pam_unix(cron:session): session opened for user root(uid=0)"),
    ]
    assert _run("t1053-003-cron-crontab-replace", benign) == []


_SYSCALL_TAMPER = ('type=SYSCALL msg=audit(1699999999.123:4567): arch=c000003e syscall=257 '
                   'success=yes exit=0 euid=0 auid=4294967295 comm="dash" exe="/usr/bin/dash" '
                   'key="log_tamper"')


def test_log_tamper_rule_fires_on_non_daemon_write():
    rows = [_row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=_SYSCALL_TAMPER)]
    assert len(_run("t1070-002-log-tamper", rows)) == 1


def test_log_tamper_rule_ignores_log_daemons_and_updates():
    def ev(serial, comm):
        return (f'type=SYSCALL msg=audit(1699999999.{serial}:{serial}): euid=0 '
                f'comm="{comm}" exe="/usr/sbin/{comm}" key="log_tamper"')
    benign = [
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=ev(200, "rsyslogd")),
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=ev(201, "logrotate")),
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=ev(202, "systemd-journal")),
        # apt / unattended-upgrades writing /var/log/dpkg.log
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=ev(203, "dpkg")),
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage=ev(204, "unattended-upgr")),
        # the EXECVE record of the real write carries no key — not a SYSCALL, ignored
        _row(Facility="local6", ProcessName="audisp-syslog", SyslogMessage='type=EXECVE msg=audit(1699999999.123:4567): argc=2 a0="echo" a1="0"'),
    ]
    assert _run("t1070-002-log-tamper", benign) == []


def _shell_event(serial, a0, a1, comm="sh"):
    ev = f"msg=audit(1699999999.{serial}:{serial})"
    return [
        _row(Facility="local6", ProcessName="audisp-syslog",
             SyslogMessage=f'type=SYSCALL {ev}: euid=0 comm="{comm}" exe="/usr/bin/dash" key="shell_exec"'),
        _row(Facility="local6", ProcessName="audisp-syslog",
             SyslogMessage=f'type=EXECVE {ev}: argc=2 a0="{a0}" a1="{a1}"'),
    ]


def test_shell_rule_fires_on_script_from_tmp():
    rows = _shell_event(7777, "sh", "/tmp/eregion-t1059-art.sh")
    assert len(_run("t1059-004-shell-from-world-writable", rows)) == 1


def test_shell_rule_ignores_benign_script_locations():
    benign = (
        # apt maintainer script: sh from /var/lib/dpkg, not a world-writable path
        _shell_event(8001, "/bin/sh", "/var/lib/dpkg/info/foo.postinst")
        # logrotate postrotate: sh -c '<command>' — the argument is -c, not a /tmp script
        + _shell_event(8002, "/bin/sh", "-c")
    )
    assert _run("t1059-004-shell-from-world-writable", benign) == []


# ── The T1059.004 shell rule is NOT read by the auditd human-root pipeline ────────────

def test_shell_rule_bypasses_the_auditd_human_root_settle():
    """A row with no SYSCALL/EXECVE would become an 'unreadable' auditd card for the shipped
    human-root rule (auditd.RULE). The VM3 shell rule shares the TTP but is read as-is — the
    poller gates the human-root reading to auditd.RULE (or a client rule replacing it)."""
    def row():
        # No SYSCALL/EXECVE: the human-root reading cannot read it → an 'unreadable' card.
        return {"Computer": "vm1", "TimeGenerated": "2026-11-05T10:00:00Z", "Foo": "bar"}

    human = _make_rule(name=auditd.RULE, ttp=auditd.TTP, query="Syslog | limit 1")
    p, sent = _poller(_Det([row()]), [human])
    p.poll_once(human)
    assert sent and "AuditRead" in sent[0]["raw_signal"]["first_result_row"]

    shell = _make_rule(name="t1059-004-shell-from-world-writable", ttp=auditd.TTP,
                       query="Syslog | limit 1")
    p2, sent2 = _poller(_Det([row()]), [shell])
    p2.poll_once(shell)
    assert sent2 and "AuditRead" not in sent2[0]["raw_signal"]["first_result_row"]


def test_auditd_rule_constant_matches_the_shipped_rule():
    assert auditd.RULE in RULES and RULES[auditd.RULE]["ttp"] == auditd.TTP
    assert RULES["t1059-004-shell-from-world-writable"]["name"] != auditd.RULE


# ── The proposed telemetry changes are off by default ─────────────────────────────────

def test_cron_facility_proposed_off_by_default():
    variables = (ROOT / "infra/terraform/variables.tf").read_text()
    assert 'variable "cron_logs_enabled"' in variables
    assert 'default     = false' in variables.split('variable "cron_logs_enabled"')[1].split("}")[0]
    mon = (ROOT / "infra/terraform/monitoring.tf").read_text()
    assert 'var.cron_logs_enabled ? ["cron"] : []' in mon


def test_vm3_auditd_rules_proposed_not_wired():
    script = (ROOT / "infra/terraform/scripts/vm3_auditd.sh").read_text()
    # The two keys the blue rules read, each on a rule the script lays down.
    assert "-w /var/log -p wa -k log_tamper" in script
    assert "-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dash -k shell_exec" in script
    variables = (ROOT / "infra/terraform/variables.tf").read_text()
    assert 'variable "vm3_auditd_enabled"' in variables
    # Not wired to an extension (Azure allows one CustomScript per VM — AUD1 holds it).
    assert "virtual_machine_extension" not in (ROOT / "infra/terraform/vm3_auditd.tf").read_text()


def test_engine_runs_shell_atomic_with_loopback(tmp_path, monkeypatch):
    """The engine passes engine_args to the resolver: the command it sends uses the loopback
    and the disposable script path, not the upstream default (8.8.8.8, /tmp/art.sh)."""
    from .test_annatar_atomic import _atomic_executor, _commands_run, _run_atomic
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")
    ex = _atomic_executor()
    _run_atomic(tmp_path, monkeypatch, ex, path=str(SCENARIOS / "shell-execution-atomic.yaml"))
    # The atomic's own command (not a probe) carries the ping — at the loopback, not 8.8.8.8.
    atomic = next(c for c in _commands_run(ex) if "ping -c 4" in c)
    assert "127.0.0.1" in atomic and "8.8.8.8" not in atomic
    assert "/tmp/eregion-t1059-art.sh" in atomic
