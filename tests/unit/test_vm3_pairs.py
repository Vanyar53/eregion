"""VM3 (#548) — three attack/detection pairs on VM: T1053.003 (cron), T1059.004 (Unix shell),
T1070.002 (clear Linux logs). Each is a pinned Atomic Red Team test (red) and a shipped
detection rule (blue). No Azure, no LLM: the atomics resolve from the vendored files, the
experiments run against a mocked executor, and the rules run over lines the test writes,
through the KQL subset (tests/unit/kql_subset.py).

Mutants M3840–M3859 and M3930–M3939 (scripts/mutants/VM3.py).
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from annatar.campaign.catalog import catalog_destructive, load_catalog
from annatar.campaign.scope import Scope
from annatar.campaign.synthesizer import synthesize
from annatar.engines.atomic import AtomicError, resolve_ref
from annatar.runner.parser import ScenarioParser
from glorfindel import auditd
from glorfindel.detection_rules import _row_identity, has_recognized_indicator

from . import kql_subset
from .test_detection_rules import _Det, _make_rule, _poller
from .test_injector_guards import PROD_TAGS, _executor, _run

ROOT = Path(__file__).resolve().parents[2]
ATOMICS = ROOT / "annatar" / "atomics"
SCENARIOS = ROOT / "annatar" / "scenarios" / "azure"
CATALOG = yaml.safe_load((ROOT / "technique_catalog.yaml").read_text())
RULES = {r["name"]: r for r in yaml.safe_load(
    (ROOT / "glorfindel/rules/azure/detection_rules.yaml").read_text())["rules"]}
SANDBOX_VM = ("/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
              "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
SHELL_RULE = "t1059-004-shell-from-world-writable"
TAMPER_RULE = "t1070-002-log-tamper"
CRON_RULE = "t1053-003-cron-crontab-replace"

# ttp -> (scenario file, engine_ref, detection rule name)
PAIRS = {
    "T1053.003": ("cron-persistence-atomic", "T1053.003/435057fb-74b1-410e-9403-d81baf194f75", CRON_RULE),
    "T1059.004": ("shell-execution-atomic", "T1059.004/7e7ac3ed-f795-4fa5-b711-09d6fbe9b873", SHELL_RULE),
    "T1070.002": ("log-clearing-atomic", "T1070.002/d304b2dc-90b4-4465-a650-16ddd503f7b5", TAMPER_RULE),
}


@pytest.fixture(autouse=True)
def _subscription(monkeypatch):
    # The bench's scope names its subscription (SEC11): the one of the executors' targets.
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")


def _entry(ttp: str) -> dict:
    for e in CATALOG["resource_types"]["azure_vm"]["techniques"]:
        if e.get("ttp") == ttp:
            return e
    raise AssertionError(f"{ttp} absent from the catalog")


def _scenario(ttp: str) -> Path:
    return SCENARIOS / f"{PAIRS[ttp][0]}.yaml"


# ── The catalog: three techniques turned implemented, each an atomic engine ───────────

def test_catalog_three_pairs_implemented_atomic():
    for ttp, (_scn, ref, _rule) in PAIRS.items():
        e = _entry(ttp)
        assert e["status"] == "implemented", ttp
        assert e["engine"] == "atomic" and e["engine_ref"] == ref, ttp
        probes = (e.get("steady_state") or {}).get("probes") or []
        assert probes and all(p.get("verify") and p.get("expect") for p in probes), ttp


def test_destructive_pairs_declare_their_containment():
    """T1070.002 clears a log; T1053.003 replaces root's whole crontab (B3): both destructive,
    on the bench only. T1059.004 runs a shell script in /tmp and removes it."""
    for ttp in ("T1070.002", "T1053.003"):
        e = _entry(ttp)
        assert e["destructive"] is True and e["safe_target"] == "sandbox_disposable", ttp
    assert _entry("T1059.004")["destructive"] is False


@pytest.mark.parametrize("ttp", ["T1053.003", "T1070.002"])
def test_destructive_pairs_are_refused_in_production(tmp_path, monkeypatch, ttp):
    executor = _executor(PROD_TAGS)
    out = _run(tmp_path, monkeypatch, _scenario(ttp), executor)
    assert out.refused and "destructive technique never runs in production" in out.error
    executor.run_command.assert_not_called()


# ── The PIN: the sha256 of each newly vendored file is recorded and matches ───────────

def test_pin_records_the_three_vendored_sha256():
    pin = (ATOMICS / "PIN").read_text(encoding="utf-8")
    for ttp in PAIRS:
        rel = f"{ttp}/{ttp}.yaml"
        digest = hashlib.sha256((ATOMICS / rel).read_bytes()).hexdigest()
        assert digest in pin, f"{rel}: sha256 {digest} not pinned"
    assert "9f6a1eab36d561272cf9f34c61dd80263db3ce8e" in pin


# ── The red side: the atomics resolve on Linux, clean up, no outbound dependency ──────

def test_atomics_resolve_linux_with_cleanup():
    for ttp, (_scn, ref, _rule) in PAIRS.items():
        r = resolve_ref(ref, _entry(ttp).get("engine_args"))
        assert r.executor in ("sh", "bash"), ttp
        assert r.command and r.cleanup_command, ttp
        assert "PathToAtomicsFolder" not in r.command, ttp
        assert "#{" not in r.command and "#{" not in r.cleanup_command, ttp


def test_shell_atomic_has_no_outbound_dependency_with_the_catalog_args():
    ref = PAIRS["T1059.004"][1]
    assert "8.8.8.8" in resolve_ref(ref).command   # the upstream default: an egress
    with_args = resolve_ref(ref, _entry("T1059.004")["engine_args"]).command
    assert "8.8.8.8" not in with_args and "127.0.0.1" in with_args


def test_log_clearing_atomic_restores_state_via_disposable_path():
    """The cleanup removes the file only when log_path differs from the test's default."""
    ref = PAIRS["T1070.002"][1]
    r = resolve_ref(ref, _entry("T1070.002")["engine_args"])
    assert "rm -f /var/log/eregion-t1070-disposable.log" in r.cleanup_command
    assert '"/var/log/secure" != "/var/log/secure"' in resolve_ref(ref).cleanup_command


# ── B2: engine_args held by the adapter, the parser and the catalog ───────────────────

def test_an_engine_arg_the_test_does_not_declare_is_refused():
    with pytest.raises(AtomicError, match="not an input argument"):
        resolve_ref(PAIRS["T1059.004"][1], {"host": "127.0.0.1", "payload": "x"})


@pytest.mark.parametrize("value", ["127.0.0.1; reboot", "127.0.0.1 && id", "$(id)", "a b",
                                   "x`id`", "'x'", "x|y", "", True, ["127.0.0.1"]])
def test_an_engine_arg_that_is_not_a_plain_value_is_refused(value):
    with pytest.raises(AtomicError, match="not a plain value"):
        resolve_ref(PAIRS["T1059.004"][1], {"host": value})


@pytest.mark.parametrize("args", [["host", "127.0.0.1"], "host=127.0.0.1", 3])
def test_engine_args_that_are_no_mapping_are_refused_never_a_crash(tmp_path, args):
    with pytest.raises(AtomicError, match="must be a mapping"):
        resolve_ref(PAIRS["T1059.004"][1], args)
    doc = yaml.safe_load(_scenario("T1059.004").read_text())
    doc["engine_args"] = args
    path = tmp_path / "x.yaml"
    path.write_text(yaml.safe_dump(doc))
    res = ScenarioParser().validate(str(path))
    assert not res.valid and any("engine_args must be a mapping" in e for e in res.errors)


def test_the_catalog_decides_the_engine_args():
    ttp, ref = "T1059.004", PAIRS["T1059.004"][1]
    own = _entry(ttp)["engine_args"]
    assert catalog_destructive(ttp, engine="atomic", engine_ref=ref, engine_args=own) is False
    # Another value, one more, one less, none, no mapping: not what the catalog vouched for.
    for other in ({**own, "host": "127.0.0.2"}, {"host": own["host"]}, None, ["x"]):
        assert catalog_destructive(ttp, engine="atomic", engine_ref=ref, engine_args=other) is None
    # An entry without engine_args takes none.
    cron = PAIRS["T1053.003"][1]
    assert catalog_destructive("T1053.003", engine="atomic", engine_ref=cron) is True
    assert catalog_destructive("T1053.003", engine="atomic", engine_ref=cron,
                               engine_args={"command": "/tmp/evil.sh"}) is None


def _variant(tmp_path, ttp, **changes) -> Path:
    doc = yaml.safe_load(_scenario(ttp).read_text())
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    path = tmp_path / "variant.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def test_a_scenario_with_other_engine_args_is_destructive_never_in_production(tmp_path, monkeypatch):
    """A non-destructive technique played with arguments the catalog does not set is unknown,
    so destructive: refused in production (SEC5, V-19)."""
    args = {"host": "127.0.0.2", "script_path": "/tmp/eregion-t1059-art.sh"}
    path = _variant(tmp_path, "T1059.004", engine_args=args, destructive=None)
    executor = _executor(PROD_TAGS)
    out = _run(tmp_path, monkeypatch, path, executor)
    assert out.refused and "destructive technique never runs in production" in out.error
    executor.run_command.assert_not_called()


def test_a_scenario_calling_other_engine_args_harmless_is_refused_everywhere(tmp_path, monkeypatch):
    args = {"host": "127.0.0.2", "script_path": "/tmp/eregion-t1059-art.sh"}
    path = _variant(tmp_path, "T1059.004", engine_args=args)   # keeps destructive: false
    out = _run(tmp_path, monkeypatch, path, _executor())
    assert out.refused and "the catalog decides" in out.error


# ── B1: the campaign synthesizer plays the catalog's engine_args ──────────────────────

def _synthesize(tmp_path, ttp, allow_destructive=False):
    entry = load_catalog()[ttp]
    return synthesize(entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(subscription_id="sub-1"),
                      out_dir=tmp_path, seq=1, allow_destructive=allow_destructive)


def test_a_campaign_on_the_shell_technique_pings_the_loopback(tmp_path):
    res = _synthesize(tmp_path, "T1059.004")
    assert res.ok, res.reason
    s = ScenarioParser().load(str(res.path))
    assert s.engine_args == _entry("T1059.004")["engine_args"]
    command = resolve_ref(s.engine_ref, s.engine_args).command
    assert "8.8.8.8" not in command and "127.0.0.1" in command
    assert catalog_destructive(s.mitre, engine=s.engine, engine_ref=s.engine_ref,
                               engine_args=s.engine_args) is False


def test_a_campaign_on_log_clearing_targets_the_disposable_path(tmp_path):
    assert not _synthesize(tmp_path, "T1070.002").ok   # destructive: the budget must allow it
    res = _synthesize(tmp_path, "T1070.002", allow_destructive=True)
    assert res.ok, res.reason
    s = ScenarioParser().load(str(res.path))
    assert s.engine_args == {"log_path": "/var/log/eregion-t1070-disposable.log"}
    r = resolve_ref(s.engine_ref, s.engine_args)
    assert "echo 0> /var/log/eregion-t1070-disposable.log" in r.command
    assert "rm -f /var/log/eregion-t1070-disposable.log" in r.cleanup_command


def test_a_campaign_on_cron_needs_the_destructive_budget(tmp_path):
    res = _synthesize(tmp_path, "T1053.003")
    assert not res.ok and "destructive" in res.reason


# ── The scenarios validate, resolve, and run what the catalog vouched for ─────────────

def test_scenarios_validate_resolve_and_carry_the_catalog_args():
    for ttp, (scn, ref, _rule) in PAIRS.items():
        path = SCENARIOS / f"{scn}.yaml"
        res = ScenarioParser().validate(str(path))
        assert res.valid, (ttp, res.errors)
        s = ScenarioParser().load(str(path))
        assert s.engine == "atomic" and s.engine_ref == ref and s.steps == []
        assert (s.engine_args or {}) == (_entry(ttp).get("engine_args") or {}), ttp
        r = resolve_ref(s.engine_ref, s.engine_args or None)
        for probe in (s.raw.get("steady_state") or {}).get("probes") or []:
            assert "#{" not in r.substitute(probe["verify"]), ttp


def _probe_executor(after: str = "ABSENT TMP_ABSENT"):
    """A bench executor answering each probe by its phase: clean before, broken right after the
    command (the effect), `after` once cleaned up."""
    ex = _executor()

    def run_command(cmd, label=""):
        if "(before)" in label:
            return "ABSENT TMP_ABSENT"
        if "(effect)" in label:
            return "PRESENT TMP_PRESENT"
        if "(after)" in label:
            return after
        return ""
    ex.run_command.side_effect = run_command
    return ex


def _sent(ex) -> list[str]:
    return [c.args[0] for c in ex.run_command.call_args_list]


def test_the_shell_scenario_runs_the_loopback_ping(tmp_path, monkeypatch):
    ex = _probe_executor()
    out = _run(tmp_path, monkeypatch, _scenario("T1059.004"), ex)
    assert not out.error, out.error
    atomic = next(c for c in _sent(ex) if "ping -c 4" in c)
    assert "127.0.0.1" in atomic and "8.8.8.8" not in atomic
    assert "/tmp/eregion-t1059-art.sh" in atomic


def test_the_log_scenario_overwrites_the_disposable_path_only(tmp_path, monkeypatch):
    ex = _probe_executor()
    out = _run(tmp_path, monkeypatch, _scenario("T1070.002"), ex)
    assert not out.error, out.error
    sent = _sent(ex)
    assert "#!/bin/bash\necho 0> /var/log/eregion-t1070-disposable.log" in sent
    assert not any("/var/log/secure" in c and "echo 0>" in c for c in sent)


def test_the_cron_scenario_checks_the_tmp_files_before_and_after(tmp_path, monkeypatch):
    """B3: /tmp/notevil (root's crontab, reinstalled by the cleanup) and /tmp/persistevil absent
    before — a planted file is refused — and the after-check says the cleanup left them."""
    doc = yaml.safe_load(_scenario("T1053.003").read_text())
    probe = next(p for p in doc["steady_state"]["probes"] if p["name"] == "tmp-files-absent")
    assert "/tmp/notevil" in probe["verify"] and "#{tmp_cron}" in probe["verify"]
    ex = _probe_executor(after="ABSENT TMP_PRESENT")   # the upstream cleanup leaves them
    out = _run(tmp_path, monkeypatch, _scenario("T1053.003"), ex)
    assert out.error == "initial state not restored"
    probes = [c for c in _sent(ex) if "/tmp/notevil" in c and "TMP_ABSENT" in c]
    assert probes and all("/tmp/persistevil" in c for c in probes)

    planted = _probe_executor()
    planted.run_command.side_effect = lambda cmd, label="": "ABSENT TMP_PRESENT"
    out = _run(tmp_path, monkeypatch, _scenario("T1053.003"), planted)
    assert out.error == "initial state not clean before the atomic"
    assert not any("crontab /tmp/persistevil" in c for c in _sent(planted))


# ── The blue side: each rule fires on a realistic line and not on benign noise ────────

NOW = dt.datetime.now(dt.timezone.utc)


def _row(**k):
    k.setdefault("TimeGenerated", NOW)
    k.setdefault("Computer", "gondolin")
    k.setdefault("_ResourceId", "/subs/x/gondolin")
    return k


def _run_rule(rule_name: str, rows: list[dict]) -> list[dict]:
    return kql_subset.run(RULES[rule_name]["query"], rows, NOW)


def test_cron_rule_fires_on_crontab_replace():
    rows = [_row(Facility="cron", ProcessName="crontab", SyslogMessage="(root) REPLACE (root)")]
    assert len(_run_rule(CRON_RULE, rows)) == 1


def test_cron_rule_ignores_benign_noise():
    benign = [
        _row(Facility="cron", ProcessName="CRON", SyslogMessage="(root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)"),
        _row(Facility="cron", ProcessName="CRON", SyslogMessage="(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"),
        _row(Facility="cron", ProcessName="crontab", SyslogMessage="(root) LIST (root)"),
        _row(Facility="cron", ProcessName="anacron", SyslogMessage="Job `cron.daily' started"),
        _row(Facility="authpriv", ProcessName="CRON", SyslogMessage="pam_unix(cron:session): session opened for user root(uid=0)"),
    ]
    assert _run_rule(CRON_RULE, benign) == []


def _audit(serial, *records):
    return [_row(Facility="local6", ProcessName="audisp-syslog",
                 SyslogMessage=f"type={kind} msg=audit(1730800000.{serial}:{serial}): {body}")
            for kind, body in records]


def _tamper(serial, exe, *paths, comm="x", nametype="CREATE"):
    syscall = ("SYSCALL", f'arch=c000003e syscall=257 success=yes exit=3 items={len(paths) + 1} '
                          f'auid=4294967295 uid=0 euid=0 comm="{comm}" exe="{exe}" key="log_tamper"')
    parent = ("PATH", 'item=0 name="/var/log/" inode=1 nametype=PARENT')
    entries = [("PATH", f'item={i + 1} name="{p}" inode={i + 2} nametype={nametype}')
               for i, p in enumerate(paths)]
    return _audit(serial, syscall, parent, *entries)


def test_log_tamper_rule_fires_on_the_atomic_write():
    rows = _tamper(4567, "/usr/bin/dash", "/var/log/eregion-t1070-disposable.log", comm="dash")
    [hit] = _run_rule(TAMPER_RULE, rows)
    assert hit["Writer"] == ["/usr/bin/dash"]
    assert hit["Paths"] == ["/var/log/eregion-t1070-disposable.log"]


@pytest.mark.parametrize("exe,path,comm", [
    # comm is the attacker's to choose: a shell named like rsyslog is still a shell
    ("/usr/bin/bash", "/var/log/auth.log", "rsyslogd"),
    # a known writer outside its own files
    ("/usr/sbin/sshd", "/var/log/auth.log", "sshd"),
    ("/usr/bin/python3.10", "/var/log/auth.log", "waagent"),
    ("/usr/sbin/useradd", "/var/log/syslog", "useradd"),
])
def test_log_tamper_rule_judges_the_writer_by_exe_and_its_files(exe, path, comm):
    rows = _tamper(5001, exe, path, comm=comm, nametype="NORMAL")
    assert len(_run_rule(TAMPER_RULE, rows)) == 1


def test_log_tamper_rule_keeps_a_known_writer_whose_entry_is_unread():
    """An event with a SYSCALL and no entry read is kept (fail closed)."""
    rows = _audit(5002, ("SYSCALL", 'success=yes comm="sshd" exe="/usr/sbin/sshd" key="log_tamper"'))
    assert len(_run_rule(TAMPER_RULE, rows)) == 1


def test_log_tamper_rule_ignores_realistic_benign_noise():
    benign = (
        # rsyslog's main thread: comm in hex (« rs:main Q:Reg »), exe readable
        _tamper(6001, "/usr/sbin/rsyslogd", "/var/log/syslog", comm="72733A6D61696E20513A526567", nametype="NORMAL")
        + _tamper(6002, "/usr/lib/systemd/systemd-journald", "/var/log/journal/abc/system.journal", nametype="NORMAL")
        + _tamper(6003, "/usr/sbin/logrotate", "/var/log/syslog.1", nametype="CREATE")
        # sshd and logins: wtmp, btmp, lastlog
        + _tamper(6004, "/usr/sbin/sshd", "/var/log/btmp", nametype="NORMAL")
        + _tamper(6005, "/usr/lib/openssh/sshd-session", "/var/log/wtmp", "/var/log/lastlog", nametype="NORMAL")
        # useradd: lastlog and faillog
        + _tamper(6006, "/usr/sbin/useradd", "/var/log/lastlog", "/var/log/faillog", nametype="NORMAL")
        # the Azure agent and its extensions
        + _tamper(6007, "/usr/bin/python3.10", "/var/log/waagent.log", comm="python3", nametype="NORMAL")
        + _tamper(6008, "/opt/microsoft/azuremonitoragent/bin/mdsd",
                  "/var/log/azure/Microsoft.Azure.Monitor.AzureMonitorLinuxAgent/extension.log", nametype="NORMAL")
        # apt's cron and unattended-upgrades
        + _tamper(6009, "/usr/bin/dpkg", "/var/log/dpkg.log", nametype="NORMAL")
        + _tamper(6010, "/usr/bin/apt-get", "/var/log/apt/history.log", nametype="NORMAL")
        + _tamper(6011, "/usr/bin/python3.10", "/var/log/unattended-upgrades/unattended-upgrades.log", nametype="NORMAL")
    )
    assert _run_rule(TAMPER_RULE, benign) == []


def test_a_log_tamper_card_is_never_taken_for_an_account_creation():
    """useradd's name in a record does not make the card characterized (account_creation)."""
    [hit] = _run_rule(TAMPER_RULE, _tamper(7001, "/usr/sbin/useradd", "/var/log/syslog", comm="useradd",
                                           nametype="NORMAL"))
    assert "SyslogMessage" not in hit
    assert has_recognized_indicator(hit, "T1070.002") is False


def test_log_tamper_records_are_bounded():
    rows = _audit(7002, ("SYSCALL", 'comm="dash" exe="/usr/bin/dash" key="log_tamper" ' + "x" * 5000),
                  ("PATH", 'item=1 name="/var/log/z.log" nametype=CREATE'))
    [hit] = _run_rule(TAMPER_RULE, rows)
    assert all(len(r) <= 1000 for r in hit["Records"])


def _shell_event(serial, *argv, comm="sh"):
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return _audit(serial,
                  ("SYSCALL", f'euid=0 auid=4294967295 comm="{comm}" exe="/usr/bin/dash" key="shell_exec"'),
                  ("EXECVE", f"argc={len(argv)} {args}"))


def test_shell_rule_fires_on_script_from_tmp():
    assert len(_run_rule(SHELL_RULE, _shell_event(7777, "sh", "/tmp/eregion-t1059-art.sh"))) == 1


@pytest.mark.parametrize("argv", [("bash", "-x", "/tmp/x.sh"), ("sh", "-c", "/dev/shm/y")])
def test_shell_rule_fires_on_a_script_after_an_option(argv):
    assert len(_run_rule(SHELL_RULE, _shell_event(7778, *argv))) == 1


def test_shell_rule_ignores_benign_script_locations():
    benign = (
        _shell_event(8001, "/bin/sh", "/var/lib/dpkg/info/foo.postinst", "configure")
        # logrotate's postrotate: sh -c '<command>' — a command of several words, written in hex
        + _audit(8002, ("SYSCALL", 'comm="sh" exe="/usr/bin/dash" key="shell_exec"'),
                 ("EXECVE", 'argc=3 a0="/bin/sh" a1="-c" a2=73797374656D63746C2072656C6F6164'))
        + _shell_event(8003, "/bin/sh", "/etc/cron.daily/logrotate")
        + _shell_event(8004, "sh", "/usr/bin/unattended-upgrade", "/tmp/not-the-script")
    )
    assert _run_rule(SHELL_RULE, benign) == []


def test_shell_rows_are_bounded_and_told_apart_by_their_event():
    """Two events at the same instant stay two (C3), each record kept to 1000 characters."""
    rows = (_shell_event(9001, "sh", "/tmp/a.sh") + _shell_event(9002, "sh", "/tmp/b.sh")
            + _audit(9003, ("SYSCALL", 'comm="sh" exe="/usr/bin/dash" key="shell_exec"'),
                     ("EXECVE", 'argc=2 a0="sh" a1="/tmp/' + "c" * 4000 + '"')))
    hits = _run_rule(SHELL_RULE, rows)
    assert len(hits) == 3 and all("SyslogMessage" not in h for h in hits)
    assert len({_row_identity(h) for h in hits}) == 3
    assert all(len(r) <= 1000 for h in hits for r in h["Execve"] + h["Syscall"])


# ── C1: the AUD1 human-root reading stays the default for every T1059.004 rule ────────

def _unreadable_row():
    # No SYSCALL/EXECVE: the human-root reading cannot read it → an 'unreadable' card.
    return {"Computer": "vm1", "TimeGenerated": "2026-11-05T10:00:00Z", "Foo": "bar"}


@pytest.mark.parametrize("name", ["auditd-sensitive-root-command", "client-root-shell-rule"])
def test_every_t1059_rule_keeps_the_human_root_reading(name):
    """The shipped human-root rule and a client rule under any other name: read, fail closed."""
    rule = _make_rule(name=name, ttp=auditd.TTP, query="Syslog | limit 1")
    p, sent = _poller(_Det([_unreadable_row()]), [rule])
    p.poll_once(rule)
    assert sent and "AuditRead" in sent[0]["raw_signal"]["first_result_row"]


def test_only_the_exempt_shell_rule_is_read_as_it_comes():
    assert auditd.EXEMPT_RULES == frozenset({SHELL_RULE}) and SHELL_RULE in RULES
    assert RULES[SHELL_RULE]["ttp"] == auditd.TTP
    shell = _make_rule(name=SHELL_RULE, ttp=auditd.TTP, query="Syslog | limit 1")
    p, sent = _poller(_Det([_unreadable_row()]), [shell])
    p.poll_once(shell)
    assert sent and "AuditRead" not in sent[0]["raw_signal"]["first_result_row"]
    assert auditd.reads("anything-else", auditd.TTP) and not auditd.reads(SHELL_RULE, auditd.TTP)
    assert not auditd.reads("auditd-sensitive-root-command", "T1070.002")


# ── The proposed telemetry: the cron facility off by default, the auditd rules a script ──

def test_cron_facility_proposed_off_by_default():
    variables = (ROOT / "infra/terraform/variables.tf").read_text()
    body = variables.split('variable "cron_logs_enabled"')[1].split("}")[0]
    assert "default     = false" in body
    mon = (ROOT / "infra/terraform/monitoring.tf").read_text()
    assert 'var.cron_logs_enabled ? ["cron"] : []' in mon


def test_vm3_auditd_rules_are_a_script_not_terraform():
    script = (ROOT / "infra/terraform/scripts/vm3_auditd.sh").read_text()
    assert "-w /var/log -p wa -k log_tamper" in script
    assert "-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dash -k shell_exec" in script
    assert "augenrules --load" in script and "systemctl restart auditd" not in script.split("set -euo")[1]
    # Not wired: no Terraform file, no variable that would say otherwise (C4).
    assert not (ROOT / "infra/terraform/vm3_auditd.tf").exists()
    tf = "".join(p.read_text() for p in (ROOT / "infra/terraform").glob("*.tf"))
    assert "vm3_auditd" not in tf


def test_the_engine_never_runs_a_refused_engine_arg(tmp_path, monkeypatch):
    path = _variant(tmp_path, "T1059.004", engine_args={"host": "127.0.0.1;reboot",
                                                        "script_path": "/tmp/eregion-t1059-art.sh"})
    ex = MagicMock()
    out = _run(tmp_path, monkeypatch, path, ex)
    assert out.refused and "not a plain value" in out.error
    ex.run_command.assert_not_called()
