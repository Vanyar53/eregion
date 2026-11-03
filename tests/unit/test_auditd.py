"""AUD1 (#408): what a human login does as root, read in auditd's lines — the root shell's blind spot.

ADM1 and COR1 judge a sudo to root; what is then done in the root shell is never written by sudo.
auditd's two rules (the CIS's `user_emulation`, and `root_command`: a root shell's commands, uid =
euid = 0, under the login's auid) reach Syslog through audisp-syslog (local6). The shipped rule
`auditd-sensitive-root-command` is run here as written (`kql_subset`) on lines in memory, then the
RulePoller: a command of ADM1's sensitive list makes a card that names the login account; any
other command none; a line unreadable or ambiguous a card (A0).

The records' form is the documentation's (auditd, the kernel's audit_log_untrustedstring, AMA) —
hypotheses A1–A13 in docs/operations.md, to measure on the bench. Every account and name is made
up (repository public): admin1, mallory, vm-example-01. No Azure, no model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from click.testing import CliRunner

from glorfindel import auditd, expected_sudo
from glorfindel.config import ExpectedAdmins, ExpectedSudoConfig, GlorfindelConfig
from glorfindel.detection_rules import (
    DetectionRule,
    RulePoller,
    has_recognized_indicator,
    normalize_row,
    shipped_rules_path,
)

from . import kql_subset

SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
RULE = SHIPPED["auditd-sensitive-root-command"]
SUB = "00000000-0000-0000-0000-0000000000cc"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"
VM2 = VM.replace("vm-example-01", "vm-example-02")
NOW = datetime.now(timezone.utc)
GS = "\x1d"          # the separator auditd writes before the ENRICHED fields
UNSET = 4294967295


@pytest.fixture(autouse=True)
def _now():
    global NOW
    NOW = datetime.now(timezone.utc)


def _arg(text: str) -> str:
    """An argument as the kernel writes it: in quotes, or in hex when it holds a space, a quote, a
    control character or a byte above 0x7e (audit_log_untrustedstring)."""
    if any(c in text for c in ' "') or any(ord(c) < 0x21 or ord(c) > 0x7e for c in text):
        return text.encode().hex().upper()
    return f'"{text}"'


def _stamp(serial: int) -> str:
    return f"msg=audit(1762160000.{serial % 1000:03d}:{serial}):"


def syscall(serial: int, *, auid=1001, uid=0, euid=0, key="root_command", exe="/usr/bin/cat",
            comm="cat", name="admin1", sep=GS, node="") -> str:
    """A SYSCALL record of an execve (x86_64), raw fields then the ENRICHED ones."""
    head = f"node={node} " if node else ""
    text = (f"{head}type=SYSCALL {_stamp(serial)} arch=c000003e syscall=59 success=yes exit=0 "
            f"a0=55d0c1a2b3c0 a1=55d0c1a2b400 a2=55d0c1a2b420 a3=0 items=2 ppid=2001 pid={3000 + serial} "
            f"auid={auid} uid={uid} gid=0 euid={euid} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 "
            f"comm={_arg(comm)} exe={_arg(exe)} subj=unconfined key=" + (f'"{key}"' if key else "(null)"))
    if name:
        text += (f'{sep}ARCH=x86_64 SYSCALL=execve AUID="{name}" UID="root" GID="root" EUID="root" '
                 'SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"')
    return text


def execve(serial: int, *argv: str) -> str:
    return f"type=EXECVE {_stamp(serial)} argc={len(argv)} " + " ".join(
        f"a{i}={_arg(a)}" for i, a in enumerate(argv))


def _others(serial: int) -> list[str]:
    """The records the rule does not read: the working directory, the paths, the title."""
    return [f'type=CWD {_stamp(serial)} cwd="/root"',
            f'type=PATH {_stamp(serial)} item=0 name="/usr/bin/cat" inode=1234 dev=08:01 mode=0100755 '
            "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0",
            f"type=PROCTITLE {_stamp(serial)} proctitle=636174002F6574632F736861646F77"]


def _line(message: str, minutes_ago: float = 1, facility: str = "local6", process: str = "audisp-syslog",
          computer: str = "vm-example-01", rid: str = VM) -> dict:
    return {"Type": "Syslog", "TimeGenerated": NOW - timedelta(minutes=minutes_ago), "Facility": facility,
            "ProcessName": process, "SyslogMessage": message, "Computer": computer, "_ResourceId": rid}


def event(serial: int, *argv: str, minutes_ago: float = 1, rid: str = VM, computer: str = "vm-example-01",
          **sc) -> list[dict]:
    """The lines of one exec: SYSCALL, EXECVE and the rest, as audisp-syslog sends them."""
    sc.setdefault("exe", "/usr/bin/" + argv[0].rsplit("/", 1)[-1])
    sc.setdefault("comm", argv[0].rsplit("/", 1)[-1][:15])
    return [_line(m, minutes_ago, rid=rid, computer=computer)
            for m in [syscall(serial, **sc), execve(serial, *argv), *_others(serial)]]


def _rows(lines: list[dict]) -> list[dict]:
    return kql_subset.run(RULE["query"], lines, now=NOW)


class _Registry:
    def __init__(self, names=("vm-example-01",)):
        self.assets = [type("A", (), {"name": n, "resource_id": VM.replace("vm-example-01", n)})() for n in names]

    def for_backend(self, _name):
        return self.assets


class _Kql:
    def __init__(self, lines):
        self.lines = lines

    def run_query(self, query, timespan=None):
        return kql_subset.run(query, self.lines, now=NOW)


def _poller(lines, cfg: GlorfindelConfig | None = None, names=("vm-example-01",), rule=RULE):
    r = DetectionRule(name=rule["name"], source="azure_monitor", workspace_id="ws", query=rule["query"],
                      ttp=rule["ttp"], resource_id="", interval_s=60, auto_apply=True,
                      monitoring_backend_name="law")
    sent: list = []
    p = RulePoller([r], sent.append)
    p._detector = lambda _r: _Kql(lines)
    p._registry = _Registry(names)
    p._cfg = cfg
    return p, r, sent


def _card(sig: dict) -> dict:
    return sig["raw_signal"]["first_result_row"]


# ── The rule as written: one row per exec of a human login as root ───────────────

def test_a_root_shell_s_command_is_one_row_with_its_two_records():
    [row] = _rows(event(7, "cat", "/etc/shadow"))
    assert row["Computer"] == "vm-example-01" and row["_ResourceId"] == VM and row["AuditEvent"] == "1762160000.007:7"
    assert row["Syscall"] == [syscall(7, exe="/usr/bin/cat", comm="cat")]
    assert row["Execve"] == [execve(7, "cat", "/etc/shadow")]


def test_the_cis_rule_s_lines_are_read_too():
    """sudo itself, setuid root, run by admin1: euid 0 ≠ uid 1001 — `user_emulation` (the CIS)."""
    [row] = _rows(event(8, "sudo", "cat", "/etc/shadow", key="user_emulation", uid=1001))
    assert auditd.read(row)["command"] == "sudo cat /etc/shadow"


@pytest.mark.parametrize("over", [
    {"auid": UNSET},                 # a daemon: no login
    {"auid": 0},                     # root's own login, cron's root jobs
    {"auid": 999},                   # a system account
    {"euid": 1002},                  # run as another user, not root
    {"key": "other_rule"},           # another audit rule's line
    {"key": None},                   # no key
])
def test_what_is_no_human_login_as_root_is_not_read(over):
    assert _rows(event(9, "cat", "/etc/shadow", **over)) == []


@pytest.mark.parametrize("where", [{"facility": "auth"}, {"facility": "user"},
                                   {"process": "logger"}, {"process": "sudo"}])
def test_only_the_plugin_s_lines_in_local6_are_read(where):
    lines = [_line(m, **where) for m in (syscall(10), execve(10, "cat", "/etc/shadow"))]
    assert _rows(lines) == []


def test_auditd_2_s_own_dispatcher_tag_is_read():
    lines = [_line(m, process="audispd") for m in (syscall(11), execve(11, "cat", "/etc/shadow"))]
    assert len(_rows(lines)) == 1


def test_a_line_older_than_the_window_is_not_read():
    assert _rows(event(12, "cat", "/etc/shadow", minutes_ago=11)) == []


def test_two_execs_are_two_rows_and_two_vms_two_more():
    lines = (event(13, "cat", "/etc/shadow") + event(14, "ls", "/root")
             + event(13, "cat", "/etc/shadow", rid=VM2, computer="vm-example-02"))
    assert sorted((r["Computer"], r["AuditEvent"]) for r in _rows(lines)) == [
        ("vm-example-01", "1762160000.013:13"), ("vm-example-01", "1762160000.014:14"),
        ("vm-example-02", "1762160000.013:13")]


# ── The reader: the records read whole, or a card (A0) ───────────────────────────

def _read(lines):
    [row] = _rows(lines)
    return auditd.read(row)


def test_the_login_account_its_command_and_its_session_are_read():
    said = _read(event(20, "cat", "/etc/shadow"))
    assert said["command"] == "cat /etc/shadow" and said["text"] == "/usr/bin/cat cat /etc/shadow"
    assert (said["auid"], said["account"], said["tty"], said["session"], said["key"]) == (
        1001, "admin1", "pts0", "3", "root_command")
    assert auditd.login_account(said) == "admin1 (auid 1001)"


@pytest.mark.parametrize("sep", [GS, "#035", " "])
def test_the_enriched_name_is_read_after_any_separator(sep):
    """rsyslog writes a control character as `#035` (its default escape): hypothesis A7."""
    assert _read(event(21, "cat", "/etc/shadow", sep=sep))["account"] == "admin1"


def test_without_the_enriched_fields_the_card_names_the_auid():
    said = _read(event(22, "cat", "/etc/shadow", name=""))
    assert said["account"] == "" and auditd.login_account(said) == "auid 1001 (nom absent de la ligne)"


def test_a_node_prefix_is_read():
    lines = [_line(m) for m in (syscall(23, node="vm-example-01"), "node=vm-example-01 " + execve(23, "cat", "/etc/shadow"))]
    assert _read(lines)["command"] == "cat /etc/shadow"


def test_an_argument_in_hex_is_decoded():
    said = _read(event(24, "vi", "/etc/sudoers.d/ops team"))
    assert said["command"] == "vi /etc/sudoers.d/ops team"
    assert expected_sudo.listed(said["text"]) == "sudoers"


def test_the_program_is_read_by_its_path_argv0_cannot_hide_it():
    """`exec -a vim /usr/sbin/useradd backdoor`: argv[0] is the caller's to write, exe the kernel's."""
    said = _read(event(25, "vim", "backdoor", exe="/usr/sbin/useradd", comm="useradd"))
    assert said["command"] == "vim backdoor" and expected_sudo.listed(said["text"]) == "accounts"


def test_a_path_with_a_space_in_hex_is_decoded():
    said = _read(event(26, "x", exe="/tmp/my tools/x"))
    assert said["exe"] == "/tmp/my tools/x"


@pytest.mark.parametrize("lines,why", [
    (lambda: [_line(syscall(30))], "aucun enregistrement EXECVE"),
    (lambda: [_line(syscall(31)), _line(execve(31, "ls")), _line(execve(31, "cat", "/etc/shadow"))],
     "2 enregistrements EXECVE pour un événement"),
    (lambda: [_line(syscall(32)), _line(syscall(32, exe="/usr/bin/ls")), _line(execve(32, "ls"))],
     "2 enregistrements SYSCALL pour un événement"),
    (lambda: [_line(syscall(33)), _line(f"type=EXECVE {_stamp(33)} argc=2 a0=\"cat\" a1_len=9000 a1[0]=2F")],
     "argument découpé"),
    (lambda: [_line(syscall(34)), _line(f"type=EXECVE {_stamp(34)} argc=3 a0=\"cat\" a1=\"/etc/shadow\"")],
     "argc=3, 2 argument(s) lu(s)"),
    (lambda: [_line(syscall(35)), _line(f"type=EXECVE {_stamp(35)} argc=2 a0=\"cat\" a1=ZZ")],
     "argument a1 illisible"),
    (lambda: [_line(syscall(36).replace('exe="/usr/bin/cat"', "exe=(null)")), _line(execve(36, "cat"))],
     "exe illisible"),
    (lambda: [_line(syscall(37)), _line(execve(37, "cat", "x" * 1100))], "non lue en entier"),
])
def test_what_is_not_read_whole_is_a_card(lines, why):
    said = _read(lines())
    assert why in said["why"]


def test_an_intruder_s_benign_line_at_its_own_event_s_serial_never_chooses_what_is_read():
    """Root on the VM can write a line at its own exec's serial (`logger -p local6.info -t
    audisp-syslog`): two EXECVE records for one event — a card, never the benign one read."""
    lines = event(38, "cat", "/etc/shadow") + [_line(execve(38, "ls"))]
    p, rule, sent = _poller(lines)
    [sig] = p.poll_once(rule)
    card = _card(sig)
    assert card["AuditRead"]["status"] == "unreadable" and "2 enregistrements EXECVE" in card["AuditRead"]["why"]
    assert card["LoginAccount"] == "admin1 (auid 1001)"


def test_records_of_another_event_are_not_taken_for_its_own():
    rows = _rows([_line(syscall(39)), _line(execve(40, "ls"))])
    assert len(rows) == 1 and auditd.read(rows[0])["why"] == "aucun enregistrement EXECVE"
    row = {"Syscall": [syscall(39)], "Execve": [execve(40, "ls")]}
    assert auditd.read(row)["why"] == "enregistrement EXECVE d'un autre événement"


def test_a_row_that_says_no_human_login_as_root_is_never_cleared_on_what_it_says():
    """Read again by the poller, not trusted from the query: a SYSCALL that is not a human's root
    exec (a client's rule of the same technique) is a card, never set aside as not sensitive."""
    row = {"Syscall": [syscall(41, auid=0)], "Execve": [execve(41, "ls")]}
    assert "pas une commande root d'un humain" in auditd.read(row)["why"]


@pytest.mark.parametrize("as_text", [False, True])
def test_the_records_are_read_from_a_list_or_its_json_text(as_text):
    """A dynamic column may arrive as its JSON text (hypothesis A11): both read."""
    row = {"Syscall": [syscall(42)], "Execve": [execve(42, "cat", "/etc/shadow")]}
    if as_text:
        row = {k: json.dumps(v) for k, v in row.items()}
    assert auditd.read(row)["command"] == "cat /etc/shadow"


# ── ADM1's list, the same one ────────────────────────────────────────────────────

@pytest.mark.parametrize("argv,category", [
    (("cat", "/etc/shadow"), "shadow"),
    (("useradd", "-m", "backdoor"), "accounts"),
    (("visudo",), "sudoers"),
    (("crontab", "-e"), "cron"),
    (("auditctl", "-D"), "audit"),
    (("systemctl", "stop", "auditd"), "supervision"),
    (("pkill", "audisp-syslog"), "supervision"),
    (("systemctl", "stop", "audispd"), "supervision"),
    (("tee", "-a", "/root/.ssh/authorized_keys"), "ssh_keys"),
])
def test_a_sensitive_command_in_a_root_shell_is_named_by_adm1_s_list(argv, category):
    said = _read(event(50, *argv))
    assert expected_sudo.listed(said["text"]) == category


@pytest.mark.parametrize("argv", [("bash",), ("vim", "/etc/hosts"), ("python3", "-c", "print(1)"),
                                  ("ls", "-la", "/root"), ("systemctl", "restart", "nginx")])
def test_a_shell_or_an_ordinary_command_inside_the_root_shell_is_no_card(argv):
    """A root shell inside one is no finding of itself: the shell was judged on sudo's line."""
    said = _read(event(51, *argv))
    assert expected_sudo.listed(said["text"]) is None
    assert auditd.settle(auditd.TTP, _rows(event(51, *argv)))[0] == []


def test_listed_is_sensitive_without_the_root_shell():
    assert expected_sudo.sensitive("/bin/bash") == "root_shell" and expected_sudo.listed("/bin/bash") is None
    for name, _ in expected_sudo.SENSITIVE_SHIPPED:
        assert name != "root_shell"
    assert expected_sudo.listed("/usr/local/bin/backup-restore --all", ["Backup-Restore"]) == "config: Backup-Restore"


# ── The poller: before any signal ────────────────────────────────────────────────

def test_a_sensitive_command_in_a_root_shell_is_a_card_that_names_the_login_account():
    p, rule, sent = _poller(event(60, "cat", "/etc/shadow"))
    [sig] = p.poll_once(rule)
    assert sent == [sig] and sig["ttp"] == "T1059.004" and sig["context"]["asset_name"] == "vm-example-01"
    card = _card(sig)
    assert card["LoginAccount"] == "admin1 (auid 1001)" and card["AuditCommand"] == "cat /etc/shadow"
    assert card["Sensitive"] == "shadow" and card["Exe"] == "/usr/bin/cat" and card["AuditKey"] == "root_command"
    assert (card["Tty"], card["Session"], card["Auid"]) == ("pts0", "3", 1001)
    norm = normalize_row(card, ttp=sig["ttp"])
    assert norm["indicator_key"] == "root_command" and norm["indicator_value"] == "cat /etc/shadow"
    assert has_recognized_indicator(card, sig["ttp"])


def test_an_ordinary_command_is_no_card_and_the_window_is_said():
    p, rule, sent = _poller(event(61, "ls", "/root") + event(62, "id"))
    assert p.poll_once(rule) == [] and sent == []
    [snap] = p.status_snapshot()
    assert {k: snap["auditd"][k] for k in auditd.COUNTS} == {"events": 2, "sensitive": 0, "unreadable": 0}
    assert snap["auditd"]["at"]


def test_no_line_says_zero_events():
    p, rule, sent = _poller([])
    p.poll_once(rule)
    assert p.status_snapshot()[0]["auditd"]["events"] == 0


@pytest.mark.parametrize("cfg", [None, GlorfindelConfig(),
                                 GlorfindelConfig(expected_sudo=ExpectedSudoConfig(
                                     admins=[ExpectedAdmins("vm-example-*", ["admin1"])]))])
def test_an_expected_administrator_is_held_to_the_list_as_for_sudo(cfg):
    p, rule, sent = _poller(event(63, "cat", "/etc/shadow") + event(64, "apt", "update", minutes_ago=2), cfg)
    [sig] = p.poll_once(rule)
    assert _card(sig)["Sensitive"] == "shadow" and "AuditCommands" not in _card(sig)


def test_the_config_s_sensitive_commands_extend_the_list():
    cfg = GlorfindelConfig(expected_sudo=ExpectedSudoConfig(sensitive_commands=["backup-restore"]))
    lines = event(65, "backup-restore", "--all", exe="/usr/local/bin/backup-restore")
    p, rule, sent = _poller(lines)
    assert p.poll_once(rule) == []
    p, rule, sent = _poller(lines, cfg)
    [sig] = p.poll_once(rule)
    assert _card(sig)["Sensitive"] == "config: backup-restore"


def test_two_sensitive_commands_of_one_vm_are_one_card_naming_both():
    lines = event(66, "useradd", "backdoor", exe="/usr/sbin/useradd", minutes_ago=2) + event(67, "cat", "/etc/shadow")
    p, rule, sent = _poller(lines)
    [sig] = p.poll_once(rule)
    card = _card(sig)
    assert card["AuditCommand"] == "cat /etc/shadow" and card["AuditCount"] == 2
    assert [(c["AuditCommand"], c["Sensitive"], c["LoginAccount"]) for c in card["AuditCommands"]] == [
        ("useradd backdoor", "accounts", "admin1 (auid 1001)")]


def test_two_vms_are_two_cards():
    lines = event(68, "cat", "/etc/shadow") + event(68, "cat", "/etc/shadow", rid=VM2, computer="vm-example-02")
    p, rule, sent = _poller(lines, names=("vm-example-01", "vm-example-02"))
    assert sorted(s["context"]["asset_name"] for s in p.poll_once(rule)) == ["vm-example-01", "vm-example-02"]


def test_the_same_lines_at_the_next_poll_are_no_new_card():
    lines = event(69, "cat", "/etc/shadow")
    p, rule, sent = _poller(lines)
    assert len(p.poll_once(rule)) == 1
    assert p.poll_once(rule) == [] and len(sent) == 1
    lines += event(70, "visudo")
    [sig] = p.poll_once(rule)
    assert _card(sig)["AuditCommand"] == "visudo"


def test_an_unreadable_exec_is_a_characterized_card():
    """No EXECVE record: what the command was is unknown — a card (A0), characterized, so that a
    snapshot alone still leaves one (the floor of decide)."""
    p, rule, sent = _poller([_line(syscall(71))])
    [sig] = p.poll_once(rule)
    card = _card(sig)
    assert card["AuditRead"] == {"status": "unreadable", "why": "aucun enregistrement EXECVE"}
    assert card["AuditCommand"] == "/usr/bin/cat" and has_recognized_indicator(card, sig["ttp"])
    assert p.status_snapshot()[0]["auditd"]["unreadable"] == 1


def test_another_technique_s_rows_pass_as_they_came():
    rows = _rows(event(72, "ls"))
    assert auditd.settle("T1548.003", rows) == (rows, dict.fromkeys(auditd.COUNTS, 0))


def test_a_row_of_another_form_is_left_as_it_came_and_stays_a_card():
    """A client's rule of this technique whose rows hold no audit record: unreadable, a card,
    its own columns untouched."""
    row = {"TimeGenerated": NOW, "Computer": "vm-example-01", "SyslogMessage": "something"}
    [kept], counts = auditd.settle(auditd.TTP, [row])
    assert kept["SyslogMessage"] == "something" and "AuditCommand" not in kept
    assert kept["AuditRead"]["status"] == "unreadable" and counts["unreadable"] == 1


def test_glorfindel_report_says_the_window_of_the_audit_rule():
    from glorfindel.cli import cli
    p, rule, sent = _poller(event(73, "cat", "/etc/shadow") + event(74, "ls"))
    p.poll_once(rule)
    out = CliRunner().invoke(cli, ["report"]).output
    assert "auditd (AUD1)" in out and "2 root exec(s) of a human login" in out and "1 sensitive" in out
