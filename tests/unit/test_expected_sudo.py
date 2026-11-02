"""ADM1 (#284): the administrators' expected sudo — set aside before the decision, never silent.

A sudo to root of an account expected on its VM (`expected_sudo.admins` in
glorfindel-config.yaml) opens no card, unless its command is sensitive; each one set aside is
journaled and counted (`glorfindel report`, the console). Read here on sudo's real forms —
`authpriv`, fields separated by spaces as the agent writes them, no TTY, `sudo -i`,
`sudo su -`, `sudo -u other` — through the shipped rule run as written (`kql_subset`), then
the RulePoller.

Every account and name is made up (repository public): admin1, ops, mallory, vm-example-01.
No Azure, no model.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from glorfindel import expected_sudo
from glorfindel.config import (
    ConfigError,
    ExpectedAdmins,
    ExpectedSudoConfig,
    GlorfindelConfig,
    load_glorfindel_config,
)
from glorfindel.detection_rules import DetectionRule, RulePoller, shipped_rules_path

from . import kql_subset

SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
SUB = "00000000-0000-0000-0000-0000000000bb"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"
VM2 = VM.replace("vm-example-01", "vm-example-02")
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now():
    global NOW
    NOW = datetime.now(timezone.utc)


def _policy(**over) -> ExpectedSudoConfig:
    return ExpectedSudoConfig(admins=over.get("admins", [ExpectedAdmins("vm-example-*", ["admin1", "ops"])]),
                              sensitive_commands=over.get("sensitive", []))


def _cfg_file(tmp_path, text: str) -> Path:
    p = tmp_path / "glorfindel-config.yaml"
    p.write_text(text)
    return p


# ── The config, read strictly (A3) ───────────────────────────────────────────────

_GOOD = """
expected_sudo:
  admins:
    - match: "vm-web-*"
      accounts: [admin1, ops]
    - match: "VM-Example-01"
      accounts: [deploy, "someone@example.com"]
  sensitive_commands:
    - crontab
"""


def test_the_expected_admins_are_read(tmp_path):
    es = load_glorfindel_config(_cfg_file(tmp_path, _GOOD)).expected_sudo
    assert [(a.match, a.accounts) for a in es.admins] == [
        ("vm-web-*", ["admin1", "ops"]), ("VM-Example-01", ["deploy", "someone@example.com"])]
    assert es.sensitive_commands == ["crontab"]
    assert es.accounts_for("vm-web-03") == {"admin1", "ops"}
    assert es.accounts_for("vm-example-01") == {"deploy", "someone@example.com"}   # case ignored
    assert es.accounts_for("vm-db-01") == frozenset() and es.accounts_for("") == frozenset()


def test_every_entry_that_names_a_vm_counts():
    es = ExpectedSudoConfig(admins=[ExpectedAdmins("vm-*", ["ops"]), ExpectedAdmins("vm-db-01", ["dba"])])
    assert es.accounts_for("vm-db-01") == {"ops", "dba"} and es.accounts_for("vm-web-01") == {"ops"}


def test_no_section_expects_nobody(tmp_path):
    cfg = load_glorfindel_config(_cfg_file(tmp_path, "never_block: []\n"))
    assert cfg.expected_sudo.admins == [] and cfg.expected_sudo.sensitive_commands == []


@pytest.mark.parametrize("text,said", [
    ("expected_sudo:\n  admin: []\n", "expected_sudo.admin : clé inconnue"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      account: [admin1]\n",
     "expected_sudo.admins[0].account : clé inconnue"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n", "expected_sudo.admins[0].accounts : obligatoire"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: []\n", "au moins un compte"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: admin1\n",
     "expected_sudo.admins[0].accounts : une liste est attendue"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: [\"admin*\"]\n",
     "expected_sudo.admins[0].accounts[0] : \"admin*\" n'est pas un nom de compte"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: [\"admin 1\"]\n", "n'est pas un nom de compte"),
    ("expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: [1000]\n", "un texte est attendu"),
    ("expected_sudo:\n  admins:\n    - accounts: [admin1]\n", "expected_sudo.admins[0].match : obligatoire"),
    ("expected_sudo:\n  admins:\n    - vm-1\n", "une table (match, accounts) est attendue"),
    ("expected_sudo:\n  admins: vm-1\n", "expected_sudo.admins : une liste"),
    ("expected_sudo: [admin1]\n", "expected_sudo : une table"),
    ("expected_sudo:\n  sensitive_commands: [\"  \"]\n", "expected_sudo.sensitive_commands[0] : un texte vide"),
    ("expected_sudo:\n  sensitive_commands: crontab\n", "expected_sudo.sensitive_commands : une liste"),
])
def test_a_form_nobody_reads_refuses_the_file(tmp_path, text, said):
    with pytest.raises(ConfigError) as exc:
        load_glorfindel_config(_cfg_file(tmp_path, text))
    assert said in str(exc.value)


def test_the_example_s_commented_section_loads(tmp_path):
    """The section the example shows in comments, uncommented, passes the strict reading."""
    example = (Path(__file__).resolve().parents[2] / "glorfindel-config.yaml.example").read_text()
    block = example.split("expected_sudo:", 1)[1].split("\n# ──", 1)[0]
    text = "expected_sudo:" + re.sub(r"^(\s*)# ", r"\1", block, flags=re.M)
    text = text.replace("admins: []", "admins:").replace("sensitive_commands: []", "sensitive_commands:")
    es = load_glorfindel_config(_cfg_file(tmp_path, text)).expected_sudo
    assert es.admins and all(a.accounts for a in es.admins) and es.sensitive_commands


# ── sudo's line, read as the shipped rule reads it ───────────────────────────────

@pytest.mark.parametrize("message,account,command", [
    ("admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/usr/bin/apt update", "admin1", "/usr/bin/apt update"),
    # the agent's form: the fields separated by spaces
    ("admin1 : TTY=pts/0   PWD=/home/admin1   USER=root   COMMAND=/usr/bin/apt update", "admin1", "/usr/bin/apt update"),
    # no terminal (cron, a script)
    ("ops : PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx", "ops", "/usr/bin/systemctl restart nginx"),
    ("ops : PWD=/   USER=root   COMMAND=/usr/bin/systemctl restart nginx", "ops", "/usr/bin/systemctl restart nginx"),
    # sudo -i, sudo su -
    ("admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/bin/bash", "admin1", "/bin/bash"),
    ("admin1 : TTY=pts/1 ; PWD=/home/admin1 ; USER=root ; COMMAND=/usr/bin/su -", "admin1", "/usr/bin/su -"),
    # an ENV= field, a GROUP= field, leading spaces
    ("   admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; ENV=A=b ; COMMAND=/opt/backup.sh", "admin1", "/opt/backup.sh"),
    ("admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; GROUP=docker ; COMMAND=/usr/bin/id", "admin1", "/usr/bin/id"),
])
def test_an_expected_admin_s_sudo_to_root_is_expected(message, account, command):
    entry = expected_sudo.judge({"SyslogMessage": message, "TimeGenerated": "t"}, "vm-example-01", _policy())
    assert entry == {"asset": "vm-example-01", "account": account, "command": command, "logged_at": "t"}


@pytest.mark.parametrize("message", [
    # sudo -u other: no escalation to root
    "admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=postgres ; COMMAND=/usr/bin/psql",
    "admin1 : PWD=/   USER=postgres   COMMAND=/usr/bin/psql",
    # another account
    "mallory : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/apt update",
    "admin10 : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/apt update",
    # sudo's failures, its other lines
    "admin1 : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    "admin1 : command not allowed ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    "admin1 : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    "pam_unix(sudo:session): session opened for user root(uid=0) by admin1(uid=1000)",
    # another program's prefix, no field before the command
    "sudo:   admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
    "admin1 : USER=root ; COMMAND=/bin/sh",
    # a PWD that names a command before USER=: the run-as cannot be read — a card
    "admin1 : TTY=pts/0 ; PWD=/tmp/x COMMAND=/bin/true ; USER=root ; COMMAND=/bin/sh",
    # a PWD that writes another USER=: the run-as is not root alone — a card
    "admin1 : TTY=pts/0 ; PWD=/x USER=postgres ; USER=root ; COMMAND=/bin/true",
    "",
])
def test_what_is_not_an_expected_sudo_stays_a_card(message):
    assert expected_sudo.judge({"SyslogMessage": message}, "vm-example-01", _policy()) is None


def test_an_expected_account_on_another_vm_is_a_card():
    msg = "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update"
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-db-01", _policy()) is None
    assert expected_sudo.judge({"SyslogMessage": msg}, "", _policy()) is None        # no VM claims it


def test_no_list_expects_nobody():
    msg = "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update"
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-example-01", None) is None
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-example-01", ExpectedSudoConfig()) is None
    assert expected_sudo.judge({"SyslogMessage": 42}, "vm-example-01", _policy()) is None


@pytest.mark.parametrize("command,category", [
    ("/usr/bin/cat /etc/shadow", "shadow"),
    ("/usr/bin/cat shadow", "shadow"),                        # cd /etc first
    ("/usr/bin/cp /etc/gshadow /tmp/g", "shadow"),
    ("/bin/bash -c cat /etc/shadow", "shadow"),               # through a shell
    ("/usr/sbin/useradd -m mallory", "accounts"),
    ("/usr/sbin/usermod -aG sudo mallory", "accounts"),
    ("/usr/bin/passwd", "accounts"),                         # root's own password
    ("/usr/bin/passwd ops", "accounts"),
    ("/usr/sbin/userdel ops", "accounts"),
    ("/usr/bin/tee -a /etc/sudoers.d/zz", "sudoers"),
    ("/usr/sbin/visudo", "sudoers"),
    ("/usr/bin/chmod u+s /tmp/x", "setuid"),
    ("/usr/bin/chmod +s /tmp/x", "setuid"),
    ("/usr/bin/chmod -R g+s /srv", "setuid"),
    ("/usr/bin/chmod 4755 /tmp/x", "setuid"),
    ("/usr/bin/chmod 02755 /tmp/x", "setuid"),
    ("/usr/sbin/setcap cap_setuid+ep /tmp/x", "capabilities"),
    ("/usr/bin/systemctl stop azuremonitoragent", "supervision"),
    ("/usr/bin/systemctl disable --now auditd", "supervision"),
    ("/usr/sbin/service rsyslog stop", "supervision"),
    ("/usr/bin/apt remove -y mdatp", "supervision"),
    ("/usr/bin/pkill -f omsagent", "supervision"),
    ("/usr/sbin/auditctl -e 0", "audit"),
    ("/usr/bin/rm -f /var/log/auth.log", "logs"),
    ("/bin/sh -c > /var/log/syslog", "logs"),
    ("/usr/bin/journalctl --vacuum-time=1s", "logs"),
    ("/usr/bin/tee -a /root/.ssh/authorized_keys", "ssh_keys"),
    ("/usr/bin/vi /etc/pam.d/sshd", "pam"),
    ("/usr/bin/tee /etc/ld.so.preload", "preload"),
])
def test_a_sensitive_command_of_an_expected_admin_is_a_card(command, category):
    assert expected_sudo.sensitive(command) == category
    msg = f"admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND={command}"
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-example-01", _policy()) is None
    spaced = f"admin1 : PWD=/home/admin1   USER=root   COMMAND={command}"
    assert expected_sudo.judge({"SyslogMessage": spaced}, "vm-example-01", _policy()) is None


@pytest.mark.parametrize("command", [
    "/usr/bin/apt update", "/usr/bin/systemctl restart rsyslog", "/usr/bin/chmod 755 /srv/app",
    "/usr/bin/chmod +x deploy.sh", "/usr/bin/ls /var/log", "/usr/bin/journalctl -u nginx",
    "/usr/bin/cat /etc/hosts", "/bin/bash", "/usr/bin/su -", "/usr/bin/docker ps",
])
def test_an_everyday_command_is_not_sensitive(command):
    assert expected_sudo.sensitive(command) is None


def test_a_pwd_never_hides_the_real_command():
    """sudo writes COMMAND last: a PWD that holds « ; USER=root ; COMMAND=/bin/true » leaves the
    real command in what follows the first COMMAND= — read whole."""
    msg = ("admin1 : TTY=pts/0 ; PWD=/tmp/x ; USER=root ; COMMAND=/bin/true ; USER=root ; "
           "COMMAND=/usr/bin/cat /etc/shadow")
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-example-01", _policy()) is None


def test_a_command_that_writes_command_equals_is_read_whole():
    """The command is everything after the FIRST COMMAND=: one that holds « COMMAND=/bin/ls »
    after its sensitive part is not read as /bin/ls."""
    msg = ("admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; "
           "COMMAND=/bin/sh -c cat /etc/shadow; echo ;COMMAND=/bin/ls")
    assert expected_sudo.judge({"SyslogMessage": msg}, "vm-example-01", _policy()) is None


def test_the_config_extends_the_sensitive_commands_never_replaces_them():
    pol = _policy(sensitive=["CronTab"])
    cron = "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/crontab -e"
    shadow = "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    assert expected_sudo.judge({"SyslogMessage": cron}, "vm-example-01", _policy()) is not None
    assert expected_sudo.judge({"SyslogMessage": cron}, "vm-example-01", pol) is None
    assert expected_sudo.sensitive("/usr/bin/crontab -e", pol.sensitive_commands) == "config: CronTab"
    assert expected_sudo.judge({"SyslogMessage": shadow}, "vm-example-01", pol) is None


# ── The poller: before any signal, journaled, counted ────────────────────────────

def _line(message: str, minutes_ago: float = 1, facility: str = "authpriv", computer: str = "vm-example-01",
          rid: str = VM) -> dict:
    return {"Type": "Syslog", "TimeGenerated": NOW - timedelta(minutes=minutes_ago), "Facility": facility,
            "ProcessName": "sudo", "SyslogMessage": message, "Computer": computer, "_ResourceId": rid}


class _Registry:
    def __init__(self, names=("vm-example-01",)):
        self.assets = [type("A", (), {"name": n, "resource_id": VM.replace("vm-example-01", n)})() for n in names]

    def for_backend(self, _name):
        return self.assets


class _Kql:
    def __init__(self, lines, rows=None):
        self.lines, self.rows = lines, rows

    def run_query(self, query, timespan=None):
        return list(self.rows) if self.rows is not None else kql_subset.run(query, self.lines, now=NOW)


def _poller(lines, cfg: GlorfindelConfig | None, rule_name="sudo-privilege-escalation", rows=None,
            names=("vm-example-01",)):
    r = SHIPPED[rule_name]
    rule = DetectionRule(name=r["name"], source="azure_monitor", workspace_id="ws", query=r["query"],
                         ttp=r["ttp"], resource_id="", interval_s=30, auto_apply=True,
                         monitoring_backend_name="law")
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _r: _Kql(lines, rows)
    p._registry = _Registry(names)
    p._cfg = cfg
    return p, rule, sent


def _cfg(**over) -> GlorfindelConfig:
    return GlorfindelConfig(expected_sudo=_policy(**over))


ADMIN = "admin1 : TTY=pts/0   PWD=/home/admin1   USER=root   COMMAND=/usr/bin/apt update"
ADMIN_I = "admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/bin/bash"
ADMIN_SU = "ops : PWD=/home/ops   USER=root   COMMAND=/usr/bin/su -"
INTRUDER = "mallory : PWD=/tmp   USER=root   COMMAND=/bin/sh"


def _journal() -> list[dict]:
    p = expected_sudo._JOURNAL
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_an_expected_sudo_opens_no_card_and_is_counted():
    p, rule, sent = _poller([_line(ADMIN, 3), _line(ADMIN_I, 2), _line(ADMIN_SU, 1)], _cfg())
    assert p.poll_once(rule) == [] and sent == []
    [snap] = p.status_snapshot()
    assert snap["expected_count"] == 3 and snap["expected_last"] and snap["match_count"] == 0
    assert sorted((e["account"], e["command"], e["asset"], e["rule"]) for e in _journal()) == [
        ("admin1", "/bin/bash", "vm-example-01", rule.name),
        ("admin1", "/usr/bin/apt update", "vm-example-01", rule.name),
        ("ops", "/usr/bin/su -", "vm-example-01", rule.name)]
    # the same lines at the next poll: neither a card nor counted again
    assert p.poll_once(rule) == [] and p.status_snapshot()[0]["expected_count"] == 3 and len(_journal()) == 3


def test_the_count_adds_up_across_polls():
    lines = [_line(ADMIN, 3)]
    p, rule, sent = _poller(lines, _cfg())
    p.poll_once(rule)
    lines.append(_line(ADMIN_I, 1))
    p.poll_once(rule)
    assert p.status_snapshot()[0]["expected_count"] == 2 and len(_journal()) == 2 and sent == []


@pytest.mark.parametrize("cfg", [GlorfindelConfig(), None])
def test_without_a_list_every_sudo_is_a_card_as_before(cfg):
    p, rule, sent = _poller([_line(ADMIN)], cfg)
    assert len(p.poll_once(rule)) == 1 and _journal() == []
    assert p.status_snapshot()[0]["expected_count"] == 0


def test_an_admin_s_later_sudo_never_hides_another_account_s():
    """A line tagged sudo can be written by any local user: an expected one after an
    intruder's, in the same window, used to be the only row of the VM (arg_max by VM)."""
    p, rule, sent = _poller([_line(INTRUDER, 3), _line(ADMIN, 1)], _cfg())
    [sig] = p.poll_once(rule)
    assert sig["raw_signal"]["first_result_row"]["SyslogMessage"] == INTRUDER
    assert p.status_snapshot()[0]["expected_count"] == 1


@pytest.mark.parametrize("message", [
    "admin1 : TTY=pts/0   PWD=/home/admin1   USER=root   COMMAND=/usr/bin/cat /etc/shadow",
    "admin1 : PWD=/   USER=root   COMMAND=/usr/sbin/usermod -aG sudo mallory",
    "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl stop azuremonitoragent",
])
def test_an_expected_admin_s_sensitive_command_is_a_card(message):
    p, rule, sent = _poller([_line(message)], _cfg())
    [sig] = p.poll_once(rule)
    assert sig["raw_signal"]["first_result_row"]["SyslogMessage"] == message
    assert p.status_snapshot()[0]["expected_count"] == 0 and _journal() == []


@pytest.mark.parametrize("facility", ["auth", "authpriv"])
def test_both_facilities(facility):
    p, rule, sent = _poller([_line(ADMIN, facility=facility)], _cfg())
    assert p.poll_once(rule) == [] and p.status_snapshot()[0]["expected_count"] == 1


def test_an_expected_admin_on_a_vm_where_it_is_not_expected_is_a_card():
    cfg = _cfg(admins=[ExpectedAdmins("vm-example-01", ["admin1"])])
    lines = [_line(ADMIN, computer="vm-example-02", rid=VM2)]
    p, rule, sent = _poller(lines, cfg, names=("vm-example-01", "vm-example-02"))
    [sig] = p.poll_once(rule)
    assert sig["context"]["asset_name"] == "vm-example-02"


def test_a_row_no_vm_claims_is_a_card():
    row = {"TimeGenerated": NOW.isoformat(), "Computer": "", "_ResourceId": "", "SyslogMessage": ADMIN}
    p, rule, sent = _poller([], _cfg(), rows=[row])
    [sig] = p.poll_once(rule)
    assert sig["context"]["attribution"] == "unattributed"


def test_a_journal_that_cannot_be_written_excludes_nothing(monkeypatch, tmp_path):
    (tmp_path / "a-directory").mkdir()
    monkeypatch.setattr(expected_sudo, "_JOURNAL", tmp_path / "a-directory")
    p, rule, sent = _poller([_line(ADMIN)], _cfg())
    assert len(p.poll_once(rule)) == 1 and p.status_snapshot()[0]["expected_count"] == 0


def test_another_technique_s_rule_is_not_filtered():
    row = {"TimeGenerated": NOW.isoformat(), "Computer": "vm-example-01", "_ResourceId": VM, "SyslogMessage": ADMIN}
    p, rule, sent = _poller([], _cfg(), rule_name="ssh-brute-force", rows=[row])
    assert len(p.poll_once(rule)) == 1


def test_an_expected_sudo_does_not_eat_the_card_budget_of_another_vm():
    lines = [_line(ADMIN, 2)] + [_line(INTRUDER, 1, computer="vm-example-02", rid=VM2)]
    p, rule, sent = _poller(lines, _cfg(), names=("vm-example-01", "vm-example-02"))
    [sig] = p.poll_once(rule)
    assert sig["context"]["asset_name"] == "vm-example-02"


# ── Never silent: the report and the console ─────────────────────────────────────

def _entry(at: datetime, asset="vm-example-01", account="admin1", command="/usr/bin/apt update") -> str:
    return json.dumps({"at": at.isoformat(), "rule": "sudo-privilege-escalation", "asset": asset,
                       "account": account, "command": command, "logged_at": ""}) + "\n"


def test_the_summary_counts_the_period_per_vm_and_account():
    expected_sudo._JOURNAL.parent.mkdir(parents=True, exist_ok=True)
    expected_sudo._JOURNAL.write_text(
        _entry(NOW - timedelta(days=10)) + _entry(NOW - timedelta(hours=2)) + "not json\n"
        + _entry(NOW - timedelta(hours=1), asset="vm-example-02", account="ops"))
    s = expected_sudo.summary(NOW - timedelta(days=1))
    assert s["count"] == 2 and s["by_asset"] == {"vm-example-01": 1, "vm-example-02": 1}
    assert s["by_account"] == {"admin1": 1, "ops": 1} and s["unreadable"] == 1
    assert s["journal_from"].startswith((NOW - timedelta(days=10)).isoformat()[:16])
    assert [e["account"] for e in s["latest"]] == ["admin1", "ops"]
    assert expected_sudo.summary(None)["count"] == 3


def test_an_unreadable_journal_is_said(monkeypatch, tmp_path):
    (tmp_path / "d").mkdir()
    monkeypatch.setattr(expected_sudo, "_JOURNAL", tmp_path / "d")
    s = expected_sudo.summary(None)
    assert s["error"] and s["count"] == 0


def test_the_journal_keeps_its_newest_half_past_its_size(monkeypatch):
    monkeypatch.setattr(expected_sudo, "_JOURNAL_MAX_BYTES", 2000)
    for i in range(30):
        assert expected_sudo.record([{"asset": "vm-example-01", "account": "admin1", "command": f"/bin/c{i}",
                                      "logged_at": ""}], "r", (NOW + timedelta(seconds=i)).isoformat())
    lines = expected_sudo._JOURNAL.read_text().splitlines()
    assert expected_sudo._JOURNAL.stat().st_size <= 2000 and json.loads(lines[-1])["command"] == "/bin/c29"
    assert json.loads(lines[0])["command"] != "/bin/c0"
    assert expected_sudo.summary(None)["journal_from"] == json.loads(lines[0])["at"]


def test_the_report_says_the_expected_sudo(monkeypatch):
    from glorfindel.cli import cli
    expected_sudo._JOURNAL.parent.mkdir(parents=True, exist_ok=True)
    expected_sudo._JOURNAL.write_text(_entry(NOW - timedelta(hours=1))
                                      + _entry(NOW, account="ops", command="/usr/bin/echo [bold]x[/bold]"))
    out = CliRunner().invoke(cli, ["report", "--json"])
    assert out.exit_code == 0, out.output
    es = json.loads(out.output)["expected_sudo"]
    assert es["count"] == 2 and es["by_account"] == {"admin1": 1, "ops": 1}
    text = CliRunner().invoke(cli, ["report"])
    assert text.exit_code == 0, text.output
    said = " ".join(text.output.split())            # the terminal's width wraps the lines
    assert "Expected sudo (no card, ADM1): 2" in said
    assert "per VM: vm-example-01 2" in said and "per account: admin1 1, ops 1" in said
    assert "[bold]x[/bold]" in said                 # a log's text, never read as markup


def test_the_console_shows_the_count(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from glorfindel.detection_rules import _save_status
    from .console_client import console
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    _save_status({"sudo-privilege-escalation": {"expected_sudo": {"count": 4, "last": NOW.isoformat()}}})
    rules = console().get("/api/config").json()["detection"]["rules"]
    [sudo] = [r for r in rules if r["name"] == "sudo-privilege-escalation"]
    assert sudo["expected_count"] == 4 and sudo["expected_last"] == NOW.isoformat()
    assert all(r["expected_count"] == 0 for r in rules if r["name"] != "sudo-privilege-escalation")
