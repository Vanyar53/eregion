"""SEC2: detection rules and the IP block, against log lines that anyone can write.

The shipped Syslog rules run as written (`tests/unit/kql_subset.py`, a KQL subset in
memory) on lines shaped like those of sshd and sudo, and on lines written by something
else. Then what Glorfindel does with what they return: the address a block would take,
the addresses never blocked, one card per address, a proposed rule never in the place of
a shipped one, the rules' floor interval, `${VAR}` in documented fields only, a cap of
cards per rule and poll for every source.

Every identifier is made up (repository public): documentation addresses (RFC 5737),
00000000-… GUIDs, example names. No Azure, no model.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from glorfindel import config, escalations
from glorfindel.detection_rules import (
    MIN_INTERVAL_S,
    DetectionRule,
    RulePoller,
    _DATA_CARDS_PER_POLL,
    load_config,
    shipped_rule_names,
    shipped_rules_path,
)

from . import kql_subset

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    """NOW is the clock when each test starts, not when this file was imported: a long suite
    (the CI's) no longer ages it past the windows and heartbeats the code under test compares
    with its own clock (SEC6, P-08)."""
    global NOW
    NOW = datetime.now(timezone.utc)
SUB = "00000000-0000-0000-0000-0000000000bb"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"
PEER = "198.51.100.7"         # the address that really connects
NAMED = "203.0.113.5"         # an address written in the line by the client


def _line(message: str, process: str = "sshd", facility: str = "auth", minutes_ago: float = 1) -> dict:
    return {"Type": "Syslog", "TimeGenerated": NOW - timedelta(minutes=minutes_ago), "Facility": facility,
            "ProcessName": process, "SyslogMessage": message, "Computer": "vm-example-01", "_ResourceId": VM}


def _ssh(rows):
    return kql_subset.run(SHIPPED["ssh-brute-force"]["query"], rows, now=NOW)


def _sudo(rows):
    return kql_subset.run(SHIPPED["sudo-privilege-escalation"]["query"], rows, now=NOW)


def _attempts(fmt: str, n: int = 10, **kw) -> list[dict]:
    return [_line(fmt.format(port=40000 + i), **kw) for i in range(n)]


# ── ssh-brute-force ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fmt", [
    f"Failed password for root from {PEER} port {{port}} ssh2",
    f"Failed password for invalid user admin from {PEER} port {{port}} ssh2",
    f"Invalid user admin from {PEER} port {{port}}",
    f"message repeated 2 times: [ Failed password for root from {PEER} port {{port}} ssh2]",
])
@pytest.mark.parametrize("process", ["sshd", "sshd-session"])
def test_sshd_failures_are_counted_by_the_peer_address(fmt, process):
    assert _ssh(_attempts(fmt, process=process)) == [
        {"SourceIP": PEER, "Computer": "vm-example-01", "_ResourceId": VM, "FailedAttempts": 10}]


def test_a_line_written_before_authentication_is_counted():
    # sshd's ` [preauth]` suffix, as measured: the address is still the last of the line.
    fmt = (f"error: maximum authentication attempts exceeded for invalid user alice from {PEER} "
           "port {port} ssh2 [preauth]")
    assert [r["SourceIP"] for r in _ssh(_attempts(fmt))] == [PEER]
    fmt = (f"error: maximum authentication attempts exceeded for invalid user x from {NAMED} port 22 "
           f"ssh2 [preauth] from {PEER} port {{port}} ssh2 [preauth]")
    assert [r["SourceIP"] for r in _ssh(_attempts(fmt))] == [PEER]


@pytest.mark.parametrize("fmt", [
    f"Invalid user x from {NAMED} port 22 from {PEER} port {{port}}",
    f"Failed password for invalid user x from {NAMED} port 22 ssh2 from {PEER} port {{port}} ssh2",
    f"Failed password for invalid user from{NAMED} from {PEER} port {{port}} ssh2",
    f"Invalid user {NAMED} from {PEER} port {{port}}",
])
def test_an_address_in_the_user_name_is_never_the_peer(fmt):
    rows = _ssh(_attempts(fmt))
    assert [r["SourceIP"] for r in rows] == [PEER]


def test_a_line_that_ends_without_sshd_s_own_field_names_no_peer():
    # Truncated, or not sshd's wording: no address taken from the middle of it.
    assert _ssh(_attempts(f"Invalid user x from {NAMED} port 22 and more")) == []


@pytest.mark.parametrize("process", ["root", "sudo", "cron", "", None])
def test_lines_of_another_program_are_not_sshd_s(process):
    # Written with sshd's words by something else — `logger`, a service, an application.
    rows = _attempts(f"sshd[4242]: Failed password for root from {NAMED} port {{port}} ssh2", process=process)
    assert _ssh(rows) == []


def test_the_threshold_and_the_private_ranges_are_unchanged():
    assert _ssh(_attempts(f"Failed password for root from {PEER} port {{port}} ssh2", n=9)) == []
    for private in ("10.1.2.3", "172.20.0.4", "192.168.1.9", "127.0.0.1"):
        assert _ssh(_attempts(f"Failed password for root from {private} port {{port}} ssh2")) == []
    assert _ssh(_attempts(f"Failed password for root from {PEER} port {{port}} ssh2", minutes_ago=11)) == []


# ── sudo-privilege-escalation ────────────────────────────────────────────────────

_SUDO_OK = "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"


@pytest.mark.parametrize("facility", ["auth", "authpriv"])
@pytest.mark.parametrize("message", [
    "alice : PWD=/home/alice   USER=root   COMMAND=/usr/bin/id",             # as the agent writes it
    "  alice : TTY=pts/0   PWD=/home/alice   USER=root   COMMAND=/bin/sh",
])
def test_the_agent_s_form_of_a_sudo_to_root_is_an_escalation(message, facility):
    [row] = _sudo([_line(message, process="sudo", facility=facility)])
    assert row["SyslogMessage"] == message


@pytest.mark.parametrize("message", [
    _SUDO_OK,
    "alice : PWD=/srv ; USER=root ; COMMAND=/bin/sh",
    "svc-backup : TTY=pts/1 ; PWD=/tmp ; USER=root ; ENV=A=b ; COMMAND=/opt/scripts/backup.sh /dev/null",
    "deploy : PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart app",       # no terminal (cron)
])
def test_a_sudo_to_root_is_an_escalation(message):
    [row] = _sudo([_line(message, process="sudo")])
    assert row["SyslogMessage"] == message and row["_ResourceId"] == VM


@pytest.mark.parametrize("message,process", [
    # another program's line holding sudo's words (a user name, a command line, an app log)
    (f"Invalid user sudo : TTY=x ; USER=root ; COMMAND=/bin/sh from {PEER} port 22", "sshd"),
    ("alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "sshd"),
    ("sudo[1]:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "root"),
    ("alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", None),
    # sudo's own lines that are no escalation
    ("alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "sudo"),
    ("pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", "sudo"),
    ("pam_unix(sudo:auth): authentication failure; logname= uid=1001 USER=root COMMAND=x", "sudo"),
    ("alice : TTY=pts/0 ; PWD=/ ; USER=bob ; COMMAND=/bin/sh", "sudo"),
    ("unable to resolve host vm-example-01: USER=root COMMAND=/bin/sh", "sudo"),
    # sudo's failures, in its form: no escalation happened
    ("alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "sudo"),
    ("alice : command not allowed ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh", "sudo"),
    ("alice : 3 incorrect password attempts   TTY=pts/0   PWD=/   USER=root   COMMAND=/bin/sh", "sudo"),
    ("alice : PWD=/   USER=bob   COMMAND=/bin/sh", "sudo"),
])
def test_what_is_not_a_sudo_to_root(message, process):
    assert _sudo([_line(message, process=process)]) == []


# ── Annatar's simulations write as the daemons do ────────────────────────────────

def _logged(script: str, **values) -> list[dict]:
    """The lines a simulation script's `logger` calls write: (tag → ProcessName, text)."""
    rows = []
    for m in re.finditer(r'logger -p (\S+) (?:-t (\S+) )?(?:--id=\S+ )?"([^"]*)"',
                         (ROOT / "scripts" / "vm" / script).read_text()):
        facility, tag, text = m.group(1).split(".")[0], m.group(2), m.group(3)
        for k, v in values.items():
            text = text.replace("${" + k + "}", v)
        rows.append(_line(text, process=tag or "root", facility=facility))
    return rows


def test_the_ssh_simulation_is_still_detected():
    rows = []
    for port in range(25):
        rows += _logged("lateral_movement_sim.sh", ATTACKER_IP=PEER, port=str(40000 + port))
    assert [r["SourceIP"] for r in _ssh(rows)] == [PEER]


def test_the_sudo_simulation_is_still_detected():
    rows = _sudo(_logged("privilege_escalation_sim.sh", ATTACKER_USER="svc-backup"))
    assert len(rows) == 1 and "USER=root ; COMMAND=" in rows[0]["SyslogMessage"]


def test_the_investigation_finds_the_simulation_s_root_commands():
    # What `investigate` puts before the model on a T1548 detection: sudo's lines are
    # tagged sudo, the word is not in their message (SEC2).
    from glorfindel.agent import _IQ_ROOT_COMMANDS
    rows = _logged("privilege_escalation_sim.sh", ATTACKER_USER="svc-backup")
    rows.append(_line("x : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/forged", process="root"))
    out = kql_subset.run(_IQ_ROOT_COMMANDS.format(vm="vm-example-01"), rows, now=NOW)
    assert any("COMMAND=/bin/cat /etc/shadow" in r["SyslogMessage"] for r in out)
    assert not any("/bin/forged" in r["SyslogMessage"] for r in out)


def test_the_investigation_finds_sudo_s_lines_in_authpriv():
    from glorfindel.agent import _IQ_ROOT_COMMANDS
    rows = [_line("alice : PWD=/home/alice   USER=root   COMMAND=/bin/cat /etc/shadow",
                  process="sudo", facility="authpriv")]
    out = kql_subset.run(_IQ_ROOT_COMMANDS.format(vm="vm-example-01"), rows, now=NOW)
    assert [r["SyslogMessage"] for r in out] == [rows[0]["SyslogMessage"]]


def test_the_investigation_reads_sshd_s_successful_logins_only():
    from glorfindel.agent import _IQ_SUCCESS_AUTH
    rows = [_line(f"Accepted password for alice from {PEER} port 41000 ssh2"),
            _line(f"Accepted password for x from {PEER} port 41001 ssh2", process="root"),
            _line(f"Invalid user Accepted from {PEER} port 41002")]
    out = kql_subset.run(_IQ_SUCCESS_AUTH.format(vm="vm-example-01", ip=PEER), rows, now=NOW)
    assert [r["SyslogMessage"] for r in out] == [rows[0]["SyslogMessage"]]


# ── From the rule to the block ───────────────────────────────────────────────────

class _Registry:
    def __init__(self):
        self.assets = [type("A", (), {"name": "vm-example-01", "resource_id": VM})()]

    def for_backend(self, _name):
        return self.assets


class _Kql:
    """A detector that runs the rule's query over the lines in memory."""
    def __init__(self, lines):
        self.lines = lines

    def run_query(self, query, timespan=None):
        return kql_subset.run(query, self.lines, now=NOW)


def _poll(lines, rule_name="ssh-brute-force"):
    r = SHIPPED[rule_name]
    rule = DetectionRule(name=r["name"], source="azure_monitor", workspace_id="ws", query=r["query"],
                         ttp=r["ttp"], resource_id="", interval_s=30, auto_apply=True,
                         monitoring_backend_name="law")
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _r: _Kql(lines)
    p._registry = _Registry()
    p.poll_once(rule)
    return sent


def test_the_block_takes_the_peer_never_an_address_of_the_user_name():
    from glorfindel.agent import _extract_suspicious_ip
    lines = _attempts(f"Invalid user x from {NAMED} port 22 from {PEER} port {{port}}")
    lines += _attempts(f"sshd[1]: Failed password for root from {NAMED} port {{port}} ssh2", process="root")
    [signal] = _poll(lines)
    assert _extract_suspicious_ip(signal) == PEER


def test_an_sshd_line_with_sudo_s_words_is_no_escalation_signal():
    lines = [_line(f"Invalid user x : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh from {PEER} port 22")]
    assert _poll(lines, "sudo-privilege-escalation") == []
    assert len(_poll([_line(_SUDO_OK, process="sudo")], "sudo-privilege-escalation")) == 1


# ── Never blocked ────────────────────────────────────────────────────────────────

@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    path = tmp_path / "glorfindel-config.yaml"
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [path])
    return path


@pytest.mark.parametrize("ip", ["168.63.129.16", "169.254.169.254", "10.0.0.9", "172.31.255.1",
                                "192.168.0.1", "127.0.0.1", "100.64.0.1", "fd00::1",
                                "::ffff:168.63.129.16", "::ffff:10.0.0.1"])
def test_the_shipped_addresses_are_never_blockable(ip, cfg_file):
    from glorfindel.response.policy import protected_by, blockable_ip
    assert protected_by(ip)                      # what decide holds on
    with pytest.raises(ValueError):              # what every connector refuses
        blockable_ip(ip)


def test_an_ipv4_written_as_ipv6_is_that_ipv4(cfg_file):
    from glorfindel.response.policy import ProtectedAddressError, blockable_ip
    cfg_file.write_text("never_block: [203.0.113.77]\n")
    with pytest.raises(ProtectedAddressError):
        blockable_ip("::ffff:203.0.113.77")
    assert blockable_ip("2001:db8::1") == "2001:db8::1"


def test_the_config_adds_its_own_and_others_stay_blockable(cfg_file):
    from glorfindel.response.policy import ProtectedAddressError, blockable_ip
    cfg_file.write_text("never_block:\n  - 198.51.100.0/28\n  - 203.0.113.77\n")
    assert config.load_glorfindel_config().never_block == ["198.51.100.0/28", "203.0.113.77/32"]
    for ip in ("198.51.100.7", "203.0.113.77"):
        with pytest.raises(ProtectedAddressError):
            blockable_ip(ip)
    assert blockable_ip("198.51.100.16") == "198.51.100.16"
    assert blockable_ip(NAMED) == NAMED


def test_an_unreadable_config_blocks_nothing(cfg_file):
    from glorfindel.response.policy import ProtectedAddressError, blockable_ip
    cfg_file.write_text("never_blok: []\n")
    with pytest.raises(ProtectedAddressError, match="illisible"):
        blockable_ip(NAMED)


@pytest.mark.parametrize("text,said", [
    ("never_block: 198.51.100.7\n", "une liste"),
    ("never_block: [not-an-address]\n", "ni une adresse"),
    ("never_block: [0.0.0.0/0]\n", "mode d'autonomie"),
    ("never_block: ['::/0']\n", "mode d'autonomie"),
    ("never_block: [42]\n", "texte"),
])
def test_never_block_is_read_strictly(text, said, cfg_file):
    cfg_file.write_text(text)
    with pytest.raises(config.ConfigError, match=said):
        config.load_glorfindel_config()


def test_the_example_config_reads_with_its_never_block():
    assert config.load_glorfindel_config(ROOT / "glorfindel-config.yaml.example").never_block == []


def test_the_azure_connector_refuses_before_any_write(cfg_file, monkeypatch):
    from glorfindel.actions import AzureConnector
    from glorfindel.response.policy import ProtectedAddressError
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    c = AzureConnector(dry_run=False)
    monkeypatch.setattr(c, "_guard_write", lambda *_a: pytest.fail("a write was attempted"))
    monkeypatch.setattr(c, "_ensure_clients", lambda *_a: pytest.fail("Azure was reached"))
    for scope in ("vm", "subnet"):
        with pytest.raises(ProtectedAddressError):
            c.block_suspicious_ip("168.63.129.16", VM, scope=scope)


def test_the_aws_connector_refuses_before_any_write(cfg_file, monkeypatch):
    from glorfindel.providers.aws.connector import AwsConnector
    from glorfindel.response.policy import ProtectedAddressError
    from .fake_aws import ACCOUNT, REGION, FakeAws, arn
    c = AwsConnector(ec2=FakeAws(), account=ACCOUNT, region=REGION, read_only=False)
    monkeypatch.setattr(c, "_guard_write", lambda *_a: pytest.fail("a write was attempted"))
    with pytest.raises(ProtectedAddressError):
        c.block_suspicious_ip("168.63.129.16", arn("i-web1"))


def _block_state(ip: str) -> dict:
    from .test_agent_nodes import _state
    st = _state()
    st["signal"]["raw_signal"]["first_result_row"] = {"SourceIP": ip, "Computer": "vm-example-01",
                                                      "FailedAttempts": 40}
    st["signal"]["context"]["rule_name"] = "ssh-brute-force"
    return st


def test_decide_holds_a_block_of_a_protected_address_whatever_the_model_says(cfg_file):
    from glorfindel.agent import _HELD_BY_TYPE, decide
    from glorfindel.config import AutonomyConfig
    from .test_agent_nodes import _mock_llm_response
    cfg_file.write_text(f"never_block: [{NAMED}]\n")
    for ip in ("168.63.129.16", NAMED):
        with patch("litellm.completion", return_value=_mock_llm_response("block_suspicious_ip", confidence=0.99)):
            out = decide(_block_state(ip), model="claude-test", autonomy=AutonomyConfig(default="non_disruptive"))
        assert out["escalate"] is True and out["held_by"] == "never_block", out
        assert ip in out["escalation_reason"] and "never_block" in out["escalation_reason"]
    assert _HELD_BY_TYPE["never_block"] == "protected_address"
    assert "protected_address" in escalations._ESCALATION_LABELS
    with patch("litellm.completion", return_value=_mock_llm_response("block_suspicious_ip", confidence=0.99)):
        out = decide(_block_state(PEER), model="claude-test", autonomy=AutonomyConfig(default="non_disruptive"))
    assert out["held_by"] != "never_block"


def test_an_earlier_hold_keeps_its_words_and_the_card_says_the_address(cfg_file):
    from glorfindel.agent import _apply_never_block_guard
    d = {"action": "block_suspicious_ip", "escalate": True, "held_by": "confidence",
         "escalation_reason": "Low confidence (40%)"}
    _apply_never_block_guard(d, _block_state("10.0.0.9")["signal"])
    assert d["held_by"] == "never_block" and "10.0.0.9" in d["escalation_reason"]
    assert "Low confidence" in d["escalation_reason"]


# ── One card per address (V-09) ──────────────────────────────────────────────────

def test_two_addresses_on_one_vm_are_two_cards():
    a = escalations.record("s1", VM, "block_suspicious_ip", "mode_hold", "held", action_params={"ip": NAMED})
    b = escalations.record("s2", VM, "block_suspicious_ip", "mode_hold", "held", action_params={"ip": PEER})
    c = escalations.record("s3", VM, "block_suspicious_ip", "mode_hold", "held", action_params={"ip": PEER})
    assert a != b and b == c
    cards = {e["action_params"]["ip"]: e for e in escalations.pending()}
    assert set(cards) == {NAMED, PEER} and cards[PEER]["occurrences"] == 2


# ── A proposed rule never takes a shipped rule's place (N-02) ─────────────────────

def _propose(name="ssh-brute-force", interval_s=30.0, query="Syslog | where SyslogMessage has \"x\"\n"):
    from glorfindel.proposed_rules import record
    return record(run_id="r", ttp="T1110.001", resource_id="", rule_name=name, source="azure_monitor",
                  workspace_id="", query=query, interval_s=interval_s, explanation="e", confidence=0.9,
                  analysis="a")


def test_a_proposal_named_like_a_shipped_rule_is_renamed():
    from glorfindel.proposed_rules import all_proposals
    assert {"ssh-brute-force", "sudo-privilege-escalation"} <= shipped_rule_names()
    _propose()
    [p] = all_proposals()
    assert p["rule_name"] == "ssh-brute-force-proposed" and p["renamed_from"] == "ssh-brute-force"


def test_its_approval_leaves_the_shipped_rule_loaded(tmp_path):
    from glorfindel.proposed_rules import approve
    out = approve(_propose(), shipped_rules_path())
    assert out["rule_name"] == "ssh-brute-force-proposed" and out["replaces"] == ""
    cfg = load_config(shipped_rules_path())
    rules = {r.name: r for r in cfg.rules}
    assert rules["ssh-brute-force"].layer == "base" and rules["ssh-brute-force"].query == SHIPPED["ssh-brute-force"]["query"]
    assert rules["ssh-brute-force-proposed"].layer == "client" and cfg.overrides == []


def test_a_proposal_recorded_before_the_suffix_is_approved_under_its_own_name():
    from glorfindel import proposed_rules
    _propose(name="mine")
    stored = [json.loads(line) for line in proposed_rules._STORE.read_text().splitlines()]
    stored[0]["rule_name"] = "sudo-privilege-escalation"            # as recorded before SEC2
    proposed_rules._STORE.write_text(json.dumps(stored[0]) + "\n")
    out = proposed_rules.approve(stored[0]["id"], shipped_rules_path())
    assert out["rule_name"] == "sudo-privilege-escalation-proposed"
    assert out["renamed_from"] == "sudo-privilege-escalation"
    assert {r.name: r.layer for r in load_config(shipped_rules_path()).rules}["sudo-privilege-escalation"] == "base"


def test_replacing_a_client_rule_is_said_before_and_at_approval():
    from glorfindel import rule_layers
    from glorfindel.proposed_rules import approve, pending
    rule_layers.write_client_rule({"name": "log-clearing", "assets": ["auto"], "query": "Syslog\n"})
    pid = _propose(name="log-clearing")
    assert [p["replaces"] for p in pending()] == ["client"]
    out = approve(pid, shipped_rules_path())
    assert out["replaces"] == "client" and out["replaced_rule"]["query"] == "Syslog\n"


def test_cli_approve_and_pending_say_it(tmp_path):
    from click.testing import CliRunner
    from glorfindel import rule_layers
    from glorfindel.cli import cli
    rule_layers.write_client_rule({"name": "log-clearing", "assets": ["auto"], "query": "Syslog\n"})
    _propose(name="log-clearing")
    pid = _propose()
    out = CliRunner().invoke(cli, ["pending"], catch_exceptions=False).output
    assert "remplace la règle « log-clearing »" in out and "renommée" in out
    out = CliRunner().invoke(cli, ["approve-rule", pid, "--rules", str(shipped_rules_path())],
                             catch_exceptions=False).output
    assert "shipped rule stays" in out


def test_a_client_rule_in_a_shipped_rule_s_place_is_said_loudly():
    from click.testing import CliRunner
    from glorfindel import rule_layers
    from glorfindel.cli import cli
    rule_layers.write_client_rule({"name": "ssh-brute-force", "assets": ["auto"], "query": "Syslog\n"})
    cfg = load_config(shipped_rules_path())
    assert cfg.overrides == ["ssh-brute-force"]
    assert [r.replaces_base for r in cfg.rules if r.name == "ssh-brute-force"] == [True]
    assert not any(r.replaces_base for r in cfg.rules if r.name != "ssh-brute-force")
    out = CliRunner().invoke(cli, ["rules", "--rules", str(shipped_rules_path())], catch_exceptions=False).output
    assert "client (remplace)" in out and "Règle livrée « ssh-brute-force » remplacée" in out


@pytest.mark.parametrize("how", ["disable", "enabled_false"])
def test_a_shipped_rule_turned_off_by_the_client_is_said_loudly(how):
    from click.testing import CliRunner
    from glorfindel.cli import cli
    from glorfindel.detection_rules import client_rules_path
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(
        "disable: [sudo-privilege-escalation]\n" if how == "disable" else
        "rules:\n  - name: sudo-privilege-escalation\n    enabled: false\n")
    cfg = load_config(shipped_rules_path())
    assert cfg.disabled_base == ["sudo-privilege-escalation"] and cfg.overrides == []
    out = CliRunner().invoke(cli, ["rules", "--rules", str(shipped_rules_path())], catch_exceptions=False).output
    assert "Règle livrée « sudo-privilege-escalation » désactivée" in out


def test_without_a_client_layer_nothing_is_said_turned_off():
    assert load_config(shipped_rules_path()).disabled_base == []


# ── The floor interval, ${VAR} (V-14) ────────────────────────────────────────────

@pytest.mark.parametrize("interval", [1, 15, 29.9])
def test_a_client_rule_under_the_floor_polls_at_the_floor_never_faster(interval, tmp_path):
    # Refusing it would drop a rule approved before SEC2 (proposals asked 10–120 s) from
    # the detection: it keeps detecting, at the floor, and that is said.
    from glorfindel.detection_rules import client_rules_path
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(f"rules:\n  - name: fast\n    interval_s: {interval}\n    query: Syslog\n")
    cfg = load_config(shipped_rules_path())
    [rule] = [r for r in cfg.rules if r.name == "fast"]
    assert rule.interval_s == MIN_INTERVAL_S
    assert any("fast" in n and "minimum" in n for n in cfg.notes)


@pytest.mark.parametrize("interval", [0, -5, ".inf", ".nan"])
def test_a_client_interval_that_means_nothing_is_refused(interval, tmp_path):
    from glorfindel.detection_rules import client_rules_path
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(f"rules:\n  - name: odd\n    interval_s: {interval}\n    query: Syslog\n")
    cfg = load_config(shipped_rules_path())
    assert "odd" not in {r.name for r in cfg.rules}
    assert any("odd" in n and "positif" in n for n in cfg.notes)


def test_the_authoring_schema_asks_for_the_floor():
    from glorfindel import detection_authoring
    text = Path(detection_authoring.__file__).read_text()
    assert "(30–120)" in text and "(10–120)" not in text


def test_a_legacy_rule_under_the_floor_polls_at_the_floor(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text("rules:\n  - name: inline\n    workspace_id: ws\n    resource_id: /x/vm\n"
                    "    assets: [vm]\n    interval_s: 1\n    query: Syslog\n")
    cfg = load_config(base, client_layer=False)
    [rule] = cfg.rules
    assert rule.interval_s == MIN_INTERVAL_S and any("minimum" in n for n in cfg.notes)


def test_every_shipped_rule_polls_at_or_above_the_floor():
    assert all(float(r.get("interval_s", 30)) >= MIN_INTERVAL_S for r in SHIPPED.values())


def test_a_proposed_interval_is_raised_to_the_floor():
    from glorfindel.proposed_rules import all_proposals, rule_from_proposal
    _propose(name="mine", interval_s=1)
    [p] = all_proposals()
    assert p["interval_s"] == MIN_INTERVAL_S
    assert rule_from_proposal({**p, "interval_s": 1}, shipped_rules_path())["interval_s"] == MIN_INTERVAL_S


def test_env_vars_are_expanded_in_documented_fields_only(tmp_path, monkeypatch):
    from glorfindel.detection_rules import client_rules_path
    monkeypatch.setenv("SEC2_TEST_VALUE", "expanded")
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(
        "rules:\n  - name: mine\n    workspace_id: ${SEC2_TEST_VALUE}\n    description: d ${SEC2_TEST_VALUE}\n"
        "    query: |\n      Syslog | where SyslogMessage has \"${SEC2_TEST_VALUE}\" or SyslogMessage has \"$SEC2_TEST_VALUE\"\n")
    [rule] = [r for r in load_config(shipped_rules_path()).rules if r.name == "mine"]
    assert rule.workspace_id == "expanded"
    assert "${SEC2_TEST_VALUE}" in rule.query and "$SEC2_TEST_VALUE" in rule.query
    assert rule.description == "d ${SEC2_TEST_VALUE}"


# ── A cap per rule and poll, every source (V-13) ─────────────────────────────────

class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def run_query(self, query, timespan=None):
        return list(self.rows)


def _capped(rows, vms=("vm-example-01",)):
    rule = DetectionRule(name="ssh-brute-force", source="azure_monitor", workspace_id="ws",
                         query="Syslog | where TimeGenerated > ago(10m)", ttp="T1110.001", resource_id="",
                         interval_s=30, auto_apply=True, monitoring_backend_name="law")
    reg = _Registry()
    reg.assets = [type("A", (), {"name": n, "resource_id": VM.replace("vm-example-01", n)})() for n in vms]
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _r: _Rows(rows)
    p._registry = reg
    p.poll_once(rule)
    return p, rule, sent


def _attackers(n, vm="vm-example-01"):
    return [{"SourceIP": f"198.51.100.{i}", "Computer": vm, "_ResourceId": VM.replace("vm-example-01", vm),
             "FailedAttempts": 10 + i} for i in range(1, n + 1)]


def test_many_rows_on_one_vm_are_capped_then_summed_up():
    rows = _attackers(12)
    p, rule, sent = _capped(rows)
    assert len(sent) == _DATA_CARDS_PER_POLL + 1
    firsts = [s["raw_signal"]["first_result_row"] for s in sent]
    # the gravest first, each its own card
    assert [r["FailedAttempts"] for r in firsts[:_DATA_CARDS_PER_POLL]] == [22, 21, 20, 19, 18]
    omitted = firsts[-1]["OmittedRows"]
    assert firsts[-1]["OmittedCount"] == 7
    assert sorted(r["SourceIP"] for r in omitted) == sorted(r["SourceIP"] for r in rows[:7])
    # none lost, none sent twice: every row is said once, and marked sent
    said = {r["SourceIP"] for r in firsts[:-1]} | {r["SourceIP"] for r in omitted}
    assert said == {r["SourceIP"] for r in rows}
    p._detector = lambda _r: _Rows(rows)
    assert p.poll_once(rule) == []


def test_a_summary_card_carries_at_most_its_maximum_and_the_count():
    from glorfindel.detection_rules import _SUMMARY_ROWS_MAX
    rows = [{"SourceIP": f"198.51.{i // 250}.{i % 250 + 1}", "Computer": "vm-example-01",
             "_ResourceId": VM, "FailedAttempts": 10 + i} for i in range(300)]
    _, _, sent = _capped(rows)
    summary = sent[-1]["raw_signal"]["first_result_row"]
    assert summary["OmittedCount"] == 300 - _DATA_CARDS_PER_POLL
    assert len(summary["OmittedRows"]) == _SUMMARY_ROWS_MAX == 50
    # the gravest of the rest, first
    assert summary["OmittedRows"][0]["FailedAttempts"] == 10 + 299 - _DATA_CARDS_PER_POLL


def test_under_the_cap_nothing_changes():
    _, _, sent = _capped(_attackers(_DATA_CARDS_PER_POLL))
    assert len(sent) == _DATA_CARDS_PER_POLL
    assert not any("OmittedRows" in s["raw_signal"]["first_result_row"] for s in sent)


def test_past_the_cap_each_vm_still_has_its_card():
    rows = []
    for i in range(8):
        rows += _attackers(1, vm=f"vm-example-{i:02d}")
    _, _, sent = _capped(rows, vms=[f"vm-example-{i:02d}" for i in range(8)])
    assert sorted(s["context"]["asset_name"] for s in sent) == [f"vm-example-{i:02d}" for i in range(8)]
