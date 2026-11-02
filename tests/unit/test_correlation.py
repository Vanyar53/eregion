"""COR1 (#407): the correlation, a brick of the product — two events of a VM tied together
before the decision, never in the prompt, never by the model's confidence.

1. The brick: the SSH sessions that carry a line of a VM (account, instant), read in Syslog —
   sshd's « Accepted … for <account> from <address> », sshd's pam session, the account taken
   by another (su, sudo -u, login, cron). Unreadable, cut, absent → unknown, a card (A0).
2. ADM1's root shells: set aside only if EVERY session of the account comes from an origin
   it declares (`expected_sudo.admins[].origins`); a sensitive command never.
3. A brute force followed by a login from the same address on the same VM: a critical card,
   once per address and VM.

The queries are run as written over lines in memory (`kql_subset`). Addresses of the
documentation ranges only (198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), made-up accounts
(admin1, ops, mallory) and VMs (vm-example-01). No Azure, no model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from click.testing import CliRunner

from glorfindel import correlation, expected_sudo
from glorfindel.config import (
    ConfigError,
    ExpectedAdmins,
    ExpectedSudoConfig,
    GlorfindelConfig,
    load_glorfindel_config,
)
from glorfindel.detection_rules import DetectionRule, RulePoller, _row_identity, shipped_rules_path

from . import kql_subset

SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
SUB = "00000000-0000-0000-0000-0000000000bb"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"
NOW = datetime.now(timezone.utc)

BASTION = "198.51.100.7"            # an expected origin (198.51.100.0/24)
BASTION_2 = "198.51.100.8"
STRANGER = "203.0.113.9"            # an origin nobody declared
V6_OK = "2001:db8:1::5"             # in 2001:db8:1::/48, declared
V6_KO = "2001:db8:2::5"
ORIGINS = ["198.51.100.0/24", "2001:db8:1::/48"]

SUDO_I = "admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/bin/bash"
SUDO_SU = "admin1 : TTY=pts/1   PWD=/home/admin1   USER=root   COMMAND=/usr/bin/su -"
SUDO_APT = "admin1 : TTY=pts/0 ; PWD=/home/admin1 ; USER=root ; COMMAND=/usr/bin/apt update"
SUDO_SHADOW = "admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -c cat /etc/shadow"
INTRUDER = "mallory : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"


@pytest.fixture(autouse=True)
def _now():
    global NOW
    NOW = datetime.now(timezone.utc)


def _row(message, minutes_ago=1.0, process="sudo", facility="authpriv", pid=None, computer="vm-example-01",
         rid=VM) -> dict:
    return {"Type": "Syslog", "TimeGenerated": NOW - timedelta(minutes=minutes_ago), "Facility": facility,
            "ProcessName": process, "ProcessID": pid, "SyslogMessage": message, "Computer": computer,
            "_ResourceId": rid}


def _login(ip, account="admin1", minutes_ago=20.0, pid=4100, method="publickey", process="sshd", **kw) -> list[dict]:
    """The lines of one real SSH login: sshd's Accepted and its pam session, systemd's user session."""
    return [
        _row(f"Accepted {method} for {account} from {ip} port 50022 ssh2: ED25519 SHA256:AAAA", minutes_ago,
             process=process, facility="auth", pid=pid, **kw),
        _row(f"pam_unix(sshd:session): session opened for user {account}(uid=1001) by (uid=0)",
             minutes_ago, process=process, facility="auth", pid=pid, **kw),
        _row(f"pam_unix(systemd-user:session): session opened for user {account}(uid=1001) by (uid=0)",
             minutes_ago, process="systemd", pid=pid + 1, **kw),
    ]


class _Kql:
    """A detector that runs each query as written over the lines in memory, and counts them."""
    def __init__(self, lines, fail=None):
        self.lines, self.fail, self.queries = lines, fail, []

    def run_query(self, query, timespan=None):
        self.queries.append(query)
        if self.fail and self.fail(query):
            raise RuntimeError("workspace query not successful: PartialError")
        return kql_subset.run(query, self.lines, now=NOW)

    def correlation_queries(self):
        return [q for q in self.queries if "ProcessID" in q]


class _Registry:
    def __init__(self, names=("vm-example-01",)):
        self.assets = [type("A", (), {"name": n, "resource_id": VM.replace("vm-example-01", n)})() for n in names]

    def for_backend(self, _name):
        return self.assets


def _admins(origins=ORIGINS, accounts=("admin1", "ops"), match="vm-example-*"):
    return [ExpectedAdmins(match, list(accounts), list(origins))]


def _cfg(admins=None, sensitive=()) -> GlorfindelConfig:
    return GlorfindelConfig(expected_sudo=ExpectedSudoConfig(
        admins=_admins() if admins is None else admins, sensitive_commands=list(sensitive)))


def _poller(lines, cfg=None, rule_name="sudo-privilege-escalation", names=("vm-example-01",), fail=None):
    r = SHIPPED[rule_name]
    rule = DetectionRule(name=r["name"], source="azure_monitor", workspace_id="ws", query=r["query"],
                         ttp=r["ttp"], resource_id="", interval_s=30, auto_apply=True,
                         monitoring_backend_name="law")
    sent: list = []
    p = RulePoller([rule], sent.append)
    kql = _Kql(lines, fail)
    p._detector = lambda _r: kql
    p._registry = _Registry(names)
    p._cfg = _cfg() if cfg is None else cfg
    return p, rule, sent, kql


def _journal() -> list[dict]:
    path = expected_sudo._JOURNAL
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def _card(p, rule) -> dict:
    [sig] = p.poll_once(rule)
    return sig["raw_signal"]["first_result_row"]


# ── The brick: the sessions of a line ────────────────────────────────────────────

@pytest.mark.parametrize("message,origin", [
    (f"Accepted publickey for admin1 from {BASTION} port 50022 ssh2: ED25519 SHA256:AAAA", BASTION),
    (f"Accepted password for admin1 from {BASTION} port 50022 ssh2", BASTION),
    (f"Accepted keyboard-interactive/pam for admin1 from {BASTION} port 50022 ssh2", BASTION),
    (f"Accepted publickey for admin1 from {V6_OK} port 50022 ssh2", V6_OK),
    (f"Accepted publickey for admin1 from ::ffff:{BASTION} port 50022 ssh2", BASTION),
])
def test_sshd_s_accepted_line_gives_the_session_and_its_origin(message, origin):
    [s] = correlation.sessions([_row(message, 5, process="sshd", facility="auth")], "admin1", NOW)
    assert (s["via"], s["origin"]) == ("ssh", origin)


def test_another_account_s_session_is_not_this_one_s():
    lines = _login(BASTION) + _login(STRANGER, account="ops", pid=4200)
    assert [s["origin"] for s in correlation.sessions(lines, "admin1", NOW)] == [BASTION]


def test_a_session_opened_after_the_line_does_not_carry_it():
    lines = _login(BASTION, minutes_ago=20) + _login(STRANGER, minutes_ago=0.5, pid=4200)
    at = NOW - timedelta(minutes=1)
    assert [s["origin"] for s in correlation.sessions(lines, "admin1", at)] == [BASTION]


@pytest.mark.parametrize("origins,ip,ok", [
    (ORIGINS, BASTION, True),
    (ORIGINS, V6_OK, True),
    (ORIGINS, V6_KO, False),
    (ORIGINS, STRANGER, False),
    (["2001:db8:1::/48"], BASTION, False),        # an IPv4 is in no IPv6 range
])
def test_the_verdict_on_one_session(origins, ip, ok):
    found = [{"via": "ssh", "origin": ip, "at": NOW, "by": ""}]
    assert correlation.verdict(found, origins)[0] is ok


def test_a_private_address_outside_the_origins_is_a_possible_lateral_movement():
    ok, why, _ = correlation.verdict([{"via": "ssh", "origin": "10.0.0.5", "at": NOW, "by": ""}], ORIGINS)
    assert not ok and "10.0.0.5" in why and "mouvement latéral" in why


def test_no_session_is_unknown():
    ok, why, _ = correlation.verdict([], ORIGINS)
    assert not ok and "aucune session" in why


def test_an_unreadable_instant_on_a_line_still_counts_it():
    row = _row(f"Accepted publickey for admin1 from {STRANGER} port 1 ssh2", process="sshd", facility="auth")
    row["TimeGenerated"] = "not a time"
    assert [s["origin"] for s in correlation.sessions([row], "admin1", NOW)] == [STRANGER]


def test_the_origins_are_read_strictly():
    assert correlation.origin("198.51.100.0/24") == ("198.51.100.0/24", "")
    assert correlation.origin("198.51.100.7") == ("198.51.100.7/32", "")
    assert correlation.origin("2001:db8:1::/48") == ("2001:db8:1::/48", "")
    for bad in ("198.51.100.7/24", "0.0.0.0/0", "::/0", "bastion", "198.51.100.0/33", ""):
        assert correlation.origin(bad)[1], bad


# ── ADM1's root shells: set aside only from an expected origin ────────────────────

def test_a_root_shell_from_the_bastion_is_set_aside_journaled_and_counted():
    p, rule, sent, kql = _poller(_login(BASTION) + [_row(SUDO_I)])
    assert p.poll_once(rule) == [] and sent == []
    [e] = _journal()
    assert (e["account"], e["command"], e["via"], e["origin"]) == ("admin1", "/bin/bash", "origin", BASTION)
    [snap] = p.status_snapshot()
    assert snap["expected_count"] == 1 and snap["origin_count"] == 1
    assert snap["correlation"]["queries"] == 1 and snap["correlation"]["origin"] == 1
    assert len(kql.correlation_queries()) == 1


def test_several_sessions_all_from_expected_origins_set_it_aside():
    lines = _login(BASTION) + _login(BASTION_2, pid=4200, minutes_ago=40) + _login(V6_OK, pid=4300, minutes_ago=60)
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert p.poll_once(rule) == []
    assert _journal()[0]["origin"] == ", ".join(sorted([BASTION, BASTION_2, V6_OK]))


@pytest.mark.parametrize("stranger", [STRANGER, V6_KO])
def test_mixed_origins_make_a_card_that_says_the_unknown_one(stranger):
    lines = _login(BASTION) + _login(stranger, pid=4200, minutes_ago=50)
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    row = _card(p, rule)
    assert row["SessionOrigin"] == f"session depuis {stranger}, origine inconnue"
    assert _journal() == [] and p.status_snapshot()[0]["correlation"]["card"] == 1


def test_a_private_address_not_declared_is_a_card():
    p, rule, sent, _ = _poller(_login("10.1.2.3") + [_row(SUDO_I)])
    assert "mouvement latéral possible" in _card(p, rule)["SessionOrigin"]


def test_su_after_a_session_from_an_unknown_origin_is_a_card():
    p, rule, sent, _ = _poller(_login(STRANGER) + [_row(SUDO_SU)])
    assert _card(p, rule)["SessionOrigin"] == f"session depuis {STRANGER}, origine inconnue"


def test_an_account_taken_by_su_from_another_is_a_card_even_with_a_bastion_session():
    took = _row("pam_unix(su-l:session): session opened for user admin1(uid=1001) by mallory(uid=1002)",
                5, process="su", pid=5100)
    p, rule, sent, _ = _poller(_login(BASTION) + [took, _row(SUDO_I)])
    assert _card(p, rule)["SessionOrigin"] == "compte pris par su-l depuis mallory — origine non suivie"


def test_an_sshd_session_without_its_accepted_line_is_unknown():
    lines = _login(BASTION) + [_row("pam_unix(sshd:session): session opened for user admin1(uid=1001) by (uid=0)",
                                    10, process="sshd", facility="auth", pid=4999)]
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert "sans ligne « Accepted »" in _card(p, rule)["SessionOrigin"]


def test_an_sshd_session_pairs_only_with_its_own_process_s_accepted_line():
    """A pam session of another sshd process, a second after the bastion's Accepted line: its
    own Accepted line is missing — unknown."""
    lines = _login(BASTION) + [_row("pam_unix(sshd:session): session opened for user admin1(uid=1001) by (uid=0)",
                                    20 - 1 / 60, process="sshd", facility="auth", pid=4999)]
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert "sans ligne « Accepted »" in _card(p, rule)["SessionOrigin"]


def test_a_closed_line_never_clears_a_session():
    """Any local user writes « session closed » with logger: a session from an unknown origin,
    said closed, still counts."""
    closed = _row("pam_unix(sshd:session): session closed for user admin1", 10, process="sshd",
                  facility="auth", pid=4200)
    lines = _login(BASTION) + _login(STRANGER, pid=4200, minutes_ago=30) + [closed]
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert STRANGER in _card(p, rule)["SessionOrigin"]


def test_no_session_found_is_a_card():
    p, rule, sent, _ = _poller([_row(SUDO_I)])
    assert "aucune session SSH" in _card(p, rule)["SessionOrigin"]


def test_an_unreadable_journal_is_a_card_counted_unknown():
    p, rule, sent, _ = _poller(_login(BASTION) + [_row(SUDO_I)], fail=lambda q: "ProcessID" in q)
    assert "journal illisible" in _card(p, rule)["SessionOrigin"]
    assert p.status_snapshot()[0]["correlation"]["unknown"] == 1 and _journal() == []


def test_a_reading_cut_at_its_limit_is_a_card(monkeypatch):
    """The oldest lines first, cut at the limit: the stranger's session, later, would be missed."""
    monkeypatch.setattr(correlation, "ROWS_MAX", 6)
    lines = (_login(BASTION, minutes_ago=50) + _login(BASTION_2, pid=4200, minutes_ago=40)
             + _login(STRANGER, pid=4300, minutes_ago=30))
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert "lecture incomplète" in _card(p, rule)["SessionOrigin"]


def test_the_lines_of_another_vm_or_facility_are_not_read():
    other = "/subscriptions/" + SUB + "/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-x"
    lines = (_login(BASTION) + _login(STRANGER, pid=4200, computer="vm-x", rid=other)
             + [_row(f"Accepted publickey for admin1 from {STRANGER} port 1 ssh2", 5, process="sshd", facility="user")])
    p, rule, sent, _ = _poller(lines + [_row(SUDO_I)])
    assert p.poll_once(rule) == [] and _journal()[0]["origin"] == BASTION


@pytest.mark.parametrize("message,sensitive", [
    (SUDO_SHADOW, ()),
    ("admin1 : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -c /opt/restore.sh", ("restore.sh",)),
])
def test_the_origin_never_clears_a_sensitive_command(message, sensitive):
    p, rule, sent, kql = _poller(_login(BASTION) + [_row(message)], cfg=_cfg(sensitive=sensitive))
    row = _card(p, rule)
    assert "SessionOrigin" not in row and kql.correlation_queries() == []


def test_without_origins_a_root_shell_is_a_card_as_in_adm1():
    p, rule, sent, kql = _poller(_login(BASTION) + [_row(SUDO_I)], cfg=_cfg(admins=_admins(origins=())))
    assert "SessionOrigin" not in _card(p, rule) and kql.correlation_queries() == []


def test_the_origins_of_another_account_s_entry_do_not_count():
    admins = [ExpectedAdmins("vm-example-*", ["admin1"]), ExpectedAdmins("vm-example-*", ["ops"], ORIGINS)]
    p, rule, sent, kql = _poller(_login(BASTION) + [_row(SUDO_I)], cfg=_cfg(admins=admins))
    _card(p, rule)
    assert kql.correlation_queries() == []


def test_the_query_runs_only_for_the_lines_that_need_it():
    lines = _login(BASTION) + [_row(SUDO_APT, 2), _row(INTRUDER, 1.5)]
    p, rule, sent, kql = _poller(lines)
    _card(p, rule)                                   # the intruder's
    assert kql.correlation_queries() == [] and [e["command"] for e in _journal()] == ["/usr/bin/apt update"]


def test_a_line_already_seen_is_not_queried_again():
    p, rule, sent, kql = _poller(_login(BASTION) + [_row(SUDO_I)])
    p.poll_once(rule)
    p.poll_once(rule)
    assert len(kql.correlation_queries()) == 1 and len(_journal()) == 1


def test_the_queries_are_capped_per_poll_and_beyond_it_is_a_card():
    names = tuple(f"vm-example-0{i}" for i in range(1, 7))
    lines = []
    for i, n in enumerate(names):
        rid = VM.replace("vm-example-01", n)
        lines += _login(BASTION, pid=4100 + 10 * i, computer=n, rid=rid) + [_row(SUDO_I, computer=n, rid=rid)]
    p, rule, sent, kql = _poller(lines, names=names)
    sigs = p.poll_once(rule)
    assert len(kql.correlation_queries()) == correlation.QUERIES_PER_POLL
    assert len(sigs) == len(names) - correlation.QUERIES_PER_POLL
    assert all("plafond" in s["raw_signal"]["first_result_row"]["SessionOrigin"] for s in sigs)
    assert p.status_snapshot()[0]["correlation"]["unknown"] == 2


def test_a_pending_row_is_never_left_set_aside_unsettled():
    """A row whose VM cannot be named, or whose instant cannot be read: unknown, a card."""
    nameless = {"TimeGenerated": NOW, "SyslogMessage": SUDO_I, "Computer": "a b", "_ResourceId": "x"}
    timeless = {**_row(SUDO_I), "TimeGenerated": "?"}
    judged = {id(r): {"account": "admin1", "origins": tuple(ORIGINS)} for r in (nameless, timeless)}
    counts = correlation.settle("T1548.003", {"k": (("rid", "vm"), [nameless, timeless])}, judged,
                                _Kql(_login(BASTION)).run_query, set(), _row_identity, 900)
    assert judged == {} and counts["unknown"] == 2
    assert "ne nomme pas sa VM" in nameless["SessionOrigin"] and "instant" in timeless["SessionOrigin"]


def test_a_fault_in_the_correlation_leaves_the_root_shell_a_card_and_the_poll_running(monkeypatch):
    def broken(*_a, **_k):
        raise ValueError("a bug")
    monkeypatch.setattr(correlation, "sessions", broken)
    p, rule, sent, _ = _poller(_login(BASTION) + [_row(SUDO_I)])
    _card(p, rule)
    assert _journal() == [] and p.status_snapshot()[0]["correlation"]["unknown"] == 1


def test_the_report_and_the_console_say_the_root_shells_set_aside_by_origin(monkeypatch):
    from glorfindel.cli import cli
    p, rule, sent, _ = _poller(_login(BASTION) + [_row(SUDO_I)])
    p.poll_once(rule)
    out = CliRunner().invoke(cli, ["report", "--json"])
    es = json.loads(out.output)["expected_sudo"]
    assert es["origin_count"] == 1 and es["by_origin"] == {BASTION: 1}
    said = " ".join(CliRunner().invoke(cli, ["report"]).output.split())
    assert f"root shells from an expected origin (COR1): 1 — {BASTION} 1" in said
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from .console_client import console
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    rules = console().get("/api/config").json()["detection"]["rules"]
    [sudo] = [r for r in rules if r["name"] == "sudo-privilege-escalation"]
    assert sudo["origin_count"] == 1 and sudo["correlation"]["queries"] == 1


# ── The config ─────────────────────────────────────────────────────────────────────

def _load(tmp_path, text):
    path = tmp_path / "glorfindel-config.yaml"
    path.write_text(text)
    return load_glorfindel_config(path)


def test_the_origins_are_read_from_the_config(tmp_path):
    es = _load(tmp_path, """
expected_sudo:
  admins:
    - match: "vm-example-*"
      accounts: [admin1]
      origins: [198.51.100.0/24, "2001:db8:1::/48", 198.51.100.0/24]
    - match: "vm-example-01"
      accounts: [admin1, ops]
      origins: [203.0.113.10]
""").expected_sudo
    assert es.admins[0].origins == ["198.51.100.0/24", "2001:db8:1::/48"]
    assert es.origins_for("vm-example-01", "admin1") == ("198.51.100.0/24", "2001:db8:1::/48", "203.0.113.10/32")
    assert es.origins_for("vm-example-01", "ops") == ("203.0.113.10/32",)
    assert es.origins_for("vm-example-02", "ops") == ()


@pytest.mark.parametrize("origins,said", [
    ("[198.51.100.7/24]", "bits d'hôte"),
    ("[0.0.0.0/0]", "/0"),
    ("[bastion]", "plage CIDR"),
    ("[]", "liste vide"),
    ("198.51.100.0/24", "une liste est attendue"),
])
def test_a_bad_origin_refuses_the_file(tmp_path, origins, said):
    with pytest.raises(ConfigError, match="origins") as exc:
        _load(tmp_path, f"expected_sudo:\n  admins:\n    - match: vm-1\n      accounts: [admin1]\n"
                        f"      origins: {origins}\n")
    assert said in str(exc.value)


# ── A brute force followed by a login from the same address ─────────────────────────

def _attempts(ip, n=12, minutes_ago=3.0) -> list[dict]:
    return [_row(f"Failed password for root from {ip} port {40000 + i} ssh2", minutes_ago, process="sshd",
                 facility="auth", pid=6000 + i) for i in range(n)]


def test_a_brute_force_then_a_login_from_its_address_is_a_critical_card():
    lines = _attempts(STRANGER) + _login(STRANGER, account="ops", minutes_ago=1, method="password")
    p, rule, sent, _ = _poller(lines, rule_name="ssh-brute-force")
    [sig] = p.poll_once(rule)
    row = sig["raw_signal"]["first_result_row"]
    assert sig["severity"] == "critical" and row["Correlation"] == correlation.COMPROMISED
    assert [(x["account"], x["method"]) for x in row["SuccessfulLogins"]] == [("ops", "password")]
    assert p.status_snapshot()[0]["correlation"]["compromised"] == 1
    assert p.poll_once(rule) == []                   # deduplicated by address and VM


def test_a_login_after_a_brute_force_already_carded_makes_one_critical_card_more():
    lines = _attempts(STRANGER)
    p, rule, sent, _ = _poller(lines, rule_name="ssh-brute-force")
    [first] = p.poll_once(rule)
    assert first["severity"] == "high" and "Correlation" not in first["raw_signal"]["first_result_row"]
    lines += _login(STRANGER, account="ops", minutes_ago=0.5)
    [second] = p.poll_once(rule)
    assert second["severity"] == "critical"
    assert p.poll_once(rule) == [] and p.poll_once(rule) == []


def test_a_login_from_another_address_or_on_another_vm_is_no_compromise():
    other = VM.replace("vm-example-01", "vm-example-02")
    lines = (_attempts(STRANGER) + _login(BASTION, minutes_ago=1)
             + _login(STRANGER, pid=4200, minutes_ago=1, computer="vm-example-02", rid=other))
    p, rule, sent, _ = _poller(lines, rule_name="ssh-brute-force", names=("vm-example-01", "vm-example-02"))
    [sig] = p.poll_once(rule)
    assert sig["severity"] == "high" and "Correlation" not in sig["raw_signal"]["first_result_row"]


def test_a_login_check_that_fails_leaves_the_brute_force_card_and_is_counted():
    lines = _attempts(STRANGER) + _login(STRANGER, minutes_ago=1)
    p, rule, sent, _ = _poller(lines, rule_name="ssh-brute-force", fail=lambda q: "ProcessID" in q)
    [sig] = p.poll_once(rule)
    assert sig["severity"] == "high" and p.status_snapshot()[0]["correlation"]["unchecked"] == 1


def test_two_addresses_on_one_vm_one_query():
    lines = _attempts(STRANGER) + _attempts("203.0.113.10") + _login("203.0.113.10", minutes_ago=1)
    p, rule, sent, kql = _poller(lines, rule_name="ssh-brute-force")
    sigs = p.poll_once(rule)
    assert len(kql.correlation_queries()) == 1
    assert {s["raw_signal"]["first_result_row"]["SourceIP"]: s["severity"] for s in sigs} == {
        STRANGER: "high", "203.0.113.10": "critical"}
    assert sigs[0]["severity"] == "critical"         # the compromise first


# ── A compromise is always said to a human (the Orchestre, 02/11) ────────────────────

def _llm(action, confidence=0.99):
    from unittest.mock import MagicMock
    call = MagicMock()
    call.function.arguments = json.dumps({
        "reasoning": "x", "confidence": confidence, "action": action, "reversible": True,
        "explanation": "x", "escalate": False, "escalation_reason": "", "suggested_steps": []})
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(tool_calls=[call]))]
    return resp


def _compromise_signal() -> dict:
    lines = _attempts(STRANGER) + _login(STRANGER, account="ops", minutes_ago=1, method="password")
    p, rule, sent, _ = _poller(lines, rule_name="ssh-brute-force")
    [sig] = p.poll_once(rule)
    assert sig["severity"] == "critical"
    return sig


def _run_graph(tmp_path, monkeypatch, sig, mode):
    from unittest.mock import MagicMock, patch
    import glorfindel.agent as agent
    from glorfindel.config import AutonomyConfig
    from glorfindel.memory import CycleMemory
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir(exist_ok=True)
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: [])
    connector = MagicMock()
    connector.dry_run = False
    connector.block_suspicious_ip.return_value = {"status": "success", "ip": STRANGER}
    connector.verify_block_ip.return_value = {"verified": True, "method": "nsg"}
    graph = agent._build_graph(CycleMemory(path=tmp_path / "cycles"), connector, "claude-test",
                               autonomy=AutonomyConfig(default=mode))
    initial = {"signal": sig, "past_cycles": [], "incident": None, "dry_run": False, "reasoning": "",
               "confidence": 0.0, "action": "", "reversible": True, "explanation": "", "escalate": False,
               "escalation_reason": "", "suggested_steps": [], "outcome": None}
    with patch("litellm.completion", return_value=_llm("block_suspicious_ip")):
        return graph.invoke(initial), connector


def test_a_compromise_blocked_alone_in_non_disruptive_still_makes_a_human_card(tmp_path, monkeypatch):
    """The model blocks at 99 % in non_disruptive: the block runs, and the card exists."""
    from glorfindel import escalations
    final, connector = _run_graph(tmp_path, monkeypatch, _compromise_signal(), "non_disruptive")
    connector.block_suspicious_ip.assert_called_once()
    assert final["outcome"]["executed"] is True and final["outcome"]["verified"] is True
    assert final["outcome"]["compromise_card"] is True
    [card] = escalations.pending()
    assert card["escalation_type"] == "account_compromised" and card["action"] == ""
    assert "Compte peut-être compromis" in card["reason"] and STRANGER in card["reason"]
    assert "ops" in card["reason"] and "block_suspicious_ip" in card["reason"]
    pytest.importorskip("fastapi")
    from eregion_console.api import _approval_refusal
    assert _approval_refusal(card, "vm-example-01")          # never approvable in one click


def test_a_compromise_held_in_human_only_is_one_card_that_says_so(tmp_path, monkeypatch):
    from glorfindel import escalations
    final, connector = _run_graph(tmp_path, monkeypatch, _compromise_signal(), "human_only")
    connector.block_suspicious_ip.assert_not_called()
    [card] = escalations.pending()
    assert card["escalation_type"] == "mode_hold" and card["reason"].startswith("Compte peut-être compromis")


def test_a_plain_brute_force_blocked_alone_makes_no_compromise_card(tmp_path, monkeypatch):
    from glorfindel import escalations
    p, rule, sent, _ = _poller(_attempts(STRANGER), rule_name="ssh-brute-force")
    [sig] = p.poll_once(rule)
    final, connector = _run_graph(tmp_path, monkeypatch, sig, "non_disruptive")
    connector.block_suspicious_ip.assert_called_once()
    assert escalations.pending() == [] and "compromise_card" not in final["outcome"]
