"""WL1 (#595): bree's scheduled maintenance set aside from `sudo-privilege-escalation`, in the
client's layer of the bench — and nothing else.

`infra/terraform/scripts/workload.sh` puts `/etc/cron.d/eregion-workload` on bree, H0's
pre-observation workload: as `celebrimbor`, without a terminal, `sudo -n /usr/sbin/nginx -t &&
sudo -n systemctl reload nginx` at 08:15 and `sudo -n journalctl --vacuum-time=14d` every six hours.
The shipped rule made a card of it every morning (judged `wrong` by Jonathan, 06/11). The rule of
the bench's layer (`infra/glorfindel-host/client_rules.bench.yaml`) is the shipped one, copied, plus
one exclusion: that account, no terminal, these three commands with exactly these arguments, on
bree alone. Any other sudo still makes a card.

The rules run as written (`tests/unit/kql_subset.py`) on lines in sudo's form, the fields separated
by « ; » or, as the agent (AMA) writes them, by spaces. The copy is held to the base: the same query
plus the exclusion block, and the fingerprint of the whole base rule it came from (`base_sha256`)
— a base that changes without the copy fails here; where it runs, the watch sets the stale copy
aside, the shipped rule loads in its place, and it says so (drift): more cards, never fewer.

Every identifier is the bench's own (`vm-celebrimbor-bree`, `rg-celebrimbor`, `celebrimbor`, already
in the repository) or made up: 00000000-… GUIDs. No Azure, no model.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from glorfindel.detection_rules import (
    DetectionRule,
    RulePoller,
    base_rule_sha256,
    client_rules_path,
    load_config,
    shipped_rules_path,
)

from . import kql_subset

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "infra" / "glorfindel-host" / "client_rules.bench.yaml"
NAME = "sudo-privilege-escalation"
SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
CLIENT = {r["name"]: r for r in yaml.safe_load(BENCH.read_text())["rules"]}
SUB = "00000000-0000-0000-0000-0000000000bb"
BREE = "vm-celebrimbor-bree"
GONDOLIN = "vm-celebrimbor-gondolin"


def _rid(vm: str, rg: str = "rg-celebrimbor") -> str:
    # As Azure writes it (mixed case); the rule compares without case, as KQL's endswith does.
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}"


BREE_ID = _rid(BREE)
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    global NOW
    NOW = datetime.now(timezone.utc)


def _line(message: str, computer: str = BREE, resource_id: str = BREE_ID, process: str = "sudo",
          facility: str = "authpriv") -> dict:
    return {"Type": "Syslog", "TimeGenerated": NOW - timedelta(minutes=1), "Facility": facility,
            "ProcessName": process, "SyslogMessage": message, "Computer": computer, "_ResourceId": resource_id}


def _sep(form: str) -> str:
    return " ; " if form == "semicolons" else "   "


def _sudo(account: str, command: str, form: str = "semicolons", tty: str = "",
          pwd: str = "/home/celebrimbor", between: str = "") -> str:
    """A line in sudo's form: `<account> : [TTY=… ; ]PWD=… ; USER=root ; […] COMMAND=…`."""
    s = _sep(form)
    fields = ([f"TTY={tty}"] if tty else []) + [f"PWD={pwd}", "USER=root"] + ([between] if between else [])
    return f"{account} : " + s.join(fields + [f"COMMAND={command}"])


def _bench(rows):
    return kql_subset.run(CLIENT[NAME]["query"], rows, now=NOW)


def _base(rows):
    return kql_subset.run(SHIPPED[NAME]["query"], rows, now=NOW)


# What the cron runs, as sudo writes it (the full path sudo resolved, then the arguments):
# `nginx -t` is called by its path; systemctl and journalctl are found in secure_path, /usr/bin.
CRON = ["/usr/sbin/nginx -t", "/usr/bin/systemctl reload nginx", "/usr/bin/journalctl --vacuum-time=14d"]
FORMS = ["semicolons", "agent"]


# ── The copy: the base, plus the exclusion block, nothing else ──────────────────────

_BLOCK_START = "// WL1 (#595)"


def _without_block(query: str) -> str:
    lines = query.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.strip().startswith(_BLOCK_START))
    end = next(i for i in range(start, len(lines)) if "COMMAND=(" in lines[i])
    return "".join(lines[:start] + lines[end + 1:])


def test_the_bench_rule_is_the_shipped_query_plus_the_exclusion_block_alone():
    """Drift, read in the repository: the base changed and the copy did not → this fails, in the
    pull request that changes the base. Redo the copy (the base's query, then the block)."""
    client, base = CLIENT[NAME], SHIPPED[NAME]
    assert _without_block(client["query"]) == base["query"]
    assert client["base_sha256"] == base_rule_sha256(base)
    for key in ("ttp", "assets", "interval_s", "expected_latency_s", "enabled"):
        assert client[key] == base[key], key
    assert client["description"].startswith(base["description"])
    assert set(client) - set(base) == {"base_sha256"}
    # The block sits before `project`, so it reads the line as the shipped filters left it.
    block = client["query"][client["query"].index(_BLOCK_START):]
    assert block.index("| where not(") < block.index("| project")


def test_the_bench_layer_replaces_the_shipped_rule_said_and_without_drift(tmp_path):
    cfg = load_config(shipped_rules_path(), client_layer=BENCH)
    [rule] = [r for r in cfg.rules if r.name == NAME]
    assert rule.layer == "client" and rule.replaces_base and rule.query == CLIENT[NAME]["query"]
    assert cfg.overrides == [NAME] and cfg.drifted == [] and cfg.disabled_base == []
    assert cfg.notes == [f"règle de base « {NAME} » remplacée par celle de la couche du client"]
    # The base itself is untouched: an update of Glorfindel replaces it, never this layer.
    assert "celebrimbor" not in shipped_rules_path().read_text()


def test_the_bench_layer_holds_this_rule_alone():
    data = yaml.safe_load(BENCH.read_text())
    assert set(data) == {"rules"} and list(CLIENT) == [NAME]


# ── The cron passes; the shipped rule still sees it ─────────────────────────────────

@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("command", CRON)
def test_the_maintenance_of_bree_makes_no_card(command, form):
    line = _sudo("celebrimbor", command, form)
    assert _base([_line(line)]) != []           # the shipped rule's card, every morning
    assert _bench([_line(line)]) == []
    assert _bench([_line("   " + line)]) == []  # sudo's leading spaces, as the agent keeps them


def test_the_three_lines_of_the_cron_together_make_no_signal():
    lines = [_line(_sudo("celebrimbor", c, f)) for c in CRON for f in FORMS]
    assert _poll(lines) == []
    # …and an intruder's line among them still makes one.
    assert len(_poll(lines + [_line(_sudo("celebrimbor", "/bin/bash"))])) == 1


# ── Anything else is a card ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("command", [
    "/bin/bash", "/usr/bin/id", "/usr/bin/su -", "/usr/bin/systemctl restart nginx",
    "/usr/bin/journalctl --rotate", "/usr/sbin/nginx", "/usr/bin/cat /etc/shadow",
    "/usr/local/sbin/nginx -t", "/tmp/usr/sbin/nginx -t",
])
def test_another_command_is_a_card(command, form):
    assert len(_bench([_line(_sudo("celebrimbor", command, form))])) == 1


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("command", [
    "/usr/sbin/nginx -t; bash", "/usr/sbin/nginx -t -c /tmp/nginx.conf", "/usr/sbin/nginx -t ",
    "/usr/sbin/nginx -tq", "/usr/sbin/nginx -T", "/usr/bin/systemctl reload nginx sshd",
    "/usr/bin/systemctl reload nginx; id", "/usr/bin/journalctl --vacuum-time=14d --rotate",
    "/usr/bin/journalctl --vacuum-time=1s", "/usr/bin/journalctl --vacuum-time=14d && sh",
])
def test_the_same_commands_with_other_arguments_are_a_card(command, form):
    assert len(_bench([_line(_sudo("celebrimbor", command, form))])) == 1


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("account", ["alice", "root", "celebrimbor2", "xcelebrimbor", "Celebrimbor"])
def test_another_account_is_a_card(account, form):
    for command in CRON:
        assert len(_bench([_line(_sudo(account, command, form))])) == 1, command


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("tty", ["pts/0", "unknown", "console"])
def test_a_terminal_is_a_card(tty, form):
    for command in CRON:
        assert len(_bench([_line(_sudo("celebrimbor", command, form, tty=tty))])) == 1, command


@pytest.mark.parametrize("computer,resource_id", [
    (GONDOLIN, _rid(GONDOLIN)),                             # another VM of the bench
    (BREE, _rid(GONDOLIN)),                                 # bree's host name, another resource
    (GONDOLIN, BREE_ID),                                    # bree's resource, another host name
    (BREE, _rid(BREE, rg="rg-other")),                      # a VM named bree in another group
    (BREE, _rid("xvm-celebrimbor-bree")),
    (BREE, ""), ("", BREE_ID), ("VM-CELEBRIMBOR-BREE", BREE_ID),
])
@pytest.mark.parametrize("form", FORMS)
def test_another_vm_is_a_card(computer, resource_id, form):
    for command in CRON:
        row = _line(_sudo("celebrimbor", command, form), computer=computer, resource_id=resource_id)
        assert len(_bench([row])) == 1, command


def test_bree_s_resource_id_is_read_without_case():
    line = _sudo("celebrimbor", CRON[0])
    assert _bench([_line(line, resource_id=BREE_ID.lower())]) == []


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("between", ["ENV=LD_PRELOAD=/tmp/x.so", "GROUP=root", "TSID=000001"])
def test_a_field_between_the_target_and_the_command_is_a_card(between, form):
    # `sudo LD_PRELOAD=/tmp/x.so /usr/sbin/nginx -t` runs code as root through nginx's loader.
    assert len(_bench([_line(_sudo("celebrimbor", CRON[0], form, between=between))])) == 1


@pytest.mark.parametrize("message", [
    # A working directory that writes a line of its own in front of the real one (ADM1).
    "celebrimbor : PWD=/tmp/a ; USER=root ; COMMAND=/usr/sbin/nginx -t ; USER=root ; COMMAND=/bin/bash",
    "celebrimbor : PWD=/tmp/a b ; USER=root ; COMMAND=/usr/sbin/nginx -t",
    "celebrimbor : PWD=/x;y ; USER=root ; COMMAND=/usr/sbin/nginx -t",
    "celebrimbor : USER=root ; COMMAND=/usr/sbin/nginx -t",
])
def test_a_line_of_another_shape_is_a_card(message):
    # Each is a line the shipped rule reads as an escalation — or would not read at all.
    rows = _bench([_line(message)])
    assert rows == _base([_line(message)])


def test_a_line_of_another_emitter_is_no_escalation_as_before():
    line = _sudo("alice", "/bin/bash")
    assert _bench([_line(line, process="root")]) == [] == _base([_line(line, process="root")])


# ── Through the poller: the cron makes no signal, anything else one ─────────────────

class _Registry:
    def __init__(self):
        self.assets = [type("A", (), {"name": vm, "resource_id": _rid(vm)})() for vm in (BREE, GONDOLIN)]

    def for_backend(self, _name):
        return self.assets


class _Kql:
    def __init__(self, lines):
        self.lines = lines

    def run_query(self, query, timespan=None):
        return kql_subset.run(query, self.lines, now=NOW)


def _poll(lines):
    r = CLIENT[NAME]
    rule = DetectionRule(name=r["name"], source="azure_monitor", workspace_id="ws", query=r["query"],
                         ttp=r["ttp"], resource_id="", interval_s=30, auto_apply=True,
                         monitoring_backend_name="law")
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _r: _Kql(lines)
    p._registry = _Registry()
    p.poll_once(rule)
    return sent


def test_the_same_line_on_gondolin_is_a_signal_on_gondolin():
    [signal] = _poll([_line(_sudo("celebrimbor", CRON[0]), computer=GONDOLIN, resource_id=_rid(GONDOLIN))])
    assert GONDOLIN in str(signal)


# ── Drift: the base changes, the stale copy is set aside — said, the shipped rule runs ─

def _layer(tmp_path, disable: list | None = None, drop: tuple = (), **changes) -> Path:
    rule = {k: v for k, v in {**CLIENT[NAME], **changes}.items() if k not in drop}
    layer = {"rules": [rule], **({"disable": disable} if disable is not None else {})}
    path = tmp_path / "client_rules.yaml"
    path.write_text(yaml.safe_dump(layer, sort_keys=False, allow_unicode=True))
    return path


def _base_with(tmp_path, gone: bool = False, **changes) -> tuple[Path, dict | None]:
    """The shipped base, its rule NAME changed (`gone=True`: removed) → (path, that rule)."""
    data = yaml.safe_load(shipped_rules_path().read_text())
    rule = next(r for r in data["rules"] if r["name"] == NAME)
    if gone:
        data["rules"].remove(rule)
        rule = None
    else:
        rule.update(changes)
    path = tmp_path / "base.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return path, rule


CHANGED_QUERY = SHIPPED[NAME]["query"].replace("ago(10m)", "ago(15m)")


@pytest.mark.parametrize("change", [
    {"query": CHANGED_QUERY},                                   # a fix of the query
    {"interval_s": 60}, {"expected_latency_s": 600},            # not the query alone
    {"description": SHIPPED[NAME]["description"] + " (v2)"},
])
def test_a_shipped_rule_changed_since_the_copy_sets_the_copy_aside_and_runs(tmp_path, change):
    base, rule = _base_with(tmp_path, **change)
    cfg = load_config(base, client_layer=_layer(tmp_path))
    assert cfg.drifted == [NAME]
    [note] = [n for n in cfg.notes if "dérive" in n]
    assert f"« {NAME} »" in note and "copie périmée ignorée" in note and "la règle livrée tourne" in note
    assert base_rule_sha256(rule) in note
    # The shipped rule loads in the copy's place: more cards, never fewer.
    loaded = next(r for r in cfg.rules if r.name == NAME)
    assert loaded.layer == "base" and loaded.query == rule["query"] and cfg.overrides == []
    # …so bree's maintenance makes its card again, until the copy is redone.
    assert kql_subset.run(loaded.query, [_line(_sudo("celebrimbor", CRON[0]))], now=NOW) != []


def test_the_fingerprint_is_the_rule_not_its_layout():
    rule = SHIPPED[NAME]
    assert base_rule_sha256(dict(reversed(list(rule.items())))) == base_rule_sha256(rule)
    flow = yaml.safe_load(yaml.safe_dump(rule, default_flow_style=True, width=10_000))
    assert base_rule_sha256(flow) == base_rule_sha256(rule)
    assert base_rule_sha256({**rule, "ttp": "T1548"}) != base_rule_sha256(rule)


def test_a_base_rule_gone_since_the_copy_keeps_the_copy_and_says_it(tmp_path):
    base, _ = _base_with(tmp_path, gone=True)
    cfg = load_config(base, client_layer=_layer(tmp_path))
    assert cfg.drifted == [NAME] and any("n'existe plus" in n and "tourne toujours" in n for n in cfg.notes)
    # Nothing else detects its technique: the copy runs.
    loaded = next(r for r in cfg.rules if r.name == NAME)
    assert loaded.layer == "client" and loaded.query == CLIENT[NAME]["query"]


@pytest.mark.parametrize("off", ["disable", "shipped_disabled", "entry_disabled"])
def test_a_stale_copy_whose_shipped_rule_would_not_load_keeps_running(tmp_path, off):
    """Setting the copy aside must never leave its technique undetected: with the shipped rule
    named in the layer's `disable`, `enabled: false` in a release, or another entry of its name in
    the layer (`{name, enabled: false}` before the copy: merge_layers keeps the last), the copy
    runs, and the drift is said — never « la règle livrée tourne »."""
    if off == "disable":
        base, rule = _base_with(tmp_path, query=CHANGED_QUERY)
        layer = _layer(tmp_path, disable=[NAME])
    elif off == "entry_disabled":
        base, rule = _base_with(tmp_path, query=CHANGED_QUERY)
        layer = tmp_path / "client_rules.yaml"
        layer.write_text(yaml.safe_dump({"rules": [{"name": NAME, "enabled": False}, CLIENT[NAME]]},
                                        sort_keys=False, allow_unicode=True))
    else:
        base, rule = _base_with(tmp_path, enabled=False)
        layer = _layer(tmp_path)
    cfg = load_config(base, client_layer=layer)
    [loaded] = [r for r in cfg.rules if r.name == NAME]
    assert loaded.layer == "client" and loaded.query == CLIENT[NAME]["query"]
    assert cfg.drifted == [NAME] and cfg.disabled_base == []
    [note] = [n for n in cfg.notes if "dérive" in n]
    assert ("ne tournerait pas" in note or "autre entrée" in note) and "tourne toujours" in note
    assert "tourne à sa place" not in note
    assert base_rule_sha256(rule) in note


def test_a_copy_with_the_retired_field_is_set_aside_and_the_shipped_rule_loads(tmp_path):
    """`base_query_sha256` (WL1's first form, the query alone): a copy carrying it is never
    compared — skipped and said, the shipped rule loads."""
    layer = _layer(tmp_path, drop=("base_sha256",), base_query_sha256="0" * 64)
    cfg = load_config(shipped_rules_path(), client_layer=layer)
    rule = next(r for r in cfg.rules if r.name == NAME)
    assert rule.layer == "base" and rule.query == SHIPPED[NAME]["query"]
    assert any("base_query_sha256" in n and "champ retiré" in n and "base_sha256" in n and "ignorée" in n
               for n in cfg.notes)


def test_an_invalid_stale_copy_is_said_skipped_never_drift(tmp_path):
    cfg = load_config(_base_with(tmp_path, query=CHANGED_QUERY)[0],
                      client_layer=_layer(tmp_path, interval_s="30s"))
    assert cfg.drifted == [] and not any("dérive" in n for n in cfg.notes)
    assert any("interval_s" in n and "ignorée" in n for n in cfg.notes)
    assert next(r for r in cfg.rules if r.name == NAME).layer == "base"


def test_a_name_drifted_twice_is_said_once(tmp_path):
    layer = tmp_path / "client_rules.yaml"
    layer.write_text(yaml.safe_dump({"rules": [CLIENT[NAME], CLIENT[NAME]]}, sort_keys=False, allow_unicode=True))
    cfg = load_config(_base_with(tmp_path, query=CHANGED_QUERY)[0], client_layer=layer)
    assert cfg.drifted == [NAME]


def test_a_client_rule_that_is_no_copy_says_no_drift(tmp_path):
    rule = {k: v for k, v in CLIENT[NAME].items() if k != "base_sha256"}
    path = tmp_path / "client_rules.yaml"
    path.write_text(yaml.safe_dump({"rules": [rule]}, sort_keys=False))
    cfg = load_config(_base_with(tmp_path, query=CHANGED_QUERY)[0], client_layer=path)
    assert cfg.drifted == [] and cfg.overrides == [NAME]


@pytest.mark.parametrize("sha", ["abc", "F" * 64, 12, ["x"], "g" * 64])
def test_a_fingerprint_that_is_not_one_skips_the_copy_and_the_shipped_rule_loads(tmp_path, sha):
    cfg = load_config(shipped_rules_path(), client_layer=_layer(tmp_path, base_sha256=sha))
    rule = next(r for r in cfg.rules if r.name == NAME)
    assert rule.layer == "base" and rule.query == SHIPPED[NAME]["query"]
    assert any("base_sha256" in n and "ignorée" in n for n in cfg.notes)


def test_a_disabled_copy_says_no_drift_and_still_disables(tmp_path):
    cfg = load_config(_base_with(tmp_path, query="Syslog | take 1\n")[0],
                      client_layer=_layer(tmp_path, enabled=False))
    assert cfg.drifted == [] and cfg.disabled_base == [NAME]


def test_glorfindel_rules_and_the_banner_say_the_drift_loudly(tmp_path):
    from glorfindel.cli import cli
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(_layer(tmp_path).read_text())
    res = CliRunner().invoke(cli, ["rules", "--rules", str(_base_with(tmp_path, query=CHANGED_QUERY)[0])])
    assert res.exit_code == 0, res.output
    assert "copie périmée" in res.output and NAME in res.output
    text = (ROOT / "glorfindel" / "cli.py").read_text()
    assert text.count("for name in det_cfg.drifted:") == 1
