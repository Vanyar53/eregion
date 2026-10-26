"""P1: rule layers — the shipped base stays intact, the client's rules live in their own layer.

`proposed_rules.approve` wrote the approved rule into detection_rules.yaml, the file shipped
with Glorfindel: an update replaced it (rule lost), and on H0 the modified checkout stopped
the deployment (M-3). Now the rule goes to the client's layer (~/.glorfindel/client_rules.yaml,
redirected to tmp by the conftest), loaded over the base: a client rule of a base rule's name
wins (said), a client rule can disable a base rule by name, and `export-rule` gives one rule
generalised, without any resource or workspace identifier.

Every identifier here is made up (repository public): 00000000-… GUIDs, example names.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from glorfindel import rule_layers
from glorfindel.detection_rules import client_rules_path, load_config, merge_layers
from glorfindel.proposed_rules import all_proposals, approve, pending, record

ROOT = Path(__file__).resolve().parents[2]
SHIPPED_BASE = ROOT / "glorfindel" / "rules" / "azure" / "detection_rules.yaml"

WS = "00000000-0000-0000-0000-0000000000aa"
SUB = "00000000-0000-0000-0000-0000000000bb"
VM_ID = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"

BASE_V1 = """\
rules:
  - name: ssh-brute-force
    ttp: T1110.001
    assets: [auto]
    interval_s: 30
    query: |
      Syslog | where SyslogMessage has "Failed password"
  - name: sudo-root
    ttp: T1548.003
    assets: [auto]
    query: |
      Syslog | where SyslogMessage has "USER=root"
"""

# The update: a rule changed, one removed, one added — none of it the client's.
BASE_V2 = """\
rules:
  - name: ssh-brute-force
    ttp: T1110.001
    assets: [auto]
    interval_s: 60
    query: |
      Syslog | where SyslogMessage has "Failed password" | summarize count() by Computer
  - name: account-creation
    ttp: T1136.001
    assets: [auto]
    query: |
      Syslog | where SyslogMessage has "new user:"
"""


def _gcfg():
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig
    return GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-main", type="azure_monitor", workspace_id=WS)])


def _propose(**kw) -> str:
    fields = dict(run_id="20261026T120000Z", ttp="T1070.002", resource_id=VM_ID,
                  rule_name="log-clearing", source="azure_monitor", workspace_id=WS,
                  query='Syslog\n| where SyslogMessage has "rm -f /var/log"\n', interval_s=30.0,
                  explanation="Log files removed", confidence=0.8, analysis="a")
    fields.update(kw)
    return record(**fields)


def _names(cfg) -> dict:
    return {r.name: r for r in cfg.rules}


# ── Fini quand (1/2): an update of the base loses no client rule ─────────────────

def test_an_update_of_the_base_loses_no_client_rule(tmp_path):
    base = tmp_path / "detection_rules.yaml"
    base.write_text(BASE_V1)
    approve(_propose(), base)
    rule_layers.write_client_rule({"name": "sudo-root", "ttp": "T1548.003", "assets": ["auto"],
                                   "query": "Syslog | where SyslogMessage has \"sudo\"\n"})
    assert base.read_text() == BASE_V1                       # the base is never written

    base.write_text(BASE_V2)                                 # the update replaces the base
    rules = _names(load_config(base, glorfindel_cfg=_gcfg()))

    assert rules["log-clearing"].layer == "client"           # the approved rule is still there
    assert "rm -f /var/log" in rules["log-clearing"].query
    assert rules["sudo-root"].layer == "client"              # the client's own version survives
    assert rules["ssh-brute-force"].interval_s == 60         # the base's update is taken
    assert "account-creation" in rules                       # and its new rule
    assert set(rules) == {"ssh-brute-force", "account-creation", "sudo-root", "log-clearing"}


def test_approving_never_writes_the_shipped_base():
    before = SHIPPED_BASE.read_bytes()
    approve(_propose(), SHIPPED_BASE)
    assert SHIPPED_BASE.read_bytes() == before
    rules = _names(load_config(SHIPPED_BASE, glorfindel_cfg=_gcfg()))
    assert rules["log-clearing"].layer == "client"
    assert all(r.layer == "base" for n, r in rules.items() if n != "log-clearing")


def test_approving_twice_the_same_name_replaces_it(tmp_path):
    base = tmp_path / "detection_rules.yaml"
    base.write_text(BASE_V1)
    approve(_propose(), base)
    second = approve(_propose(query="Syslog | where SyslogMessage has \"shred\"\n"), base)
    assert second["rule_write"] == "replaced"
    layer = rule_layers.read_client_layer()
    assert [r["name"] for r in layer["rules"]] == ["log-clearing"]
    assert "shred" in layer["rules"][0]["query"]


def test_an_unreadable_layer_leaves_the_proposal_pending_and_the_file_as_it_was(tmp_path):
    base = tmp_path / "detection_rules.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text("rules: [unclosed\n")
    pid = _propose()
    with pytest.raises(ValueError, match="illisible"):
        approve(pid, base)
    assert client_rules_path().read_text() == "rules: [unclosed\n"
    assert [p["id"] for p in pending()] == [pid]
    # The watch still loads the base, and says why the layer is missing.
    cfg = load_config(base)
    assert set(_names(cfg)) == {"ssh-brute-force", "sudo-root"}
    assert any("illisible" in n for n in cfg.notes)


# ── Loading: the client's layer over the base ─────────────────────────────────────

def test_a_client_rule_of_a_base_rule_name_wins_and_it_is_said(tmp_path, caplog, monkeypatch):
    import glorfindel.detection_rules as dr
    monkeypatch.setattr(dr, "_NOTES_LOGGED", set())
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    rule_layers.write_client_rule({"name": "ssh-brute-force", "ttp": "T1110.001",
                                   "assets": ["auto"], "interval_s": 120,
                                   "query": "Syslog | where SyslogMessage has \"Invalid user\"\n"})
    with caplog.at_level("WARNING", logger="glorfindel.detection_rules"):
        cfg = load_config(base)
    rules = _names(cfg)
    assert rules["ssh-brute-force"].layer == "client"
    assert rules["ssh-brute-force"].interval_s == 120 and "Invalid user" in rules["ssh-brute-force"].query
    assert [r.name for r in cfg.rules] == ["ssh-brute-force", "sudo-root"]     # in its place
    said = "règle de base « ssh-brute-force » remplacée par celle de la couche du client"
    assert said in cfg.notes and caplog.text.count(said) == 1
    caplog.clear()
    with caplog.at_level("WARNING", logger="glorfindel.detection_rules"):
        assert said in load_config(base).notes          # still on the config…
    assert said not in caplog.text                      # …logged once per process (/api/state)


@pytest.mark.parametrize("how", ["disable", "enabled_false"])
def test_a_client_rule_can_disable_a_base_rule_by_name(tmp_path, how):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    layer = ({"disable": ["sudo-root"]} if how == "disable"
             else {"rules": [{"name": "sudo-root", "enabled": False}]})
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(yaml.safe_dump(layer))
    cfg = load_config(base)
    assert set(_names(cfg)) == {"ssh-brute-force"}
    assert "règle de base « sudo-root » désactivée par la couche du client" in cfg.notes


def test_disabling_a_name_that_is_no_base_rule_is_said(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text("disable: [ssh-brute-forse]\n")
    cfg = load_config(base)
    assert set(_names(cfg)) == {"ssh-brute-force", "sudo-root"}
    assert any("ssh-brute-forse" in n and "rien n'est désactivé" in n for n in cfg.notes)


def test_a_bad_client_entry_is_skipped_and_said_the_others_load(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(
        "rules:\n  - name: no-query\n  - ttp: T1\n    query: x\n"
        "  - name: fine\n    assets: [auto]\n    query: Syslog\n")
    cfg = load_config(base)
    assert _names(cfg)["fine"].layer == "client" and "no-query" not in _names(cfg)
    assert any("no-query" in n for n in cfg.notes) and any("pas de nom" in n for n in cfg.notes)


def test_without_a_client_layer_nothing_changes(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    cfg = load_config(base)
    assert [r.name for r in cfg.rules] == ["ssh-brute-force", "sudo-root"]
    assert cfg.notes == [] and cfg.client_file == ""
    assert all(r.layer == "base" for r in cfg.rules)


def test_the_base_alone_on_demand(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    rule_layers.write_client_rule({"name": "extra", "query": "Syslog\n"})
    assert "extra" in _names(load_config(base))
    assert "extra" not in _names(load_config(base, client_layer=False))


def test_merge_layers_assets_and_backends_by_name():
    merged, notes, _ = merge_layers(
        {"assets": [{"name": "a", "resource_id": "x"}], "rules": []},
        {"assets": [{"name": "a", "resource_id": "y"}, {"name": "b"}],
         "monitoring_backends": [{"name": "law-2"}]})
    assert merged["assets"] == [{"name": "a", "resource_id": "y"}, {"name": "b"}]
    assert merged["monitoring_backends"] == [{"name": "law-2"}]
    assert any("assets « a »" in n for n in notes)


def test_the_layer_written_keeps_the_query_as_lines_and_reads_back():
    rule = {"name": "multi", "assets": ["auto"], "query": "Syslog\n| where A == 1\n| project B\n"}
    assert rule_layers.write_client_rule(rule) == "added"
    text = client_rules_path().read_text()
    assert text.startswith("# Couche du client de Glorfindel (P1)")
    assert "  query: |\n    Syslog\n    | where A == 1\n" in text
    assert rule_layers.read_client_layer()["rules"] == [rule]
    assert rule_layers.write_client_rule(rule) == "same"


# ── Fini quand (2/2): an exported rule holds no resource or workspace identifier ───

def _identified_client_rule() -> dict:
    """A client rule as a deployment writes it: everything that names the deployment."""
    return {
        "name": "vm-example-01-log-clearing",
        "description": f"Proposed after a miss on vm-example-01 (workspace {WS}).",
        "enabled": True,
        "source": "azure_monitor",
        "workspace_id": WS,
        "ttp": "T1070.002",
        "resource_id": VM_ID,
        "monitoring_backends": ["law-main"],
        "assets": ["vm-example-01"],
        "interval_s": 30,
        "query": (
            "Syslog\n"
            '| where Computer == "vm-example-01"\n'
            f'| where _ResourceId =~ "{VM_ID.lower()}"\n'
            '| where Computer in ("vm-example-02", "")\n'
            f'| where TenantId == "{SUB}"\n'
            '| where SyslogMessage has "rm -f /var/log" and HostName != "db-example"\n'
        ),
    }


def _export(tmp_path, rule=None, **kw) -> str:
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1 + "assets:\n  - name: vm-example-01\n"
                    f"    resource_id: {VM_ID}\n")
    rule_layers.write_client_rule(rule or _identified_client_rule())
    return rule_layers.export_rule((rule or _identified_client_rule())["name"], base,
                                   glorfindel_cfg=_gcfg(), **kw)


def test_an_exported_rule_holds_no_resource_or_workspace_identifier(tmp_path):
    text = _export(tmp_path)
    for leaked in (WS, SUB, VM_ID, VM_ID.lower(), "vm-example-01", "vm-example-02",
                   "db-example", "rg-example", "law-main", "/subscriptions/"):
        assert leaked.lower() not in text.lower(), leaked
    assert rule_layers.find_identifiers(text) == []
    exported = yaml.safe_load(text)["rules"][0]
    assert set(exported) <= {"name", "description", "enabled", "source", "ttp", "interval_s",
                             "expected_latency_s", "query"}
    for key in ("workspace_id", "resource_id", "assets", "monitoring_backends"):
        assert key not in exported
    # What generalises it is kept: the logic of the query, the technique.
    assert 'SyslogMessage has "rm -f /var/log"' in exported["query"]
    assert exported["ttp"] == "T1070.002" and exported["interval_s"] == 30
    assert 'Computer in ("<name>", "")' in exported["query"]
    assert "Remplacé :" in text and "identifiant de ressource" in text


def test_an_exported_rule_loads_as_a_rule_for_every_discovered_vm(tmp_path):
    text = _export(tmp_path)
    shipped = tmp_path / "upstream.yaml"
    shipped.write_text(text)
    [rule] = load_config(shipped, glorfindel_cfg=_gcfg(), client_layer=False).rules
    assert rule.auto_apply and rule.resource_id == "" and rule.workspace_id == WS   # bound at load


def test_a_vm_name_the_deployment_knows_is_replaced_wherever_it_appears(tmp_path):
    """A discovered VM, a proposal's target: names a deployment gives, in any column."""
    from glorfindel.discovery import AssetRegistry, DiscoveredAsset
    AssetRegistry().update([DiscoveredAsset(name="web-example-07", resource_id="",
                                            monitoring_backend="law-main", last_seen="x")])
    rule = {"name": "proc", "ttp": "T1059", "assets": ["auto"],
            "query": 'Syslog | where ProcessName has "web-example-07"\n'}
    text = _export(tmp_path, rule=rule)
    assert "web-example-07" not in text and '"<name>"' in text


def test_a_workspace_the_deployment_does_not_list_is_replaced_too(tmp_path):
    """Another workspace, named only in the query (cross-workspace union): a GUID, whoever
    it belongs to, never leaves."""
    other = "00000000-0000-0000-0000-0000000000cc"
    rule = {"name": "cross", "ttp": "T1110", "assets": ["auto"],
            "query": f'union Syslog, workspace("{other}").Syslog\n| where SyslogMessage has "x"\n'}
    text = _export(tmp_path, rule=rule)
    assert other not in text and 'workspace("<id>").Syslog' in text


def test_nothing_is_exported_when_an_identifier_would_leave(tmp_path, monkeypatch):
    """The last guard: whatever the replacement misses, the exported text is checked."""
    monkeypatch.setattr(rule_layers, "_scrub", lambda text, names, counts, kql=False: text)
    with pytest.raises(rule_layers.IdentifierLeft) as err:
        _export(tmp_path)
    assert VM_ID in err.value.found and WS in err.value.found


@pytest.mark.parametrize("text, found", [
    (f"x {VM_ID} y", VM_ID),
    ('"/subscriptions/<id>/resourceGroups/<name>"', "/subscriptions/<id>/resourceGroups/<name>"),
    (f'workspace("{WS}")', WS),
    ('| where Computer == "vm-a1"', '"vm-a1"'),
    ("| where tolower(Computer) =~ 'vm-a1'", "'vm-a1'"),
    ('| where _ResourceId has "rg-x"', '"rg-x"'),
    ('| where AccountName in ("sa1", "sa2")', '"sa1"'),
])
def test_find_identifiers_sees_each_kind(text, found):
    assert found in rule_layers.find_identifiers(text)


@pytest.mark.parametrize("text", [
    '| where Computer != ""', '| where Computer == "<name>"', "Perf | where CounterValue > 5",
    "| summarize count() by Computer, _ResourceId",
])
def test_find_identifiers_lets_a_general_query_through(text):
    assert rule_layers.find_identifiers(text) == []


def test_export_of_an_unknown_rule(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    with pytest.raises(KeyError):
        rule_layers.export_rule("nope", base)
    # A base rule exports too (nothing of the deployment in it).
    assert "ssh-brute-force" in rule_layers.export_rule("ssh-brute-force", base)


# ── Migration: rules approved into the base before P1 ────────────────────────────

def _pre_p1_approved(base_text: str) -> str:
    """What the old approve appended to the base (text, inline workspace/target)."""
    return base_text + (
        "\n  - name: log-clearing\n    description: >\n      Auto-proposed by Glorfindel.\n"
        "    enabled: true\n    source: azure_monitor\n"
        f"    workspace_id: \"{WS}\"\n    ttp: T1070.002\n    resource_id: \"{VM_ID}\"\n"
        "    interval_s: 30\n    query: |\n      Syslog | where SyslogMessage has \"rm -f\"\n")


def test_migrate_moves_what_the_modified_base_holds_beyond_the_base(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    modified = tmp_path / "approved.yaml"
    # Approved rule appended; ssh-brute-force edited on the VM; sudo-root removed on the VM.
    text = _pre_p1_approved(BASE_V1).replace("interval_s: 30\n    query: |\n      Syslog | where "
                                             "SyslogMessage has \"Failed", "interval_s: 15\n    query: |\n"
                                             "      Syslog | where SyslogMessage has \"Failed")
    text = text.replace(BASE_V1.split("  - name: sudo-root")[1], "\n").replace("  - name: sudo-root", "")
    modified.write_text(text)

    dry = rule_layers.migrate(modified, base, dry_run=True)
    assert not client_rules_path().exists()
    report = rule_layers.migrate(modified, base)
    assert dry["added"] == report["added"] == ["ssh-brute-force", "log-clearing"]
    assert report["overrides"] == ["ssh-brute-force"] and report["disable"] == ["sudo-root"]

    cfg = load_config(base)
    rules = _names(cfg)
    assert set(rules) == {"ssh-brute-force", "log-clearing"}
    assert rules["ssh-brute-force"].interval_s == 15 and rules["ssh-brute-force"].layer == "client"
    assert rules["log-clearing"].layer == "client" and rules["log-clearing"].workspace_id == WS

    again = rule_layers.migrate(modified, base)
    assert again["added"] == [] and again["replaced"] == [] and again["disable"] == []
    assert sorted(again["same"]) == ["log-clearing", "ssh-brute-force"]


def test_migrate_an_untouched_base_moves_nothing(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    report = rule_layers.migrate(base, base)
    assert not any(report[k] for k in ("added", "replaced", "same", "disable", "assets"))


# ── CLI ──────────────────────────────────────────────────────────────────────────

def _cli(*args):
    from glorfindel.cli import cli
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def test_cli_approve_rule_says_the_client_layer(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    res = _cli("approve-rule", _propose(), "--rules", str(base))
    assert "approved" in res.output and "client" in res.output and base.read_text() == BASE_V1
    assert all_proposals()[0]["status"] == "approved"


def test_cli_rules_shows_each_rule_and_its_layer(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text("disable: [sudo-root]\nrules:\n  - name: mine\n    query: Syslog\n")
    res = _cli("rules", "--rules", str(base))
    assert res.exit_code == 0
    assert "mine" in res.output and "client" in res.output and "ssh-brute-force" in res.output
    assert "sudo-root" in res.output and "désactivée" in res.output


def test_cli_export_rule_prints_it_generalised_or_refuses(tmp_path, monkeypatch):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    rule_layers.write_client_rule(_identified_client_rule())
    res = _cli("export-rule", "vm-example-01-log-clearing", "--rules", str(base))
    assert res.exit_code == 0 and WS not in res.output and VM_ID not in res.output
    assert yaml.safe_load(res.output)["rules"][0]["ttp"] == "T1070.002"
    out = tmp_path / "out.yaml"
    res = _cli("export-rule", "vm-example-01-log-clearing", "--rules", str(base), "--out", str(out))
    assert res.exit_code == 0 and WS not in out.read_text()
    monkeypatch.setattr(rule_layers, "_scrub", lambda text, names, counts, kql=False: text)
    res = _cli("export-rule", "vm-example-01-log-clearing", "--rules", str(base), "--out", str(out))
    assert res.exit_code == 1 and "exporté" in res.output and WS in res.output


def test_cli_migrate_rules(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    modified = tmp_path / "approved.yaml"
    modified.write_text(_pre_p1_approved(BASE_V1))
    res = _cli("migrate-rules", "--from", str(modified), "--base", str(base), "--dry-run")
    assert "log-clearing: added" in res.output and not client_rules_path().exists()
    res = _cli("migrate-rules", "--from", str(modified), "--base", str(base))
    assert res.exit_code == 0 and "log-clearing: added" in res.output
    assert "Restart the watch" in res.output
    assert _names(load_config(base))["log-clearing"].layer == "client"


# ── Docker: the base read-only, the layer in ~/.glorfindel ───────────────────────

def test_the_containers_mount_the_base_read_only_and_the_state_read_write():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for name in ("watch", "war-room", "bot"):
        vols = compose["services"][name]["volumes"]
        assert "./glorfindel/rules:/app/glorfindel/rules:ro" in vols, name
        assert "${HOME}/.glorfindel:/root/.glorfindel" in vols, name
    make = (ROOT / "Makefile").read_text()
    assert "-v $(PWD)/glorfindel/rules:/app/glorfindel/rules:ro" in make


# ── Reviews: the export replaces what is sure, refuses what it does not follow ────

# (form in the query, what must not leave). Names the deployment does not list (vm-other-9,
# rg-other, law-other) are caught by where they stand: a literal directly compared to an
# identity column, the argument of workspace()/resource()/app(), an ARM instance path.
_LEAKS = [
    ('Computer has_any ("vm-other-9", "vm-other-8")', "vm-other-"),
    ('Computer has_all ("vm-other-9")', "vm-other-9"),
    ('Computer matches regex "^vm-other-9$"', "vm-other-9"),
    ('Computer matches regex "^vm-example-0[1-3]$"', "vm-example-0[1-3]"),
    ('Computer matches regex @"vm\\-example\\-01"', "example"),
    ('Computer == @"vm-other-9"', "vm-other-9"),
    ("Computer == h'vm-other-9'", "vm-other-9"),
    ('Computer =~ H@"vm-other-9"', "vm-other-9"),
    ('Computer in~ ("vm-other-9")', "vm-other-9"),
    ('Computer startswith "vm-other"', "vm-other"),
    ('"vm-other-9" == Computer', "vm-other-9"),
    ('tolower(Computer) == "vm-other-9"', "vm-other-9"),
    ('_ResourceId endswith "/virtualMachines/vm-other-9"', "vm-other-9"),
    ('TenantId == "tenant-other"', "tenant-other"),
    ('Caller == "admin@other.example"', "admin@other"),
    ('SyslogMessage has "resourceGroups/rg-other/providers/Microsoft.Compute/virtualMachines/vm-other-9"',
     "other"),
    ('SyslogMessage matches regex @"vm\\-example\\-01"', "example"),
]


@pytest.mark.parametrize("form, secret", _LEAKS)
def test_every_identifying_form_is_replaced_and_seen_by_the_guard(tmp_path, form, secret):
    query = f"Syslog\n| where {form}\n| project TimeGenerated\n"
    names = rule_layers.known_names([{"assets": [{"name": "vm-example-01", "resource_id": VM_ID}]}])
    assert rule_layers.find_identifiers(query, names), form            # the guard sees it raw
    text = _export(tmp_path, rule={"name": "form", "ttp": "T1", "assets": ["auto"], "query": query})
    assert secret.lower() not in text.lower(), text
    assert "| project TimeGenerated" in text                            # the rest stays


@pytest.mark.parametrize("query, secret", [
    ('union Syslog, workspace("law-other").Syslog\n| where SyslogMessage has "x"\n', "law-other"),
    ('resource("vm-other-9").Heartbeat\n| take 1\n', "vm-other-9"),
    ('app("appi-other").requests\n| take 1\n', "appi-other"),
    ('Syslog // only vm-other-9 for now\n| where SyslogMessage has "x"\n', "vm-other-9"),
])
def test_a_scope_function_or_a_comment_lets_nothing_out(tmp_path, query, secret):
    if "//" not in query:
        assert rule_layers.find_identifiers(query), query
    text = _export(tmp_path, rule={"name": "q", "ttp": "T1", "assets": ["auto"], "query": query})
    assert secret not in text, text


# Forms that reach an identity through an intermediate: the export refuses, names the form,
# and says to generalise by hand — it never guesses (second review).
_REFUSED = [
    ("let", 'let target = "vm-other-9";\nSyslog\n| where Computer == target\n', "let « target »"),
    ("let", 'Syslog\n| where TimeGenerated > ago(1h)\n| where Computer == t\n| extend x = 1;\nlet t = "vm-other-9"\n',
     "let « t »"),
    ("let in let", 'let a = "vm-other-9";\nlet b = a;\nSyslog\n| where Computer == b\n', "let « b »"),
    ("let", 'let hosts = dynamic(["vm-other-9"]);\nSyslog\n| where Computer in (hosts)\n', "let « hosts »"),
    ("let", 'let ws = "law-other";\nunion workspace(ws).Syslog\n', "let « ws »"),
    ("scope", 'union workspace(strcat("law-", "other")).Syslog\n', "argument non littéral de workspace()"),
    ("scope", 'let w = toscalar(Heartbeat | take 1 | project Computer);\nunion workspace(w).Syslog\n',
     "argument non littéral de workspace()"),
    ("alias", 'Syslog\n| extend h = Computer\n| where h == "vm-other-9"\n', "alias « h »"),
    ("alias", 'Syslog\n| project-rename Machine = Computer\n| where Machine has "vm-other"\n', "alias « Machine »"),
    ("alias", 'Syslog\n| project M = Computer, SyslogMessage\n| where M in ("vm-other-9")\n', "alias « M »"),
    ("alias", 'Syslog\n| summarize n = count() by Machine=Computer\n| where Machine =~ "vm-other-9"\n',
     "alias « Machine »"),
    ("alias", 'AzureActivity\n| extend g = ResourceGroup\n| extend g2 = g\n| where g2 == "rg-other"\n', "alias « g2 »"),
    ("udf", 'let f = (c:string) { Syslog | where Computer == c };\nf("vm-other-9")\n', "fonction « f »"),
    ("udf", 'let f = () { Heartbeat | where Computer startswith "vm" };\nf()\n', "fonction « f »"),
    ("expression", 'Syslog\n| where Computer == strcat("vm-", "other-9")\n', "Computer comparé à une expression"),
]


@pytest.mark.parametrize("family, query, said", _REFUSED)
def test_a_form_the_export_does_not_follow_is_refused_and_named(tmp_path, family, query, said):
    with pytest.raises(rule_layers.NotGeneralizable) as err:
        _export(tmp_path, rule={"name": "q", "ttp": "T1", "assets": ["auto"], "query": query})
    assert "à la main" in str(err.value) and "rien n'est exporté" in str(err.value)
    assert any(said in f for f in err.value.found), err.value.found
    assert rule_layers.find_identifiers(query), family                 # the guard refuses it too


def test_cli_export_rule_names_the_form_to_generalise_by_hand(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    rule_layers.write_client_rule({"name": "q", "ttp": "T1", "assets": ["auto"],
                                   "query": 'let t = "vm-other-9";\nSyslog\n| where Computer == t\n'})
    res = _cli("export-rule", "q", "--rules", str(base))
    assert res.exit_code == 1 and "à la main" in res.output and "let « t »" in res.output
    assert "vm-other-9" not in res.output


# Sound rules: nothing in them names the deployment — they export as written (comments aside).
_SANE = [
    'Syslog\n| where TimeGenerated > ago(10m)\n| summarize FailedAttempts = countif(SyslogMessage has '
    '"Failed password") by Computer, _ResourceId\n| where FailedAttempts >= 10\n',
    'Syslog\n| summarize n = count() by Computer, SourceIP = extract(@"from (\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, '
    'SyslogMessage)\n',
    'Perf\n| extend Vm = tostring(split(_ResourceId, "/")[8])\n| where CounterName == "Disk Write Bytes/sec"\n',
    'Perf\n| extend Vm = iff(isnotempty(_ResourceId), tolower(_ResourceId), Computer)\n'
    '| where ObjectName == "Logical Disk"\n',
    'Syslog\n| where SyslogMessage has_any ("history -c", "shred")\n'
    '| project TimeGenerated, Computer, _ResourceId, SyslogMessage\n',
    'Syslog\n| where Computer != "" and Facility == "authpriv"\n',
    'AzureActivity\n| where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"\n'
    '| where ActivityStatusValue == "Success"\n| project TimeGenerated, Caller, _ResourceId\n',
    'AzureActivity\n| where Caller !has "@" and OperationNameValue has "roleAssignments/write"\n',
    'AzureActivity\n| where OperationNameValue in~ ("Microsoft.Storage/storageAccounts/listKeys/action", '
    '"Microsoft.Network/networkSecurityGroups/securityRules/write", "Microsoft.KeyVault/vaults/secrets/write", '
    '"Microsoft.Compute/disks/beginGetAccess/action")\n',
    'AzureActivity\n| where OperationNameValue has "storageAccounts/listKeys/action"\n',
    # A rule as detection_authoring writes them.
    'Syslog\n| where TimeGenerated > ago(10m)\n| where Facility in ("auth", "authpriv", "user")\n'
    '| where SyslogMessage has_any ("rm -f /var/log", "shred", "history -c", "truncate -s 0")\n'
    '| summarize Count = count(), First = min(TimeGenerated) by Computer, _ResourceId, ProcessName\n'
    '| where Count >= 1\n| project TimeGenerated = First, Computer, _ResourceId, ProcessName, Count\n',
]


@pytest.mark.parametrize("query", _SANE)
def test_a_sound_rule_exports_as_written(tmp_path, query):
    text = _export(tmp_path, rule={"name": "sane", "ttp": "T1", "assets": ["auto"], "query": query})
    assert yaml.safe_load(text)["rules"][0]["query"] == query
    assert rule_layers.find_identifiers(query) == []


def test_the_shipped_rules_export_as_written_but_their_comments():
    """Every rule of the base exports, equal to its query without its comment lines."""
    data = yaml.safe_load(SHIPPED_BASE.read_text())
    for rule in data["rules"]:
        text = rule_layers.export_rule(rule["name"], SHIPPED_BASE)
        exported = yaml.safe_load(text)["rules"][0]["query"]
        without_comments = "".join(line for line in rule["query"].splitlines(keepends=True)
                                   if not line.strip().startswith("//"))
        assert exported.rstrip("\n") == without_comments.rstrip("\n"), rule["name"]


def test_the_guard_reads_the_exported_query_as_kql(tmp_path, monkeypatch):
    """A literal compared to an identity column, unknown to the deployment, that the
    replacement missed: only the guard's KQL reading sees it — nothing is exported."""
    monkeypatch.setattr(rule_layers, "_scrub", lambda text, names, counts, kql=False: text)
    rule = {"name": "q", "ttp": "T1", "assets": ["auto"], "query": 'Syslog\n| where Computer has_any ("vm-other-9")\n'}
    with pytest.raises(rule_layers.IdentifierLeft) as err:
        _export(tmp_path, rule=rule)
    assert '"vm-other-9"' in err.value.found


# ── Review: one bad entry of the client's layer never stops the detection ────────

@pytest.mark.parametrize("layer, said", [
    ("rules:\n  - name: bad\n    interval_s: 30s\n    query: S\n", "interval_s"),
    ("rules:\n  - name: bad\n    expected_latency_s: soon\n    query: S\n", "expected_latency_s"),
    ("rules:\n  - name: [x]\n    query: S\n", "pas de nom"),
    ("rules:\n  - name: bad\n    enabled: yes please\n    query: S\n", "enabled"),
    ("rules:\n  - name: bad\n    assets: vm-1\n    query: S\n", "assets"),
    ("rules:\n  - name: bad\n    query: [S]\n", "query"),
    ("rules:\n  - name: bad\n    interval_s: 0\n    query: S\n", "positif"),
    ("assets:\n  - name: a1\n    monitoring_backends: law\n", "monitoring_backends"),
])
def test_a_bad_client_entry_is_skipped_said_and_the_rest_loads(tmp_path, layer, said):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(layer + ("rules:\n" if not layer.startswith("rules") else "")
                                   + "  - name: fine\n    assets: [auto]\n    query: Syslog\n")
    cfg = load_config(base, glorfindel_cfg=_gcfg())
    names = _names(cfg)
    assert {"ssh-brute-force", "sudo-root", "fine"} <= set(names) and "bad" not in names
    assert any(said in n and "ignorée" in n for n in cfg.notes), cfg.notes


@pytest.mark.parametrize("layer, said", [
    ("rules:\n  mine:\n    query: S\n", "`rules` n'est pas une liste"),
    ("disable: sudo-root\n", "`disable` n'est pas une liste"),
    ("- name: x\n", "n'est pas un dictionnaire"),
    ("rule:\n  - name: x\n    query: S\n", "clé `rule` inconnue"),
    ("disable: [[sudo-root]]\n", "n'est pas un nom de règle"),
])
def test_a_layer_of_the_wrong_shape_is_said_and_the_base_loads(tmp_path, layer, said):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(layer)
    cfg = load_config(base)
    assert set(_names(cfg)) == {"ssh-brute-force", "sudo-root"}
    assert any(said in n for n in cfg.notes), cfg.notes


# ── Review: an approved rule applies to the VMs of its backend ───────────────────

def test_an_approved_rule_on_a_base_without_assets_binds_to_its_backend(tmp_path, monkeypatch):
    """`rule_from_proposal` read `r.monitoring_backends`, which DetectionRule lacks: every
    approved rule took the inline form and applied to no VM, silently."""
    import glorfindel.config as config
    monkeypatch.setattr(config, "load_glorfindel_config", _gcfg)
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    proposal = approve(_propose(), base)
    assert proposal["rule_bound"] is True
    [rule] = rule_layers.read_client_layer()["rules"]
    assert rule["assets"] == ["auto"] and rule["monitoring_backends"] == ["law-main"]
    assert "workspace_id" not in rule and "resource_id" not in rule
    loaded = _names(load_config(base, glorfindel_cfg=_gcfg()))["log-clearing"]
    assert loaded.auto_apply and loaded.monitoring_backend_name == "law-main" and loaded.workspace_id == WS


def test_an_approved_rule_with_no_backend_says_it_detects_nothing(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    proposal = approve(_propose(), base)
    assert proposal["rule_bound"] is False
    cfg = load_config(base)
    assert any("log-clearing" in n and "aucune VM" in n for n in cfg.notes), cfg.notes
    res = _cli("approve-rule", _propose(rule_name="other"), "--rules", str(base))
    assert "applies to no" in res.output


def test_migrate_binds_a_rule_approved_before_p1_to_its_backend_or_says_it_cannot(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    modified = tmp_path / "approved.yaml"
    modified.write_text(_pre_p1_approved(BASE_V1))
    report = rule_layers.migrate(modified, base, glorfindel_cfg=_gcfg())
    assert report["converted"] and "law-main" in report["converted"][0] and report["legacy"] == []
    [rule] = rule_layers.read_client_layer()["rules"]
    assert rule["assets"] == ["auto"] and rule["monitoring_backends"] == ["law-main"]
    assert "workspace_id" not in rule and "resource_id" not in rule
    assert _names(load_config(base, glorfindel_cfg=_gcfg()))["log-clearing"].monitoring_backend_name == "law-main"
    assert rule_layers.migrate(modified, base, glorfindel_cfg=_gcfg())["same"] == ["log-clearing"]

    client_rules_path().unlink()
    report = rule_layers.migrate(modified, base)                       # no backend for its workspace
    assert report["converted"] == [] and "log-clearing" in report["legacy"][0]
    assert rule_layers.read_client_layer()["rules"][0]["workspace_id"] == WS
    res = _cli("migrate-rules", "--from", str(modified), "--base", str(base), "--dry-run")
    assert "aucun backend unique" in res.output


@pytest.mark.parametrize("which", ["from", "base"])
def test_migrate_rules_says_an_unreadable_file_and_writes_nothing(tmp_path, which):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    modified = tmp_path / "approved.yaml"
    modified.write_text(_pre_p1_approved(BASE_V1))
    (modified if which == "from" else base).write_text("rules: [unclosed\n")
    res = _cli("migrate-rules", "--from", str(modified), "--base", str(base))
    assert res.exit_code == 1 and "YAML illisible" in res.output and "nothing written" in res.output
    assert not client_rules_path().exists()


# ── Second review: bound or not, and said ────────────────────────────────────────

def test_cli_rules_shows_the_backend_of_an_auto_rule_or_that_it_is_inert(tmp_path, monkeypatch):
    import glorfindel.config as config
    monkeypatch.setattr(config, "load_glorfindel_config", _gcfg)
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(
        "rules:\n  - name: bound\n    monitoring_backends: [law-main]\n    assets: [auto]\n    query: Syslog\n"
        "  - name: inline\n    workspace_id: ws-elsewhere\n    query: Syslog\n")
    res = _cli("rules", "--rules", str(base))
    lines = {line.split()[0]: line for line in res.output.splitlines() if line.strip()}
    assert "auto (law-main)" in lines["bound"]
    assert "inerte" in lines["inline"]


def test_cli_rules_says_an_ignored_layer_not_an_absent_one(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text("- name: x\n")
    res = _cli("rules", "--rules", str(base))
    assert "ignorée" in res.output and "(absente)" not in res.output


def _base_with_a_bound_rule(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text("rules:\n  - name: a\n    monitoring_backends: [law-main]\n    assets: [auto]\n    query: Syslog\n")
    return base


def test_an_approved_rule_of_another_workspace_is_not_bound_to_the_first_rules_backend(tmp_path, monkeypatch):
    """The first rule's backend watches WS: a proposal on another workspace bound there would
    run on the wrong workspace, silently. Not bound, and why."""
    import glorfindel.config as config
    monkeypatch.setattr(config, "load_glorfindel_config", _gcfg)
    base = _base_with_a_bound_rule(tmp_path)
    proposal = approve(_propose(workspace_id="00000000-0000-0000-0000-0000000000c3"), base)
    assert proposal["rule_bound"] is False and "ne surveille son workspace" in proposal["rule_unbound_reason"]
    assert "assets" not in rule_layers.read_client_layer()["rules"][0]
    res = _cli("approve-rule", _propose(rule_name="other", workspace_id="00000000-0000-0000-0000-0000000000c3"),
               "--rules", str(base))
    out = " ".join(res.output.split())
    assert "Not bound" in out and "ne surveille son workspace" in out


def test_an_approved_rule_without_workspace_borrows_the_first_rules_backend(tmp_path, monkeypatch):
    import glorfindel.config as config
    monkeypatch.setattr(config, "load_glorfindel_config", _gcfg)
    base = _base_with_a_bound_rule(tmp_path)
    proposal = approve(_propose(workspace_id=""), base)
    assert proposal["rule_bound"] is True
    assert rule_layers.read_client_layer()["rules"][0]["monitoring_backends"] == ["law-main"]


def test_migrate_rules_says_an_unreadable_config(tmp_path, monkeypatch):
    import glorfindel.config as config

    def broken(*a, **k):
        raise config.ConfigError("glorfindel-config.yaml : ScannerError: bad")
    monkeypatch.setattr(config, "load_glorfindel_config", broken)
    base = tmp_path / "base.yaml"
    base.write_text(BASE_V1)
    modified = tmp_path / "approved.yaml"
    modified.write_text(_pre_p1_approved(BASE_V1))
    res = _cli("migrate-rules", "--from", str(modified), "--base", str(base), "--dry-run")
    assert "glorfindel-config.yaml illisible" in res.output and "aucun backend unique" not in res.output
