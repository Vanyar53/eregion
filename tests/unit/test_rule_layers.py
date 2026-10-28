"""P1: rule layers — the shipped base stays intact, the client's rules live in their own layer.

`proposed_rules.approve` wrote the approved rule into detection_rules.yaml, the file shipped
with Glorfindel: an update replaced it (rule lost), and on H0 the modified checkout stopped
the deployment (M-3). Now the rule goes to the client's layer (~/.glorfindel/client_rules.yaml,
redirected to tmp by the conftest), loaded over the base: a client rule of a base rule's name
wins (said), a client rule can disable a base rule by name. (Exporting a rule generalised,
without any identifier, is left to a lot of P2, reviewed by a human before anything is sent.)

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


# ── Fini quand: an update of the base loses no client rule ─────────────────

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
                                             "SyslogMessage has \"Failed", "interval_s: 45\n    query: |\n"
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
    assert rules["ssh-brute-force"].interval_s == 45 and rules["ssh-brute-force"].layer == "client"
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


# ── Review: one bad entry of the client's layer never stops the detection ────────

@pytest.mark.parametrize("layer, said", [
    ("rules:\n  - name: bad\n    interval_s: 30s\n    query: S\n", "interval_s"),
    ("rules:\n  - name: bad\n    expected_latency_s: soon\n    query: S\n", "expected_latency_s"),
    ("rules:\n  - name: [x]\n    query: S\n", "pas de nom"),
    ("rules:\n  - name: bad\n    enabled: yes please\n    query: S\n", "enabled"),
    ("rules:\n  - name: bad\n    assets: vm-1\n    query: S\n", "assets"),
    ("rules:\n  - name: bad\n    query: [S]\n", "query"),
    ("rules:\n  - name: bad\n    interval_s: 0\n    query: S\n", "au moins"),
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
