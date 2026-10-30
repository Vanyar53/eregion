"""ID1 (#281): the bench's diagnostic settings — the Activity Log (AL1) and Entra ID (C2).

Read from the files, no Azure, no Terraform needed (the CI has none):
  - the categories the Terraform sends are exactly those the shipped rules read — a table
    a rule reads with no category sent is a blind rule; a category sent that no rule reads
    is ingestion paid for nothing (Entra's are billed per GB);
  - both settings are off by default, switched by a Terraform variable, posed by the
    canonical instance only;
  - `make celebrimbor-logs-plan` / `celebrimbor-logs-up` touch those two settings and
    nothing else of the bench, never on another instance, never with a `-var` of their own;
    the recipe really runs, against a fake `terraform` first on the PATH.
The same contract, planned against a fake azurerm: infra/terraform/tests/
diagnostic_settings.tftest.hcl (`terraform test`, run by hand). Mutants M1790–M1799.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform"
RULES = ROOT / "glorfindel/rules/azure/detection_rules.yaml"

# Each table a rule may read → the Terraform file that sends it, and its diagnostic category
# (Microsoft Learn: the Activity Log's write/delete/action operations are « Administrative »;
# Entra's categories and the tables they land in).
CATEGORY = {
    "AzureActivity": ("activity_log.tf", "Administrative"),
    "AuditLogs": ("entra_logs.tf", "AuditLogs"),
    "AADServicePrincipalSignInLogs": ("entra_logs.tf", "ServicePrincipalSignInLogs"),
    "SigninLogs": ("entra_logs.tf", "SignInLogs"),
    "AADNonInteractiveUserSignInLogs": ("entra_logs.tf", "NonInteractiveUserSignInLogs"),
    "AADManagedIdentitySignInLogs": ("entra_logs.tf", "ManagedIdentitySignInLogs"),
}
SOURCES = ("azure_activity", "azure_entra")


def _rules():
    return [r for r in yaml.safe_load(RULES.read_text())["rules"]
            if r.get("source") in SOURCES and r.get("enabled", True)]


def _tables(query: str) -> set[str]:
    """The tables a query starts a tabular expression from: a line that is a table name
    alone, or `let x = Table` (a `let` over another name — `baseline` — is lowercase)."""
    return set(re.findall(r"(?m)^\s*(?:let\s+\w+\s*=\s*)?([A-Z]\w*)\s*;?\s*$", query))


def _categories(tf_file: str) -> list[str]:
    text = (TF / tf_file).read_text()
    return re.findall(r'(?m)^\s*category\s*=\s*"([^"]+)"', text)


def test_the_tables_are_found_in_every_shipped_rule():
    rules = _rules()
    assert {r["source"] for r in rules} == set(SOURCES)
    for r in rules:
        assert _tables(r["query"]), r["name"]


def test_each_table_a_rule_reads_is_sent_and_nothing_more():
    needed: dict[str, set[str]] = {"activity_log.tf": set(), "entra_logs.tf": set()}
    for r in _rules():
        for table in _tables(r["query"]):
            assert table in CATEGORY, f"{r['name']} reads {table}: which category sends it?"
            tf_file, category = CATEGORY[table]
            needed[tf_file].add(category)
    assert needed == {"activity_log.tf": {"Administrative"},
                      "entra_logs.tf": {"AuditLogs", "ServicePrincipalSignInLogs"}}
    for tf_file, cats in needed.items():
        sent = _categories(tf_file)
        assert len(sent) == len(set(sent)), tf_file
        assert set(sent) == cats, f"{tf_file} sends {sent}, the rules read {sorted(cats)}"


def test_the_activity_rules_read_only_operations_of_the_administrative_category():
    """Administrative holds the create, update, delete and action operations made through
    Resource Manager: an operation of another kind would need another category."""
    for r in _rules():
        if r["source"] != "azure_activity":
            continue
        ops = re.findall(r'"(MICROSOFT\.[A-Z0-9./]+)"', r["query"].upper())
        assert ops, r["name"]
        assert all(op.rsplit("/", 1)[-1] in ("WRITE", "DELETE", "ACTION") for op in ops), ops


def _variable(name: str) -> str:
    text = (TF / "variables.tf").read_text()
    m = re.search(r'(?ms)^variable "%s" \{\n(.*?)^\}' % name, text)
    assert m, name
    return m.group(1)


@pytest.mark.parametrize("name,tf_file", [("activity_log_enabled", "activity_log.tf"),
                                          ("entra_logs_enabled", "entra_logs.tf")])
def test_off_by_default_switched_by_a_variable_on_the_canonical_instance_only(name, tf_file):
    body = _variable(name)
    assert re.search(r"(?m)^\s*type\s*=\s*bool\s*$", body)
    assert re.search(r"(?m)^\s*default\s*=\s*false\s*$", body)
    assert re.search(r"(?m)^\s*nullable\s*=\s*false\s*$", body)
    text = (TF / tf_file).read_text()
    assert f'{name} = var.{name} && local.instance == "default"' in text
    assert f"count = local.{name} ? 1 : 0" in text
    # Every resource and data block of the file carries that count: nothing runs disabled.
    blocks = re.findall(r'(?m)^(?:resource|data) "[^"]+" "[^"]+" \{\n\s*count = (.*)$', text)
    assert blocks and all(c == f"local.{name} ? 1 : 0" for c in blocks), blocks


def test_never_switched_from_the_tracked_config_nor_the_example():
    """A tenant's logs are its operator's decision: never from config.yaml (tracked, public:
    a fork would send its tenant's logs), never on in the example."""
    cfg = yaml.safe_load((TF / "config.yaml").read_text())
    assert "activity_log" not in cfg and "entra_logs" not in cfg
    for f in TF.glob("*.tf"):
        assert not re.search(r"cfg\.(activity_log|entra_logs)", f.read_text()), f.name
    example = (TF / "terraform.tfvars.example").read_text()
    for name in ("activity_log_enabled", "entra_logs_enabled"):
        assert re.search(rf"(?m)^# {name}\s*=\s*true", example)
        assert not re.search(rf"(?m)^\s*{name}\s*=", example)


def test_an_ephemeral_instance_asking_for_them_is_told():
    text = (TF / "activity_log.tf").read_text()
    assert 'check "diagnostic_settings_on_the_canonical_instance"' in text
    assert ('condition     = local.instance == "default" || '
            "!(var.activity_log_enabled || var.entra_logs_enabled)") in text


# ── the Make targets, against a fake terraform ───────────────────────────────

pytestmark_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
TARGETS = ["-target=azurerm_monitor_diagnostic_setting.activity_log",
           "-target=azurerm_monitor_aad_diagnostic_setting.entra"]


def _make(tmp_path, target, *args):
    """Run ``make target args`` with a fake terraform; return (exit code, output, calls)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "tf.log"
    log.write_text("")
    tf = bin_dir / "terraform"
    tf.write_text('#!/bin/sh\necho "$*" >> "$FAKE_TF_LOG"\n')
    tf.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "FAKE_TF_LOG": str(log)}
    for var in ("INSTANCE", "YES", "TOPO"):
        env.pop(var, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout + res.stderr, [c.split() for c in log.read_text().splitlines()]


@pytestmark_make
def test_logs_plan_plans_the_two_settings_and_nothing_else(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-logs-plan")
    assert code == 0, out
    chdir = "-chdir=infra/terraform"
    assert calls == [[chdir, "init", "-upgrade"], [chdir, "workspace", "select", "default"],
                     [chdir, "plan", *TARGETS]]


@pytestmark_make
@pytest.mark.parametrize("args,approve", [((), []), (("YES=1",), ["-auto-approve"])])
def test_logs_up_applies_them_alone_confirmed_unless_yes(tmp_path, args, approve):
    code, out, calls = _make(tmp_path, "celebrimbor-logs-up", *args)
    assert code == 0, out
    assert calls[-1] == ["-chdir=infra/terraform", "apply", *approve, *TARGETS]
    assert not any(a.startswith("-var") for c in calls for a in c)


@pytestmark_make
@pytest.mark.parametrize("target", ["celebrimbor-logs-plan", "celebrimbor-logs-up"])
def test_another_instance_is_refused_before_any_call(tmp_path, target):
    code, out, calls = _make(tmp_path, target, "INSTANCE=ci-1234", "YES=1")
    assert code != 0
    assert "instance 'ci-1234' refusée" in out
    assert calls == []
