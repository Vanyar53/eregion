"""AUD1 (#408): auditd on the bench's VMs — the Terraform, the script it runs, the rule that reads it.

Read from the files, no Azure, no Terraform needed (the CI has none here):
  - off by default, switched by a Terraform variable in terraform.tfvars, never from the tracked
    config.yaml nor on in the example;
  - on, an extension on each VM of the bench (never the custom_data: changing it replaces the
    VM) and local6 in the bench's DCR; off, the DCR's facilities as they always were;
  - the script loads the CIS rule and the root shell's one, under the login's auid, and sends
    their lines to local6 — the facility the DCR collects, the keys and the human threshold the
    shipped rule and the reader (glorfindel/auditd.py) read: one contract, four files;
  - `make celebrimbor-auditd-plan` / `-up` touch the extension and the DCR, nothing else of the
    bench, never with a `-var` of their own — against a fake `terraform` first on the PATH.
The same contract, planned against a fake azurerm: infra/terraform/tests/auditd.tftest.hcl
(`terraform test`, the CI's terraform-test job). Mutants M2760–M2779.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from glorfindel import auditd

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform"
SCRIPT = TF / "scripts/auditd.sh"
RULES = ROOT / "glorfindel/rules/azure/detection_rules.yaml"


def _rule() -> dict:
    [r] = [r for r in yaml.safe_load(RULES.read_text())["rules"] if r["name"] == "auditd-sensitive-root-command"]
    return r


def _audit_rules() -> list[str]:
    return re.findall(r"(?m)^-a always,exit .*$", SCRIPT.read_text())


def test_off_by_default_switched_by_a_variable():
    text = (TF / "variables.tf").read_text()
    m = re.search(r'(?ms)^variable "auditd_enabled" \{\n(.*?)^\}', text)
    assert m
    body = m.group(1)
    assert re.search(r"(?m)^\s*type\s*=\s*bool\s*$", body)
    assert re.search(r"(?m)^\s*default\s*=\s*false\s*$", body)
    assert re.search(r"(?m)^\s*nullable\s*=\s*false\s*$", body)


def test_never_switched_from_the_tracked_config_nor_the_example():
    cfg = yaml.safe_load((TF / "config.yaml").read_text())
    assert "auditd" not in cfg
    for f in TF.glob("*.tf"):
        assert not re.search(r"cfg\.auditd", f.read_text()), f.name
    example = (TF / "terraform.tfvars.example").read_text()
    assert re.search(r"(?m)^# auditd_enabled\s*=\s*true", example)
    assert not re.search(r"(?m)^\s*auditd_enabled\s*=", example)


def test_on_an_extension_per_bench_vm_never_the_custom_data():
    text = (TF / "auditd.tf").read_text()
    assert "auditd_vms = { for k, v in local.vms : k => v if var.auditd_enabled }" in text
    assert re.search(r'(?ms)resource "azurerm_virtual_machine_extension" "auditd" \{\n\s*for_each\s*= local\.auditd_vms\n', text)
    assert 'type                       = "CustomScript"' in text
    assert 'base64encode(file("${path.module}/scripts/auditd.sh"))' in text
    assert "auditd" not in (TF / "vm.tf").read_text()


def test_local6_in_the_dcr_only_when_on():
    text = (TF / "monitoring.tf").read_text()
    assert ('facility_names = concat(["auth", "authpriv", "syslog", "daemon"], '
            "var.auditd_enabled ? [local.auditd_facility] : [], "
            'var.cron_logs_enabled ? ["cron"] : [])') in text
    assert 'auditd_facility = "local6"' in (TF / "auditd.tf").read_text()


def test_the_script_loads_the_cis_rule_and_the_root_shell_s_one():
    assert _audit_rules() == [
        "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
        "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
        "-a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command",
        "-a always,exit -F arch=b32 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command",
    ]
    text = SCRIPT.read_text()
    assert text.startswith("#!/bin/bash\n") and "set -euo pipefail" in text
    assert "log_format = ENRICHED" in text
    assert "args = LOG_INFO LOG_LOCAL6" in text and "active = yes" in text


def test_one_contract_the_script_the_dcr_the_rule_the_reader():
    """The keys, the facility, the human threshold: written once in each file, the same."""
    keys = tuple(dict.fromkeys(re.findall(r"-k (\w+)$", "\n".join(_audit_rules()), re.M)))
    assert keys == auditd.KEYS
    query = _rule()["query"]
    assert 'Key in ("user_emulation", "root_command")' in query
    assert 'Facility == "local6"' in query
    assert f"Auid >= {auditd.HUMAN_UID_MIN}" in query and f"auid>={auditd.HUMAN_UID_MIN}" in SCRIPT.read_text()
    assert f"Auid != {auditd.UNSET}" in query and "Euid == 0" in query
    assert _rule()["ttp"] == auditd.TTP and _rule()["enabled"] is True


def test_the_terraform_test_plans_both_cases():
    text = (TF / "tests/auditd.tftest.hcl").read_text()
    assert 'run "off_nothing_on_the_vms_the_dcr_as_always"' in text
    assert 'run "on_every_bench_vm_and_local6_nothing_else"' in text
    for f in ("diagnostic_settings.tftest.hcl", "chaos_noise.tftest.hcl", "auditd.tftest.hcl"):
        assert re.search(r"(?m)^  auditd_enabled\s*= false$", (TF / "tests" / f).read_text()), f


# ── the Make targets, against a fake terraform ───────────────────────────────

pytestmark_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
TARGETS = ["-target=azurerm_virtual_machine_extension.auditd",
           "-target=azurerm_monitor_data_collection_rule.celebrimbor"]


def _make(tmp_path, target, *args):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "tf.log"
    log.write_text("")
    tf = bin_dir / "terraform"
    tf.write_text('#!/bin/sh\necho "$*" >> "$FAKE_TF_LOG"\n')
    tf.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_TF_LOG": str(log)}
    for var in ("INSTANCE", "YES", "TOPO"):
        env.pop(var, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout + res.stderr, [c.split() for c in log.read_text().splitlines()]


@pytestmark_make
@pytest.mark.parametrize("args,instance", [((), "default"), (("INSTANCE=ci-1234",), "ci-1234")])
def test_auditd_plan_plans_the_extension_and_the_dcr_alone(tmp_path, args, instance):
    code, out, calls = _make(tmp_path, "celebrimbor-auditd-plan", *args)
    assert code == 0, out
    chdir = "-chdir=infra/terraform"
    assert calls == [[chdir, "init"], [chdir, "workspace", "select", instance], [chdir, "plan", *TARGETS]]


@pytest.mark.parametrize("args,approve", [((), []), (("YES=1",), ["-auto-approve"])])
@pytestmark_make
def test_auditd_up_applies_them_alone_confirmed_unless_yes(tmp_path, args, approve):
    code, out, calls = _make(tmp_path, "celebrimbor-auditd-up", *args)
    assert code == 0, out
    assert calls[-1] == ["-chdir=infra/terraform", "apply", *approve, *TARGETS]
    assert not any(a.startswith("-var") for c in calls for a in c)
