"""IDI1 (#546): the bench's test identity in Entra ID — an application and its service principal,
enrolled by both keys (its Graph tags name the bench and the zone; the bench's resource group names
it, eregion-identities) — off by default, the canonical instance only, no secret, single tenant.

Read from the files, no Azure, no Graph, no Terraform needed; the Make targets run against a fake
terraform first on the PATH. The same contract, planned against mock providers:
infra/terraform/tests/entra_identity.tftest.hcl (`terraform test`). Mutants M3864 (scripts/mutants/IDI1.py).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from eregion_core import inscription

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform"


def _identity_tf() -> str:
    return (TF / "entra_identity.tf").read_text(encoding="utf-8")


def _block(text: str, kind: str, name: str) -> str:
    return text.split(f'{kind} "{name}"')[1].split("\n}\n")[0]


def test_off_by_default_on_the_canonical_instance_only():
    variables = (TF / "variables.tf").read_text(encoding="utf-8")
    body = re.search(r'(?ms)^variable "entra_test_identity_enabled" \{\n(.*?)^\}', variables).group(1)
    assert re.search(r"(?m)^\s*type\s*=\s*bool\s*$", body)
    assert re.search(r"(?m)^\s*default\s*=\s*false\s*$", body)
    assert re.search(r"(?m)^\s*nullable\s*=\s*false\s*$", body)
    text = _identity_tf()
    assert 'entra_test_identity_enabled = var.entra_test_identity_enabled && local.instance == "default"' in text
    blocks = re.findall(r'(?m)^(?:resource|data) "[^"]+" "[^"]+" \{\n\s*count = (.*)$', text)
    assert len(blocks) == 2 and all(c == "local.entra_test_identity_enabled ? 1 : 0" for c in blocks), blocks
    assert 'check "entra_test_identity_on_the_canonical_instance"' in text
    assert 'condition     = local.instance == "default" || !var.entra_test_identity_enabled' in text
    example = (TF / "terraform.tfvars.example").read_text(encoding="utf-8")
    assert re.search(r"(?m)^# entra_test_identity_enabled = true", example)
    assert not re.search(r"(?m)^\s*entra_test_identity_enabled\s*=", example)


def test_the_entra_key_names_the_bench_and_its_zone_as_the_guard_reads_them():
    """The application's tags are the bench's own inscription values (locals.tf), written
    ``name=value`` — the form the guard reads (eregion_core/inscription.py)."""
    text = _identity_tf()
    assert f'"{inscription.TARGET_TAG}=${{local.common_tags["{inscription.TARGET_TAG}"]}}"' in text
    assert f'"{inscription.ZONE_TAG}=${{local.common_tags["{inscription.ZONE_TAG}"]}}"' in text
    app = _block(text, "resource", "azuread_application\" \"bench_test")
    assert "tags             = local.identity_enrollment_tags" in app
    assert f'sign_in_audience = "{inscription.SINGLE_TENANT}"' in app


def test_the_arm_key_names_the_application_on_the_bench_s_group():
    text = _identity_tf()
    assert (f'"{inscription.IDENTITIES_TAG}" = azuread_application.bench_test[0].object_id' in text)
    main = (TF / "main.tf").read_text(encoding="utf-8")
    group = _block(main, "resource", "azurerm_resource_group\" \"celebrimbor")
    assert "tags     = merge(local.common_tags, local.identity_tags)" in group
    # Only the bench's group names it: no other resource takes identity_tags.
    every = "\n".join(p.read_text(encoding="utf-8") for p in TF.glob("*.tf"))
    assert every.count("local.identity_tags") == 1


def test_the_test_identity_has_no_secret_no_right_no_owner():
    """No password, certificate or federated credential (a technique adds one, the rule
    entra-credential-added sees it); no permission asked, no role, no consent."""
    every = "\n".join(p.read_text(encoding="utf-8") for p in TF.glob("*.tf"))
    resources = set(re.findall(r'resource "(azuread_\w+)"', every))
    # IDI1b adds the bench's test users, their unit membership and the executor's roles
    # (entra_bench_unit.tf, tests/unit/test_bench_users.py): still no secret, no consent, no owner.
    # BRO1 adds the bench's read identity: one certificate, on its own application alone
    # (bench_reader.tf, tests/unit/test_bench_reader.py) — never on the test identity.
    assert resources == {"azuread_application", "azuread_service_principal", "azuread_user",
                         "azuread_administrative_unit_member", "azuread_directory_role_assignment",
                         "azuread_application_certificate"}
    reader = (TF / "bench_reader.tf").read_text(encoding="utf-8")
    assert every.count('resource "azuread_application_certificate"') == 1
    assert 'resource "azuread_application_certificate" "bench_reader"' in reader
    assert "application_id = azuread_application.bench_reader[0].id\n" in reader
    assert "azuread_application.bench_test" not in reader
    for word in ("azuread_application_password", "azuread_service_principal_password",
                 "azuread_application_federated_identity_credential", "azuread_app_role_assignment",
                 "azuread_service_principal_delegated_permission_grant", "azuread_application_owner"):
        assert f'resource "{word}"' not in every, word
    app = _block(_identity_tf(), "resource", "azuread_application\" \"bench_test")
    for word in ("password", "certificate", "federated", "required_resource_access", "owners", "app_role "):
        assert word not in app, word


def test_the_module_locks_azuread():
    lock = (TF / ".terraform.lock.hcl").read_text(encoding="utf-8")
    assert 'provider "registry.terraform.io/hashicorp/azuread"' in lock
    main = (TF / "main.tf").read_text(encoding="utf-8")
    assert 'source  = "hashicorp/azuread"' in main
    # Bound to the bench subscription's tenant: an az login on another tenant writes nothing there
    # (relecture of IDI1, M3943) — read without a count, so the plan off changes nothing.
    assert 'provider "azuread" {\n  tenant_id = data.azurerm_subscription.bench.tenant_id\n}' in main
    assert 'data "azurerm_subscription" "bench" {}' in main
    assert main.count('provider "azuread"') == 1
    tftest = (TF / "tests" / "entra_identity.tftest.hcl").read_text(encoding="utf-8")
    for run in ("off_nothing_in_the_tenant_the_group_as_always", "on_both_keys_one_per_plane"):
        assert f'run "{run}"' in tftest, run
    # Every Terraform test of the module mocks azuread: none reaches Graph.
    for path in (TF / "tests").glob("*.tftest.hcl"):
        assert 'mock_provider "azuread"' in path.read_text(encoding="utf-8"), path.name


# ── the Make targets, against a fake terraform ───────────────────────────────

pytestmark_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
TARGETS = ["-target=azuread_application.bench_test", "-target=azuread_service_principal.bench_test",
           "-target=azurerm_resource_group.celebrimbor"]


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
def test_identity_plan_plans_the_identity_and_its_group_alone(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-identity-plan")
    assert code == 0, out
    chdir = "-chdir=infra/terraform"
    assert calls == [[chdir, "init"], [chdir, "workspace", "select", "default"], [chdir, "plan", *TARGETS]]


@pytestmark_make
@pytest.mark.parametrize("args,approve", [((), []), (("YES=1",), ["-auto-approve"])])
def test_identity_up_applies_it_alone_confirmed_unless_yes(tmp_path, args, approve):
    code, out, calls = _make(tmp_path, "celebrimbor-identity-up", *args)
    assert code == 0, out
    assert calls[-1] == ["-chdir=infra/terraform", "apply", *approve, *TARGETS]
    assert not any(a.startswith("-var") for c in calls for a in c)


@pytestmark_make
@pytest.mark.parametrize("target", ["celebrimbor-identity-plan", "celebrimbor-identity-up"])
def test_another_instance_is_refused_before_any_call(tmp_path, target):
    code, out, calls = _make(tmp_path, target, "INSTANCE=ci-1234", "YES=1")
    assert code != 0 and "instance 'ci-1234' refusée" in out and calls == []


@pytestmark_make
@pytest.mark.parametrize("value", ["", "not-a-guid", "$(shell touch MARKER)",
                                   "00000000-0000-0000-0000-0000000000c1 x", "00000000-0000-0000-0000-0000000000c1\n"])
def test_orodruin_identity_takes_an_object_id_alone_before_any_ssh(tmp_path, value):
    """The ID is checked — a GUID, nothing else — before any ssh; never expanded by make."""
    marker = tmp_path / "ran"
    code, out, _ = _make(tmp_path, "orodruin-identity", "ID=" + value.replace("MARKER", str(marker)))
    assert code != 0 and "ID invalide" in out
    assert not marker.exists()


def test_orodruin_identity_passes_the_id_by_the_environment():
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "unexport ID\norodruin-identity orodruin-identity-id: export EREGION_IDENTITY = $(value ID)" in text
    check = text.split("\norodruin-identity-id:\n")[1].split("\n\n")[0]
    assert "grep -Eqx '$(ORO_GUID)'" in check and "ID invalide" in check
    # Checked first, the host's key next, the ssh last.
    assert "\norodruin-identity: orodruin-identity-id orodruin-known\n" in text
    recipe = text.split("\norodruin-identity: orodruin-identity-id orodruin-known\n")[1].split("\n\n")[0]
    assert "python -m eregion_core.inscription identity '\"$$EREGION_IDENTITY\"" in recipe
    assert "$(ID)" not in recipe
