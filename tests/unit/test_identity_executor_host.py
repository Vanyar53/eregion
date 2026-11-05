"""IR1b (#572): the identity executor's application in H0's Terraform (infra/glorfindel-host/
identity_executor.tf) — off by default, its Graph permissions exactly the contract's closed list,
never a refused one, never a directory role here (IDI1b's), never H0's own identity.

Read from the files, no Azure, no Graph, no Terraform needed. The same, planned against mock
providers: infra/glorfindel-host/tests/identity_executor.tftest.hcl (`terraform test`). Mutants
M4070–M4084 (scripts/mutants/IR1b.py).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from glorfindel.providers.azure import identity_contract as ic

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "infra/glorfindel-host"


def _tf() -> str:
    return (HOST / "identity_executor.tf").read_text(encoding="utf-8")


def _every_tf() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(HOST.glob("*.tf")))


def test_its_graph_permissions_are_the_contracts_closed_list():
    local = re.search(r"identity_executor_permissions\s*=\s*var\.identity_executor_enabled \? "
                      r"toset\(\[([^\]]*)\]\) : toset\(\[\]\)", _tf())
    assert local, "the permissions are not one list behind the flag"
    names = set(re.findall(r'"([^"]+)"', local.group(1)))
    assert names == ic.ADMITTED_PERMISSIONS
    assert not names & ic.REFUSED_PERMISSIONS


def test_no_refused_right_and_no_directory_role_anywhere_in_h0s_terraform():
    every = _every_tf()
    for right in ic.REFUSED_PERMISSIONS | set(ic.REFUSED_ROLES.values()):
        assert right not in every, right
    # Its scoped roles are IDI1b's (Celebrimbor), the ownership of what is enrolled IDI1's.
    assert "azuread_directory_role" not in every
    assert "owners" not in _tf()
    assert set(re.findall(r'resource "(azuread_\w+)"', every)) == {
        "azuread_application", "azuread_service_principal", "azuread_app_role_assignment",
        "azuread_application_certificate"}


def test_off_by_default_and_every_resource_behind_the_flag():
    variables = (HOST / "variables.tf").read_text(encoding="utf-8")
    block = variables.split('variable "identity_executor_enabled"')[1].split("\n}\n")[0]
    assert "default     = false" in block
    tf = _tf()
    for kind, name in re.findall(r'(?:resource|data) "(\w+)" "(\w+)" \{', tf):
        body = tf.split(f'"{kind}" "{name}" {{')[1].split("\n}\n")[0]
        assert ("count" in body and "var.identity_executor_enabled" in body) or \
            "for_each            = local.identity_executor_permissions" in body, (kind, name)


def test_its_rights_go_to_its_own_principal_never_to_h0s_identity():
    tf = _tf()
    assert "azurerm_linux_virtual_machine" not in tf
    assert tf.count("principal_object_id = azuread_service_principal.identity_executor[0].object_id") == 1
    assert "principal_id         = azuread_service_principal.identity_executor[0].object_id" in tf
    assert 'role_definition_name = "Log Analytics Reader"' in tf
    assert "scope                = data.azurerm_log_analytics_workspace.bench.id" in tf
    assert 'sign_in_audience = "AzureADMyOrg"' in tf
    # No secret: a certificate's public part only, its key drawn on H0.
    assert "azuread_application_password" not in _every_tf()


def test_a_private_key_is_refused_by_the_plan():
    variables = (HOST / "variables.tf").read_text(encoding="utf-8")
    block = variables.split('variable "identity_executor_certificate"')[1].split("\n}\n")[0]
    assert '!strcontains(upper(var.identity_executor_certificate), "PRIVATE KEY")' in block
    assert 'default     = ""' in block


def test_the_module_locks_azuread_and_every_test_mocks_it():
    lock = (HOST / ".terraform.lock.hcl").read_text(encoding="utf-8")
    assert 'provider "registry.terraform.io/hashicorp/azuread"' in lock
    main = (HOST / "main.tf").read_text(encoding="utf-8")
    assert 'provider "azuread" {\n  tenant_id = data.azurerm_subscription.current.tenant_id\n}' in main
    for path in sorted((HOST / "tests").glob("*.tftest.hcl")):
        assert 'mock_provider "azuread"' in path.read_text(encoding="utf-8"), path.name


def test_its_tfvars_stay_off_the_repository_and_its_example_does_not():
    if not (ROOT / ".git").exists():
        pytest.skip("outside a checkout (the mutants' copy): git cannot say what it ignores")

    def ignored(rel):
        return subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT).returncode == 0
    assert ignored("infra/glorfindel-host/identity_executor.auto.tfvars")
    assert not ignored("infra/glorfindel-host/identity_executor.auto.tfvars.example")
    example = (HOST / "identity_executor.auto.tfvars.example").read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in example and 'identity_executor_certificate = ""' in example


def test_its_outputs_name_the_contracts_variable():
    outputs = (HOST / "outputs.tf").read_text(encoding="utf-8")
    assert ic.CLIENT_ENV in outputs.split('output "identity_executor_client_id"')[1].split("\n}\n")[0]
