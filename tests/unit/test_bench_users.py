"""IDI1b (#573): the bench's restricted administrative unit and its test users — read from the files
(infra/terraform/entra_bench_unit.tf), the Make targets against a fake terraform, and the Graph
script (infra/terraform/scripts/entra_bench_unit.py) against a fake az: no Azure, no Graph, no
Terraform needed. The same contract, planned against mock providers:
infra/terraform/tests/entra_bench_unit.tftest.hcl (`terraform test`). Every identifier here is an
example. Mutants M4096–M4099 (scripts/mutants/IDI1b.py)."""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from eregion_core import inscription

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform"
SCRIPT = TF / "scripts" / "entra_bench_unit.py"
SUB = "00000000-0000-0000-0000-000000000000"
UNIT = "00000000-0000-0000-0000-0000000000d0"
NEW_UNIT = "00000000-0000-0000-0000-0000000000d1"
USER = "00000000-0000-0000-0000-0000000000c5"
G = "https://graph.microsoft.com/v1.0"


def _tf() -> str:
    return (TF / "entra_bench_unit.tf").read_text(encoding="utf-8")


def _block(text: str, kind: str, name: str) -> str:
    return text.split(f'{kind} "{name}" {{')[1].split("\n}\n")[0]


def _every_tf() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in TF.glob("*.tf"))


def _code(text: str) -> str:
    """The configuration without its comments: what Terraform reads."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# ── The Terraform, read ────────────────────────────────────────────────────────────────

def test_off_by_default_on_the_canonical_instance_only():
    """M4098."""
    text = _tf()
    body = _block(text, "variable", "entra_bench_unit_enabled")
    assert re.search(r"(?m)^\s*type\s*=\s*bool\s*$", body)
    assert re.search(r"(?m)^\s*default\s*=\s*false\s*$", body)
    assert re.search(r"(?m)^\s*nullable\s*=\s*false\s*$", body)
    assert 'entra_bench_unit_enabled = var.entra_bench_unit_enabled && local.instance == "default"' in text
    assert "entra_test_users = local.entra_bench_unit_enabled ? var.entra_test_users : toset([])" in text
    assert 'identity_executor_roles = local.entra_bench_unit_enabled && var.entra_identity_executor_object_id != "" ?' in text
    # Each block is gated: by the flag, by the users (gated), or by the roles (gated).
    gates = re.findall(r'(?m)^(?:resource|data) "[^"]+" "[^"]+" \{\n\s*(count|for_each)\s*=\s*(.*)$', text)
    allowed = {"local.entra_bench_unit_enabled ? 1 : 0", "local.entra_test_users", "azuread_user.bench_test",
               "local.identity_executor_roles", "length(local.identity_executor_roles) > 0 ? 1 : 0"}
    assert len(gates) == 7 and all(g in allowed for _, g in gates), gates
    assert 'check "entra_bench_unit_on_the_canonical_instance"' in text
    example = (TF / "terraform.tfvars.example").read_text(encoding="utf-8")
    for var in ("entra_bench_unit_enabled", "entra_bench_unit_id", "entra_test_users",
                "entra_identity_executor_object_id"):
        assert re.search(rf"(?m)^# {var}\s*=", example), var
        assert not re.search(rf"(?m)^\s*{var}\s*=", example), var


def test_the_unit_is_pinned_by_its_id_never_looked_up_by_name():
    text = _tf()
    data = _block(text, "data", 'azuread_administrative_unit" "bench')
    assert "object_id = var.entra_bench_unit_id" in data and "display_name" not in data
    assert 'resource "azuread_administrative_unit"' not in _every_tf()   # never a non-restricted one
    assert 'output "entra_bench_unit_id"' in text
    assert "data.azuread_administrative_unit.bench[0].object_id" in _block(text, "output", "entra_bench_unit_id")


def test_the_users_hold_no_role_no_licence_no_group():
    """No license, no usage location, no group, no role: a role on a test user would make the guard
    refuse it, and put its rights within reach of whoever takes it."""
    every = _code(_every_tf())
    for word in ("azuread_user_license", "azuread_group_member", "azuread_group_license", "usage_location",
                 "azuread_directory_role_member", "azuread_app_role_assignment", "azuread_application_owner"):
        assert word not in every, word
    user = _block(_tf(), "resource", 'azuread_user" "bench_test')
    assert "ignore_changes = [password]" in user and "uuid()" in user
    # A role goes to the executor only, never to a test user.
    roles = _block(_tf(), "resource", 'azuread_directory_role_assignment" "identity_executor')
    assert "principal_object_id = var.entra_identity_executor_object_id" in roles
    assert every.count('resource "azuread_directory_role_assignment"') == 1


def test_the_attribute_is_posed_before_the_membership():
    """In a restricted unit, a tenant's administrator no longer modifies its members (doc): the
    attribute first, by Graph, then the membership (M4097)."""
    member = _block(_tf(), "resource", 'azuread_administrative_unit_member" "bench_test')
    assert "depends_on = [terraform_data.bench_test_user_attributes]" in member
    assert "administrative_unit_object_id = data.azuread_administrative_unit.bench[0].object_id" in member
    attrs = _block(_tf(), "resource", 'terraform_data" "bench_test_user_attributes')
    assert 'command     = "python3 scripts/entra_bench_unit.py assign"' in attrs
    assert 'EREGION_ATTR_TARGET    = local.common_tags["eregion-target"]' in attrs
    assert 'EREGION_ATTR_ZONE      = local.common_tags["eregion-zone"]' in attrs
    # Values by the environment, never in the command line.
    assert "${" not in attrs.split("command")[1].split("\n")[0]


def test_the_executor_s_three_roles_each_at_its_scope():
    """User Administrator at the unit's scope only — at the tenant's it would manage every user
    (M4099); Directory Readers at the tenant; Attribute Assignment Reader at Eregion's set."""
    text = _tf()
    assert ('user_administrator          = { role = "User Administrator", scope = '
            '"/administrativeUnits/${var.entra_bench_unit_id}" }') in text
    assert 'directory_readers           = { role = "Directory Readers", scope = "/" }' in text
    assert ('attribute_assignment_reader = { role = "Attribute Assignment Reader", scope = '
            '"/attributeSets/${local.entra_attribute_set}" }') in text
    templates = dict(re.findall(r'(?m)^\s*"([A-Za-z ]+)"\s*=\s*"([0-9a-f-]{36})"$', text))
    assert templates == {"User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
                         "Directory Readers": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
                         "Attribute Assignment Reader": "ffd52fa5-98dc-465c-991d-fc073eb59f8f"}
    # Each checked against the tenant's own list before anything is assigned.
    roles = _block(text, "resource", 'azuread_directory_role_assignment" "identity_executor')
    assert "data.azuread_directory_role_templates.all[0].role_templates" in roles and "precondition" in roles
    # Never a role the design refuses to any identity of Eregion (§3.4), anywhere in the module.
    every = _every_tf()
    for refused in ("62e90394-69f5-4237-9190-012177145e10",    # Global Administrator
                    "e8611ab8-c189-46e8-94e1-60213ab1f814",    # Privileged Role Administrator
                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",    # Privileged Authentication Administrator
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",    # Application Administrator
                    "158c047a-c907-4556-b7ef-446551a6b5f7",    # Cloud Application Administrator
                    "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d"):   # Attribute Assignment Administrator
        assert refused not in every, refused


def test_the_names_are_the_guard_s():
    text = _tf()
    assert f'entra_attribute_set = "{inscription.ATTRIBUTE_SET}"' in text
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        import entra_bench_unit as script
    finally:
        sys.path.pop(0)
    assert script.ATTRIBUTE_SET == inscription.ATTRIBUTE_SET
    assert set(script.ATTRIBUTES) == set(inscription.ATTRIBUTE_NAMES.values())
    assert script.ZONES == inscription.ZONES and script.UNIT_ENV == inscription.ADMIN_UNIT_ENV
    assert inscription.UNIT_ZONE == "bench"
    # Celebrimbor's zone, the unit's: what the attribute is posed with.
    assert '"eregion-zone"   = "bench"' in (TF / "locals.tf").read_text(encoding="utf-8")


def test_every_terraform_test_mocks_azuread_and_keeps_the_unit_off():
    for path in (TF / "tests").glob("*.tftest.hcl"):
        text = path.read_text(encoding="utf-8")
        assert 'mock_provider "azuread"' in text, path.name
        assert re.search(r"(?m)^\s*entra_bench_unit_enabled\s*=\s*false$", text), path.name
    tftest = (TF / "tests" / "entra_bench_unit.tftest.hcl").read_text(encoding="utf-8")
    for run in ("off_nothing_in_the_tenant", "on_the_unit_pinned_its_users_held_after_their_attribute",
                "on_the_executor_three_roles_each_at_its_scope", "on_without_the_pinned_unit_the_plan_stops",
                "a_role_template_the_tenant_names_otherwise_stops_the_plan", "a_unit_id_that_is_no_object_id_is_refused"):
        assert f'run "{run}"' in tftest, run


# ── The Make targets, against a fake terraform and a fake az ─────────────────────────────

pytestmark_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
TARGETS = ["-target=azuread_user.bench_test", "-target=terraform_data.bench_test_user_attributes",
           "-target=azuread_administrative_unit_member.bench_test",
           "-target=azuread_directory_role_assignment.identity_executor"]

FAKE_AZ = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_AZ_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
world = json.load(open(os.environ["FAKE_AZ_WORLD"]))
if args[:2] == ["account", "show"]:
    print(json.dumps(world["account"]))
    sys.exit(0)
method, url = args[args.index("--method") + 1], args[args.index("--url") + 1]
resp = world["routes"].get(f"{method} {url}")
if resp is None and method == "GET":
    sys.stderr.write('ERROR: Not Found({"error":{"code":"Request_ResourceNotFound"}})')
    sys.exit(1)
if isinstance(resp, dict) and "__error__" in resp:
    sys.stderr.write(resp["__error__"])
    sys.exit(1)
print(json.dumps(resp) if resp is not None else "")
'''


def _env(tmp_path, world=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "terraform").write_text('#!/bin/sh\necho "$*" >> "$FAKE_TF_LOG"\n')
    (bin_dir / "az").write_text(FAKE_AZ)
    for name in ("terraform", "az"):
        (bin_dir / name).chmod(0o755)
    (tmp_path / "world.json").write_text(json.dumps(world or _world()))
    for log in ("tf.log", "az.log"):
        (tmp_path / log).write_text("")
    env = {k: v for k, v in os.environ.items() if k not in ("INSTANCE", "YES", "UNIT", "EREGION_BENCH_ADMIN_UNIT_ID",
                                                           "ARM_SUBSCRIPTION_ID")}
    env.update({"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
                "FAKE_TF_LOG": str(tmp_path / "tf.log"), "FAKE_AZ_LOG": str(tmp_path / "az.log"),
                "FAKE_AZ_WORLD": str(tmp_path / "world.json"), "AZURE_SUBSCRIPTION_ID": SUB})
    return env


def _calls(tmp_path, log):
    lines = (tmp_path / log).read_text().splitlines()
    return [json.loads(c) for c in lines] if log == "az.log" else [c.split() for c in lines]


def _make(tmp_path, target, *args, world=None):
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, *args],
                         env=_env(tmp_path, world), capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout + res.stderr


@pytestmark_make
def test_users_plan_plans_the_users_alone(tmp_path):
    code, out = _make(tmp_path, "celebrimbor-users-plan")
    assert code == 0, out
    chdir = "-chdir=infra/terraform"
    assert _calls(tmp_path, "tf.log") == [[chdir, "init"], [chdir, "workspace", "select", "default"],
                                          [chdir, "plan", *TARGETS]]


@pytestmark_make
@pytest.mark.parametrize("args,approve", [((), []), (("YES=1",), ["-auto-approve"])])
def test_users_up_applies_them_alone_confirmed_unless_yes(tmp_path, args, approve):
    code, out = _make(tmp_path, "celebrimbor-users-up", *args)
    assert code == 0, out
    calls = _calls(tmp_path, "tf.log")
    assert calls[-1] == ["-chdir=infra/terraform", "apply", *approve, *TARGETS]
    assert not any(a.startswith("-var") for c in calls for a in c)


@pytestmark_make
@pytest.mark.parametrize("target", ["celebrimbor-users-plan", "celebrimbor-users-up", "celebrimbor-unit-prepare"])
def test_another_instance_is_refused_before_any_call(tmp_path, target):
    code, out = _make(tmp_path, target, "INSTANCE=ci-1234", "YES=1")
    assert code != 0 and "instance 'ci-1234' refusée" in out
    assert _calls(tmp_path, "tf.log") == [] and _calls(tmp_path, "az.log") == []


@pytestmark_make
def test_unit_prepare_without_yes_reads_only(tmp_path):
    code, out = _make(tmp_path, "celebrimbor-unit-prepare")
    assert code == 0, out
    assert {c[2] for c in _calls(tmp_path, "az.log") if c[0] == "rest"} == {"GET"}
    assert '"isMemberManagementRestricted": true' in out


@pytestmark_make
def test_unit_prepare_takes_the_pinned_unit_by_the_environment_never_expanded(tmp_path):
    marker = tmp_path / "ran"
    code, out = _make(tmp_path, "celebrimbor-unit-prepare", f"UNIT=$(shell touch {marker})")
    assert code != 0 and "un object id" in out and not marker.exists()
    code, out = _make(tmp_path, "celebrimbor-unit-prepare", f"UNIT={UNIT}", "YES=1")
    assert code == 0, out
    assert not any(c[0] == "rest" and c[2] == "POST" and c[4].endswith("/administrativeUnits")
                   for c in _calls(tmp_path, "az.log"))
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "unexport UNIT\ncelebrimbor-unit-prepare: export EREGION_BENCH_ADMIN_UNIT_ID = $(value UNIT)" in text


# ── The Graph script, against a fake az ─────────────────────────────────────────────────

def _world(**over):
    world = {
        "account": {"id": SUB, "type": "user"},
        "routes": {
            f"POST {G}/directory/administrativeUnits": {"id": NEW_UNIT},
            f"GET {G}/directory/administrativeUnits/{NEW_UNIT}?$select=id,isMemberManagementRestricted":
                {"id": NEW_UNIT, "isMemberManagementRestricted": True},
            f"GET {G}/directory/administrativeUnits/{UNIT}?$select=id,displayName,isMemberManagementRestricted":
                {"id": UNIT, "displayName": "au-celebrimbor-bench", "isMemberManagementRestricted": True},
            f"POST {G}/directory/attributeSets": {"id": "Eregion"},
            f"POST {G}/directory/customSecurityAttributeDefinitions": {},
            f"PATCH {G}/users/{USER}": None,
            f"GET {G}/users/{USER}?$select=id,customSecurityAttributes":
                {"id": USER, "customSecurityAttributes": {"Eregion": {"eregionTarget": "celebrimbor",
                                                                       "eregionZone": "bench"}}},
        },
    }
    for key, value in over.items():
        if key == "account":
            world["account"] = value
        else:
            world["routes"][key] = value
    return world


def _script(tmp_path, *args, world=None, **env):
    e = _env(tmp_path, world)
    e.update(env)
    res = subprocess.run([sys.executable, str(SCRIPT), *args], env=e, capture_output=True, text=True,
                         timeout=60, cwd=str(TF))
    return res.returncode, res.stdout + res.stderr, _calls(tmp_path, "az.log")


def _rest(calls):
    return [(c[2], c[4], json.loads(c[c.index("--body") + 1]) if "--body" in c else None)
            for c in calls if c[0] == "rest"]


def test_prepare_creates_the_set_the_definitions_and_a_restricted_unit(tmp_path):
    """The unit is restricted at its creation — fixed then, never after (M4096)."""
    code, out, calls = _script(tmp_path, "prepare", "--yes")
    assert code == 0, out
    posts = [(url, body) for m, url, body in _rest(calls) if m == "POST"]
    assert [u.rsplit("/", 1)[-1] for u, _ in posts] == ["attributeSets", "customSecurityAttributeDefinitions",
                                                        "customSecurityAttributeDefinitions", "administrativeUnits"]
    assert posts[0][1]["id"] == "Eregion"
    defs = {b["name"]: b for _, b in posts[1:3]}
    assert set(defs) == {"eregionTarget", "eregionZone"}
    assert all(b["type"] == "String" and b["isCollection"] is False and b["attributeSet"] == "Eregion"
               for b in defs.values())
    assert posts[3][1]["isMemberManagementRestricted"] is True
    assert f'entra_bench_unit_id = "{NEW_UNIT}"' in out
    # Then read back, restricted.
    assert ("GET", f"{G}/directory/administrativeUnits/{NEW_UNIT}?$select=id,isMemberManagementRestricted",
            None) in _rest(calls)


def test_prepare_says_what_exists_and_creates_nothing_twice(tmp_path):
    world = _world(**{f"GET {G}/directory/attributeSets/Eregion": {"id": "Eregion"},
                      f"GET {G}/directory/customSecurityAttributeDefinitions/Eregion_eregionTarget":
                          {"type": "String", "isCollection": False, "status": "Available"},
                      f"GET {G}/directory/customSecurityAttributeDefinitions/Eregion_eregionZone":
                          {"type": "String", "isCollection": False, "status": "Available"}})
    code, out, calls = _script(tmp_path, "prepare", "--yes", world=world, EREGION_BENCH_ADMIN_UNIT_ID=UNIT)
    assert code == 0, out
    assert [m for m, _, _ in _rest(calls)] == ["GET"] * 4
    assert f'entra_bench_unit_id = "{UNIT}"' in out


def test_a_pinned_unit_that_is_not_restricted_is_refused(tmp_path):
    key = f"GET {G}/directory/administrativeUnits/{UNIT}?$select=id,displayName,isMemberManagementRestricted"
    for restricted in (False, None):
        code, out, _ = _script(tmp_path, "prepare", "--yes", EREGION_BENCH_ADMIN_UNIT_ID=UNIT,
                               world=_world(**{key: {"id": UNIT, "isMemberManagementRestricted": restricted}}))
        assert code == 1 and "pas restreinte" in out, restricted
    code, out, _ = _script(tmp_path, "prepare", EREGION_BENCH_ADMIN_UNIT_ID=UNIT, world=_world(**{key: None}))
    assert code == 1 and "n'existe pas" in out


def test_a_unit_created_unrestricted_is_never_pinned(tmp_path):
    key = f"GET {G}/directory/administrativeUnits/{NEW_UNIT}?$select=id,isMemberManagementRestricted"
    code, out, _ = _script(tmp_path, "prepare", "--yes", world=_world(**{key: {"id": NEW_UNIT}}))
    assert code == 1 and "pas restreinte" in out and "entra_bench_unit_id =" not in out


def test_a_definition_not_as_eregion_defines_it_is_refused(tmp_path):
    world = _world(**{f"GET {G}/directory/customSecurityAttributeDefinitions/Eregion_eregionTarget":
                      {"type": "String", "isCollection": True, "status": "Available"}})
    code, out, calls = _script(tmp_path, "prepare", "--yes", world=world)
    assert code == 1 and "pas comme Eregion le définit" in out
    assert not any(m == "POST" and u.endswith("/administrativeUnits") for m, u, _ in _rest(calls))


def test_a_read_error_that_is_not_a_404_stops(tmp_path):
    world = _world(**{f"GET {G}/directory/attributeSets/Eregion": {"__error__": "ERROR: Forbidden(Authorization_RequestDenied)"}})
    code, out, calls = _script(tmp_path, "prepare", "--yes", world=world)
    assert code == 1 and "Forbidden" in out
    assert not any(m == "POST" for m, _, _ in _rest(calls))


@pytest.mark.parametrize("account,why", [({"id": "00000000-0000-0000-0000-000000000009", "type": "user"}, "abonnement"),
                                         ({"id": SUB, "type": "servicePrincipal"}, "principal")])
def test_the_az_login_must_be_a_user_on_the_bench_s_subscription(tmp_path, account, why):
    code, out, calls = _script(tmp_path, "prepare", "--yes", world=_world(account=account))
    assert code == 1 and why in out and _rest(calls) == []


def test_without_the_subscription_nothing_is_asked(tmp_path):
    code, out, calls = _script(tmp_path, "prepare", AZURE_SUBSCRIPTION_ID="")
    assert code == 1 and "AZURE_SUBSCRIPTION_ID" in out and calls == []


def test_assign_patches_the_attribute_then_reads_it_back(tmp_path):
    code, out, calls = _script(tmp_path, "assign", EREGION_USER_OBJECT_ID=USER, EREGION_ATTR_TARGET="celebrimbor",
                               EREGION_ATTR_ZONE="bench")
    assert code == 0, out
    (patch,) = [b for m, _, b in _rest(calls) if m == "PATCH"]
    value = patch["customSecurityAttributes"]["Eregion"]
    assert value == {"@odata.type": "#Microsoft.DirectoryServices.CustomSecurityAttributeValue",
                     "eregionTarget": "celebrimbor", "eregionZone": "bench"}
    assert _rest(calls)[-1][0] == "GET"


def test_assign_refuses_a_read_back_that_differs(tmp_path):
    key = f"GET {G}/users/{USER}?$select=id,customSecurityAttributes"
    code, out, _ = _script(tmp_path, "assign", EREGION_USER_OBJECT_ID=USER, EREGION_ATTR_TARGET="celebrimbor",
                           EREGION_ATTR_ZONE="bench", world=_world(**{key: {"id": USER}}))
    assert code == 1 and "relu" in out


@pytest.mark.parametrize("user,bench,zone", [("not-a-guid", "celebrimbor", "bench"), (USER, "prod", "bench"),
                                             (USER, "celebrimbor", "staging"), (f"{USER}/../x", "celebrimbor", "bench"),
                                             (USER, "celebrimbor; rm -rf /", "bench")])
def test_assign_checks_what_it_writes_before_any_call(tmp_path, user, bench, zone):
    code, out, calls = _script(tmp_path, "assign", EREGION_USER_OBJECT_ID=user, EREGION_ATTR_TARGET=bench,
                               EREGION_ATTR_ZONE=zone)
    assert code == 1 and calls == []


def test_the_script_uses_az_rest_with_an_argument_list_only():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "shell=True" not in text and "os.system" not in text
    assert 'subprocess.run(["az", *args]' in text
    # Standard library only: run by Terraform from any Python.
    import ast
    tree = ast.parse(text)
    imports = {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imports |= {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert imports <= {"__future__", "json", "os", "re", "subprocess", "sys"}, imports
