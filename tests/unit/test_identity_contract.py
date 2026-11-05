"""IR1b (#572): the identity executor's contract, read at its start — armed only if what its
identity holds in Entra ID is within the closed list (docs/design/reponse-identite.md §3.4), else
passive, and it refuses to start. Its token's claims and a fake Graph (tests/unit/fake_graph.py),
no network, no Azure: every id is a placeholder. Mutants M4070–M4084 (scripts/mutants/IR1b.py).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from eregion_core.never_target import NeverTarget
from glorfindel.providers.azure import identity_contract as ic
from glorfindel.response.policy import IDENTITY_ACTIONS

from .fake_graph import FakeGraph

ROOT = Path(__file__).resolve().parents[2]
TENANT = "00000000-0000-0000-0000-0000000000f0"
CLIENT = "00000000-0000-0000-0000-0000000000e1"       # its application (client) id
OID = "00000000-0000-0000-0000-0000000000e2"          # its principal
GRAPH_SP = "00000000-0000-0000-0000-0000000000a8"     # Microsoft Graph's principal in the tenant
OTHER_API = "00000000-0000-0000-0000-0000000000a9"
UNIT = "00000000-0000-0000-0000-0000000000c1"
OPERATOR = "00000000-0000-0000-0000-0000000000ee"
WATCH = "00000000-0000-0000-0000-0000000000b0"
ENROLLED_APP = "00000000-0000-0000-0000-0000000000d0"
ENROLLED_APP_ID = "00000000-0000-0000-0000-0000000000d9"
DEFAULT_WIDS = sorted(ic.APP_DEFAULT_WIDS)[0]
ROLE_IDS = {"Application.ReadWrite.OwnedBy": "00000000-0000-0000-0000-000000000d01",
            "User.RevokeSessions.All": "00000000-0000-0000-0000-000000000d02",
            "Application.ReadWrite.All": "00000000-0000-0000-0000-000000000d03",
            "RoleManagement.ReadWrite.Directory": "00000000-0000-0000-0000-000000000d04",
            "Mail.Send": "00000000-0000-0000-0000-000000000d05"}
GA = "62e90394-69f5-4237-9190-012177145e10"

ENV = {ic.TENANT_ENV: TENANT, ic.CLIENT_ENV: CLIENT, ic.UNIT_ENV: UNIT, ic.ATTRIBUTE_SET_ENV: "Eregion",
       "EREGION_OPERATOR_OBJECT_ID": OPERATOR, "EREGION_PROTECTED_IDENTITIES": WATCH}


def _graph() -> FakeGraph:
    g = FakeGraph()
    g.sps[GRAPH_SP] = {"id": GRAPH_SP, "appId": ic.GRAPH_APP_ID, "displayName": "Microsoft Graph",
                       "appRoles": [{"id": v, "value": k} for k, v in ROLE_IDS.items()]}
    g.sps[OTHER_API] = {"id": OTHER_API, "appId": "00000000-0000-0000-0000-0000000000aa",
                        "displayName": "another API", "appRoles": [{"id": ROLE_IDS["Mail.Send"], "value": "Mail.Send"}]}
    g.sps[OID] = {"id": OID, "appId": CLIENT}
    g.app_roles[OID] = [_perm(p) for p in sorted(ic.ADMITTED_PERMISSIONS)]
    g.role_assignments = [_role(ic.DIRECTORY_READERS, "/"),
                          _role(ic.USER_ADMINISTRATOR, f"/administrativeUnits/{UNIT}"),
                          _role(ic.ATTRIBUTE_ASSIGNMENT_READER, "/attributeSets/Eregion")]
    g.owned[OID] = [{"@odata.type": "#microsoft.graph.application", "id": ENROLLED_APP, "appId": ENROLLED_APP_ID}]
    return g


def _perm(name: str, resource: str = GRAPH_SP) -> dict:
    return {"principalId": OID, "resourceId": resource, "appRoleId": ROLE_IDS[name]}


def _role(role_id: str, scope: str, **kw) -> dict:
    return {"principalId": OID, "roleDefinitionId": role_id, "directoryScopeId": scope, **kw}


def _claims(**kw) -> dict:
    return {"tid": TENANT, "appid": CLIENT, "oid": OID, "roles": sorted(ic.ADMITTED_PERMISSIONS),
            "wids": [ic.DIRECTORY_READERS, DEFAULT_WIDS], **kw}


def _assess(graph=None, claims=None, env=None) -> ic.Verdict:
    env = ENV if env is None else env
    return ic.assess(_claims() if claims is None else claims, _graph() if graph is None else graph,
                     env=env, never=NeverTarget.from_env(env))


def _codes(v: ic.Verdict) -> set[str]:
    return {m["code"] for m in v.missing}


def _beyond(v: ic.Verdict, *words: str) -> None:
    assert not v.armed and v.verdict == ic.PASSIVE
    assert ic.BEYOND in _codes(v), v.missing
    text = v.reasons()
    assert all(w in text for w in words), text


# ── The contract that holds ───────────────────────────────────────────────────────────────────

def test_within_the_closed_list_it_is_armed_and_its_rights_allow_every_verb():
    v = _assess()
    assert v.armed and v.verdict == ic.ARMED and v.missing == ()
    assert v.held == {"Application.ReadWrite.OwnedBy", "User.RevokeSessions.All", "Directory Readers",
                      "User Administrator", "Attribute Assignment Reader"}
    assert all(v.allows(verb) for verb in IDENTITY_ACTIONS)


def test_every_verb_of_the_executor_names_the_rights_it_needs():
    assert set(ic.VERB_RIGHTS) == set(IDENTITY_ACTIONS)
    assert all(ic.VERB_RIGHTS[v] for v in IDENTITY_ACTIONS)


def test_the_admitted_and_the_refused_lists_never_meet():
    assert ic.ADMITTED_PERMISSIONS == {"Application.ReadWrite.OwnedBy", "User.RevokeSessions.All"}
    assert not ic.ADMITTED_PERMISSIONS & ic.REFUSED_PERMISSIONS
    assert not set(ic.ADMITTED_ROLES) & set(ic.REFUSED_ROLES)
    assert "Directory.ReadWrite.All" in ic.REFUSED_PERMISSIONS and "Application.ReadWrite.All" in ic.REFUSED_PERMISSIONS
    assert GA in ic.REFUSED_ROLES


def test_without_a_right_it_stays_armed_but_its_verbs_are_not_allowed():
    """The contract is about what it must never hold; a right it lacks only takes its verbs away."""
    g = _graph()
    g.app_roles[OID] = [_perm("Application.ReadWrite.OwnedBy")]
    g.role_assignments = []
    v = _assess(g, _claims(roles=["Application.ReadWrite.OwnedBy"], wids=[DEFAULT_WIDS]))
    assert v.armed
    assert v.allows("entra_remove_credential") and v.allows("entra_disable_principal")
    assert not v.allows("entra_revoke_sessions") and not v.allows("entra_disable_user")


@pytest.mark.parametrize("token_has, assigned", [(True, False), (False, True)])
def test_a_permission_is_held_only_when_its_token_and_its_assignments_both_say_so(token_has, assigned):
    g = _graph()
    if not assigned:
        g.app_roles[OID] = [_perm("Application.ReadWrite.OwnedBy")]
    roles = sorted(ic.ADMITTED_PERMISSIONS) if token_has else ["Application.ReadWrite.OwnedBy"]
    v = _assess(g, _claims(roles=roles))
    assert v.armed and not v.allows("entra_revoke_sessions")


def test_a_passive_verdict_allows_no_verb_and_an_unknown_verb_is_never_allowed():
    v = _assess(claims=_claims(roles=["Application.ReadWrite.All"]))
    assert not any(v.allows(verb) for verb in IDENTITY_ACTIONS)
    assert not _assess().allows("entra_remove_role")


# ── A right too many: beyond the contract ───────────────────────────────────────────────────

@pytest.mark.parametrize("right", sorted(ic.REFUSED_PERMISSIONS))
def test_a_refused_permission_in_its_token_is_beyond_the_contract(right):
    _beyond(_assess(claims=_claims(roles=sorted(ic.ADMITTED_PERMISSIONS) + [right])), right, "refused right")


def test_an_unknown_permission_in_its_token_is_beyond_the_contract():
    _beyond(_assess(claims=_claims(roles=["Mail.Send"])), "Mail.Send", "outside the contract")


def test_a_refused_permission_assigned_after_its_token_is_beyond_the_contract():
    g = _graph()
    g.app_roles[OID].append(_perm("RoleManagement.ReadWrite.Directory"))
    _beyond(_assess(g), "RoleManagement.ReadWrite.Directory", "refused right")


def test_an_assigned_permission_graph_does_not_name_is_beyond_the_contract():
    g = _graph()
    g.app_roles[OID].append({"principalId": OID, "resourceId": GRAPH_SP,
                             "appRoleId": "00000000-0000-0000-0000-000000000dff"})
    _beyond(_assess(g), "unnamed permission")


def test_a_permission_on_another_api_is_beyond_the_contract():
    g = _graph()
    g.app_roles[OID].append(_perm("Mail.Send", OTHER_API))
    _beyond(_assess(g), "another API")


def test_a_refused_directory_role_in_its_token_is_beyond_the_contract():
    _beyond(_assess(claims=_claims(wids=[GA, DEFAULT_WIDS])), "Global Administrator")


def test_an_unknown_directory_role_in_its_token_is_beyond_the_contract():
    _beyond(_assess(claims=_claims(wids=["00000000-0000-0000-0000-00000000aaaa"])), "outside the contract")


@pytest.mark.parametrize("definition, scope, words", [
    (GA, "/", ("Global Administrator", "refused")),
    (ic.USER_ADMINISTRATOR, "/", ("User Administrator", "one scope")),
    (ic.USER_ADMINISTRATOR, "/administrativeUnits/00000000-0000-0000-0000-0000000000c2", ("one scope",)),
    (ic.ATTRIBUTE_ASSIGNMENT_READER, "/attributeSets/Other", ("one scope",)),
    (ic.ATTRIBUTE_ASSIGNMENT_READER, "/", ("one scope",)),
    (ic.DIRECTORY_READERS, f"/administrativeUnits/{UNIT}", ("one scope",)),
    (ic.DIRECTORY_READERS, f"/{ENROLLED_APP}", ("one scope",)),
    ("00000000-0000-0000-0000-00000000bbbb", "/", ("outside the contract",)),
])
def test_a_directory_role_beyond_its_one_scope_is_beyond_the_contract(definition, scope, words):
    g = _graph()
    g.role_assignments.append(_role(definition, scope))
    _beyond(_assess(g), *words)


def test_a_custom_role_that_takes_a_built_in_roles_template_id_and_name_is_beyond_the_contract():
    """A custom role may set ``templateId`` to anything, and its name: only the definition's id
    tells a built-in role."""
    g = _graph()
    g.roles["00000000-0000-0000-0000-00000000cccc"] = "User Administrator"
    g.role_assignments.append(_role("00000000-0000-0000-0000-00000000cccc", f"/administrativeUnits/{UNIT}",
                                    definition={"templateId": ic.USER_ADMINISTRATOR, "isBuiltIn": False}))
    _beyond(_assess(g), "outside the contract")


def test_a_role_whose_definition_only_borrows_a_template_id_is_beyond_the_contract():
    """``isBuiltIn`` not given (the definition not fully read): the definition's own id still tells
    it is no built-in role."""
    g = _graph()
    g.role_assignments.append(_role("00000000-0000-0000-0000-00000000dddd", f"/administrativeUnits/{UNIT}",
                                    definition={"templateId": ic.USER_ADMINISTRATOR}))
    _beyond(_assess(g), "outside the contract")


def test_a_role_said_not_built_in_is_beyond_the_contract():
    g = _graph()
    g.role_assignments[0] = _role(ic.DIRECTORY_READERS, "/", definition={"isBuiltIn": False})
    _beyond(_assess(g), "outside the contract")


def test_a_role_scoped_to_an_application_is_beyond_the_contract():
    g = _graph()
    g.role_assignments[0] = _role(ic.DIRECTORY_READERS, "/", appScopeId=ENROLLED_APP)
    _beyond(_assess(g), "one scope")


@pytest.mark.parametrize("missing_env, words", [(ic.UNIT_ENV, ("User Administrator", "none declared")),
                                                (ic.ATTRIBUTE_SET_ENV, ("Attribute Assignment Reader", "none declared"))])
def test_a_scoped_role_whose_scope_is_not_declared_is_beyond_the_contract(missing_env, words):
    env = {k: v for k, v in ENV.items() if k != missing_env}
    _beyond(_assess(env=env), *words)


def test_the_unit_and_the_attribute_set_compare_without_case():
    g = _graph()
    g.role_assignments = [_role(ic.USER_ADMINISTRATOR, f"/AdministrativeUnits/{UNIT.upper()}"),
                          _role(ic.ATTRIBUTE_ASSIGNMENT_READER, "/attributesets/eregion")]
    assert _assess(g).armed


def test_an_eligible_role_is_beyond_the_contract():
    g = _graph()
    g.eligibilities = [_role(ic.DIRECTORY_READERS, "/")]
    _beyond(_assess(g), "eligible", "Directory Readers")


@pytest.mark.parametrize("owned, words", [
    ({"@odata.type": "#microsoft.graph.group", "id": "00000000-0000-0000-0000-0000000000f9"}, ("no application",)),
    ({"@odata.type": "#microsoft.graph.servicePrincipal", "id": OID, "appId": CLIENT}, ("itself",)),
    ({"@odata.type": "#microsoft.graph.application", "id": "00000000-0000-0000-0000-0000000000f8",
      "appId": CLIENT}, ("itself",)),
    ({"@odata.type": "#microsoft.graph.servicePrincipal", "id": WATCH,
      "appId": "00000000-0000-0000-0000-0000000000f7"}, ("never a target",)),
    ({"@odata.type": "#microsoft.graph.application", "id": "00000000-0000-0000-0000-0000000000f6",
      "appId": OPERATOR}, ("never a target",)),
])
def test_owning_what_is_no_enrolled_application_is_beyond_the_contract(owned, words):
    g = _graph()
    g.owned[OID].append(owned)
    _beyond(_assess(g), *words)


def test_what_it_owns_with_the_never_target_list_unreadable_leaves_it_passive():
    env = {k: v for k, v in ENV.items() if k != "EREGION_OPERATOR_OBJECT_ID"}
    v = _assess(env=env)
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and "never_target" in v.reasons()
    g = _graph()
    g.owned[OID] = []
    assert _assess(g, env=env).armed      # nothing owned: nothing to tell apart


# ── A contract it cannot read: passive ──────────────────────────────────────────────────────

@pytest.mark.parametrize("name, value", [(ic.TENANT_ENV, ""), (ic.TENANT_ENV, "contoso"), (ic.CLIENT_ENV, ""),
                                         (ic.CLIENT_ENV, "not-an-id"), (ic.UNIT_ENV, "bench-unit"),
                                         (ic.ATTRIBUTE_SET_ENV, "eregion-set")])
def test_a_declaration_it_cannot_read_leaves_it_passive_before_graph_is_read(name, value):
    g = _graph()
    v = _assess(g, env={**ENV, name: value})
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and name in v.reasons()
    assert g.calls == []


@pytest.mark.parametrize("claims, words", [
    (_claims(scp="User.Read"), "a user's scopes"),
    (_claims(tid="00000000-0000-0000-0000-0000000000f1"), "another tenant"),
    (_claims(appid="00000000-0000-0000-0000-0000000000e9"), "another application"),
    (_claims(oid=""), "another application"),
    (_claims(roles="Application.ReadWrite.OwnedBy"), "not lists"),
    (_claims(wids=None), "not lists"),
])
def test_a_token_that_is_not_the_executors_own_leaves_it_passive(claims, words):
    v = _assess(claims=claims)
    assert not v.armed and ic.UNREADABLE in _codes(v) and words in v.reasons()


def test_a_v2_token_names_its_client_in_azp():
    claims = _claims()
    claims["azp"] = claims.pop("appid")
    assert _assess(claims=claims).armed


@pytest.mark.parametrize("fail", ["right", "error", "delay", "crash"])
def test_its_own_rights_not_read_leave_it_passive(fail):
    g = _graph()
    g.fail = fail
    v = _assess(g)
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and "its own rights not read" in v.reasons()


def test_its_principal_unknown_to_graph_leaves_it_passive():
    g = _graph()
    del g.sps[OID]
    v = _assess(g)
    assert not v.armed and _codes(v) == {ic.UNREADABLE}


def test_a_permissions_resource_graph_does_not_give_leaves_it_passive():
    g = _graph()
    del g.sps[GRAPH_SP]
    v = _assess(g)
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and "not read" in v.reasons()


def test_a_listing_that_is_not_a_list_leaves_it_passive():
    class NotAList(FakeGraph):
        def list(self, path, params=None, deadline=None):
            got = super().list(path, params, deadline)
            return {"value": got} if path.endswith("ownedObjects") else got
    g = NotAList()
    g.__dict__.update(_graph().__dict__)
    v = _assess(g)
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and "ownedObjects" in v.reasons()


def test_its_reads_are_bounded_by_one_budget():
    g = _graph()
    seen = []
    real = g.list

    def bounded(path, params=None, deadline=None):
        seen.append(deadline)
        return real(path, params, deadline)
    g.list = bounded
    assert _assess(g).armed
    assert seen and all(d is not None for d in seen) and len(set(seen)) == 1


# ── Read only, and its own identity only ────────────────────────────────────────────────────

def test_it_reads_graph_and_writes_nothing():
    g = _graph()
    _assess(g)
    assert g.calls and {c[0] for c in g.calls} <= {"get", "list"}
    src = (ROOT / "glorfindel/providers/azure/identity_contract.py").read_text(encoding="utf-8")
    for verb in (".post(", ".patch(", ".put(", ".delete(", "requests."):
        assert verb not in src, verb


def _token(claims: dict) -> str:
    def part(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


class _Credential:
    def __init__(self, claims):
        self.claims, self.scopes = claims, []

    def get_token(self, scope):
        self.scopes.append(scope)
        return type("T", (), {"token": _token(self.claims)})()


def test_check_reads_its_token_for_graph_and_judges_it(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    cred = _Credential(_claims())
    v = ic.check(credential=cred, reader=_graph())
    assert v.armed and cred.scopes == ["https://graph.microsoft.com/.default"]
    cred = _Credential(_claims(roles=["Directory.ReadWrite.All"]))
    _beyond(ic.check(credential=cred, reader=_graph()), "Directory.ReadWrite.All")


def test_a_token_it_cannot_have_leaves_it_passive(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    class Broken:
        def get_token(self, scope):
            raise RuntimeError("no token")
    v = ic.check(credential=Broken(), reader=_graph())
    assert not v.armed and _codes(v) == {ic.UNREADABLE} and "token not had" in v.reasons()


def test_without_its_certificate_it_never_takes_another_identity(monkeypatch):
    """Never DefaultAzureCredential: on H0 the VM's token endpoint answers every container."""
    import azure.identity
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv(ic.CERTIFICATE_ENV, raising=False)

    def refused(*a, **kw):
        raise AssertionError("another identity than the executor's was asked for")
    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", refused)
    monkeypatch.setattr(azure.identity, "ManagedIdentityCredential", refused)
    v = ic.check(reader=_graph())
    assert not v.armed and ic.CERTIFICATE_ENV in v.reasons()
    src = (ROOT / "glorfindel/providers/azure/identity_contract.py").read_text(encoding="utf-8")
    assert "DefaultAzureCredential(" not in src and "ManagedIdentityCredential" not in src


def test_its_credential_is_its_certificate(monkeypatch, tmp_path):
    import azure.identity
    got = {}

    class Cert:
        def __init__(self, tenant, client, certificate_path):
            got.update(tenant=tenant, client=client, path=certificate_path)
    monkeypatch.setattr(azure.identity, "CertificateCredential", Cert)
    ic.executor_credential({**ENV, ic.CERTIFICATE_ENV: str(tmp_path / "executor.pem")})
    assert got == {"tenant": TENANT, "client": CLIENT, "path": str(tmp_path / "executor.pem")}


def test_a_passive_contract_refuses_to_start(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ic.Passive, match="beyond_contract"):
        ic.start(credential=_Credential(_claims(roles=["Application.ReadWrite.All"])), reader=_graph())
    with pytest.raises(ic.Passive, match="contract_unreadable"):
        ic.start(credential=_Credential(_claims()), reader=FakeGraph())
    assert ic.start(credential=_Credential(_claims()), reader=_graph()).armed


def test_the_cli_says_the_verdict_and_exits_1_unless_armed(monkeypatch):
    from click.testing import CliRunner

    from glorfindel.cli import cli
    monkeypatch.setattr(ic, "check", lambda: _assess(claims=_claims(roles=["Application.ReadWrite.All"])))
    r = CliRunner().invoke(cli, ["identity-contract"])
    assert r.exit_code == 1 and "passive" in r.output and "beyond_contract" in r.output
    monkeypatch.setattr(ic, "check", lambda: _assess())
    r = CliRunner().invoke(cli, ["identity-contract"])
    assert r.exit_code == 0 and "armed" in r.output and "entra_disable_user" in r.output


def test_the_executor_is_never_a_target():
    """Its client id, declared, joins the shared list (eregion_core/never_target.py): never its own
    target, nor a technique's."""
    never = NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": OPERATOR, ic.CLIENT_ENV: CLIENT})
    assert never.covers(CLIENT) and not never.refusal()
    assert NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": OPERATOR, ic.CLIENT_ENV: "typo"}).refusal()
