"""IDI1 (#546): an identity of Entra ID is enrolled for the bench by two keys, one per plane — the
application's own tags in Microsoft Graph name the bench and the zone, the bench's resource group
names the application (``eregion-identities``) — and passes the same guard as a VM: of the named
tenant, an application's principal, never an identity of the shared list (eregion_core/never_target.py),
never a privileged one, its zone deciding. A read that fails refuses. All against a fake Graph and a
fake ARM: no network, no Azure, no Graph; every identifier here is an example. Mutants M3810–M3819,
M3900–M3905 (scripts/mutants/IDI1.py)."""
import base64
import json
from types import SimpleNamespace

import pytest

from eregion_core.inscription import (
    GraphEnrollment,
    IdentityScope,
    check_identity,
    identity_enrollment,
    main,
    privilege_refusal,
)
from eregion_core.never_target import NeverTarget

TENANT = "00000000-0000-0000-0000-0000000000f0"
OTHER_TENANT = "00000000-0000-0000-0000-0000000000f9"
OPERATOR = "00000000-0000-0000-0000-0000000000ee"
ORODRUIN = "00000000-0000-0000-0000-0000000000a0"   # the reader: Orodruin's managed identity
H0 = "00000000-0000-0000-0000-0000000000b0"         # Glorfindel's hosted watch
APP = "00000000-0000-0000-0000-0000000000c1"        # the bench's test application (object id)
APP_ID = "00000000-0000-0000-0000-0000000000c2"     # its appId (client id)
SP = "00000000-0000-0000-0000-0000000000c3"         # its service principal
SUB = "00000000-0000-0000-0000-000000000000"

NEVER = NeverTarget(ids=frozenset({ORODRUIN, H0, OPERATOR}), operators=frozenset({OPERATOR}))
SCOPE = IdentityScope(bench="celebrimbor", tenant_id=TENANT, subscription_id=SUB,
                      resource_group="rg-celebrimbor", never=NEVER)
TOKEN = {"tid": TENANT, "oid": ORODRUIN, "appid": "00000000-0000-0000-0000-0000000000a1"}


def _identity(**over):
    app = {"id": APP, "appId": APP_ID, "signInAudience": "AzureADMyOrg",
           "tags": ["eregion-target=celebrimbor", "eregion-zone=bench"]}
    sp = {"id": SP, "appId": APP_ID, "servicePrincipalType": "Application",
          "appOwnerOrganizationId": TENANT}
    app.update(over.pop("app", {}))
    sp.update(over.pop("sp", {}))
    out = {"application": app, "service_principal": sp, "owned": [], "assigned_to": [], "member_of": [],
           "app_roles_held": [], "directory_roles": []}
    out.update(over)
    return out


RG = {"eregion-target": "celebrimbor", "eregion-zone": "bench", "eregion-identities": APP}


def _verdict(identity=None, rg=None, *, scope=SCOPE, token=TOKEN):
    return identity_enrollment(_identity() if identity is None else identity,
                               RG if rg is None else rg, scope=scope, token=token)


# ── Both keys, and only both ────────────────────────────────────────────────────────────

def test_an_application_named_by_both_keys_is_enrolled_in_its_zone():
    v = _verdict()
    assert v.allowed and v.zone == "bench"


def test_the_entra_key_alone_opens_nothing():
    """Any member may register an application and tag it: without the bench's group naming
    it, it is no target (M3810)."""
    v = _verdict(rg={"eregion-target": "celebrimbor", "eregion-zone": "bench"})
    assert not v.allowed and "eregion-identities" in v.reason
    v = _verdict(rg={**RG, "eregion-identities": "00000000-0000-0000-0000-0000000000c9"})
    assert not v.allowed


def test_the_arm_key_alone_opens_nothing():
    v = _verdict(_identity(app={"tags": []}))
    assert not v.allowed and "eregion-target=celebrimbor" in v.reason


def test_the_group_names_several_identities_in_any_case():
    other = "00000000-0000-0000-0000-0000000000d1"
    assert _verdict(rg={**RG, "eregion-identities": f"{other} {APP.upper()}"}).allowed
    assert _verdict(rg={**RG, "eregion-identities": f"{other},{APP}"}).allowed


def test_a_group_list_with_what_is_no_object_id_refuses():
    assert not _verdict(rg={**RG, "eregion-identities": f"{APP} my-app"}).allowed


@pytest.mark.parametrize("rg", [
    {"eregion-identities": APP, "eregion-zone": "bench"},                              # group not enrolled
    {"eregion-target": "celebrimbor-other", "eregion-zone": "bench", "eregion-identities": APP},
    {"annatar-test": "true", "eregion-zone": "bench", "eregion-identities": APP},      # no legacy here
    {"eregion-target": "Celebrimbor", "eregion-zone": "bench", "eregion-identities": APP},
])
def test_the_group_must_be_the_bench_s(rg):
    assert not _verdict(rg=rg).allowed


@pytest.mark.parametrize("tags", [
    ["eregion-target=celebrimbor-other", "eregion-zone=bench"],
    ["eregion-target=Celebrimbor", "eregion-zone=bench"],                  # values exactly
    ["eregion-target=", "eregion-zone=bench"],
    ["eregion-target=celebrimbor"],                                         # no zone
    ["eregion-target=celebrimbor", "eregion-zone=Bench"],
    ["eregion-target=celebrimbor", "eregion-zone=staging"],
    ["eregion-target=celebrimbor", "eregion-target=celebrimbor-x", "eregion-zone=bench"],
    ["eregion-target=celebrimbor", "eregion-zone=bench", "EREGION-ZONE=production"],
])
def test_the_application_s_tags_name_the_bench_and_one_zone(tags):
    assert not _verdict(_identity(app={"tags": tags})).allowed


def test_tag_names_in_any_case_and_entra_s_own_tags_ignored():
    tags = ["WindowsAzureActiveDirectoryIntegratedApp", "Eregion-Target=celebrimbor", "eregion-zone=bench"]
    assert _verdict(_identity(app={"tags": tags})).allowed


def test_the_two_zones_must_agree():
    """M3816."""
    v = _verdict(_identity(app={"tags": ["eregion-target=celebrimbor", "eregion-zone=production"]}))
    assert not v.allowed and "zones disagree" in v.reason
    assert not _verdict(rg={"eregion-target": "celebrimbor", "eregion-identities": APP}).allowed


# ── The tenant, the principal ──────────────────────────────────────────────────────────

def test_a_scope_without_a_tenant_refuses_every_identity():
    v = _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "tenant_id": ""}))
    assert not v.allowed and "EREGION_TENANT_ID" in v.reason


def test_a_reader_of_another_tenant_refuses():
    """M3811."""
    assert not _verdict(token={**TOKEN, "tid": OTHER_TENANT}).allowed
    assert not _verdict(token={"oid": ORODRUIN}).allowed


def test_an_application_registered_in_another_tenant_refuses():
    """A multi-tenant application's principal carries the tags its home tenant writes (Graph: a
    principal's tags are the union of its own and its application's) — M3812."""
    v = _verdict(_identity(sp={"appOwnerOrganizationId": OTHER_TENANT}))
    assert not v.allowed and "another tenant" in v.reason


@pytest.mark.parametrize("audience", ["AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "", None])
def test_an_application_that_reaches_other_tenants_refuses(audience):
    """M3819."""
    assert not _verdict(_identity(app={"signInAudience": audience})).allowed


@pytest.mark.parametrize("kind", ["ManagedIdentity", "Legacy", "ServiceIdentity", "SocialIdp", "", None])
def test_only_an_application_s_principal_is_a_target(kind):
    """A managed identity — Glorfindel's, Orodruin's — is never a target (M3813)."""
    v = _verdict(_identity(sp={"servicePrincipalType": kind}))
    assert not v.allowed and "never a target" in v.reason


def test_a_principal_of_another_application_refuses():
    assert not _verdict(_identity(sp={"appId": "00000000-0000-0000-0000-0000000000d9"})).allowed
    assert not _verdict(_identity(app={"id": "not-a-guid"})).allowed


# ── The identities that are never targets ─────────────────────────────────────────────

@pytest.mark.parametrize("where, value", [
    ("app", {"id": H0}), ("sp", {"id": H0}), ("app", {"appId": H0}),
    ("sp", {"id": ORODRUIN}), ("sp", {"id": OPERATOR}),
])
def test_a_protected_identity_is_never_a_target(where, value):
    """Glorfindel's, Orodruin's, the operator's — even enrolled by both keys (M3814)."""
    identity = _identity(**{where: value})
    if where == "app" and "appId" in value:
        identity["service_principal"]["appId"] = value["appId"]
    rg = {**RG, "eregion-identities": f"{APP} {H0}"}
    v = _verdict(identity, rg)
    assert not v.allowed and "protected identity" in v.reason


def test_the_reader_itself_is_never_a_target():
    scope = IdentityScope(**{**SCOPE.__dict__, "never": NeverTarget(ids=frozenset({OPERATOR}), operators=frozenset({OPERATOR}))})
    assert not _verdict(_identity(sp={"id": ORODRUIN}), scope=scope).allowed
    assert not _verdict(token={**TOKEN, "appid": APP_ID}, scope=scope).allowed


def test_an_application_that_owns_a_protected_identity_refuses():
    """Its credentials would rule what it owns: Glorfindel's own registration, say."""
    v = _verdict(_identity(owned=["00000000-0000-0000-0000-0000000000d1", H0.upper()]))
    assert not v.allowed and "owns a protected identity" in v.reason


def test_without_the_operator_no_identity_is_accepted():
    """The operator's object id comes from infra/orodruin (terraform output operator_object_id):
    without it, the guard refuses every identity (M3815)."""
    v = _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "never": NeverTarget(ids=NEVER.ids)}))
    assert not v.allowed and "EREGION_OPERATOR_OBJECT_ID" in v.reason
    assert not _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "never": None})).allowed


def test_the_scope_comes_from_the_environment():
    env = {"EREGION_TENANT_ID": TENANT.upper(), "EREGION_OPERATOR_OBJECT_ID": OPERATOR,
           "EREGION_PROTECTED_IDENTITIES": f"{ORODRUIN},{H0}", "GLORFINDEL_OWN_CALLERS": "x,00000000-0000-0000-0000-0000000000b9",
           "AZURE_SUBSCRIPTION_ID": SUB, "EREGION_BENCH": "celebrimbor-blue"}
    scope = IdentityScope.for_bench(env)
    assert scope.tenant_id == TENANT and scope.bench == "celebrimbor-blue"
    assert scope.never.operators == {OPERATOR} and not scope.never.refusal()
    assert scope.never.ids == {ORODRUIN, H0, OPERATOR, "00000000-0000-0000-0000-0000000000b9"}
    assert scope.resource_group == "rg-celebrimbor-blue"
    assert IdentityScope.for_bench({**env, "EREGION_BENCH_RG": "rg-celebrimbor"}).resource_group == "rg-celebrimbor"
    assert IdentityScope.for_bench({}).tenant_id == "" and IdentityScope.for_bench({}).never.refusal()


def test_a_protected_list_written_wrong_refuses_everything():
    """A typo in the list would leave an identity unprotected, unsaid (M3815)."""
    never = NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": OPERATOR,
                                  "EREGION_PROTECTED_IDENTITIES": f"{ORODRUIN},{H0[:-1]}"})
    assert never.refusal()
    assert not _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "never": never})).allowed


def test_an_unknown_bench_refuses():
    assert not _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "bench": "prod"})).allowed


# ── The zone decides what runs ─────────────────────────────────────────────────────────

def _production():
    return (_identity(app={"tags": ["eregion-target=celebrimbor", "eregion-zone=production"]}),
            {**RG, "eregion-zone": "production"})


def test_in_production_a_non_destructive_technique_only():
    """M3818."""
    identity, rg = _production()
    ok = check_identity(identity, rg, scope=SCOPE, token=TOKEN, kind="technique", destructive=False)
    assert ok.allowed and ok.zone == "production"
    for kind, destructive in (("technique", True), ("technique", None), ("fault", False)):
        assert not check_identity(identity, rg, scope=SCOPE, token=TOKEN, kind=kind,
                                  destructive=destructive).allowed


def test_on_the_bench_a_destructive_technique_passes():
    assert check_identity(_identity(), RG, scope=SCOPE, token=TOKEN, kind="technique", destructive=True).allowed


# ── The reader, on a fake Graph and a fake ARM ─────────────────────────────────────────

def _jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


class _Credential:
    """A distinct token per scope: Graph's carries the reader's claims, ARM's another audience."""

    def __init__(self):
        self.asked = []

    def get_token(self, scope):
        self.asked.append(scope)
        return SimpleNamespace(token=_jwt({**TOKEN, "aud": scope.rsplit("/", 1)[0]}))


GRAPH_BEARER = "Bearer " + _jwt({**TOKEN, "aud": "https://graph.microsoft.com"})
ARM_BEARER = "Bearer " + _jwt({**TOKEN, "aud": "https://management.azure.com"})


class FakeGraph:
    """Microsoft Graph and ARM as the reader asks them: a dict of URL → body (or status)."""

    def __init__(self, identity=None, rg=None, *, fail=None, owned_pages=None, eligible=None):
        identity = identity or _identity()
        self.calls = []
        self.fail = fail or {}
        g = "https://graph.microsoft.com/v1.0"
        self.routes = {
            f"{g}/applications/{APP}": identity["application"],
            f"{g}/servicePrincipals(appId='{APP_ID}')": identity["service_principal"],
            f"{g}/servicePrincipals/{SP}/ownedObjects": {"value": [{"id": o} for o in identity["owned"]]},
            f"{g}/servicePrincipals/{SP}/appRoleAssignedTo": {"value": [{"id": o} for o in identity["assigned_to"]]},
            f"{g}/servicePrincipals/{SP}/transitiveMemberOf": {"value": [{"id": o} for o in identity["member_of"]]},
            f"{g}/servicePrincipals/{SP}/appRoleAssignments": {"value": [
                {"resourceId": h["resourceId"], "appRoleId": h["appRoleId"]} for h in identity["app_roles_held"]]},
            f"{g}/roleManagement/directory/roleAssignments": {"value": identity["directory_roles"]},
            f"{g}/roleManagement/directory/roleEligibilityScheduleInstances": {"value": eligible or []},
            f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-celebrimbor":
                {"tags": RG if rg is None else rg},
        }
        for url, body in (owned_pages or {}).items():
            self.routes[url] = body

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, headers["Authorization"], params))
        status = self.fail.get(url, 200 if url in self.routes else 404)
        body = self.routes.get(url, {})
        return SimpleNamespace(ok=status < 400, status_code=status, json=lambda: body)


def _reader(graph, scope=SCOPE):
    return GraphEnrollment(scope=scope, credential=_Credential(), get=graph)


def test_the_reader_judges_what_graph_and_arm_say():
    graph = FakeGraph()
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert v.allowed and v.zone == "bench"
    urls = [u for u, _, _ in graph.calls]
    assert urls[0].endswith(f"/applications/{APP}") and urls[-1].endswith("/resourceGroups/rg-celebrimbor")
    # Each token goes to its own API only: Graph's to Graph, ARM's to ARM (M3944).
    assert all(u.startswith("https://graph.microsoft.com/v1.0/") for u in urls[:-1])
    assert {a for u, a, _ in graph.calls[:-1]} == {GRAPH_BEARER}
    assert graph.calls[-1][1] == ARM_BEARER


def test_the_reader_refuses_what_the_guard_refuses():
    v = _reader(FakeGraph(rg={"eregion-target": "celebrimbor", "eregion-zone": "bench"})).check(
        APP, kind="technique", destructive=False)
    assert not v.allowed and "eregion-identities" in v.reason


@pytest.mark.parametrize("which", ["applications", "servicePrincipals(appId", "ownedObjects", "appRoleAssignedTo",
                                   "transitiveMemberOf", "appRoleAssignments", "roleAssignments",
                                   "roleEligibilityScheduleInstances", "resourceGroups"])
@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_a_read_that_fails_refuses(which, status):
    """Never enrolled by default (M3817) — a tenant without PIM whose eligibility read fails
    included: everything is then refused, said (to measure on the bench)."""
    graph = FakeGraph()
    ends = {"applications": f"/applications/{APP}", "servicePrincipals(appId": f"(appId='{APP_ID}')",
            "roleAssignments": "/directory/roleAssignments", "resourceGroups": "/resourceGroups/rg-celebrimbor"}
    (url,) = [u for u in graph.routes if u.endswith(ends.get(which, f"/{which}"))]
    graph.fail[url] = status
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "unreadable" in v.reason


def test_a_credential_that_fails_refuses():
    class Broken:
        def get_token(self, scope):
            raise RuntimeError("no identity")
    v = GraphEnrollment(scope=SCOPE, credential=Broken(), get=FakeGraph()).check(
        APP, kind="technique", destructive=False)
    assert not v.allowed and "unreadable" in v.reason


@pytest.mark.parametrize("app", ["", "not-a-guid", f"{APP}/../users", f"{APP}?$select=x", "*"])
def test_an_id_that_is_no_object_id_is_read_nowhere(app):
    graph = FakeGraph()
    v = _reader(graph).check(app, kind="technique", destructive=False)
    assert not v.allowed and graph.calls == []


def test_a_scope_that_cannot_judge_asks_for_no_token():
    cred, graph = _Credential(), FakeGraph()
    scope = IdentityScope(**{**SCOPE.__dict__, "never": NeverTarget()})
    v = GraphEnrollment(scope=scope, credential=cred, get=graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and cred.asked == [] and graph.calls == []


@pytest.mark.parametrize("rg", ["rg-production", "rg-celebrimbor/../rg-prod", ""])
def test_the_group_read_is_the_bench_s_only(rg):
    graph = FakeGraph()
    v = _reader(graph, IdentityScope(**{**SCOPE.__dict__, "resource_group": rg})).check(
        APP, kind="technique", destructive=False)
    assert not v.allowed and graph.calls == []


def test_owned_objects_are_read_whole_and_their_next_page_stays_in_graph():
    g = "https://graph.microsoft.com/v1.0"
    nxt = f"{g}/servicePrincipals/{SP}/ownedObjects?$skiptoken=2"
    graph = FakeGraph(owned_pages={
        f"{g}/servicePrincipals/{SP}/ownedObjects": {"value": [], "@odata.nextLink": nxt},
        nxt: {"value": [{"id": H0}]}})
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "owns a protected identity" in v.reason
    graph = FakeGraph(owned_pages={
        f"{g}/servicePrincipals/{SP}/ownedObjects": {"value": [], "@odata.nextLink": "https://evil.example/x"}})
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "outside Microsoft Graph" in v.reason
    assert not any("evil" in u for u, _, _ in graph.calls)


def test_the_command_says_what_may_run(monkeypatch, capsys):
    monkeypatch.setattr("eregion_core.inscription.GraphEnrollment",
                        lambda: _reader(FakeGraph()))
    assert main(["identity", APP]) == 0
    out = capsys.readouterr().out
    assert "non-destructive technique: allowed (zone bench)" in out
    assert main(["whoami"]) == 2
    monkeypatch.setattr("eregion_core.inscription.GraphEnrollment",
                        lambda: _reader(FakeGraph(rg={"eregion-target": "celebrimbor"})))
    assert main(["identity", APP]) == 1


# ── A privileged identity is never enrolled (05/11: IR1's executor will own what is enrolled) ──

GRAPH_SP = "00000000-0000-0000-0000-0000000000a8"     # Microsoft Graph's principal in the tenant
ROLE = {"principalId": SP, "roleDefinitionId": "00000000-0000-0000-0000-0000000000e1", "directoryScopeId": "/"}


def test_an_identity_with_a_directory_role_is_never_enrolled():
    """Active or eligible, at the tenant or an administrative unit's scope: any role (M3900, M3901)."""
    v = _verdict(_identity(directory_roles=[ROLE]))
    assert not v.allowed and "directory role" in v.reason
    assert not _verdict(_identity(directory_roles=[{**ROLE, "directoryScopeId": "/administrativeUnits/x"}])).allowed


def test_a_member_of_a_group_is_never_enrolled():
    """A group can carry a directory role or an Azure role: a membership refuses (M3903)."""
    v = _verdict(_identity(member_of=["00000000-0000-0000-0000-0000000000e9"]))
    assert not v.allowed and "member of a group" in v.reason


@pytest.mark.parametrize("value", ["Application.ReadWrite.All", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
                                   "RoleManagement.ReadWrite.Directory", "Mail.Send", "User.Invite.All",
                                   "Sites.FullControl.All", "User.ReadBasic.All", "", "Files.Read.All.Write"])
def test_an_application_permission_that_is_not_a_read_is_never_enrolled(value):
    """A write in Graph, or a permission not named as a read (or not named): refused (M3902)."""
    held = [{"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d2", "value": value}]
    v = _verdict(_identity(app_roles_held=held))
    assert not v.allowed and "application permission" in v.reason


@pytest.mark.parametrize("value", ["User.Read.All", "Application.Read.All", "AuditLog.Read.All", "Files.Read",
                                   "Mail.Read"])
def test_no_application_permission_is_admitted_until_r2_needs_one(value):
    """Relecture of IDI1: even a read (Mail.Read, Files.Read.All) — its owner would read it all —
    refused while the admitted list is empty (M3942)."""
    from eregion_core import inscription
    assert inscription.ADMITTED_APP_PERMISSIONS == ()
    held = [{"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d1", "value": value}]
    v = _verdict(_identity(app_roles_held=held))
    assert not v.allowed and "not one admitted" in v.reason


def test_an_admitted_permission_must_still_be_a_read(monkeypatch):
    from eregion_core import inscription
    monkeypatch.setattr(inscription, "ADMITTED_APP_PERMISSIONS", ("User.Read.All", "Mail.ReadWrite"))
    read = [{"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d1", "value": "User.Read.All"}]
    write = [{"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d2", "value": "Mail.ReadWrite"}]
    assert _verdict(_identity(app_roles_held=read)).allowed
    assert not _verdict(_identity(app_roles_held=write)).allowed


@pytest.mark.parametrize("key", ["directory_roles", "member_of", "app_roles_held", "owned", "assigned_to"])
@pytest.mark.parametrize("how", ["absent", "None"])
def test_privileges_not_read_refuse(key, how):
    """Each of the five must have been read: a key absent, or None, refuses — in the privilege
    check and in the shared list alike (M3908, M3909)."""
    identity = _identity()
    if how == "absent":
        identity.pop(key)
    else:
        identity[key] = None
    assert privilege_refusal(identity), key
    assert not _verdict(identity).allowed, key
    if key in ("owned", "assigned_to"):
        assert NEVER.why(identity, tenant=TENANT, token=TOKEN), key


def test_an_identity_that_owns_anything_is_never_enrolled():
    """Owning a group with a role, or a principal with one, is holding it — any owned object refuses,
    protected or not (relecture of IDI1, M3907)."""
    v = _verdict(_identity(owned=["00000000-0000-0000-0000-0000000000e8"]))
    assert not v.allowed and "owns 1 object" in v.reason


def test_an_eligible_role_read_from_graph_refuses():
    """PIM: an identity one activation away from a role — read from Graph, refused (M3901)."""
    graph = FakeGraph(eligible=[{**ROLE, "memberType": "Direct"}])
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "directory role" in v.reason


# ── The shared list of identities never targeted (eregion_core/never_target.py) ──────────

@pytest.mark.parametrize("sp", [{"appRoles": [{"id": "00000000-0000-0000-0000-0000000000e2", "value": "Data.Read"}]},
                                {"oauth2PermissionScopes": [{"value": "user_impersonation"}]}])
def test_the_principal_of_a_resource_is_never_a_target(sp):
    """An API others call: its owner would rule what they reach (M3904)."""
    v = _verdict(_identity(sp=sp))
    assert not v.allowed and "principal of a resource" in v.reason
    v = _verdict(_identity(assigned_to=["00000000-0000-0000-0000-0000000000e3"]))
    assert not v.allowed and "principal of a resource" in v.reason


def test_microsoft_s_applications_are_never_targets():
    """Registered in Microsoft's tenant: refused by its home tenant, no Microsoft id written here."""
    v = _verdict(_identity(sp={"appOwnerOrganizationId": OTHER_TENANT}))
    assert not v.allowed and "Microsoft" in v.reason


@pytest.mark.parametrize("name", ["ANNATAR_AZURE_CLIENT_ID", "GLORFINDEL_AZURE_CLIENT_ID", "AZURE_CLIENT_ID",
                                  "GLORFINDEL_OWN_CALLERS", "EREGION_PROTECTED_IDENTITIES", "EREGION_OPERATOR_OBJECT_ID"])
def test_annatar_glorfindel_and_the_operators_are_never_targets(name):
    """By their client id (appId) or object id, whichever the variable holds."""
    env = {"EREGION_OPERATOR_OBJECT_ID": OPERATOR, name: APP_ID}
    never = NeverTarget.from_env(env)
    if name == "EREGION_OPERATOR_OBJECT_ID":
        never = NeverTarget.from_env({name: f"{OPERATOR},{APP_ID}"})
    assert never.covers(APP_ID) and never.covers(APP_ID.upper())
    v = _verdict(scope=IdentityScope(**{**SCOPE.__dict__, "never": never}))
    assert not v.allowed and "protected identity" in v.reason


def test_covers_says_whether_an_object_id_is_never_a_target():
    """The interface IR1a reads: listed → True; not listed → False; unreadable → True for all (M3905)."""
    never = NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": OPERATOR, "EREGION_PROTECTED_IDENTITIES": H0})
    assert never.covers(H0) and never.covers(OPERATOR) and not never.covers(APP)
    assert never.covers("not-an-id")
    assert NeverTarget.from_env({"EREGION_PROTECTED_IDENTITIES": H0}).covers(APP)              # no operator
    assert NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": f"{OPERATOR},oops"}).covers(APP)  # a typo
    assert NeverTarget.from_env({"EREGION_OPERATOR_OBJECT_ID": OPERATOR, "ANNATAR_AZURE_CLIENT_ID": "x"}).covers(APP)


def test_never_target_is_in_the_shared_core():
    """D1: eregion_core alone, no component imported — IR1a's executor reads the same list."""
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).resolve().parents[2] / "eregion_core" / "never_target.py").read_text())
    mods = {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    mods |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not {m for m in mods if m.split(".")[0] in ("glorfindel", "annatar", "gothmog", "azure")}


# ── The reader names each application permission by its resource's own list ──────────────

def test_the_reader_names_a_permission_by_its_resource_and_refuses_a_write():
    g = "https://graph.microsoft.com/v1.0"
    held = [{"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d2"}]
    graph = FakeGraph(_identity(app_roles_held=held), owned_pages={
        f"{g}/servicePrincipals/{GRAPH_SP}": {"id": GRAPH_SP, "appRoles": [
            {"id": "00000000-0000-0000-0000-0000000000d1", "value": "Application.Read.All"},
            {"id": "00000000-0000-0000-0000-0000000000d2", "value": "Application.ReadWrite.All"}]}})
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "Application.ReadWrite.All" in v.reason
    graph.routes[f"{g}/servicePrincipals/{SP}/appRoleAssignments"] = {"value": [
        {"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d1"}]}
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "Application.Read.All" in v.reason      # a read, not admitted
    # A role its resource does not list: not named, refused.
    graph.routes[f"{g}/servicePrincipals/{SP}/appRoleAssignments"] = {"value": [
        {"resourceId": GRAPH_SP, "appRoleId": "00000000-0000-0000-0000-0000000000d9"}]}
    assert not _reader(graph).check(APP, kind="technique", destructive=False).allowed


def test_the_reader_asks_the_directory_roles_of_the_principal_only():
    graph = FakeGraph(_identity(directory_roles=[ROLE]))
    v = _reader(graph).check(APP, kind="technique", destructive=False)
    assert not v.allowed and "directory role" in v.reason
    asked = {u: p for u, _, p in graph.calls if "roleManagement" in u}
    assert len(asked) == 2 and all(p == {"$filter": f"principalId eq '{SP}'"} for p in asked.values())
