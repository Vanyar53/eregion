"""IDI1b (#573): a test user of Entra ID is enrolled for the bench by two halves, the way a VM is by
its group and itself — the bench's restricted administrative unit holds it (pinned by its object id,
posed by Celebrimbor), and a custom security attribute of Eregion's set, on the user, names the bench
and the zone — and passes the same guard: of the named tenant, a member (never a guest), never an
identity of the shared list (eregion_core/never_target.py), never a privileged one, its zone deciding.
A half missing, two halves that disagree, a read that fails: refused. All against a fake Graph: no
network, no Azure, no Graph; every identifier here is an example. Mutants M4085–M4095
(scripts/mutants/IDI1b.py)."""
import base64
import json
from types import SimpleNamespace

import pytest

from eregion_core import inscription
from eregion_core.inscription import (
    GraphEnrollment,
    IdentityScope,
    check_user,
    main,
    user_enrollment,
    user_privilege_refusal,
)
from eregion_core.never_target import NeverTarget

TENANT = "00000000-0000-0000-0000-0000000000f0"
OTHER_TENANT = "00000000-0000-0000-0000-0000000000f9"
OPERATOR = "00000000-0000-0000-0000-0000000000ee"
BREAK_GLASS = "00000000-0000-0000-0000-0000000000ef"   # a break-glass account, named by the operator
ORODRUIN = "00000000-0000-0000-0000-0000000000a0"      # the reader
UNIT = "00000000-0000-0000-0000-0000000000d0"          # the bench's restricted unit
OTHER_UNIT = "00000000-0000-0000-0000-0000000000d9"
USER = "00000000-0000-0000-0000-0000000000c5"          # a test user
OTHER_USER = "00000000-0000-0000-0000-0000000000c6"
SUB = "00000000-0000-0000-0000-000000000000"
AU = "#microsoft.graph.administrativeUnit"

NEVER = NeverTarget(ids=frozenset({ORODRUIN, OPERATOR, BREAK_GLASS}), operators=frozenset({OPERATOR}))
SCOPE = IdentityScope(bench="celebrimbor", tenant_id=TENANT, subscription_id=SUB,
                      resource_group="rg-celebrimbor", never=NEVER, admin_unit_id=UNIT)
TOKEN = {"tid": TENANT, "oid": ORODRUIN, "appid": "00000000-0000-0000-0000-0000000000a1"}


def _csa(**attrs):
    return {"Eregion": {"@odata.type": "#microsoft.graph.customSecurityAttributeValue",
                        "eregionTarget": "celebrimbor", "eregionZone": "bench", **attrs}}


def _user(**over):
    out = {"id": USER, "userType": "Member", "customSecurityAttributes": _csa(),
           "member_of": [{"id": UNIT, "@odata.type": AU}], "owned": [], "app_roles_held": [],
           "directory_roles": []}
    out.update(over)
    return out


def _unit(**over):
    return {"id": UNIT, "isMemberManagementRestricted": True, "members": [OTHER_USER, USER], **over}


def _verdict(user=None, unit=None, *, scope=SCOPE, token=TOKEN):
    return user_enrollment(_user() if user is None else user, _unit() if unit is None else unit,
                           scope=scope, token=token)


def _scope(**over):
    return IdentityScope(**{**SCOPE.__dict__, **over})


# ── Both halves, and only both ──────────────────────────────────────────────────────────

def test_a_user_held_by_the_unit_and_carrying_the_attribute_is_enrolled_in_its_zone():
    v = _verdict()
    assert v.allowed and v.zone == "bench"


def test_the_attribute_alone_opens_nothing():
    """An Attribute Assignment Administrator tags any user: without the bench's unit holding it, it
    is no target (M4085)."""
    v = _verdict(unit=_unit(members=[OTHER_USER]))
    assert not v.allowed and "not a member of the bench's administrative unit" in v.reason
    assert not _verdict(unit=_unit(members=[])).allowed


def test_the_unit_alone_opens_nothing():
    v = _verdict(_user(customSecurityAttributes={}))
    assert not v.allowed and "no attribute of the set 'Eregion'" in v.reason
    v = _verdict(_user(customSecurityAttributes={"Eregion": {"eregionZone": "bench"}}))
    assert not v.allowed and "Eregion.eregionTarget=celebrimbor" in v.reason


@pytest.mark.parametrize("csa", [None, "Eregion", []])
def test_attributes_not_read_refuse(csa):
    """Graph returns them only to a reader allowed to: absent, the half is missing."""
    v = _verdict(_user(customSecurityAttributes=csa))
    assert not v.allowed and "not read" in v.reason
    user = _user()
    user.pop("customSecurityAttributes")
    assert not _verdict(user).allowed


def test_an_unrestricted_unit_refuses():
    """In a unit that is not restricted, a tenant's administrator manages its members: the
    enrollment is no longer a traced gesture at the unit's scope (M4086)."""
    for restricted in (False, None, "true", 1):
        v = _verdict(unit=_unit(isMemberManagementRestricted=restricted))
        assert not v.allowed and "not restricted" in v.reason, restricted
    unit = _unit()
    unit.pop("isMemberManagementRestricted")
    assert not _verdict(unit=unit).allowed


@pytest.mark.parametrize("kind", ["Dynamic", "dynamic", "DYNAMIC"])
def test_a_dynamic_unit_refuses(kind):
    """A rule, not Celebrimbor, would choose its members: anyone who matches it enrolls (M4140)."""
    v = _verdict(unit=_unit(membershipType=kind))
    assert not v.allowed and "dynamic" in v.reason
    for kind in (None, "Assigned"):
        assert _verdict(unit=_unit(membershipType=kind)).allowed


def test_the_unit_is_the_pinned_one_never_another():
    """Pinned by its id, never looked up by its name: another unit holding the user opens nothing
    (M4087)."""
    v = _verdict(unit=_unit(id=OTHER_UNIT))
    assert not v.allowed and "pinned id" in v.reason
    assert not _verdict(unit=_unit(id="")).allowed


def test_a_scope_without_the_unit_refuses_every_user():
    v = _verdict(scope=_scope(admin_unit_id=""))
    assert not v.allowed and "EREGION_BENCH_ADMIN_UNIT_ID" in v.reason


def test_unit_members_not_read_refuse():
    unit = _unit()
    unit.pop("members")
    v = _verdict(unit=unit)
    assert not v.allowed and "members are not read" in v.reason
    assert not _verdict(unit=_unit(members=None)).allowed


def test_a_member_of_another_unit_refuses():
    """Within another administrator's reach (M4095)."""
    v = _verdict(_user(member_of=[{"id": UNIT, "@odata.type": AU}, {"id": OTHER_UNIT, "@odata.type": AU}]))
    assert not v.allowed and "another administrative unit" in v.reason


def test_the_user_side_may_not_list_the_unit():
    """Whether a user's transitiveMemberOf lists its administrative units is to measure: the unit's
    own members are the half, read from the pinned unit."""
    assert _verdict(_user(member_of=[])).allowed


@pytest.mark.parametrize("attrs", [
    {"eregionTarget": "celebrimbor-other"},
    {"eregionTarget": "Celebrimbor"},                  # values exactly
    {"eregionTarget": ""},
    {"eregionTarget": ["celebrimbor"]},                # a collection
    {"eregionTarget": None},
])
def test_the_attribute_names_this_bench(attrs):
    """M4088."""
    assert not _verdict(_user(customSecurityAttributes=_csa(**attrs))).allowed


@pytest.mark.parametrize("zone", [None, "", "Bench", "staging", ["bench"]])
def test_the_attribute_names_a_zone(zone):
    v = _verdict(_user(customSecurityAttributes=_csa(eregionZone=zone)))
    assert not v.allowed and "eregionZone" in v.reason
    csa = _csa()
    csa["Eregion"].pop("eregionZone")
    assert not _verdict(_user(customSecurityAttributes=csa)).allowed


@pytest.mark.parametrize("zone", ["production", "twin"])
def test_the_two_halves_must_agree_on_the_zone(zone):
    """The bench's unit is in zone bench: a user it holds tagged production is a disagreement, not a
    production target (M4089)."""
    v = _verdict(_user(customSecurityAttributes=_csa(eregionZone=zone)))
    assert not v.allowed and "zones disagree" in v.reason


def test_names_in_any_case_values_exactly_and_a_name_twice_refuses():
    csa = {"eregion": {"EregionTarget": "celebrimbor", "EREGIONZONE": "bench"}}
    assert _verdict(_user(customSecurityAttributes=csa)).allowed
    csa = {"Eregion": {"eregionTarget": "celebrimbor", "EregionTarget": "celebrimbor-x", "eregionZone": "bench"}}
    v = _verdict(_user(customSecurityAttributes=csa))
    assert not v.allowed and "twice" in v.reason
    csa = {"Eregion": {"eregionTarget": "celebrimbor", "eregionZone": "bench"},
           "EREGION": {"eregionTarget": "celebrimbor", "eregionZone": "bench"}}
    assert not _verdict(_user(customSecurityAttributes=csa)).allowed
    assert not _verdict(_user(customSecurityAttributes={"Eregion": "celebrimbor"})).allowed


def test_another_set_does_not_count():
    """Only Eregion's set: an attribute set anyone else defines writes nothing that enrolls."""
    csa = {"Other": {"eregionTarget": "celebrimbor", "eregionZone": "bench"}}
    assert not _verdict(_user(customSecurityAttributes=csa)).allowed


def test_the_hyphenated_tag_is_never_read_as_the_attribute():
    """An attribute's name admits no hyphen (doc): the guard maps eregion-target onto eregionTarget."""
    assert inscription.ATTRIBUTE_NAMES == {"eregion-target": "eregionTarget", "eregion-zone": "eregionZone"}
    csa = {"Eregion": {"eregion-target": "celebrimbor", "eregion-zone": "bench"}}
    assert not _verdict(_user(customSecurityAttributes=csa)).allowed


# ── Never a target, never privileged, never a guest ────────────────────────────────────

@pytest.mark.parametrize("who", [OPERATOR, BREAK_GLASS, ORODRUIN, OPERATOR.upper()])
def test_a_protected_identity_is_never_a_target(who):
    """An operator or a break-glass account is never a member of the unit, and the guard checks it
    anyway against never_target — even held by the unit and tagged (M4090)."""
    v = _verdict(_user(id=who), _unit(members=[who]))
    assert not v.allowed and "protected identity" in v.reason


def test_the_reader_itself_is_never_a_target():
    scope = _scope(never=NeverTarget(ids=frozenset({OPERATOR}), operators=frozenset({OPERATOR})))
    v = _verdict(_user(id=ORODRUIN), _unit(members=[ORODRUIN]), scope=scope)
    assert not v.allowed and "protected identity" in v.reason


def test_a_list_unreadable_refuses_every_user():
    assert not _verdict(scope=_scope(never=NeverTarget(ids=NEVER.ids))).allowed
    assert not _verdict(scope=_scope(never=None)).allowed


@pytest.mark.parametrize("kind", ["Guest", "", None, "member"])
def test_a_guest_is_another_tenant_s(kind):
    """M4093."""
    v = _verdict(_user(userType=kind))
    assert not v.allowed and "guest" in v.reason


def test_a_reader_of_another_tenant_refuses():
    assert not _verdict(token={**TOKEN, "tid": OTHER_TENANT}).allowed
    assert not _verdict(token={"oid": ORODRUIN}).allowed


def test_a_scope_without_a_tenant_refuses():
    assert not _verdict(scope=_scope(tenant_id="")).allowed


def test_an_unknown_bench_refuses():
    assert not _verdict(scope=_scope(bench="prod")).allowed


def test_a_user_without_an_object_id_refuses():
    assert not _verdict(_user(id="not-a-guid"), _unit(members=["not-a-guid"])).allowed


ROLE = {"principalId": USER, "roleDefinitionId": "00000000-0000-0000-0000-0000000000e1", "directoryScopeId": "/"}


def test_a_user_with_a_directory_role_is_never_enrolled():
    """Active or eligible, at any scope — at the unit's own too: a User Administrator at its scope
    would not manage it, and taking it would give its role (M4091)."""
    v = _verdict(_user(directory_roles=[ROLE]))
    assert not v.allowed and "directory role" in v.reason
    assert not _verdict(_user(directory_roles=[{**ROLE, "directoryScopeId": f"/administrativeUnits/{UNIT}"}])).allowed


@pytest.mark.parametrize("member", [{"id": "00000000-0000-0000-0000-0000000000e9", "@odata.type": "#microsoft.graph.group"},
                                    {"id": "00000000-0000-0000-0000-0000000000e8", "@odata.type": "#microsoft.graph.directoryRole"},
                                    {"id": "00000000-0000-0000-0000-0000000000e7"}, "00000000-0000-0000-0000-0000000000e6"])
def test_a_member_of_a_group_or_a_role_is_never_enrolled(member):
    """M4092: a group can carry a role; what is not an administrative unit refuses."""
    v = _verdict(_user(member_of=[{"id": UNIT, "@odata.type": AU}, member]))
    assert not v.allowed and "member of a group" in v.reason


def test_a_user_who_owns_or_holds_an_application_role_is_never_enrolled():
    v = _verdict(_user(owned=["00000000-0000-0000-0000-0000000000e5"]))
    assert not v.allowed and "owns 1 object" in v.reason
    v = _verdict(_user(app_roles_held=[{"resourceId": "00000000-0000-0000-0000-0000000000e4",
                                         "appRoleId": "00000000-0000-0000-0000-000000000000"}]))
    assert not v.allowed and "application role" in v.reason


@pytest.mark.parametrize("key", ["directory_roles", "member_of", "owned", "app_roles_held"])
@pytest.mark.parametrize("how", ["absent", "None"])
def test_privileges_not_read_refuse(key, how):
    user = _user()
    if how == "absent":
        user.pop(key)
    else:
        user[key] = None
    assert user_privilege_refusal(user), key
    assert not _verdict(user).allowed, key


# ── The zone decides what runs ─────────────────────────────────────────────────────────

def test_on_the_bench_a_destructive_technique_passes():
    assert check_user(_user(), _unit(), scope=SCOPE, token=TOKEN, kind="technique", destructive=True).allowed


def test_the_zone_decides(monkeypatch):
    """A unit of another zone (none yet, a twin's later): its users get what the zone allows."""
    monkeypatch.setattr(inscription, "UNIT_ZONE", "production")
    user = _user(customSecurityAttributes=_csa(eregionZone="production"))
    ok = check_user(user, _unit(), scope=SCOPE, token=TOKEN, kind="technique", destructive=False)
    assert ok.allowed and ok.zone == "production"
    for kind, destructive in (("technique", True), ("technique", None), ("fault", False)):
        assert not check_user(user, _unit(), scope=SCOPE, token=TOKEN, kind=kind, destructive=destructive).allowed


def test_the_scope_reads_the_unit_from_the_environment():
    env = {"EREGION_TENANT_ID": TENANT, "EREGION_OPERATOR_OBJECT_ID": OPERATOR,
           "EREGION_BENCH_ADMIN_UNIT_ID": UNIT.upper()}
    assert IdentityScope.for_bench(env).admin_unit_id == UNIT
    assert IdentityScope.for_bench({**env, "EREGION_BENCH_ADMIN_UNIT_ID": "au-celebrimbor"}).admin_unit_id == ""
    assert IdentityScope.for_bench({}).admin_unit_id == ""


# ── The reader, on a fake Graph ────────────────────────────────────────────────────────

def _jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


class _Credential:
    def __init__(self):
        self.asked = []

    def get_token(self, scope):
        self.asked.append(scope)
        return SimpleNamespace(token=_jwt({**TOKEN, "aud": scope.rsplit("/", 1)[0]}))


G = "https://graph.microsoft.com/v1.0"


class FakeGraph:
    """Microsoft Graph as the reader asks it: a dict of URL → body, a status per URL."""

    def __init__(self, user=None, unit=None, *, eligible=None):
        user = user or _user()
        unit = unit or _unit()
        self.calls = []
        self.fail = {}
        self.routes = {
            f"{G}/users/{USER}": {k: user[k] for k in ("id", "userType", "customSecurityAttributes") if k in user},
            f"{G}/users/{USER}/transitiveMemberOf": {"value": user["member_of"]},
            f"{G}/users/{USER}/ownedObjects": {"value": [{"id": o} for o in user["owned"]]},
            f"{G}/users/{USER}/appRoleAssignments": {"value": user["app_roles_held"]},
            f"{G}/roleManagement/directory/roleAssignments": {"value": user["directory_roles"]},
            f"{G}/roleManagement/directory/roleEligibilityScheduleInstances": {"value": eligible or []},
            f"{G}/directory/administrativeUnits/{UNIT}": {k: unit[k] for k in ("id", "isMemberManagementRestricted",
                                                                       "membershipType") if k in unit},
            f"{G}/directory/administrativeUnits/{UNIT}/members": {"value": [{"id": m} for m in unit["members"]]},
        }

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append((url, headers["Authorization"], params))
        status = self.fail.get(url, 200 if url in self.routes else 404)
        body = self.routes.get(url, {})

        def json():                     # a body that is no JSON: an exception put in its place
            if isinstance(body, Exception):
                raise body
            return body
        return SimpleNamespace(ok=status < 400, status_code=status, json=json)


def _reader(graph, scope=SCOPE, credential=None):
    return GraphEnrollment(scope=scope, credential=credential or _Credential(), get=graph)


def test_the_reader_judges_what_graph_says():
    graph = FakeGraph()
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert v.allowed and v.zone == "bench"
    urls = [u for u, _, _ in graph.calls]
    assert all(u.startswith(f"{G}/") for u in urls)
    assert urls[0] == f"{G}/users/{USER}"
    assert graph.calls[0][2] == {"$select": "id,userType,customSecurityAttributes"}
    # The unit is read by its pinned id, never by a name.
    assert f"{G}/directory/administrativeUnits/{UNIT}" in urls
    assert not any("$filter" in (p or {}) and "displayName" in str(p) for _, _, p in graph.calls)
    roles = {u: p for u, _, p in graph.calls if "roleManagement" in u}
    assert len(roles) == 2 and all(p == {"$filter": f"principalId eq '{USER}'"} for p in roles.values())


def test_the_reader_refuses_what_the_guard_refuses():
    v = _reader(FakeGraph(unit=_unit(isMemberManagementRestricted=False))).check_user(
        USER, kind="technique", destructive=False)
    assert not v.allowed and "not restricted" in v.reason
    v = _reader(FakeGraph(eligible=[{**ROLE, "memberType": "Direct"}])).check_user(
        USER, kind="technique", destructive=False)
    assert not v.allowed and "directory role" in v.reason


@pytest.mark.parametrize("which", ["users/" + USER, "transitiveMemberOf", "ownedObjects", "appRoleAssignments",
                                   "roleAssignments", "roleEligibilityScheduleInstances",
                                   "administrativeUnits/" + UNIT, "members"])
@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_a_read_that_fails_refuses(which, status):
    """Never enrolled by default (M4094)."""
    graph = FakeGraph()
    (url,) = [u for u in graph.routes if u.endswith("/" + which)]
    graph.fail[url] = status
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "unreadable" in v.reason


def test_graph_answering_for_another_user_refuses():
    graph = FakeGraph()
    graph.routes[f"{G}/users/{USER}"] = {**graph.routes[f"{G}/users/{USER}"], "id": OTHER_USER}
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "unreadable" in v.reason


@pytest.mark.parametrize("user", ["", "not-a-guid", f"{USER}/../applications", f"{USER}?$select=x", "*"])
def test_an_id_that_is_no_object_id_is_read_nowhere(user):
    graph = FakeGraph()
    v = _reader(graph).check_user(user, kind="technique", destructive=False)
    assert not v.allowed and graph.calls == []


@pytest.mark.parametrize("unit", ["x", f"{UNIT}/../users", f"{UNIT}?$select=*", UNIT.upper()])
def test_a_pinned_unit_that_is_no_object_id_is_read_nowhere(unit):
    """A scope built by hand, not by for_bench: the unit's id is checked again before any URL (M4141)."""
    cred, graph = _Credential(), FakeGraph()
    v = _reader(graph, _scope(admin_unit_id=unit), cred).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and graph.calls == [] and cred.asked == []


def test_the_reader_reads_the_unit_s_membership_type():
    graph = FakeGraph(unit=_unit(membershipType="Dynamic"))
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "dynamic" in v.reason
    (params,) = [p for u, _, p in graph.calls if u == f"{G}/directory/administrativeUnits/{UNIT}"]
    assert params == {"$select": "id,isMemberManagementRestricted,membershipType"}


def test_without_the_unit_nothing_is_read():
    cred, graph = _Credential(), FakeGraph()
    v = _reader(graph, _scope(admin_unit_id=""), cred).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and graph.calls == [] and cred.asked == []


def test_a_scope_that_cannot_judge_asks_for_no_token():
    cred, graph = _Credential(), FakeGraph()
    v = _reader(graph, _scope(never=NeverTarget()), cred).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and cred.asked == [] and graph.calls == []


def test_the_unit_s_members_are_read_whole_and_their_next_page_stays_in_graph():
    graph = FakeGraph(unit=_unit(members=[]))
    nxt = f"{G}/directory/administrativeUnits/{UNIT}/members?$skiptoken=2"
    graph.routes[f"{G}/directory/administrativeUnits/{UNIT}/members"] = {"value": [], "@odata.nextLink": nxt}
    graph.routes[nxt] = {"value": [{"id": USER}]}
    assert _reader(graph).check_user(USER, kind="technique", destructive=False).allowed
    graph.routes[f"{G}/directory/administrativeUnits/{UNIT}/members"] = {
        "value": [], "@odata.nextLink": "https://evil.example/x"}
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "outside Microsoft Graph" in v.reason
    assert not any("evil" in u for u, _, _ in graph.calls)


def test_the_command_says_what_may_run_on_a_user(monkeypatch, capsys):
    monkeypatch.setattr("eregion_core.inscription.GraphEnrollment", lambda: _reader(FakeGraph()))
    assert main(["user", USER]) == 0
    assert "non-destructive technique: allowed (zone bench)" in capsys.readouterr().out
    monkeypatch.setattr("eregion_core.inscription.GraphEnrollment",
                        lambda: _reader(FakeGraph(unit=_unit(members=[]))))
    assert main(["user", USER]) == 1
    assert "not a member" in capsys.readouterr().out
    assert main(["users", USER]) == 2


# ── A tenant without PIM (IDI1p, #618): the same exact answer, the same reading, for a user ─────

ELIGIBLE = f"{G}/roleManagement/directory/roleEligibilityScheduleInstances"
NO_LICENSE = {"error": {"code": "AadPremiumLicenseRequired",
                        "message": "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID "
                                   "Governance license.", "innerError": {}}}


def _answering(graph, url, status=400, body=NO_LICENSE):
    graph.fail[url] = status
    graph.routes[url] = body
    return graph


def test_a_tenant_without_pim_has_no_eligible_role_for_a_user_and_it_is_said(monkeypatch, capsys):
    v = _reader(_answering(FakeGraph(), ELIGIBLE)).check_user(USER, kind="technique", destructive=False)
    assert v.allowed and v.zone == "bench" and v.notes == (inscription.NO_PIM_LICENSE_NOTE,)
    assert _reader(FakeGraph()).check_user(USER, kind="technique", destructive=False).notes == ()
    # Never a reason to admit: a user with an active role stays refused, the note said.
    v = _reader(_answering(FakeGraph(_user(directory_roles=[ROLE])), ELIGIBLE)).check_user(
        USER, kind="technique", destructive=False)
    assert not v.allowed and "directory role" in v.reason and v.notes == (inscription.NO_PIM_LICENSE_NOTE,)
    monkeypatch.setattr("eregion_core.inscription.GraphEnrollment",
                        lambda: _reader(_answering(FakeGraph(), ELIGIBLE)))
    assert main(["user", USER]) == 0
    assert f"note — {inscription.NO_PIM_LICENSE_NOTE}" in capsys.readouterr().out


@pytest.mark.parametrize("status, body, said", [
    (400, {"error": {"code": "BadRequest"}}, "HTTP 400 BadRequest"),
    (400, {"error": {"code": "AADPREMIUMLICENSEREQUIRED"}}, "HTTP 400 AADPREMIUMLICENSEREQUIRED"),
    (403, NO_LICENSE, "HTTP 403 AadPremiumLicenseRequired"),
    (400, ValueError("no JSON"), "HTTP 400 reading"),
    (400, {}, "HTTP 400 reading"),
])
def test_any_other_answer_to_a_user_s_eligible_read_refuses_and_says_its_code(status, body, said):
    v = _reader(_answering(FakeGraph(), ELIGIBLE, status, body)).check_user(USER, kind="technique",
                                                                            destructive=False)
    assert not v.allowed and said in v.reason and v.notes == ()


@pytest.mark.parametrize("which", ["users/" + USER, "transitiveMemberOf", "ownedObjects", "appRoleAssignments",
                                   "roleAssignments", "administrativeUnits/" + UNIT, "members"])
def test_the_same_answer_to_another_of_a_user_s_reads_refuses(which):
    graph = FakeGraph()
    (url,) = [u for u in graph.routes if u.endswith("/" + which)]
    v = _reader(_answering(graph, url)).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "HTTP 400 AadPremiumLicenseRequired" in v.reason and v.notes == ()


def test_a_user_s_next_eligible_page_that_answers_so_refuses():
    nxt = f"{ELIGIBLE}?$skiptoken=2"
    graph = FakeGraph()
    graph.routes[ELIGIBLE] = {"value": [], "@odata.nextLink": nxt}
    _answering(graph, nxt)
    v = _reader(graph).check_user(USER, kind="technique", destructive=False)
    assert not v.allowed and "HTTP 400 AadPremiumLicenseRequired" in v.reason and v.notes == ()
