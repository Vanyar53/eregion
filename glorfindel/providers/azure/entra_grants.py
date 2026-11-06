"""The items of a plan on a consent and on a privileged role (IR1a, entra_plan.py): Eregion never
removes either (§3.4) — steps for a human, with their exact ids read on Graph, and their check."""
from __future__ import annotations

from glorfindel.providers.azure.entra_items import (
    GRAPH_URL, UNREAD, _CONSENT, _ROLE, _Reads, _disable_principal, _item, _object_param, _param,
    _revoke_sessions, _user_actor, _v, graph_id, guid, role_key, scope_id, when, words,
)

# ── A consent ──────────────────────────────────────────────────────────────────────────────

def _consent_items(row: dict, reads: _Reads, event_at: str) -> list[dict]:
    op = str(row.get("EntraOperation") or "").strip().lower()
    # The client: the target of « Consent to application »; outside that flow the target is likely
    # the RESOURCE's principal (Microsoft Graph): the client then from modifiedProperties, or none.
    client = guid(row.get("TargetId")) if op == "consent to application" else guid(row.get("ClientId"))
    items: list[dict] = []
    if not client:
        items.append(_item(
            "Identifier l'application cliente (modifiedProperties de l'événement) avant tout blocage : la "
            "cible est sans doute le principal de la ressource (Microsoft Graph) — le désactiver couperait "
            "tout le tenant", why_human="la cliente n'est pas nommée par le journal",
            unchecked="Graph ne peut pas le vérifier : l'application cliente n'est pas nommée, son octroi peut tenir encore"))
    else:
        cp = _param("id du principal de l'application cliente", client, "log")
        name = row.get("TargetName") if op == "consent to application" else ""
        sp = reads.get(f"/servicePrincipals/{client}",
                       {"$select": "id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType"})
        if isinstance(sp, dict):
            name = sp.get("displayName") or name
        items.append(_disable_principal(cp, sp, name, "l'application cliente"))
        items += _grant_items(client, reads, row)
    user = _user_actor(row)
    if user:
        items.append(_revoke_sessions(user, event_at, str(row.get("ActorName") or "qui a consenti")))
    return items


def _grant_item(client: str, gid_p: dict, res: str, ctype, principal: str, scope: str) -> dict:
    """Remove one delegated grant: its id read on Graph, or given by the log (C2b)."""
    ctype = ctype if ctype in ("AllPrincipals", "Principal") else ""
    gid = gid_p["value"]
    body = (f"{{\"clientId\":\"{client}\",\"consentType\":\"{ctype}\",\"principalId\":"
            + (f"\"{principal}\"" if principal else "null")
            + f",\"resourceId\":\"{res}\",\"scope\":\"{scope}\"}}")
    back = (f"az rest --method POST --url {GRAPH_URL}/oauth2PermissionGrants --body '{body}'"
            if ctype and res and scope else "recréer l'octroi à l'identique (portée non reprise : "
                                            "des caractères inattendus)")
    return _item(
        f"Retirer l'octroi délégué ({scope or 'portée non reprise'}"
        + (", pour tout le tenant" if ctype == "AllPrincipals" else "") + ")",
        why_human=_CONSENT, params=[gid_p],
        command=f"az rest --method DELETE --url {GRAPH_URL}/oauth2PermissionGrants/{gid}",
        side_effect="une intégration légitime perd l'accès (courrier, fichiers, Graph) et s'arrête",
        rollback=back, check={"kind": "grant_gone", "client": client, "grant_id": gid})


def _logged_items(client: str, reads: _Reads, row: dict) -> list[dict]:
    """Graph not read (C2b): what the row itself names — the grants a « Consent to application »
    added (ConsentAction.Permissions: their ids, resource, type, scope), the resource of an app
    role assignment (its target). Never a value that is no id: `entra_consent.parse` keeps ids."""
    from glorfindel.providers.azure import entra_consent
    why = f"lu dans le journal, non confirmé dans Graph : {reads.why or 'non lu'}"
    items = [_grant_item(client, _param("id de l'octroi", g["id"], "log", why), g["resource"],
                         g["consent_type"], g["principal"], g["scope"])
             for g in entra_consent.parse(row.get("Permissions"))["grants"]
             if g["id"] and g["client"] in ("", client)]
    if items:   # the delegated grants only: the same consent may have assigned application permissions
        items.append(_item(
            "Revoir aussi les permissions d'application de l'application cliente (le journal de ce "
            "consentement ne nomme que ses octrois délégués)",
            find=f"az rest --method GET --url {GRAPH_URL}/servicePrincipals/{client}/appRoleAssignments"))
    op = str(row.get("EntraOperation") or "").strip().lower()
    res = guid(row.get("TargetId")) if op == "add app role assignment to service principal" else ""
    if res:
        aid_p = _param("id de l'attribution", "", "", "le journal ne le donne pas ; " + (reads.why or "non lu"))
        role = words(row.get("Permissions"))
        items.append(_item(
            "Retirer la permission d'application attribuée" + (f" ({role})" if role else ""),
            why_human=_CONSENT, params=[aid_p, _param("id du principal de la ressource", res, "log")],
            command=f"az rest --method DELETE --url {GRAPH_URL}/servicePrincipals/{res}/appRoleAssignedTo/{_v(aid_p)}",
            find=f"az rest --method GET --url {GRAPH_URL}/servicePrincipals/{client}/appRoleAssignments",
            side_effect="une intégration légitime perd la permission et s'arrête",
            rollback="recréer l'attribution à l'identique : lire ses champs avant de la retirer",
            check={"kind": "consent_gone", "client": client}))
    return items


def _grant_items(client: str, reads: _Reads, row: dict | None = None) -> list[dict]:
    grants = reads.list("/oauth2PermissionGrants", {"$filter": f"clientId eq '{client}'"})
    roles = reads.list(f"/servicePrincipals/{client}/appRoleAssignments")
    items: list[dict] = []
    if isinstance(grants, list) and isinstance(roles, list):
        for g in grants:
            gid, res = graph_id(g.get("id")), guid(g.get("resourceId"))
            if not gid:
                continue
            items.append(_grant_item(client, _param("id de l'octroi", gid, "graph"), res, g.get("consentType"),
                                     guid(g.get("principalId")), words(g.get("scope"))))
        for a in roles:
            aid, res, role = graph_id(a.get("id")), guid(a.get("resourceId")), guid(a.get("appRoleId"))
            if not (aid and res):
                continue
            items.append(_item(
                "Retirer la permission d'application attribuée (un rôle d'application)",
                why_human=_CONSENT, params=[_param("id de l'attribution", aid, "graph"),
                                            _param("id du principal de la ressource", res, "graph")],
                command=f"az rest --method DELETE --url {GRAPH_URL}/servicePrincipals/{res}/appRoleAssignedTo/{aid}",
                side_effect="une intégration légitime perd la permission et s'arrête",
                rollback=(f"az rest --method POST --url {GRAPH_URL}/servicePrincipals/{res}/appRoleAssignedTo "
                          f"--body '{{\"principalId\":\"{client}\",\"resourceId\":\"{res}\",\"appRoleId\":\"{role}\"}}'"
                          if role else "recréer l'attribution à l'identique (rôle d'application non lu)"),
                check={"kind": "assignment_gone", "client": client, "assignment_id": aid}))
        if not items:
            items.append(_item("Aucun octroi ni attribution lu pour l'application cliente : déjà retirés ?",
                               why_human=_CONSENT, check={"kind": "consent_gone", "client": client}))
        return items
    logged = _logged_items(client, reads, row or {})
    if logged:
        return logged
    unread = _param("id de l'octroi", "", "", reads.why or "non lu")
    items.append(_item(
        "Retirer l'octroi délégué ou la permission d'application",
        why_human=_CONSENT, params=[unread],
        command=f"az rest --method DELETE --url {GRAPH_URL}/oauth2PermissionGrants/{_v(unread)}",
        find=(f"az ad app permission list-grants --id {client} ; az rest --method GET --url "
              f"{GRAPH_URL}/servicePrincipals/{client}/appRoleAssignments"),
        side_effect="une intégration légitime perd l'accès et s'arrête",
        rollback="recréer l'octroi à l'identique : lire ses champs avant de le retirer",
        check={"kind": "consent_gone", "client": client}))
    return items


# ── A privileged role ──────────────────────────────────────────────────────────────────────

def _role_items(row: dict, reads: _Reads, event_at: str) -> list[dict]:
    member_p = _object_param(row.get("TargetId"), "id du membre")
    member = member_p["value"]
    mtype = str(row.get("TargetType") or "").strip()
    role_name = str(row.get("RoleName") or "").strip()
    eligible = "eligible" in str(row.get("EntraOperation") or "").lower()
    coll = "roleEligibilitySchedules" if eligible else "roleAssignments"
    items: list[dict] = []
    found = UNREAD
    if member:
        found = reads.list(f"/roleManagement/directory/{coll}",
                           {"$filter": f"principalId eq '{member}'", "$expand": "roleDefinition"})
    # Matched by the role's name, its aliases folded (« Company Administrator » is Global Administrator's
    # former name: C2 keeps it, Graph says the new one); an assignment whose role's name is not read
    # (roleDefinition not expanded, no displayName) is never taken for another role — a candidate.
    matched, candidates = [], []
    for a in found if isinstance(found, list) else []:
        if not isinstance(a, dict):
            continue
        rd = a.get("roleDefinition") if isinstance(a.get("roleDefinition"), dict) else {}
        if role_name and rd.get("displayName") and role_key(rd.get("displayName")) == role_key(role_name):
            matched.append(a)
        else:
            candidates.append({"id": graph_id(a.get("id")), "roleDefinitionId": guid(a.get("roleDefinitionId")),
                               "name": str(rd.get("displayName") or "")[:120]})
    check_by_name = ({"kind": "role_gone", "member": member, "role_name": role_name, "eligible": eligible}
                     if member and role_name else None)
    for a in matched:
        aid, rdef, scope = graph_id(a.get("id")), guid(a.get("roleDefinitionId")), scope_id(a.get("directoryScopeId"))
        if not (aid and rdef and scope):
            candidates.append({"id": aid, "roleDefinitionId": rdef, "name": role_name[:120]})
            continue
        rd = a.get("roleDefinition") if isinstance(a.get("roleDefinition"), dict) else {}
        triple = f"\"principalId\":\"{member}\",\"roleDefinitionId\":\"{rdef}\",\"directoryScopeId\":\"{scope}\""
        if eligible:
            end = when((((a.get("scheduleInfo") or {}).get("expiration")) or {}).get("endDateTime"))
            exp = (f"{{\"type\":\"afterDateTime\",\"endDateTime\":\"{end}\"}}" if end else "{\"type\":\"noExpiration\"}")
            command = (f"az rest --method POST --url {GRAPH_URL}/roleManagement/directory/roleEligibilityScheduleRequests "
                       f"--body '{{\"action\":\"adminRemove\",{triple},\"justification\":\"Eregion IR1a\"}}'")
            back = (f"az rest --method POST --url {GRAPH_URL}/roleManagement/directory/roleEligibilityScheduleRequests "
                    f"--body '{{\"action\":\"adminAssign\",{triple},\"scheduleInfo\":{{\"expiration\":{exp}}},"
                    "\"justification\":\"Eregion IR1a\"}'")
        else:
            command = f"az rest --method DELETE --url {GRAPH_URL}/roleManagement/directory/roleAssignments/{aid}"
            back = (f"az rest --method POST --url {GRAPH_URL}/roleManagement/directory/roleAssignments "
                    f"--body '{{{triple}}}'")
        items.append(_item(
            f"Retirer l'attribution {'éligible ' if eligible else ''}du rôle « {role_name} »",
            why_human=_ROLE, params=[_param("id de l'attribution", aid, "graph"),
                                     _param("id de la définition du rôle", rdef, "graph")],
            command=command, side_effect="un administrateur légitime ou un pipeline perd le rôle : ses écritures "
                                         "suivantes échouent en 403",
            rollback=back + " (la même attribution, un nouvel id)",
            check={"kind": "role_gone", "member": member, "role_definition_id": rdef,
                   "template_id": guid(rd.get("templateId")), "role_name": role_name, "eligible": eligible}))
    if not items:
        why = ("le journal ne nomme pas le rôle" if not role_name
               else reads.why or "non lu" if not isinstance(found, list)
               else f"le membre tient {len(candidates)} attribution(s), aucune lue sous le nom « {role_name} » : "
                    "à choisir parmi les candidates, à la main" if candidates
               else "aucune attribution sur le membre : déjà retirée ?")
        aid_p = _param("id de l'attribution", "", "", why)
        items.append(_item(
            f"Retirer l'attribution {'éligible ' if eligible else ''}du rôle « {role_name or 'non lu'} »",
            why_human=_ROLE, params=[aid_p] + ([] if member_p["read"] else [member_p]),
            command=f"az rest --method DELETE --url {GRAPH_URL}/roleManagement/directory/roleAssignments/{_v(aid_p)}",
            find=(f"az rest --method GET --url \"{GRAPH_URL}/roleManagement/directory/{coll}"
                  f"?\\$filter=principalId%20eq%20'{_v(member_p)}'&\\$expand=roleDefinition\""),
            side_effect="un administrateur légitime ou un pipeline perd le rôle",
            rollback="recréer l'attribution avec le même rôle, le même membre, la même portée",
            check=check_by_name, verifiable=True))
        if eligible:      # an eligibility is no assignment: a schedule request removes it, never a DELETE (C2b)
            rdef_p = _param("id de la définition du rôle", "", "", why)
            scope_p = _param("portée du rôle", "", "", why)
            items[-1].update(
                params=[rdef_p, scope_p] + ([] if member_p["read"] else [member_p]), complete=False,
                command=(f"az rest --method POST --url {GRAPH_URL}/roleManagement/directory/roleEligibilityScheduleRequests "
                         f"--body '{{\"action\":\"adminRemove\",\"principalId\":\"{_v(member_p)}\",\"roleDefinitionId\":"
                         f"\"{_v(rdef_p)}\",\"directoryScopeId\":\"{_v(scope_p)}\",\"justification\":\"Eregion IR1a\"}}'"))
        if candidates:
            items[-1]["candidates"] = candidates[:20]
    if mtype.lower() == "user" and member:
        items.append(_revoke_sessions(member, event_at, str(row.get("TargetName") or "le membre ajouté")))
    author = _user_actor(row)
    if author:
        items.append(_revoke_sessions(author, event_at, str(row.get("ActorName") or "l'auteur"), optional=True))
    items.append(_item(
        "Revoir ce que le nouveau membre a fait depuis (AuditLogs, InitiatedBy)",
        find=(f"AuditLogs | where InitiatedBy has \"{member}\" | where TimeGenerated > datetime({event_at})"
              if member and event_at else "")))
    return items
