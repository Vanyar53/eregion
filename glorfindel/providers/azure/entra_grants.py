"""The items of a plan on a consent and on a privileged role (IR1a, entra_plan.py): Eregion never
removes either (§3.4) — steps for a human, with their exact ids read on Graph, and their check."""
from __future__ import annotations

from glorfindel.providers.azure.entra_items import (
    GRAPH_URL, UNREAD, _CONSENT, _ROLE, _Reads, _disable_principal, _item, _object_param, _param,
    _revoke_sessions, _user_actor, _v, graph_id, guid, scope_id, when, words,
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
            "tout le tenant", why_human="la cliente n'est pas nommée par le journal"))
    else:
        cp = _param("id du principal de l'application cliente", client, "log")
        name = row.get("TargetName") if op == "consent to application" else ""
        sp = reads.get(f"/servicePrincipals/{client}",
                       {"$select": "id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType"})
        if isinstance(sp, dict):
            name = sp.get("displayName") or name
        items.append(_disable_principal(cp, sp, name, "l'application cliente"))
        items += _grant_items(client, reads)
    user = _user_actor(row)
    if user:
        items.append(_revoke_sessions(user, event_at, str(row.get("ActorName") or "qui a consenti")))
    return items


def _grant_items(client: str, reads: _Reads) -> list[dict]:
    grants = reads.list("/oauth2PermissionGrants", {"$filter": f"clientId eq '{client}'"})
    roles = reads.list(f"/servicePrincipals/{client}/appRoleAssignments")
    items: list[dict] = []
    if isinstance(grants, list) and isinstance(roles, list):
        for g in grants:
            gid, res = graph_id(g.get("id")), guid(g.get("resourceId"))
            if not gid:
                continue
            ctype = g.get("consentType") if g.get("consentType") in ("AllPrincipals", "Principal") else ""
            principal, scope = guid(g.get("principalId")), words(g.get("scope"))
            body = (f"{{\"clientId\":\"{client}\",\"consentType\":\"{ctype}\",\"principalId\":"
                    + (f"\"{principal}\"" if principal else "null")
                    + f",\"resourceId\":\"{res}\",\"scope\":\"{scope}\"}}")
            back = (f"az rest --method POST --url {GRAPH_URL}/oauth2PermissionGrants --body '{body}'"
                    if ctype and res and scope else "recréer l'octroi à l'identique (portée non reprise : "
                                                    "des caractères inattendus)")
            items.append(_item(
                f"Retirer l'octroi délégué ({scope or 'portée non reprise'}"
                + (", pour tout le tenant" if ctype == "AllPrincipals" else "") + ")",
                why_human=_CONSENT, params=[_param("id de l'octroi", gid, "graph")],
                command=f"az rest --method DELETE --url {GRAPH_URL}/oauth2PermissionGrants/{gid}",
                side_effect="une intégration légitime perd l'accès (courrier, fichiers, Graph) et s'arrête",
                rollback=back, check={"kind": "grant_gone", "client": client, "grant_id": gid}))
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
    matched = []
    if isinstance(found, list) and role_name:
        matched = [a for a in found
                   if str(((a.get("roleDefinition") or {}).get("displayName")) or "").lower() == role_name.lower()]
    check_by_name = ({"kind": "role_gone", "member": member, "role_name": role_name, "eligible": eligible}
                     if member and role_name else None)
    for a in matched:
        aid, rdef, scope = graph_id(a.get("id")), guid(a.get("roleDefinitionId")), scope_id(a.get("directoryScopeId"))
        if not (aid and rdef and scope):
            continue
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
            check={"kind": "role_gone", "member": member, "role_definition_id": rdef, "eligible": eligible}))
    if not items:
        why = ("aucune attribution de ce rôle lue sur le membre : déjà retirée ?" if isinstance(found, list) and role_name
               else "le journal ne nomme pas le rôle" if not role_name else reads.why or "non lu")
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
