"""The items of an identity card's plan (IR1a): the ids a command may hold, the reads of Graph,
and the verbs on a credential, a principal, a user's sessions (entra_plan.py says what a plan is;
entra_grants.py, a consent and a role)."""
from __future__ import annotations

import re
import unicodedata

from glorfindel.providers.azure.graph import Unreadable

PLAN_VERSION = 1
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_GRAPH_ID = re.compile(r"[A-Za-z0-9_-]{1,200}")
_SCOPE_ID = re.compile(r"/(administrativeUnits/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?")
_WORDS = re.compile(r"[A-Za-z0-9._ -]{0,2000}")
_WHEN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?")
_KEY_ID = re.compile(r"KeyIdentifier=([0-9A-Fa-f-]{36})")
_KEY_TYPE = re.compile(r"KeyType=([A-Za-z0-9]+)")
_FIC_NAME = re.compile(r"""["']?Name["']?\s*[:=]\s*["']?([A-Za-z0-9._-]{1,120})""")
GRAPH_URL = "https://graph.microsoft.com/v1.0"
_GLORFINDEL = ("l'identité de Glorfindel, acteur ou cible : jamais un verbe de l'exécuteur — un "
               "attaquant ne doit pas pouvoir faire désactiver la watch par Eregion (§3.5)")
_NO_EXECUTOR = "pas d'exécuteur d'identité avant IR1c : chaque verbe se fait à la main"
_USER = "un utilisateur ne s'inscrit qu'avec IDI1b (§3.6) : jamais un verbe de l'exécuteur, une étape"
_ROLE = "retirer un rôle : jamais par Eregion (le droit permet de s'accorder des privilèges, §3.4)"
_CONSENT = ("retirer un consentement : jamais par Eregion (le droit permet de s'accorder des "
            "privilèges, §3.4)")


def guid(value) -> str:
    """`value` in lower case if it is an object id, else ""."""
    v = str(value or "").strip().lower()
    return v if _GUID.fullmatch(v) else ""


def graph_id(value) -> str:
    """A grant's or an assignment's id (not a GUID: Graph's own base64url), else ""."""
    v = str(value or "").strip()
    return v if _GRAPH_ID.fullmatch(v) else ""


def scope_id(value) -> str:
    v = str(value or "").strip()
    return v if _SCOPE_ID.fullmatch(v) else ""


def words(value) -> str:
    """A permission's words (`Mail.Read offline_access`), else "" — never a quote in a command."""
    v = str(value or "").strip()
    return v if _WORDS.fullmatch(v) else ""


# The names a directory role goes by: Global Administrator's former name, still read in some logs
# (entra.PRIVILEGED_ROLES keeps it) — on Graph, the new one. Lowercase.
ROLE_ALIASES = {"company administrator": "global administrator"}


def role_key(name) -> str:
    """A role's name as compared: lowercase, its alias folded."""
    n = str(name or "").strip().lower()
    return ROLE_ALIASES.get(n, n)


def when(value) -> str:
    v = str(value or "").strip()
    return v if _WHEN.fullmatch(v) else ""


# ── Reading Graph: what was read, and why not ──────────────────────────────────────────────

class _Unread:
    """A read that could not be made (sentinel), distinct from None (Graph: no such object)."""

    def __bool__(self):
        return False


UNREAD = _Unread()


# The plan is written in `decide`, on the queue of the card's anchor VM: its reads of Graph have one
# budget in all (a real detection on that VM waits behind it), and stop at the first delay or right
# missing — the next read would only wait or be refused the same way.
PLAN_BUDGET_S = 20.0


class _Reads:
    def __init__(self, reader, budget_s: float = PLAN_BUDGET_S):
        import time
        self.reader = reader
        self.why = ""
        self.done = 0
        self.stopped = False
        self._clock = time.monotonic
        self.deadline = self._clock() + budget_s

    def _call(self, how: str, path: str, params=None):
        if self.reader is None:
            self.why = self.why or "Graph non lu (aucun lecteur)"
            return UNREAD
        if self.stopped:
            return UNREAD
        if self._clock() >= self.deadline:
            self.stopped = True
            self.why = self.why or f"budget de lecture du plan dépassé ({PLAN_BUDGET_S:.0f} s)"
            return UNREAD
        try:
            out = getattr(self.reader, how)(path, params, deadline=self.deadline)
            self.done += 1
            return out
        except Unreadable as exc:
            self.why = self.why or str(exc)
            if exc.kind in ("delay", "right", "off"):
                self.stopped = True
            return UNREAD
        except Exception as exc:        # a reader's bug is said, never taken for an answer
            self.why = self.why or f"Graph : {type(exc).__name__}"
            return UNREAD

    def get(self, path, params=None):
        return self._call("get", path, params)

    def list(self, path, params=None):
        return self._call("list", path, params)


# ── Items ──────────────────────────────────────────────────────────────────────────────────

def _param(name: str, value: str, source: str, why: str = "") -> dict:
    if value:
        return {"name": name, "value": value, "from": source, "read": True, "note": why}
    return {"name": name, "value": "", "from": "", "read": False, "why": why or "non lu"}


def placeholder(name: str) -> str:
    """What a command holds in place of a parameter not read (C2b): `<id-de-l-octroi>` — it says
    what to replace, and stays inert pasted as it is: no space nor quote (a quote of « l'octroi »
    left the shell waiting); bare in a command, the shell refuses its `<`; between quotes (the body
    of an `adminRemove`, a `find` in double quotes), Graph refuses it (400) — never a call on an
    empty id (an empty one left `…/roleAssignments//…`). Never an id: a template."""
    slug = unicodedata.normalize("NFKD", str(name or "")).encode("ascii", "ignore").decode()
    return "<" + (re.sub(r"[^A-Za-z0-9]+", "-", slug).strip("-") or "valeur") + ">"


def _v(p: dict) -> str:
    return p["value"] if p["read"] else placeholder(p["name"])


def _item(what: str, *, verb: str = "", target: dict | None = None, params: list | None = None,
          command: str = "", before: str = "", side_effect: str = "", rollback: str = "",
          check: dict | None = None, optional: bool = False, by: str = "executor", why_human: str = "",
          find: str = "", verifiable: bool = False, unchecked: str = "") -> dict:
    """`verifiable`: what Verify reads afterwards, even when its check could not be written (a
    parameter not read: then « unreadable », never « held »). `unchecked`: a step of the
    remediation Graph cannot check, and why — counted in the verdict, always « unreadable »."""
    params = params or []
    return {"verb": verb, "by": by if verb else "human", "why_human": why_human, "what": what,
            "target": target or {}, "params": params, "command": command,
            "complete": bool(command) and all(p["read"] for p in params),
            "find": find, "before": before, "side_effect": side_effect, "rollback": rollback,
            "check": check, "verifiable": verifiable or check is not None or bool(unchecked),
            "unchecked": unchecked, "optional": optional}


def _target(kind: str, oid: str, name) -> dict:
    return {"type": kind, "id": oid, "name": str(name or "").strip()[:200]}


def _object_param(row_id, label: str) -> dict:
    oid = guid(row_id)
    if oid:
        return _param(label, oid, "log")
    return _param(label, "", "", "le journal ne donne pas d'identifiant d'objet (un GUID)"
                  if not str(row_id or "").strip() else "le journal donne ce qui n'est pas un identifiant d'objet")


def _user_actor(row: dict) -> str:
    """The actor's object id when the actor is a user (an application has an `ActorAppId`)."""
    if str(row.get("ActorAppId") or "").strip():
        return ""
    return guid(row.get("ActorId"))


def _revoke_sessions(user: str, after: str, who: str, *, optional: bool = False) -> dict:
    p = _param("id de l'utilisateur", user, "log")
    return _item(
        f"Révoquer les sessions de {who}" + (" — si l'auteur n'est pas attendu" if optional else ""),
        verb="entra_revoke_sessions", by="human", why_human=_USER, target=_target("user", user, who),
        params=[p],
        command=f"az rest --method POST --url {GRAPH_URL}/users/{_v(p)}/revokeSignInSessions",
        side_effect=("l'utilisateur se reconnecte partout, avec son MFA ; un jeton d'accès déjà émis "
                     "vit jusqu'à son expiration (60 à 90 min)"),
        rollback="aucun, rien à remettre : l'utilisateur se reconnecte",
        check={"kind": "sessions_revoked", "id": user, "after": after} if user else None,
        optional=optional, verifiable=True)


# ── A credential: added (C2's first rule), or used by an unusual sign-in ───────────────────

def _credential_type(added: str) -> str:
    kt = _KEY_TYPE.search(added or "")
    if kt:
        return "password" if kt.group(1).lower() == "password" else "certificate"
    if re.search(r"issuer|subject|audiences", added or "", re.IGNORECASE):
        return "federated"
    return ""


def _find_key(obj, key_id: str) -> str:
    """'password' or 'certificate' if `key_id` is on the object Graph returned, else ""."""
    if not isinstance(obj, dict):
        return ""
    for field, kind in (("passwordCredentials", "password"), ("keyCredentials", "certificate")):
        for c in obj.get(field) or []:
            if isinstance(c, dict) and guid(c.get("keyId")) == key_id:
                return kind
    return ""


def _candidates(obj) -> list[dict]:
    out = []
    if isinstance(obj, dict):
        for field, kind in (("passwordCredentials", "password"), ("keyCredentials", "certificate")):
            for c in obj.get(field) or []:
                if isinstance(c, dict) and guid(c.get("keyId")):
                    out.append({"keyId": guid(c.get("keyId")), "type": kind,
                                "name": str(c.get("displayName") or "")[:120],
                                "start": when(c.get("startDateTime"))})
    return out[:20]


def _remove_credential(coll: str, oid_p: dict, key_p: dict, ctype: str, name, *, fic_p: dict | None = None,
                       note: str = "") -> dict:
    """The verb `entra_remove_credential`, on an application or a service principal."""
    cli = "app" if coll == "applications" else "sp"
    oid = _v(oid_p)
    label = "l'application" if coll == "applications" else "le principal de service"
    target = _target("application" if coll == "applications" else "servicePrincipal", oid_p["value"], name)
    if ctype == "federated":
        fic = fic_p or _param("id de l'identifiant fédéré", "", "", "non lu")
        return _item(
            f"Retirer l'identifiant fédéré ajouté sur {label} {target['name'] or oid}" + note,
            verb="entra_remove_credential", target=target, params=[oid_p, fic],
            command=f"az ad app federated-credential delete --id {oid} --federated-credential-id {_v(fic)}",
            before=(f"garder sa définition : az ad app federated-credential show --id {oid} "
                    f"--federated-credential-id {_v(fic)} > fic-{_v(fic)}.json"),
            side_effect="un pipeline fédéré (une CI) qui s'en sert s'arrête",
            rollback=f"az ad app federated-credential create --id {oid} --parameters fic-{_v(fic)}.json",
            check=({"kind": "federated_gone", "id": oid_p["value"], "fic_id": fic["value"]}
                   if oid_p["read"] and fic["read"] else None),
            verifiable=True,
            find=f"az ad app federated-credential list --id {oid}" if not fic["read"] else "")
    cert = ctype == "certificate"
    secret = ctype == "password"
    what = ("le certificat" if cert else "le secret" if secret else "l'identifiant") + " ajouté"
    return _item(
        f"Retirer {what} sur {label} {target['name'] or oid}" + note,
        verb="entra_remove_credential", target=target, params=[oid_p, key_p],
        command=f"az ad {cli} credential delete --id {oid} --key-id {_v(key_p)}" + (" --cert" if cert else ""),
        before=(f"garder la partie publique : az rest --method GET --url \"{GRAPH_URL}/{coll}/{oid}"
                f"?\\$select=keyCredentials\" > keycredentials-{oid}.json" if cert else ""),
        side_effect=("si c'est l'identifiant d'un usage légitime (une rotation), l'application échoue à "
                     "son prochain jeton ; les autres identifiants restent"),
        rollback=(f"az ad {cli} credential reset --id {oid} --cert @<cert.pem> --append, la partie "
                  f"publique tirée de keycredentials-{oid}.json (hypothèse, à mesurer)" if cert
                  else "aucun : un secret retiré ne revient pas — le propriétaire en crée un autre "
                       f"(az ad {cli} credential reset --id {oid} --append) et le distribue" if secret
                  else "selon son type : un secret ne revient pas ; un certificat se remet par sa partie "
                       "publique gardée avant"),
        check=({"kind": "credential_gone", "collection": coll, "id": oid_p["value"], "key_id": key_p["value"]}
               if oid_p["read"] and key_p["read"] else None),
        verifiable=True,
        find=f"az ad {cli} credential list --id {oid}" + (" --cert" if cert else "") if not key_p["read"] else "")


def _credential_items(row: dict, reads: _Reads) -> list[dict]:
    ttype = str(row.get("TargetType") or "").strip().lower()
    coll = "servicePrincipals" if ttype == "serviceprincipal" else "applications"
    name = row.get("TargetName")
    oid_p = _object_param(row.get("TargetId"), "id de l'objet")
    added = str(row.get("CredentialAdded") or "")
    ctype = _credential_type(added)
    key = guid(m.group(1)) if (m := _KEY_ID.search(added)) else ""
    items: list[dict] = []
    note = ""
    obj = UNREAD
    if oid_p["read"]:
        obj = reads.get(f"/{coll}/{oid_p['value']}",
                        {"$select": "id,appId,displayName,passwordCredentials,keyCredentials"})
    if obj is None:
        note = " — l'objet n'existe plus dans Graph (supprimé ?)"
    if ctype == "federated":
        fic_p = _param("id de l'identifiant fédéré", "", "", "le journal ne le donne pas")
        fic_name = m.group(1) if (m := _FIC_NAME.search(added)) else ""
        if oid_p["read"] and coll == "applications" and fic_name:
            fics = reads.list(f"/applications/{oid_p['value']}/federatedIdentityCredentials")
            if isinstance(fics, list):
                hit = [guid(f.get("id")) for f in fics if str(f.get("name") or "") == fic_name and guid(f.get("id"))]
                fic_p = (_param("id de l'identifiant fédéré", hit[0], "graph") if len(hit) == 1 else
                         _param("id de l'identifiant fédéré", "", "", f"aucun identifiant fédéré « {fic_name} » "
                                "lu sur l'application (déjà retiré ?)"))
            else:
                fic_p = _param("id de l'identifiant fédéré", "", "", reads.why or "non lu")
        items.append(_remove_credential(coll, oid_p, {}, "federated", name, fic_p=fic_p, note=note))
    else:
        if not key:
            key_p = _param("keyId", "", "", "le journal ne nomme pas le keyId de l'identifiant ajouté")
        elif isinstance(obj, dict):
            on = _find_key(obj, key)
            ctype = on or ctype
            key_p = (_param("keyId", key, "graph") if on else
                     _param("keyId", key, "log", "absent de l'objet dans Graph : déjà retiré ?"))
        else:
            key_p = _param("keyId", key, "log", "" if obj is None else
                           f"non confirmé dans Graph : {reads.why or 'non lu'}")
        it = _remove_credential(coll, oid_p, key_p, ctype, name, note=note)
        if not key_p["read"] and isinstance(obj, dict):
            it["candidates"] = _candidates(obj)
        items.append(it)
    cli = "app" if coll == "applications" else "sp"
    items.append(_item(
        "Si l'auteur n'est pas attendu : renouveler les autres identifiants de l'objet (l'attaquant a pu "
        "en lire ou en ajouter d'autres)",
        command=f"az ad {cli} credential list --id {_v(oid_p)}", params=[oid_p], optional=True,
        side_effect="chaque identifiant renouvelé se redistribue à ses usages"))
    return items


def _signin_items(row: dict, reads: _Reads) -> list[dict]:
    sp_p = _object_param(row.get("ActorId"), "id du principal de service")
    name = row.get("ActorName")
    app_id = guid(row.get("ActorAppId"))
    used = guid(row.get("ServicePrincipalCredentialKeyId") or row.get("CredentialKeyId"))
    items: list[dict] = []
    sp = UNREAD
    if sp_p["read"]:
        sp = reads.get(f"/servicePrincipals/{sp_p['value']}",
                       {"$select": "id,appId,displayName,accountEnabled,passwordCredentials,keyCredentials"})
    if used:
        app = UNREAD
        if app_id:
            app = reads.get(f"/applications(appId='{app_id}')",
                            {"$select": "id,appId,displayName,passwordCredentials,keyCredentials"})
        on_app, on_sp = _find_key(app, used), _find_key(sp, used)
        key_p = _param("keyId", used, "log", "l'identifiant que la connexion a utilisé")
        if on_app and isinstance(app, dict):
            items.append(_remove_credential("applications", _param("id de l'objet", guid(app.get("id")), "graph"),
                                            {**key_p, "from": "graph"}, on_app, app.get("displayName") or name))
        elif on_sp:
            items.append(_remove_credential("servicePrincipals", sp_p, {**key_p, "from": "graph"}, on_sp, name))
        else:
            why = (reads.why or "non lu") if (app is UNREAD or sp is UNREAD) else \
                "ni l'application ni le principal ne portent ce keyId dans Graph (déjà retiré ?)"
            items.append(_remove_credential("applications", _param("id de l'objet", "", "", why), key_p, "",
                                            name))
    else:
        items.append(_disable_principal(sp_p, sp, name, "le principal de service"))
    items.append(_item(
        "Renouveler ses autres identifiants avec son propriétaire, si l'adresse n'est pas attendue",
        command=f"az ad sp credential list --id {_v(sp_p)}" + (f" ; az ad app credential list --id {app_id}"
                                                                if app_id else ""),
        params=[sp_p], optional=True, side_effect="chaque identifiant renouvelé se redistribue à ses usages"))
    return items


def _disable_principal(sp_p: dict, sp, name, label: str) -> dict:
    enabled = sp.get("accountEnabled") if isinstance(sp, dict) else None
    state = ("il est actif (lu dans Graph)" if enabled is True else
             "il est déjà désactivé (lu dans Graph) : rien à faire" if enabled is False else
             "son état n'est pas lu : ne le réactiver que s'il était actif avant")
    return _item(
        f"Bloquer la connexion de {label} {str(name or '').strip() or _v(sp_p)}, le temps de l'enquête",
        verb="entra_disable_principal", target=_target("servicePrincipal", sp_p["value"], name), params=[sp_p],
        command=f"az ad sp update --id {_v(sp_p)} --set accountEnabled=false",
        side_effect=("l'application s'arrête entièrement, pour tous ses utilisateurs et ses charges : "
                     "l'usage légitime s'arrête aussi — au propriétaire d'en décider"),
        rollback=f"az ad sp update --id {_v(sp_p)} --set accountEnabled=true — {state}",
        check={"kind": "disabled", "collection": "servicePrincipals", "id": sp_p["value"]} if sp_p["read"] else None, verifiable=True)
