"""Entra ID as a detection source (C2): its audit and sign-in logs, read from the same Log
Analytics workspace as Perf, Syslog and AzureActivity. Detection only.

A row says who (`ActorName`, `ActorId`, `ActorAppId`, `ActorIp`) did what (`EntraOperation`)
to which identity (`TargetName`, `TargetId`, `TargetType`). The RulePoller gives each one its
card; `decide` builds the decision by code, without the model (`_identity_decision`,
glorfindel/agent.py): an escalation `identity_change`, its steps (who, what, how to revoke),
no action — never an autonomous one on an identity (`revoke_service_principal` does not
exist).

The columns a shipped rule projects (glorfindel/rules/azure/detection_rules.yaml), whatever
the table it reads:
  - `EntraKind`: `credential` (T1098.001), `consent` (T1528), `role` (T1098.003),
    `signin` (an unusual sign-in of a service principal);
  - `EventId`: what makes the finding one across polls (its CorrelationId and target; for a
    sign-in, the service principal and the address) — the RulePoller's dedup;
  - `Result`, `RoleName`, `Permissions`, `AdminConsent`, `CredentialAdded`, `Location`,
    `SignIns`, `BaselineSignIns`, `BaselineDays`: what the thresholds and the card read.

What this adapter does before the rows leave it — the thresholds a rule's query cannot hold
alone, in code, so they are tested on fake logs:
  - a failed operation is not a finding (`Result` other than success);
  - a role is a finding only when it is privileged (`PRIVILEGED_ROLES`; a role whose name
    the row does not give is kept: never silenced for want of a column);
  - a sign-in is unusual only for a service principal with a history: seen on at least
    `MIN_BASELINE_DAYS` days of the baseline (the query: 14 days, the last hour left out),
    and from an address never seen in it — a new service principal, or the first days
    after the diagnostic setting, would otherwise flood.
And the marks, never a drop: `GlorfindelIdentity` (Glorfindel's identity is the actor —
it never writes in Entra ID, and its sign-in from a new address is its credential used
elsewhere), `GlorfindelManaged` (the target is Glorfindel's identity — a credential added
there gives its rights to someone else). Both critical. **No row is dropped under
Glorfindel's identity**: unlike the Activity Log (AL1), Glorfindel makes no write here; its
usual sign-ins are left out by the baseline, as anyone's. Its identity is read as AL1 reads
it (its token, AZURE_CLIENT_ID, GLORFINDEL_OWN_CALLERS); its application's object id, the
target of a credential added to its registration, is not in its token: add it to
GLORFINDEL_OWN_CALLERS.

Entra's logs reach the workspace only through a diagnostic setting of the TENANT (not of the
subscription): AuditLogs, ServicePrincipalSignInLogs — infra/terraform/entra_logs.tf proposes
it, disabled. Hypotheses to measure on the bench: the tables and columns, the latency (minutes,
sometimes more), and the licence (sign-in logs in a workspace: Entra ID P1 or P2).
"""
from __future__ import annotations

import logging

from glorfindel.providers.azure.activity import AzureActivityDetector
from glorfindel.providers.azure.monitor import AzureMonitorDetector

logger = logging.getLogger("glorfindel.providers.azure.entra")

# A rule on Entra's logs whose window is shorter than this misses the rows that arrive late.
MIN_LOOKBACK_S = 1800.0
# A service principal's sign-in from a new address is unusual only if it has a history: seen
# on at least this many days of the baseline.
MIN_BASELINE_DAYS = 3
# The directory roles Entra ID marks privileged (its documentation, « privileged roles »),
# by display name — the same in every tenant. Lowercase.
PRIVILEGED_ROLES = frozenset(r.lower() for r in (
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Application Administrator",
    "Cloud Application Administrator", "Application Developer", "Authentication Administrator",
    "Authentication Extensibility Administrator", "B2C IEF Keyset Administrator",
    "Cloud Device Administrator", "Conditional Access Administrator",
    "Directory Synchronization Accounts", "Directory Writers", "Domain Name Administrator",
    "External Identity Provider Administrator", "Global Reader", "Helpdesk Administrator",
    "Hybrid Identity Administrator", "Intune Administrator",
    "Lifecycle Workflows Administrator", "Password Administrator", "Security Administrator",
    "Security Operator", "Security Reader", "User Administrator",
    "Partner Tier1 Support", "Partner Tier2 Support",
))
KINDS = ("credential", "consent", "role", "signin")
# Entra's tables: a rule of another source that reads one is said at load (no threshold,
# no mark) — its rows are still decided by the code (the row's columns say so).
ENTRA_TABLES = ("auditlogs", "signinlogs", "aadserviceprincipalsigninlogs",
                "aadnoninteractiveusersigninlogs", "aadmanagedidentitysigninlogs")
# Columns that only an Entra row carries (raw or projected): the guard of `decide` reads them
# when the signal says neither its plane nor its source.
IDENTITY_COLUMNS = ("EntraOperation", "EntraKind", "InitiatedBy", "TargetResources",
                    "ServicePrincipalId")


def _ids(row: dict, *cols: str) -> set[str]:
    return {str(row[c]).strip().lower() for c in cols if row.get(c)} - {""}


def actor_ids(row: dict) -> set[str]:
    return _ids(row, "ActorId", "ActorAppId", "ActorName")


def target_ids(row: dict) -> set[str]:
    return _ids(row, "TargetId", "TargetAppId")


def _succeeded(row: dict) -> bool:
    result = str(row.get("Result") or "").strip().lower()
    return result in ("", "success", "0")


def _number(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def above_threshold(row: dict) -> bool:
    """The thresholds of the shipped rules, in code (see the module's docstring)."""
    if not _succeeded(row):
        return False
    kind = str(row.get("EntraKind") or "").strip().lower()
    if kind == "role":
        role = str(row.get("RoleName") or "").strip().lower()
        return not role or role in PRIVILEGED_ROLES
    if kind == "signin":
        days = _number(row.get("BaselineDays"))
        return days is None or days >= MIN_BASELINE_DAYS
    return True


def prepare_rows(rows: list[dict], own: set[str]) -> list[dict]:
    """Keep the findings; mark each one. Nothing is dropped for being Glorfindel's."""
    out = []
    for row in rows:
        if not above_threshold(row):
            continue
        out.append({**row,
                    "GlorfindelIdentity": bool(own) and bool(actor_ids(row) & own),
                    "GlorfindelManaged": bool(own) and bool(target_ids(row) & own)})
    return out


# ── What a card says (read by `_identity_decision`, glorfindel/agent.py) ──────────────────

def _target(row: dict) -> str:
    name, tid, kind = (str(row.get(c) or "").strip() for c in ("TargetName", "TargetId", "TargetType"))
    label = f"{kind} " if kind else ""
    if name and tid and name != tid:
        return f"{label}{name} ({tid})"
    return f"{label}{name or tid or '?'}"


def _actor(row: dict) -> str:
    who = str(row.get("ActorName") or row.get("ActorId") or row.get("ActorAppId") or "").strip()
    where = str(row.get("ActorIp") or "").strip()
    return (who or "acteur inconnu") + (f" depuis {where}" if where else "")


def _ref(row: dict) -> str:
    corr = str(row.get("CorrelationId") or "").strip()
    return f" (CorrelationId {corr})" if corr else ""


def describe(row: dict) -> tuple[str, list[str]]:
    """What an identity detection says, from its row alone, and the steps for a human:
    who, what, how to revoke. Never an action: the steps are commands for a human."""
    kind = str(row.get("EntraKind") or "").strip().lower()
    op = str(row.get("EntraOperation") or row.get("OperationName") or "?").strip()
    target, actor = _target(row), _actor(row)
    tid = str(row.get("TargetId") or "<id>").strip() or "<id>"
    steps: list[str] = []
    if kind == "credential":
        added = str(row.get("CredentialAdded") or "").strip()
        what = (f"Entra ID : identifiant ajouté ({op}) par {actor} sur {target}."
                + (f" Identifiant : {added}." if added else ""))
        steps += [
            f"Vérifier avec {actor.split(' depuis ')[0]} ou le propriétaire de l'application que "
            f"cet ajout est voulu{_ref(row)}.",
            f"Lister les identifiants : `az ad app credential list --id {tid}` (application) ou "
            f"`az ad sp credential list --id {tid}` (principal de service).",
            f"Non voulu : retirer l'identifiant — `az ad app credential delete --id {tid} "
            f"--key-id <keyId>` (ou `az ad sp credential delete`), le keyId dans l'identifiant "
            "ajouté ci-dessus ; puis revoir les connexions du principal depuis l'ajout "
            "(AADServicePrincipalSignInLogs).",
        ]
    elif kind == "consent":
        perms = str(row.get("Permissions") or "").strip()
        admin = str(row.get("AdminConsent") or "").strip().lower() in ("true", "1")
        what = (f"Entra ID : consentement accordé ({op}) par {actor} à {target}"
                + (" — consentement d'administrateur, pour tout le tenant" if admin else "")
                + (f". Permissions : {perms}" if perms else "") + ".")
        steps += [
            f"Vérifier que l'application et ses permissions sont attendues{_ref(row)} "
            "(portail Entra : Applications d'entreprise → l'application → Autorisations).",
            "Non voulu : révoquer l'octroi — délégué : `az rest --method DELETE --url "
            "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/<id>` ; d'application : "
            "`az rest --method DELETE --url https://graph.microsoft.com/v1.0/servicePrincipals/"
            "<id>/appRoleAssignedTo/<id>`.",
            f"Bloquer la connexion de l'application le temps de l'enquête : `az ad sp update --id "
            f"{tid} --set accountEnabled=false` ; révoquer les sessions de qui a consenti "
            "(`az rest --method POST --url https://graph.microsoft.com/v1.0/users/<id>/"
            "revokeSignInSessions`) — un jeton déjà émis vit jusqu'à son expiration.",
        ]
    elif kind == "role":
        role = str(row.get("RoleName") or "").strip() or "rôle non lu"
        what = (f"Entra ID : rôle d'annuaire privilégié « {role} » attribué ({op}) par {actor} "
                f"à {target}.")
        steps += [
            f"Vérifier que cette attribution est voulue{_ref(row)} (portail Entra : Rôles et "
            "administrateurs → le rôle → Attributions).",
            "Non voulue : retirer l'attribution — portail, ou `az rest --method DELETE --url "
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/<id>`.",
            "Revoir ce que le nouveau membre a fait depuis (AuditLogs, InitiatedBy) et, si "
            "l'auteur n'est pas attendu, révoquer ses sessions (revokeSignInSessions).",
        ]
    elif kind == "signin":
        loc = str(row.get("Location") or "").strip()
        days, count = row.get("BaselineDays"), row.get("SignIns")
        what = (f"Entra ID : connexion inhabituelle du principal de service {actor}"
                + (f" ({loc})" if loc else "") + " : adresse jamais vue dans sa base"
                + (f" ({days} jours d'historique)" if days not in (None, "") else "")
                + (f", {count} connexion(s)" if count not in (None, "") else "")
                + (f", vers {row['TargetName']}" if row.get("TargetName") else "") + ".")
        steps += [
            f"Vérifier avec le propriétaire du principal que cette adresse est attendue{_ref(row)} "
            "(un nouveau runner, une nouvelle région).",
            f"Non attendue : retirer ses identifiants (`az ad sp credential list --id "
            f"{str(row.get('ActorId') or '<id>')}`, puis `az ad sp credential delete`) et, le "
            "temps de l'enquête, bloquer sa connexion (`az ad sp update --set "
            "accountEnabled=false`) — l'usage légitime s'arrête aussi : au propriétaire d'en "
            "décider.",
        ]
    else:
        what = f"Entra ID : {op} par {actor} sur {target}."
        steps.append(f"Vérifier dans les journaux d'Entra ID qui a fait cette opération{_ref(row)}.")
    if row.get("GlorfindelIdentity") is True:
        what += (" L'acteur est l'identité de Glorfindel : il n'écrit rien dans Entra ID, et "
                 "une connexion depuis une adresse nouvelle est son identifiant utilisé "
                 "ailleurs — ses identifiants sont peut-être entre d'autres mains.")
        steps.append("Renouveler les identifiants de Glorfindel, puis revoir ce qu'ils ont fait.")
    if row.get("GlorfindelManaged") is True:
        what += (" La cible est l'identité de Glorfindel : un identifiant ou un rôle ajouté là "
                 "donne ses droits (isoler, bloquer) à quelqu'un d'autre.")
        steps.append("Vérifier les identifiants et les rôles de l'identité de Glorfindel.")
    omitted = row.get("OmittedOperations") or []
    if omitted:
        listed = "; ".join(
            f"{o.get('EntraOperation') or '?'} par {o.get('ActorName') or '?'} sur "
            f"{o.get('TargetName') or o.get('TargetId') or '?'} ({str(o.get('TimeGenerated') or '')[:19]})"
            for o in omitted)
        what = (f"Entra ID : {len(omitted)} opération(s) de plus dans le même relevé, au-delà "
                f"des cartes individuelles — chacune listée ici : {listed}.")
        if any(o.get("GlorfindelManaged") for o in omitted):
            what += " Au moins une vise l'identité de Glorfindel."
        if any(o.get("GlorfindelIdentity") for o in omitted):
            what += " Au moins une est faite sous l'identité de Glorfindel."
    steps.append("Légitime (un pipeline connu) : l'exclure dans la couche du client. Glorfindel "
                 "n'agit jamais seul sur une identité (détection seule).")
    return what, steps


class AzureEntraDetector(AzureActivityDetector):
    """Entra ID's audit and sign-in logs, in the Log Analytics workspace. Glorfindel's
    identity is read as the Activity Log's detector reads it (`own_identities`)."""

    plane = "identity"
    backend_type = "azure_monitor"   # same workspace as Perf / Syslog / AzureActivity
    min_lookback_s = MIN_LOOKBACK_S

    def run_query(self, query: str, timespan=None) -> list[dict]:
        rows = AzureMonitorDetector.run_query(self, query, timespan=timespan)
        return prepare_rows(rows, self.own_identities())

    def poll_alert(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        own = self.own_identities()

        def keep(row):
            return above_threshold(row) and (match_row is None or match_row(row))

        result = AzureMonitorDetector.poll_alert(self, query, since, timeout_s, interval_s=interval_s,
                                                 verbose=verbose, match_row=keep)
        if result is None:
            return None
        elapsed, row = result
        return elapsed, prepare_rows([row], own)[0]
