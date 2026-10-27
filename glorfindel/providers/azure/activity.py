"""Azure's control plane as a detection source (AL1): the Activity Log (`AzureActivity`),
read from the same Log Analytics workspace as Perf and Syslog.

Detection only. A row of `AzureActivity` says who (`Caller`, `CallerIpAddress`) did what
(`OperationNameValue`) to which resource (`_ResourceId`). The RulePoller dispatches it
like any detection; `decide` builds its decision by code, without the model
(`_control_plane_decision`, glorfindel/agent.py): escalated, explained, to a human, with
no action — never an autonomous one.

Two things only this adapter knows, so it does them before the rows leave it:
  - Glorfindel's own writes. Its isolations, quarantines, blocks and releases show in
    the Activity Log under its own identity. A row is dropped only when all three hold:
    its caller is Glorfindel, its operation is one its capabilities declare
    (capabilities.py: the rights of each response), and its TARGET is Glorfindel's — a
    `glorfindel-*` rule, a quarantine NSG, or what an isolation state records as its own
    on a customer's resource (a rule whose priority it moved, `bumped`, that its release
    puts back; a NIC it put in quarantine). Else each isolation escalates itself. Its
    identity is read, never written in code: the claims of its credential's token,
    `AZURE_CLIENT_ID`, and `GLORFINDEL_OWN_CALLERS` (comma separated). From an
    application's token (a service principal, a managed identity) its `appid`/`azp` and
    `oid`; from a user's (`az login`), its `oid` only — there `appid` names the client
    application (the Azure CLI, the same for the whole tenant), and comparing it would
    drop everyone's `az` writes (said once). The same identity doing anything else — a
    role assignment, a snapshot, `listKeys`, a write on a customer's rule — is kept and
    marked `GlorfindelIdentity` (critical): its credential may be in other hands.
  - Glorfindel's own rules. A write by anyone else on a rule or an NSG Glorfindel manages
    (`glorfindel-*` rules, its quarantine NSGs) is the gravest case — an isolation or a
    block may have been lifted. The row is marked `GlorfindelManaged`.

`AzureActivity` reaches the workspace only through a diagnostic setting of the
subscription (category Administrative) — not by default. Without it the table is empty:
the rules match nothing (infra/terraform/activity_log.tf proposes the setting for the
bench). Its ingestion is late — minutes, sometimes more than ten: a rule on it looks back
`ago(1h)` or more (MIN_LOOKBACK_S, said at load otherwise).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
import time

from glorfindel.providers.azure.capabilities import CAPABILITIES
from glorfindel.providers.azure.monitor import AzureMonitorDetector
from glorfindel.providers.azure.quarantine import QUARANTINE_NSG_PREFIX

logger = logging.getLogger("glorfindel.providers.azure.activity")

# A control-plane rule whose window is shorter than this misses the rows that arrive late.
MIN_LOOKBACK_S = 1800.0
# How long a customer resource an isolation state recorded as Glorfindel's stays its own
# after the state is gone (a release's write lands in the log minutes later): longer than
# the shipped rules' window (1 h) and its margin. A restart forgets: that write escalates.
RECORDED_TTL_S = 7200.0

# The columns AzureActivity names its caller in. `CallerAppId` / `CallerObjectId` are what
# the shipped rules extract from `Claims` (a service principal's `Caller` is one of its ids,
# depending on the token: both are compared).
_CALLER_COLUMNS = ("Caller", "CallerAppId", "CallerObjectId")
_OID_CLAIMS = ("oid", "http://schemas.microsoft.com/identity/claims/objectidentifier")
# The client application of a token: for an application's token, the application itself;
# for a user's, the tool the user signed in with (the Azure CLI, the portal) — never theirs.
_APP_CLAIMS = ("appid", "azp")
_CLAIM_KEYS = (
    *_APP_CLAIMS, *_OID_CLAIMS, "upn", "unique_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
)
_RULE_ID_RE = re.compile(
    r"/resourcegroups/([^/]+)/providers/microsoft\.network/networksecuritygroups/([^/]+)"
    r"/securityrules/([^/]+)$")
_TOKEN_SCOPE = "https://management.azure.com/.default"


def own_operations() -> frozenset[str]:
    """The operations Glorfindel makes on Azure (lowercase): the rights its capabilities
    declare — one list, the one the readiness check reads."""
    return frozenset(r.lower() for c in CAPABILITIES.capabilities for r in c.rights)


def _claims(row: dict) -> dict:
    raw = row.get("Claims_d") or row.get("Claims")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def caller_ids(row: dict) -> set[str]:
    """Every id the row gives for its caller, lowercase."""
    ids = {str(row[c]).strip().lower() for c in _CALLER_COLUMNS if row.get(c)}
    claims = _claims(row)
    ids |= {str(claims[k]).strip().lower() for k in _CLAIM_KEYS if claims.get(k)}
    return ids - {""}


def operation(row: dict) -> str:
    return str(row.get("OperationNameValue") or row.get("OperationName") or "").strip().lower()


def target_resource(row: dict) -> str:
    return str(row.get("_ResourceId") or row.get("ResourceId") or "").strip()


def glorfindel_managed(row: dict) -> bool:
    """The row's target is a rule or an NSG Glorfindel writes: a `glorfindel-*` security
    rule (isolation, block, quarantine content), or one of its quarantine NSGs."""
    rid = target_resource(row).lower()
    if "/securityrules/glorfindel-" in rid:
        return True
    marker = "/networksecuritygroups/"
    if marker in rid:
        nsg = rid.split(marker, 1)[1].split("/", 1)[0]
        return nsg.startswith(QUARANTINE_NSG_PREFIX)
    return False


def recorded_targets() -> frozenset[str]:
    """What the isolation states record as Glorfindel's on a customer's resources,
    lowercase: each customer rule whose priority an isolation moved (`bumped`, put back by
    its release — providers/azure/network.py `_restore_bumped`), as `rg/nsg/rule`, and each
    NIC it put in quarantine, by id. Unreadable: nothing (its writes there then escalate)."""
    try:
        from glorfindel.response.state import active_isolations
        states = active_isolations()
    except Exception:
        return frozenset()
    out: set[str] = set()
    for st in states:
        places = list(st.get("placements") or [])
        if "placements" not in st and st.get("nsg_name"):          # a legacy single-NSG state
            places.append({"nsg_rg": st.get("nsg_rg", ""), "nsg_name": st["nsg_name"],
                           "bumped": st.get("bumped") or []})
        for p in places:
            for b in p.get("bumped") or []:
                if isinstance(b, dict) and b.get("name"):
                    out.add(f"{p.get('nsg_rg', '')}/{p.get('nsg_name', '')}/{b['name']}".lower())
            if p.get("kind") == "quarantine" and p.get("nic_id"):
                out.add(str(p["nic_id"]).rstrip("/").lower())
    return frozenset(out)


def owned_target(row: dict, recorded: frozenset[str] | set[str] = frozenset()) -> bool:
    """The row's target is Glorfindel's: one of its rules or NSGs, or what an isolation
    state records as its own on a customer's resource (`recorded_targets`)."""
    if glorfindel_managed(row):
        return True
    rid = target_resource(row).rstrip("/").lower()
    if rid in recorded:
        return True
    m = _RULE_ID_RE.search(rid)
    return bool(m) and "/".join(m.groups()) in recorded


def is_own_call(row: dict, own: set[str], recorded: frozenset[str] | set[str] = frozenset()) -> bool:
    """Glorfindel's identity, doing what Glorfindel does, on what is Glorfindel's."""
    return (bool(own) and bool(caller_ids(row) & own) and operation(row) in own_operations()
            and owned_target(row, recorded))


def prepare_rows(rows: list[dict], own: set[str],
                 recorded: frozenset[str] | set[str] = frozenset()) -> list[dict]:
    """Drop Glorfindel's own writes; mark what is left. Each kept row gains
    `GlorfindelManaged` (its target is Glorfindel's) and `GlorfindelIdentity` (Glorfindel's
    identity, outside what it does or on what is not its own)."""
    out = []
    for row in rows:
        if is_own_call(row, own, recorded):
            continue
        out.append({**row,
                    "GlorfindelManaged": glorfindel_managed(row),
                    "GlorfindelIdentity": bool(own) and bool(caller_ids(row) & own)})
    return out


def _token_claims(token: str) -> dict:
    """The payload of a JWT, unverified: only read to learn who we are."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (IndexError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_app_token(claims: dict) -> bool:
    """An application's token (a service principal, a managed identity), not a user's:
    `idtyp` says so when present; else a token with neither `scp` nor `upn` (a user's
    token carries delegated scopes, and its user's name)."""
    idtyp = str(claims.get("idtyp") or "").strip().lower()
    if idtyp:
        return idtyp == "app"
    return not claims.get("scp") and not claims.get("upn")


def token_identities(claims: dict) -> set[str]:
    """Who the token says Glorfindel is, lowercase. An application's token: its `appid`
    / `azp` and its `oid`. A user's: its `oid` only — its `appid` is the client tool's."""
    keys = _CLAIM_KEYS if is_app_token(claims) else _OID_CLAIMS
    return {str(claims[k]).strip().lower() for k in keys if claims.get(k)} - {""}


def configured_identities() -> set[str]:
    """`AZURE_CLIENT_ID` (the service principal or user-assigned identity Glorfindel signs
    in with) and `GLORFINDEL_OWN_CALLERS`, lowercase."""
    values = [os.environ.get("AZURE_CLIENT_ID", "")]
    values += (os.environ.get("GLORFINDEL_OWN_CALLERS") or "").split(",")
    return {v.strip().lower() for v in values if v and v.strip()}


class AzureActivityDetector(AzureMonitorDetector):
    """The Activity Log of the subscription, in the Log Analytics workspace."""

    plane = "control"
    backend_type = "azure_monitor"   # same workspace as Perf / Syslog
    min_lookback_s = MIN_LOOKBACK_S

    def __init__(self, workspace_id: str, credential=None):
        super().__init__(workspace_id)
        self._credential = credential
        self._token_ids: set[str] | None = None
        self._id_lock = threading.Lock()
        self._warned = False
        # What the isolation states recorded as Glorfindel's, kept a while after the state
        # is gone: a release puts a customer rule back, and its row lands minutes later.
        self._recorded: dict[str, float] = {}

    def _identity_credential(self):
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        return self._credential

    def own_identities(self) -> set[str]:
        """Who Glorfindel is on Azure: the token's claims (read once), plus the configured
        ids. A token that can't be read is retried at the next poll, and said once: until
        then only the configured ids are known — Glorfindel's own writes may escalate."""
        ids = configured_identities()
        with self._id_lock:
            if self._token_ids is None:
                try:
                    token = self._identity_credential().get_token(_TOKEN_SCOPE).token
                    claims = _token_claims(token)
                    self._token_ids = token_identities(claims)
                    if claims and not is_app_token(claims):
                        logger.warning(
                            "AzureActivity : Glorfindel tourne sous un jeton d'utilisateur "
                            "(az login) — seul son oid l'identifie (l'appid du jeton est celui "
                            "de l'outil, commun au tenant) ; les écritures de cet utilisateur "
                            "sur les règles de Glorfindel seront écartées comme les siennes. "
                            "Sur un hôte : une identité managée ou un principal de service.")
                except Exception as exc:
                    if not self._warned:
                        self._warned = True
                        logger.warning(
                            "AzureActivity: identité de Glorfindel illisible (%s) — seuls "
                            "AZURE_CLIENT_ID et GLORFINDEL_OWN_CALLERS l'excluent ; ses propres "
                            "écritures peuvent s'escalader", exc)
                    return ids
            return ids | self._token_ids

    def recorded(self) -> frozenset[str]:
        """`recorded_targets()` now, plus what was recorded within the last RECORDED_TTL_S."""
        now = time.time()
        current = recorded_targets()
        with self._id_lock:
            for key in current:
                self._recorded[key] = now
            self._recorded = {k: at for k, at in self._recorded.items() if now - at < RECORDED_TTL_S}
            return frozenset(self._recorded)

    def run_query(self, query: str, timespan=None) -> list[dict]:
        rows = super().run_query(query, timespan=timespan)
        return prepare_rows(rows, self.own_identities(), self.recorded())

    def poll_alert(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        own, recorded = self.own_identities(), self.recorded()

        def keep(row):
            return not is_own_call(row, own, recorded) and (match_row is None or match_row(row))

        result = super().poll_alert(query, since, timeout_s, interval_s=interval_s,
                                    verbose=verbose, match_row=keep)
        if result is None:
            return None
        elapsed, row = result
        return elapsed, prepare_rows([row], own, recorded)[0]
