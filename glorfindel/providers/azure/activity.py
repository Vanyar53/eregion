"""Azure's control plane as a detection source (AL1): the Activity Log (`AzureActivity`),
read from the same Log Analytics workspace as Perf and Syslog.

Detection only. A row of `AzureActivity` says who (`Caller`, `CallerIpAddress`) did what
(`OperationNameValue`) to which resource (`_ResourceId`). The RulePoller dispatches it
like any detection; `decide` never lets an autonomous action follow it (the control-plane
guard, glorfindel/agent.py) — it is escalated, explained, to a human.

Two things only this adapter knows, so it does them before the rows leave it:
  - Glorfindel's own writes. Its isolations, quarantines, blocks and releases show in
    the Activity Log under its own identity. A row whose caller is Glorfindel AND whose
    operation is one its capabilities declare (capabilities.py: the rights of each
    response) is dropped — else each isolation escalates itself. Its identity is read,
    never written in code: the token of its credential (`oid`, `appid`…),
    `AZURE_CLIENT_ID`, and `GLORFINDEL_OWN_CALLERS` (comma separated). The same identity
    doing something Glorfindel never does (a role assignment, a snapshot, `listKeys`) is
    kept, and marked `GlorfindelIdentity`: its credential may be in other hands.
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
import threading

from glorfindel.providers.azure.capabilities import CAPABILITIES
from glorfindel.providers.azure.monitor import AzureMonitorDetector
from glorfindel.providers.azure.quarantine import QUARANTINE_NSG_PREFIX

logger = logging.getLogger("glorfindel.providers.azure.activity")

# A control-plane rule whose window is shorter than this misses the rows that arrive late.
MIN_LOOKBACK_S = 1800.0

# The columns AzureActivity names its caller in. `CallerAppId` / `CallerObjectId` are what
# the shipped rules extract from `Claims` (a service principal's `Caller` is one of its ids,
# depending on the token: both are compared).
_CALLER_COLUMNS = ("Caller", "CallerAppId", "CallerObjectId")
_CLAIM_KEYS = (
    "appid", "azp", "oid", "upn", "unique_name",
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
)
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


def is_own_call(row: dict, own: set[str]) -> bool:
    """Glorfindel's identity, doing what Glorfindel does."""
    return bool(own) and bool(caller_ids(row) & own) and operation(row) in own_operations()


def prepare_rows(rows: list[dict], own: set[str]) -> list[dict]:
    """Drop Glorfindel's own writes; mark what is left. Each kept row gains
    `GlorfindelManaged` (its target is Glorfindel's) and `GlorfindelIdentity` (Glorfindel's
    identity made a call it never makes)."""
    out = []
    for row in rows:
        if is_own_call(row, own):
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
                    self._token_ids = {str(claims[k]).strip().lower() for k in _CLAIM_KEYS
                                       if claims.get(k)}
                except Exception as exc:
                    if not self._warned:
                        self._warned = True
                        logger.warning(
                            "AzureActivity: identité de Glorfindel illisible (%s) — seuls "
                            "AZURE_CLIENT_ID et GLORFINDEL_OWN_CALLERS l'excluent ; ses propres "
                            "écritures peuvent s'escalader", exc)
                    return ids
            return ids | self._token_ids

    def run_query(self, query: str, timespan=None) -> list[dict]:
        rows = super().run_query(query, timespan=timespan)
        return prepare_rows(rows, self.own_identities())

    def poll_alert(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        own = self.own_identities()

        def keep(row):
            return not is_own_call(row, own) and (match_row is None or match_row(row))

        result = super().poll_alert(query, since, timeout_s, interval_s=interval_s,
                                    verbose=verbose, match_row=keep)
        if result is None:
            return None
        elapsed, row = result
        return elapsed, prepare_rows([row], own)[0]
