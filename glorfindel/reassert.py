"""Reassert active isolations and blocks whose rules disappeared from Azure.

A rule Glorfindel placed can vanish without Glorfindel: a `terraform apply` on an NSG
with inline rules deletes every rule absent from the code, and a person can remove one
in the portal. The local state then says ISOLATED / BLOCKED while nothing is enforced.

Each watch cycle (every few minutes) checks every recorded isolation and block:
- rules all present → nothing to do;
- rules missing, first time → put them back once (outside `human_only`) and alert;
- rules missing again after that → alert only. Two removals look deliberate (a person,
  or a pipeline that will keep deleting them): Glorfindel does not fight it.

Only MISSING rules trigger this. A bypass (an allow before the deny) or an unreadable
rule list is not fixed by re-applying; verification already reports those.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _missing(verification: dict) -> bool:
    return verification.get("verified") is False and bool(
        verification.get("uncovered_nics") or verification.get("missing_rules"))


def _mode(autonomy, vm_name: str) -> str:
    try:
        return autonomy.resolve(vm_name) if autonomy is not None else "human_only"
    except Exception:
        return "human_only"


def reassert_active(connector, autonomy=None) -> list[dict]:
    """Check every active isolation and block; re-apply missing rules once.

    Returns one record per isolation/block whose rules were missing:
    {"kind", "vm", "ip"?, "outcome": "reapplied" | "escalated" | "failed", "detail"}.
    """
    from glorfindel import escalations
    from glorfindel.actions import (
        _load_isolation_state, _save_isolation_state, _update_block_entry,
        active_blocks, active_isolations,
    )

    now = datetime.now(timezone.utc).isoformat()
    report: list[dict] = []

    for iso in active_isolations():
        vm, rid = iso["vm_name"], iso["resource_id"]
        if iso.get("partial"):
            continue          # already reported as partial; the operator decides
        try:
            if not _missing(connector.verify_isolation(rid)):
                continue
        except Exception as exc:                                   # VM gone, API down
            log.warning("reassert: isolation of %s not checked (%s)", vm, exc)
            continue
        if iso.get("reasserted_at") or _mode(autonomy, vm) == "human_only":
            reason = (
                f"Les règles d'isolation de {vm} ont disparu d'Azure"
                + (" une deuxième fois (déjà reposées le " + iso["reasserted_at"] + ")"
                   if iso.get("reasserted_at") else "")
                + " — la VM n'est plus isolée. Retrait délibéré ou `terraform apply` sur un "
                "NSG à règles en ligne ? Glorfindel ne les repose pas : "
                f"`glorfindel release {rid} --yes` si la levée est voulue, sinon ré-isoler."
            )
            escalations.record(signal_id=f"reassert-{vm}", resource_id=rid, action="isolate_vm",
                               escalation_type="verification_failed", reason=reason)
            report.append({"kind": "isolation", "vm": vm, "outcome": "escalated", "detail": reason})
            continue
        try:
            connector.isolate_vm(rid)
            state = _load_isolation_state(vm) or {}
            # Keep the original isolation time (TTL); record the re-application.
            _save_isolation_state(vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),
                                       "reasserted_at": now})
            reason = (f"Les règles d'isolation de {vm} avaient disparu d'Azure (retrait hors "
                      "Glorfindel) : reposées une fois. Si elles disparaissent encore, "
                      "Glorfindel alertera sans les reposer.")
            outcome = "reapplied"
        except Exception as exc:
            reason = f"Les règles d'isolation de {vm} ont disparu d'Azure ; les reposer a échoué : {exc}"
            outcome = "failed"
        escalations.record(signal_id=f"reassert-{vm}", resource_id=rid, action="isolate_vm",
                           escalation_type="verification_failed", reason=reason)
        report.append({"kind": "isolation", "vm": vm, "outcome": outcome, "detail": reason})

    for b in active_blocks():
        vm, rid, ip = b["vm_name"], b.get("resource_id", ""), b.get("ip", "")
        if not rid or not ip or b.get("partial"):
            continue
        try:
            if not _missing(connector.verify_block_ip(ip, rid)):
                continue
        except Exception as exc:
            log.warning("reassert: block of %s on %s not checked (%s)", ip, vm, exc)
            continue
        if b.get("reasserted_at") or _mode(autonomy, vm) == "human_only":
            reason = (f"Le blocage de {ip} sur {vm} a disparu d'Azure"
                      + (" une deuxième fois" if b.get("reasserted_at") else "")
                      + " — l'IP n'est plus bloquée. Glorfindel ne le repose pas : "
                      f"`glorfindel unblock {ip} {rid} --yes` si c'est voulu, sinon re-bloquer.")
            escalations.record(signal_id=f"reassert-{vm}-{ip}", resource_id=rid,
                               action="block_suspicious_ip", escalation_type="verification_failed",
                               reason=reason, action_params={"ip": ip})
            report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
            continue
        try:
            connector.block_suspicious_ip(
                ip, rid, scope="vm" if b.get("scoped", True) else "subnet",
                threat_port=b.get("threat_port"))
            _update_block_entry(vm, ip, reasserted_at=now)
            reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure : reposé une fois. "
                      "S'il disparaît encore, Glorfindel alertera sans le reposer.")
            outcome = "reapplied"
        except Exception as exc:
            reason = f"Le blocage de {ip} sur {vm} a disparu d'Azure ; le reposer a échoué : {exc}"
            outcome = "failed"
        escalations.record(signal_id=f"reassert-{vm}-{ip}", resource_id=rid,
                           action="block_suspicious_ip", escalation_type="verification_failed",
                           reason=reason, action_params={"ip": ip})
        report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": outcome, "detail": reason})

    return report
