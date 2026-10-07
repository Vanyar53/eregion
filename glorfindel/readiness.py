"""Can Glorfindel act on this VM? The check behind the activation button (lot L6).

Before a VM leaves `human_only`, the operator sees one verdict and the reasons behind
it — computed from Azure, nothing written:

  ready       — the response will run as designed;
  reserve     — it will run, with a known limitation the operator must acknowledge;
  not_ready   — it cannot run (missing rights, read-only credentials).

Each reason has a stable `code`. Activation (api `/api/activate/<vm>`, `glorfindel
activate`) recomputes the verdict and refuses unless every reserve code it finds was
acknowledged by the caller: no VM is switched to autonomous response without its
reserves having been shown.

The gate (lot L6, second part). Activation covered one VM at a time, but a VM can also
become autonomous through the global default, a pattern in glorfindel-config.yaml or
`watch --mode`, including every VM created later. So the configured mode is only an
intention: a VM acts alone only once its readiness allows it.
  ready                      → autonomous, nothing to confirm;
  reserve, all acknowledged  → autonomous;
  reserve, some not          → held in human_only, one card asks for confirmation;
  not_ready, or not checked  → held in human_only.
The watch checks every VM whose configured mode is autonomous when it is discovered and
again at the posture cadence (`ReadinessTracker`). A reserve that appears after the
activation puts the VM back in human_only, with an alert. `decide` and the reassertion
read the effective mode (`effective_mode`), never the configured one.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_STATE_FILE = Path.home() / ".glorfindel" / "readiness.json"
_lock = threading.Lock()

# Read errors, not limitations: on a VM that was autonomous, one is confirmed on the
# next pass before the VM is held (a throttled API must not flap the mode).
_INCONCLUSIVE = {"permissions_unknown", "nsg_unreadable"}
# Held without a card: read-only credentials (the watch already warns at start-up, one
# card per VM would bury the rest) and resources Glorfindel does not isolate.
_SILENT = {"read_only", "unsupported_asset"}

_ISOLATION_RIGHTS = {
    "Microsoft.Network/networkInterfaces/write",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/join/action",
}
_RULE_RIGHTS = {
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
}
_DRAIN_RIGHT = "Microsoft.Compute/virtualMachines/runCommand/action"


def _reason(code: str, level: str, message: str, fix: str = "") -> dict:
    return {"code": code, "level": level, "message": message, "fix": fix}


def assess(resource_id: str, connector, quarantine_nsg: bool = True) -> dict:
    """Verdict + reasons for one VM. `quarantine_nsg`: the JIT isolation is enabled
    (glorfindel-config.yaml `isolation.quarantine_nsg`)."""
    reasons: list[dict] = []
    vm = resource_id.rstrip("/").split("/")[-1]

    from glorfindel.actions import _is_backupable_vm
    if not _is_backupable_vm(resource_id):
        reasons.append(_reason(
            "unsupported_asset", "not_ready",
            "La réponse de Glorfindel vise les VM Azure : ce type de ressource (cluster AKS, "
            "instance de VMSS) n'est pas pris en charge.", ""))
        return _verdict(vm, reasons)

    from glorfindel.actions import _subscription_of
    target = _subscription_of(resource_id)
    mine = getattr(connector, "_subscription_id", None)
    if isinstance(mine, str) and mine and target and target.lower() != mine.lower():
        reasons.append(_reason(
            "other_subscription", "not_ready",
            f"VM dans l'abonnement {target}, Glorfindel agit dans {mine} : toute action "
            "serait refusée.", "Une instance de Glorfindel configurée pour cet abonnement."))
        return _verdict(vm, reasons)

    if getattr(connector, "read_only", False) is True:
        reasons.append(_reason(
            "read_only", "not_ready",
            "Identifiants en lecture seule : Glorfindel peut détecter et recommander, pas agir.",
            "Utiliser une identité avec des droits d'écriture (voir « droits » ci-dessous)."))
        return _verdict(vm, reasons)

    # Rights, read from Azure's permissions API.
    perms = connector.check_permissions(resource_id)
    if not isinstance(perms, dict) or not perms.get("ok"):
        reasons.append(_reason(
            "permissions_unknown", "reserve",
            f"Droits non vérifiables ({(perms or {}).get('error', '?') if isinstance(perms, dict) else '?'}).",
            "Donner au moins Reader sur le resource group pour lire les permissions."))
        missing: set[str] = set()
        release_missing: list[dict] = []
    else:
        # What the isolation needs, apart from the release's own right (below).
        missing = {m["action"] for m in perms.get("missing") or [] if m.get("used_by") != "release_isolation"}
        release_missing = [m for m in perms.get("missing") or [] if m.get("used_by") == "release_isolation"]
    jit_ok = quarantine_nsg and not (missing & _ISOLATION_RIGHTS)
    rules_ok = not (missing & _RULE_RIGHTS)
    if not jit_ok and not rules_ok:
        reasons.append(_reason(
            "cannot_isolate", "not_ready",
            "Ni l'isolation par NSG de quarantaine ni les règles de repli ne sont possibles : "
            "droits manquants (" + ", ".join(sorted(missing & (_ISOLATION_RIGHTS | _RULE_RIGHTS))) + ").",
            "Network Contributor sur le resource group de la VM, ou un rôle personnalisé avec ces actions."))
    elif quarantine_nsg and not jit_ok:
        reasons.append(_reason(
            "rules_fallback", "reserve",
            "Isolation par règles seulement (droits manquants pour le NSG de quarantaine) : "
            "exposée aux règles allow du client et aux `terraform apply`.",
            "Ajouter " + ", ".join(sorted(missing & _ISOLATION_RIGHTS)) + "."))
    if not rules_ok:
        reasons.append(_reason(
            "no_block", "reserve",
            "Blocage d'IP impossible (droits sur les règles NSG manquants).",
            "Ajouter " + ", ".join(sorted(missing & _RULE_RIGHTS)) + "."))
    if release_missing and jit_ok:
        reasons.append(_reason(
            "release_blocked", "reserve",
            "La levée ne pourra pas remettre le NSG d'origine de la carte (join/action manquant sur "
            + ", ".join(sorted({m["scope"] for m in release_missing}))
            + ") : la carte resterait en quarantaine jusqu'à une intervention.",
            "Ajouter Microsoft.Network/networkSecurityGroups/join/action sur le groupe du NSG du client."))
    if _DRAIN_RIGHT in missing:
        reasons.append(_reason(
            "no_drain", "reserve",
            "Les sessions déjà ouvertes ne seront pas coupées à l'isolation (droit Run Command "
            "manquant) : un attaquant connecté garde la main.",
            f"Ajouter {_DRAIN_RIGHT} (Virtual Machine Contributor)."))

    # Windows: no session drain (Linux `ss -K` only).
    try:
        if "windows" in (connector.vm_os(resource_id) or "").lower():
            reasons.append(_reason(
                "windows_no_drain", "reserve",
                "VM Windows : les sessions déjà ouvertes ne sont pas coupées à l'isolation.", ""))
    except Exception:
        pass

    # NSGs at rest: precedence for blocks (the JIT isolation has no precedence issue).
    nsg = connector.check_nsg_access(resource_id)
    if isinstance(nsg, dict):
        if not nsg.get("ok"):
            err = str(nsg.get("error", ""))
            if "no NSG" in err:
                reasons.append(_reason(
                    "no_nsg_for_blocks", "reserve",
                    "Ni la carte ni son subnet n'ont de NSG : l'isolation reste possible (NSG de "
                    "quarantaine), pas le blocage d'une IP.", "Associer un NSG au subnet."))
            else:
                reasons.append(_reason("nsg_unreadable", "reserve", f"NSG illisibles ({err[:160]}).", ""))
        else:
            issues = [i for i in nsg.get("precedence") or [] if not i.get("unreadable")]
            iso = sorted({i["rule"] for i in issues if i.get("action") == "isolate_vm"})
            blk = sorted({i["rule"] for i in issues if i.get("action") == "block_suspicious_ip"})
            if iso and not jit_ok:
                reasons.append(_reason(
                    "isolation_bypassed", "reserve",
                    "Règle(s) allow évaluée(s) avant le deny d'isolation : " + ", ".join(iso) + ".",
                    "Placer ces règles après la plage 100–999, ou donner les droits du NSG de quarantaine."))
            if blk:
                reasons.append(_reason(
                    "block_may_be_bypassed", "reserve",
                    "Règle(s) allow évaluée(s) avant le deny de blocage : " + ", ".join(blk)
                    + " (contournement réel seulement si elle ouvre le port de l'attaque).",
                    "Placer ces règles après la plage 100–999."))

    reasons.append(_reason(
        "unverified_layers", "info",
        "Non vérifié : règles d'admin AVNM (« Always Allow ») ; Azure Policy qui refuserait "
        "l'échange de NSG (repli automatique sur les règles) ; deny assignments, verrous de "
        "ressource, PIM. Non tenable : une carte redéployée en Bicep/ARM, ou gérée par un "
        "réconciliateur continu (Crossplane, Azure Service Operator), retire la quarantaine "
        "— la réaffirmation alerte, mais ne peut pas la maintenir.", ""))
    return _verdict(vm, reasons)


def _verdict(vm: str, reasons: list[dict]) -> dict:
    levels = {r["level"] for r in reasons}
    verdict = "not_ready" if "not_ready" in levels else ("reserve" if "reserve" in levels else "ready")
    return {
        "vm": vm, "verdict": verdict, "reasons": reasons,
        "reserve_codes": sorted(r["code"] for r in reasons if r["level"] == "reserve"),
    }


def activation_refusal(assessment: dict, acknowledged: list[str] | None) -> str | None:
    """Why activation must be refused, or None. Not ready → refused; reserves → each
    one must have been acknowledged (shown to and accepted by the operator)."""
    if assessment["verdict"] == "not_ready":
        return "VM pas prête : " + " ; ".join(
            r["message"] for r in assessment["reasons"] if r["level"] == "not_ready")
    unacked = set(assessment["reserve_codes"]) - set(acknowledged or [])
    if unacked:
        return "Réserves non confirmées : " + ", ".join(sorted(unacked))
    return None


# ── Store: last assessment + what the operator acknowledged, per VM ──────────────

def _key(vm: str) -> str:
    return (vm or "").rstrip("/").split("/")[-1].lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextlib.contextmanager
def _locked():
    """The watch (tracker) and the War Room (activation) are two processes writing the
    same file: a thread lock plus an flock around every read-modify-write."""
    with _lock:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_STATE_FILE.with_suffix(".lock"), "a") as fh:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:          # not POSIX: the thread lock only
                pass
            yield


def _read() -> dict:
    try:
        data = json.loads(_STATE_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        # Unreadable = nothing checked: every autonomous VM is held until re-checked.
        log.warning("readiness: %s unreadable (%s) — VMs held until re-checked", _STATE_FILE, exc)
        return {}


def _write(data: dict) -> None:
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    os.replace(tmp, _STATE_FILE)


def _update(name: str, /, **fields) -> dict:
    """Merge `fields` into the VM's record (None removes a field). Returns the record."""
    with _locked():
        data = _read()
        rec = dict(data.get(_key(name)) or {})
        for k, v in fields.items():
            if v is None:
                rec.pop(k, None)
            else:
                rec[k] = v
        data[_key(name)] = rec
        _write(data)
        return rec


def _raw(vm: str) -> dict:
    rec = _read().get(_key(vm))
    return rec if isinstance(rec, dict) else {}


def get(vm: str) -> dict | None:
    """The VM's last assessment (with what was acknowledged), or None if never checked."""
    rec = _raw(vm)
    return rec if rec.get("verdict") else None


def all_records() -> dict:
    return {k: v for k, v in _read().items() if isinstance(v, dict) and v.get("verdict")}


def record_assessment(assessment: dict, resource_id: str = "") -> dict:
    return _update(
        assessment["vm"], vm=assessment["vm"], resource_id=resource_id or None,
        verdict=assessment["verdict"], reserve_codes=list(assessment["reserve_codes"]),
        reasons=assessment["reasons"], checked_at=_now(), recheck=None)


def acknowledge(vm: str, codes: list[str], by: str) -> dict:
    """The operator was shown these reserves and accepted them for this VM."""
    merged = sorted(set(_raw(vm).get("acknowledged") or []) | set(codes or []))
    return _update(vm, acknowledged=merged, acknowledged_at=_now(), acknowledged_by=by)


def revoke(vm: str) -> None:
    """The VM was put back in human_only: a later activation shows the reserves again."""
    if _raw(vm):
        _update(vm, acknowledged=None, acknowledged_at=None, acknowledged_by=None,
                active_since=None, alerted=None)


# ── The gate ───────────────────────────────────────────────────────────────────

def hold_for(vm: str, configured: str) -> dict:
    """Why a VM configured autonomous stays in human_only, or {} when it may act alone.
    {"reason": not_checked | not_ready | unconfirmed_reserves, "codes", "message"}."""
    if configured == "human_only":
        return {}
    rec = get(vm)
    if rec is None:
        return {"reason": "not_checked", "codes": [],
                "message": "préparation pas encore contrôlée"}
    if rec["verdict"] == "not_ready":
        blocking = [r for r in rec.get("reasons") or [] if r.get("level") == "not_ready"]
        return {"reason": "not_ready", "codes": [r["code"] for r in blocking],
                "message": "pas prête : " + " ; ".join(r["message"] for r in blocking)}
    unacked = sorted(set(rec.get("reserve_codes") or []) - set(rec.get("acknowledged") or []))
    if unacked:
        return {"reason": "unconfirmed_reserves", "codes": unacked,
                "message": "réserves non confirmées : " + ", ".join(unacked)}
    return {}


def effective_mode(vm: str, configured: str) -> tuple[str, dict]:
    """The mode the VM actually runs in: the configured one, or human_only while held."""
    hold = hold_for(vm, configured)
    return ("human_only", {**hold, "configured": configured}) if hold else (configured, {})


def _quarantine_enabled() -> bool:
    try:
        from glorfindel.config import load_glorfindel_config
        return load_glorfindel_config().isolation.quarantine_nsg
    except Exception:
        return True


class ReadinessGate:
    """`decide`'s view of the mode. A VM never checked (a signal before the first
    discovery pass, a VM outside discovery) is checked now: a few seconds, once."""

    def __init__(self, connector) -> None:
        self._connector = connector

    def __call__(self, vm: str, resource_id: str, configured: str) -> tuple[str, dict]:
        if configured != "human_only" and get(vm) is None and resource_id:
            try:
                record_assessment(
                    assess(resource_id, self._connector, _quarantine_enabled()), resource_id)
            except Exception as exc:
                log.warning("readiness: %s not checked (%s) — held in human_only", vm, exc)
        return effective_mode(vm, configured)


# ── The tracker: checks VMs as they are discovered, then at the posture cadence ──

def _card_id(vm: str) -> str:
    return f"readiness-{_key(vm)}"


def resolve_card(vm: str) -> None:
    """Close the VM's pending 'autonomous response held' card, if any."""
    from glorfindel import escalations
    for e in escalations.pending():
        if e.get("signal_id") == _card_id(vm):
            escalations.resolve(e["id"])


class ReadinessTracker:
    """Run by the discovery service after every discovery pass (60 s). Only VMs whose
    configured mode is autonomous are checked: the gate matters for them alone, and a
    VM in human_only is checked on demand by the activation screen."""

    def __init__(self, connector, interval_s: float = 1800,
                 autonomy_override: str | None = None, config_loader=None) -> None:
        self._connector = connector
        self._interval_s = interval_s
        self._override = autonomy_override
        self._load_config = config_loader

    def _config(self):
        if self._load_config is not None:
            return self._load_config()
        from glorfindel.config import load_glorfindel_config
        return load_glorfindel_config()

    def _due(self, rec: dict) -> bool:
        if not rec.get("verdict") or rec.get("recheck"):
            return True
        try:
            checked = datetime.fromisoformat(rec["checked_at"])
        except Exception:
            return True
        return (datetime.now(timezone.utc) - checked).total_seconds() >= self._interval_s

    def refresh(self, assets) -> list[dict]:
        """Check what is due and apply the transitions. Returns one event per
        transition: {"vm", "event": "activated" | "held" | "demoted", "hold"?}."""
        cfg = self._config()           # fresh: a War Room mode change applies
        autonomy = cfg.autonomy
        if self._override:
            autonomy.default = self._override
        quarantine = cfg.isolation.quarantine_nsg
        events: list[dict] = []
        for asset in assets:
            rid = getattr(asset, "resource_id", "") or ""
            if not rid:
                continue
            vm = rid.rstrip("/").split("/")[-1]
            configured = autonomy.resolve(vm)
            if configured == "human_only":
                self._stand_down(vm)
                continue
            rec = _raw(vm)
            if self._due(rec):
                try:
                    assessment = assess(rid, self._connector, quarantine_nsg=quarantine)
                except Exception as exc:
                    log.warning("readiness: %s not checked (%s)", vm, exc)
                    continue
                self._store(assessment, rid, rec)
            ev = self._transition(vm, rid, configured)
            if ev:
                events.append(ev)
        return events

    def _store(self, assessment: dict, rid: str, prev: dict) -> None:
        new = set(assessment["reserve_codes"]) - set(prev.get("acknowledged") or [])
        if (prev.get("active_since") and assessment["verdict"] == "reserve"
                and new and new <= _INCONCLUSIVE and not prev.get("recheck")):
            _update(assessment["vm"], recheck=True)      # confirm on the next pass
            return
        record_assessment(assessment, rid)

    def _stand_down(self, vm: str) -> None:
        """Configured human_only again: nothing held any more, no card to keep open."""
        rec = _raw(vm)
        if rec.get("alerted") or rec.get("active_since"):
            resolve_card(vm)
            _update(vm, alerted=None, active_since=None)

    def _transition(self, vm: str, rid: str, configured: str) -> dict | None:
        rec = _raw(vm)
        hold = hold_for(vm, configured)
        if not hold:
            if rec.get("active_since"):
                return None
            resolve_card(vm)
            _update(vm, active_since=_now(), alerted=None)
            log.info("readiness: %s now acts autonomously (%s)", vm,
                     "ready" if rec.get("verdict") == "ready" else "reserves confirmed")
            return {"vm": vm, "event": "activated"}
        was_active = bool(rec.get("active_since"))
        signature = hold["reason"] + ":" + ",".join(hold["codes"])
        if rec.get("alerted") == signature and not was_active:
            return None                      # one card per situation, not one per pass
        if was_active:
            _update(vm, active_since=None, demoted_at=_now())
        if hold["reason"] != "not_checked" and not set(hold["codes"]) & _SILENT:
            self._alert(vm, rid, hold, rec, was_active)
        _update(vm, alerted=signature)
        log.warning("readiness: %s held in human_only (%s)", vm, hold["message"])
        return {"vm": vm, "event": "demoted" if was_active else "held", "hold": hold}

    def _alert(self, vm: str, rid: str, hold: dict, rec: dict, was_active: bool) -> None:
        from glorfindel import escalations
        reasons = [r for r in rec.get("reasons") or [] if r.get("code") in hold["codes"]]
        detail = " ".join(f"[{r['code']}] {r['message']}" for r in reasons)
        if hold["reason"] == "not_ready":
            lead = (f"{vm} : réponse autonome configurée mais impossible, la VM reste en "
                    "observation (human_only).")
        elif was_active:
            lead = (f"{vm} repasse en observation (human_only) : une réserve est apparue "
                    "depuis son activation.")
        else:
            lead = (f"{vm} : réponse autonome configurée, VM retenue en observation "
                    "(human_only) tant que ses réserves ne sont pas confirmées.")
        steps = [r["fix"] for r in reasons if r.get("fix")]
        if hold["reason"] != "not_ready":
            steps.append(f"Lire et confirmer les réserves : War Room (Activer) ou "
                         f"`glorfindel activate {vm}`.")
        resolve_card(vm)        # a new situation is a new card (and a new notification)
        escalations.record(
            signal_id=_card_id(vm), resource_id=rid, action="activate_autonomy",
            escalation_type="readiness_hold", reason=f"{lead} {detail}".strip(),
            suggested_steps=steps,
            action_params={"verdict": rec.get("verdict", ""), "codes": hold["codes"]})
