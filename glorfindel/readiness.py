"""Can Glorfindel act on this VM? The check behind the activation button (lot L6).

Before a VM leaves `human_only`, the operator sees one verdict and the reasons behind
it — computed from Azure, nothing written:

  ready       — the response will run as designed;
  reserve     — it will run, with a known limitation the operator must acknowledge;
  not_ready   — it cannot run (missing rights, read-only credentials).

Each reason has a stable `code`. Activation (api `/api/activate/<vm>`) recomputes the
verdict and refuses unless every reserve code it finds was acknowledged by the caller:
no VM is switched to autonomous response without its reserves having been shown.
"""
from __future__ import annotations

_ISOLATION_RIGHTS = {
    "Microsoft.Network/networkInterfaces/write",
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
    else:
        missing = {m["action"] for m in perms.get("missing") or []}
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
        "Non vérifié : règles d'admin AVNM (« Always Allow ») et Azure Policy qui refuserait "
        "l'échange de NSG (repli automatique sur les règles dans ce cas).", ""))
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
