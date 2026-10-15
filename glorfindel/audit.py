from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

AuditStatus = Literal["ok", "warn", "fail", "skip"]


@dataclass
class AuditCheck:
    action: str       # remediation action this check covers
    name: str         # what was checked
    status: AuditStatus
    message: str
    fix: str = ""     # actionable CLI command to resolve the gap
    # Structured extras so the War Room doesn't have to parse `message`.
    # NSG check → {"nsg": "rg/name", "nsg_scope": "nic"|"subnet"}.
    # Backup check → {"points": int, "protected": bool} (when available).
    data: dict = field(default_factory=dict)


@dataclass
class AuditResult:
    resource_id: str
    timestamp: str
    checks: list[AuditCheck] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not any(c.status == "fail" for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "timestamp": self.timestamp,
            "ready": self.ready,
            "checks": [
                {
                    "action": c.action,
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "fix": c.fix,
                    "data": c.data,
                }
                for c in self.checks
            ],
        }


def run(
    resource_id: str,
    connector,
    vault: str = "",
    vault_rg: str = "",
    staging_storage: str = "",
    workspace_id: str | None = None,
) -> AuditResult:
    """Check that Glorfindel can execute all remediation actions on this resource.

    vault_rg: the vault's own resource group (a central vault protects VMs across many
    RGs). Falls back to the VM's RG when empty (sandbox: vault and VM co-located).
    staging_storage: the SA where Azure stages recovered disks during a restore (see
    _check_restore_staging). Empty → surfaced as a readiness gap, not a live failure.

    Covers: NSG (isolate_vm, block_suspicious_ip), Azure Backup (restore_from_backup),
    and Compute (snapshot). Detects both IAM gaps and missing infrastructure.
    """
    result = AuditResult(
        resource_id=resource_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if getattr(connector, "dry_run", False):
        result.checks = [
            AuditCheck("all", "dry-run", "skip",
                       "Audit skipped in dry-run — no Azure API calls made")
        ]
        return result

    # Read-only credentials: remediation actions cannot execute by design. The
    # checks below still run — they confirm READ access (needed for detection) —
    # but write capability is not verifiable without performing a write.
    # `is True` (not truthy): MagicMock connectors in tests have an auto-truthy
    # read_only attribute — only a real bool True should trigger this branch.
    if getattr(connector, "read_only", False) is True:
        result.checks.append(AuditCheck(
            action="all",
            name="Credentials",
            status="warn",
            message=(
                "Read-only credentials (GLORFINDEL_READ_ONLY) — Glorfindel detects "
                "and recommends but cannot execute remediation. Checks below confirm "
                "READ access only; write capability is not verifiable."
            ),
            fix="Use a service principal with write roles to enable autonomous actions.",
        ))

    # Run the three Azure checks concurrently. The RSV backup check
    # (recovery_points.list) is the slow leg (several seconds); running it in
    # parallel with the fast NSG/Compute checks means the whole result returns at
    # the speed of the slowest single check instead of their sum. Order is
    # preserved (NSG, backup, compute) — futures are read in submission order.
    from concurrent.futures import ThreadPoolExecutor

    # Import the Azure SDK once, on THIS thread, before spawning the 3 parallel
    # checks — otherwise their concurrent first-import of azure.core deadlocks the
    # import system (_ModuleLock) / yields a half-init module. No-op after the first
    # call. Covers the War Room API process too (it calls audit.run via to_thread).
    from glorfindel.actions import warm_up_azure_sdk
    warm_up_azure_sdk()

    jobs = [
        (_check_nsg, (resource_id, connector)),
        (_check_backup, (resource_id, connector, vault, vault_rg)),
        (_check_compute, (resource_id, connector)),
        (_check_permissions, (resource_id, connector)),
    ]
    ws = _workspace_id() if workspace_id is None else workspace_id
    if ws:
        jobs.append((_check_perf_sampling, (resource_id, ws)))
        jobs.append((_check_syslog, (resource_id, ws)))
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(fn, *args) for fn, args in jobs]
        for f in futures:
            out = f.result()
            # _check_nsg may return two checks (access + precedence).
            result.checks.extend(out if isinstance(out, list) else [out])
    if ws:
        # From what the two telemetry checks just read — no Azure call of its own.
        result.checks.append(_check_rule_coverage(resource_id, result.checks))
    _align_precedence(result.checks)

    # Restore staging SA — pure config check (no Azure call), so it runs outside the pool.
    result.checks.append(_check_restore_staging(staging_storage))
    return result


# ── Per-action checks ──────────────────────────────────────────────────────────

def _workspace_id() -> str:
    """The Log Analytics workspace of the first azure_monitor backend in the config."""
    try:
        from glorfindel.config import load_glorfindel_config
        for b in load_glorfindel_config().monitoring_backends:
            if getattr(b, "workspace_id", ""):
                return b.workspace_id
    except Exception:
        pass
    return ""


_COARSE_STEP_S = 25


def _check_perf_sampling(resource_id: str, workspace_id: str, detector=None) -> AuditCheck:
    """What the ransomware rule actually receives for this VM (third review, T6/L14).

    Read from the data, not the DCR: it also catches a DCR that doesn't collect the
    counter at all — the rule is then blind, without any error. At Azure's default
    60-s sampling the rule used to never fire; it now uses a coarse mode whose
    threshold is provisional."""
    name = "Disk write sampling"
    vm = resource_id.rstrip("/").split("/")[-1]
    query = (
        "Perf | where TimeGenerated > ago(1h)"
        ' | where ObjectName == "Logical Disk" or ObjectName == "LogicalDisk"'
        ' | where CounterName == "Disk Write Bytes/sec"'
        f' | where _ResourceId =~ "{resource_id}" or Computer =~ "{vm}"'
        # The cadence is the smallest gap between two seconds that each carry ONE sample of
        # the series. A second with several is an agent batch: its first upload after a boot
        # sends them under one timestamp (measured, 15/10) — read as a 0-s step, it claimed
        # the fine mode. Gaps above the cadence are samples the agent skipped under load.
        " | summarize c = count() by InstanceName, s = bin(TimeGenerated, 1s)"
        " | order by InstanceName asc, s asc"
        " | extend gap = iff(prev(InstanceName) == InstanceName and c == 1 and prev(c) == 1,"
        " datetime_diff('second', s, prev(s)), long(null))"
        " | summarize n = sum(c), step = min(gap), gaps = countif(isnotnull(gap)) by InstanceName"
        " | order by n desc | take 1"
    )
    try:
        if detector is None:
            from glorfindel.detectors import detector_for
            detector = detector_for("azure_monitor", workspace_id=workspace_id)
        rows = detector.run_query(query)
    except Exception as e:
        return AuditCheck("detection", name, "warn", f"Échantillonnage illisible ({str(e)[:160]}).",
                          data={"present": None})
    fix = ("Collecter \\LogicalDisk(*)\\Disk Write Bytes/sec dans la DCR Perf, toutes les "
           "10 à 15 s.")
    if not rows or int(rows[0].get("n") or 0) < 2:
        return AuditCheck(
            "detection", name, "warn",
            "Aucun échantillon « Disk Write Bytes/sec » depuis 1 h : la détection ransomware est "
            "aveugle pour cette VM (compteur absent de la DCR) — ou la VM est éteinte.", fix,
            data={"present": False})
    n = int(rows[0]["n"])
    if not int(rows[0].get("gaps") or 0) or rows[0].get("step") is None:
        return AuditCheck(
            "detection", name, "warn",
            f"Compteur présent, cadence pas encore mesurable : {n} échantillons, pas encore deux à "
            "des instants distincts (premier envoi de l'agent après un démarrage). Relancer dans "
            "quelques minutes.",
            data={"present": True, "samples": n, "step_s": None})
    step = float(rows[0]["step"])
    data = {"present": True, "samples": n, "step_s": round(step)}
    if step <= _COARSE_STEP_S:
        return AuditCheck("detection", name, "ok",
                          f"Échantillonnage ~{step:.0f} s : règle ransomware en mode fin "
                          "(2 échantillons > 45 Mo/s, calibré sur le banc).", data=data)
    return AuditCheck(
        "detection", name, "warn",
        f"Échantillonnage ~{step:.0f} s : règle ransomware en mode grossier (1 échantillon "
        "> 25 Mo/s) — seuil provisoire, marge mince ; une attaque courte ou un disque lent "
        "peut passer sous le seuil.", fix, data=data)


def _check_syslog(resource_id: str, workspace_id: str, detector=None) -> AuditCheck:
    """Does this VM send Syslog? Most shipped rules read it (brute force, sudo, account
    creation): without it they are blind for this VM, without any error (P4)."""
    name = "Syslog"
    vm = resource_id.rstrip("/").split("/")[-1]
    query = (
        "Syslog | where TimeGenerated > ago(1h)"
        f' | where _ResourceId =~ "{resource_id}" or Computer =~ "{vm}"'
        " | summarize n = count(), facilities = strcat_array(make_set(Facility, 12), ', ')"
    )
    try:
        if detector is None:
            from glorfindel.detectors import detector_for
            detector = detector_for("azure_monitor", workspace_id=workspace_id)
        rows = detector.run_query(query)
    except Exception as e:
        return AuditCheck("detection", name, "warn", f"Syslog illisible ({str(e)[:160]}).",
                          data={"present": None})
    n = int((rows[0].get("n") if rows else 0) or 0)
    if not n:
        return AuditCheck(
            "detection", name, "warn",
            "Aucune ligne Syslog depuis 1 h : les règles qui lisent Syslog sont aveugles pour "
            "cette VM (DCR Syslog absente) — ou la VM est éteinte.",
            "Associer la VM à une DCR Syslog (facilities auth et authpriv au moins).",
            data={"present": False})
    facilities = str(rows[0].get("facilities") or "")
    return AuditCheck("detection", name, "ok",
                      f"{n} lignes Syslog depuis 1 h" + (f" ({facilities})" if facilities else "") + ".",
                      data={"present": True, "rows": n, "facilities": facilities})


# Tables a rule can read, in the order they are looked for in its query.
_RULE_TABLES = ("Perf", "Syslog", "StorageBlobLogs", "AzureActivity", "SigninLogs", "AuditLogs", "Heartbeat")
# Tables whose rows the VM itself sends: a rule on them is blind if the VM sends none.
_VM_TELEMETRY = {"Perf": "perf", "Syslog": "syslog"}


def rule_table(query: str) -> str:
    """The table a detection rule reads: the first known table its query names."""
    found = [(m.start(), tbl) for tbl in _RULE_TABLES
             for m in [re.search(rf"\b{tbl}\b", query or "")] if m]
    return min(found)[1] if found else ""


def rule_coverage(rules, resource_id: str, telemetry: dict, status: dict, is_excluded=None) -> list[dict]:
    """What each rule that applies to this VM can see (P4).

    ``telemetry`` maps "perf"/"syslog" to True (the VM sends it), False (it doesn't) or
    None (unreadable). State per rule: ``covered`` · ``blind`` (its table gets nothing from
    this VM) · ``unknown`` · ``error`` (its last poll failed) · ``not_vm`` (its rows don't
    come from the VM — storage, identity) · ``excluded`` · ``disabled``."""
    vm = resource_id.rstrip("/").split("/")[-1]
    out = []
    for r in rules:
        rid = getattr(r, "resource_id", "") or ""
        if not getattr(r, "auto_apply", False) and rid.lower() != resource_id.lower():
            continue
        table = rule_table(getattr(r, "query", ""))
        row = {"name": r.name, "ttp": getattr(r, "ttp", ""), "table": table}
        error = (status.get(r.name) or {}).get("last_error", "")
        if not getattr(r, "enabled", True):
            row["state"] = "disabled"
        elif is_excluded is not None and is_excluded(vm, r.name):
            row["state"] = "excluded"
        elif error:
            row["state"], row["error"] = "error", str(error)[:200]
        elif table not in _VM_TELEMETRY:
            row["state"] = "not_vm"
        else:
            seen = telemetry.get(_VM_TELEMETRY[table])
            row["state"] = "covered" if seen is True else "blind" if seen is False else "unknown"
        out.append(row)
    return out


# (one rule, several rules) — a rule is « une règle ».
_COVERAGE_LABEL = {
    "covered": ("voit des données", "voient des données"), "blind": ("aveugle", "aveugles"),
    "unknown": ("inconnue", "inconnues"), "error": ("en erreur", "en erreur"),
    "not_vm": ("hors VM", "hors VM"), "excluded": ("exclue", "exclues"),
    "disabled": ("désactivée", "désactivées"),
}


def _load_rules():
    """The detection rules, resolved against glorfindel-config.yaml, and its exceptions."""
    from glorfindel.config import load_glorfindel_config
    from glorfindel.detection_rules import load_config

    candidates = [Path("glorfindel/rules/azure/detection_rules.yaml"),
                  Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml"]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        return [], None
    cfg = load_glorfindel_config()
    return load_config(path, glorfindel_cfg=cfg).rules, getattr(cfg, "is_excluded", None)


def _check_rule_coverage(resource_id: str, checks: list) -> AuditCheck:
    """The rules that cover this VM, and whether each one sees anything (P4)."""
    name = "Detection rules"
    by_name = {c.name: c for c in checks}
    telemetry = {"perf": (by_name.get("Disk write sampling") or AuditCheck("", "", "skip", "")).data.get("present"),
                 "syslog": (by_name.get("Syslog") or AuditCheck("", "", "skip", "")).data.get("present")}
    try:
        from glorfindel.detection_rules import _load_status
        rules, is_excluded = _load_rules()
        cov = rule_coverage(rules, resource_id, telemetry, _load_status(), is_excluded)
    except Exception as e:
        return AuditCheck("detection", name, "warn", f"Règles illisibles ({str(e)[:160]}).")
    data = {"rules": cov}
    if not cov:
        return AuditCheck("detection", name, "warn", "Aucune règle de détection ne s'applique à cette VM.",
                          data=data)
    counts: dict[str, int] = {}
    for r in cov:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    summary = ", ".join(f"{n} {_COVERAGE_LABEL[s][n > 1]}" for s, n in counts.items())
    weak = [r for r in cov if r["state"] in ("blind", "unknown", "error")]
    if not weak:
        return AuditCheck("detection", name, "ok", f"{len(cov)} règles : {summary}.", data=data)
    detail = " ; ".join(f"{r['name']} ({r['table'] or '?'}) {_COVERAGE_LABEL[r['state']][0]}" for r in weak)
    return AuditCheck("detection", name, "warn", f"{len(cov)} règles : {summary} — {detail}.",
                      "Voir « Disk write sampling » et « Syslog » ci-dessus : la DCR de la VM doit "
                      "collecter ce que lisent ses règles.", data=data)


def _check_permissions(resource_id: str, connector) -> AuditCheck | list:
    """Rights the isolation needs (JIT NSG swap, session drain, fallback rules), read
    from Azure's permissions API — nothing written. Read-only credentials → skipped
    (the observe-only regime is a choice, not a gap)."""
    if getattr(connector, "read_only", False) is True:
        return []
    res = connector.check_permissions(resource_id)
    if not isinstance(res, dict):
        return []
    name, action = "Isolation permissions", "isolate_vm, block_suspicious_ip"
    if not res.get("ok"):
        return AuditCheck(action, name, "warn",
                          f"Droits non vérifiables : {res.get('error', '?')}",
                          fix="Donner au moins Reader sur le resource group pour lire les permissions.")
    missing = res.get("missing") or []
    if not missing:
        return AuditCheck(action, name, "ok",
                          "Échange du NSG, coupure des sessions et règles de repli : droits présents.")
    by_scope: dict[str, list[str]] = {}
    for m in missing:
        by_scope.setdefault(m["scope"], []).append(m["action"])
    detail = " ; ".join(f"{scope} : {', '.join(acts)}" for scope, acts in by_scope.items())
    return AuditCheck(
        action, name, "fail",
        f"Droits manquants — {detail}",
        fix=("Rôles intégrés suffisants : Network Contributor + Virtual Machine Contributor "
             "sur le resource group (ou un rôle personnalisé avec ces seules actions)."),
        data={"missing_permissions": missing},
    )


def _check_precedence(issues: list[dict]) -> AuditCheck | None:
    """ALLOW rules evaluated before Glorfindel's denies → isolate/block would be
    bypassed for the traffic they allow, while verification of rule PRESENCE passes.

    Found on the Celebrimbor bench (2026-10-05): allow-ssh at priority 100 on the subnet
    NSG kept SSH open on every isolated VM and let an SSH brute force through a block.
    """
    unreadable = sorted({i["nsg"] for i in issues if i.get("unreadable")})
    issues = [i for i in issues if not i.get("unreadable")]
    if not issues and not unreadable:
        return None
    if not issues:
        # An unreadable rule list is not "no allow before our deny".
        return AuditCheck(
            action="isolate_vm, block_suspicious_ip",
            name="NSG precedence",
            status="warn",
            message="Préséance non vérifiable : règles illisibles sur " + ", ".join(unreadable),
            fix="Vérifier le droit Microsoft.Network/networkSecurityGroups/securityRules/read, "
                "puis relancer l'audit",
            data={"precedence": [], "precedence_unreadable": unreadable},
        )
    rules: dict[tuple[str, str], dict] = {}
    for i in issues:
        entry = rules.setdefault((i["nsg"], i["rule"]), {**i, "actions": set()})
        entry["actions"].add(i["action"])
    parts, fixes = [], []
    for (nsg, rule), info in rules.items():
        parts.append(
            f"'{rule}' (priorité {info['priority']}, {info['direction']}, ports {info['ports']}) "
            f"sur {nsg} → contourne {', '.join(sorted(info['actions']))}"
        )
        rg, name = nsg.split("/", 1)
        fixes.append(f"az network nsg rule update -g {rg} --nsg-name {name} -n {rule} --priority 1000")
    message = "Règle(s) allow évaluée(s) avant les deny de Glorfindel : " + " ; ".join(parts)
    if unreadable:
        message += " (règles illisibles, non vérifié : " + ", ".join(unreadable) + ")"
    return AuditCheck(
        action="isolate_vm, block_suspicious_ip",
        name="NSG precedence",
        status="fail",
        message=message,
        fix=" ; ".join(fixes) + "  — placer les allow après la plage de Glorfindel (100–999)",
        data={"precedence": issues, "precedence_unreadable": unreadable},
    )

def _align_precedence(checks: list) -> None:
    """Judge « NSG precedence » as the readiness gate does (seventh review, P2).

    The card showed ✗ NSG where the gate said ready: with the quarantine NSG available,
    an allow before Glorfindel's deny can't get in an isolation's way (the NIC carries our
    deny-all), and for a block it is a reserve — a real bypass only if it opens the attack's
    port. The gate never fails on precedence; neither does the card now. Same inputs as the
    gate: the quarantine setting and the isolation rights the permissions check found
    missing (the release's own rights aside); unreadable permissions count as none missing,
    as the gate does (it shows them as a reserve of their own)."""
    prec = next((c for c in checks if c.name == "NSG precedence" and c.status == "fail"), None)
    if prec is None:
        return
    from glorfindel.readiness import _quarantine_enabled, isolation_by_quarantine

    perm = next((c for c in checks if c.name == "Isolation permissions"), None)
    missing = {m.get("action", "") for m in ((perm.data if perm else {}) or {}).get("missing_permissions") or []
               if m.get("used_by") != "release_isolation"}
    jit = isolation_by_quarantine(_quarantine_enabled(), missing)
    issues = prec.data.get("precedence") or []
    iso = sorted({i["rule"] for i in issues if i.get("action") == "isolate_vm"})
    blk = sorted({i["rule"] for i in issues if i.get("action") == "block_suspicious_ip"})
    reserves = []
    if iso and not jit:
        reserves.append("isolation par règles contournée : " + ", ".join(iso))
    if blk:
        reserves.append("blocage d'IP contourné si l'allow ouvre le port de l'attaque : " + ", ".join(blk))
    prec.data = {**prec.data, "isolation_by_quarantine": jit}
    note = (" L'isolation passe par le NSG de quarantaine : son deny-all suffit, ces allow ne la "
            "contournent pas." if iso and jit else "")
    if not reserves:
        prec.status, prec.action = "ok", "isolate_vm"
        prec.message = prec.message + "." + note
        return
    prec.status = "warn"
    prec.action = ", ".join(a for a, rules in (("isolate_vm", iso and not jit), ("block_suspicious_ip", blk)) if rules)
    prec.message = "Réserve (comme la préparation) — " + " ; ".join(reserves) + ". " + prec.message + "." + note


def _check_nsg(resource_id: str, connector) -> AuditCheck:
    rg = _rg(resource_id)
    res = connector.check_nsg_access(resource_id)

    if res.get("ok"):
        nsg = res.get("nsg", "")
        rules = res.get("rules", "?")
        nsgs = res.get("nsgs", [])
        # Multi-NIC: a VM with several NICs has several NSGs. Surface them all so the
        # War Room shows full coverage at rest (data.nsg = primary, kept for back-compat).
        extra = f" (+{len(nsgs) - 1} more NIC)" if len(nsgs) > 1 else ""
        access = AuditCheck(
            action="isolate_vm, block_suspicious_ip",
            name="NSG access",
            status="ok",
            message=f"NSG {nsg} readable ({rules} rules){extra}",
            data={"nsg": nsg, "nsg_scope": res.get("scope", ""), "nsgs": nsgs},
        )
        precedence = _check_precedence(res.get("precedence") or [])
        return [access, precedence] if precedence else access

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="isolate_vm, block_suspicious_ip",
            name="NSG access",
            status="fail",
            message=f"IAM: no permission on NSG — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Network Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{rg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("isolate_vm, block_suspicious_ip", "NSG access", err)
    return AuditCheck(
        action="isolate_vm, block_suspicious_ip",
        name="NSG access",
        status="fail",
        message=f"NSG not found or VM has no NSG — {err}",
        fix=f"Attach an NSG to the VM's NIC in resource group {rg}",
    )


def _check_backup(resource_id: str, connector, vault: str, vault_rg: str = "") -> AuditCheck:
    if not vault and not getattr(connector, "dry_run", False):
        from glorfindel.config import NO_VAULT_MSG
        return AuditCheck("restore_from_backup", "Backup vault", "fail",
                          "Restauration impossible : " + NO_VAULT_MSG,
                          "Déclarer le coffre dans action_backends de glorfindel-config.yaml.")
    rg = _rg(resource_id)
    vm = resource_id.split("/")[-1]
    # az backup commands are scoped to the VAULT's resource group, not the VM's.
    vrg = vault_rg or rg
    res = connector.check_backup_points(resource_id, vault, vault_rg)

    if res.get("dry_run"):
        return AuditCheck("restore_from_backup", "Backup vault", "skip", "Skipped in dry-run")

    if res.get("not_backupable"):
        # VMSS instance (e.g. AKS node) — IaaS-VM backup doesn't apply. Not a gap.
        return AuditCheck(
            action="restore_from_backup", name="Backup vault", status="skip",
            message=f"{vm} is a VMSS instance (e.g. AKS node) — not an IaaS-VM backup item",
            data={"not_backupable": True},
        )

    if res.get("ok"):
        points = res.get("points", 0)
        age_h = res.get("latest_age_h", 0)
        status: AuditStatus = "ok" if age_h < 48 else "warn"
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status=status,
            message=f"Vault '{vault}': {points} point(s), latest {age_h}h ago",
            fix=(
                "" if status == "ok" else
                f"az backup protection backup-now -g {vrg} -v {vault} "
                f"-c {vm} -i {vm} --backup-management-type AzureIaasVM"
            ),
            data={"protected": True, "points": points, "latest_age_h": age_h},
        )

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status="fail",
            message=f"IAM: no access to vault '{vault}' — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Backup Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{vrg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("restore_from_backup", "Backup vault", err)
    if res.get("protected"):
        # Protected but no recovery point yet — restore not yet possible, but the VM
        # IS linked. Warn (not fail), and the fix is to trigger the first backup.
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status="warn",
            message=f"{vm} protected in '{vault}' but no recovery point yet (first backup pending)",
            fix=(
                f"az backup protection backup-now -g {vrg} -v {vault} "
                f"-c {vm} -i {vm} --backup-management-type AzureIaasVM"
            ),
            data={"protected": True, "points": 0},
        )
    return AuditCheck(
        action="restore_from_backup",
        name="Backup vault",
        status="fail",
        message=f"Backup not configured for {vm} in '{vault}' — {err}",
        fix=(
            f"az backup protection enable-for-vm -g {vrg} -v {vault} "
            f"--vm {vm} --policy-name DefaultPolicy"
        ),
        data={"protected": False, "points": 0},
    )


def _check_compute(resource_id: str, connector) -> AuditCheck:
    rg = _rg(resource_id)
    vm = resource_id.split("/")[-1]
    res = connector.check_compute_access(resource_id)

    if res.get("dry_run"):
        return AuditCheck("snapshot", "Compute access", "skip", "Skipped in dry-run")

    if res.get("ok"):
        disks = res.get("disks", [])
        return AuditCheck(
            action="snapshot",
            name="Compute access",
            status="ok",
            message=f"VM {vm}: {len(disks)} disk(s) — {', '.join(disks[:2])}",
        )

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="snapshot",
            name="Compute access",
            status="fail",
            message=f"IAM: no access to VM {vm} — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Virtual Machine Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{rg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("snapshot", "Compute access", err)
    return AuditCheck(
        action="snapshot",
        name="Compute access",
        status="fail",
        message=f"VM {vm} not found in {rg} — {err}",
        fix=f"Verify the VM exists: az vm show -g {rg} -n {vm}",
    )


def _check_restore_staging(staging_storage: str) -> AuditCheck:
    """Restore readiness: is a staging storage account configured?

    Azure restores a VM by first writing the recovered disks to a throwaway storage
    account (not the vault's storage), then attaching them — required to restore from
    the immutable vault tier. Surfaced as a readiness gap at rest so the operator learns
    WHY it's needed *before* a ransomware incident, not mid-restore. Config-presence only
    (no Azure call) — verifying the SA exists/region is a follow-up.
    """
    if staging_storage:
        return AuditCheck(
            action="restore_from_backup",
            name="Restore staging",
            status="ok",
            message=f"staging account '{staging_storage}' configured",
            data={"staging_storage": staging_storage},
        )
    return AuditCheck(
        action="restore_from_backup",
        name="Restore staging",
        status="warn",
        message=(
            "No staging storage account — restore will stop. Azure needs a throwaway "
            "account to stage recovered disks when restoring from the immutable vault "
            "tier (not the vault's own storage). Detection/isolation are unaffected."
        ),
        fix=(
            "Set 'restore_staging_storage: <account>' on the azure_backup_vault backend "
            "in glorfindel-config.yaml (any Standard LRS account in the VM's region)."
        ),
        data={"staging_storage": ""},
    )


def _is_transient_error(err: str) -> bool:
    """True for an SDK/transport error (not a real IAM or config gap).

    A transient error must NOT be reported as "no NSG / not configured / not found"
    — that sends the operator chasing a phantom infra fix. Covers the lazy-import
    race and common transport failures.
    """
    markers = (
        "cannot import name", "_modulelock", "partially initialized",
        "connectionerror", "connection aborted", "timeout", "timed out",
        "temporarily unavailable", "service unavailable",
    )
    e = err.lower()
    return any(m in e for m in markers)


def _transient_check(action: str, name: str, err: str) -> AuditCheck:
    return AuditCheck(
        action=action,
        name=name,
        status="warn",
        message=f"Could not verify (transient SDK/transport error) — {err}",
        fix="Retry; if it persists, check the Azure SDK install and connectivity.",
    )


def _rg(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except StopIteration:
        return "?"
