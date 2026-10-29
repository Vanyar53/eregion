"""restore_from_backup (human-approved): the newest recovery point before the attack —
never without knowing when it began (SEC4c) —, Run Command scripts neutralised first
(moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.sdk import _enum_text, rest_post
from glorfindel.response.ids import _parse_vm_resource_id
from glorfindel.response.policy import _console, _ERR_MAX, _first_line


class RestoreMixin:
    """The restore from backup (part of AzureConnector)."""

    def restore_from_backup(
        self,
        resource_id: str,
        vault: str = "",
        before_attack_time: str | None = None,
        wait: bool = True,
        staging_storage: str = "",
        vault_rg: str = "",
    ) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "restore_from_backup", "resource_id": resource_id}

        self._guard_write("restore_from_backup")
        # Never the newest point by default (SEC4c): it may have been taken after the attack.
        if not before_attack_time:
            raise RuntimeError(
                "restore_from_backup : moment de l'attaque inconnu — le point le plus récent "
                "peut être postérieur à l'attaque ; donner before_attack_time "
                "(`glorfindel restore --before`).")
        if not vault:
            from glorfindel.config import NO_VAULT_MSG
            raise RuntimeError(NO_VAULT_MSG)
        import time
        from datetime import datetime, timezone
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        # Vault calls are scoped to the VAULT's resource group (a central vault protects
        # VMs across RGs); the container name stays keyed by the VM's RG.
        v_rg = vault_rg or rg
        sub = self._subscription_id
        fabric = "Azure"

        backup_client = RecoveryServicesBackupClient(self._credential, sub)
        # Stored names, not hand-built ones: recovery_points.list is case-sensitive
        # (lowercase prefixes returned an EMPTY list on the Celebrimbor bench → "No
        # recovery points" on a VM that has some).
        container_name, item_name = self._resolve_backup_item_names(
            backup_client, vault, v_rg, rg, vm_name)

        rps = list(backup_client.recovery_points.list(vault, v_rg, fabric, container_name, item_name))
        if not rps:
            raise RuntimeError(f"No recovery points in vault {vault}")

        def _has_vault_tier(rp) -> bool:
            return any(
                t.type == "HardenedRP" and getattr(t, "status", "") == "Valid"
                for t in (getattr(rp.properties, "recovery_point_tier_details", None) or [])
            )

        def _rp_time(rp):
            return getattr(rp.properties, "recovery_point_time", None)

        # The most recent clean recovery point — it must predate the attack, or the
        # restored disk already holds what the attack did. A point without a time can't be
        # placed before anything: never taken.
        attack_dt = datetime.fromisoformat(before_attack_time.replace("Z", "+00:00"))
        if attack_dt.tzinfo is None:
            attack_dt = attack_dt.replace(tzinfo=timezone.utc)
        attack_dt = attack_dt.astimezone(timezone.utc)
        pre_attack = [
            rp for rp in rps
            if _rp_time(rp) is not None and _rp_time(rp) < attack_dt
        ]
        if not pre_attack:
            raise RuntimeError(
                f"No recovery point found before attack time {before_attack_time}. "
                "A backup may have run during the attack. Check the portal."
            )

        # Prefer the immutable vault tier, then the NEWEST point by its timestamp.
        # Taking pool[0] relied on the order Azure happens to list points in.
        vaulted = [rp for rp in pre_attack if _has_vault_tier(rp)]
        latest = max(vaulted or pre_attack, key=_rp_time)
        rp_time = _rp_time(latest)
        _console.print(f"  [dim]Using pre-attack recovery point: {rp_time}[/dim]")

        vm = self._compute.virtual_machines.get(rg, vm_name)
        if not staging_storage:
            raise RuntimeError(
                "Restore needs a staging storage account, and none is configured.\n"
                "  Why: to restore a VM from the immutable vault tier (the copy an "
                "attacker can't have tampered — the one you want after ransomware), "
                "Azure temporarily writes the recovered disks to a scratch storage "
                "account, then attaches them. This is NOT the vault's storage; it's a "
                "throwaway staging area in the same region/subscription.\n"
                "  Fix: set 'restore_staging_storage: <account>' on the "
                "azure_backup_vault backend in glorfindel-config.yaml (any Standard "
                "LRS account in the VM's region works; `make celebrimbor-output` "
                "generates it for the Celebrimbor sandbox)."
            )
        # Staging SA co-located with the VM's RG (Celebrimbor sandbox). A staging SA in a
        # different RG would need its own rg field — refinement (cf. vault cross-RG).
        storage_id = (
            f"/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.Storage/storageAccounts/{staging_storage}"
        )

        # Before the disks are swapped: the restored disk would otherwise REPLAY the last
        # Run Command at boot (real run, 2026-10-05: ransomware_sim.sh re-encrypted the
        # restored data). An attacker who used Run Command (T1651) gets the same replay.
        neutralize = self._neutralize_run_command(rg, vm_name, vm)

        self._compute.virtual_machines.begin_deallocate(rg, vm_name).result()

        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{v_rg}/providers/Microsoft.RecoveryServices/vaults/{vault}"
            f"/backupFabrics/Azure/protectionContainers/{container_enc}"
            f"/protectedItems/{item_enc}/recoveryPoints/{latest.name}/restore"
            f"?api-version=2021-10-01"
        )
        data_luns = [d.lun for d in (vm.storage_profile.data_disks or [])]
        payload = {
            "properties": {
                "objectType": "IaasVMRestoreRequest",
                "recoveryPointId": latest.name,
                "recoveryType": "OriginalLocation",
                "sourceResourceId": vm.id,
                "storageAccountId": storage_id,
                "region": vm.location,
                "affinityGroup": "",
                "createNewCloudService": False,
                "originalStorageAccountOption": False,
                "skipPreOLRBackup": True,
                "targetVirtualMachineId": None,
                "targetResourceGroupId": None,
                "restoreDiskLunList": data_luns,
            }
        }

        triggered_at = datetime.now(timezone.utc)
        r = rest_post(url, "Déclenchement du restore (VM désallouée)", json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Restore trigger failed ({r.status_code}): {r.text[:300]}")

        restore_job = self._find_backup_job(
            backup_client, vault, v_rg, "Restore", vm_name, triggered_at, delay_s=15.0)
        if restore_job is None:
            raise RuntimeError(f"Restore job for {vm_name} not found after trigger")

        _console.print(f"  [dim]Tracking job {restore_job.name} (15-30 min expected)...[/dim]")

        if not wait:
            return {
                "status": "restore_triggered",
                "job_name": restore_job.name,
                "vault": vault,
                # `rg` is the resource group job lookups run against (jobs.refresh_job):
                # the VAULT's. The VM's own RG is kept separately.
                "rg": v_rg,
                "vault_rg": v_rg,
                "vm_rg": rg,
                "recovery_point": latest.name,
                "recovery_point_time": str(rp_time),
                "recovery_point_vault_tier": bool(vaulted),
                "before_attack_time": before_attack_time,
                "resource_id": resource_id,
                **neutralize,
            }

        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault, v_rg, restore_job.name)
            status = getattr(job.properties, "status", "Unknown")
            _console.print(f"  [dim]Still restoring... {elapsed // 60}min elapsed — {status}[/dim]")
            if status in ("Completed", "Failed", "Cancelled"):
                break

        if status != "Completed":
            raise RuntimeError(f"Restore ended with status: {status}")

        _console.print("  [dim]Starting VM after restore...[/dim]")
        self._compute.virtual_machines.begin_start(rg, vm_name).result()

        return {
            "status": "restored",
            "recovery_point": latest.name,
            "recovery_point_time": str(rp_time),
            "recovery_point_vault_tier": bool(vaulted),
            "before_attack_time": before_attack_time,
            "resource_id": resource_id,
            **neutralize,
        }

    def _neutralize_run_command(self, rg: str, vm_name: str, vm) -> dict:
        """Make a harmless command the VM's last Run Command.

        The guest agent of a restored disk replays the Run Command whose sequence number
        it has not seen yet: the last one in the VM model, i.e. the attacker's (or, on
        the bench, Annatar's attack script). Running a no-op first makes the replay
        harmless. Works on an isolated VM (Run Command goes through the platform
        address 168.63.129.16, which NSGs don't filter — measured 2026-10-05). Needs a
        running VM; on failure the restore still proceeds (recovery first) and the
        result says so, which holds the autonomous release.
        """
        from azure.mgmt.compute.models import RunCommandInput
        os_type = _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", "") or "")
        if "windows" in os_type.lower():
            cmd = RunCommandInput(command_id="RunPowerShellScript",
                                  script=["Write-Output 'glorfindel: run command neutralized'"])
        else:
            cmd = RunCommandInput(command_id="RunShellScript",
                                  script=["echo 'glorfindel: run command neutralized'"])
        try:
            poller = self._compute.virtual_machines.begin_run_command(rg, vm_name, cmd)
            poller.result(timeout=600)
            # result(timeout) returns at the deadline without raising: "neutralized"
            # must mean the harmless command actually finished (third review, T13).
            if not poller.done():
                raise TimeoutError("la commande inoffensive n'a pas terminé en 600 s")
            others = self._replayable_scripts(rg, vm_name)
            if others:
                # Run Command v1 is neutralized, but these replay the same way on a
                # restored disk and Glorfindel can't vouch for them: hold the release.
                return {"run_command_neutralized": False, "replay_vectors": others,
                        "run_command_error": "autres scripts rejouables sur la VM : " + ", ".join(others)}
            return {"run_command_neutralized": True}
        except Exception as e:
            _console.print(
                f"  [yellow]Run Command non neutralisée ({_first_line(e)[:_ERR_MAX]}) — le "
                "disque restauré peut rejouer la dernière commande au démarrage.[/yellow]")
            return {"run_command_neutralized": False,
                    "run_command_error": _first_line(e)[:_ERR_MAX]}

    # Extensions a restored disk may run again without Glorfindel vouching for a script:
    # agents that take no command from the VM model — monitoring, security, backup,
    # sign-in, patching, attestation, inventory. Any other holds the release:
    # CustomScript, VMAccess (it resets users and SSH keys: an attacker's key comes
    # back), DSC, Chef, a third party's — and Guest Configuration, which applies what a
    # policy assigns (a configuration, a script through it): kept out on purpose. The
    # list of the dangerous ones it replaces (three CustomScript names) missed every one
    # of those (L23, A3). Publisher and type names as documented — to measure on the
    # bench, which only has AMA (A3, first review).
    _REPLAY_SAFE_EXTENSIONS = frozenset({
        ("microsoft.azure.monitor", "azuremonitorlinuxagent"),
        ("microsoft.azure.monitor", "azuremonitorwindowsagent"),
        ("microsoft.enterprisecloud.monitoring", "omsagentforlinux"),
        ("microsoft.enterprisecloud.monitoring", "microsoftmonitoringagent"),
        ("microsoft.azure.monitoring.dependencyagent", "dependencyagentlinux"),
        ("microsoft.azure.monitoring.dependencyagent", "dependencyagentwindows"),
        ("microsoft.azure.diagnostics", "linuxdiagnostic"),
        ("microsoft.azure.diagnostics", "iaasdiagnostics"),
        ("microsoft.azure.recoveryservices", "vmsnapshot"),
        ("microsoft.azure.recoveryservices", "vmsnapshotlinux"),
        ("microsoft.azure.networkwatcher", "networkwatcheragentlinux"),
        ("microsoft.azure.networkwatcher", "networkwatcheragentwindows"),
        ("microsoft.azure.activedirectory", "aadsshloginforlinux"),
        ("microsoft.azure.activedirectory", "aadloginforwindows"),
        ("microsoft.azure.azuredefenderforservers", "mde.linux"),
        ("microsoft.azure.azuredefenderforservers", "mde.windows"),
        ("microsoft.azure.security", "iaasantimalware"),
        ("microsoft.azure.security.linuxattestation", "guestattestation"),
        ("microsoft.azure.security.windowsattestation", "guestattestation"),
        ("microsoft.cplat.core", "linuxpatchextension"),
        ("microsoft.cplat.core", "windowspatchextension"),
        ("microsoft.softwareupdatemanagement", "linuxosupdateextension"),
        ("microsoft.softwareupdatemanagement", "windowsosupdateextension"),
        ("microsoft.azure.changetrackingandinventory", "changetracking-linux"),
        ("microsoft.azure.changetrackingandinventory", "changetracking-windows"),
        ("microsoft.compute", "bginfo"),
        # Run Command's handlers: v1's last command is the harmless one just run; v2's
        # commands are resources of their own, listed below.
        ("microsoft.cplat.core", "runcommandlinux"),
        ("microsoft.cplat.core", "runcommandhandlerlinux"),
        ("microsoft.cplat.core", "runcommandhandlerwindows"),
    })

    def _replayable_scripts(self, rg: str, vm_name: str) -> list[str]:
        """Extensions outside the allowlist and managed Run Commands (v2, `runCommands`
        resources) on the VM: like Run Command v1, a restored disk can run them again at
        boot. Unreadable → reported as such (no success on an unknown)."""
        found: list[str] = []
        try:
            for ext in self._compute.virtual_machine_extensions.list(rg, vm_name).value or []:
                # azure-mgmt-compute 38 nests publisher/type under `properties` (the
                # top-level `type` is the ARM resource type); older SDKs flattened them
                # as publisher / type_properties_type — read whichever is there.
                d = ext.as_dict() if hasattr(ext, "as_dict") else {}
                props = d.get("properties") or {}
                key = (str(props.get("publisher") or d.get("publisher") or getattr(ext, "publisher", "") or "").lower(),
                       str(props.get("type") or d.get("type_properties_type")
                           or getattr(ext, "type_properties_type", "") or "").lower())
                if key not in self._REPLAY_SAFE_EXTENSIONS:
                    found.append(f"extension {ext.name}" + ("" if all(key) else " (éditeur ou type illisible)"))
        except Exception as e:
            found.append(f"extensions illisibles ({_first_line(e)[:120]})")
        try:
            for rc in self._compute.virtual_machine_run_commands.list_by_virtual_machine(rg, vm_name):
                found.append(f"run command managé {rc.name}")
        except Exception as e:
            found.append(f"run commands managés illisibles ({_first_line(e)[:120]})")
        return found
