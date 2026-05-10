# Annatar — Security Chaos Engineering

**Simulate attacks. Measure real RTO/RPO. Prove your resilience.**

Annatar is the first module of the [Eregion](https://github.com/eregion) open-core platform. It runs realistic attack scenarios (ransomware, data exfiltration) against your own Azure infrastructure in a controlled environment, measures detection and recovery times, and compares them to your declared RTO/RPO.

> "Annatar is already in your fortress. The question is: do you know it?"

## How it works

Annatar is **bring-your-own-monitoring**. It does not install agents, deploy SIEMs, or create backup policies. It tests the monitoring and backup you already have.

```
YOUR INFRASTRUCTURE                    ANNATAR
─────────────────────────────────────  ─────────────────────────────────────
Log Analytics Workspace ◄──── OMS ────  Test VM (provisioned by annatar init)
Recovery Services Vault ◄── Backup ───  Test VM
                                        │
                                        ▼
                                  Setup: initialize test volume
                                  T0: run attack script
                                  Poll YOUR LAW for alert → detection_s
                                  Trigger YOUR RSV restore
                                  Wait for Heartbeat in YOUR LAW → heartbeat_s
                                  Verify disk integrity
                                  Emit PASS/FAIL vs YOUR declared RTO
```

## Scenarios

| Name | MITRE | What it tests | Status |
|------|-------|---------------|--------|
| `azure/ransomware-vm` | T1486 | File encryption detection + Azure Backup RTO + disk integrity | ✅ |
| `azure/data-exfiltration` | T1041 | Outbound anomaly detection via NSG Flow Logs | 🚧 WIP |

## Requirements

- Python 3.12+ (Linux or WSL)
- Azure CLI authenticated (`az login`)
- Terraform >= 1.5
- An Azure subscription with Contributor access

## Installation

```bash
git clone https://github.com/eregion/annatar && cd annatar
bash scripts/setup.sh
source .venv/bin/activate
```

## Quick start

### 1. Provision the test environment

```bash
# Create terraform.tfvars with your SSH public key
echo 'admin_ssh_public_key = "'$(cat ~/.ssh/id_ed25519.pub)'"' > infra/terraform/terraform.tfvars

annatar init
```

This runs `terraform apply` and provisions:
- `vm-annatar-victim` — Ubuntu 22.04 test VM with a 32 GB data disk on `/mnt/testdata`
- `rsv-annatar` — Recovery Services Vault with a daily backup policy
- `law-annatar` — Log Analytics Workspace (OMS agent pre-installed on the VM)
- `st-annatar-exfil` — Storage account for exfiltration scenario

The workspace ID is printed at the end. It is already set in the scenario YAMLs if you use the default resource group.

### 2. Create the clean disk snapshot

The ransomware scenario restores the data disk via rsync from a clean snapshot. Create it once after `annatar init`, before the first run:

```bash
# Find the data disk created by Terraform
DATA_DISK_ID=$(az disk show -g annatar -n disk-annatar-testdata --query id -o tsv)

# Take a snapshot of the clean empty disk
az snapshot create -g annatar -n snap-annatar-testdata --source "$DATA_DISK_ID"
```

> **Why a separate snapshot?** Azure Backup V1 (Standard policy) restores the OS disk cleanly but does not restore the content of externally-attached managed disks. Annatar works around this by hot-attaching a disk created from this snapshot and rsyncing the clean state onto `/mnt/testdata` from inside the running VM.

### 3. Take the first backup

Trigger an on-demand backup so there is at least one recovery point before the first run:

```bash
annatar snapshot scenarios/azure/ransomware-vm.yaml
```

This cleans the VM disk, verifies its state, triggers a backup, and waits for the vault transfer to complete (~10-20 min). Only proceed to step 4 once this reports **green**.

### 4. Run the scenario

```bash
# Dry run first
annatar run scenarios/azure/ransomware-vm.yaml --dry-run

# Run for real
annatar run scenarios/azure/ransomware-vm.yaml
```

Expected duration: ~30-35 minutes (attack ~1 min, detection ~1-3 min, restore ~20-25 min).

## Output

```
┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┓
┃ Check     ┃ Measured ┃ Threshold ┃ Status ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━┩
│ detection │ 87s      │ 180.0s    │ PASS   │
│ recovery  │ 1355s    │ 1800.0s   │ PASS   │
└───────────┴──────────┴───────────┴────────┘
```

Full report saved as JSON in `runs/<run-id>.json`.

## Adapting to your own infrastructure

If you want to test your existing VM rather than the provisioned test environment, two fields in the scenario YAML connect Annatar to your infrastructure:

```yaml
target:
  type: azure_vm
  resource_group: your-rg         # Must be tagged annatar-test: "true"
  vm_name: your-vm
  log_analytics_workspace_id: "..." # Azure Portal → Log Analytics → Properties

recovery:
  vault: your-rsv-name
  data_disk_snapshot: your-snapshot-name   # Clean snapshot of /mnt/testdata equivalent
  time_max: "1800s"                        # Your declared RTO
```

Everything else (NSG, backup policy, alert rules, OMS agent) stays in your environment. Annatar just measures it.

## Re-running the scenario

After each run, Annatar restores the disk to clean state automatically. Before the next run you need a fresh backup (so there is a recovery point that predates the new attack):

```bash
annatar snapshot scenarios/azure/ransomware-vm.yaml
```

## CLI reference

```bash
annatar run <scenario>          # Run a scenario (interactive confirmation)
annatar run <scenario> --yes    # Skip confirmation
annatar run <scenario> --dry-run  # Show execution plan without running
annatar list                    # List available scenarios
annatar validate <scenario>     # Validate scenario YAML
annatar report <run-id>         # Display a past report
annatar init [<scenario>]       # Provision Azure infrastructure
annatar snapshot <scenario>     # Clean disk + on-demand backup (run before each test)
```

## Safety

- Scenarios only run on resource groups tagged `annatar-test: "true"` — hard-enforced in `annatar/safety/guard.py` before any action
- `--dry-run` shows the execution plan without running anything
- Interactive confirmation before every run (bypass with `--yes`)
- Attack scripts check for a safety marker (`/mnt/testdata/.annatar_test_marker`) before touching any file

## Cost

The test environment costs roughly **$2-5/day** when the VM is running (Standard_B2s + Premium_LRS disks + vault storage). Destroy it between sessions:

```bash
cd infra/terraform && terraform destroy
```

The `rsv-annatar` vault may block destroy if it has protected items. Remove the backup protection from the portal first, or use `az backup protection disable`.

## License

Apache 2.0 — CLI, scenarios, and JSON reporting are open source.  
Commercial SaaS modules (drift monitoring, PDF audit reports, war room) coming soon under the Eregion platform.
