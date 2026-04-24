# Annatar — Security Chaos Engineering

**Simulate attacks. Measure real RTO/RPO. Prove your resilience.**

Annatar is the first module of the [Eregion](https://github.com/eregion) open-core platform. It runs realistic attack scenarios (ransomware, data exfiltration) against your own Azure infrastructure in a controlled environment, measures detection and recovery times, and compares them to your declared RTO/RPO.

> "Annatar is already in your fortress. The question is: do you know it?"

## Requirements

- Python 3.12+ (WSL/Linux recommended)
- Azure CLI authenticated (`az login`)
- Terraform >= 1.5
- Docker + make (optional, for containerized runs)

## Setup

```bash
# Clone
git clone https://github.com/eregion/annatar && cd annatar

# Install system dependencies and Python env
bash scripts/setup.sh

# Activate
source .venv/bin/activate
```

## Provision Azure Test Infrastructure

```bash
cd infra/terraform
terraform init

# Create terraform.tfvars with your SSH public key
echo 'admin_ssh_public_key = "'$(cat ~/.ssh/id_ed25519.pub)'"' > terraform.tfvars

terraform apply
```

After apply, update `log_analytics_workspace_id` in your scenario YAMLs with the output value:

```bash
terraform output log_analytics_workspace_id
```

## Usage

```bash
# List available scenarios
annatar list

# Validate a scenario
annatar validate scenarios/azure/ransomware-vm.yaml

# Dry run — shows execution plan without running anything
annatar run scenarios/azure/ransomware-vm.yaml --dry-run

# Run for real
annatar run scenarios/azure/ransomware-vm.yaml

# View a past report
annatar report <run-id>
```

### Docker

```bash
export AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... AZURE_TENANT_ID=... AZURE_SUBSCRIPTION_ID=...

make annatar-build
make annatar-dry-run
make annatar-run SCENARIO=scenarios/azure/ransomware-vm.yaml
```

## Scenarios

| Name | MITRE | What it tests |
|------|-------|---------------|
| `azure/ransomware-vm` | T1486 | File encryption detection + Azure Backup RTO |
| `azure/data-exfiltration` | T1041 | Outbound anomaly detection |

## Output

```
┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┓
┃ Check     ┃ Measured ┃ Threshold ┃ Status ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━┩
│ detection │ 130s     │ 180.0s    │ PASS   │
│ recovery  │ 188s     │ 1800.0s   │ PASS   │
└───────────┴──────────┴───────────┴────────┘
```

Full report saved as JSON in `runs/<run-id>.json`.

## Safety

- Scenarios only run on resource groups tagged `annatar-test: "true"` — enforced in `annatar/safety/guard.py`
- `--dry-run` shows execution plan without running anything
- Interactive confirmation before every run (bypass with `--yes`)
- Auto-rollback on error or timeout

## Cost Management

The test environment costs money when running. Destroy it between sessions:

```bash
cd infra/terraform && terraform destroy
```

## License

Apache 2.0 — scenarios, CLI, and JSON reporting are open source.
Commercial SaaS modules (drift monitoring, PDF audit reports, war room guidance) coming soon under the Eregion platform.
