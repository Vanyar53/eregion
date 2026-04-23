# SecurityChaos

**Simulate attacks. Measure real RTO/RPO. Prove your resilience.**

SecurityChaos is an open-core Security Chaos Engineering platform. It runs realistic attack scenarios (ransomware, data exfiltration, lateral movement) against your own infrastructure in a controlled environment, measures detection/isolation/recovery times, and compares them to your declared RTO/RPO.

> "You declare a 4-hour RTO and configured alerts. SecurityChaos tells you how long it actually takes — with an audit report."

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Provision Azure test environment
cd infra/terraform
terraform init
terraform apply -var="admin_ssh_public_key=$(cat ~/.ssh/id_rsa.pub)"

# Update log_analytics_workspace_id in your scenario YAML
# (value from: terraform output log_analytics_workspace_id)

# Validate a scenario
sechaos validate scenarios/azure/ransomware-vm.yaml

# Dry run
sechaos run scenarios/azure/ransomware-vm.yaml --dry-run

# Run for real
sechaos run scenarios/azure/ransomware-vm.yaml
```

## Requirements

- Python 3.11+
- Azure CLI authenticated (`az login`)
- Terraform >= 1.5 (for test infra provisioning)

## Scenarios

| Name | MITRE | What it tests |
|------|-------|---------------|
| `azure/ransomware-vm` | T1486 | Ransomware detection + backup RTO |
| `azure/data-exfiltration` | T1041 | Outbound anomaly detection |

## Output

```json
{
  "scenario": "azure-ransomware-vm",
  "result": "FAIL",
  "metrics": { "detection_time_s": 87, "recovery_time_s": 3240 },
  "checks": {
    "detection": "PASS",
    "recovery": "FAIL — 54min vs declared RTO 30min"
  }
}
```

## Safety

- Scenarios only execute on resources tagged `sechaos-test: "true"`
- `--dry-run` shows execution plan without running anything
- Auto-rollback on error or timeout
- Interactive confirmation before execution (bypass with `--yes`)

## License

Apache 2.0
