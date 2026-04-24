# Eregion — Contexte projet pour Claude

## Concept

**Eregion** est une plateforme open-core de résilience opérationnelle organisée en modules Tolkien.
**Annatar** est le premier module — Security Chaos Engineering : simule des scénarios d'attaque réels (ransomware, exfiltration, lateral movement) sur l'infra en environnement contrôlé, mesure les temps de détection/isolation/recovery, et compare au RTO/RPO déclaré.

> "Annatar est déjà dans ta forteresse. La question c'est : est-ce que tu le sais ?"

## Naming

| Module | Nom | Rôle |
|---|---|---|
| Chaos Engine | **Annatar** | Simule les attaques (ce repo) |
| DR Coverage Scanner | **Celebrimbor** | Scanne les gaps de couverture DR (phase 2) |
| Drift Monitor | **Thranduil** | Surveille la dérive RTO/RPO en continu (SaaS futur) |
| Reports Pro | **Gil-galad** | Rapports PDF audit NIS2/DORA (SaaS futur) |
| War Room | **Fingolfin** | Guidance d'incident (SaaS futur) |
| Failover Canary | **Glorfindel** | Tests automatiques de failover (SaaS futur) |

## Stack technique

- **Language** : Python 3.11+
- **CLI** : Click (commande : `annatar`)
- **Azure SDK** : azure-mgmt-compute, azure-monitor-query, azure-mgmt-recoveryservicesbackup
- **Parsing** : PyYAML
- **Terminal** : rich
- **Infra test** : Terraform (dans `infra/terraform/`)
- **Tests** : pytest

## Architecture

```
eregion/                        # Racine du repo (encore nommé sechaos/ sur disque)
├── scenarios/                  # Scénarios YAML (MITRE ATT&CK mappés)
│   ├── azure/                  # MVP — cible principale
│   └── k8s/                    # Phase 2
├── annatar/                    # Package Python principal (module Chaos Engine)
│   ├── cli.py                  # Entrypoint Click
│   ├── runner/                 # engine.py, parser.py, report.py
│   ├── executors/              # azure_vm.py (MVP), kubernetes.py (phase 2)
│   ├── collectors/             # azure_monitor.py, prometheus.py
│   └── safety/                 # guard.py — safety checks obligatoires
├── infra/terraform/            # Provisioning env de test Azure
├── scripts/                    # Scripts exécutés sur les VMs de test
└── tests/
```

## Décisions structurantes

- **Azure VM first** (pas K8s) : les ransomwares frappent des VMs, pas des clusters. Marché plus large.
- K8s = phase 2, deuxième executor.
- **Scénarios en YAML** mappés MITRE ATT&CK, lisibles et contributables par la communauté.
- **Safety non négociable** : les scénarios ne tournent QUE sur des ressources taguées `sechaos-test: "true"`. Vérification dans `safety/guard.py` avant toute exécution.
- **Dry-run obligatoire** en mode dev (`--dry-run` flag).
- Rollback automatique sur erreur ou timeout.

## MVP — 2 scénarios Azure

### Scénario 1 : Ransomware VM
```
Script chiffre /mnt/testdata → Azure Monitor alerte sur pic I/O
→ Azure Backup restore déclenché → RTO mesuré vs déclaré
Métriques : detection_time_s, recovery_time_s
```

### Scénario 2 : Data exfiltration
```
Script transfère ~1GB vers storage account de test
→ Azure Monitor / NSG Flow Logs alerte sur trafic sortant anormal
Métriques : detection_time_s
```

## Format scénario YAML

```yaml
name: string
description: string
mitre: string                  # ATT&CK technique ID (ex: T1486)
version: "1.0.0"
target:
  type: azure_vm
  resource_group: string       # DOIT être tagué sechaos-test: "true"
  vm_name: string
setup: []                      # Actions de préparation
steps:
  - name: string
    action: string             # run_script_on_vm | apply_manifest | etc.
    record: T0                 # Timestamp de référence
detection:
  source: azure_monitor | prometheus
  query: string
  timeout: "300s"
  record: T1
recovery:
  action: azure_backup_restore
  record: T3
thresholds:
  detection_time_max: "120s"
  recovery_time_max: "1800s"
cleanup: []
```

## Output rapport JSON

```json
{
  "scenario": "azure-ransomware-vm",
  "run_id": "2026-04-23T14:32:00Z",
  "mitre": "T1486",
  "result": "FAIL",
  "metrics": {
    "detection_time_s": 87,
    "recovery_time_s": 3240
  },
  "thresholds": {
    "detection_time_max_s": 120,
    "recovery_time_max_s": 1800
  },
  "checks": {
    "detection": "PASS",
    "recovery": "FAIL — 54min vs RTO déclaré 30min"
  }
}
```

## CLI

```bash
annatar run <scenario.yaml> [--dry-run] [--yes]
annatar list
annatar validate <scenario.yaml>
annatar report <run-id>
annatar init       # Crée l'env Azure de test via Terraform
```

## Ressources Azure de test

Toutes dans `rg-sechaos-test`, taguées `sechaos-test: "true"` :
- `vm-sechaos-victim` : Ubuntu 22.04, Standard_B2s, disque data 32GB monté sur `/mnt/testdata`
- `law-sechaos` : Log Analytics Workspace
- `rsv-sechaos` : Recovery Services Vault + backup policy
- `st-sechaos-exfil` : Storage account cible exfiltration
- NSG avec flow logs activés

## Modèle open-core

- **Open source** : CLI Annatar, scénarios YAML, reporting JSON/Markdown — Apache 2.0
- **SaaS payant** (futur) : Thranduil (drift monitor), Gil-galad (PDF audit), Fingolfin (war room), Glorfindel (failover canary)

## Ce qu'on ne fait PAS en MVP

- Dashboard/UI (JSON + rich terminal suffisent)
- K8s scenarios
- PDF reports
- Multi-tenant, auth, scheduler
- IA/ML
- Proxmox/vSphere/GCP

## Cibles commerciales

- DevOps/SRE lead (100-500 salariés)
- RSSI PME/ETI — audits NIS2/ISO 27001
- Secteur financier — DORA (en vigueur jan 2025)
- MSP/MSSP

## Concurrence clé

- **Gremlin** : a un scénario ransomware mais $1200+/mois, pas open-core, pas compliance-oriented
- **Azure Chaos Studio** : chaos infra (pannes), pas sécurité — objection principale à démonter
- **Veeam SureBackup** : teste les backups, pas les attaques
- **BAS tools** (AttackIQ, Cymulate) : testent la détection, pas la recovery — $50-200k/an

## Critère MVP done

- 2 scénarios Azure bout en bout
- Rapport JSON PASS/FAIL par seuil
- `annatar init` opérationnel en < 5 min
- README : quelqu'un d'autre peut l'utiliser en 30 min
- GitHub public, Apache 2.0
