# Eregion — Contexte projet pour Claude

## Concept

**Eregion** est une plateforme de **défense active de l'infra cloud**.

> "On simule ce que ferait un attaquant sur ton infra cloud. On te montre ce qui tombe. On ferme automatiquement ce qui peut l'être. Tu vois la différence avant et après."

Pas de la détection passive. Pas de la compliance. Une boucle complète : simuler l'attaque → produire des signaux → répondre automatiquement → prouver que c'est fermé.

**Stack** : Python 3.11+, Azure (provider initial), cloud agnostique par design.

---

## Les deux agents

### Annatar — Agent Rouge (MVP ✅)
- Chaos engine qui simule des attaques réelles (ransomware T1486, exfiltration T1041)
- Scénarios YAML mappés MITRE ATT&CK, bout en bout, rapport JSON PASS/FAIL
- Produit des signaux normalisés indépendants du provider
- Tourne **uniquement** sur ressources taguées `annatar-test: "true"`
- **Rôle strict** : pre-check intégrité → attaque → émet `attack_started` → done
- Ne poll pas la détection, ne restore pas la VM — ce sont les rôles de Glorfindel

**Entraînement** : connaissance structurée, pas ML — base MITRE ATT&CK + CVEs publics cloud.

### Glorfindel — Agent Bleu (MVP ✅ — run réel validé)
- Reçoit les signaux normalisés d'Annatar (JSONL)
- **Poll la détection** (Azure Monitor) quand `attack_started` arrive — calcule `detection_s`
- Raisonne via Claude API (tool use), décide de la réponse, explique le pourquoi
- Agit seul sur actions réversibles, escalade à l'humain sur actions destructives ou inconnues
- Vérifie que l'action a eu l'effet voulu (ex : règle NSG bien posée)
- Propose des actions nouvelles si aucune action connue ne convient — l'humain valide
- **Possède le RTO complet** : detection_s + isolation_s + restore_time

**Mode watch** : `glorfindel watch runs/` — poll toutes les 2s, répond en temps réel pendant qu'Annatar tourne.

**Apprentissage** : chaque cycle `(signal → décision → action → outcome)` est stocké dans ChromaDB. Les 3 cycles les plus similaires sont injectés comme contexte à chaque décision.

**Lien fondamental** : plus Annatar attaque, plus Glorfindel apprend.

---

## Boucle complète (état actuel)

```
Annatar
  pre-check intégrité VM (valide restore précédent)
  → setup
  → attaque (T0)
  → émet attack_started {T0, detection_query, workspace_id}
  → done

Glorfindel (watch ou respond)
  poll_detection : Azure Monitor toutes les 10s
  → détecte (detection_s) ou timeout
  → émet detection ou detection_timeout
  → décide : isolate_vm (autonome)
  → vérifie : règles NSG présentes
  → store cycle (ChromaDB)

Humain
  glorfindel restore <resource_id> --yes   (human-approved)
  → restore Azure Backup (~20 min)
  → émet recovery_complete signal inline
  → Glorfindel décide : release_isolation (autonome, idempotent)
  → vérifie : isolation absente
  → store cycle
```

RTO validé en réel (2026-05-24, run 2) : detect 50s + isolate 9s + restore 20min 20s + release 4s ≈ 21min 23s (hors décision humaine)

T1041 validé en réel (2026-05-24, run 3) : detect 229s + isolate 10s (via StorageBlobLogs — near-realtime)

T1110.001 validé en réel (2026-05-24, run 4) : detect 60s + block_suspicious_ip 7s = RTO 67s (via Syslog DCR — Tor exit node 185.220.101.1 bloqué au NSG, isolate_vm non requis)

---

## Architecture — Cloud agnostique

Les TTPs des attaquants ne changent pas selon le cloud provider. Seuls les connecteurs changent.

```
Scénarios d'attaque (universels — MITRE ATT&CK)
        ↓
Connecteurs cloud (Azure existant / AWS et GCP à venir)
        ↓
Signaux normalisés
        ↓
Glorfindel (universel — raisonne + décide)
        ↓
Actions via connecteurs cloud
        ↓
Vérification
```

Modèle inspiré de Terraform : logique agnostique, providers interchangeables.

---

## Règles d'autonomie de Glorfindel

```python
# Réversible — Glorfindel agit seul
AUTONOMOUS_ACTIONS = [
    "isolate_vm",
    "release_isolation",   # inverse de isolate_vm — autonome par symétrie
    "revoke_temp_access",
    "snapshot",            # forensic snapshot of compromised state
    "block_suspicious_ip",
]

# Destructif — validation humaine obligatoire
HUMAN_APPROVAL_REQUIRED = [
    "delete_resource",
    "modify_network_rule",
    "escalate_permissions",
    "wipe_storage",
    "restore_from_backup",  # remplace les disques — irréversible sans backup supplémentaire
]
```

---

## Naming

| Module | Nom | Rôle | Statut |
|---|---|---|---|
| Agent Rouge | **Annatar** | Simule les attaques — corrompt de l'intérieur | MVP Azure ✅ |
| Agent Bleu | **Glorfindel** | Détecte, répond, rétablit — revient toujours | MVP fonctionnel ✅ |

---

## Stack technique

- **Language** : Python 3.11+
- **CLI** : Click (commandes : `annatar`, `glorfindel`)
- **Azure SDK** : azure-mgmt-compute, azure-monitor-query, azure-mgmt-recoveryservicesbackup
- **Parsing** : PyYAML
- **Terminal** : rich
- **Infra test** : Terraform (`infra/terraform/`)
- **Tests** : pytest
- **Agent framework** : LangGraph — `load_context → poll_detection → decide → execute_action → verify_action → store_cycle`
- **LLM** : Claude API (Anthropic) — raisonnement structuré, tool use natif, alignement sécurité
- **Vector store** : ChromaDB local (fichier, zéro serveur) — OSS ; base collective sur serveur Eregion en SaaS

---

## Architecture fichiers

```
eregion/
├── scenarios/           # Scénarios YAML MITRE ATT&CK
│   └── azure/           # ransomware-vm.yaml, data-exfiltration.yaml, lateral-movement.yaml
├── annatar/             # Package Agent Rouge
│   ├── cli.py
│   ├── runner/          # engine.py, parser.py, report.py
│   ├── executors/       # azure_vm.py (resource_id property)
│   ├── collectors/      # azure_monitor.py (heartbeat + poll_alert)
│   ├── safety/          # guard.py — safety checks obligatoires
│   └── signals/         # schema.py (Signal, severity_for_ttp), emitter.py
├── glorfindel/          # Package Agent Bleu
│   ├── agent.py         # LangGraph : load_context→poll_detection→decide→execute→verify→store
│   ├── signals.py       # load_signals(), load_latest_signals()
│   ├── actions.py       # CloudConnector ABC, AzureConnector, AUTONOMOUS_ACTIONS
│   ├── detectors.py     # DetectionConnector ABC, AzureMonitorDetector, detector_for()
│   ├── escalations.py   # record/resolve/pending — ~/.glorfindel/escalations.jsonl
│   ├── memory.py        # CycleMemory (ChromaDB)
│   └── cli.py           # respond, watch, restore, release, pending, ack, memory-stats
├── scripts/
│   └── simulate_annatar.py  # simulation locale sans Azure
├── runs/                # Rapports JSON + signaux JSONL (gitignored)
├── infra/terraform/
├── Dockerfile           # image eregion, entrypoint annatar ou glorfindel
├── Makefile             # targets annatar-* et glorfindel-*
└── tests/
```

---

## Format signal normalisé (Annatar → Glorfindel)

```python
signal = {
    "signal_id": "{run_id}_{event}",
    "timestamp": "ISO8601",
    "provider": "azure",
    "resource_id": "/subscriptions/.../virtualMachines/...",
    "resource_type": "vm|storage|network",
    "ttp": "T1486",
    "severity": "critical|high|medium|low",
    "event": "attack_started|detection|detection_timeout|recovery_complete|recovery_failed",
    "raw_signal": {},
    "context": {"run_id": "...", "scenario": "..."}
}
```

### Événements et contenu raw_signal

| Event | Émis par | raw_signal clés |
|---|---|---|
| `attack_started` | Annatar | `attack_time`, `detection_query`, `detection_source`, `detection_timeout_s`, `detection_max_s`, `log_analytics_workspace_id` |
| `detection` | Glorfindel (poll_detection) | `detection_time_s`, `detected_data` (première ligne résultat) |
| `detection_timeout` | Glorfindel (poll_detection) | — |
| `recovery_complete` | `glorfindel restore` CLI | `recovery_point_time`, `restore_time_s` |
| `recovery_failed` | `glorfindel restore` CLI | `error`, `status` |

Annatar écrit `runs/{run_id}_signals.jsonl`. Glorfindel le lit via `watch` ou `respond`.
`recovery_complete` est écrit dans `runs/recovery/{run_id}_signals.jsonl` (hors portée de watch) puis traité inline.

---

## Ressources Azure de test

Toutes dans `rg: annatar`, taguées `annatar-test: "true"` (déployées via `infra/terraform/`) :
- `vm-annatar-victim` : Ubuntu 22.04, Standard_D2as_v6, 32GB sur `/mnt/testdata`
- `law-annatar` : Log Analytics Workspace (`b451c51a-1cd0-4125-ac70-6aaf2c1dc209`)
- `rsv-annatar` : Recovery Services Vault + backup policy
- `stannatarexfil` : Storage account cible exfiltration — diagnostic settings activés (`StorageBlobLogs` → `law-annatar`)
- `nsg-annatar` : NSG attaché au **subnet** (pas au NIC) — fallback implémenté dans `_get_nic_nsg`
- VNet flow logs activés sur `vnet-annatar` → Traffic Analytics → `law-annatar` (10 min interval, peuple `AzureNetworkAnalytics_CL`)

VM auto-shutdown 23h00 UTC — `az vm start -g annatar -n vm-annatar-victim` avant chaque run.

---

## Runbook opérateur

```bash
# 1. Démarrer la VM si nécessaire
az vm start -g annatar -n vm-annatar-victim

# CRITIQUE — vérifier l'état d'isolation avant chaque run
# Une isolation active bloque AMA (outbound deny-all) → syslog non uploadé → detection timeout
az network nsg rule list -g annatar --nsg-name nsg-annatar -o table  # chercher glorfindel-isolation-*
# Si la VM est encore isolée :
echo y | glorfindel release /subscriptions/44a4dc83-3e79-4e4e-aa93-1b4f8e3ede80/resourceGroups/annatar/providers/Microsoft.Compute/virtualMachines/vm-annatar-victim

# 2. Lancer Glorfindel en watch (terminal 1)
glorfindel watch runs/

# 3a. Scénario ransomware (terminal 2)
annatar run scenarios/azure/ransomware-vm.yaml

# 3b. Scénario exfiltration (terminal 2)
annatar run scenarios/azure/data-exfiltration.yaml
# détection via StorageBlobLogs (~229s) → isolate_vm autonome

# 3c. Scénario lateral movement SSH brute force (terminal 2)
annatar run scenarios/azure/lateral-movement.yaml
# détection via Syslog DCR (~60s) → block_suspicious_ip autonome (IP externe uniquement)

# 4. Attendre que Glorfindel isole la VM (automatique)

# 5. Restore humain (terminal 3) — IMPORTANT: passer --before T0 de l'attaque
#    pour éviter de restaurer un backup post-attaque
glorfindel restore \
  /subscriptions/44a4dc83-3e79-4e4e-aa93-1b4f8e3ede80/resourceGroups/annatar/providers/Microsoft.Compute/virtualMachines/vm-annatar-victim \
  --yes \
  --before 2026-05-24T13:44:00+00:00   # timestamp T0 du run Annatar
# → restore (~20 min) → recovery_complete → Glorfindel release_isolation

# Mode forensique (garder la VM isolée après restore)
glorfindel restore ... --yes --keep-isolated
# ou export GLORFINDEL_KEEP_ISOLATED=1
```

---

## Positionnement concurrentiel

| | Lupovis | CrowdStrike/Palo Alto | Eregion |
|---|---|---|---|
| Approche | Déception passive | Détection enterprise | Simulation active |
| Boucle | Détection seulement | Détection + alerte | Rouge → Bleu complet |
| Cible | Enterprise/OT | Enterprise | Mid-market DevOps |
| Modèle | SaaS | SaaS cher | Open-core |
| Réponse | Alerte + SIEM | Manuel | Agent IA automatisé |

---

## Prochaines tâches

1. ✅ Normaliser les signaux Annatar (`annatar/signals/`)
2. ✅ Premier agent Glorfindel : signal ransomware → décision expliquée + `isolate_vm`
3. ✅ Fermer la boucle : `verify_isolation` → escalade si échec, `store_cycle` en mémoire
4. ✅ `glorfindel release <resource_id>` — lever une isolation
5. ✅ `glorfindel watch runs/` — deux agents concurrents, réponse en temps réel
6. ✅ Action discovery — Glorfindel peut proposer des actions inconnues
7. ✅ Run réel Azure end-to-end (2026-05-24) — RTO ~20min 49s validé
8. ✅ Glorfindel poll détection (`poll_detection` + `DetectionConnector` ABC) — Annatar émet `attack_started`
9. ✅ `glorfindel restore` émet `recovery_complete` → Glorfindel `release_isolation` autonome (run 2 validé)
10. ✅ `glorfindel pending` / `ack` — escalades persistées, webhook optionnel (`GLORFINDEL_WEBHOOK_URL`)
11. ✅ `block_suspicious_ip` + `verify_block_ip` implémentés dans `AzureConnector`
12. ✅ Scénario T1041 validé en réel — détection via `StorageBlobLogs` (229s), `isolate_vm` autonome, RAG cross-scénario
13. ✅ Observabilité — `runs/{run_id}_debug.jsonl`, `confidence` + `past_cycles_used` dans ChromaDB, label self-reported
14. ✅ `glorfindel restore --before ISO8601` — sélection recovery point pre-attaque
15. ✅ Engine Annatar : setup avant integrity check — Annatar nettoie ses propres résidus
16. ✅ Scénario T1110.001 validé en réel — detect 60s + block_suspicious_ip 7s, Syslog DCR, IP externe Tor bloquée au NSG

**Milestone : MVP Azure complet — 3 TTPs validés en réel, boucle rouge→bleu fonctionnelle**

Prochaines priorités :
17. `verify_block_ip` : tester la vérification sur le run T1110.001 (déjà confirmée ✓ mais ajouter test unitaire)
18. Scénario privilege escalation (T1068 ou T1548) — tester une action post-compromise interne
19. Pytest : couverture unitaire des nodes LangGraph (decide, verify, store_cycle) avec signaux mockés
20. `glorfindel check-ttl` : intégrer en cron (crontab ou systemd timer) pour auto-release après 4h
21. Packaging OSS : pyproject.toml, README, CONTRIBUTING, licence Apache 2.0
22. AWS provider : `AwsConnector(CloudConnector)` — Security Groups pour isolate_vm, GuardDuty pour detection

---

## Décisions techniques arrêtées

### LangGraph — Graph Glorfindel

```
load_context → poll_detection → decide → execute_action → verify_action → store_cycle
                                    ↓ (escalate)
                              escalate_to_human → store_cycle
```

`poll_detection` : no-op sauf si `event == attack_started`. Dans ce cas, poll Azure Monitor
jusqu'à détection ou timeout, puis convertit l'event en `detection` (avec `detection_time_s`)
ou `detection_timeout` avant que `decide` ne voie le signal.

### Responsabilités strictes

| Périmètre | Annatar | Glorfindel | Humain |
|---|---|---|---|
| Pré-check intégrité VM | ✅ | | |
| Simulation attaque | ✅ | | |
| Poll détection Azure Monitor | | ✅ | |
| Isolation NSG | | ✅ (autonome) | |
| Release isolation | | ✅ (autonome) | |
| Restore Azure Backup | | escalade → | ✅ |
| Mesure RTO | | ✅ | |

### Format de décision Glorfindel

```python
decision = {
    "signal_id": "...",
    "reasoning": "...",          # chaîne de pensée LLM
    "confidence": 0.0–1.0,
    "action": "isolate_vm",      # action connue ou proposée (snake_case libre)
    "reversible": True,
    "explanation": "...",        # version lisible pour l'humain
    "escalate": False,
    "escalation_reason": "...",  # rempli si escalate=True ou action inconnue
    "outcome": {                 # rempli après exécution
        "status": "isolated|dry_run|escalated",
        "verified": True,        # résultat de verify_action
        "escalation_type": "destructive_action|proposed_action|low_confidence"
    }
}
```

### Comportement par type d'événement

| Event | Posture | Action | Escalade |
|---|---|---|---|
| `attack_started` | — | poll_detection (node, pas une action LLM) | — |
| `detection` (T1486/T1041 IP interne) | Attaque confirmée | `isolate_vm` | Non |
| `detection` (T1110 IP externe) | Attaque périmètre | `block_suspicious_ip` | Non |
| `detection_timeout` | Gap IDS | `snapshot` (forensique non-disruptif) | Oui — expliquer le gap |
| `recovery_complete` | VM propre après restore | `release_isolation` (idempotent) | Non |
| `recovery_failed` | Restore échoué | Escalade | Oui |

### Vérification post-action

| Action | Méthode | Succès = |
|---|---|---|
| `isolate_vm` | `verify_isolation` → Azure NSG API | règles deny-all présentes |
| `release_isolation` | `verify_isolation` inverted | règles absentes |
| `snapshot` | `verify_snapshot` → Azure Compute API | snapshot existe |
| `block_suspicious_ip` | `verify_block_ip` → Azure NSG API | règle deny entrante sur l'IP présente |
| dry_run | court-circuit | `verified=None` |

`verified=False` → escalade humaine.
`verified=None` → non implémenté, cycle stocké sans claim.

Statut : toutes les actions autonomes ont leur `verify_*` implémenté.

### NSG — détails Azure

Le NSG est attaché au **subnet** (pas au NIC). `_get_nic_nsg` remonte au subnet si le NIC
n'a pas de NSG direct. Si une règle existante occupe la priorité 100 (ex: `allow-ssh`),
elle est décalée +100 et sauvegardée dans `~/.glorfindel/isolation/<vm>.json` pour
restauration au `release_isolation`.

### recovery_complete — qui l'émet ?

`glorfindel restore` CLI (commande humaine). Il écrit le signal dans `runs/` puis appelle
`GlorfindelAgent.respond()` inline — pas besoin que `watch` soit actif. Si `--keep-isolated`
(ou `GLORFINDEL_KEEP_ISOLATED=1`), le signal n'est pas émis et la VM reste isolée.

### Action discovery

Glorfindel n'est pas contraint à une liste fixe. Si aucune action connue ne convient,
il propose une action libre (snake_case) et explique dans `escalation_reason`. Le routing
escalade automatiquement toute action hors de `AUTONOMOUS_ACTIONS`. L'humain approuve et
potentiellement codifie l'action (ex: `release_isolation` fut d'abord proposée, puis codifiée).

### Apprentissage par la boucle (RAG)

Chaque cycle `(signal → décision → action → outcome)` est stocké dans ChromaDB avec
métadonnées : `ttp`, `action`, `event`, `run_id`, `detection_s`, `action_s`, `confidence`, `past_cycles_used`.
Les 3 cycles les plus similaires sont injectés à chaque décision. Le modèle de base
reste stable — l'expérience s'accumule dans la base vectorielle.

RAG cross-scénario validé : au run T1041, Glorfindel a référencé 2 cycles T1041 passés
(detection_timeout) + 1 cycle T1486 (isolate_vm validé) pour calibrer sa décision.

Chaque run produit `runs/{run_id}_debug.jsonl` — trace complète signal + past_cycles + reasoning + outcome.

### Abstraction cloud (CloudConnector)

```python
class CloudConnector(ABC):
    def isolate_vm(self, resource_id: str) -> dict: ...
    def release_isolation(self, resource_id: str) -> dict: ...
    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict: ...
    def snapshot(self, resource_id: str) -> str: ...
    def verify_isolation(self, resource_id: str) -> dict: ...
    def verify_snapshot(self, snap_id: str) -> dict: ...
    def restore_from_backup(self, resource_id: str, vault: str, before_attack_time: str | None) -> dict: ...
    def verify_block_ip(self, ip: str, resource_id: str) -> dict: ...
```

### Détection T1041 — StorageBlobLogs (décision arrêtée)

`AzureNetworkAnalytics_CL` (Traffic Analytics) a une latence de 10-60 min — inutilisable pour
un timeout de 300-900s. Détection T1041 via `StorageBlobLogs` sur `stannatarexfil` :
- Latence : quelques secondes (diagnostic settings direct → Log Analytics)
- `CallerIpAddress` dans les logs = IP de la source (interne si VM dans le VNet)
- `OperationName == "PutBlob"` + `ObjectKey has "exfil-target"` = signature exfiltration

Note : `CallerIpAddress` est l'IP **privée** de la VM (10.10.1.4) quand elle upload via MSI
depuis le VNet. Glorfindel a correctement préféré `isolate_vm` à `block_suspicious_ip` car
bloquer une IP interne au NSG périmétrique n'arrête pas l'exfiltration depuis la VM elle-même.
`block_suspicious_ip` sera pertinent sur un scénario avec attaquant **externe**.

### glorfindel restore — sélection pre-attaque

Sans `--before`, Azure Backup sélectionne le recovery point le plus récent — qui peut être
post-attaque si un backup a tourné pendant l'attaque. Toujours passer `--before <T0>` :
```bash
glorfindel restore <resource_id> --yes --before 2026-05-24T13:44:00+00:00
```
Le run_id Annatar encode l'heure du run (format `%Y%m%dT%H%M%SZ`) — T0 est extractible.

### Détection T1110.001 — Syslog DCR (décision arrêtée)

Détection brute force SSH via `Syslog` table (facility `auth`, severity `warning`+) :
- DCR `dcr-annatar` collecte `auth`, `syslog`, `daemon` au niveau `Warning`+
- `logger -p auth.warning` → rsyslog → port 28330 → AMA → Log Analytics
- Latence observée : ~60s (nettement mieux que les 2-3 min initialement attendus)
- Seuil KQL : ≥10 tentatives échouées depuis une IP publique (filtre RFC1918 exclu)
- Glorfindel choisit `block_suspicious_ip` (pas `isolate_vm`) — attaquant externe, VM non compromise

**Pitfall critique : isolation bloque AMA**
L'isolation NSG (deny-all outbound) empêche AMA de joindre `global.handler.control.monitor.azure.com`
pour obtenir un GIG token d'ingestion. Les logs s'accumulent dans LevelDB local (auth.warning/,
daemon.warning/) mais ne sont pas uploadés. Symptômes : `mdsd.err` plein de
`Failed to get gig token` toutes les ~4 minutes. Fix : `glorfindel release` avant le run suivant.

### Annatar engine — ordre setup / integrity check

Setup tourne **avant** l'integrity check (pas après). `setup_testdata.sh` supprime les
résidus de l'attaque précédente. L'integrity check valide l'état post-setup. Si le check
échoue après setup, le disque a un problème structurel (pas monté, marker manquant).

### Open-core — ce qui est OSS vs SaaS

| OSS (Apache 2.0) | SaaS payant |
|---|---|
| Framework Annatar + Glorfindel | Base vectorielle collective (cycles de tous les clients) |
| Connecteurs cloud (Azure, AWS, GCP) | Scénarios avancés (lateral movement, privilege escalation) |
| Scénarios de base (ransomware, exfiltration) | Déploiement managé multi-tenant |
| CLI | Support + SLA |

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA, etc.)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de scope creep vers SOC ou SIEM — rester sur la boucle rouge → bleu
- Pas de dashboard/UI en MVP
- Pas de multi-cloud avant que la boucle Azure soit solide
