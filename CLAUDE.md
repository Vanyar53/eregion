# Eregion — Contexte projet pour Claude

## Concept

**Eregion** est une plateforme de **défense active de l'infra cloud**.

> "On simule ce que ferait un attaquant sur ton infra cloud. On te montre ce qui tombe. On ferme automatiquement ce qui peut l'être. Tu vois la différence avant et après."

Pas de la détection passive. Pas de la compliance. Une boucle complète : simuler l'attaque → produire des signaux → répondre automatiquement → prouver que c'est fermé.

**Stack** : Python 3.11+, Azure (provider initial), cloud agnostique par design.

---

## Les deux agents

### Annatar — Agent Rouge (MVP Azure ~95%)
- Chaos engine qui simule des attaques réelles (ransomware T1486, exfiltration)
- Scénarios YAML mappés MITRE ATT&CK, bout en bout, rapport JSON PASS/FAIL
- Produit des signaux normalisés indépendants du provider
- Tourne **uniquement** sur ressources taguées `sechaos-test: "true"`

**Entraînement** : connaissance structurée, pas ML — base MITRE ATT&CK + CVEs publics cloud.

### Glorfindel — Agent Bleu (MVP fonctionnel)
- Reçoit les signaux normalisés d'Annatar (JSONL)
- Raisonne via Claude API (tool use), décide de la réponse, explique le pourquoi
- Agit seul sur actions réversibles, escalade à l'humain sur actions destructives ou inconnues
- Vérifie que l'action a eu l'effet voulu (ex : règle NSG bien posée)
- Propose des actions nouvelles si aucune action connue ne convient — l'humain valide

**Mode watch** : `glorfindel watch runs/` — poll toutes les 2s, répond en temps réel pendant qu'Annatar tourne.

**Apprentissage** : chaque cycle `(signal → décision → action → outcome)` est stocké dans ChromaDB. Les 3 cycles les plus similaires sont injectés comme contexte à chaque décision.

**Lien fondamental** : plus Annatar attaque, plus Glorfindel apprend.

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
    "revoke_temp_access",
    "snapshot",           # forensic snapshot of compromised state — réversible
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
- **CLI** : Click (commande : `annatar`)
- **Azure SDK** : azure-mgmt-compute, azure-monitor-query, azure-mgmt-recoveryservicesbackup
- **Parsing** : PyYAML
- **Terminal** : rich
- **Infra test** : Terraform (`infra/terraform/`)
- **Tests** : pytest
- **Agent framework** : LangGraph — boucle conditionnelle (autonome vs escalade) + human-in-the-loop natif + observabilité par state snapshots
- **LLM** : Claude API (Anthropic) — raisonnement structuré, tool use natif, alignement sécurité
- **Vector store** : ChromaDB local (fichier, zéro serveur) — OSS ; base collective sur serveur Eregion en SaaS

---

## Architecture fichiers

```
eregion/
├── scenarios/           # Scénarios YAML MITRE ATT&CK
│   └── azure/           # ransomware-vm.yaml, data-exfiltration.yaml
├── annatar/             # Package Agent Rouge
│   ├── cli.py
│   ├── runner/          # engine.py, parser.py, report.py
│   ├── executors/       # azure_vm.py (resource_id property)
│   ├── collectors/      # azure_monitor.py
│   ├── safety/          # guard.py — safety checks obligatoires
│   └── signals/         # schema.py (Signal, severity_for_ttp), emitter.py
├── glorfindel/          # Package Agent Bleu
│   ├── agent.py         # LangGraph : load_context→decide→execute→verify→store
│   ├── signals.py       # load_signals(), load_latest_signals()
│   ├── actions.py       # CloudConnector ABC, AzureConnector, AUTONOMOUS_ACTIONS
│   ├── memory.py        # CycleMemory (ChromaDB)
│   └── cli.py           # respond, watch, release, memory-stats
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
    "signal_id": "{run_id}_{event}",   # ex: 20260522T193434Z_detection
    "timestamp": "ISO8601",
    "provider": "azure",
    "resource_id": "/subscriptions/.../virtualMachines/...",
    "resource_type": "vm|storage|network",
    "ttp": "T1486",
    "severity": "critical|high|medium|low",
    "event": "detection|detection_timeout|recovery_complete|recovery_failed",
    "raw_signal": {},
    "context": {"run_id": "...", "scenario": "..."}
}
```

Annatar écrit un fichier `runs/{run_id}_signals.jsonl` (une ligne JSON par événement).
Glorfindel le lit via `glorfindel watch runs/` ou `glorfindel respond <file>`.

---

## Ressources Azure de test

Toutes dans `rg-sechaos-test`, taguées `sechaos-test: "true"` :
- `vm-sechaos-victim` : Ubuntu 22.04, Standard_B2s, 32GB sur `/mnt/testdata`
- `law-sechaos` : Log Analytics Workspace
- `rsv-sechaos` : Recovery Services Vault + backup policy
- `st-sechaos-exfil` : Storage account cible exfiltration
- NSG avec flow logs activés

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

1. ✅ Normaliser les signaux Annatar (`annatar/signals/` — `Signal`, `SignalEmitter`, `severity_for_ttp`)
2. ✅ Premier agent Glorfindel : signal ransomware → décision expliquée + `isolate_vm`
3. ✅ Fermer la boucle : `verify_isolation` → escalade si échec, `store_cycle` en mémoire
4. ✅ `glorfindel release <resource_id>` — lever une isolation avec garde de sécurité
5. ✅ `glorfindel watch runs/` — deux agents concurrents, réponse en temps réel
6. ✅ Action discovery — Glorfindel peut proposer des actions inconnues (escalade automatique)
7. Run réel Azure end-to-end — valider sans `--dry-run` sur `rg-sechaos-test`
8. Scénario exfiltration câblé aux signaux — T1041 → `block_suspicious_ip`

## Décisions techniques arrêtées

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

### Action discovery

Glorfindel n'est pas contraint à une liste fixe. Si aucune action connue ne convient, il propose une action libre (snake_case) dans le champ `action` et explique dans `escalation_reason`. Le routing escalade automatiquement toute action hors de `AUTONOMOUS_ACTIONS`. L'humain approuve et potentiellement codifie l'action pour le prochain cycle.

### Apprentissage par la boucle (RAG sur cycles passés)

Chaque cycle complet `(signal → décision → action → outcome)` est stocké dans un vecteur store.
À chaque nouvelle décision, Glorfindel récupère les 3 cycles les plus similaires comme contexte.
Pas de fine-tuning — le modèle de base reste stable. L'expérience s'accumule dans la base vectorielle.

### Abstraction cloud (CloudConnector)

```python
class CloudConnector(ABC):
    @abstractmethod
    def isolate_vm(self, resource_id: str) -> dict: ...
    @abstractmethod
    def release_isolation(self, resource_id: str) -> dict: ...
    @abstractmethod
    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict: ...
    @abstractmethod
    def snapshot(self, resource_id: str) -> str: ...
    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict: ...
```

`AzureConnector` implémente cette interface (`dry_run=True` pour les tests sans infra).
`AwsConnector` et `GcpConnector` à brancher plus tard.

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
