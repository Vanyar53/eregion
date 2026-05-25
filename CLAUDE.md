# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud. Deux agents IA en boucle :
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK)
- **Glorfindel** (bleu) détecte, répond de façon autonome, vérifie, apprend via ChromaDB

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/`, `.envrc` charge `ANTHROPIC_API_KEY`
**Stack** : Python 3.11, Azure SDK, LangGraph, Claude API (tool use), ChromaDB, Click, pytest

---

## TTPs validés en réel (2026-05-24/25)

| TTP | Scénario | Détection | Temps | Action |
|-----|----------|-----------|-------|--------|
| T1486 | Ransomware VM | Perf disk write | 50s | `isolate_vm` → restore 21m23s |
| T1041 | Data exfiltration | StorageBlobLogs | 229s | `isolate_vm` (IP interne) |
| T1110.001 | SSH brute force | Syslog DCR | 60s | `block_suspicious_ip` (IP Tor) |
| T1548.003 | Sudo priv esc | Syslog DCR | 40s | `isolate_vm` (root confirmé) |
| T1110+T1548 | Run parallèle | — | 41s/59s | block → isolate (incident context) |

Glorfindel choisit la bonne action sans règles per-TTP explicites — raisonnement depuis le contexte signal + incident.

---

## Architecture — boucle complète

```
Annatar
  setup (nettoie résidus) → integrity check → attaque → attack_started {T0, query, workspace_id}

Glorfindel (watch ou respond)
  poll_detection Azure Monitor (10s) → detection ou detection_timeout
  → decide (LangGraph + Claude API + RAG ChromaDB 3 cycles similaires)
  → execute autonomous action (isolate_vm / block_suspicious_ip / snapshot)
  → verify (Azure NSG API) → store_cycle (ChromaDB + debug.jsonl)

Humain
  glorfindel restore <resource_id> --yes   # --before auto-détecté depuis signals JSONL
  → restore Azure Backup (~20min) → recovery_complete
  → Glorfindel release_isolation (autonome) → verify → store
```

---

## Architecture watch — parallèle + sérialisé

```
attack_started → thread poll-<vm>-<id>   (parallèle, N attaques × N threads)
                      ↓ détecté
               queue resource_id → decide+execute  (sérialisé, incident context partagé)
```

---

## LangGraph — 6 nodes

```
load_context → poll_detection → decide → execute_action → verify_action → store_cycle
                                    ↓ (escalate)
                              escalate_to_human → store_cycle
```

- `poll_detection` : no-op sauf `attack_started` → poll Azure Monitor jusqu'à alerte ou timeout
- `decide` : Claude API + RAG (3 cycles similaires) + incident context si multi-signal
- `verify_action` : NSG check (isolate/release), Compute API (snapshot), NSG rule (block)
- `store_cycle` : ChromaDB + `runs/{run_id}_debug.jsonl`
- `dry_run: bool` dans `GlorfindelState` → skipe escalations.record() et actions réelles

---

## Routing TTP → action (_SYSTEM_PROMPT)

| Situation | Action | Escalade |
|---|---|---|
| `detection` + IP interne (T1486/T1041/T1548) | `isolate_vm` | Non |
| `detection` + IP externe (T1110) | `block_suspicious_ip` | Non |
| `detection_timeout` | `snapshot` forensique | Oui |
| `recovery_complete` | `release_isolation` | Non |
| `recovery_failed` | escalade | Oui |

**Règle de sécurité** : action destructive sans `escalate=True` → bloquée par le graph, pas par confiance dans le LLM.

---

## Règles d'autonomie strictes

```python
AUTONOMOUS_ACTIONS = ["isolate_vm", "release_isolation", "snapshot", "block_suspicious_ip", "revoke_temp_access"]
HUMAN_APPROVAL_REQUIRED = ["restore_from_backup", "delete_resource", "wipe_storage", ...]
```

Actions inconnues proposées → escalade automatique, humain valide et codifie.

---

## Vérification post-action

| Action | Vérification | État |
|---|---|---|
| `isolate_vm` | Règles NSG deny-all | ✅ |
| `release_isolation` | Isolation absente confirmée | ✅ |
| `snapshot` | Snapshot existe Azure | ✅ |
| `block_suspicious_ip` | Règle NSG pour l'IP | ✅ |

`verified=False` → escalade. `verified=None` → cycle stocké sans claim de succès.

---

## IncidentRegistry

`glorfindel/incidents.py` → groupe signaux par `resource_id` dans TTL (défaut 300s, `GLORFINDEL_INCIDENT_TTL_S`).
Persiste dans `~/.glorfindel/incidents.jsonl`. Thread-safe.
Quand `signals_count > 1` ou `actions_taken` non vide → prompt injecte contexte incident.

---

## Fichiers clés

```
glorfindel/
  agent.py        → LangGraph 6 nodes + system prompt
  actions.py      → CloudConnector ABC + AzureConnector (isolate, release, block, unblock, snapshot, verify_*)
  detectors.py    → DetectionConnector ABC + AzureMonitorDetector (poll 10s)
  memory.py       → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py    → IncidentRegistry (TTL, persist, thread-safe)
  cli.py          → watch, respond, restore, release, unblock, revert, list, pending, ack, check-ttl
  escalations.py  → ~/.glorfindel/escalations.jsonl

annatar/
  runner/engine.py    → setup AVANT integrity check → attack → emit attack_started
  signals/schema.py   → Signal + severity_for_ttp (T1486/T1041/T1110/T1548)
  signals/emitter.py  → signal normalisé JSONL

scenarios/azure/
  ransomware-vm.yaml          → T1486 (setup_testdata.sh ici uniquement)
  data-exfiltration.yaml      → T1041
  lateral-movement.yaml       → T1110.001
  privilege-escalation.yaml   → T1548.003

schemas/scenario.schema.json  → JSON Schema validation IDE
terraform/                    → infra complète Azure (VM, NSG, LAW, Backup, DCR, StorageBlobLogs)

~/.glorfindel/
  escalations.jsonl           → escalades persistées
  incidents.jsonl             → incidents actifs
  isolation/<vm>.json         → état NSG isolation + TTL
  blocks/<vm>.json            → IPs bloquées par VM
```

---

## CLI — référence complète

```bash
# Workflow opérateur — 3 terminaux
glorfindel watch runs/                       # terminal 1 — réponses automatiques
annatar run scenarios/azure/ransomware-vm.yaml  # terminal 2 — attaque
glorfindel pending --watch                   # terminal 3 — alerting (poll 2s, NEW ESCALATION)

# État
glorfindel list                              # toutes VMs : isolations + IPs bloquées
glorfindel pending                           # escalades en attente
glorfindel pending --watch                   # alerting temps réel

# Actions
glorfindel revert <resource_id> --yes        # reset complet : release + unblock toutes IPs
glorfindel release <resource_id> --yes       # isolation seule
glorfindel unblock <ip> <resource_id> --yes  # IP seule
glorfindel restore <resource_id> --yes       # Azure Backup (--before auto-détecté)
glorfindel ack <escalation_id>               # acquitter escalade
glorfindel ack --all                         # acquitter toutes
glorfindel check-ttl                         # libérer isolations expirées
glorfindel memory-stats                      # ChromaDB cycle count
glorfindel --version                         # 0.2.0

# Annatar
annatar run scenarios/azure/<scenario>.yaml  # --dry-run disponible

# Simulation locale sans Azure
python scripts/simulate_annatar.py
python scripts/simulate_annatar.py --ids-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams sur escalade
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h)
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
```

---

## Tests

```bash
pytest                    # 88 tests, 0 appel Azure, 0 appel Claude API
pytest tests/unit/test_agent_nodes.py   # 30 tests LangGraph nodes
pytest tests/unit/test_glorfindel.py    # 27 tests actions/routing/signals
```

---

## Packaging

```
name = "eregion", version = "0.2.0", Apache 2.0 ✓
entrypoints : annatar + glorfindel CLIs
wheel : eregion-0.2.0-py3-none-any.whl ✓
```

---

## Coûts réels (West Europe)

- **Infra existante** : Claude API uniquement, <$2/mois (~$0.05–0.10 par run)
- **Sandbox Terraform** : ~$25–35/mois (VM ~6h/jour + disques + IP + backup + LAW). Désactivable entre runs.

---

## Détails Azure à connaître

- NSG isolation = outbound deny-all → bloque AMA (`mdsd.err` : Failed to get gig token) → detection timeout sur run suivant. Toujours `glorfindel revert` avant le prochain run.
- Règles block IP persistent entre runs → conflit priority si T1110 puis T1548. Nettoyage : `glorfindel revert`.
- Priority bump `isolate_vm` : dynamique (premier slot libre ≥ 200) → fix bug conflit T1110 + T1548.
- StorageBlobLogs : latence secondes. `AzureNetworkAnalytics_CL` inutilisable (10-60min).
- Restore via REST API `IaasVMRestoreRequest OriginalLocation` → VM deallocated puis redémarrée.
- VM auto-shutdown 23h UTC → `az vm start -g annatar -n vm-annatar-victim` avant chaque session.
- Syslog latence ~60s nominal, timeout 300s dans les scénarios.

---

## Pitfalls opérateur

```bash
# Avant chaque run — vérifier état propre
glorfindel list
# Si isolations ou blocks présents :
glorfindel revert <resource_id> --yes

# Vérification NSG directe si besoin
az network nsg rule list -g annatar --nsg-name nsg-annatar -o table
```

---

## Conventions

- **À chaque commit** : mettre à jour README + CLAUDE.md + générer résumé claude.ai
- `target:` = ressource attaquée, `detection:` = infra surveillance (workspace_id ici)
- `prerequisites:` = KQL vérification + instructions setup dans chaque scénario
- `setup_testdata.sh` uniquement dans T1486
- RunCommand : 5 retries (15s, 30s, 60s, 90s, 120s)
- `dry_run=True` dans tous les tests — jamais d'appel Azure ou Claude API dans les tests

---

## Prochaines priorités (voir ROADMAP.md pour détail complet)

1. **Utilisateur extérieur** — avant tout nouveau scénario ou provider
2. **glorfindel check-ttl en cron** — crontab ou systemd timer
3. **Entra ID / Service Principal** — vecteur #1 Azure 2025, `revoke_service_principal`
4. **Schéma normalisé `first_result_row`** — prérequis tous connecteurs
5. **AWS provider** — `AwsConnector` + CloudWatch/GuardDuty
6. **Prometheus + Loki** — stack open source dominante
7. **War Room UI** — après feedback premier utilisateur

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — RAG ChromaDB suffit
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels
