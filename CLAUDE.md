# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud. Deux agents IA en boucle :
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK)
- **Glorfindel** (bleu) détecte, répond de façon autonome, vérifie, apprend via ChromaDB

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/` (créé par `make install`), `.envrc` charge les creds
**Stack** : Python 3.11, Azure SDK, LangGraph, LiteLLM (Anthropic défaut, OpenAI, Azure, Ollama, self-hosted), ChromaDB, Click, pytest
**Docker** : `make build` → `eregion-annatar` + `eregion-glorfindel`. `make annatar-shell` (alias `ar`) / `make glorfindel-shell` (alias `gf`). State persisté dans `~/.annatar/` et `~/.glorfindel/`, cache ChromaDB dans `~/.cache/chroma/`.

---

## TTPs validés en réel (2026-05-24/25/26)

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
  → decide (LangGraph + LLM via LiteLLM + RAG ChromaDB 3 cycles similaires)
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
- `decide` : LLM via LiteLLM + RAG (3 cycles similaires) + incident context si multi-signal
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
  cli.py          → watch, respond, restore, release, unblock, revert, list, pending, ack, check-ttl, bot
  escalations.py  → ~/.glorfindel/escalations.jsonl + _ACTION_LABELS + _ESCALATION_LABELS
  bot.py          → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command

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
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  .bashrc                     → PS1 + HISTFILE + alias gf (chargé par make glorfindel-shell)
  .bash_history               → historique bash persistant

~/.annatar/
  .bashrc                     → PS1 + HISTFILE + alias ar (chargé par make annatar-shell)
  .bash_history               → historique bash persistant

~/.cache/chroma/              → modèle ONNX ChromaDB (79MB, téléchargé une seule fois)
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
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel --version                         # 0.2.0

# Annatar
annatar run scenarios/azure/<scenario>.yaml  # --dry-run disponible, --skip-preflight pour bypasser le check VM

# Simulation locale sans Azure
make annatar-simulate
make annatar-simulate-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...               # requis si provider Anthropic (défaut)
GLORFINDEL_LLM_MODEL=...            # ex: ollama/llama3.1, openai/gpt-4o, azure/gpt-4o (défaut: anthropic/claude-sonnet-4-6)
GLORFINDEL_LLM_BASE_URL=...         # endpoint self-hosted/Ollama (ex: http://localhost:11434)
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams/Discord webhook — escalades ET actions autonomes
                                    # Discord : https://discord.com/api/webhooks/<id>/<token>/slack
DISCORD_BOT_TOKEN=...               # Bot Discord interactif (fils par VM, boutons Acquitter/Commande)
DISCORD_CHANNEL_ID=...              # ID du channel (clic droit → Copy Channel ID)
DISCORD_PING_ROLE=...               # ID du rôle à pinger à l'ouverture d'un fil (optionnel)
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h)
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
```

---

## Tests

```bash
pytest                    # 90 tests, 0 appel Azure, 0 appel LLM
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

- **Infra existante** : LLM API uniquement (Anthropic défaut), <$2/mois (~$0.05–0.10 par run)
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

`annatar run` fait un preflight check automatique (VM running + pas de règles `glorfindel-isolation-*`). Si ça échoue, le run s'arrête avec la commande exacte à lancer. `--skip-preflight` pour bypasser.

```bash
# Si preflight échoue — commandes de fix
glorfindel list                           # voir isolations + IPs bloquées
glorfindel revert <resource_id> --yes     # reset complet

# Vérification NSG directe si besoin
az network nsg rule list -g annatar --nsg-name nsg-annatar -o table
```

---

## Conventions

- **À chaque commit** : mettre à jour README + CLAUDE.md + générer résumé claude.ai
- `target:` = ressource attaquée, `detection:` = infra surveillance (workspace_id ici)
- `prerequisites:` = KQL vérification + instructions setup dans chaque scénario
- `setup_testdata.sh` uniquement dans T1486
- RunCommand : 5 retries (15s, 30s, 60s, 90s, 120s) — pas de SSH, pas d'IP publique requise pour Annatar (Azure VM Agent via Wire Protocol)
- `dry_run=True` dans tous les tests — jamais d'appel Azure ou LLM dans les tests
- `AZURE_SUBSCRIPTION_ID` obligatoire dans l'env (plus d'auto-détection via SubscriptionClient)

---

## escalations — comportement

`gf pending` affiche les escalades avec **next steps générés par le LLM** (`suggested_steps`), contextuels à l'historique ChromaDB. Fallback statique pour les anciennes escalades sans ce champ.

Types d'escalade : `low_confidence` (detection_timeout + snapshot), `destructive_action` (HUMAN_APPROVAL_REQUIRED), `proposed_action` (action inconnue), `verification_failed`.

`gf ack <id>` / `gf ack --all` → marque `resolved` dans `~/.glorfindel/escalations.jsonl`. Purement administratif — ne fait rien sur Azure. `restore_from_backup` auto-acquitte via `resolve_by_resource`.

## alerting webhook + bot Discord

**Webhook** (`GLORFINDEL_WEBHOOK_URL`) — one-way, Slack format :
- **Escalade** (`:rotating_light:`) — action humaine requise
- **Action autonome** (`:robot_face:`) — `isolate_vm ✓`, `block_suspicious_ip ✓`, etc. — skippé en dry-run et si `verified=False`
- Discord : utiliser l'URL webhook Discord avec `/slack` à la fin

**Bot Discord** (`glorfindel bot`, `DISCORD_BOT_TOKEN`) — bidirectionnel :
- Un fil Discord par `resource_id` (`🔴 vm-name`), créé à la première escalade pour la VM
- Chaque escalade posée dans le fil comme embed structuré (action, ressource, TTP, prochaines étapes LLM)
- Bouton **✓ Acquitter** → `escalations.resolve()` + archivage auto si plus d'escalades pour la VM
- Bouton **📋 Commande** → commande CLI à exécuter (éphémère)
- `/pending` slash command → liste des escalades en attente
- `DISCORD_PING_ROLE` → ping `@rôle` à l'ouverture d'un fil
- `bot_posted.json` + `bot_threads.json` : persistance entre redémarrages (pas de doublons, même fil)

---

## Prochaines priorités (voir ROADMAP.md pour détail complet)

1. **Utilisateur extérieur** — avant tout nouveau scénario ou provider
2. **glorfindel check-ttl en cron** — crontab ou systemd timer
3. **Entra ID / Service Principal** — vecteur #1 Azure 2025, `revoke_service_principal`
4. **Tests + scénarios MITRE** — T1068, T1528, T1078, T1190
5. **Schéma normalisé `first_result_row`** — prérequis tous connecteurs
6. **AWS provider** — `AwsConnector` + CloudWatch/GuardDuty
7. **Prometheus + Loki** — stack open source dominante
8. **War Room UI** — après feedback premier utilisateur

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — RAG ChromaDB suffit
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels
