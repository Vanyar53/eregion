# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud. Deux agents IA en boucle :
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK)
- **Glorfindel** (bleu) détecte, répond de façon autonome, vérifie, apprend via ChromaDB

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/` (créé par `make install`), `.envrc` charge les creds
**Stack** : Python 3.12, Azure SDK, LangGraph, LiteLLM (Anthropic défaut, OpenAI, Azure, Ollama, self-hosted), ChromaDB, Click, pytest
**Docker** : `make build` → `eregion-annatar` + `eregion-glorfindel`. `make annatar-shell` (alias `ar`) / `make glorfindel-shell` (alias `gf`). State persisté dans `~/.annatar/` et `~/.glorfindel/`, cache ChromaDB dans `~/.cache/chroma/`.

---

## TTPs validés en réel (2026-05-24/25/26)

| TTP | Scénario | Détection | Temps | Action |
|-----|----------|-----------|-------|--------|
| T1486 | Ransomware VM | Perf disk write | ~71s | `restore_from_backup` (escalade) → 21m23s RTO |
| T1041 | Data exfiltration | StorageBlobLogs (RFC-1918, PutBlob ≥ 1) | ~30s | `isolate_vm` (disk intact) |
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

## LangGraph — 8 nodes

```
load_context → poll_detection → investigate → decide → execute_action → verify_action → store_cycle
                                                  ↓ (escalate)
                                            escalate_to_human → store_cycle
```

- `poll_detection` : no-op sauf `attack_started` → poll Azure Monitor jusqu'à alerte ou timeout
- `investigate` : requêtes KQL post-détection selon contenu du signal (pas le TTP label)
  - MaxWrite présent → top_write_processes + backup_agent_check (ransomware vs backup légitime)
  - FailedAttempts+SourceIP → successful_auth_from_ip (brute force a-t-il réussi ?)
  - USER=root dans syslog → root_commands + disk_write_after_escalation
  - Résultats dans `raw_signal.investigative_context` — le LLM les voit avant decide
  - No-op si pas de workspace_id ou dry_run
- `decide` : LLM via LiteLLM + few-shot anchors + RAG (3 cycles) + incident context + investigative_context
- `verify_action` : NSG check (isolate/release), Compute API (snapshot), NSG rule (block)
- `store_cycle` : ChromaDB + `runs/{run_id}_debug.jsonl`
- `dry_run: bool` dans `GlorfindelState` → skipe escalations.record() et actions réelles

---

## Raisonnement LLM — few-shot + signal enrichi

Le LLM ne suit pas de routing table TTP→action. Il raisonne depuis :
1. Les indicateurs bruts du signal (`first_result_row`)
2. Le contexte investigatif (`investigative_context`) collecté par le noeud `investigate`
3. Les exemples few-shot validés en prod dans `_SYSTEM_PROMPT`
4. Les cycles passés ChromaDB + l'incident context multi-signal

Exemples few-shot : 4 chaînes de raisonnement complètes (MaxWrite → encryption → restore ;
CallerIP RFC-1918 → exfil, disk intact → isolate ; etc.). Le LLM peut dévier sur les cas
ambigus — les exemples ancrent les cas validés.

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
glorfindel-config.yaml          → source unique pour la config infra (NE PAS confondre avec detection_rules.yaml)
                                   monitoring_backends: workspace_id LAW, endpoint Prometheus...
                                   action_backends: RSV vault_name + resource_group
                                   exceptions: fnmatch patterns opt-out par VM et/ou par règle
                                   (fichier non versionné — monté en Docker volume ou présent localement)

glorfindel/
  config.py             → GlorfindelConfig + load_glorfindel_config() — charge glorfindel-config.yaml
                          ExceptionConfig.is_excluded(asset_name, rule_name) — opt-out fnmatch
  discovery.py          → AssetRegistry (thread-safe, persist ~/.glorfindel/discovered_assets.json)
                          DiscoveryService — thread daemon, découverte au démarrage + périodique
                          _discover_from_azure_monitor() → LAW Heartbeat query → liste VMs actives
                          replace_for_backend() : remplace (pas merge) — évince les VMs supprimées
                          None sur erreur query → cache conservé (pas d'éviction sur panne)
  agent.py              → LangGraph 8 nodes + _SOURCE_LANGUAGES map (source → query lang)
                          load_context → [poll_detection | propose_detection_rule]
                          → investigate → decide → execute_action → verify_action → store_cycle
  actions.py            → CloudConnector ABC + AzureConnector + check_nsg_access/check_backup_points/check_compute_access
  detectors.py          → DetectionConnector ABC + AzureMonitorDetector (poll 10s) + run_query()
  detection_rules.py    → DetectionRule dataclass + RulePoller (continuous polling, status persistence)
                          load_config(path, glorfindel_cfg=None) — workspace_id résolu depuis glorfindel_cfg
                          RulePoller.expand_for_discovered(registry, glorfindel_cfg) — démarre threads
                          par (règle auto_apply, asset découvert), thread s'arrête si asset évincé
  audit.py              → AuditCheck, AuditResult, run() — NSG/backup/compute readiness checks, IAM gap detection
  proposed_rules.py     → record/pending/approve() — detection rule proposal lifecycle
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py          → IncidentRegistry (TTL, persist, thread-safe)
  cli.py                → watch, respond, restore, release, unblock, reset (revert=alias), list, pending, ack,
                          audit (--all), approve-rule, check-ttl, bot, dashboard, war-room
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés)
  bot.py                → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command
  tui.py                → Rich TUI full-screen (glorfindel dashboard) : resources + feed + escalations, raccourcis a/r/x/u/v
  api.py                → FastAPI War Room — /api/state, /api/feed (WS), /api/config, /api/audit[/<vm>],
                          /api/pending/rules, /api/action/{release,revert,restore,ack,approve-rule}
                          /api/discovered — assets découverts (registry)
  static/index.html     → War Room web UI — cards VM, feed live,
                          boutons ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux) | 🔄 Restore
                          carte MONITORING : backends + assets découverts + règles cliquables (modal query)
                          panneau ⚙ Config : Azure credentials + LLM uniquement
  rules/azure/
    detection_rules.yaml → rules UNIQUEMENT — queries KQL, TTPs, noms de backends
                           PAS de workspace_id, resource_id, ni section assets
                           assets: [auto] → s'applique aux VMs découvertes par le backend
                           monitoring_backends: [law-annatar] dans chaque rule → nom du backend

annatar/
  runner/engine.py    → setup → integrity check → attack → emit attack_started (sans query — Glorfindel résout via detection_rules.yaml)
                        → thread daemon feedback: si detection_timeout → emit detection_missed
  runner/parser.py    → Scenario dataclass simplifié (detection: timeout/prerequisites/hints)
  signals/schema.py   → Signal + severity_for_ttp (T1486/T1041/T1110/T1548)
  signals/emitter.py  → signal normalisé JSONL

annatar/scenarios/azure/
  Structure: name, mitre, target, setup, steps, detection{timeout, prerequisites, hints}
  ransomware-vm.yaml          → T1486
  data-exfiltration.yaml      → T1041
  lateral-movement.yaml       → T1110.001
  privilege-escalation.yaml   → T1548.003
  (cleanup/recovery/source/query/workspace_id supprimés — appartiennent à Glorfindel)

schemas/scenario.schema.json  → JSON Schema validation IDE (mis à jour: prerequisites→detection.prerequisites)
terraform/                    → infra complète Azure (VM, NSG, LAW, Backup, DCR, StorageBlobLogs)

~/.glorfindel/
  escalations.jsonl           → escalades persistées
  incidents.jsonl             → incidents actifs
  isolation/<vm>.json         → état NSG isolation + TTL
  blocks/<vm>.json            → IPs bloquées par VM
  proposed_rules.jsonl        → règles de détection proposées (en attente d'approbation)
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  rule_status.json            → état de polling des règles (last_poll, last_match, match_count, last_error)
  discovered_assets.json      → cache assets découverts (AssetRegistry) — survit aux redémarrages
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
# Workflow opérateur — Docker Compose (recommandé)
make glorfindel-start                        # lance watch + war-room → http://localhost:7007
make glorfindel-logs                         # tail logs des deux services
make glorfindel-dev                          # auto-reload sur modification de code (docker compose watch)
make glorfindel-stop                         # arrêt

# Workflow opérateur — 3 terminaux (local sans Docker Compose)
glorfindel watch runs/                       # terminal 1 — réponses automatiques
annatar run annatar/scenarios/azure/ransomware-vm.yaml  # terminal 2 — attaque
glorfindel pending --watch                   # terminal 3 — alerting (poll 2s, NEW ESCALATION)

# État
glorfindel list                              # toutes VMs : isolations + IPs bloquées
glorfindel pending                           # escalades en attente
glorfindel pending --watch                   # alerting temps réel

# Actions remédiation — choisir le bon périmètre
#
# Sémantique :
#   isolated = règle NSG deny-all sur la VM  → glorfindel release (lever l'isolation)
#   blocked  = règle NSG deny sur une IP     → glorfindel unblock (dé-bloquer l'IP)
#   les deux → glorfindel reset (reset complet)
#
# War Room :  ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux)
# TUI :       x:release  u:unblock  v:reset  r:restore
#
glorfindel release <resource_id> --yes       # lever isolation NSG (post-restore, VM de retour)
glorfindel unblock <ip> <resource_id> --yes  # supprimer une règle block IP
glorfindel reset <resource_id> --yes        # reset complet : release + unblock toutes IPs
glorfindel restore <resource_id> --yes       # Azure Backup (--before auto-détecté)
glorfindel ack <escalation_id>               # acquitter escalade
glorfindel ack --all                         # acquitter toutes
glorfindel check-ttl                         # libérer isolations expirées

# Audit remédiation — vérifier que Glorfindel peut agir avant l'incident
glorfindel audit <resource_id>               # NSG / backup / compute / IAM
glorfindel audit --all                       # toutes ressources de detection_rules.yaml
glorfindel audit --all --vault <nom>         # vault non-défaut (défaut: rsv-annatar)

# Boucle purple team — apprentissage détection
glorfindel pending                           # voir les règles proposées (proposed_rule)
glorfindel approve-rule <id>                 # appliquer la règle → detection_rules.yaml

glorfindel memory-stats                      # ChromaDB cycle count
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel dashboard                         # TUI full-screen : resources + feed + escalations
glorfindel war-room                          # War Room web sur http://localhost:7007 (pip install eregion[war-room])
glorfindel --version                         # 0.2.0

# Annatar
annatar run annatar/scenarios/azure/<scenario>.yaml  # --dry-run disponible, --skip-preflight pour bypasser le check VM

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
pytest                    # 193 tests, 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel/
pytest tests/unit/test_agent_nodes.py        # 43 tests LangGraph nodes (incl. investigate)
pytest tests/unit/test_glorfindel.py         # 27 tests actions/routing/signals
pytest tests/unit/test_detection_rules.py    # 14 tests RulePoller + load_rules + status
pytest tests/unit/test_proposed_rules.py     # 14 tests record/pending/approve + routing
pytest tests/unit/test_audit.py              # 14 tests NSG/backup/compute/IAM readiness
pytest tests/unit/test_config.py             # 11 tests GlorfindelConfig + ExceptionConfig
pytest tests/unit/test_discovery.py          # 24 tests AssetRegistry + DiscoveryService + eviction
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

- NSG isolation = outbound deny-all → bloque AMA (`mdsd.err` : Failed to get gig token) → detection timeout sur run suivant. Toujours `glorfindel reset` avant le prochain run.
- Règles block IP persistent entre runs → conflit priority si T1110 puis T1548. Nettoyage : `glorfindel reset`.
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
glorfindel reset <resource_id> --yes     # reset complet

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
- `tests/unit/conftest.py` : fixture `autouse` redirige `escalations._STORE` → `tmp_path/escalations.jsonl` (les tests n'écrivent jamais dans `~/.glorfindel/`)
- `AZURE_SUBSCRIPTION_ID` obligatoire dans l'env (plus d'auto-détection via SubscriptionClient)

---

## escalations — comportement

`gf pending` affiche les escalades avec **next steps générés par le LLM** (`suggested_steps`), contextuels à l'historique ChromaDB. Fallback statique pour les anciennes escalades sans ce champ.

Types d'escalade : `low_confidence` (detection_timeout + snapshot), `destructive_action` (HUMAN_APPROVAL_REQUIRED), `proposed_action` (action inconnue), `verification_failed`, `proposed_rule` (règle de détection proposée après detection_missed).

`gf ack <id>` / `gf ack --all` → marque `resolved` dans `~/.glorfindel/escalations.jsonl`. Purement administratif — ne fait rien sur Azure. `restore_from_backup` auto-acquitte via `resolve_by_resource`.

## alerting webhook + bot Discord

**Webhook** (`GLORFINDEL_WEBHOOK_URL`) — one-way, Slack format :
- **Escalade** (`:rotating_light:`) — action humaine requise
- **Action autonome** (`:robot_face:`) — `isolate_vm ✓`, `block_suspicious_ip ✓`, etc. — skippé en dry-run et si `verified=False`
- Discord : utiliser l'URL webhook Discord avec `/slack` à la fin

**Bot Discord** (`glorfindel bot`, `DISCORD_BOT_TOKEN`) — bidirectionnel :
- Un fil Discord par `resource_id` (`🔴 vm-name`), créé à la première escalade pour la VM
- Chaque escalade posée dans le fil comme embed structuré (action, ressource, TTP, prochaines étapes LLM)
- Bouton **✓ Acknowledge** → `escalations.resolve()` + archivage auto si plus d'escalades pour la VM
- Bouton **📋 Command** → commande CLI à exécuter (éphémère)
- Bouton **🔄 Restore** → exécute `glorfindel restore <rid> --yes` (`restore_from_backup`, `low_confidence`)
- Bouton **↩️ Revert** → exécute `glorfindel reset <rid> --yes` (`verification_failed`) = reset complet (isolation + blocs IP)
- `/pending` slash command → liste des escalades en attente
- `DISCORD_PING_ROLE` → ping `@rôle` à l'ouverture d'un fil
- `bot_posted.json` + `bot_threads.json` : persistance entre redémarrages (pas de doublons, même fil)
- Si `DISCORD_BOT_TOKEN` set → webhook escalade supprimé (le bot gère dans les fils)
- Thread supprimé sur Discord → bot recrée automatiquement (NotFound handling)

---

## Prochaines priorités (voir ROADMAP.md pour détail complet)

1. **Utilisateur extérieur** — avant tout nouveau scénario ou provider
2. **glorfindel check-ttl en cron** — crontab ou systemd timer
3. **Entra ID / Service Principal** — vecteur #1 Azure 2025, `revoke_service_principal`
4. **Tests + scénarios MITRE** — T1068, T1528, T1078, T1190
5. **Schéma normalisé `first_result_row`** — prérequis tous connecteurs
6. **AWS provider** — `AwsConnector` + CloudWatch/GuardDuty
7. **Prometheus + Loki** — stack open source dominante

## Boucle purple team — implémentée

**Détection manquée :**
```
Annatar attaque → detection_timeout
  → thread daemon (_wait_and_emit_feedback) poll runs/<run_id>_debug.jsonl
  → émet detection_missed {TTP, detection.hints, failed_query, source}
  → Glorfindel: propose_detection_rule node (LLM)
  → propose une query dans le bon langage (source → _SOURCE_LANGUAGES)
  → ~/.glorfindel/proposed_rules.jsonl + escalation proposed_rule
  → glorfindel pending / War Room ⚙ → Approve
  → glorfindel approve-rule <id> → detection_rules.yaml
  → restart watch → règle active au prochain run
```

**Remédiation non prête :**
```
glorfindel audit --all (ou watch startup)
  → AuditCheck par action: NSG (isolate_vm/block), backup (restore), compute (snapshot)
  → status: ok / warn (backup > 48h) / fail (IAM gap ou config manquante)
  → fix: commande az exacte pour corriger le trou
  → War Room ⚙ → section Remediation readiness par ressource
```

**Deux asymétries intentionnelles :**
- Réaction = LLM libre + RAG ChromaDB — apprentissage implicite, continu, aucune règle
- Détection = règles explicites (`detection_rules.yaml`) — source de vérité, query language = fonction du `source`
- Audit = vérification IAM + infra — détecte les trous *avant* l'incident

## Conventions scénarios Annatar

```yaml
# Structure minimale après refactoring :
detection:
  timeout: "300s"       # Annatar feedback watcher
  time_max: "180s"      # SLA déclaré (optionnel)
  prerequisites:        # ce qu'il faut vérifier avant de lancer
    - name: ...
      why: ...
      verify: "KQL ou commande az"
  hints:                # contexte pour propose_detection_rule
    log_source: Perf
    attack_commands_summary: >
      ...
    expected_indicators: [...]
    failure_candidates: [...]
```

Supprimés des scénarios : `cleanup`, `recovery`, `source`, `workspace_id`, `query` (tout dans Glorfindel).

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — RAG ChromaDB suffit
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels
