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

## TTPs validés en réel (nouvelle architecture RulePoller — 2026-05-31)

| TTP | Scénario | Détection | Temps | Action |
|-----|----------|-----------|-------|--------|
| T1486 | Ransomware VM | Perf disk write | 55–71s | cycle 1 : `isolate_vm` (autonome en `non_disruptive`, retenu en `human_only` → `mode_hold`), `restore --wait` → `recovery_complete` → `release_isolation` auto → RTO ~21m29s |
| T1041 | Data exfiltration | StorageBlobLogs (RFC-1918, PutBlob ≥ 1) | ~79–108s* | `isolate_vm` (disk intact) |
| T1110.001 | SSH brute force | Syslog DCR | 58s | `block_suspicious_ip` |
| T1548.003 | Sudo priv esc | Syslog DCR | 40s | `isolate_vm` (root confirmé) |
| T1110+T1548 | Run parallèle | — | 41s/59s | block → isolate (incident context) |
| T1136.001 | Account creation (purple loop) | Syslog DCR (authpriv) | 21–49s‡ | `snapshot + escalade` (few-shot b36a5a7, confidence < 0.7 → gate) — règle proposée + approuvée via purple loop |

\* T1041 : latence StorageBlobLogs variable (ingestion Azure, pas la query). SLA fonctionnel, à surveiller.
† T1548 run parallèle (T1110+T1548) : detection_timeout possible si DCR saturé — contention infra Azure, pas un bug Glorfindel.
‡ T1136.001 : scénario créé spécifiquement pour valider le purple loop end-to-end (`detection_missed → propose_detection_rule → approve-rule → détection réussie`). Règle approuvée dans `detection_rules.yaml` lors du run 20260608T143312Z. Ingestion DCR Syslog empiriquement rapide (21–49s) mais peut monter à >300s sur spike Azure — `expected_latency_s: 480` dans la règle + `detection.timeout: 600s` dans le scénario couvrent le P99. Commit `dd48b12`.

Glorfindel choisit la bonne action sans règles per-TTP explicites — raisonnement depuis le contexte signal + incident.

---

## Architecture — boucle complète

```
Annatar
  setup (nettoie résidus) → integrity check → attaque → attack_started {T0}

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
  - Gate confidence : `confidence < GLORFINDEL_CONFIDENCE_THRESHOLD` (défaut 0.7) + action autonome → escalade forcée
- `verify_action` : NSG check (isolate/release), Compute API (snapshot), NSG rule (block)
- `store_cycle` : ChromaDB + `runs/{run_id}_debug.jsonl` (toujours écrit, même si ChromaDB/webhook échoue)
- `dry_run: bool` dans `GlorfindelState` → skipe escalations.record() et actions réelles

---

## Raisonnement LLM — few-shot + signal enrichi

Le LLM ne suit pas de routing table TTP→action. Il raisonne depuis :
1. Les indicateurs bruts du signal (`first_result_row`) — normalisés via `normalize_row()` (indicateur sémantique uniforme)
2. Le contexte investigatif (`investigative_context`) collecté par le noeud `investigate`
3. Les exemples few-shot validés en prod dans `_SYSTEM_PROMPT` (prompt caching activé)
4. Les cycles passés ChromaDB + l'incident context multi-signal (investigative_context des cycles précédents propagé)

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

### Modes d'autonomie par asset (commit 9154fc6)

La gate destructive est nécessaire mais pas suffisante : le persona sans SOC craint l'action **réversible mais disruptive** (`isolate_vm`) décidée en autonome sur un faux positif. Réponse : 3 modes résolus **par asset** (escalier de confiance).

| Mode | Comportement | Statut |
|------|-------------|--------|
| `human_only` | **Aucune** action exécutée — tout recommandé/escaladé (y compris réversibles). | **Défaut** |
| `non_disruptive` | Comportement historique : `AUTONOMOUS_ACTIONS` autonomes, destructif gated. | Sélectionnable |
| `full_auto` | Différé — **valeur refusée** par la validation config. | Différé |

- Config : section `autonomy` dans `glorfindel-config.yaml` (résolution asset fnmatch > défaut global). `allow_destructive: []` = axe **séparé** du mode, `delete`/`wipe` jamais autonomes.
- Couche politique **après `decide`** (jamais un bypass) : en `human_only`, action autonome → `escalate=True` + `mode_hold=True`. Gate destructive + gate confiance restent actives.
- Nouveau type d'escalade `mode_hold` (≠ `low_confidence`/`destructive_action`) — porte l'action recommandée + confidence pour approbation en un clic.
- `store_cycle` logue `resolved_autonomy_mode` (cycle + debug.jsonl) — trail d'audit.
- `glorfindel watch --mode <m>` surcharge le défaut **global** d'une session (les règles par-asset restent prioritaires). `glorfindel list` affiche le mode résolu par VM. Warning au démarrage si `human_only` sans webhook/bot (gap de process : détection sans réponse tant qu'un humain n'agit pas).
- ⚠️ **Défaut `human_only`** : les runs gate autonomes (T1486/T1548) nécessitent `--mode non_disruptive` ou une section `autonomy` dans le config live.
- **Gate validée 2026-06-11** : T1486 human_only → `mode_hold` (NSG intact, approve War Room → `isolate_vm` exécuté) ✅ ; T1486 non_disruptive → `isolate_vm` autonome, `resolved_autonomy_mode=non_disruptive` dans debug.jsonl ✅. War Room : badge mode par VM, dropdown per-asset (hot-pickup `b7af4cc`), approve & execute (`/api/action/approve/{esc_id}`).

### Mode observe-only — credentials read-only (`GLORFINDEL_READ_ONLY=1`)

`human_only` n'exécute que des chemins **lecture** (détection LAW, investigate KQL, discovery Heartbeat, decide LLM, escalade locale) → peut tourner sur un SP **Reader / Log Analytics Reader** (pas Contributor). C'est l'on-ramp du premier test externe : un pair donne un accès lecture seule, observe les recos une semaine, zéro risque.

- `AzureConnector(read_only=...)` (défaut depuis `GLORFINDEL_READ_ONLY`). `_ensure_clients()` est déjà paresseux — aucun check write à l'init, `watch` démarre proprement sur Reader.
- Méthodes write (`isolate_vm`/`block`/`snapshot`/`release`/`restore`/`unblock`) → `_guard_write()` lève un `PermissionError` clair si read-only (jamais atteint en human_only).
- ⚠️ `non_disruptive` + read-only (mauvaise config) : `execute_action` catche le `PermissionError` → escalade type `write_blocked` (≠ mode_hold) → cycle complété, debug file + `pending` visibles (pas de perte silencieuse). Commit `902951a`.
- `audit.run` sous read-only → check `Credentials` (warn, pas fail) : « capacité d'écriture non vérifiable, checks ci-dessous = accès lecture uniquement ». Déploiement reste `ready` pour son usage observe-only.
- `glorfindel watch` logue le régime (`Credentials: read_only`) + warning si read-only combiné à un mode exécutant (les actions échoueront).
- ⚠️ Bouton War Room « Approuver & exécuter » sous read-only → `PermissionError` (à surfacer côté UI).

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
  proposed_rules.py     → record/pending/approve()/reject() — detection rule proposal lifecycle
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py          → IncidentRegistry (TTL, persist, thread-safe)
  cli.py                → watch, respond, restore (--wait), release, unblock, reset (revert=alias), list, pending, ack,
                          audit (--all), approve-rule, reject-rule, check-ttl, jobs, bot, dashboard, war-room
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés)
  bot.py                → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command
  tui.py                → Rich TUI full-screen (glorfindel dashboard) : resources + feed + escalations, raccourcis a/r/x/u/v
  api.py                → FastAPI War Room — /api/state, /api/feed (WS), /api/config, /api/audit[/<vm>],
                          /api/pending/rules, /api/action/{release,revert,restore,ack,approve-rule,snapshot/<vm>}
                          /api/discovered — assets découverts (lecture fraîche JSON à chaque appel)
                          /api/jobs/<vm> — état du job snapshot/restore en cours (lit active_jobs/<vm>.json)
  static/index.html     → War Room web UI — cards VM expandables (compact + étendu), feed live
                          boutons ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux) | 🔄 Restore
                          section BACKUP par carte : nb de RPs, âge dernier backup, bouton 📸 Snapshot (fire-and-forget RSV)
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
  account-creation.yaml       → T1136.001 (purple loop test — pas de règle initiale, règle proposée + approuvée)
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
  active_jobs/<vm>.json       → état persisté du job snapshot/restore en cours (partagé CLI/War Room)
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

# Setup scénario T1486 (avant chaque run)
annatar clean annatar/scenarios/azure/ransomware-vm.yaml   # nettoyage disque
# ⚠ Attendre 10 min après annatar clean — les I/O du nettoyage peuvent déclencher
#   ransomware-disk-write (ago(10m)) et fausser detection_time_s à 0.
glorfindel snapshot <resource_id> --yes --wait             # recovery point propre (~5-20min, --wait requis)
annatar run annatar/scenarios/azure/ransomware-vm.yaml     # lancer l'attaque

# État
glorfindel list                              # toutes VMs : isolations + IPs bloquées + assets découverts
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
glorfindel snapshot <resource_id> --yes      # backup on-demand RSV (setup scénario, ~5-20min)
glorfindel restore <resource_id> --yes       # Azure Backup fire-and-forget (--before auto-détecté)
glorfindel restore <resource_id> --yes --wait  # workflow complet : attend recovery_complete → release_isolation auto
glorfindel jobs <vm-name> [--refresh]        # état du job snapshot/restore en cours
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
glorfindel reject-rule <id>                  # écarter la règle sans l'approuver

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
GLORFINDEL_CONFIDENCE_THRESHOLD=0.7 # gate autonomie LLM (défaut 0.7 — en dessous → escalade forcée)
GLORFINDEL_READ_ONLY=1              # creds lecture seule (SP Reader) — mode observe-only
```

---

## Tests

```bash
pytest                    # 279 tests, 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel/
pytest tests/unit/test_agent_nodes.py        # LangGraph nodes (incl. investigate + confidence gate)
pytest tests/unit/test_glorfindel.py         # actions/routing/signals
pytest tests/unit/test_detection_rules.py    # RulePoller + load_rules + status + recently_matched
pytest tests/unit/test_proposed_rules.py     # record/pending/approve/reject + routing
pytest tests/unit/test_audit.py              # NSG/backup/compute/IAM readiness
pytest tests/unit/test_config.py             # GlorfindelConfig + ExceptionConfig
pytest tests/unit/test_discovery.py          # AssetRegistry + DiscoveryService + eviction
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
- `annatar clean` T1486 génère des I/O disque élevées → RulePoller peut matcher la règle `ransomware-disk-write` (données dans `ago(10m)`) avant le vrai run. Résultat : `detection_time_s=0`, isolation sur données du nettoyage, pas du vrai run. Fix : attendre 10 min entre `annatar clean` et `annatar run`, ou vérifier que `detection_time_s > 0` après le run.
- Règles block IP persistent entre runs → conflit priority si T1110 puis T1548. Nettoyage : `glorfindel reset`.
- Priority bump `isolate_vm` : dynamique (premier slot libre ≥ 200) → fix bug conflit T1110 + T1548.
- StorageBlobLogs : latence secondes. `AzureNetworkAnalytics_CL` inutilisable (10-60min).
- Restore via REST API `IaasVMRestoreRequest OriginalLocation` → VM deallocated puis redémarrée.
- VM auto-shutdown 23h UTC → `az vm start -g annatar -n vm-annatar-victim` avant chaque session.
- Syslog latence ~60s nominal, timeout 300s dans les scénarios.
- DCR `facility_names` doit inclure `authpriv` — `useradd` sur Ubuntu génère des messages `LOG_AUTHPRIV`. Sans ce facility, T1136.001 (account creation) ne remonte pas dans LAW. Ajouté dans `monitoring.tf` (commit 9a64e83).
- Azure Backup OriginalLocation restore laisse des disques orphelins à LUN 10 → `terraform apply` échoue sur le prochain attachement. Fix : `null_resource.clean_lun10` dans `vm.tf` détache automatiquement tout disque non-testdata à LUN 10.
- `isolate_vm` écrit `~/.glorfindel/isolation/<vm>.json` **après** confirmation des règles NSG (commit `b2a41c3`) — un 403 ne laisse plus d'état orphelin « ISOLATED » sans règle. `glorfindel reset` matche le `resource_id` en case-insensitive et `release_isolation` nettoie le state file local même si Azure n'a aucune règle.

---

## Pitfalls opérateur

`backup_agent_check` retourne toujours `[]` sur les Linux VMs — `\\Process(*)\\IO Write Bytes/sec` est un counter Windows-only, Linux AMA ne le collecte pas. Idem pour `top_write_processes` (même counter). **C'est le comportement voulu** : résultats vides → le LLM ne peut pas exclure le ransomware → escalade forcée. L'alternative (`az backup job list` via RunCommand) ajouterait latence 15-30s + dépendance AZ CLI in-guest pour un résultat qui rendrait le produit trop confiant sur des données incomplètes.

`annatar run` fait un preflight check automatique (VM running + pas de règles `glorfindel-isolation-*`). Si ça échoue, le run s'arrête avec la commande exacte à lancer. `--skip-preflight` pour bypasser.

Après un `restore_from_backup`, le backup suivant est un **full backup** (~40min–4h selon Azure). Aucune API ne permet de prédire la durée. Le `glorfindel snapshot` du setup T1486 suivant peut donc être long. À anticiper avant les sessions de test.

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
- **Edit de `few_shot_examples.yaml`, `_SYSTEM_PROMPT` ou `_build_user_message()`** : requiert un run end-to-end T1486 + au moins un autre TTP avant merge. Ces trois zones contrôlent ce que le LLM voit et comment il raisonne — les 275 tests unitaires (LLM mocké, dry_run=True) ne peuvent pas valider le comportement résultant. Un edit mal calibré peut introduire un raccourci critique (ex: ransomware non-isolé 20min, faux positif T1041, cycle 1 sauté). Voir c6fe0d0, 740659a.
- **`past_cycles` ChromaDB = historique uniquement** : ne jamais inférer l'état courant de la VM depuis les cycles passés. `_build_user_message()` injecte `## État actuel de la VM` depuis `~/.glorfindel/isolation/<vm>.json` — c'est la source de vérité. Voir commit 740659a (bug : LLM voyait `isolate_vm` dans past_cycles → concluait "VM déjà isolée" → sautait le cycle 1).

---

## Sessions Claude spécialisées (multi-agents)

4 sessions spécialisées + 2 sessions transversales, coordonnées via `collab/`.

| Session | Fichier de rôle | Périmètre |
|---------|----------------|-----------|
| Glorfindel | `CLAUDE_GLORFINDEL.md` | `glorfindel/`, `rules/azure/`, tests unitaires Glorfindel |
| Annatar | `CLAUDE_ANNATAR.md` | `annatar/`, `annatar/scenarios/`, tests unitaires Annatar |
| Tests | `CLAUDE_TESTS.md` | Chef d'orchestre — tests fonctionnels bout en bout sur Azure réel |
| War Room | `CLAUDE_WARROOM.md` | UI/UX `glorfindel/static/index.html` + `glorfindel/api.py` |
| Review | `CLAUDE.md` (base) | Design review, architecture critique, BA sprint — ad hoc |
| General | `CLAUDE.md` (base) | Coordination inter-sessions, inbox routing, CLAUDE.md/README/ROADMAP |

**Démarrer une session :**
```
# Session Glorfindel
"Lis CLAUDE_GLORFINDEL.md pour tes instructions de session, puis commence par ton inbox."

# Session Annatar
"Lis CLAUDE_ANNATAR.md pour tes instructions de session, puis commence par ton inbox."

# Session Tests
"Lis CLAUDE_TESTS.md pour tes instructions de session, puis commence par ton inbox."

# Session War Room
"Lis CLAUDE_WARROOM.md pour tes instructions de session, puis commence par ton inbox."

# Session Review (ad hoc — challenge design et implémentations)
"Tu es la session Review d'Eregion. Lis CLAUDE.md. Ta mission : challenger les décisions architecturales, les implémentations critiques et les choix de sécurité. Commence par lire inbox_review.md."

# Session General (coordination)
"Tu es la session General d'Eregion. Lis CLAUDE.md. Ta mission : coordonner les sessions spécialisées, router les items cross-cutting, mettre à jour CLAUDE.md/README.md/ROADMAP.md. Commence par lire inbox_general.md."
```

**Protocole :** chaque session lit son inbox (`collab/inbox_<role>.md`) en début de tâche, met à jour son status (`collab/<role>_status.md`) après chaque changement significatif, et écrit dans l'inbox de l'autre si un changement a un impact cross-cutting.

---

## escalations — comportement

`gf pending` affiche les escalades avec **next steps générés par le LLM** (`suggested_steps`), contextuels à l'historique ChromaDB. Fallback statique pour les anciennes escalades sans ce champ.

Types d'escalade : `low_confidence` (detection_timeout + snapshot), `destructive_action` (HUMAN_APPROVAL_REQUIRED), `proposed_action` (action inconnue), `verification_failed`, `proposed_rule` (règle de détection proposée après detection_missed), `mode_hold` (action autonome retenue par le mode `human_only` de l'asset — pas un manque de confiance), `write_blocked` (action tentée mais credentials read-only / IAM 403 — capability gap, pas un choix de politique), `action_failed` (échec Azure non-auth pendant l'exécution — toujours escaladé, jamais d'abort silencieux du cycle).

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
