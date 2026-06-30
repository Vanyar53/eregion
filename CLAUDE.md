# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud. Deux agents IA en boucle :
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK)
- **Glorfindel** (bleu) détecte, répond de façon autonome, vérifie, apprend via ChromaDB

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/` (créé par `make install`), `.envrc` charge les creds
**Stack** : Python 3.12, Azure SDK, LangGraph, LiteLLM (Anthropic défaut, OpenAI, Azure, Ollama, self-hosted), ChromaDB, Click, pytest
**Docker** : `make build` → `eregion-annatar` + `eregion-glorfindel`. `make annatar-shell` (alias `ar`) / `make glorfindel-shell` (alias `gf`). State persisté dans `~/.annatar/` et `~/.glorfindel/`, cache ChromaDB dans `~/.cache/chroma/`. **Images non-root** : `make build` injecte l'UID/GID de l'opérateur (`id -u`/`id -g`) en build-arg → le container écrit le state bind-monté comme l'opérateur, pas root (sinon la CLI locale ne peut pas muter ce que le container a écrit → `PermissionError` sur `reset`/`unblock`). HOME reste `/root` (chowné), aucun chemin de mount ne change. Une seule fois après upgrade depuis l'ancienne image root : `make fix-state-ownership` (`chown` des fichiers root legacy).

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
  - **Garde-fou déterministe (signal non caractérisé)** : indépendant du LLM — une action autonome **disruptive** (`isolate_vm`/`block_suspicious_ip`/`revoke_temp_access`) sur un signal **sans indicateur de menace reconnu** (`normalize_row` → fallback générique/`"unknown"`, pas un label curé) → **escalade forcée**. Le gate de confiance fait confiance au modèle pour avouer une confiance basse, ce qu'un modèle faible ne fait pas (smoke : 0.85 sur un signal vague). Le garde-fou ne dépend pas de cette honnêteté. Un signal **caractérisé mais ambigu** (ex. account creation syslog) n'est PAS attrapé ici (c'est le job du gate confiance). `detection_rules.has_recognized_indicator()` + `RECOGNIZED_INDICATOR_KEYS` (= labels de `_INDICATOR_COLUMNS`). Pour « blesser » une nouvelle colonne d'indicateur → l'ajouter à `_INDICATOR_COLUMNS`.
  - **Parsing défensif de la décision AVANT les gates** (`_as_bool` + float safe + `.get` défauts) : un modèle non-conforme peut (a) **omettre un champ requis** → `d["reasoning"]` KeyError → crash, (b) renvoyer `escalate` en **string `"false"`** (truthy → bypasse le gate), (c) une confidence non-numérique → `float()` lève, (d) **aucun tool-call** (malgré `tool_choice`) → `tool_calls[0]` TypeError, ou un JSON malformé. Tous trouvés par le smoke multi-run (`scripts/llm_smoke.py` : llama3.2 string-bool, command-r7b champ omis, mistral-nemo no-tool-call). Extraction du tool-call protégée + tous les champs hard-défaultés/coercés ; **aucune action/décision parsée → escalade forcée**. Un modèle quirky ne peut ni crasher le cycle ni défaire un contrôle de sécurité.
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
                          DiscoveryService — thread daemon. Cadences DÉCOUPLÉES :
                            discovery (LAW Heartbeat, cheap) toutes les 60s → VM allumée apparaît vite ;
                            posture (RSV/NSG par VM, cher) throttlée à interval_s (défaut 30min) → pas de matraquage RSV.
                          _discover_from_azure_monitor() → LAW Heartbeat query → liste VMs actives
                          _classify_asset(rid) → (kind, parent) : AKS réel (le heartbeat AMA résout l'id
                          des nœuds vers le managed cluster .../Microsoft.ContainerService/managedClusters/<n>,
                          partagé par tous les nœuds) → kind="aks_node" + parent=<id cluster> (clé de groupage) ;
                          instance VMSS directe (.../virtualMachineScaleSets/<vmss>/virtualMachines/<n>) →
                          kind="vmss_instance" + parent=<id VMSS> ; VM standalone → ("vm",""). DiscoveredAsset
                          porte kind/parent (defaults rétro-compat cache) → /api/state → War Room replie par parent.
                          replace_for_backend() : refresh + rétention — une VM absente du Heartbeat (éteinte)
                          est retenue (last_seen figé) tant que gap < GLORFINDEL_DISCOVERY_RETENTION_H (défaut 8h), puis évincée
                          None sur erreur query → cache conservé (pas d'éviction sur panne)
                          audit.run() lance NSG/backup/compute en parallèle (le RSV ne s'empile plus sur le reste)
  agent.py              → LangGraph 8 nodes + _SOURCE_LANGUAGES map (source → query lang)
                          load_context → [poll_detection | propose_detection_rule]
                          → investigate → decide → execute_action → verify_action → store_cycle
  actions.py            → CloudConnector ABC + AzureConnector + check_nsg_access/check_backup_points/check_compute_access
                          list_backup_items(vault, rg) → inventaire RSV vault-wide (protected items + last RP/state),
                          indépendant de l'état des VMs (source de vérité backup même VM éteinte). Cheap leg : 1 appel
                          paginé, pas de count RP par item (count = check_backup_points par VM, opt-in). Read-only OK.
                          list_nsgs() → inventaire NSG réel (network_security_groups.list_all) : tous les NSG +
                          associations (subnets/nics) + `vms` (resource_ids gouvernés, via nic→vm/subnet→vms d'un
                          network_interfaces.list_all) + restriction Glorfindel (rule `glorfindel-*`). Corrige le
                          sous-comptage de check_nsg_access (dérivé par-VM : rate le NSG subnet quand la NIC a le
                          sien, le NSG d'un subnet AKS, les VMs éteintes). `vms` → War Room : flag monitored
                          (VM hors-LAW = angle mort) + glow de la/les carte(s) VM au survol. Read-only OK.
  detectors.py          → DetectionConnector ABC + AzureMonitorDetector (poll 10s) + run_query()
                          run_query/poll_alert REMONTENT les échecs de query (lèvent), ne les avalent
                          plus en `[]`/no-match : un LAW injoignable (supprimé/IAM/GUID faux) était
                          indistinguable d'un LAW sain sans détection → détection aveugle en silence +
                          fausse éviction discovery. poll_alert ne lève que sur échec PERSISTANT (jamais
                          un seul SUCCESS dans la fenêtre ; 0 row sur query réussie = no-match légitime).
                          Handlers en aval déjà prêts (discovery except→None garde cache ; poller
                          except→last_error ; investigate try→[]). /api/state.monitoring_backends porte
                          `reachable`/`last_error` (dérivé du poll status) → War Room rougit le DETECT.
  detection_rules.py    → DetectionRule dataclass + RulePoller (continuous polling, status persistence)
                          load_config(path, glorfindel_cfg=None) — workspace_id résolu depuis glorfindel_cfg
                          _resolve_backend_for_rule() — la règle se LIE au backend de glorfindel-config :
                            backend nommé s'il existe ; sinon fallback sur l'unique backend du type de la règle
                            (cas mono-LAW → le nom dans detection_rules.yaml devient optionnel). Échec bruyant
                            (warning) si nom absent / ambiguïté / 0 backend — jamais de workspace_id="" silencieux.
                            Règle non résolue → enabled=False (ne poll pas). monitoring_backend_name = nom RÉSOLU
                            (l'asset matching de expand_for_discovered en dépend). start()/expand respectent enabled.
                          RulePoller.expand_for_discovered(registry, glorfindel_cfg) — démarre threads
                          par (règle auto_apply, asset découvert), thread s'arrête si asset évincé
  audit.py              → AuditCheck (+ champ `data` structuré : nsg/nsg_scope + nsgs[] multi-NIC, points/protected), AuditResult,
                          run() — NSG/backup/compute readiness checks en parallèle, IAM gap detection
  proposed_rules.py     → record/pending/approve()/reject() — detection rule proposal lifecycle
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py          → IncidentRegistry (TTL, persist, thread-safe)
  cli.py                → watch, respond, restore (--wait), release, unblock, reset (revert=alias), list, pending, ack,
                          audit (--all), approve-rule, reject-rule, check-ttl, jobs, bot, dashboard, war-room
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés)
  bot.py                → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command
  tui.py                → Rich TUI full-screen (glorfindel dashboard) : resources + feed + escalations, raccourcis a/r/x/u/v
  api.py                → FastAPI War Room — /api/state (expose autonomy_modes, autonomy_default,
                          read_only, capability), /api/feed (WS), /api/config, /api/audit[/<vm>],
                          /api/pending/rules, /api/action/{release,revert,restore,ack,approve-rule,snapshot/<vm>}
                          /api/action/approve/{esc_id} — exécute l'action retenue d'un mode_hold (action_params)
                          /api/autonomy/{vm} (set_asset_mode) + /api/config/autonomy/default (set_default_mode)
                          /api/discovered — assets découverts (lecture fraîche JSON à chaque appel)
                          /api/jobs/<vm> — état du job snapshot/restore en cours (lit active_jobs/<vm>.json)
  static/index.html     → War Room web UI — cards VM expandables (compact + étendu), feed live
                          bandeau INFRASTRUCTURE (posture) : 2 axes orthogonaux — régime credentials
                          (👁 OBSERVE-ONLY ↔ ⚡ ACTIVE) + autonomy (⚡ non-disruptive / 👁 human-only).
                          Langage couleur : orange = peut agir, bleu = observe. Tue « absence de badge = actif ».
                          Mode autonomie : dropdown ⚙ Config (défaut global) + badge par carte cliquable
                          → popover capacité (ce que Glorfindel fait seul par mode, lit /api/state.capability)
                          boutons ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux) | 🔄 Restore
                          grisage read-only préventif (_applyReadOnlyGuards) : write désactivés en observe-only,
                          Ack/Cmd restent actifs. Badge VM OFFLINE (heartbeat >15min, reste grisée, rétention 8h).
                          Approve & execute paramétré : block_suspicious_ip en 1-clic (action_params.ip ou invite)
                          section BACKUP par carte : nb de RPs, âge dernier backup, bouton 📸 Snapshot (fire-and-forget RSV)
                          carte MONITORING : backends + assets découverts + règles cliquables (modal query)
                          panneau ⚙ Config : Azure credentials + LLM + mode autonomie global
  rules/azure/
    detection_rules.yaml → rules UNIQUEMENT — queries KQL, TTPs, noms de backends
                           PAS de workspace_id, resource_id, ni section assets
                           assets: [auto] → s'applique aux VMs découvertes par le backend
                           monitoring_backends: [law-celebrimbor-amonsul] par rule → nom du backend
                           (OPTIONNEL : omis si un seul backend du type, cas mono-LAW → résolution fallback)

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
infra/terraform/              → module Celebrimbor : infra de test Azure modulaire, namespacée, jetable.
                                Celebrimbor = le bâtisseur (annatar=rouge, glorfindel=bleu, celebrimbor=infra).
                                Pilotée par config.yaml (yamldecode + for_each). instance = WORKSPACE Terraform :
                                "default" → noms canoniques (vm-celebrimbor-gondolin, law-celebrimbor-amonsul,
                                rsv-celebrimbor-erebor, rg-celebrimbor) ; instance nommée → tout suffixé "-<instance>"
                                + state isolé → stacks parallèles (pipelines short/long run).
                                Topologies de validation dans config.yaml (topologies.<n>.enabled, toutes false
                                par défaut), gated par for_each, 1 RG par topo. topo_multinic.tf = topo #1 (2 NIC).
                                Cibles : make celebrimbor-{plan,up,down,output,stop,start} [INSTANCE=] [TOPO=].
                                Schéma de noms type-celebrimbor-nom (CAF) : VM=cités, LAW=tours de guet, RSV=coffres.

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
                                réconcilié par la boucle watch (`jobs.reconcile_jobs`, cadence TTL ~1min) :
                                poll Azure (`refresh_job`, source unique CLI+API+watch) → Completed/Failed ;
                                garde-fou déterministe → `Stale` si InProgress > 24h (job mort, sinon InProgress
                                éternel — un snapshot a traîné 10j faute de `jobs --refresh` manuel)
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
glorfindel audit --all --vault <nom>         # vault non-défaut (défaut: rsv-celebrimbor-erebor)

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
GLORFINDEL_DISCOVERY_RETENTION_H=8  # rétention d'une VM éteinte dans le registre avant éviction (défaut 8h)
```

---

## Tests

```bash
pytest                    # 314 tests, 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel/
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
- **Infra Celebrimbor (Terraform)** : ~$25–35/mois (VM ~6h/jour + disques + IP + backup + LAW). Jetable — `make celebrimbor-stop` pour pauser sans détruire. ⚠️ **`celebrimbor-down` est GARDÉ** (suite incident 2026-06-25 où un `down` non scopé a emporté tout le baseline) : il est **symétrique de `up`** et **protège le baseline**. `make celebrimbor-down TOPO=multinic` → destruction **scopée** d'une topo (via `-target` sur son RG), baseline intact. `make celebrimbor-down` **sans arg refuse** et exige `CONFIRM=<instance>` pour un teardown total (baseline inclus). Retirer une topo proprement = `enabled: false` dans `config.yaml` + `make celebrimbor-up`. Convention : chaque topo définit `azurerm_resource_group.<topo>` (count) = la cible `-target`.

---

## Détails Azure à connaître

- NSG isolation = outbound deny-all → bloque AMA (`mdsd.err` : Failed to get gig token) → detection timeout sur run suivant. Toujours `glorfindel reset` avant le prochain run.
- `annatar clean` T1486 génère des I/O disque élevées → RulePoller peut matcher la règle `ransomware-disk-write` (données dans `ago(10m)`) avant le vrai run. Résultat : `detection_time_s=0`, isolation sur données du nettoyage, pas du vrai run. Fix : attendre 10 min entre `annatar clean` et `annatar run`, ou vérifier que `detection_time_s > 0` après le run.
- **Multi-NIC — isolation/block couvrent TOUTES les NICs** : un NSG s'associe à un **subnet** OU une **NIC** (≤1 chacun ; un même NSG peut être partagé entre plusieurs subnets/NICs). Une NIC est soumise à ≤2 NSG (le sien + celui de son subnet). Une VM a 1..N NICs, chacune avec 1..N ipConfigs (IP privées multiples). **Ne couvrir que la NIC primaire laisse les autres NICs ouvertes** (faux « isolé »). `_get_vm_nic_targets(rg, vm)` énumère toutes les NICs → `isolate_vm`/`block_suspicious_ip(scope="vm")` posent **un placement par NIC** : deny any/any sur un NSG de NIC (priority 100, bump des conflits), ou deny **scopé à TOUTES les IP privées de la NIC** (règle augmentée `*_address_prefixes`) sur un NSG subnet partagé (priorité libre, pas de bump). Noms de règle uniques par (VM, NIC) via `_placement_rule_base` (hash si > 80 char). `release_isolation`/`unblock_ip` défont chaque placement ; `verify_isolation`/`verify_block_ip` renvoient `verified=False` si **une seule** NIC n'est pas couverte (`uncovered_nics`). State : liste `placements[]` dans `isolation/<vm>.json` et entrée block (+ champs plats `nsg`/`nsg_scope` rétro-compat `/api/state`). **Rétro-compat** : release/verify gèrent l'ancien state single-NSG. ⚠️ `verify` confirme la **présence des règles par NIC** (pas l'API *effective security rules* — écartée : nom SDK non vérifiable hors Azure + flaky VM éteinte). ⚠️ **Phase B (backlog)** : les couches AU-DESSUS du NSG peuvent court-circuiter l'isolation et ne sont PAS encore détectées — **Azure Virtual Network Manager security admin rules** (`Always allow` globale, priorité > NSG), **UDR/route tables/Azure Firewall** (routage), **ASG**, IPs plateforme `168.63.129.16`/`169.254.169.254`. Voir mémoire `reference_azure_nsg_model`. **✅ Phase A validée sur Azure réel 2026-06-25** (topo Celebrimbor `multinic`, 2 NICs/2 NSG scope-NIC, PASS 7/7) : isolate pose la deny sur **les 2** NSG, `verify_isolation` `verified=True nics_covered=2`, retrait manuel d'une règle → `uncovered_nics` détecté, release/block/unblock multi-NIC propres. Le trou « 2e NIC joignable malgré ISOLATED » est **fermé et vérifié** (plus seulement mocké).
- **NSG subnet-level — isolation scopée à l'IP VM** (historique single-NIC, généralisé ci-dessus) : `_get_nic_nsg` prend l'NSG de la NIC si elle en a une, sinon retombe sur l'NSG du **subnet** (partagé), exposé via `nsg_scope` (`nic`|`subnet`). scope `nic` → deny any/any à priority 100 (n'affecte que la VM) ; scope `subnet` → deny **scopé aux IP privées de la VM**, priorité libre → isole UNIQUEMENT la cible. **Plus de blast radius pour isolate, même autonome.** `block_suspicious_ip(ip, resource_id, scope="vm"|"subnet")` (commit `8e085ec` + `5d32516`) :
- `scope="vm"` (défaut, **autonome**) : scopé à l'IP de la VM sur NSG subnet (inbound src=attaquant/dst=IP_VM, outbound src=IP_VM/dst=attaquant, nom suffixé par VM) ou any sur NSG NIC → ne touche que cette VM. `scoped=True`.
- `scope="subnet"` (**opt-in délibéré opérateur**) : une règle `any` (attaquant↔*) sur le **NSG du subnet** (`_get_subnet_nsg`, nom partagé sans suffixe) → bloque l'IP pour TOUT le subnet (+ VMs futures). `scoped=False` → War Room ⚠ subnet-wide. Erreur claire si le subnet n'a pas de NSG.
- `scope="subnet", replace=True` (**promote VM→subnet**, commit `522f572`) : **create-then-delete** — pose d'abord la règle subnet-wide (la VM est alors couverte) puis supprime la règle VM redondante → **jamais de gap de protection** (si la pose subnet échoue, la règle VM reste intacte, pas de rollback nécessaire). État remplacé (1 entrée), outcome porte `promoted_from`.
- Recommandation : une seule règle `any` pour le subnet-wide (pas N règles scopées) — couvre les VMs futures, cycle de vie simple. La **modal de choix** (VM vs subnet) + passage de `scope` via `/api/action approve` + affordance « Extend to subnet » (`/api/action/block-promote`) = travail War Room.
- `unblock` cible le NSG **enregistré dans l'état** (fidèle pour une règle subnet-wide), fallback résolution NIC pour l'état legacy. `verify_block` suit le scope. Principe : une action **autonome** ne modifie jamais la posture des autres VMs ; le subnet-wide est un choix explicite.
- Règles block IP persistent entre runs → conflit priority si T1110 puis T1548. Nettoyage : `glorfindel reset`.
- Priority bump `isolate_vm` : dynamique (premier slot libre ≥ 200) → fix bug conflit T1110 + T1548.
- StorageBlobLogs : latence secondes. `AzureNetworkAnalytics_CL` inutilisable (10-60min).
- Restore via REST API `IaasVMRestoreRequest OriginalLocation` → VM deallocated puis redémarrée.
- VM auto-shutdown 23h UTC → `az vm start -g rg-celebrimbor -n vm-celebrimbor-gondolin` avant chaque session (ou `make celebrimbor-start`).
- Syslog latence ~60s nominal, timeout 300s dans les scénarios.
- DCR `facility_names` doit inclure `authpriv` — `useradd` sur Ubuntu génère des messages `LOG_AUTHPRIV`. Sans ce facility, T1136.001 (account creation) ne remonte pas dans LAW. Ajouté dans `monitoring.tf` (commit 9a64e83).
- Azure Backup OriginalLocation restore laisse des disques orphelins à LUN 10 → `terraform apply` échoue sur le prochain attachement. Fix : `null_resource.clean_lun10` dans `vm.tf` détache automatiquement tout disque non-testdata à LUN 10.
- `isolate_vm` écrit `~/.glorfindel/isolation/<vm>.json` **après** confirmation des règles NSG (commit `b2a41c3`) — un 403 ne laisse plus d'état orphelin « ISOLATED » sans règle. `glorfindel reset` matche le `resource_id` en case-insensitive et `release_isolation` nettoie le state file local même si Azure n'a aucune règle.
- **Imports azure.* concurrents → deadlock `_ModuleLock`** : les imports `from azure... import ...` sont paresseux (dans les méthodes). Deux threads important `azure.core` pour la 1re fois en même temps (audit parallèle, threads de poll watch) → deadlock du système d'import Python ou « cannot import name 'Pipeline' ». Fix : `actions.warm_up_azure_sdk()` importe tout une fois sur le thread principal au démarrage de `watch` ET au début de `audit.run` (avant le ThreadPool). Commit `23c2f88`. ⚠ Tout nouveau code qui importe azure dans un thread doit pouvoir compter sur le warm-up préalable, ou l'appeler.
- **Asset non-VM (AKS / VMSS) ≠ item backup IaaS — allowlist** : seule une **VM standalone** `Microsoft.Compute/virtualMachines` est un protected item Azure Backup IaaS. **Constat terrain** : le heartbeat AMA des nœuds AKS résout l'id vers le **managed cluster** (`.../Microsoft.ContainerService/managedClusters/<n>`), PAS l'instance VMSS — donc un test sur `/virtualmachinescalesets/` seul rate le vrai AKS. `recovery_points.list` y renvoie `BMSUserErrorDataSourceObjectNotFound`, **la même erreur qu'une VM standalone non protégée** (l'erreur ne discrimine pas, la **forme du resource_id** oui). `_is_backupable_vm(rid)` (allowlist : `Microsoft.Compute/virtualMachines` ET pas `/virtualMachineScaleSets/`) — plus robuste que lister les exceptions. `check_backup_points` court-circuite → `{not_backupable: True}` sans appel Azure. `posture._check_asset` **skip TOUT** (backup + NSG + compute) si `not _is_backupable_vm` → plus aucun gap parasite (`backup_linked` ni `nsg_reachable`) sur un cluster/nœud (qui n'est ni backupable ni NSG-isolatable la voie IaaS). `audit._check_backup` → `skip`. Commits `9a7bd59` (VMSS) puis élargi managed cluster + allowlist + skip-all posture. ⚠️ L'**agrégation** d'un cluster en 1 asset logique côté Glorfindel (option A) reste backlog — le repli est fait côté War Room (groupage par resource_id partagé / `parent`).
- **Vault central multi-RG — le RG du vault ≠ le RG de la VM** : un RSV central (dans son propre resource group) peut protéger des VMs réparties sur plusieurs resource groups distincts. `check_backup_points` interrogeait le vault sous le **RG de la VM** → `ResourceNotFound` → faux « backup missing » sur TOUTES les VMs + posture_gap récurrent. Fix : `check_backup_points(resource_id, vault, vault_rg)` — le **container** d'item reste keyé par le RG de la VM (naming fabric Azure), mais le lookup `recovery_points.list`/`protected_items.get` est scopé au **RG du vault**. `vault_rg` résolu depuis `glorfindel-config.yaml` (`action_backends[].resource_group`) et propagé via `audit.run(..., vault_rg)`, `posture._vault_rg()`, `/api/audit[/<vm>]`, `glorfindel audit --vault-rg`. Fallback = RG de la VM quand vide (sandbox annatar : vault et VM co-localisés). `list_backup_items(vault, rg)` prend déjà le RG du vault.
- **Nom de container/item backup — CASSE sensible** : `recovery_points.list` est **case-SENSITIVE** sur le préfixe de type (`IaasVMContainer;` / `VM;`), alors que `protected_items.get` est **case-insensitive**. Construire en minuscules (`iaasvmcontainer;`/`vm;`) faisait réussir `protected_items.get` (→ `protected=True`) mais renvoyer `recovery_points.list` **vide** → faux « first backup pending » sur une VM **réellement** sauvegardée (RECOVER/`list_backup_items` lisait `last_recovery_point` de l'item trouvé par get → l'affichait, d'où l'incohérence posture vs RECOVER). Confirmé sur le bench Celebrimbor (`az backup recoverypoint list` montrait le RP, notre query le ratait sur la casse seule). `check_backup_points` utilise désormais le format canonique `IaasVMContainer;iaasvmcontainerv2;{rg_vm};{vm}` + `VM;...`. (⚠ `snapshot` utilise encore le préfixe minuscule via un POST REST `backup-now` — toléré par cet endpoint, laissé tel quel.)

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
az network nsg rule list -g rg-celebrimbor --nsg-name nsg-celebrimbor -o table
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

5 sessions spécialisées + 2 sessions transversales, coordonnées via `collab/`.

| Session | Fichier de rôle | Périmètre |
|---------|----------------|-----------|
| Glorfindel | `CLAUDE_GLORFINDEL.md` | `glorfindel/`, `rules/azure/`, tests unitaires Glorfindel |
| Annatar | `CLAUDE_ANNATAR.md` | `annatar/`, `annatar/scenarios/`, tests unitaires Annatar |
| Tests | `CLAUDE_TESTS.md` | Chef d'orchestre — tests fonctionnels bout en bout sur Azure réel |
| War Room | `CLAUDE_WARROOM.md` | UI/UX `glorfindel/static/index.html` + `glorfindel/api.py` |
| Infra | `CLAUDE_INFRA.md` | `infra/terraform/` — module Celebrimbor : infra Azure modulaire, namespacée, jetable + topos de validation |
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

# Session Infra
"Lis CLAUDE_INFRA.md pour tes instructions de session, puis commence par ton inbox."

# Session Review (ad hoc — challenge design et implémentations)
"Tu es la session Review d'Eregion. Lis CLAUDE.md. Ta mission : challenger les décisions architecturales, les implémentations critiques et les choix de sécurité. Commence par lire inbox_review.md."

# Session General (coordination)
"Tu es la session General d'Eregion. Lis CLAUDE.md. Ta mission : coordonner les sessions spécialisées, router les items cross-cutting, mettre à jour CLAUDE.md/README.md/ROADMAP.md. Commence par lire inbox_general.md."
```

**Protocole :** chaque session lit son inbox (`collab/inbox_<role>.md`) en début de tâche, met à jour son status (`collab/<role>_status.md`) après chaque changement significatif, et écrit dans l'inbox de l'autre si un changement a un impact cross-cutting.

---

## escalations — comportement

`gf pending` affiche les escalades avec **next steps générés par le LLM** (`suggested_steps`), contextuels à l'historique ChromaDB. Fallback statique pour les anciennes escalades sans ce champ.

**Escalade persistante — 1 carte vivante (pas N, pas figée).** La dédup `record()` (clé `action+resource_id+escalation_type` parmi les `pending`) garde **une seule** carte quand un finding re-déclenche, mais la rend vivante : `occurrences++` + `last_seen` à chaque re-fire (cheap, `first_seen` préservé → « 12× depuis 3h » d'un coup d'œil), et le contenu cher (reason/suggested_steps/confidence) **rafraîchi uniquement sur changement matériel** (delta de confiance ≥ `_MATERIAL_CONFIDENCE_DELTA`=0.1) — sinon le contenu reste stable (pas de flicker), et le **premier triage est préservé** (`first_reason`/`first_suggested_steps`/`first_confidence`). Avant : la sortie du re-`decide` était jetée → carte périmée sur un finding qui dure (constat terrain). ⚠️ Deux raffinements **différés** (touchent des hot-paths, validation run réel requise) : (a) throttle du re-`decide` LLM lui-même (risque de masquer un changement matériel si l'équivalence est trop lâche — `indicator_value` varie) ; (b) résolution du mismatch `Computer`≠`resource_id` via la map discovery (change l'input LLM via `normalize_row` → run end-to-end requis).

Types d'escalade : `low_confidence` (detection_timeout + snapshot), `destructive_action` (HUMAN_APPROVAL_REQUIRED), `proposed_action` (action inconnue), `verification_failed`, `proposed_rule` (règle de détection proposée après detection_missed), `mode_hold` (action autonome retenue par le mode `human_only` de l'asset — pas un manque de confiance), `write_blocked` (action tentée mais credentials read-only / IAM 403 — capability gap, pas un choix de politique), `action_failed` (échec Azure non-auth pendant l'exécution — toujours escaladé, jamais d'abort silencieux du cycle).

L'escalade porte `action_params` (dict, vide par défaut) pour les actions paramétrées — ex. `block_suspicious_ip` → `{"ip": ...}` extrait du signal via `_extract_suspicious_ip` (même source que `execute_action`). Permet à la War Room « Approve & execute » d'exécuter en 1 clic une action qui n'est pas à `resource_id` seul. Commit `9583ec6`.

`gf ack <id>` / `gf ack --all` → marque `resolved` dans `~/.glorfindel/escalations.jsonl`. Purement administratif — ne fait rien sur Azure. `restore_from_backup` auto-acquitte via `resolve_by_resource`. Les `posture_gap` s'**auto-résolvent** quand la condition disparaît (ex. backup nocturne comble « no recovery point yet ») — `PostureChecker.check_and_escalate` résout l'escalade au cycle suivant (commit `b208a0a`).

⚠️ **Ack d'un posture_gap encore RÉEL** : l'ack ne fait que `resolve` l'escalade ; `posture_state.json` gardait `status: "pending"` → le cycle suivant voyait « mon escalade n'est plus pending mais le gap existe toujours » → **recréait une escalade à chaque cycle** (ack inutile sur un gap persistant, ex. 14 VMs vraiment sans backup). Fix : `_maybe_escalate` interprète « pending + escalade absente de `pending()` » comme **acquitté** → `status: "acknowledged"`, ne ré-escalade plus. Le gap n'est ré-alerté que s'il **se résout puis réapparaît** (`_resolve_cleared_gaps` transitionne `pending`/`acknowledged` → `resolved` quand la condition disparaît). Un gap `acknowledged` sort de `active_gaps()` (n'apparaît plus dans `/api/state`).

⚠️ **Éviction ≠ condition résolue** : `_resolve_cleared_gaps` ne résout un gap que si son asset a été **réellement checké ce cycle** (`checked_vms`). Une VM éteinte > rétention (8h) → évincée de l'inventaire → **non checkée** → ses gaps sont **gelés** (ack préservé), PAS résolus. Sinon : VM éteinte le weekend → gap résolu à l'éviction → re-découverte lundi → **ré-escalade fraîche en masse** (le « flood du lundi », acks effacés). Avec le gel, un gap `acknowledged` reste silencieux au retour de la VM. Effet de bord assumé : une VM **supprimée** (pas juste éteinte) garde son gap gelé jusqu'à un ack (qui tient). Pour une VM intentionnellement sans backup → `exceptions:` dans `glorfindel-config.yaml` (sort du check, pas juste un ack).

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
