# Fichiers clés

_Extrait tel quel de `CLAUDE.md` le 2026-10-15 (lot DX1) : le rôle de chaque fichier et l'état local. Les règles de sûreté et les conventions restent dans `CLAUDE.md`._

## Fichiers clés

```
glorfindel-config.yaml          → source unique pour la config infra (NE PAS confondre avec detection_rules.yaml)
                                   monitoring_backends: workspace_id LAW, endpoint Prometheus...
                                   action_backends: RSV vault_name + resource_group
                                   exceptions: fnmatch patterns opt-out par VM et/ou par règle
                                   (fichier non versionné — monté en Docker volume ou présent localement)

technique_catalog.yaml          → CONTRAT PARTAGÉ Annatar↔Glorfindel (boucle purple générative).
                                   Référentiel des techniques (resource_type → [{ttp, tactic, ...}]),
                                   seul couplage entre rouge et bleu (boucle aveugle). Bloc blue
                                   (log_source/indicator_columns/expected_latency_s) consommé par
                                   detection_authoring (autoring grounded) ; bloc red (destructive/
                                   safe_target/testdata_marker/params/reference_script) par le synthé
                                   Annatar. status: implemented | planned. Versionné (≠ config locale) ;
                                   monté en Docker (compose) + COPY Dockerfile (image autonome).

eregion_core/exercise.py        → B2 : fenêtres d'exercice des injecteurs. Annatar en ouvre une avant de toucher sa
                                   cible (setup compris) et la ferme en fin de run : runs/exercises/<run_id>.json
                                   (run_id, injector, kind, experiment, targets, start, end, expires ; ou
                                   EREGION_EXERCISES_DIR). Glorfindel en tire la source d'un cycle (exercise/real).

gothmog/                        → G0 : pannes déclarées. experiments/<id>.yaml (schéma E1, kind fault) ;
                                   engines/chaos_studio.py (ARM REST : lire l'expérience et ses cibles,
                                   démarrer/suivre/annuler, chaque écriture journalisée par Orodruin avant
                                   l'appel) ; probes.py (état normal) ; runner/engine.py (le déroulé) ;
                                   runs/<run_id>.json (forme d'Annatar) + runs/gothmog/<run_id>_signals.jsonl
                                   (hors du motif runs/*_signals.jsonl que la watch de Glorfindel lit).

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
                          Clé : l'ID de ressource pour une VM (troisième passe T1 : deux VMs de même nom
                          d'hôte dans deux groupes étaient fusionnées), le nom pour un nœud de cluster.
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
  audit.py              → « Disk write sampling » (`_check_perf_sampling`, si un workspace est configuré) : cadence réelle du compteur Disk Write Bytes/sec de la VM sur 1 h — ≤ 25 s mode fin, au-delà mode grossier (warn), aucun échantillon = détection ransomware aveugle (warn + correctif DCR) ; « Syslog » (`_check_syslog` : la VM envoie-t-elle du Syslog depuis 1 h, quelles facilities) ; « Detection rules » (`_check_rule_coverage` → `rule_coverage()`, pur : chaque règle qui s'applique à la VM, sa table (`rule_table`, la première que nomme la requête) et son état — `covered`, `blind` (sa table ne reçoit rien de la VM), `unknown`, `error` (dernier poll en échec, `rule_status.json`), `not_vm` (lignes venues d'ailleurs : stockage, identité), `excluded`, `disabled`). Tous trois en action `detection`, seulement avec un workspace (P4). « NSG precedence » est relu après coup comme la préparation le fait (`_align_precedence`, P2) : ok si l'isolation passe par le NSG de quarantaine (`readiness.isolation_by_quarantine`), réserve (warn) sinon et pour un blocage — jamais un échec
                          AuditCheck (+ champ `data` structuré : nsg/nsg_scope + nsgs[] multi-NIC, points/protected), AuditResult,
                          run() — NSG/backup/compute readiness checks en parallèle, IAM gap detection
  proposed_rules.py     → record/pending/approve()/reject() — detection rule proposal lifecycle
  detection_authoring.py → moteur d'autoring grounded (boucle purple GÉNÉRATIVE, côté bleu).
                          load_catalog()/catalog_entry() (lit technique_catalog.yaml),
                          fetch_table_schema() (KQL getschema — schéma RÉEL du LAW, best-effort),
                          author_rule() (appel LLM grounded partagé : catalogue + schéma → règle
                          proposée ; flag grounded_schema). techniques_needing_rules() (sélection
                          cold-start). Source UNIQUE du tool+prompt d'autoring (agent.py importe).
                          Deux appelants : propose_detection_rule (réactif) + `propose-rules` (proactif).
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py          → IncidentRegistry (TTL, persist, thread-safe)
  cli.py                → watch, respond, restore (--wait), release, unblock, reset (revert=alias), list, pending, ack, activate,
                          audit (--all), approve-rule, reject-rule, propose-rules, check-ttl, jobs, bot, dashboard, war-room
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
                          groupes de préparation par carte (ACTION_GROUPS) : NSG, Backup, Compute et Detection (P4 : compteur,
                          cadence, Syslog, règles qui couvrent la VM — une VM aveugle ne paraît plus normale)
                          carte MONITORING : backends + assets découverts + règles cliquables (modal query)
                          panneau ⚙ Config : Azure credentials + LLM + mode autonomie global
  rules/azure/
    detection_rules.yaml → rules UNIQUEMENT — queries KQL, TTPs, noms de backends
                           PAS de workspace_id, resource_id, ni section assets
                           assets: [auto] → s'applique aux VMs découvertes par le backend
                           monitoring_backends: [law-celebrimbor-amonsul] par rule → nom du backend
                           (OPTIONNEL : omis si un seul backend du type, cas mono-LAW → résolution fallback)

eregion_core/
  inscription.py      → O0 : LE garde-fou de cible de tout injecteur (Annatar, puis Gothmog). `Scope.check` (périmètre :
                        abonnement s'il est nommé, groupes du banc `rg-celebrimbor*` ou liste, IDs) — à la synthèse ET à
                        l'exécution ; `enrollment` (tags `eregion-target=<banc>` sur le groupe ET la VM, noms sans casse,
                        valeurs exactes ; `eregion-zone` de la VM, celle du groupe doit concorder ; `annatar-test=true` =
                        zone `bench`, migration) ; `check_zone` (production : technique non destructive seulement,
                        `destructive=None` refusé, panne jamais) ; `check_target` = les trois. Banc : `EREGION_BENCH`
                        (défaut `celebrimbor`, instance nommée `celebrimbor-<nom>`). Tout inconnu est refusé.

annatar/
  runner/engine.py    → inscription (`eregion_core.inscription.check_target` : périmètre du banc + tags `eregion-target`/`eregion-zone`
                        sur le groupe ET la VM + zone ; `scenario_destructive()` = champ du scénario puis catalogue ; `annatar clean` gardé aussi, destructif) → setup → integrity check → attack
                        → emit attack_started (sans query — Glorfindel résout via detection_rules.yaml)
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

schemas/scenario.schema.json      → JSON Schema (technique Annatar, validation IDE)
schemas/experiment.schema.json    → E1 : schéma d'EXPÉRIENCE versionné (v1) — technique OU panne, une
                                    même forme. `kind` absent = technique, `engine` absent = local-script →
                                    les scénarios actuels valident sans changement. Champs : id, kind, engine,
                                    engine_ref, targets (sélecteur sur l'inscription), steady_state, abort_conditions,
                                    revert, detection.hints, destructive, status. Vit À CÔTÉ de scenario.schema.json
                                    pendant la migration.
schemas/technique_catalog.schema.json → E1 : schéma du catalogue. Pannes dans une liste `faults:` à part (id propre, pas
                                    de TTP ATT&CK), invisible des chargeurs de techniques d'Annatar et de Glorfindel ;
                                    une technique sur un autre moteur que local-script : `engine_ref`, pas de script ni d'étapes
eregion_core/experiment.py        → validate_experiment() / validate_catalog() (jsonschema, import paresseux ;
                                    dev/CI, pas sur le hot-path) — la CI valide le catalogue via les tests
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
  isolation/<vm>--<h>.json    → état NSG isolation + TTL. Clé = nom + hash de l'ID de ressource (troisième
                                passe : deux VMs homonymes partageaient `<vm>.json`) ; un ancien `<vm>.json` n'est
                                lu que s'il porte cet ID, migré à la première écriture ; par nom seul, un nom
                                ambigu ne résout rien. Toujours lire via `_load_isolation_state(resource_id)`.
                                Nom en minuscules ; un fichier est retrouvé par son HASH quelle que soit la casse
                                (`_hash_variants`) ; à l'écriture, les autres variantes sont supprimées SAUF celle qui
                                est la cible (`samefile` — sur macOS/Windows/Docker Desktop `VM-Foo--h` et `vm-foo--h`
                                sont le même fichier : cinquième passe C1) ; `migrate_state_files()` au démarrage du watch.
                                CI : job macOS (APFS insensible à la casse) ; `main` protégée, checks requis.
  blocks/<vm>--<h>.json       → IPs bloquées par VM (même clé)
  proposed_rules.jsonl        → règles de détection proposées (en attente d'approbation)
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  rule_status.json            → état de polling des règles (last_poll, last_match, match_count, last_error)
  readiness.json              → verrou L6 par VM, clé `nom--hash(ID)` (quatrième passe Q3 : un homonyme héritait du
                                verdict « prête ») ; un nom seul ambigu ne résout rien → VM retenue : dernier contrôle de préparation + réserves acceptées
                                (active_since, alerted) — écrit par le watch (tracker) et la War Room
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
