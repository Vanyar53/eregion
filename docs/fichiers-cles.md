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
eregion_core/exercise_channel.py → O1 : les fenêtres d'Orodruin vers la watch hébergée (conteneur exercises).
                                   Porte aussi les campagnes finies (campaigns/<id>/…, #167) et le rapport d'un
                                   run seul (runs/<run_id>.json, #193) ; sur H0, runs/.pulled-runs/<run_id>
                                   marque un rapport tiré du canal (jamais écrit par-dessus un run de H0).
eregion_core/watch_channel.py   → #159 : le sens retour (conteneur watch) — heartbeat.json {at, since, windows} et
                                   detections/<run_id>/<signal_id>.json, écrits par la watch hébergée (Publisher,
                                   thread watch-channel), lus par l'attente d'Annatar ; miss_unprovable → unknown.
eregion_core/watch_gate.py      → V1 (#214) : avant chaque run d'Annatar et de Gothmog, avant tout appel au
                                   cloud, le battement de la watch (canal retour, ~/.glorfindel/watch_heartbeat) ;
                                   refusal() dit depuis quand date le dernier ; --without-glorfindel → le rapport
                                   porte metrics.without_glorfindel.

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
                          porte kind/parent (defaults rétro-compat cache) → /api/state → la console replie par parent.
                          Clé : l'ID de ressource pour une VM (troisième passe T1 : deux VMs de même nom
                          d'hôte dans deux groupes étaient fusionnées), le nom pour un nœud de cluster.
                          replace_for_backend() : refresh + rétention — une VM absente du Heartbeat (éteinte)
                          est retenue (last_seen figé) tant que gap < GLORFINDEL_DISCOVERY_RETENTION_H (défaut 8h), puis évincée
                          None sur erreur query → cache conservé (pas d'éviction sur panne)
                          audit.run() lance NSG/backup/compute en parallèle (le RSV ne s'empile plus sur le reste)
  agent.py              → LangGraph 8 nodes + _SOURCE_LANGUAGES map (source → query lang)
                          load_context → [poll_detection | propose_detection_rule]
                          → investigate → decide → execute_action → verify_action → store_cycle
  actions.py            → façade (A1, 26/10) : `from glorfindel.actions import X` marche pour chaque nom
                          de l'ancien fichier de 4 394 lignes, découpé sans changer son texte. Un seul espace
                          de noms : un nom écrit à travers elle (monkeypatch de `_ISOLATION_STATE_DIR`, `_vm_lock`…)
                          l'est dans chaque module qui le lie ; un nom est lu dans son module, à jour.
                          Sur glorfindel.actions : monkeypatch.setattr, jamais mock.patch (il supprime le nom
                          en sortie : la façade refuse, la valeur patchée resterait partout) ; ou mock.patch
                          sur le module d'origine (ce module seul).
  response/             → cœur neutre : policy.py (AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED, erreurs,
                          isolation_verdict, single_host_ip), ids.py, state.py (~/.glorfindel/isolation, blocks),
                          locks.py (_vm_lock, _quarantine_lock)
  providers/interface.py → MC0 : CloudConnector, DetectionConnector, et les capacités qu'un fournisseur déclare
                          (Capability : nom commun, actions servies, droits requis) ; capabilities_of(connector) —
                          la préparation (readiness.py) lit les droits là, plus dans ses propres constantes
  providers/azure/      → le seul adaptateur, le seul endroit de glorfindel/ qui importe le SDK Azure
                          (tests/unit/test_provider_boundary.py, étape CI « Provider boundary ») :
                          connector.py (AzureConnector = un mixin par préoccupation + garde d'abonnement + verrou
                          de VM sur les écritures), nsg.py (règles lues par contenu), network.py, quarantine.py,
                          isolation.py, release.py, verify.py, blocks.py, unblock.py, backup.py (+ restore_job_status,
                          lu par jobs.py), restore.py, sweep.py, readers.py (check_permissions, check_nsg_access,
                          list_nsgs, check_compute_access…), sdk.py (warm-up), capabilities.py, monitor.py
                          (AzureMonitorDetector, réexporté par detectors.py), activity.py (AzureActivityDetector, AL1 :
                          le journal d'activité, détection seule ; écritures de Glorfindel écartées, ses règles marquées),
                          entra.py (AzureEntraDetector, C2 : les journaux d'Entra ID, détection seule ; seuils en code,
                          identité de Glorfindel marquée acteur ou cible, jamais écartée ; texte et étapes des cartes)
                          backup.py : check_backup_points ; list_backup_items(vault, rg) → inventaire RSV vault-wide (protected items + last RP/state),
                          indépendant de l'état des VMs (source de vérité backup même VM éteinte). Cheap leg : 1 appel
                          paginé, pas de count RP par item (count = check_backup_points par VM, opt-in). Read-only OK.
                          readers.py : list_nsgs() → inventaire NSG réel (network_security_groups.list_all) : tous les NSG +
                          associations (subnets/nics) + `vms` (resource_ids gouvernés, via nic→vm/subnet→vms d'un
                          network_interfaces.list_all) + restriction Glorfindel (rule `glorfindel-*`). Corrige le
                          sous-comptage de check_nsg_access (dérivé par-VM : rate le NSG subnet quand la NIC a le
                          sien, le NSG d'un subnet AKS, les VMs éteintes). `vms` → console : flag monitored
                          (VM hors-LAW = angle mort) + glow de la/les carte(s) VM au survol. Read-only OK.
  detectors.py          → detector_for() ; DetectionConnector et AzureMonitorDetector (poll 10s) + run_query()
                          vivent dans providers/ depuis A1, réexportés ici
                          run_query/poll_alert REMONTENT les échecs de query (lèvent), ne les avalent
                          plus en `[]`/no-match : un LAW injoignable (supprimé/IAM/GUID faux) était
                          indistinguable d'un LAW sain sans détection → détection aveugle en silence +
                          fausse éviction discovery. poll_alert ne lève que sur échec PERSISTANT (jamais
                          un seul SUCCESS dans la fenêtre ; 0 row sur query réussie = no-match légitime).
                          Handlers en aval déjà prêts (discovery except→None garde cache ; poller
                          except→last_error ; investigate try→[]). /api/state.monitoring_backends porte
                          `reachable`/`last_error` (dérivé du poll status) → la console rougit le DETECT.
  detection_rules.py    → DetectionRule dataclass + RulePoller (continuous polling, status persistence)
                          load_config(path, glorfindel_cfg=None, client_layer=True) — workspace_id résolu depuis
                          glorfindel_cfg ; P1 : la base `path`, puis la couche du client par-dessus (merge_layers :
                          une règle du client du nom d'une règle de base la remplace, `disable: [nom]` la désactive,
                          tout est dit — DetectionConfig.notes, journal une fois par processus ; DetectionRule.layer)
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
  proposed_rules.py     → record/pending/approve()/reject() — detection rule proposal lifecycle ; approve() écrit
                          la règle dans la couche du client (P1), jamais dans la base livrée
  rule_layers.py        → P1 : la couche du client — write_client_rule (atomique, verrou, refuse d'écrire sur une
                          couche illisible), migrate (règles approuvées dans la base avant P1 → couche ; une
                          règle au workspace en ligne liée à son backend). P1 n'exporte pas : l'export d'une règle généralisée, sans identifiant, est reporté à un lot rattaché à P2 (relu par un humain avant tout envoi)
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
                          audit (--all), approve-rule, reject-rule, propose-rules, rules, migrate-rules, check-ttl, jobs,
                          bot, dashboard
                          (war-room : alias caché d'`eregion console`)
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés) ;
                          SEC3 : chaque écriture sous le verrou du magasin, le magasin réécrit entier
  signal_origin.py      → SEC3 (#274) : ce que la watch prend de runs/*_signals.jsonl — les événements qu'un
                          injecteur émet (attack_started → la règle de la watch, detection_missed → une proposition,
                          attack_adapted → noté), et d'eux les seuls champs qu'il écrit ; le reste refusé (journal,
                          compteur), jamais décidé. Le recovery_complete : seul celui de `glorfindel restore` (ce
                          processus, ou ~/.glorfindel/recovery_signals/) lève une isolation seul
  bot.py                → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command ;
                          ButtonPolicy (M-3) : DISCORD_ALLOWED_USERS / _ROLES, fermé par défaut
  tui.py                → Rich TUI full-screen (glorfindel dashboard) : resources + feed + escalations, raccourcis a/r/x/u/v
  rules/azure/
    detection_rules.yaml → la BASE LIVRÉE (P1) : rien ne l'écrit plus, une mise à jour la remplace ;
                           les règles du déploiement vont dans ~/.glorfindel/client_rules.yaml
                           rules UNIQUEMENT — queries KQL, TTPs, noms de backends
                           PAS de workspace_id, resource_id, ni section assets
                           assets: [auto] → s'applique aux VMs découvertes par le backend
                           monitoring_backends: [law-celebrimbor-amonsul] par rule → nom du backend
                           (OPTIONNEL : omis si un seul backend du type, cas mono-LAW → résolution fallback)

eregion_console/                → la console d'Eregion (`eregion console`, docs/design/console.md, #205) ; jusqu'au
                                  26/10, glorfindel/api.py et glorfindel/static/ (la War Room et l'atelier)
  api.py                → FastAPI — pages / (Overview), /glorfindel, /annatar, /gothmog, /config ; jeton
                          (EREGION_CONSOLE_TOKEN s'il n'est pas vide, sinon GLORFINDEL_WARROOM_TOKEN) ;
                          /api/state (autonomy_modes, autonomy_default, read_only, capability), /api/feed (WS),
                          /api/config, /api/audit[/<vm>], /api/pending/rules,
                          /api/action/{release,revert,restore,ack,approve-rule,snapshot/<vm>}
                          /api/action/approve/{esc_id} — exécute l'action retenue d'un mode_hold (action_params)
                          /api/autonomy/{vm} (set_asset_mode) + /api/config/autonomy/default (set_default_mode)
                          /api/discovered — assets découverts (lecture fraîche JSON à chaque appel)
                          /api/jobs/<vm> — état du job snapshot/restore en cours (lit active_jobs/<vm>.json)
                          /api/exercises[?injector=], /api/campaigns[/<id>], /api/catalog[?kind=], /api/channel,
                          /api/channel/detections/<run_id> — Annatar et Gothmog, GET seulement ;
                          /api/sections ; /runs/<id> → la section de l'injecteur ; /atelier → / et
                          /api/atelier/* → /api/* (308, jusqu'à la 1.0)
  sections.py           → sections actives : Glorfindel toujours, Annatar et Gothmog dès que l'hôte a leurs runs
                          (fenêtre, rapport, campagne), ou ce que --sections / EREGION_CONSOLE_SECTIONS choisit
  cli.py                → `eregion console [--host] [--port] [--sections]`
  indicators.py         → les cinq indicateurs de la finalité (UI-2) : sur 30 jours, rapports de run, cycles de la
                          watch, cartes, catalogue — jamais les fenêtres ; `GET /api/indicators`
  static/console.js     → en-tête commun : onglets (actifs ou grisés), battement de la watch, canal retour,
                          cartes à juger, horloge UTC ; console.css, la palette
  static/overview.html  → l'accueil : une ligne par section, les canaux ; les cinq indicateurs avec UI-2 (#206)
  static/injector.html  → pages d'Annatar et de Gothmog (même page, filtrée par le chemin) : fenêtres
                          d'exercice et ce que Glorfindel a fait dans chacune, campagnes (faits + report.md),
                          techniques ou pannes du catalogue ; grisée, ce que l'injecteur ajouterait
  static/exercises.js   → ce que Glorfindel a fait dans une fenêtre (partagé par l'accueil et les injecteurs)
  static/*.js           → le script de chaque page, un fichier (overview.js, glorfindel.js, injector.js) : la
                          CSP n'admet que les scripts servis par la console (#257) ; dans glorfindel.js,
                          _on et le répartiteur des événements (ACTIONS, data-on-*)
  static/glorfindel.html → page Glorfindel (/glorfindel, /config) — TO JUDGE (seul endroit où l'on juge
                          une carte, 26/10), cards VM expandables (compact + étendu), feed live
                          bandeau INFRASTRUCTURE (posture) : 2 axes orthogonaux — régime credentials
                          (👁 OBSERVE-ONLY ↔ ⚡ ACTIVE) + autonomy (⚡ non-disruptive / 👁 human-only).
                          Langage couleur : orange = peut agir, bleu = observe. Tue « absence de badge = actif ».
                          Mode autonomie : dropdown de Config (défaut global) + badge par carte cliquable
                          → popover capacité (ce que Glorfindel fait seul par mode, lit /api/state.capability)
                          boutons ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux) | 🔄 Restore
                          grisage read-only préventif (_applyReadOnlyGuards) : write désactivés en observe-only,
                          Ack/Cmd restent actifs. Badge VM OFFLINE (heartbeat >15min, reste grisée, rétention 8h).
                          Approve & execute paramétré : block_suspicious_ip en 1-clic (action_params.ip ou invite)
                          section BACKUP par carte : nb de RPs, âge dernier backup, bouton 📸 Snapshot (fire-and-forget RSV)
                          groupes de préparation par carte (ACTION_GROUPS) : NSG, Backup, Compute et Detection (P4 : compteur,
                          cadence, Syslog, règles qui couvrent la VM — une VM aveugle ne paraît plus normale)
                          nœud DETECT : backends + assets découverts + règles cliquables (modal query)
                          /config : Azure credentials + LLM + mode autonomie global + sections

eregion_core/
  inscription.py      → O0 : LE garde-fou de cible de tout injecteur (Annatar, puis Gothmog). `Scope.check` (périmètre :
                        abonnement s'il est nommé, groupes du banc `rg-celebrimbor*` ou liste, IDs) — à la synthèse ET à
                        l'exécution ; `enrollment` (tags `eregion-target=<banc>` sur le groupe ET la VM, noms sans casse,
                        valeurs exactes ; `eregion-zone` de la VM, celle du groupe doit concorder ; `annatar-test=true` =
                        zone `bench`, migration) ; `check_zone` (production : technique non destructive seulement,
                        `destructive=None` refusé, panne jamais) ; `check_target` = les trois. Banc : `EREGION_BENCH`
                        (défaut `celebrimbor`, instance nommée `celebrimbor-<nom>`). Tout inconnu est refusé.
  signals.py          → D1 : le contrat des signaux (Signal + severity_for_ttp), écrit par les injecteurs, lu par
                        la watch — dans le cœur, pour que Glorfindel tourne sans Annatar (ex-annatar/signals/schema.py).

scripts/console_escaping.py → #254, #257 : rien du dehors n'est écrit brut dans la console — suit ce que peut
                        contenir chaque ${…} d'un gabarit HTML, chaque valeur donnée à innerHTML et chaque
                        concaténation, selon sa place (texte, début d'URL) ; refuse les gestionnaires et
                        scripts en ligne, javascript:, srcdoc et les API qu'il ne suit pas ; tests :
                        tests/unit/test_console_escaping.py.

scripts/component_check.py → D1 : chaque composant tourne seul — Glorfindel, Annatar, Gothmog et le cœur, leurs
                        modules importés et leurs tests joués avec les autres composants ABSENTS (un chercheur en
                        tête de sys.meta_path), et les dépendances de Glorfindel absentes pour un injecteur ; les
                        passerelles permises (BRIDGES, CROSSINGS) avec leur raison. CI : components.yml ; tests :
                        tests/unit/test_components.py. Les profils d'usage : docs/profils/, tests/unit/test_profiles.py.

annatar/
  runner/engine.py    → inscription (`eregion_core.inscription.check_target` : périmètre du banc + tags `eregion-target`/`eregion-zone`
                        sur le groupe ET la VM + zone ; `scenario_destructive()` = champ du scénario puis catalogue ; `annatar clean` gardé aussi, destructif) → setup → integrity check → attack
                        → emit attack_started (sans query — Glorfindel résout via detection_rules.yaml)
                        → thread daemon feedback: si detection_timeout → emit detection_missed
                        → runs/<run_id>.json réécrit après l'attente : detection + detection_latency_s (#157)
  runner/detection.py → règle pure : quelle détection compte pour un run (TTP, resource_id sans la casse, vue ≥ attack_time)
                        et sa latence depuis attack_time — les deux chemins de l'attente, et le canal retour (#159)
  runner/parser.py    → Scenario dataclass simplifié (detection: timeout/prerequisites/hints)
  signals/emitter.py  → signal normalisé JSONL ; le contrat (Signal + severity_for_ttp) est dans eregion_core/signals.py,
                        lu aussi par Glorfindel (D1 : sorti d'Annatar, pour que Glorfindel tourne sans lui)

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

~/.glorfindel/                → SEC3 : fichiers d'état en 0600, dossiers en 0700, écrits entiers (fichier temporaire +
                                `os.replace`) ; un état d'une version antérieure est resserré au démarrage du watch.
                                Qui écrit : la watch, la console, le bot et la CLI (le même utilisateur). Les injecteurs
                                (Annatar, Gothmog) n'en voient que `injectors/`, en lecture seule (compose, Makefile)
  injectors/watch_heartbeat   → SEC3 (N-05) : copie du battement de la watch, le seul fichier que lisent les injecteurs
                                (garde V1) — leur conteneur monte ce dossier comme son ~/.glorfindel. 0644 (dossier 0755) : à lire
                                par eux, rien de secret. Retiré à l'arrêt
  watch_heartbeat             → le battement de la watch (V1 sur cet hôte, la console, le CD de H0)
  escalations.jsonl           → escalades persistées. SEC3 (V-10) : chaque lecture-modification-écriture sous un
                                verrou (`flock` sur `escalations.jsonl.lock`, `response/locks.py::_file_lock`), le
                                magasin réécrit entier : aucune carte perdue entre écrivains, aucune lecture tronquée
                                (`tests/unit/test_locks.py`, vrais processus)
  recovery_signals/           → SEC3 (V-05) : le `recovery_complete` qu'écrit `glorfindel restore --wait` pour un
                                `glorfindel respond` plus tard — seul endroit d'où ce signal lève une isolation seul
                                (`glorfindel/signal_origin.py`) ; plus `runs/recovery/`, que les injecteurs écrivent
  channel_refusals.json       → SEC3 (V-05) : les lignes de `runs/` que la watch a refusées, comptées par événement
                                (la dernière : fichier, heure, raison)
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
  quarantine_alerts.json      → I1F : NSG de quarantaine → le changement déjà signalé (carte `quarantine_altered`) ;
                                oublié quand le NSG est de nouveau entier, ne porte plus rien ou a disparu (relu par son ID : 404, I1S) — un acquittement ne relève pas de carte
  orphan_alerts.json          → A3 : règle orpheline (NSG/règle) → sa carte `orphan_rule` ; une règle dite ne l'est pas de nouveau
                                tant qu'elle reste ; oubliée (carte fermée) quand elle n'est plus orpheline ou a été retirée
  proposed_rules.jsonl        → règles de détection proposées (en attente d'approbation)
  client_rules.yaml           → P1 : la couche du client — règles approuvées (`approve-rule`, War Room), règles de
                                base remplacées (même nom) ou désactivées (`disable:`), chargée par-dessus la base
                                livrée. Hors du dépôt : une mise à jour ne la touche jamais (conteneurs : base `:ro`)
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  rule_status.json            → état de polling des règles (last_poll, last_match, match_count, last_error)
  readiness.json              → verrou L6 par VM, clé `nom--hash(ID)` (quatrième passe Q3 : un homonyme héritait du
                                verdict « prête ») ; un nom seul ambigu ne résout rien → VM retenue : dernier contrôle de préparation + réserves acceptées
                                (active_since, alerted) — écrit par le watch (tracker) et la console
  discovered_assets.json      → cache assets découverts (AssetRegistry) — survit aux redémarrages
  active_jobs/<vm>.json       → état persisté du job snapshot/restore en cours (partagé CLI/console)
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
