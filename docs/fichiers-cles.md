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

eregion_core/channel_reader.py  → SEC8, SEC16 : le seul lecteur de runs/, pour tous les composants (la watch,
                                   la console, l'analyse, Annatar) — un fichier ordinaire seulement, jamais à
                                   travers un lien, jamais bloquant, une lecture bornée ; et l'écriture tenue de
                                   même (append_line : une ligne entière ; write_file : un fichier remplacé, un lien
                                   jamais suivi). Jusqu'à SEC16 : glorfindel/channel_reader.py.
eregion_core/action_queue.py    → FS1a (#551) : la file d'actions signée, son format et sa vérification — la demande
                                   d'un service (console, bot) signée par sa clé sous eregion.action-request/1, la
                                   proposition que la watch signe sur ses cartes sous eregion.action-queue/1, les verbes
                                   (liste fermée, ceux de chaque service), les refus (liste fermée, REFUSALS) ;
                                   verify_request (pur : forme, signature, clé épinglée EREGION_QUEUE_KEYS, service,
                                   fraîcheur, nonce, verbe, débit), proposal_refusal ; la clé d'un service tirée par le
                                   code de watch_key (~/.eregion/console|bot/queue_ed25519). FS1b (#563) : la file sur
                                   le disque (deposit, read_receipt, await_receipt, ask : le geste d'un service, son reçu
                                   attendu), le drapeau EREGION_ACTION_QUEUE (enabled : « 1 », faux par défaut), le
                                   registre durable (SeenFile, ConsumedFile, fsync), le débit avant le registre,
                                   proposal_fresh ; `python -m eregion_core.action_queue public|pin` (make queue-keys)
                                   — docs/design/file-actions-signee.md
glorfindel/queue_watch.py       → FS1b (#563) : la watch relève la file (derrière EREGION_ACTION_QUEUE=1), dans un fil
                                   à elle — reçu received, vérification, rattachement, gardes rejouées, posture,
                                   proposition consommée, accepted, exécution sous _vm_lock, done/failed ; reçus et
                                   statut signés (runs/glorfindel/queue/), cartes queue_tampered (critiques) et
                                   queue_unavailable ; recover : un arrêt entre réclamation et fin dit interrupted
glorfindel/approval.py          → FS1b : les gardes d'un geste humain, un seul code pour la console et la watch —
                                   approval_refusal (l'âge : last_seen pour la console, l'issued_at signé pour la
                                   watch), address_refusal, scope_refusal, held_isolation/held_block(s), in_perimeter,
                                   discord_refusal, verify_approved
glorfindel/gestures.py          → FS1b : la levée et le reset de la CLI en fonctions (release_needed, reset_targets,
                                   reset_apply), appelées par la CLI et par la watch
eregion_console/action_requests.py → FS1b : le côté console de la file (ask, answer) — les routes d'écriture, derrière
                                   EREGION_ACTION_QUEUE=1
eregion_core/runs_layout.py     → SEC18 (N-05) : runs/ un répertoire par écrivain — glorfindel/, console/, annatar/,
                                   gothmog/, orodruin/, verdicts/, bot/ (FS1b : ses demandes de la file, queue/) ; ce que chacun tient (belongs), où un lecteur trouve les
                                   campagnes et les rapports (campaign_dirs, find_campaign, run_reports), où l'analyse
                                   écrit (campaign_output), ce qui n'est pas lu, dit une fois (survey, say_strays), le
                                   rapport d'un run tenu contre son répertoire (report_refusal), la migration de
                                   l'ancienne disposition (migrate ; python -m eregion_core.runs_layout migrate|survey,
                                   make runs-migrate, runs-survey). Bibliothèque standard seule (H0 la lance hors image).
eregion_core/exercise.py        → B2 : fenêtres d'exercice des injecteurs. Annatar en ouvre une avant de toucher sa
                                   cible (setup compris) et la ferme en fin de run : runs/<injecteur>/exercises/<run_id>.json
                                   (run_id, injector, kind, experiment, targets, start, end, expires ; ou
                                   EREGION_EXERCISES_DIR). Glorfindel en tire la source d'un cycle (exercise/real) ; elle
                                   lit celles d'Annatar, de Gothmog et les siennes (tirées du canal, runs/glorfindel/
                                   exercises), windows_dirs, et ne purge que les siennes (SEC18).
eregion_core/exercise_channel.py → O1 : les fenêtres d'Orodruin vers la watch hébergée (conteneur exercises).
                                   Porte aussi les campagnes finies (campaigns/<id>/…, #167) et le rapport d'un
                                   run seul (blob runs/<run_id>.json, #193) ; sur H0, tout ce que la watch tire va
                                   dans son répertoire, runs/glorfindel/ (SEC18) — runs/glorfindel/.pulled-runs/<run_id>
                                   marque un rapport tiré du canal (jamais écrit par-dessus un run de H0).
eregion_core/watch_channel.py   → #159 : le sens retour (conteneur watch) — heartbeat.json {at, since, windows, covers (SEC21b)} et
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
                                   runs/gothmog/<run_id>.json (forme d'Annatar) + runs/gothmog/<run_id>_signals.jsonl
                                   (son répertoire, SEC18 ; la watch ne lit de signaux que dans runs/annatar/).

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
                          isolation.py, release.py (+ gone.py : la VM supprimée, I7S), verify.py, blocks.py, verify_block.py, unblock.py, backup.py (+ restore_job_status,
                          lu par jobs.py), restore.py, sweep.py (+ reset_bare.py : ses cartes nues), readers.py (check_permissions, check_nsg_access,
                          list_nsgs, check_compute_access…), sdk.py (warm-up), capabilities.py, monitor.py
                          (AzureMonitorDetector, réexporté par detectors.py), activity.py (AzureActivityDetector, AL1 :
                          le journal d'activité, détection seule ; écritures de Glorfindel écartées, ses règles marquées),
                          own_run_command.py (SID1 : son Run Command hors de la coupure des sessions d'une
                          isolation qu'il a enregistrée — `drains_at` de l'état — est une carte critique),
                          entra.py (AzureEntraDetector, C2 : les journaux d'Entra ID, détection seule ; seuils en code,
                          identité de Glorfindel marquée acteur ou cible, jamais écartée ; texte et étapes des cartes)
                          graph.py (IR1a : Microsoft Graph en lecture seule, un GET et rien d'autre ; Unreadable : un droit,
                          une erreur, un délai), entra_plan.py + entra_items.py + entra_grants.py (IR1a : le plan d'une carte
                          identity_change, par le code, ses ids lus dans Graph, jamais inventés), entra_check.py (IR1a : Verify,
                          held / not_held / unreadable, jamais held sans la réponse de Graph),
                          identity_contract.py (IR1b : le contrat de l'exécuteur d'identité, lu à son
                          démarrage — son jeton Graph puis ses droits relus en lecture seule, contre la
                          liste fermée ; beyond_contract, contract_unreadable : passif, il refuse de
                          démarrer ; `glorfindel identity-contract`. Son application : Terraform de H0,
                          infra/glorfindel-host/identity_executor.tf, désactivée par défaut)
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
                          la règle dans la couche du client (P1), jamais dans la base livrée ; chaque écriture du
                          magasin sous son verrou, réécrite entière (SEC4b)
  reassert_cards.py     → SEC4b : ce que la réaffirmation dit sans agir — say_bypass (V-16 : une allow d'un tiers
                          avant nos refus, carte `bypassed` une fois par changement, jamais retirée) et
                          say_unreadable_states (carte `state_unreadable`, state_alerts.json), say_left (I4A,
                          carte `rule_left`), say_unverified (SEC13, V-16 : une vérification qui lève, carte
                          `unverified` une fois, fermée quand elle repasse) ; L2C : une marque ne fait taire que la dernière carte, fermée par un humain
  reassert_quarantine.py → I1F, I1S, ISU : les NSG de quarantaine modifiés, lus à chaque passe quel que soit
                          l'état local — _report_altered_quarantines, quarantine_alerts.json (sorti de
                          reassert.py par RB1, sans changement de comportement ; L2Q : un changement qui revient est redit)
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
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used) ; SEC4a : identifiant tiré par la mémoire
                          (jamais remplacé), tout signal ne reçoit que des cycles réels, un par (signal_id, action, run_id) ;
                          SEC17 : un cycle daté par l'hôte (stored_at), la recherche bornée à memory.max_age_days (90 j),
                          ce qu'elle écarte compté (age_census, `glorfindel report`), rien d'effacé ; un cycle sans date
                          daté par la borne de B2 (B2_FLOOR, 16/10/2026)
  incidents.py          → IncidentRegistry (TTL, persist ; threads et processus : flock, réécrit entier — SEC13)
  cli.py                → watch, respond, restore (--wait), release, unblock, reset (revert=alias), list, pending, ack, activate,
                          audit (--all), approve-rule, reject-rule, propose-rules, rules, migrate-rules, check-ttl, jobs,
                          bot, dashboard
                          (war-room : alias caché d'`eregion console`)
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés) ;
                          SEC3 : chaque écriture sous le verrou du magasin, le magasin réécrit entier
  signal_origin.py      → SEC3 (#274) : ce que la watch prend de runs/*_signals.jsonl — les événements qu'un
                          injecteur émet (attack_started → la règle de la watch, detection_missed → une proposition),
                          et d'eux les seuls champs qu'il écrit ; le reste refusé (journal, compteur), jamais décidé. Le recovery_complete : seul celui de `glorfindel restore` (ce
                          processus, ou ~/.glorfindel/recovery_signals/) lève une isolation seul
                          SEC4a : l'attack_time d'un attack_started borné (2 h en arrière, 5 min en avant), sinon refusé
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
  api.py                → FastAPI — pages / (Overview), /glorfindel, /dagorlad (Board, ou Runs avec ?view=runs ;
                          /annatar et /gothmog y mènent, filtrés), /config ; jeton
                          (EREGION_CONSOLE_TOKEN s'il n'est pas vide, sinon GLORFINDEL_WARROOM_TOKEN) ;
                          /api/state (autonomy_modes, autonomy_default, read_only, capability), /api/feed (WS),
                          /api/config, /api/audit[/<vm>], /api/pending/rules,
                          /api/action/{release,revert,restore,ack,approve-rule,snapshot/<vm>}
                          /api/action/approve/{esc_id} — exécute l'action retenue d'un mode_hold (action_params)
                          /api/autonomy/{vm} (set_asset_mode) + /api/config/autonomy/default (set_default_mode)
                          /api/discovered — assets découverts (lecture fraîche JSON à chaque appel)
                          /api/jobs/<vm> — état du job snapshot/restore en cours (lit active_jobs/<vm>.json)
                          /api/exercises[?injector=], /api/campaigns[/<id>], /api/catalog[?kind=], /api/channel,
                          /api/channel/detections/<run_id> (chaque détection signed ou refused, CON-S) —
                          Annatar et Gothmog, GET seulement ;
                          /api/sections ; /runs/<id> → la section de l'injecteur ; /atelier → / et
                          /api/atelier/* → /api/* (308, jusqu'à la 1.0)
  sections.py           → sections actives : Glorfindel toujours, Annatar et Gothmog dès que l'hôte a leurs runs
                          (fenêtre, rapport, campagne), ou ce que --sections / EREGION_CONSOLE_SECTIONS choisit
  cli.py                → `eregion console [--host] [--port] [--sections]`, `eregion coverage [--json] [--check]`
  indicators.py         → les cinq indicateurs de la finalité (UI-2) : sur 30 jours, rapports de run, cycles de la
                          watch, cartes, catalogue ; contenir et contenu seul sur le trafic réel (`real`, OV1 : les
                          cycles hors exercice, la fin de BL1), ceux des exercices (`compute`) pour Dagorlad, le
                          T0 de chaque run confronté comme le rapport de campagne (`t0_confronted`, SEC15) ;
                          `GET /api/indicators`, `GET /api/dagorlad/indicators`
  coverage.py           → C1 : la matrice de couverture — par technique du catalogue et par panne, dernier run,
                          dernière preuve, état (proven, aging, stale, regressed, unproven, never), évolution sur
                          douze semaines ; toute l'histoire des rapports et des cycles ; nourrit la couverture et
                          l'âge de la dernière preuve ; `GET /api/coverage`, `eregion coverage [--json] [--check]`
  follow.py             → DG-c : le suivi en direct d'une demande de Dagorlad — sa phase (écrite, en cours, finie)
                          et la chronologie de chaque fil, lue du statut d'Orodruin, des fenêtres, des cycles de la
                          watch, des cartes et du rapport du run ; un run mesuré comme sur l'accueil
                          (indicators.decision_of, run_report.timeline, indicators.incident_of) ; le T0 d'un run
                          confronté comme sur l'accueil (indicators.t0_confronted, SEC15) ;
                          `GET /api/dagorlad/requests/<id>`, rien n'est écrit
  runs_reader.py        → SEC15 : la seule aide par laquelle la console lit runs/, comme la watch le lit
                          (eregion_core/channel_reader.py) — un fichier ordinaire, jamais à travers un lien,
                          jamais bloquante, bornée, un refus dit une fois ; tout ce qui est refusé se lit absent
  static/console.js     → en-tête commun : onglets (actifs ou grisés), battement de la watch, canal retour,
                          cartes à juger, horloge UTC ; console.css, la palette
  static/overview.html  → l'accueil : une ligne par section, les canaux ; les cinq indicateurs avec UI-2 (#206)
  static/injector.html  → pages d'Annatar et de Gothmog (même page, filtrée par le chemin) : fenêtres
                          d'exercice et ce que Glorfindel a fait dans chacune, campagnes (faits + report.md),
                          techniques ou pannes du catalogue ; grisée, ce que l'injecteur ajouterait
  static/exercises.js   → ce que Glorfindel a fait dans une fenêtre (partagé par l'accueil et les injecteurs)
  board.py              → Dagorlad (docs/design/console.md, §7, phase a) : cartes rouges (le catalogue), bleues
                          (Glorfindel, les cibles inscrites lues par l'identité de la console), le plan des fils
                          et ce qu'on doit en attendre (enveloppe du mode, jamais le modèle) ;
                          `GET /api/dagorlad/board`, `GET /api/dagorlad/plan?wire=<expérience>@<cible>` — lecture seule
  static/dagorlad.html  → /dagorlad : on tire des fils des cartes rouges vers les cibles (clic, ou glisser la
                          poignée), le serveur juge chaque fil ; les fils tracés restent dans le navigateur
  static/*.js           → le script de chaque page, un fichier (overview.js, glorfindel.js, injector.js, dagorlad.js) : la
                          CSP n'admet que les scripts servis par la console (#257) ; dans glorfindel.js,
                          _on et le répartiteur des événements (ACTIONS, data-on-*)
  static/glorfindel.html → page Glorfindel (/glorfindel, /config) — TO JUDGE (seul endroit où l'on juge
                          une carte, 26/10), cards VM expandables (compact + étendu), feed live
                          bandeau INFRASTRUCTURE (posture) : 2 axes orthogonaux — régime credentials
                          (👁 OBSERVE-ONLY ↔ ⚡ ACTIVE) + autonomy (⚡ non-disruptive / 👁 human-only).
                          Langage couleur : orange = peut agir, bleu = observe. Tue « absence de badge = actif ».
                          Mode autonomie : dropdown de Config (défaut global) + badge par carte cliquable
                          → popover capacité (ce que Glorfindel fait seul par mode, lit /api/state.capability)
                          boutons ↩️ Release (isolated) | ↩️ Unblock (cette IP seule) | ⟳ Reset (les deux) | 🔄 Restore
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
  run_report.py       → C1 : le run au format commun d'Annatar et de Gothmog — `RunReport` (`runs/<run_id>.json`,
                        les sept clés), `identity` (`metrics.run_format`, `kind`, `injector`, `experiment_id`),
                        `read_run` / `read_reports` (la vue unifiée, rapports d'avant C1 compris), `timeline`
                        (attaque, détection, décision, action vérifiée d'un incident).
  identity.py         → #205, BL1c : `drop_empty_service_principal_env` retire les `AZURE_CLIENT_*` vides que
                        compose passe sur un hôte sans principal (sinon `DefaultAzureCredential` n'atteint pas
                        l'identité managée) ; appelée par `glorfindel`, `eregion console` et `check_enrollment`
                        (analysis/campaign_report.py : le rapport, la mesure, le triage, l'index lancés seuls)
                        — dans le cœur pour qu'aucun n'importe l'autre (D1).

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

scripts/image_check.py → CI1 : les images de Glorfindel et des injecteurs éprouvées après leur construction — --version,
                        imports (ceux du préflight du CD), config d'exemple sous A3, pas root, rien de Glorfindel chez
                        les injecteurs ; chaque vérification en docker run --network none. CI : images.yml ; local :
                        make images-check ; tests : tests/unit/test_image_check.py.

scripts/mutant_anchors.py → avant un push (docs/sessions.md) : chaque mutant du harnais et du jeu de contrôle a un
                        id unique, et le harnais pourra l'appliquer comme son measure() — le fichier à renommer
                        existe, old et new s'apparient, chaque texte est trouvé une seule fois, dans un fichier
                        suivi par git (sinon STALE). Accepte le chemin d'un autre worktree ; sort en 1 sur une faute.

annatar/
  runner/engine.py    → inscription (`eregion_core.inscription.check_target` : périmètre du banc + tags `eregion-target`/`eregion-zone`
                        sur le groupe ET la VM + zone ; `scenario_destructive()` = le catalogue décide — la technique et sa source épinglée, inconnu = destructif, un scénario qui se dit non destructif contre lui refusé (SEC5) ; `annatar clean` gardé aussi, destructif, et derrière le garde V1) → setup → integrity check → attack
                        → emit attack_started (sans query — Glorfindel résout via detection_rules.yaml)
                        → thread daemon feedback: si detection_timeout → emit detection_missed
                        → runs/<run_id>.json réécrit après l'attente : detection + detection_latency_s (#157), detection_refused (SEC21 : les détections du canal refusées), detection_missing (SEC21b : couvertes par le battement, absentes)
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
eregion_core/exercise_plan.py     → Dagorlad (§7 de docs/design/console.md) : un fil peut-il tourner, et sinon
                                    pourquoi — les règles d'Orodruin (périmètre, inscription, zone, règle de
                                    production) plus le catalogue, la watch vivante, le moteur d'une panne, les
                                    plafonds ; codes stables (REFUSALS) ; pur, la console conseille, Orodruin décide
eregion_core/exercise_request.py  → DG-b : la demande pour Orodruin (id, heure ; par fil l'expérience, la cible, le
                                    rang — rien d'autre), son seul lecteur (read : un champ de plus refusé), les noms
                                    tapés à part (read_typed), le statut publié par Orodruin (read_status) ; écrite par
                                    la console dans ~/.eregion/console/requests/ (EREGION_REQUESTS_DIR) ; `confirm`, sur
                                    le poste (make orodruin-exercise) : affichée, les noms tapés
eregion_core/drill.py             → DG-d : le drill de Dagorlad — son format et son seul lecteur (read : exact, un
                                    drill livré vise par zone, celui de l'instance par nom, jamais un identifiant),
                                    les couches (drills/ livrés ; ~/.eregion/console/drills/, EREGION_DRILLS_DIR), son
                                    enregistrement (jamais par-dessus un autre sans replace), son placement (place : une
                                    VM nommée, ou les VM qu'on donne à un sélecteur — aucune choisie à sa place) ; sur
                                    le poste, la demande d'un drill (make orodruin-exercise DRILL= [TARGETS=])
drills/                           → DG-d : les drills livrés avec Eregion, relus en PR (bl1-reponse, sentinelle) —
                                    cibles par zone ; copiés dans l'image de la console
eregion_core/exercise_runner.py   → DG-b, sur Orodruin : la demande jugée (contrat, codes de la console, nom tapé
                                    comparé au nom lu) puis ses fils l'un après l'autre (annatar wire, gothmog run
                                    --request), le plafond sur la demande entière ; statut dans runs/orodruin/requests/
                                    et le canal (orodruin/…)
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

~/.glorfindel/                → SEC3 : en 0600 (dossiers 0700), écrits entiers (fichier temporaire + `os.replace`) :
                                isolation/, blocks/, escalations.jsonl, channel_refusals.json, recovery_signals/ (et
                                orphan_alerts.json, quarantine_alerts.json, active_jobs/, recovery/, écrits par le même
                                chemin) ; proposed_rules.jsonl (SEC4b) ; incidents.jsonl, posture_state.json,
                                discovered_assets.json, readiness.json et les magasins du bot (bot_*.json) depuis
                                SEC13 (V-27) ; isolation/ et
                                blocks/ d'une version antérieure resserrés au démarrage du watch (les autres le sont
                                à leur prochaine écriture). escalations.jsonl, proposed_rules.jsonl et
                                incidents.jsonl ont plusieurs processus pour écrivains : chaque relecture-écriture
                                sous `flock` (`<fichier>.lock`), rien de perdu entre deux. Qui écrit : la watch, la console, le bot et
                                la CLI (le même utilisateur). Les injecteurs (Annatar, Gothmog) n'en voient que
                                `injectors/`, en lecture seule (compose, Makefile) ; de runs/, que leur propre
                                répertoire et runs/orodruin/ (SEC18)
  injectors/watch_heartbeat   → SEC3 (N-05) : copie du battement de la watch, le seul fichier de Glorfindel que lisent
                                les injecteurs (garde V1 ; le guetteur des blocages d'Annatar, qui lisait blocks/ et
                                émettait attack_adapted, est retiré) — leur conteneur monte ce dossier comme son
                                ~/.glorfindel. La watch le crée au démarrage. 0644 (dossier 0755) : à lire par eux, rien
                                de secret. Retiré à l'arrêt. SEC19 (N-03) : signé par la clé de la watch (seq, key,
                                sig), vérifié par l'injecteur avec EREGION_WATCH_KEY (docs/design/watch-key.md)
  watch_heartbeat             → le battement de la watch (V1 sur cet hôte, la console, le CD de H0) ; écrit d'un coup
                                (un fichier à côté, renommé par-dessus), 0644 : jamais vide ni coupé (SEC17)
  exercise_seen.json          → SEC14 (V-20) : quand la watch a vu pour la première fois chaque fenêtre d'exercice écrite
                                sur cet hôte (sans canal), et sa fermeture : une fenêtre antidatée ou réécrite n'est pas
                                crue (eregion_core/exercise.py, ``observe``). Le tirage du canal y note chaque fenêtre
                                qu'il écrit (`note_pulled`) : seule preuve qu'elle vient du canal. Sous un flock
                                (`exercise_seen.json.lock`). Hors de runs/, que l'injecteur écrit
  escalations.jsonl           → escalades persistées. SEC3 (V-10) : chaque lecture-modification-écriture sous un
                                verrou (`flock` sur `escalations.jsonl.lock`, `response/locks.py::_file_lock`), le
                                magasin réécrit entier : aucune carte perdue entre écrivains, aucune lecture tronquée
                                (`tests/unit/test_locks.py`, vrais processus)
  recovery_signals/           → SEC3 (V-05) : le `recovery_complete` qu'écrit `glorfindel restore --wait` pour un
                                `glorfindel respond` plus tard — seul endroit d'où ce signal lève une isolation seul
                                (`glorfindel/signal_origin.py`) ; plus `runs/recovery/`, que les injecteurs écrivent
  channel_refusals.json       → SEC3 (V-05) : les lignes de `runs/` que la watch a refusées, comptées par événement
                                (la dernière : fichier, heure, raison)
  console_token               → ancien emplacement du jeton tiré de la console : retiré à son premier
                                démarrage depuis SEC10 (le jeton vit dans ~/.eregion/console/token)
  incidents.jsonl             → incidents actifs ; écrit par la watch et `glorfindel respond` : sous flock
                                (`incidents.jsonl.lock`), réécrit entier, 0600 (SEC13, V-10 ; `test_locks.py`,
                                deux vrais processus)
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
                                **Illisible = inconnu (SEC3, SEC4b)** : un fichier d'isolation ou de blocage qui ne se lit
                                pas (JSON cassé, autre forme — dont des `placements` sans `resource_id` —, `unreadable_states`)
                                n'est jamais lu « rien ». Un fichier de blocage arrête le balayage des orphelines ; un
                                fichier d'isolation arrête aussi la levée, `reset --from-azure` et `verify_release` d'une
                                carte en quarantaine ou sans NSG, qui le disent — jamais l'isolation (son original inconnu
                                n'est pas écrit). Une levée en échec ne l'écrit pas ; un nouvel état de sa VM (isolation,
                                ré-isolation) le met de côté dans `isolation/aside/` (jamais plus un état, réparé ou non ; listé tant qu'il existe : le lire,
                                reporter à la main dans l'état courant, le retirer) ; le fichier illisible de sa
                                VM, une levée ou un reset Azure ne disent jamais fait (`release_partial`, `swept_partial`)
                                et ne l'effacent jamais, ni rien d'autre (I3U) — l'adaptateur AWS garde le fichier mais
                                sa levée dit encore `released`. La réaffirmation le dit (`state_unreadable`). Le réparer,
                                ou le retirer à la main après avoir cherché les règles glorfindel-iso de ses cartes sur
                                `nsg-glorfindel-quarantine-<région>` (que le message nomme).
                                Isolation : `original_unknown` — les cartes en quarantaine dont l'original est inconnu
                                (la levée demandera le tag). `bypass_said` — le contournement déjà dit (V-16, carte `bypassed`) ; blocage aussi.
                                Blocage : `left_said` — les règles laissées déjà dites (I4A, carte `rule_left`). L2C : ces marques
                                ne font taire un changement que si sa carte attend, ou si la dernière carte est la sienne, fermée par un humain.
                                `drift_alerted_at` (relecture de L2C) : une disparition dite ne se tait que si la dernière carte de son alerte
                                attend ou a été fermée par un humain, et que le watch n'a pas vu l'épisode fini (marque qui n'a pu s'effacer)
  perimeter_writes.jsonl      → L1W (#492) : les écritures de paire de périmètre de Glorfindel (une par IP et sous-réseau),
                                notées avant chaque écriture, une ligne chacune (`{"pair": "rg/nsg/règle", "at": …}`,
                                ajoutée sans verrou, 0600, jamais à travers un lien ni ailleurs que dans un fichier
                                ordinaire ; lue ligne à ligne ; `glorfindel/response/pair_journal.py`). Une paire notée après
                                l'acquittement d'une carte qui la disait partie finit cet épisode, même repartie avant la
                                passe. Jamais réécrit ni purgé (quelques lignes par blocage de périmètre) ; perdu ou
                                illisible, le code revient à ce qu'il lisait avant L1W (la carte acquittée se tait)
  quarantine_alerts.json      → I1F : NSG de quarantaine → le changement déjà signalé (carte `quarantine_altered`) ;
                                oublié quand le NSG est de nouveau entier, ne porte plus rien ou a disparu (relu par son ID : 404, I1S) — un acquittement ne relève pas de carte
                                L2Q : ne fait taire un changement que si la dernière carte du NSG est la sienne, fermée par un humain (sans note)
  state_alerts.json           → SEC4b : la liste des fichiers d'état illisibles déjà dite (carte `state_unreadable`) ;
                                oubliée quand tout se lit de nouveau — un acquittement ne relève pas de carte
                                L2C : ne fait taire une liste que si sa carte attend, ou si la dernière est la sienne, fermée par un humain
  orphan_alerts.json          → A3 : règle orpheline (NSG/règle) → sa carte `orphan_rule` ; une règle dite ne l'est pas de nouveau
                                tant qu'elle reste ; oubliée (carte fermée) quand elle n'est plus orpheline ou a été retirée
  proposed_rules.jsonl        → règles de détection proposées (en attente d'approbation). SEC4b : chaque `record`,
                                `approve`, `reject` sous un flock (`proposed_rules.jsonl.lock`), réécrit entier (fichier
                                temporaire + `os.replace`) — plus de proposition perdue entre deux écrivains (la watch, la
                                console, la CLI), jamais un fichier à moitié lu
  client_rules.yaml           → P1 : la couche du client — règles approuvées (`approve-rule`, War Room), règles de
                                base remplacées (même nom) ou désactivées (`disable:`), chargée par-dessus la base
                                livrée. Hors du dépôt : une mise à jour ne la touche jamais (conteneurs : base `:ro`)
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  rule_status.json            → état de polling des règles (last_poll, last_match, match_count, last_error ;
                                `expected_sudo` : count, last, origin_count, origin_confirmed — ADM1, COR1, COR2 ;
                                `correlation` : queries, origin, card, unknown, compromised, unchecked, confirmed,
                                unconfirmed, last — COR1, COR2 ; lus par la console ;
                                `auditd` : events, sensitive, unreadable, at — AUD1, ce que la fenêtre de
                                `auditd-sensitive-root-command` contient à sa dernière passe, lu par `glorfindel report`)
  expected_sudo.jsonl         → ADM1 : chaque sudo d'administrateur attendu écarté par le RulePoller (at, rule,
                                asset, account, command ≤ 300 car., logged_at ; un shell root écarté par l'origine de
                                ses sessions SSH : via « origin », origin — COR1 ; proof « bastion » ou « flows »
                                quand une source hors de la VM l'a confirmée — COR2), écrit AVANT d'écarter — un journal
                                qu'on ne peut écrire n'écarte rien ; 0600 ; au-delà de 2 Mo, la moitié la plus
                                récente gardée. Lu par `glorfindel report`
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

~/.annatar/                   → jamais monté entier (SEC20) : make annatar-shell en monte deux fichiers,
                                qu'il crée avant et refuse si l'un est un lien ; le service compose, rien
  .bashrc                     → alias ar (chargé par make annatar-shell, --init-file, en lecture seule
                                dans le conteneur : le rouge ne l'écrit jamais)
  .bash_history               → historique bash persistant, le seul fichier en écriture (HISTFILE posé par
                                make annatar-shell) ; bash y ajoute, il ne le tronque pas — l'image
                                root de repli (UID=0) aussi (SEC20b, « Ce que le rouge monte en écriture »)

~/.cache/chroma/              → modèle ONNX ChromaDB (79MB, téléchargé une seule fois)
```

## `runs/` — qui écrit, qui lit, qui monte (SEC18, N-05)

_SEC18 (#455), 03/11. La carte de `runs/` telle qu'elle était avant SEC18 : un seul répertoire, que
chaque service montait en écriture. Puis la disposition retenue : un répertoire par écrivain,
en écriture chez lui seul, en lecture seule chez ceux qui le lisent._

### Avant SEC18 : un répertoire, tous les écrivains

| Écrivain | Ce qu'il écrit dans `runs/` | Qui le lit |
|---|---|---|
| Annatar (`annatar run`, `campaign`, `wire`) | `<run_id>_signals.jsonl` (`attack_started`, `detection_missed`), `<run_id>.json` (le rapport du run), `exercises/<run_id>.json` (sa fenêtre, B2), `campaigns/<id>/` (manifeste, scénarios) | la watch (les signaux, par le lecteur commun ; les fenêtres), la recherche du moment d'un restore (les signaux), la console (fil, Runs, couverture, indicateurs), l'analyse (rapports, fenêtres), le lanceur d'Orodruin (fenêtres, rapports) |
| Gothmog (`gothmog run`) | `gothmog/<run_id>_signals.jsonl` (que la watch ne lit pas), `<run_id>.json`, `exercises/<run_id>.json` | la watch (les fenêtres), la console, l'analyse (`fault_rate`, `containment`), le lanceur d'Orodruin |
| La watch (`glorfindel watch`) | `<run_id>_debug.jsonl` et `watch-*_debug.jsonl` (chaque cycle : signal, raisonnement, action, vérification) | la console (fil, cartes de Runs, couverture, indicateurs, suivi d'une demande), l'analyse (décisions), la TUI, **Annatar** (l'attente de sa détection, `annatar/runner/engine.py`) |
| La watch sur H0 (le tirage du canal d'exercice, `analysis/hosted_report.py`) | `campaigns/<id>/` (manifeste et rapports tirés, `.pulled`), `<run_id>.json` et `.pulled-runs/` (rapports d'un run seul), `exercises/` (fenêtres tirées), `orodruin/` (verdict et statuts d'Orodruin) | la console, l'analyse, la watch (les fenêtres) |
| L'analyse (dans le conteneur de la watch, ou à la main) | `campaigns/<id>/report.md`, `report.error`, son verrou, `triage.md`, `triage.json` ; `glorfindel replay-campaign` : `campaigns/<id>/replay.json` | la console (page d'une campagne), `make glorfindel-host-campaign-report` |
| La console, la CLI de Glorfindel, le bot (qui lance la CLI) | `manual_actions.jsonl` (les gestes de l'opérateur : levée, reset, déblocage, instantané, restore) | la console (fil, indicateurs), l'analyse (`containment` : les levées) |
| Orodruin (`eregion_core/exercise_runner.py`, le contrat) | `orodruin/audit.jsonl` (chaque appel d'un injecteur, avant l'appel), `orodruin/requests/` (statut d'une demande, registre des demandes jouées, le verrou « un run à la fois ») | Orodruin lui-même (le plafond, le registre, le verrou) |
| Dagorlad (la console) | rien dans `runs/` : ses demandes vont dans `~/.eregion/console/requests/` | Orodruin, par l'opérateur |
| Le canal d'Orodruin vers H0 (`exercise_channel.py`) et le canal retour (`watch_channel.py`) | rien dans `runs/` sur Orodruin ; sur H0, ce que tire la watch (ci-dessus) | — |

Montages avant SEC18 :

| Où | Service | `runs/` |
|---|---|---|
| `docker-compose.yml` (poste, H0, une équipe) | `watch`, `war-room` (la console), `bot` | `runs/` entier, en écriture |
| `docker-compose.yml` | `annatar`, `gothmog` | `runs/` entier, en écriture (plus `~/.glorfindel/injectors` en lecture seule, SEC3) |
| `Makefile` (`annatar-shell`, `DOCKER_ANNATAR`) | Annatar | `runs/` entier, en écriture |
| `Makefile` (`glorfindel-shell`, `DOCKER_GLORFINDEL`) | Glorfindel à la main | `runs/` entier, en écriture |
| Orodruin (`ORO_RUN`, `ORO_RUN_REQUEST`) | Annatar, Gothmog, le lanceur d'une demande | `~/runs` entier, en écriture |
| H0 (`infra/glorfindel-host/deploy.sh` → compose) | `watch`, `war-room`, `bot` | `runs/` entier, en écriture |

Le rouge écrivait donc où le bleu écrit ses décisions, et lisait le raisonnement de la watch.

### La disposition retenue : `runs/<écrivain>/`

| Répertoire | Écrivain | Ce qu'il y écrit | Monté en lecture seule par |
|---|---|---|---|
| `runs/glorfindel/` | la watch, et ce qui tourne dans son conteneur : le tirage du canal, le rapport de campagne, l'analyse ; la CLI de Glorfindel quand elle rejoue des signaux (`respond`) | `*_debug.jsonl`, `campaigns/<id>/` (tirées sur H0 ; `report.md`, `report.error`, `triage.*`, `replay.json` partout), `<run_id>.json` et `.pulled-runs/` tirés, `exercises/` tirées, `orodruin/` tiré | la console |
| `runs/console/` | la console, la CLI de Glorfindel, le bot | `manual_actions.jsonl` | la watch (l'analyse des levées) |
| `runs/annatar/` | Annatar | `*_signals.jsonl`, `<run_id>.json`, `exercises/`, `campaigns/<id>/` | la watch, le bot (le moment d'un restore), la console |
| `runs/gothmog/` | Gothmog | `*_signals.jsonl`, `<run_id>.json`, `exercises/` | la watch, la console |
| `runs/orodruin/` | les injecteurs sur l'hôte d'Orodruin et son lanceur | `audit.jsonl`, `requests/` (statuts, registre, verrou), `.watch_seen.json` (SEC19 : le plus haut compteur de battement vu par clé, contre un rejeu) | — |
| `runs/verdicts/` | la watch, sans canal retour du stockage (le canal local des verdicts) | `heartbeat.json` (`at`, `since`, `windows`, `perimeter`), `detections/<run_id>/<n>.json` (`run_id`, `technique`, `verdict`, `detected_at`, `rule`, `latency_s`, `target` — rien d'autre) | Annatar, Gothmog |

Le rouge ne monte ni `runs/glorfindel/` ni `runs/console/` : il ne lit plus le raisonnement de la
watch. Sa détection se mesure par le canal retour du stockage (`eregion_core/watch_channel.py`) ;
sans lui, par le canal local des verdicts, `runs/verdicts/`, en lecture seule — le verdict de ses
runs, rien d'autre (`LocalVerdicts`, `local_detections`) ; sans aucun des deux, elle est inconnue.
Il n'existe pas sur Orodruin, où le canal du stockage suffit (`make orodruin-push` migre avec
`--orodruin`).

Un lecteur ne cherche un fichier que dans le répertoire de son écrivain : un signal dans
`runs/annatar/`, un cycle dans `runs/glorfindel/`, un geste dans `runs/console/`, une fenêtre dans
`exercises/` d'Annatar, de Gothmog ou de la watch, un rapport dans le répertoire d'un injecteur (qui
doit le nommer) ou de la watch. Ce qui est ailleurs — l'ancienne disposition, un fichier d'un autre
écrivain dans un répertoire — n'est jamais lu, et dit une fois (`runs_layout.survey`).

Montages après SEC18 (`tests/unit/test_runs_mounts.py` les tient) :

| Où | Service | En écriture | En lecture seule |
|---|---|---|---|
| compose (poste, H0, une équipe) | `watch` | `glorfindel`, `verdicts` | `annatar`, `gothmog`, `console` |
| compose | `war-room` (la console) | `console` | `glorfindel`, `annatar`, `gothmog` |
| compose | `bot` | `console` | `annatar` |
| compose | `annatar` | `annatar`, `orodruin` | `verdicts` |
| compose | `gothmog` | `gothmog`, `orodruin` | `verdicts` |
| Makefile `ANNATAR_VOLS` | Annatar à la main | `annatar`, `orodruin` | `verdicts` |
| Makefile `GLORFINDEL_VOLS` | Glorfindel à la main (la watch, la CLI) | `glorfindel`, `console`, `verdicts` | `annatar`, `gothmog` |
| Orodruin `ORO_RUN` | Annatar | `annatar`, `orodruin` | — |
| Orodruin `ORO_RUN_GOTHMOG` | Gothmog | `gothmog`, `orodruin` | — |
| Orodruin `ORO_RUN_CONTRACT` | le contrat (`orodruin-check`) | `orodruin` | — |
| Orodruin `ORO_RUN_REQUEST` | le lanceur d'une demande (il lance les deux) | `annatar`, `gothmog`, `orodruin` | — |
| Orodruin `ORO_MIGRATE` | la migration, une fois, à `orodruin-push` | `~/runs` entier | — |
| H0 (`deploy.sh` → compose) | `watch`, `war-room`, `bot` | comme le compose | comme le compose |

La migration de l'ancienne disposition, son choix et sa raison, et le redéploiement dans l'ordre
(poste, H0, Orodruin) : [`operations.md`](operations.md), « `runs/` : un répertoire par écrivain ».

### Ce que le rouge monte en écriture (SEC20)

_SEC20 (#467), 03/11. **Le rouge n'écrit jamais ce que l'opérateur exécute** : un conteneur
d'injecteur (Annatar, Gothmog) ne monte en écriture aucun répertoire de code, de scripts ou de
configuration que l'opérateur, la watch ou un `make` lance ensuite, ni ce qui en contient un (le
dépôt entier, le `HOME` entier). `tests/unit/test_red_mounts.py` tient cette carte : il lit le
compose et chaque lancement de l'image des injecteurs dans le Makefile (`docker run`, `docker
create`, `docker container …`), du poste et d'Orodruin, et refuse ce qu'il ne saurait lire — une
variable d'un tel lancement définie deux fois ou complétée par `+=`, un lancement dont l'image ne
s'écrit pas en clair, un `docker compose … run` qui ajoute un montage._

**Le lecteur refuse ce qu'il ne sait pas lire** (SEC20b, #494, 04/11). Les options d'un lancement
se lisent comme docker les lit, jusqu'à son image : un montage sous toutes ses formes (`-v x`,
`-v=x`, `-vx`, dans un groupe d'options courtes comme `-itv x`, `--volume`, `--volume=`, `--mount`).
Il refuse :

- **dans les options d'un lancement**, toute référence qu'il laisse non développée, hors de
  `$(HOME)`, `$(PWD)` et `$$HOME` : une variable d'un `define` ou d'un fichier inclus,
  `$(shell …)`, une variable du shell. Ce que make ou le shell en ferait, un montage parmi d'autres,
  ne se verrait pas. Il refuse aussi un mot qui n'est pas du texte simple, une option qu'il ne
  connaît pas (il ne saurait pas quel mot est l'image), `--volumes-from` (les montages d'un autre
  conteneur), un `--mount` dont il ne lit pas une clé, et un lancement derrière les options propres
  de docker. Une continuation de recette se lit comme le shell la lit, sans rien entre les deux
  lignes ; un commentaire continué sur la ligne suivante est refusé (le shell exécute ce qui suit) ;
- **ce qu'un lancement rouge ne reçoit jamais**, refusé par son nom et non plus comme une option
  inconnue : `--privileged`, `--device`, `--cap-add`, `--pid`, `--userns`, `--ipc` ou `--network`
  sur l'hôte (ou un autre conteneur), `--uts host`, une `--security-opt` autre que
  `no-new-privileges:true`. Aucune n'est dans la table des options lues ;
- **dans le Makefile**, `include`, `-include`, `sinclude`, `define`, `undefine` et `$(eval …)` ;
  `SHELL`, `.SHELLFLAGS`, `.ONESHELL` et `load`, qui changent la manière dont make lance une recette. Ils
  sont refusés plutôt que lus : les lire ferait de ce test un second make (son chemin de recherche,
  un fichier manquant qu'une règle reconstruit, l'ordre d'une évaluation), et le Makefile n'en a
  besoin d'aucun. De même, un `$(MAKE)` de recette à qui l'on nomme un autre makefile ou un autre
  répertoire (`-f`, `-C`) ;
- **côté compose**, un lancement de recette (`run`, `up`, `create`, `start`, `restart`, `watch`) à
  qui l'on nomme un autre fichier (`-f`, `--file`, `--project-directory`, `COMPOSE_FILE`), et, à
  côté de `docker-compose.yml`, tout fichier que compose prendrait à sa place ou fusionnerait seul :
  `compose.yaml`, `compose.yml`, `docker-compose.yaml`, et leurs `*.override.*`. Le compose
  n'inclut aucun autre fichier (`include`), aucun service n'en étend un autre (`extends`) ni ne
  prend les montages d'un autre (`volumes_from`), et chaque image s'écrit en clair.

Le Makefile actuel ne donne aucun refus. Chaque forme a sa sonde dans le test, et chaque cas son
mutant (M3490–M3497, M3525–M3529, M3535–M3536) ; aucun n'était vu par le lecteur de SEC20, hors de
`--volumes-from` (M3528), déjà refusé.

**L'historique avec l'image root de repli** (`UID=0`, une image construite sans les build-args de
`make build`). Bash ajoute à l'historique de même et ne le tronque pas, mais pas pour la même raison.
Sa troncature écrit un fichier voisin, puis le renomme sur l'historique. Avec l'image de
l'opérateur, le conteneur ne peut créer ce voisin : `/root/.annatar` est le point de montage que
docker crée, à root. Avec l'image root, il le crée, dans la couche du conteneur, jamais sur l'hôte ;
le renommage sur un fichier monté échoue (`EBUSY`, un point de montage), et bash efface alors le
voisin — lu dans son code, non mesuré.
Dans les deux cas, une session de plus de `HISTSIZE` commandes réécrit l'historique entier par ce
même voisin : elle n'est pas gardée. Le fichier reste à l'opérateur, qui l'a créé
(`ANNATAR_SHELL_FILES`). Mesuré sans conteneur, bash 5.2 : un répertoire qui refuse le voisin donne
un historique ajouté, jamais tronqué. Le renommage refusé sur un point de montage est une règle du
noyau, non mesurée ici (aucun conteneur).

| Où | Conteneur | En écriture | Ce qu'il y écrit |
|---|---|---|---|
| compose | `annatar` | `runs/annatar`, `runs/orodruin` | ses signaux, ses rapports, ses fenêtres, ses campagnes ; le journal avant chaque appel, le verrou « un run à la fois » |
| compose | `gothmog` | `runs/gothmog`, `runs/orodruin` | de même, pour une panne |
| Makefile `DOCKER_ANNATAR` (`annatar-run`, `annatar-dry-run`) | Annatar | `runs/annatar`, `runs/orodruin` | comme le compose |
| Makefile `annatar-shell` | Annatar, un shell | `runs/annatar`, `runs/orodruin`, `~/.annatar/.bash_history` | et l'historique du shell, ce seul fichier, jamais `~/.annatar` ; son `.bashrc`, qu'il lance, en lecture seule |
| Makefile `annatar-validate`, `annatar-list` | Annatar | rien | — |
| Orodruin `ORO_RUN`, `ORO_RUN_GOTHMOG`, `ORO_RUN_CONTRACT`, `ORO_RUN_REQUEST` | les injecteurs, le contrat, le lanceur d'une demande | leurs répertoires de `~/runs` (le tableau ci-dessus) | ce que SEC18 dit ; `~/requests`, ce que juge le lanceur, en lecture seule |
| Orodruin `ORO_MIGRATE` | la migration, une fois | `~/runs` entier | des données seulement, rien qu'on exécute |
| Orodruin `ORO_CHECK_RUN` (`orodruin-push`, OI2) | l'image reçue, lancée une fois sans réseau avant son tag | rien | — (aucun montage) |

Ce qui ne s'écrit plus : `scripts/` et `annatar/scenarios/` (le compose et `ANNATAR_VOLS`, et
`annatar-validate`, `annatar-list` pour les scénarios) passent en lecture seule. Annatar lit les
scripts de `scripts/vm/` et les envoie à sa cible par Run Command ; il lit ses scénarios ; il
n'écrit ni les uns ni les autres. Le montage reste pour qu'une modification locale serve sans
reconstruire l'image, qui les porte aussi. `~/.annatar` sort du compose : la CLI d'Annatar n'y
écrit rien, et son `.bashrc` est ce que lance `make annatar-shell` ; ce shell n'en monte que le
`.bashrc`, en lecture seule, et l'historique, où il pose `HISTFILE`. Un script qui écrit,
`setup_testdata.sh` (T1486), écrit sur la VM cible (`/mnt/testdata`), par Run Command : jamais sur
l'hôte, jamais un endroit qu'on exécute. Les scénarios d'une campagne générée s'écrivent dans
`runs/annatar/campaigns/<id>/scenarios/` : des données que seul Annatar lit, et qui ne nomment que
des scripts du catalogue, épinglés par leur empreinte (SEC14, V-19). Les `docker run` d'Orodruin
ne changent pas : ils ne montaient déjà ni scripts, ni code.
