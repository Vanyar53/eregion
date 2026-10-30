# Opérations

_Extrait tel quel de `CLAUDE.md` le 2026-10-15 (lot DX1) : la CLI, les workflows opérateur, les variables d'environnement, le packaging et les coûts. Les règles de sûreté et les conventions restent dans `CLAUDE.md`._

## CLI — référence complète

```bash
# Workflow opérateur — Docker Compose (recommandé)
make glorfindel-start                        # lance watch + la console → http://localhost:7007
make console-url                             # l'URL de la console avec son jeton (celui de l'environnement ou de .env,
                                             # sinon ~/.glorfindel/console_token, attendu CONSOLE_WAIT=20 s) ; glorfindel-start l'affiche
                                             # refuse si AZURE_SUBSCRIPTION_ID est vide (watch aveugle) ; ALLOW_NO_AZURE=1 pour une démo
make glorfindel-logs                         # tail logs des deux services
make glorfindel-dev                          # auto-reload sur modification de code (docker compose watch)
make glorfindel-stop                         # arrêt

# Profils d'usage (D1) — docs/profils/ ; Glorfindel est dans chacun (il démarre sans profil compose)
make profile-discover                        # = glorfindel-start : Glorfindel seul, en observation
make profile-detection                       # + l'image d'Annatar ; profile-resilience : Gothmog ; profile-proven : tout
                                             # (crée à ton nom ~/.glorfindel, ~/.cache/chroma, ~/.annatar : sinon root)
docker compose --profile annatar run --rm annatar list          # APRÈS make profile-… : un injecteur à la demande ;
docker compose --profile gothmog run --rm gothmog preflight vm-shutdown   # depends_on démarre la watch sans attendre
                                             # son battement : la 1re minute, il peut refuser (V1) ; sur un poste, contrat passive
make team-init TEAM=<nom>                    # plusieurs équipes : ~/.eregion/teams/<nom>/ (team.env 600, config, runs)
make team-start TEAM=<nom> [BOT=1]           # son Glorfindel : compose -p eregion-<nom> sous env -i (ton shell
                                             # n'atteint pas l'équipe), conteneurs eregion-<nom>-*, port de team.env ;
                                             # refuse sans AZURE_SUBSCRIPTION_ID ni EREGION_CONSOLE_PORT ; team-stop, team-logs
make profiles-check                          # docker compose config : chaque profil rend ses services (CI)
make components-check [COMPONENT=annatar]    # chaque composant tourne seul : ses tests, les autres absents (CI)

# Montages (SEC3, #274) — qui voit quoi de l'état (docker-compose.yml, le Makefile pour make annatar-*)
#   watch, war-room (console), bot : runs/ et ~/.glorfindel en écriture — Glorfindel, le même utilisateur ;
#     la console et le bot écrivent runs/ (manual_actions.jsonl : le fil des actions de l'opérateur, les
#     commandes que lancent les boutons du bot), d'où l'écriture.
#   annatar, gothmog : runs/ en écriture (leurs signaux, leurs rapports, leurs campagnes) et, de ~/.glorfindel,
#     ~/.glorfindel/injectors seulement, en lecture seule, monté comme leur ~/.glorfindel : la watch y écrit
#     son battement (le garde V1, eregion_core/watch_gate.py), rien d'autre ; ni Annatar ni Gothmog ne lisent
#     d'autre fichier de Glorfindel (le guetteur des blocages d'Annatar est retiré). Les escalades, l'état
#     d'isolation et de blocage, les règles du client, l'historique restent hors de leur portée. La watch crée
#     ce dossier au démarrage, et make glorfindel-start avant elle, à ton nom (laissé à docker, il serait à
#     root, et la watch ne pourrait pas y écrire : elle le dit et continue).
#   La watch ne prend de runs/ que ce qu'un injecteur émet (docs/glorfindel.md, « Le canal runs/ ») : une ligne
#     refusée est dite dans `make glorfindel-logs` et comptée dans ~/.glorfindel/channel_refusals.json.
#   État local (docs/fichiers-cles.md) : isolation/, blocks/, escalations.jsonl, channel_refusals.json et
#     recovery_signals/ en 0600 (dossiers 0700), écrits entiers ; isolation/ et blocks/ d'avant resserrés au
#     démarrage de la watch (un fichier à root d'une ancienne image reste tel quel : make fix-state-ownership).
#     Les autres fichiers de ~/.glorfindel restent au umask (suite notée).

# Glorfindel hébergé (H0) — infra/glorfindel-host/README.md
make glorfindel-host-tunnel                  # tunnel + « Console → http://localhost:7007/?token=… » ; le jeton de host.env :
                                             # EREGION_CONSOLE_TOKEN s'il n'est pas vide, sinon GLORFINDEL_WARROOM_TOKEN
                                             # (l'ancien nom reste valide, rien à renommer) ; -url : l'URL seule
make glorfindel-host-status                  # tout tourne ? lit le jeton sur la VM sous l'un ou l'autre nom, sans l'afficher
make glorfindel-host-push                    # host_env.py --check d'abord : refuse un host.env sans jeton de la console
make glorfindel-host-cd-install              # le CD de H0 (H1) : agent dans ~/.eregion-cd/, timer désactivé ; README, « Le CD de H0 »
make glorfindel-host-cd-check                # à blanc : vérifie, construit à côté, préflight (config sous A3), sans basculer
make glorfindel-host-cd-enable               # puis : toute release publiée se déploie (5 min), retour arrière si malade
make glorfindel-host-cd-status | -cd-retry | -cd-disable | -cd-uninstall

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
# Console :   ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux)
# TUI :       x:release  u:unblock  v:reset  r:restore (demande le moment, pré-rempli ; Entrée :
#             les points d'avant, y : --before ; le refus reste à l'écran — SEC4c)
#
glorfindel release <resource_id> --yes       # lever isolation NSG (post-restore, VM de retour)
glorfindel unblock <ip> <resource_id> --yes  # supprimer une règle block IP
glorfindel reset <resource_id> --yes        # reset complet : release + unblock toutes IPs
glorfindel reset <resource_id> --from-azure  # source de vérité = Azure (sans état local) : retire les
                                             # glorfindel-* de CETTE VM sur ses NSG (noms déterministes,
                                             # segment IP qui ancre la correspondance) ; garde les blocages
                                             # de périmètre ; aperçu + confirmation ; --dry-run pour lister
glorfindel snapshot <resource_id> --yes      # backup on-demand RSV (setup scénario, ~5-20min)
glorfindel restore <resource_id> --yes       # Azure Backup fire-and-forget ; point = le plus récent AVANT
                                             # le début de l'attaque sur CETTE VM : --before <ISO8601>
                                             # (UTC sans décalage), sinon le premier attack_started de
                                             # cette VM admis dans runs/ (≤ 2 h avant son isolation) ;
                                             # inconnu → refusé, --before demandé (SEC4c). Nom court :
                                             # deux VMs de ce nom (état ou découverte) → refusé ;
                                             # un autre restore de la VM en cours → refusé ; un moment
                                             # futur ou hors calendrier → refusé ; après l'isolation → dit
glorfindel restore <resource_id> --yes --wait  # workflow complet : attend recovery_complete → release_isolation auto
glorfindel jobs <vm-name> [--refresh]        # état du job snapshot/restore en cours
glorfindel ack <escalation_id>               # acquitter escalade
glorfindel ack --all                         # acquitter toutes
glorfindel verdict <id> right|wrong|unsure [--note "…"]  # observation : la recommandation était-elle juste ?
glorfindel report [--since 7d|4w|all] [--json]  # verdicts par action et par règle, taux de disruptives fausses
                                             # (docs/observation.md — le critère « 4 semaines en human_only »)
glorfindel check-ttl                         # escalade les isolations au-delà du TTL (ne lève JAMAIS — quatrième passe Q1)

# Audit remédiation — vérifier que Glorfindel peut agir avant l'incident
glorfindel activate <vm|resource_id>         # réponse autonome pour une VM : contrôle de préparation,
                                             # réserves affichées puis acceptées (--yes), refus si pas prête
glorfindel audit <resource_id>               # NSG / backup / compute / IAM
glorfindel audit --all                       # toutes ressources de detection_rules.yaml
glorfindel audit --all --vault <nom>         # vault non-défaut (défaut: rsv-celebrimbor-erebor)

# Boucle purple team — apprentissage détection
glorfindel pending                           # voir les règles proposées (proposed_rule)
glorfindel propose-rules [--ttp T..] [--include-planned] [--dry-run]  # autoring PROACTIF cold-start :
                                             # génère la détection depuis technique_catalog.yaml AVANT
                                             # l'attaque (getschema sur le vrai LAW → KQL groundée).
                                             # Skip les TTPs déjà couverts. Sortie = propositions.
glorfindel approve-rule <id>                 # appliquer la règle → couche du client (~/.glorfindel/client_rules.yaml, P1)
                                             # ; jamais à la place d'une règle livrée (nom suffixé -proposed,
                                             # dit), et dit si elle remplace une règle du client (SEC2)
glorfindel reject-rule <id>                  # écarter la règle sans l'approuver
glorfindel rules                             # règles chargées : la base livrée, puis la couche du client (couche de chaque
                                             # règle ; ce que la couche fait à la base : règle remplacée, désactivée ;
                                             # une règle livrée remplacée : « client (remplace) », en rouge, SEC2)
glorfindel rules check [--live] [--json]     # H2 : chaque règle chargée (base, couche du client, approuvées), comme
                                             # la watch la charge : liée à son backend ? Avec --live, sa requête lancée
                                             # UNE fois, en lecture seule, sur son backend (même détecteur, même fenêtre
                                             # que le RulePoller) : ok (zéro ligne compris) ; erreur seulement pour ce
                                             # qui dure (requête invalide, table ou colonne absente, 403, 404, backend
                                             # non lié, source inconnue) ; non prouvée pour ce qui peut passer (429,
                                             # 5xx, 401 ou identité indisponible, réseau, résultat partiel, inconnu) ;
                                             # délai dépassé. --query-timeout (30 s) par requête, --total (120 s) pour
                                             # le tout : au-delà, les règles restantes ne partent pas, et c'est dit.
                                             # Jamais de nouvel essai. Aucun appel au modèle, aucune écriture, aucune
                                             # action. Sortie : 0 tout ok, 1 une erreur durable, 3 des non prouvées ou
                                             # des délais seulement. --json : ce que lit le CD de H0, avant et après une
                                             # bascule (genre, code KQL ou HTTP, ligne réduite sans workspace,
                                             # abonnement, chemin de ressource, hôte ni adresse) ; les mots complets
                                             # sur stderr. Utile après un glorfindel-host-push :
                                             # docker exec eregion-watch glorfindel rules check --live
glorfindel migrate-rules --from <modifié> --base <livré> [--dry-run]  # règles approuvées DANS la base avant P1
                                             # → couche du client, une règle au workspace en ligne liée à son
                                             # backend (H0 : infra/glorfindel-host/README.md)

glorfindel memory-stats                      # ChromaDB cycle count
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel dashboard                         # TUI full-screen : resources + feed + escalations
eregion console [--sections annatar,gothmog] # la console web sur http://localhost:7007 (pip install -e '.[console]' depuis le clone) ;
                                             # Glorfindel toujours, Annatar et Gothmog s'ils ont des runs sur l'hôte
                                             # (ou --sections) ; `glorfindel war-room` reste un alias caché
                                             # toujours un jeton : EREGION_CONSOLE_TOKEN, sinon tiré au premier démarrage
                                             # (~/.glorfindel/console_token, 600) et affiché avec l'URL à ouvrir une fois
eregion coverage [--json] [--check]          # la matrice de couverture (C1), depuis runs/ du répertoire courant : chaque
                                             # technique du catalogue et chaque panne, son dernier run, sa dernière preuve,
                                             # son état (proven, aging > 21 j, stale > 30 j, regressed, unproven, never) et
                                             # ses derniers résultats (✓ ✗ ? ·) ; fichiers seulement, ni cloud ni modèle.
                                             # --check : la non-régression, sort en 1 sur une technique ou une panne
                                             # prouvée avant et ratée depuis (après un rejeu du catalogue sur le banc,
                                             # depuis Orodruin, sur l'hôte de la watch : H0 garde les rapports et les cycles)
glorfindel --version                         # 0.2.0

# Annatar et Gothmog exigent Glorfindel (V1, #214) : avant chaque run (chaque run d'une campagne aussi),
#   avant tout appel au cloud, l'injecteur lit le battement de la watch. Le canal retour fait foi s'il est
#   configuré (EREGION_WATCH_CHANNEL : la watch hébergée vue d'Orodruin — un fichier de cet hôte n'en dit
#   rien) ; sinon le fichier local ~/.glorfindel/watch_heartbeat (une watch sur le même hôte ; `make
#   annatar-run` monte sa copie, ~/.glorfindel/injectors — SEC3). Un battement de moins de 90 s, et pas daté de plus de 10 s dans le futur (le
#   décalage des horloges H0 ↔ Orodruin) : la watch vit. Sinon : refus, code 1, et le message dit depuis quand
#   date le dernier battement (« never » s'il n'y en a pas, la raison entre parenthèses : pas de fichier, canal
#   illisible… ; « in the future » si une horloge est fausse). Rien n'a été touché : ni contrat d'Orodruin, ni
#   cible, ni fenêtre, ni rapport. Une campagne sans watch est refusée entière (une ligne, code 1, son état
#   reste « ratified ») ; une watch qui meurt en cours de campagne l'arrête au run suivant (« aborted », code 1).
#   --without-glorfindel (annatar run, annatar campaign run, gothmog run, gothmog preflight ; Make d'Orodruin :
#   WITHOUT_GLORFINDEL=1, yes ou true — toute autre valeur, 0 compris, n'y touche pas) : run de développement.
#   Le rapport l'inscrit (metrics.without_glorfindel: true, metrics.detection_note « detection not measured, by
#   choice ») ; aucune attente de détection, jamais de detection_missed ; H0 accepte ce rapport au tirage (un
#   tel rapport qui dirait detected ou missed est refusé), et la console l'affiche « not measured, by choice »,
#   à part d'unknown. Une campagne ainsi lancée le porte dans son manifeste (without_glorfindel: true) et ne
#   se reprend que de la même façon ; elle n'a pas de rapport d'analyse (IA0), ni sur Orodruin ni sur H0,
#   n'entre pas dans l'index ni dans les comparaisons (D-2), et c'est dit : « campaign without Glorfindel: no
#   detection report, by choice ». Le --dry-run n'exige rien.
#   SEC5 (#276) : le battement porte le périmètre de la watch — un condensé de l'abonnement qu'elle lit
#   (AZURE_SUBSCRIPTION_ID), jamais l'abonnement lui-même ; l'injecteur le compare au sien. Une watch vivante
#   d'un autre abonnement, ou un battement sans périmètre (une watch plus ancienne : mettre Glorfindel à
#   jour), est refusé. Le garde est relu avant chaque action d'un run (chaque étape, la commande de l'atomic,
#   le démarrage de la panne) : une watch qui meurt en cours de run l'arrête là (« glorfindel: lost during
#   the run »), et la campagne avec lui. `annatar clean` passe par le garde comme `run` (--without-glorfindel
#   aussi). --without-glorfindel est refusé en zone production, et inscrit au journal d'Orodruin
#   (outcome « declared ») en plus du rapport. Ce que le garde prouve et ce qu'il ne prouve pas :
#   docs/design/orodruin-contract.md, « SEC5 ».

# Annatar
annatar run annatar/scenarios/azure/<scenario>.yaml  # --dry-run disponible, --skip-preflight pour bypasser le check VM
#   Code de sortie (#158) : 0 seulement pour un run allé au bout (détecté, manqué ou non mesuré), un --dry-run ou un
#   « non » à la confirmation ; 1 pour tout refus (pas de watch de Glorfindel vivante, contrat d'Orodruin passif, cible non inscrite, départ sale, atomic
#   refusé ou sondes incomplètes, plafond, preflight, scénario invalide) et toute erreur (aucun effet observé, état
#   initial non restauré ou non vérifié, commande qui lève). Une ligne + un indice ; ANNATAR_DEBUG=1 pour la pile.
#   `annatar campaign run` lit RunOutcome.error, marque le scénario en erreur et continue — sauf un refus
#   `glorfindel:` (la watch morte en route) : la campagne s'arrête (« aborted ») et sort en 1.
annatar run annatar/scenarios/azure/account-creation-atomic.yaml  # R1 : un test Atomic Red Team épinglé (engine: atomic)
#   depuis Orodruin armé seulement (ailleurs le contrat est passif) ; les atomics sont dans l'image (annatar/atomics/, cf. PIN
#   + sha256 vérifié par test) ; l'adaptateur (annatar/engines/atomic.py) refuse ce qu'il ne jouerait pas fidèlement (non-linux,
#   exécuteur hors sh/bash, dependencies, elevation_required: false, #{...} non résolu, PathToAtomicsFolder) et préfixe le shebang
#   #!/bin/<executor>. Le test est joué dans la VM par Run Command, puis son cleanup (toujours, même si la commande lève — rapport
#   écrit, attack: ERROR). Cycle : état initial vérifié avant (départ propre exigé), effet prouvé juste après (sinon pas
#   d'attack_started), état restauré après le cleanup (sinon le run est une erreur + commande de rattrapage affichée). La
#   détection (detected/missed/unknown) est écrite dans runs/<run_id>.json. Un moteur inconnu est refusé (pas de run vide).
#   Les deux moteurs écrivent aussi metrics.detection_latency_s (#157) : secondes entre attack_time (T0, l'appel de la
#   commande) et la détection notée par Glorfindel, null si non détecté (annatar report <run_id> l'affiche). Ne compte
#   qu'une détection du même TTP, sur la même VM (resource_id comparé sans la casse : la watch écrit le _ResourceId de
#   Log Analytics en minuscules), vue à partir de l'attaque — une détection antérieure est celle d'un autre run
#   (annatar/runner/detection.py, même règle pour runs/<run_id>_debug.jsonl et les fichiers watch-*).
#   Depuis Orodruin (#159), la watch est sur H0 : avec EREGION_WATCH_CHANNEL, l'attente lit le canal retour (battement
#   de cœur, detections/<run_id>/), même règle. Sans watch locale, `missed` exige un battement de cœur écrit après
#   l'attente (jusqu'à 130 s de plus), par une watch démarrée avant l'attaque, qui connaît la fenêtre du run ; sinon
#   `unknown`, sans detection_missed, et la raison s'affiche (« channel unreadable », « does not know the run's window »…).

# Gothmog (G0) — depuis Orodruin seulement (ailleurs le contrat est passif)
make gothmog-preflight [FAULT=vm-shutdown]   # watch de Glorfindel, contrat, cibles relues dans l'expérience, état normal — rien d'écrit
make gothmog-run [FAULT=vm-shutdown]         # la panne, son retour vérifié par sonde (~15 min) ; WITHOUT_GLORFINDEL=1 : sans watch (V1)
gothmog run vm-shutdown --dry-run            # la panne déclarée, sans appel Azure
gothmog report <run_id>                      # runs/<run_id>.json (même forme qu'Annatar)
#   Depuis Orodruin, avec EREGION_EXERCISE_CHANNEL (#193, pas encore mesuré sur le banc) : à la fin
#   de `annatar run` comme de `gothmog run`, le rapport du run part vers H0 (runs/<run_id>.json dans
#   le conteneur des fenêtres, sans droit nouveau), après la fermeture de sa fenêtre. La watch
#   hébergée le tire dans son runs/ (une forme refusée n'est pas écrite, un rapport local jamais
#   écrasé) : la page de son injecteur, dans la console, affiche son verdict. Un échec de publication est signalé
#   (« run report … not published ») et ne change ni le run ni son code de sortie.

# Campagne (kill-chain générative + rapport IA0) — depuis Orodruin, sur le modèle de gothmog
make orodruin-campaign-plan CAMPAIGN_TARGET=<resource_id de la VM inscrite> [CAMPAIGN_MAX=5]
#   BL1 (#280) : CAMPAIGN_DECLARED=annatar/campaign/declared/bl1-reponse.yaml — exactement les
#   techniques déclarées, dans leur ordre, vérifiées contre le catalogue (bibliothèque publique,
#   implémentée, non destructive ; zone bench, mode non_disruptive) ; le planner n'y choisit rien.
#   La session de banc pas à pas : docs/banc-bl1.md. Après la campagne :
#   make glorfindel-host-containment CAMPAIGN=<id> [FAULT_RUNS=<run Gothmog>]   (sur H0)
#   make campaign-containment CAMPAIGN=<id> [FAULT_RUNS=…] [JSON=1]               (ici, runs/)
#   — le temps pour contenir et la part contenue seule (docs/analysis.md), lecture seule.
#   Planifie une kill-chain depuis le catalogue (annatar campaign plan) et rend un id. Le planner
#   choisit, le synthétiseur assemble : une entrée engine: atomic (T1136.001) devient une expérience
#   E1 (aucune étape, engine_ref résolu au plan contre les atomics de l'image, sondes comprises) ;
#   une entrée local-script devient un scénario de script. Le moteur de l'entrée fait foi (jamais de
#   repli script pour un atomic). Une entrée atomic sans engine_ref valide ou sans sondes n'est pas
#   synthétisée. Le plan ne dépend ni de jsonschema ni de schemas/ (absents de l'image) : il valide
#   l'expérience comme le run la lira (parser + sondes du moteur atomic) ; le schéma E1 est vérifié
#   par les tests. Une entrée destructive (atomic ou script) demande --allow-destructive et un
#   safe_target. Manifeste et scénarios dans ~/runs/campaigns/<id>/ (bind-monté). La commande n'est
#   pas répétée à l'écran (CAMPAIGN_TARGET porte l'abonnement).
make orodruin-campaign-run CAMPAIGN=<id>     # joue la campagne (watch H0 en human_only — rien ne s'isole) ; refusée sans watch vivante (V1)
#   Chaque run passe par le moteur de son expérience (atomic ou script) ; sa détection (detected/
#   missed/unknown) et sa latence (#157) arrivent dans le manifeste, comme pour un run seul. Le reset
#   entre scénarios (glorfindel reset) n'est pas dans l'image d'Orodruin : le lanceur glorfindel y
#   est (pip install -e ".[annatar]" installe tous les [project.scripts]) mais pas le paquet, qui
#   n'est pas copié. Le runner teste donc le paquet (find_spec), puis le lanceur : s'il manque l'un
#   ou l'autre, le reset est sauté proprement (ni appel, ni échec, ni écriture) et le manifeste le
#   note (scenarios[].reset : reset, skipped: …, ou failed: exit <code> si un glorfindel installé
#   sort en erreur).
#   Le rapport s'écrit sur H0, pas sur Orodruin (#167, 21/10 : code, tests et mutants M126–M149,
#   M159–M169, M180–M188 écrits, pas encore mesuré sur le banc). Orodruin n'a ni chromadb ni litellm. Avec
#   EREGION_EXERCISE_CHANNEL (orodruin.env), la fin de la campagne publie son manifeste et le
#   rapport de chacun de ses runs dans le conteneur des fenêtres (campaigns/<id>/…), sans rien
#   d'autre et sans droit nouveau. La campagne affiche l'id publié et, pour une campagne done, où
#   le rapport s'écrira ; pour une autre (aborted), elle renvoie à make campaign-report. Un run
#   exécuté sans rapport à publier (campaign run --runs-dir X : les rapports de run restent dans
#   runs/) est signalé, et le rapport sur H0 n'est pas annoncé : H0 l'attendrait sans fin. Un
#   échec de publication est signalé et ne fait pas échouer la campagne. Avec --no-report
#   (annatar campaign run), la campagne n'est pas publiée non plus : H0 n'en écrit pas le
#   rapport. L'image d'Orodruin doit être reconstruite pour écrire l'attack_time dans le rapport
#   de chaque run : sans lui, aucune décision de la watch n'est rattachée au run.
make glorfindel-host-campaign-report CAMPAIGN=<id>   # lit runs/campaigns/<id>/report.md sur H0
#   (à défaut, son report.error). Le thread campaign-report de la watch hébergée tire la campagne
#   toutes les 30 s et écrit report.md une fois, quand elle est done et que le rapport de chaque run
#   exécuté est arrivé, seulement pour une campagne tirée du canal (marqueur .pulled). Les
#   décisions viennent des watch-*_debug.jsonl de H0 (règle de #157 bornée par la fenêtre du run,
#   docs/analysis.md). Un run détecté (ou de détection inconnue) sans décision retrouvée fait
#   attendre le rapport jusqu'à la fin de sa fenêtre (grâce comprise), ou 15 min après la fin de
#   la campagne sans fenêtre, plus 10 min pour que le cycle écrive sa décision : environ 25 min
#   après la fin de la campagne. Sans attack_time ou sans resource_id, aucune attente (rien ne pourra
#   être rattaché). Ensuite, le rapport dit pourquoi la décision est inconnue ; il donne action,
#   confiance et escalade pour les décisions retrouvées. Un tirage des fenêtres en échec reporte
#   le rapport au tirage suivant ; un tirage en échec n'est journalisé qu'une fois tant qu'il dure. En cas d'échec (une réponse du modèle
#   sans appel d'outil compte), 3 essais au plus, puis abandon signalé dans make
#   glorfindel-host-logs ([campaign-report]). Le compteur d'essais vit aussi en mémoire : effacer
#   report.error ne suffit pas à relancer : redémarrer la watch (docker restart eregion-watch
#   sur la VM) ou lancer la commande à la main ci-dessous. Index campaign_runs dans
#   ~/.eregion/analysis sur la VM (monté dans le conteneur ; montage et image au prochain
#   redéploiement de H0). À la main, sur la VM, si le rapport automatique a été abandonné :
#     docker exec eregion-watch python -m analysis.campaign_report runs/campaigns/<id>
#   D-2 (#184) : le rapport se compare à la campagne précédente, choisie dans l'index. Pour y
#   verser les campagnes passées (idempotent, aucun appel au modèle), sur la VM :
#     docker exec eregion-watch python -m analysis.campaign_index --all runs/campaigns
#   quand aucun rapport n'est en attente (le fil campaign-report écrit dans le même index
#   chromadb) : la liste de hosted_report.ready doit être vide —
#     docker exec eregion-watch python -c "from pathlib import Path; from analysis import hosted_report as h; print([p.name for p in h.ready(Path('runs/campaigns'))])"
#   (en local : python -m analysis.campaign_index --all runs/campaigns ; docs/analysis.md)
annatar campaign plan --target <resource_id> [--llm]   # en local (banc) ; --llm pour le planner LLM
annatar campaign run <campaign_id> --yes               # ratifie le budget/scope et exécute

# Simulation locale sans Azure — les signaux d'un run dans un fichier temporaire, puis
# `glorfindel respond <fichier> --dry-run` (pas de watch, pas runs/ : SEC3) ; une clé de modèle
make annatar-simulate
make annatar-simulate-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...               # requis si provider Anthropic (défaut)
GLORFINDEL_LLM_MODEL=...            # ex: ollama/llama3.1, openai/gpt-4o, azure/gpt-4o (défaut : anthropic/claude-sonnet-5-5, eregion_core/models.py)
ANNATAR_LLM_MODEL=...               # planificateur de campagne d'Annatar (défaut : anthropic/claude-sonnet-4-6 — claude-sonnet-5-5 refuse ce prompt, 19/10)
EREGION_ANALYSIS_MODEL=...          # IA d'analyse, rapport de campagne (défaut : anthropic/claude-haiku-5-5 — un autre modèle que Glorfindel ; celui de Glorfindel est refusé, IA1) ; passé à la watch par docker-compose.yml (rapport écrit sur H0, #167) et recopié dans host.env par host_env.py (IA1) ; le conteneur d'Annatar reçoit aussi GLORFINDEL_LLM_MODEL, pour que le refus y voie le vrai modèle de Glorfindel
EREGION_ANALYSIS_INDEX=...          # index campaign_runs du rapport de campagne (défaut : ~/.eregion/analysis/chroma ; refusé dans ~/.glorfindel, IA1 ; sur H0, le disque de la VM, monté)
EREGION_ANALYSIS_TIMEOUT_S=300      # borne d'un appel au modèle d'analyse (rapport de campagne), par tentative (défaut 300 ; illisible, ≤0, >3600 → 300) ; passée aux conteneurs (x-env) et à l'image d'Annatar ; sur H0, à poser à la main dans host.env (host_env.py ne la recopie pas)
GLORFINDEL_LLM_BASE_URL=...         # endpoint self-hosted/Ollama (ex: http://localhost:11434)
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams/Discord webhook — escalades ET actions autonomes
                                    # Discord : https://discord.com/api/webhooks/<id>/<token>/slack
DISCORD_BOT_TOKEN=...               # Bot Discord interactif (fils par VM, boutons Acquitter/Commande) ; le conteneur du bot seul (M-3)
DISCORD_CHANNEL_ID=...              # ID du channel (clic droit → Copy Channel ID) ; avec DISCORD_BOT_TOKEN, la watch et la console laissent les cartes au bot (webhook muet) ; seul, il ne fait taire rien
DISCORD_PING_ROLE=...               # ID du rôle à pinger à l'ouverture d'un fil (optionnel)
DISCORD_ALLOWED_USERS=111,222       # M-3 : ids des utilisateurs qui peuvent cliquer les boutons des cartes
DISCORD_ALLOWED_ROLES=333           # M-3 : ids des rôles autorisés ; les deux vides → tous les boutons refusent (fermé par défaut), refus journalisé
# L'atelier dans Discord (N1, docs/atelier-discord.md) — à part de la défense : jamais sur H0, host_env.py ne les recopie pas
EREGION_DISCORD_WEBHOOK_CI=...              # webhook de #ci (secret GitHub : notify.yml)
EREGION_DISCORD_WEBHOOK_AGENTS=...          # webhook de #agents (poste de l'opérateur : hooks d'elrond)
EREGION_DISCORD_BOT_TOKEN=...               # le bot « Eregion », celui de l'atelier (pas celui de Glorfindel) : fils du forum #lots et leurs étiquettes
EREGION_DISCORD_LOTS_FORUM=...              # id du forum #lots
EREGION_DISCORD_ROADMAP_CHANNEL=...         # id du salon #roadmap : le message de la feuille de route (N2, secret GitHub : roadmap.yml)
EREGION_DISCORD_WEBHOOK_DEPLOY=...          # webhook de #deploy : copié sur H0 par make glorfindel-host-cd-install (~/.eregion-cd/discord.env, H1)
EREGION_DISCORD_MENTION=...                 # id de l'utilisateur que mentionnent les pings de #agents
                                    # sur le poste : ~/.config/eregion/discord.env (600) si l'environnement ne les a pas
GLORFINDEL_AZURE_CLIENT_ID=…        # V-17 : le principal de la watch (et …_SECRET) ; EREGION_CONSOLE_AZURE_CLIENT_* la console,
                                    # GLORFINDEL_BOT_AZURE_CLIENT_* le bot ; vides → AZURE_CLIENT_* (« Identités Azure », plus bas)
HOST_SSH_FINGERPRINT=SHA256:…       # V-32 : l'empreinte de la clé d'hôte de H0, relevée sur la VM ; sans elle, accept-new et c'est dit
                                    # (infra/glorfindel-host/README.md, « SSH ») ; HOST_KNOWN_HOSTS : son fichier (~/.eregion/h0_known_hosts)
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h) : au-delà, une carte ttl_exceeded — jamais de levée automatique
EREGION_CONSOLE_HOSTS=nom,nom       # SEC1 : noms (sans port) sous lesquels la console répond, en plus de localhost / 127.0.0.1 / [::1] ; une
                                    # modification n'est acceptée que de l'origine de la console sous ce nom (compose la passe à la console)
GLORFINDEL_APPROVAL_MAX_AGE_H=2     # âge max d'une carte exécutable en un clic (console, « Approve & execute ») ; nan/inf → 2 ; ≤0 → approbation en un clic fermée
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
GLORFINDEL_CONFIDENCE_THRESHOLD=0.7 # gate autonomie LLM (défaut 0.7 — en dessous → escalade forcée) ; illisible, hors [0, 1] → tout est retenu
GLORFINDEL_LLM_TIMEOUT_S=120        # borne d'un appel au modèle de Glorfindel (décision, autoring de règle), par tentative (défaut 120 ; illisible, ≤0, >3600 → 120) ; pas le rapport de campagne : EREGION_ANALYSIS_TIMEOUT_S
GLORFINDEL_DECISION_DRAWS=3         # D-1 : tirages qui doivent s'accorder avant une action disruptive autonome (défaut 3 ; entier de 2 à 10 ; illisible, 1, >10 → toute action disruptive autonome retenue) ; aucun tirage de plus en human_only
GLORFINDEL_READ_ONLY=1              # creds lecture seule (SP Reader) — mode observe-only ; toute valeur sauf vide/0/false/no/off = lecture seule
GLORFINDEL_OWN_CALLERS=<id>,<id>    # AL1 : identités de Glorfindel sur Azure, en plus des claims de son jeton (jeton d'application : appid/azp et oid ; jeton d'utilisateur, `az login` : l'oid seul — l'appid y est celui de la CLI, commun au tenant, dit une fois) et d'AZURE_CLIENT_ID ; ses écritures (isolation, quarantaine, blocage) dans le journal d'activité ne s'escaladent pas, seulement sur une cible qui est à lui (NSG de quarantaine, règle qu'un état d'isolation ou de blocage nomme — un nom glorfindel-* seul ne suffit pas —, règle du client dont une isolation a décalé la priorité, NIC mise en quarantaine) — son identité sur une autre ressource s'escalade, critique. Glorfindel lancé sous l'identité d'un opérateur écarte aussi les écritures de cet opérateur sur les ressources de Glorfindel ; un seul principal pour Annatar et Glorfindel (option A de .envrc.example) écarte de même celles d'Annatar. Journaux d'Entra ID (C2) : rien n'est écarté sous ces identités, elles y sont marquées (acteur ou cible, critique) ; y ajouter l'objet de l'application de Glorfindel pour qu'un identifiant ajouté à son inscription soit marqué
GLORFINDEL_DISCOVERY_RETENTION_H=8  # rétention d'une VM éteinte dans le registre avant éviction (défaut 8h)
EREGION_EXERCISE_CHANNEL=https://…/exercises  # O1 : canal des fenêtres d'exercice (Orodruin publie, la watch hébergée lit) ; vide → fenêtres locales. Porte aussi les campagnes finies (campaigns/<id>/…, #167) et le rapport d'un run seul (runs/<run_id>.json, #193) ; posé sur la watch, il démarre le thread campaign-report, qui tire les deux
# Orodruin seulement (orodruin.env) : EREGION_CHANNEL_SCOPE (le conteneur, seule attribution hors du banc acceptée),
# EREGION_MAX_INJECTIONS / EREGION_MAX_RUN_S (plafond du contrat), EREGION_BENCH_RG
# Gothmog : EREGION_BENCH_WORKSPACE (Log Analytics du banc pour la sonde Heartbeat, défaut law-celebrimbor-amonsul)
```

Chaque conteneur ne reçoit que ses variables (M-3, `docker-compose.yml`) : les clés des modèles
à la watch seule ; `DISCORD_BOT_TOKEN` et `DISCORD_ALLOWED_*` au bot seul ;
`EREGION_CONSOLE_TOKEN` (et son ancien nom, `GLORFINDEL_WARROOM_TOKEN` ; un nouveau `host.env`
reçoit le nouveau, celui de H0 garde l'ancien) à la console seule ;
`GLORFINDEL_WEBHOOK_URL` à la watch et à la console, avec `GLORFINDEL_DISCORD_BOT` (« 1 » si `DISCORD_BOT_TOKEN` est posé, vide sinon,
jamais sa valeur : avec `DISCORD_CHANNEL_ID`, leur webhook se tait) ; à chacun des trois son
principal de service Azure (la watch, « Approve & execute », les boutons Restore / Revert du bot :
« Identités Azure », plus bas ; vides, le principal unique `AZURE_CLIENT_*`) ; les
réglages sans secret aux trois. Une variable nouvelle s'ajoute
dans le bloc de son conteneur, et dans `SECRETS` de `tests/unit/test_glorfindel_host.py` si elle
porte un secret.

Les injecteurs du compose (D1, profils `annatar` et `gothmog`) ont leur bloc, `x-injector` : leur
principal à eux (`ANNATAR_AZURE_CLIENT_ID` / `…_SECRET`, jamais celui de Glorfindel ; vide, pas
d'identité), l'abonnement, les deux canaux et le contrat d'Orodruin (vide : `passive`) ; Annatar
y ajoute `ANNATAR_LLM_MODEL` et `ANTHROPIC_API_KEY` (le planificateur `--llm`), Gothmog
`EREGION_BENCH_WORKSPACE`. Ni webhook, ni jeton du bot, ni jeton de la console.

Plusieurs équipes (D1, `docs/profils/equipes.md`) : `EREGION_INSTANCE` (préfixe des conteneurs,
défaut `eregion`), `EREGION_CONSOLE_PORT` (défaut 7007), `EREGION_RUNS` (défaut `./runs`),
`EREGION_CONFIG` (défaut `./glorfindel-config.yaml`) ; vides, `docker-compose.yml` rend ce qu'il
rendait avant D1 (H0 lit `eregion-watch`, `eregion-war-room`). `make team-start` les pose, et le
`HOME` de l'équipe, sous `env -i`.

**Aucun test n'écrit dans le dépôt** (HY1). Le garde de `tests/unit/conftest.py`
(`nothing_written_in_the_repository`), armé dès l'import du conftest, collecte comprise, fait
échouer la suite :
- **ce que le processus de test écrit sous le dépôt**, caches à part. Vu : un fichier ouvert en
  écriture, un dossier créé ou retiré, un fichier retiré, renommé ou remplacé (`os.replace`,
  `shutil.move`), un lien (`os.symlink`, `os.link`), des dates ou une taille changées
  (`Path.touch` sur un fichier existant, `os.utime`, `os.truncate`), `shutil.rmtree`,
  `sqlite3.connect`. **Pas vu** : ce qu'une bibliothèque C écrit après l'ouverture (les pages
  de sqlite, une écriture par descripteur, mmap), le store de ChromaDB 1.x (écrit par son cœur
  Rust), un chemin relatif à un
  `dir_fd` ou donné en descripteur, et toute écriture d'un sous-processus sous la racine ;
- **à la racine**, quel que soit l'auteur : un `runs/` nouveau, ou toute entrée nouvelle que git
  n'ignore pas.

Limites connues :
- dans l'arbre principal, un autre processus qui crée à la racine une entrée non ignorée
  pendant la suite (une autre session, un éditeur) la fait échouer à tort ;
- un `TMPDIR` ou un `--basetemp` dans le dépôt fait de chaque `tmp_path` une écriture ;
- `os.makedirs(exist_ok=True)` sur un dossier existant compte comme une écriture, de même qu'un
  `os.remove` d'un fichier absent ;
- seul `tests/unit/` est gardé ;
- un dépôt ouvert par un lien symbolique : les chemins sont comparés tels quels, pas résolus.

**Les secrets passent par leur nom** (L23, #228). Les cibles du `Makefile` qui lancent un conteneur
(`annatar-run`, `annatar-dry-run`, `annatar-shell`, `glorfindel-watch`, `-list`, `-shell`…)
donnent chaque secret à `docker run` par son nom, `-e AZURE_CLIENT_SECRET`, jamais par sa valeur :
`-e AZURE_CLIENT_SECRET=…` se lisait dans `ps`, l'historique du shell et `make -n`. Le shell de la
recette choisit la valeur (`GLORFINDEL_AZURE_CLIENT_*` d'abord, puis `AZURE_CLIENT_*` ;
`ANNATAR_AZURE_CLIENT_*` seul, jamais le partagé — SEC7) et la pose dans l'environnement de `docker run` seulement (`*_AZURE_PICK`, devant
la commande). Le canary, `tests/unit/test_makefile_secrets.py` : chaque cible rendue par `make -n`
avec des secrets factices, aucune valeur sur une ligne de commande ; puis les recettes des
conteneurs lancées contre un faux `docker` (le bon principal dans son environnement, rien dans
ses arguments). Une valeur que le shell développe (`-e NOM="$NOM"`) n'apparaît pas dans
`make -n`, mais bien dans `ps` : le texte rendu refuse aussi `-e NOM=`, `--env NOM=` et, sur une
ligne qui lance ssh, `export NOM=`, pour tout nom de secret. Une cible nouvelle qui passe un secret fait de même.

---

## Identités Azure — un principal par service, au moindre droit (V-17, SEC7)

Plus jamais `Contributor` sur l'abonnement (`tests/unit/test_azure_roles.py` refuse un
`--role Contributor` ou `Owner` à la portée d'un abonnement dans la doc et les scripts). Trois
services de Glorfindel, trois principaux, chacun avec ce que son code appelle vraiment :

| Service | Ce qu'il appelle sur Azure | Rôles, portée : les groupes inscrits |
|---|---|---|
| la watch | lit (journaux, NSG, NIC, coffre) ; isole, lève, bloque, débloque, instantané — seule, dans son mode | `Reader`, `Log Analytics Reader` (le workspace), **Eregion Glorfindel Response** |
| la console | lit (audit, préparation, jobs) ; ce qu'un humain approuve : isoler, bloquer, instantané (dans son processus), lever, reset, restore (par la CLI qu'elle lance) | `Reader`, `Log Analytics Reader`, **Response**, **Eregion Glorfindel Restore** |
| le bot | lit les points de restauration ; ses boutons lancent la CLI : Restore, Revert (levée et déblocage) | `Reader`, **Response**, **Restore** |

- **Eregion Glorfindel Response** (`infra/identities/glorfindel-response.json`) : les écritures
  de la réponse, rien d'autre — les droits que l'adaptateur déclare
  (`glorfindel/providers/azure/capabilities.py`, testé contre le fichier), les contrôles liés
  d'une écriture de NIC (IP publique, ASG, équilibreur : à mesurer sur le banc, ci-dessous) et
  le déclenchement d'un instantané du coffre. Jamais un restore, une suppression, une identité,
  un rôle.
- **Eregion Glorfindel Restore** (`infra/identities/glorfindel-restore.json`) : un restore en
  place depuis le coffre — Run Command neutralisée, VM désallouée, disques restaurés par le
  compte de transit, VM redémarrée. **Jamais à la watch** : Glorfindel ne restaure jamais seul,
  et même un bogue ou une décision détournée ne le pourrait pas.
- Les **lectures** : `Reader` sur chaque groupe qui tient une VM inscrite, ses NIC, NSG et
  VNet, et sur celui du coffre ; `Log Analytics Reader` sur le workspace. À mesurer sur une
  portée de groupe (ci-dessous) : ce que rendent les listes à l'échelle de l'abonnement
  (`list_all` des NSG et des NIC, le balayage, les adresses privées), et le contexte « qui a
  changé ce NSG » (le journal d'activité de l'abonnement, lu en REST) — l'un ou l'autre peut
  demander `Reader` sur l'abonnement, jamais plus.
- **Les variables** : `GLORFINDEL_AZURE_CLIENT_ID` / `…_SECRET` (la watch),
  `EREGION_CONSOLE_AZURE_CLIENT_ID` / `…_SECRET` (la console), `GLORFINDEL_BOT_AZURE_CLIENT_ID` /
  `…_SECRET` (le bot) ; vides, chacun prend `AZURE_CLIENT_ID` / `…_SECRET`, le principal unique
  d'avant (rien ne casse).
  - **Une paire va ensemble.** Le compose tire chaque repli variable par variable : un
    `…_CLIENT_ID` posé sans son `…_SECRET` (ou l'inverse) donne au service l'id d'un principal
    et le secret d'un autre. `make glorfindel-start` (`check-azure-env`) dit une paire
    incomplète, sans jamais en dire la valeur.
  - **`AZURE_CLIENT_*`, le repli de tout le reste** : la watch lancée depuis le venv
    (`DefaultAzureCredential`), et tout service du compose dont la paire est vide. Y mettre le
    principal de la watch (`.envrc.example`), jamais celui de la console : il restaure. Un
    restore depuis la CLI du poste prend la paire de la console pour cette commande seulement
    (`AZURE_CLIENT_ID=$EREGION_CONSOLE_AZURE_CLIENT_ID AZURE_CLIENT_SECRET=… glorfindel restore …`).
  - **Les injecteurs ne prennent jamais `AZURE_CLIENT_*`** : `x-injector` dans le compose, et
    `make annatar-*` / `annatar-shell` (`ANNATAR_AZURE_PICK`) ne lisent que
    `ANNATAR_AZURE_CLIENT_*` ; vides, le conteneur rouge n'a pas d'identité
    (`tests/unit/test_makefile_secrets.py`).
  - **`GLORFINDEL_OWN_CALLERS`** (la watch) : les deux `…_CLIENT_ID` de la console et du bot
    doivent y être, sinon chaque écriture approuvée devient une carte du plan de contrôle (AL1)
    — ce que la console ou le bot ont levé ou débloqué se lirait comme l'écriture d'un autre.
    Le compose les y ajoute de lui-même (`${GLORFINDEL_OWN_CALLERS},${EREGION_CONSOLE_…_ID},
    ${GLORFINDEL_BOT_…_ID}`, les vides ignorés) ; une watch lancée depuis le venv ne les
    connaît que si l'opérateur les y met.
  - **Ce que la watch tient de trop est dit** : la préparation lit les droits sur le groupe de
    la VM, et un principal qui tient `deallocate` ou le restore du coffre y reçoit une ligne
    `identity_beyond_response` (information, jamais une retenue) ; la watch le journalise une
    fois.
- **La frontière qui reste** : la console et le bot écrivent sur Azure avec leur propre
  identité (la CLI qu'ils lancent tourne dans leur conteneur). Les rendre lecteurs seuls, c'est
  confier l'action approuvée à la watch (une file sous `~/.glorfindel`, signée par la console),
  qui l'exécute — planifié.
- **H0** : rien ne change. Ses conteneurs partagent l'identité managée de la VM, lectrice
  (`Reader` sur le banc, `Log Analytics Reader` sur son workspace) : une identité par conteneur
  ne s'y sépare pas (le point de jeton de la VM répond à chacun d'eux), et il n'écrit rien.

**Créer** (une fois par tenant pour les rôles ; `<…>` à remplacer, rien de réel ici) :

```bash
SUB=<SUBSCRIPTION_ID>; RG=<groupe des VM inscrites>; VAULT_RG=<groupe du coffre>
LAW=<id de ressource du workspace>
for r in response restore; do
  sed "s|<SUBSCRIPTION_ID>|$SUB|" infra/identities/glorfindel-$r.json > /tmp/eregion-role-$r.json
  az role definition create --role-definition @/tmp/eregion-role-$r.json
done
# Un principal par service, sans rôle à sa création (appId → …_CLIENT_ID, password → …_SECRET).
for s in watch console bot; do az ad sp create-for-rbac --name "eregion-glorfindel-$s"; done
```

Le nom d'un rôle personnalisé est unique dans le tenant : pour un **second abonnement du même
tenant**, `az role definition create` refuse (le nom existe). Ajouter l'abonnement aux portées
du rôle existant, puis l'attribuer comme ci-dessous :

```bash
SUB2=<SECOND_SUBSCRIPTION_ID>
for r in "Eregion Glorfindel Response" "Eregion Glorfindel Restore"; do
  az role definition list --name "$r" --scope /subscriptions/$SUB --query '[0]' -o json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); d["assignableScopes"].append(sys.argv[1]); print(json.dumps(d))' \
        "/subscriptions/$SUB2" > /tmp/eregion-role.json
  az role definition update --role-definition @/tmp/eregion-role.json
done
```

**Attribuer** (`<appId-…>` : ce que la création a rendu) :

```bash
for scope in /subscriptions/$SUB/resourceGroups/$RG /subscriptions/$SUB/resourceGroups/$VAULT_RG; do
  for a in <appId-watch> <appId-console> <appId-bot>; do
    az role assignment create --assignee $a --role Reader --scope $scope
    az role assignment create --assignee $a --role "Eregion Glorfindel Response" --scope $scope
  done
  for a in <appId-console> <appId-bot>; do
    az role assignment create --assignee $a --role "Eregion Glorfindel Restore" --scope $scope
  done
done
for a in <appId-watch> <appId-console>; do
  az role assignment create --assignee $a --role "Log Analytics Reader" --scope $LAW
done
# Le compte de transit du restore (restore_staging_storage), s'il est dans un autre groupe :
#   for a in <appId-console> <appId-bot>; do
#     az role assignment create --assignee $a --role "Eregion Glorfindel Restore" --scope <son groupe>
#   done
```

Puis dans `.envrc` les trois paires `…_CLIENT_ID` / `…_SECRET`, et `AZURE_CLIENT_*` sur celle
de la watch (`.envrc.example`) ; `make glorfindel-restart` (aucun « paire incomplète ») ; et, par
conteneur, `docker exec eregion-watch glorfindel audit <resource_id>` (la console : sa page
Audit) — un droit manquant y est nommé.

**À mesurer sur le banc** avant de retirer l'ancien principal : une isolation et sa levée sur
une VM du banc qui porte une IP publique (les contrôles liés d'une écriture de NIC), un
instantané, un restore depuis la console ; un 403 nomme l'action qui manque, à ajouter au
fichier du rôle (`az role definition update --role-definition @…`).

**Faire tourner un secret** (un an par défaut) : `az ad sp credential reset --id <appId>` rend
un nouveau `password` ; le poser dans `.envrc`, `make glorfindel-restart`. L'ancien cesse à la
réinitialisation : un service à la fois.

**Retirer l'ancien principal partagé** (`Contributor` sur l'abonnement, l'option A d'avant) :

```bash
az role assignment list --assignee <appId-ancien> --all -o table
az role assignment delete --assignee <appId-ancien> --role Contributor --scope /subscriptions/$SUB
az ad sp delete --id <appId-ancien>
az ad app delete --id <appId-ancien>      # l'inscription d'application, que sp delete laisse
```

Le principal `annatar` d'avant (`Contributor` sur l'abonnement) se retire de même (les trois
commandes) : sur un
poste, un injecteur reste passif ; il agit depuis Orodruin, avec l'identité managée qu'y crée
`make orodruin-up` (ses droits par VM inscrite, SEC5).

## Le canari azurerm, sans secret (P-04, 30/10)

Le canari (`.github/workflows/canary-azurerm.yml`, chaque jour ; `make canary-jit` sur un poste)
revérifie, sur la dernière version de chaque ligne d'azurerm (3.x, 4.x, 5.x), le comportement de
Terraform dont dépend l'isolation juste à temps (`docs/design/module-isolation-iac.md`). Il tenait
un secret client de longue durée, et son principal pouvait créer un groupe dans l'abonnement
(constat P-04 du contre-audit). Maintenant :

- **Aucun secret de longue durée.** Le job demande à GitHub un jeton OIDC (`id-token: write`, à ce
  seul job), valable quelques minutes, qu'Entra ID échange contre le principal `eregion-canary`.
  Son identifiant fédéré ne fait confiance qu'à `main` de ce dépôt
  (`repo:Vanyar53/eregion:ref:refs/heads/main`) : un run lancé sur une autre branche, une PR ou un
  fork n'obtient rien. Terraform lit le jeton lui-même (`ARM_USE_OIDC`, et
  `ACTIONS_ID_TOKEN_REQUEST_URL` / `…_TOKEN`, que le runner pose) ; `az`, dont le canari se sert
  pour le NSG de quarantaine, se connecte avec le même genre de jeton (`az login
  --federated-token`), tiré par `curl` : aucune action tierce. `ARM_USE_CLI=false` : Terraform
  ne se rabat jamais sur cette session `az`, un canari vert prouve l'OIDC du fournisseur.
- **Ses identifiants sont des secrets du dépôt** — `CANARY_AZURE_CLIENT_ID`,
  `CANARY_AZURE_TENANT_ID`, `CANARY_AZURE_SUBSCRIPTION_ID` —, jamais des variables, qui
  s'impriment en clair dans un journal public. Sans eux, ou hors de `main`, le run échoue (T16).
- **Au moindre droit.** Le principal est `Contributor` sur un seul groupe, `rg-eregion-canary`,
  créé une fois par Jonathan ; le canari ne crée ni ne supprime de groupe. Chaque run y crée des
  ressources gratuites (VNet, NSG, NIC) nommées avec son suffixe (`gh<run>-<tentative>-<ligne>`)
  et marquées `canary-run=<suffixe>` : les trois lignes du `matrix` tournent côte à côte sans
  collision. Il les détruit à la fin, en succès comme en échec (`terraform destroy`, puis le NSG
  de quarantaine créé hors de Terraform ; un destroy qui échoue laisse place à un balayage par
  l'étiquette du run, les NIC d'abord). Le fournisseur n'enregistre aucun fournisseur de
  ressources (3.x : `ARM_SKIP_PROVIDER_REGISTRATION=true` ; 4.x et 5.x :
  `ARM_RESOURCE_PROVIDER_REGISTRATIONS=none`) : ce droit est à l'abonnement, le principal ne l'a pas.
- **Ce que le canari éprouve ne change pas** : les mêmes ressources, le même NSG posé hors de
  Terraform sur une NIC dont le NSG est dans le code puis sur une NIC sans NSG, le même `apply`
  qui met la NIC à jour, le même NSG d'origine remis, les mêmes six vérifications et les mêmes
  codes de sortie. Ce qui change : le groupe existe d'avance (sa région fait celle des
  ressources), les noms portent le suffixe, les NIC portent deux étiquettes de plus.
- **Sur un poste**, `make canary-jit` travaille dans le même groupe (`CANARY_RESOURCE_GROUP`
  pour un autre), avec la session `az` de l'opérateur ; sans le groupe, il s'arrête (code 2)
  sans rien créer.

**Les gestes de Jonathan, dans l'ordre** (une fois ; `<…>` à remplacer, rien de réel ici). Rien
ne se lance depuis une session : ces commandes écrivent dans Entra ID, dans l'abonnement et dans
les secrets du dépôt.

```bash
REPO=Vanyar53/eregion
az account set --subscription <nom ou id de l'abonnement du banc>
SUB=$(az account show --query id -o tsv)          # lu, jamais tapé : rien dans l'historique

# 1. L'inscription eregion-canary et son principal — sans secret ni certificat.
APP=$(az ad app create --display-name eregion-canary --query appId -o tsv)
az ad sp create --id "$APP" -o none

# 2. L'identifiant fédéré : main de ce dépôt seulement.
cat > /tmp/eregion-canary-fic.json <<'EOF'
{"name": "eregion-canary-main",
 "issuer": "https://token.actions.githubusercontent.com",
 "subject": "repo:Vanyar53/eregion:ref:refs/heads/main",
 "audiences": ["api://AzureADTokenExchange"],
 "description": "canary-azurerm.yml, on main"}
EOF
az ad app federated-credential create --id "$APP" --parameters @/tmp/eregion-canary-fic.json
az ad app federated-credential list --id "$APP" -o table   # un seul, ce sujet-là

# 3. Le groupe, et Contributor sur lui seul (jamais sur l'abonnement).
az group create -n rg-eregion-canary -l westeurope --tags purpose=eregion-canary-jit -o none
az role assignment create --assignee "$APP" --role Contributor \
  --scope /subscriptions/$SUB/resourceGroups/rg-eregion-canary
az role assignment list --assignee "$APP" --all -o table      # ce seul rôle, ce seul groupe

# 4. Les secrets du dépôt, la valeur par l'entrée standard : ni sur la ligne de commande, ni
#    dans l'historique du shell.
printf %s "$APP" | gh secret set CANARY_AZURE_CLIENT_ID --repo "$REPO"
az account show --query tenantId -o tsv | tr -d '\n' | gh secret set CANARY_AZURE_TENANT_ID --repo "$REPO"
printf %s "$SUB" | gh secret set CANARY_AZURE_SUBSCRIPTION_ID --repo "$REPO"

# 5. Le premier run (quelques minutes après le rôle : sa propagation), sur main.
gh workflow run canary-azurerm.yml --repo "$REPO" --ref main
sleep 10                                                     # le temps que le run apparaisse
gh run watch --repo "$REPO" \
  "$(gh run list --repo "$REPO" --workflow canary-azurerm.yml --limit 1 --json databaseId -q '.[0].databaseId')"
az resource list -g rg-eregion-canary -o table               # vide : tout a été détruit
```

**Puis, après un canari vert seulement** : retirer l'ancien secret du dépôt et l'identifiant de
l'ancien principal. D'abord, qui d'autre s'en sert :

```bash
OLD=<appId de l'ancien principal du canari>
az role assignment list --assignee "$OLD" --all -o table   # ses droits, partout
az ad app credential list --id "$OLD" -o table             # ses secrets : lequel est celui du canari
gh secret list --repo "$REPO"                              # les AZURE_* d'avant
# Le même principal sur le poste ou dans un service ? Comparer, sans l'afficher :
#   source .envrc; for v in AZURE_CLIENT_ID GLORFINDEL_AZURE_CLIENT_ID EREGION_CONSOLE_AZURE_CLIENT_ID \
#     GLORFINDEL_BOT_AZURE_CLIENT_ID ANNATAR_AZURE_CLIENT_ID; do [ "${(P)v}" = "$OLD" ] && echo "$v"; done
#   (zsh ; en bash : "${!v}")
```

S'il a d'autres rôles que ceux du canari, ou si un service s'en sert encore, ne retirer que le
secret du canari (`az ad app credential delete --id "$OLD" --key-id <keyId>`), jamais le
principal. Sinon :

```bash
for s in AZURE_CLIENT_SECRET AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID; do
  gh secret delete "$s" --repo "$REPO"
done
gh secret list --repo "$REPO"        # restent les trois CANARY_AZURE_*, et ceux de Discord
az role assignment list --assignee "$OLD" --all --query "[].[roleDefinitionName,scope]" -o tsv
az role assignment delete --assignee "$OLD" --role <rôle lu ci-dessus> --scope <portée lue ci-dessus>
az ad sp delete --id "$OLD"
az ad app delete --id "$OLD"         # l'inscription, que sp delete laisse
```

**Ce qui reste à mesurer au premier run** (hypothèses, rien n'a tourné sur Azure dans ce lot) :
que `az login` voit l'abonnement d'un principal qui n'a de rôle que sur un groupe ; que les
trois lignes s'authentifient par OIDC avec `ARM_USE_CLI=false` (lu dans la doc du fournisseur à
v3.117.1, v4.81.0 et v5.12.0, et les noms des variables trouvés dans chacun de ces binaires,
30/10) ; que `Contributor` sur le groupe suffit au `data "azurerm_resource_group"`, aux NIC et
au balayage (`az network nic|nsg|vnet list` filtré sur l'étiquette côté client — `az` refuse
`--tag` avec `-g` —, puis `delete --ids`) ; qu'aucune ressource ne reste dans le groupe après le run.
**Ce qui reste ouvert** : un runner tué (pas d'`EXIT`) laisse les ressources de son run dans le
groupe, gratuites et marquées par leur suffixe (`az resource list -g rg-eregion-canary -o
table`) ; et le principal, `Contributor` sur son groupe, pourrait le supprimer ou y créer une
ressource payante — seul un job de `main` qui tient `id-token: write` obtient son jeton (le sujet
ne nomme pas le workflow ; deux le tiennent, le canari et `publish.yml`, `tests/unit/test_workflows.py`).

## Les conteneurs durcis (V-34, SEC7)

Chaque service du compose tourne sans capacité (`cap_drop: [ALL]`), sans gain de privilège
(`no-new-privileges:true`), la racine en lecture seule (`read_only: true`, `/tmp` en tmpfs) :
il n'écrit que dans ses montages (`runs/`, `~/.glorfindel`, `~/.cache/chroma`,
`~/.eregion/analysis` pour la watch ; `~/.annatar` pour Annatar), et la config que la console
réécrit l'est sur place, sous verrou (`glorfindel/config.py`). `tests/unit/test_profiles.py`
exige les quatre clés sur chaque service. Mesuré le 29/10 sur Docker (compose 5.5) : les
écritures de chaque service (escalades, état, découverte, ChromaDB, l'index d'analyse, la
config, `/tmp`) passent, l'image et `/root` refusent, `CapEff` à zéro, `NoNewPrivs` à 1. Les
`docker run` de `make glorfindel-shell` / `annatar-shell` et du préflight du CD ne passent pas par
le compose. Annatar ne monte ni `~/.eregion/analysis` ni `~/.cache/chroma` : son rapport de
campagne s'écrit dans `runs/`, et l'index de l'IA d'analyse ne s'ouvre jamais dans son conteneur
(chromadb n'est pas dans son image, `tests/unit/test_profiles.py`). Sur H0, la santé du CD lit
le journal de chaque conteneur depuis la bascule : un « Read-only file system » que la release
d'avant ne montrait pas (relu dans sa dernière heure, avant la bascule) est une régression, et
H0 revient en arrière (`infra/glorfindel-host/cd/eregion_cd.py`, `read_only_errors`) ; le même
avant et après est dit, jamais un retour ; un journal illisible est dit en orange, non prouvé.

---

## Configuration — `glorfindel-config.yaml` lue strictement (A3, 27/10)

Le fichier est lu clé par clé : une clé que rien ne lit, une valeur du mauvais type, `"false"` entre
guillemets **refusent le fichier** (`ConfigError`), avec tous les problèmes à la fois, chacun à son
chemin (`isolation.quarantaine_nsg : clé inconnue … vouliez-vous dire « quarantine_nsg » ?`,
`exceptions[0].exclude_all : "false" est un texte entre guillemets, pas un booléen — écrire false sans
guillemets`, `autonomy.allow_destructive : une liste est attendue, pas "vm-*" — écrire [vm-*]`). Avant,
ces fautes passaient en silence : la clé mal écrite laissait son défaut (la quarantaine restait
allumée), `exclude_all: "false"` sortait la VM de toutes les règles (un texte non vide est vrai),
`allow_destructive: "vm-*"` devenait les motifs `v`, `m`, `-` et `*`.

- Clés connues : `monitoring_backends` (`name`, `type`, `workspace_id`, `endpoint`, `discovery` :
  `enabled`, `interval_s`), `action_backends` (`name`, `type`, `vault_name`, `resource_group`,
  `restore_staging_storage`), `exceptions` (`asset_pattern`, `exclude_all`, `exclude_rules`),
  `autonomy` (`default`, `assets` : `match`, `mode` ; `allow_destructive`), `isolation`
  (`quarantine_nsg`, `quarantine_rg`, `forensic_sources`, `forensic_ports`), `never_block`
  (SEC2, ci-dessous).
- Types : textes entre guillemets ou non, booléens `true` / `false` sans guillemets, listes pour
  `exclude_rules`, `allow_destructive`, `forensic_sources`, `assets` et les sections de backends ;
  `interval_s` un nombre de secondes positif ; `forensic_ports` un port ou une liste (inchangé). Une
  section vide (tous ses éléments en commentaire) vaut une liste vide.
- Valeurs de `type` : celles que quelque chose lit — `monitoring_backends` : `azure_monitor`, `prometheus` ; `action_backends` : `azure_backup_vault`. `type: azure_monitr` est refusé, avec celle qu'il rappelle (un backend que rien ne lisait : ni découverte, ni règle liée). Un nouveau type s'ajoute dans `glorfindel/config.py` (`_MONITORING_TYPES`, `_ACTION_TYPES`).
- Effets du refus : la watch **ne démarre pas** (code 2, le message en rouge) ; l'isolation est refusée
  avant toute écriture et la préparation dit `config_unreadable` (comme un YAML illisible, S1) ; la
  réaffirmation passe en alertes seules.
- Le fichier d'exemple (`glorfindel-config.yaml.example`) et le fragment de Celebrimbor
  (`make celebrimbor-output`) passent la lecture stricte (`tests/unit/test_config.py`).
- **`never_block`** (SEC2, 28/10) : une liste d'adresses ou de préfixes CIDR que Glorfindel ne
  bloque **jamais**, quelle que soit la règle ou le modèle — en plus de ceux livrés
  (`glorfindel/response/policy.py`, `NEVER_BLOCK_SHIPPED` : 168.63.129.16 et 169.254.169.254 de la
  plateforme Azure, 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, le bouclage ; `::ffff:a.b.c.d`
  est lue comme son IPv4). Y mettre la sortie du bureau, un scanner, une sonde de supervision.
  **Une adresse privée n'est donc jamais bloquée** : un mouvement latéral depuis une autre VM du
  réseau ne se répond pas par un blocage d'IP, mais par l'isolation de la VM source. Un blocage d'une de ces adresses est retenu par `decide`
  (carte `protected_address`) et refusé par le connecteur, Azure comme AWS, quel que soit le chemin
  (décision de l'agent, approbation d'une carte dans la console et
  son extension au sous-réseau, réaffirmation) ; une liste illisible refuse tout
  blocage. Chaque entrée est validée (adresse ou préfixe ; `/0` refusé : couper les blocages se fait
  par le mode d'autonomie). Absente : la liste livrée seule. **Clé nouvelle** : une config qui la
  porte est refusée par une version antérieure (lecture stricte) — la poser sur H0 après la mise à
  jour.

---

## Verrou des dépendances

`pyproject.toml` déclare des plages (`>=`) ; le verrou fixe ce qui s'installe vraiment (M-3,
#183). Une version mineure de LiteLLM avait cassé toutes les décisions de H0 (19/10) : sans
verrou, chaque reconstruction de l'image prenait la dernière version de tout.

- `requirements/dev.txt` : la CI (3.11, 3.12, macOS), `make install`, les mutants et les
  invariants de nuit. `requirements/glorfindel.txt` : l'image de Glorfindel (H0 compris).
  `requirements/annatar.txt` (HY1) : l'image des injecteurs, Annatar et Gothmog, celle que
  `make orodruin-push` envoie à Orodruin — avec `litellm`, dont le planificateur a besoin
  (`annatar campaign plan --llm`), et `jsonschema` et `requests`, déclarés plutôt qu'apportés
  par litellm et azure-core. Les deux images sont contraintes par le premier : elles
  tournent avec les versions que la CI a testées.
  `requirements/build.in` : le backend de construction (setuptools, wheel), verrouillé aussi.
- Installation : `pip install --require-hashes -r requirements/<fichier>.txt`, puis le projet
  seul, `pip install --no-deps --no-build-isolation -e .`. pip vérifie l'empreinte SHA-256 de
  chaque fichier téléchargé et refuse toute dépendance absente du verrou ou sans empreinte.
- **L'outil : uv** (`uv pip compile`), seulement pour générer. Une résolution *universelle*
  (`--universal`) : un seul fichier vaut pour Python 3.11 et 3.12, Linux et macOS, avec des
  marqueurs là où les versions divergent (numpy). pip-tools résout pour l'interpréteur qui le
  lance : un verrou fait en 3.12 peut manquer une dépendance que seul 3.11 tire, et pip la
  refuserait en mode empreintes. Le fichier produit reste au format `requirements` : pip
  l'installe sans uv, dans l'image, en CI et chez un contributeur. `--exclude-newer <date>` :
  la même commande donne le même verrou ; la date est dans l'en-tête du fichier.
- Le premier verrou (26/10) fige la résolution de ce jour-là : celle qu'une reconstruction de
  l'image aurait prise ; la suite de tests passe dessus en 3.11 et en 3.12, et l'image se
  construit. LiteLLM reste épinglée dans `pyproject.toml` (`==1.86.1` alors, `==1.100.4` depuis
  DEP1, ci-dessous). Il monte nettement de
  versions par rapport aux postes et à la CI d'avant (anthropic 0.104 → 2.3, fastapi 0.136 →
  0.162, langgraph 1.2.1 → 1.2.17) : **le harnais avant le premier redéploiement de H0 sur ce
  verrou n'est pas facultatif** (`infra/glorfindel-host/README.md`, « Redéployer H0 après M-3 »,
  étape 4).
- DEP1 (#282, 29/10) : litellm 1.86.1 → 1.100.4, à la même date de résolution (`LOCK_DATE`
  2026-10-26). 1.100.4 déclare en plus `boto3` et `pydantic-settings`. Entrent dans les trois
  verrous boto3, botocore, s3transfer et jmespath. Dans celui des injecteurs entrent aussi
  pydantic-settings, python-dateutil et six : chromadb les apportait déjà aux deux autres.
  python-dateutil redescend de 3.0.0 à 2.9.0.post0 dans `dev.txt` et `glorfindel.txt`, car
  botocore exige `<3.0.0`, et tzdata, que seule la 3.0.0 tirait, en sort. Le SDK d'AWS est
  installé par litellm, jamais importé hors d'un adaptateur de fournisseur
  (`tests/unit/test_provider_boundary.py`, aussi une étape de la CI).

**Mettre à jour** (une PR, jamais directement sur H0) :

```bash
pip install uv                          # ou pipx install uv ; seulement pour générer
make lock                               # garde les versions verrouillées, ajoute ce qui manque (dépendance ajoutée à pyproject.toml)
make lock UPGRADE=1                     # monte tout à la résolution du jour (LOCK_DATE=AAAA-MM-JJ pour une autre date)
make install && pytest                  # la suite sur le nouveau verrou
```

La PR dit ce qui change (le diff du verrou : LiteLLM, anthropic, langgraph, chromadb surtout).
Avant de la fusionner, **Jonathan relance le harnais** (appels payants), qui écrit l'attestation
que le CD de H0 exige (H1, H3) :

```bash
make install                            # le .venv suit le nouveau verrou (sinon : rien n'est lancé)
make llm-compare MODELS=<modèle de H0> RUNS=3 ATTEST=1             # référence = le dernier tag v*
make llm-compare MODELS=<modèle de H0> RUNS=3 ATTEST=1 BASE=v0.4.6 # H0 tourne sur une autre release
git add requirements/harness.json       # dans la PR du verrou
```

**Deux passages** (H3, #324, `scripts/harness_attest.py`). Le harnais tourne d'abord sur la
référence : le verrou de la release en service, installé avec `--require-hashes` dans un venv
jetable, `~/.cache/eregion/harness-reference/<sha256>/`. Ce venv est gardé pour la fois suivante
et ne va jamais dans le dépôt. Puis il tourne sur le candidat, le `.venv` du checkout. Le code et
les cas sont les mêmes, seules les dépendances changent. `requirements/harness.json` garde les
deux passages, et par cas chaque tirage (juste ou non, l'action, la confiance) : le CD juge cas
par cas contre ce qui tourne (`infra/glorfindel-host/README.md`, « L'attestation du harnais »).
Il refuse une régression, jamais une variation : le modèle par défaut refuse une température
fixée, et le même verrou a donné 51/51, puis 50/51 (29/10).

**Le coût : deux fois celui d'un passage.** Un passage, c'est 17 cas × 3 runs = 51 décisions.
Une action disruptive est tirée 3 fois (`GLORFINDEL_DECISION_DRAWS`, D-1), une décision prudente
une fois. Cela fait environ 130 appels au modèle par passage, 153 au plus, et environ 260 pour
les deux, 306 au plus. La première fois, l'installation du venv de référence prend en plus
quelques minutes (un `pip install` du verrou).

**Une PR de verrou ne porte pas de code qui exige ses nouvelles dépendances.** La référence fait
tourner le code du checkout sur l'ancien verrou : un code qui importe une dépendance que ce verrou
n'a pas échoue à l'import, et rien n'est attesté (`harness_attest.py` le dit). Il faut séparer
les PR : le verrou d'abord, attesté et déployé, puis le code qui s'en sert. Le harnais mesure le
verrou, pas le code : un recul dû au code d'une release qui change aussi le verrou paraît des
deux côtés (« faux des deux côtés »), dit, jamais refusé.

Avant le harnais, la CI a déjà éprouvé l'appel : dans chaque image, un appel d'outil par litellm,
répondu par son propre mock, sans réseau (DEP1, « La CI des images » ci-dessous). `import litellm`
ne suffit pas : 1.106.0 (19/10) s'importait, puis chaque appel échouait (« No module named
'mcp' »).

Rien n'est lancé, donc rien n'est payé, dans quatre cas :
- `RUNS` est sous 3, ou `--kinds` est passé avec `--attest` ou `--pass-out` ;
- le `.venv` ne suit pas le verrou ;
- le verrou du checkout est celui de la référence (« ce verrou est déjà celui de <tag> : donne
  BASE=<la release d'avant> ») ;
- `--attest` est passé sans référence, ou avec une référence qui ne correspond pas (runs,
  modèles).

Sans `ATTEST`, `make llm-compare` reste la comparaison d'un seul passage. Ensuite,
`make glorfindel-host-start REF=<tag>`, ou la release publiée que le CD déploie
(`infra/glorfindel-host/README.md`). Un test (`tests/unit/test_dependency_lock.py`) échoue si une
dépendance de `pyproject.toml` manque au verrou ou n'y satisfait plus sa plage : `make lock`. Un
autre (`tests/unit/test_llm_smoke.py`) échoue en CI si l'attestation commitée n'est plus celle du
verrou, ne couvre pas le modèle par défaut, n'a pas de référence, ou est à l'ancien format.

Les deux images sont construites et éprouvées en CI à chaque PR qui touche le verrou (CI1,
ci-dessous) : un verrou cassé échoue dans la PR.

---

## La CI des images (CI1, #267, 29/10)

Avant CI1, la CI ne construisait aucune image : compose était seulement rendu (`make
profiles-check`). L'image de Glorfindel n'était construite que sur H0, par le CD. Un Dockerfile ou
un verrou cassé n'apparaissait qu'à son préflight : la release était refusée, sans dégât, mais
brûlée. L'image des injecteurs n'était construite que sur le poste de l'opérateur (`make
orodruin-push`).

**Le workflow** `.github/workflows/images.yml` a deux jobs, `image (glorfindel)` et `image
(annatar)`. Il tourne sur chaque PR et chaque push sur `main`, sans filtre `paths` : c'est son
premier step qui décide (`python3 scripts/image_check.py touched`).
- Une PR dont le diff (son commit de fusion contre la base, renommages vus comme un retrait et un
  ajout) ne touche rien de ce qui entre dans une image saute la construction et passe au vert. Une
  PR de docs ou de tests seuls est dans ce cas.
- Ce qui entre dans une image est la liste `IMAGE_PATHS` du script : les Dockerfiles,
  `.dockerignore`, `requirements/`, `pyproject.toml`, la config d'exemple, `docker-compose.yml` (il
  dit où la config est montée), et les paquets et fichiers copiés (`glorfindel/`, `annatar/`,
  `gothmog/`, `eregion_core/`, `eregion_console/`, `analysis/`, `scripts/`,
  `technique_catalog.yaml`). `tests/unit/test_image_check.py` lit les `COPY` de chaque Dockerfile
  (lignes continuées jointes, casse ignorée) et échoue si un chemin copié manque à la liste.
- Un push sur `main` construit toujours, sans lire le diff. Un diff illisible construit aussi : la
  décision échoue fermée. De même (SEC7) : un HEAD qui n'est pas le commit de fusion de la PR
  (`HEAD^2` absent : le diff n'aurait pas de base), une file de fusion (`merge_group`, si elle est
  activée un jour), et une décision absente — les étapes ne sautent que sur un `false` explicite
  (`!= 'false'`), et `touched` sort en 1 dans la CI (`GITHUB_ACTIONS`) sans `GITHUB_OUTPUT`.

La CI des images ne rend pas compose : chaque profil est rendu par `make profiles-check`
(`components.yml`, `tests/unit/test_profiles.py`).

1. **La construction** : `docker/build-push-action`, épinglée par commit, comme
   `docker/setup-buildx-action`. Elle prend le Dockerfile de l'image, le dépôt pour contexte, aucun
   build-arg : l'UID/GID par défaut de l'image, rien n'est monté. Le cache de GitHub Actions a
   une portée par image. Il est lu partout et écrit seulement par les pushes sur `main` : une PR ne
   peut pas évincer le cache de `main`. L'image est chargée dans le docker du runner
   (`eregion-<image>:ci`), **jamais poussée** : aucun registre, aucune connexion, aucun secret,
   `contents: read`.
2. **Dans l'image**, `python3 scripts/image_check.py <image>`. Chaque vérification est un `docker run
   --rm --network none` qui ne prend rien de l'environnement de l'hôte : aucun secret, aucun réseau
   Azure. Elle lance une commande, jamais le `CMD` de l'image : rien ne démarre.
   - Glorfindel : `glorfindel --version` est la version de `pyproject.toml`. La watch, le bot et
     la console importent. Ce sont les mêmes imports que le préflight du CD (`eregion_cd.py`,
     étape 5). Un test lit chaque `docker run` de ce préflight et exige sa vérification ici ; le
     rendu de compose avec le `.env` de H0 est la seule exception, écrite. `glorfindel-config.yaml.example` passe la lecture stricte
     d'A3 : il est monté en lecture seule là où compose monte la config, puis ouvert avant d'être
     lu, car un fichier absent se lirait comme une config vide. Un appel d'outil passe par
     litellm, comme la décision le fait (`eregion_core/llm_call.py`), répondu par le mock de
     litellm : ni clé, ni modèle, ni réseau (DEP1). La carte des coûts locale est vérifiée par le
     message de litellm (« Failed to fetch remote model cost map », derrière un proxy fermé, dans
     `tests/unit/test_image_check.py`). Sous `--network none`, une version qui changerait ce texte
     coûterait une lenteur, jamais une fausse réussite. L'image ne tourne pas en root.
   - Annatar (l'image des injecteurs) : `annatar --version` est la version de `pyproject.toml`.
     Annatar et Gothmog importent. Ni Glorfindel, ni la console, ni leurs dépendances (la liste de
     D1, `scripts/component_check.py`) ne sont dans l'image. Le même appel d'outil par litellm
     (celui du planificateur). Elle ne tourne pas en root.

   Toutes les vérifications tournent, même après un échec : le journal dit tout ce qui ne va pas
   d'un coup. Le script sort en 0 si tout passe, en 1 sinon, en 2 si docker manque.

**En local, la même chose** : `make images-check` construit les deux images comme le job, sans le
cache de GitHub (`python3 scripts/image_check.py <image> --build`), puis les éprouve. Les tags
`eregion-glorfindel:ci` et `eregion-annatar:ci` ne touchent pas les images de `make build`
(`:latest`, à l'UID/GID de l'opérateur). `python3 scripts/image_check.py glorfindel --image <nom>`
éprouve une image déjà construite.

**Ce qu'il attrape** (démontré le 29/10 sur des copies cassées exprès, rien de poussé) :

| Copie cassée | Où le job échoue |
|---|---|
| `requirements/glorfindel.txt` : litellm épinglée à une version dont le verrou n'a pas les empreintes | la construction : pip refuse (« THESE PACKAGES DO NOT MATCH THE HASHES ») |
| `requirements/annatar.txt` : une dépendance (click) retirée du verrou | la construction : pip refuse (« all requirements must have their versions pinned ») |
| `annatar/Dockerfile` : un `COPY` d'un fichier qui n'existe pas | la construction (« not found ») |
| `glorfindel/Dockerfile` sans `COPY eregion_console/` : l'image se construit | la vérification : « la watch, le bot et la console importent », code 1 (`No module named 'eregion_console'`) |
| litellm 1.106.0 à la place de 1.100.4 (DEP1, mesuré le 29/10 dans un venv jetable, sans réseau) : `import litellm` passe | la vérification : « un appel d'outil par litellm », code 1 (`No module named 'mcp'`) |

**Durées mesurées** (29/10, poste de l'opérateur, WSL2, image de base déjà tirée, sans le cache de
GitHub) :

| | Glorfindel | Annatar |
|---|---|---|
| sans cache (`--no-cache`) | 72 s | 34 s |
| avec cache, rien de changé | 6 s | 6 s |
| avec cache, du code changé (`eregion_core/`) : la couche des dépendances reste | 8 s | 5 s |
| les vérifications dans l'image | 4 s | 2 s |

Sur un runner de GitHub, il faut ajouter le tirage de `python:3.12-slim`, le téléchargement depuis
PyPI et, sur `main`, l'écriture du cache (`mode=max`, la couche des dépendances de Glorfindel pèse
environ 1 Go). La durée réelle se lit au premier run sur la PR. Elle est bornée à 30 min par job.
Une PR qui ne touche aucune image ne coûte que le checkout et la décision : quelques secondes.

**Rendre le job requis** est la décision de Jonathan (protection de `main`). Les checks à exiger
sont `image (glorfindel)` et `image (annatar)`. Le workflow n'a pas de filtre `paths`, pour cette
raison : un workflow filtré ne tourne pas sur une PR qui ne touche aucun de ses chemins, et son check
requis y resterait « attendu », la fusion bloquée. Un job compagnon du même nom, qui passerait quand
les chemins ne sont pas touchés, serait fragile : sur une PR qui touche à la fois une image et autre
chose, les deux tourneraient, et le vert de l'un pourrait masquer le rouge de l'autre. Ici, un seul
job par image décide lui-même, dans son premier step, de construire ou de passer.

**Un run rouge est annoncé dans `#ci`** : « Images » est dans la liste `workflow_run` de
`notify.yml`. `tests/unit/test_workflows.py` exige que chaque workflow lancé par un push, une PR ou
la nuit y figure, sauf ses exceptions écrites (Notify lui-même, Roadmap, vert par conception).

**Et le CD de H0** : il exige que tous les checks du commit d'une release soient verts. Un job
`image` rouge sur `main` fait donc refuser la release, avant même son préflight. L'étape 2 de #267,
décidée par Jonathan le 29/10 : la section suivante.

## Les images publiées (CI3, #267, 29/10)

Avant CI3, H0 construisait l'image de Glorfindel de chaque release (son CD, `deploy.sh
--build-only`), et l'image des injecteurs se construisait sur le poste de l'opérateur (`make
orodruin-push`). Rien ne liait l'image qui tourne à ce que la CI avait éprouvé, ni à un commit
signé (contre-audit : P-02, ni SBOM ni signature ; V-22, des tags non signés).

**Ce qui est publié.** La tête de chaque push sur `main` (le commit de fusion d'une PR, en squash) a ses deux images, `ghcr.io/vanyar53/eregion-glorfindel`
et `ghcr.io/vanyar53/eregion-annatar`, étiquetées `sha-<commit complet>`, par
`.github/workflows/publish.yml` (jobs `publish (glorfindel)`, `publish (annatar)`) :
1. construites comme dans `images.yml` (CI1), plus ce que les hôtes demandent : l'utilisateur de
   H0 et d'Orodruin (UID/GID 1000, le premier utilisateur d'une VM Ubuntu d'Azure), et les
   étiquettes `org.opencontainers.image.version` (`v` + la version de `pyproject.toml`, que dit
   `glorfindel --version`) et `.revision` (le commit) ;
2. éprouvées dans l'image (`scripts/image_check.py`, les vérifications de CI1) **avant** d'être
   poussées : une image qui échoue n'atteint jamais le registre ;
3. poussées (`scripts/published_image.py pushed` : le digest est celui que docker a enregistré
   pour ce dépôt, celui de l'image éprouvée) ;
4. **attestées** : une provenance SLSA v1 (`actions/attest-build-provenance`) et un SBOM SPDX
   (`anchore/sbom-action`, puis `actions/attest-sbom`), toutes deux poussées dans le registre à côté
   de l'image et gardées dans le magasin d'attestations de GitHub ;
5. **signées sans clé** : `cosign sign`, un certificat de sigstore délivré sur le jeton OIDC de
   GitHub (aucune clé de longue durée, aucun secret) ;
6. **vérifiées comme H0 les vérifie** (`published_image.py verify`, le même cosign épinglé) ;
7. lues sans jeton, ou un avertissement : un paquet encore privé est dit dans le run.

Ce workflow est le seul qui peut écrire un paquet, demander un jeton OIDC ou écrire une
attestation (`packages`, `id-token`, `attestations: write`, au niveau du job), et il ne tourne que
sur un push sur `main` de ce dépôt : jamais sur une PR, celle d'un fork comprise
(`tests/unit/test_workflows.py`). Ses actions sont épinglées par commit. Un run rouge est annoncé dans
`#ci` (`notify.yml`).

**Quand : à chaque push sur `main`, pas à la release.** Le brouillon d'une release vise un commit
de `main` (`make release-draft`, le sha d'`origin/main`), et le CD de H0 la déploie dès que
Jonathan la publie. Publier à la release (un workflow sur l'événement `release`) laisserait H0
chercher une image qui n'existe pas encore ; publier sur la PR de version seule manquerait un
brouillon posé sur un commit plus récent. Le dépôt fusionne en squash : chaque commit de `main` est la tête
d'un push, et l'image de n'importe quelle release
existe déjà, attestée, quand elle est publiée : le job `publish (glorfindel)` est un check du commit,
que le CD attend comme la CI principale (absent une heure : refus). Le coût : deux constructions de
plus par fusion (le cache de `images.yml` est relu, la couche des dépendances reste), le stockage
public de GHCR est gratuit.

**Le digest, retrouvé sans faire confiance au tag.** Le tag `sha-<commit>` peut être déplacé par
quiconque peut écrire le paquet : il n'est qu'une indication. Le lecteur (`published_image.py`) :
- lit le manifeste du tag sur l'API du registre, **sans jeton** (le jeton anonyme de GHCR, pour un
  paquet public), et prend pour digest le sha256 des octets lus (l'en-tête du registre doit dire le
  même) ;
- exige de cosign (v3.1.3, son sha256 épinglé, vérifié avant chaque usage, borné à 3 min) la
  **signature** (de type `cosign/sign/v1` : cosign v3 prend aussi une attestation pour une signature,
  mesuré le 29/10) et la **provenance** de ce digest, chacune par un certificat dont l'identité est le workflow de
  publication de ce dépôt, sur `refs/heads/main`, déclenché par un push, **à ce commit**
  (`--certificate-identity`, `--certificate-oidc-issuer`, `--certificate-github-workflow-repository`,
  `-ref`, `-trigger`, `-sha`) ;
- relit la provenance vérifiée : son sujet est cette image et ce digest, son workflow, son dépôt,
  sa référence, son événement, son commit source sont ceux demandés, sur un runner de GitHub ;
- tire l'image **par son digest** (docker vérifie les octets), l'étiquette sous son nom local, et
  lit ses étiquettes : le commit, et la version.

Une image non signée, signée par un autre workflow, un autre dépôt, une autre branche ou pour un
autre commit, sans provenance, ou dont la provenance dit autre chose : refusée. Un paquet privé ou
absent aussi : GHCR refuse alors le jeton anonyme lui-même (403, mesuré par la relecture). Ce que dit
cosign est classé : une signature ou une attestation absente ou contraire (« no signatures found »,
« no matching … », « failed to verify certificate identity », « expected … ») est un refus ; le reste
— le réseau, le miroir TUF de sigstore, un délai — ne prouve rien : le CD attend, une heure au plus
(12 passages), puis refuse en le disant. `docker pull` et cosign sont bornés à 10 min. Mesuré le 29/10 avec
cosign v3.1.3, sans aucun jeton, sur des images publiques de GHCR : une provenance
d'`actions/attest-build-provenance` vérifiée avec ces six options, un autre commit et un autre
workflow refusés (« expected GithubWorkflowSHA… », « expected SAN value… »). La vérification ne
contacte que le registre (`ghcr.io`, ses blobs sur `pkg-containers.githubusercontent.com`) et la
racine de confiance de sigstore (`tuf-repo-cdn.sigstore.dev`), **à chaque vérification** : cosign
met à jour sa racine depuis ce miroir et sort en erreur s'il ne le joint pas, même avec
`~/.sigstore/root` rempli (mesuré par la relecture) ; le journal de transparence, lui, est vérifié
hors ligne, dans le paquet de la signature.

**Vérifier à la main** (sur un poste, sans jeton) :

```bash
python3 scripts/published_image.py install-cosign              # ~/.eregion/cosign/cosign-v3.1.3, sha256 vérifié
python3 scripts/published_image.py verify glorfindel --commit "$(git rev-parse v0.4.6^{commit})"
# → ✓ ghcr.io/vanyar53/eregion-glorfindel@sha256:… : signée et attestée par .github/workflows/publish.yml sur main, au commit …
gh attestation verify oci://ghcr.io/vanyar53/eregion-glorfindel@sha256:<digest> --repo Vanyar53/eregion \
  --signer-workflow Vanyar53/eregion/.github/workflows/publish.yml   # gh ≥ 2.49, connecté (non mesuré ici : le gh du poste, 2.45, n'a pas `attestation`)
gh attestation verify oci://ghcr.io/vanyar53/eregion-glorfindel@sha256:<digest> --repo Vanyar53/eregion \
  --predicate-type https://spdx.dev/Document/v2.3                    # le SBOM
```

**H0** tire l'image de chaque release par son digest et la vérifie avant de la préflighter : son CD
ne construit plus (`infra/glorfindel-host/README.md`, « Le CD de H0 »). **Orodruin** reçoit l'image
d'Annatar publiée, vérifiée sur le poste : `make orodruin-push [REF=<tag|commit>]` (sans `REF`, le
dernier tag `v*` : tant qu'il est d'avant CI3, il n'a pas d'image, donner `REF=`), sa sortie restant fermée (`docs/design/orodruin-contract.md`, « L'image des
injecteurs »). `make orodruin-push-dev` garde l'ancien chemin, l'image construite sur le poste,
**non vérifiée**, pour essayer une branche : `~/.eregion-image` sur Orodruin le dit (`dev <commit>`).

**L'image publique** : le dépôt l'est, l'image n'a aucun secret (elle n'a que le code et ses
dépendances verrouillées ; les secrets sont dans `host.env` et `orodruin.env`, montés ou passés au
démarrage). La rendre publique ne montre rien de plus que le dépôt et ses verrous ; elle permet à
H0 et à n'importe qui de la tirer et de la vérifier sans jeton. Un paquet neuf de GHCR est privé par
défaut (à vérifier au premier run) : Jonathan le passe en public une fois, dans les réglages de
chaque paquet (« Change visibility »).

Tests : `tests/unit/test_published_image.py` (un faux registre, un faux cosign qui répond comme
cosign v3.1.3, un faux docker), `tests/unit/test_host_cd.py` (le CD de bout en bout),
`tests/unit/test_workflows.py`. Mutants M1650–M1669.

### Les avis de vulnérabilité des verrous (CI2)

CI2 (#268) surveille les trois verrous. Les constats du contre-audit étaient P-03 (aucun scanner) et N-16 (un
rafraîchissement du verrou sans contrôle).

- **Le workflow** `.github/workflows/pip-audit.yml` tourne chaque mardi et à la demande
  (`workflow_dispatch`). Il passe `pip-audit` sur `requirements/dev.txt`, `glorfindel.txt` et
  `annatar.txt`, et sur `audit.txt`, le verrou de pip-audit lui-même : il tourne dans un job qui
  écrit des issues. Chaque verrou est lu tel quel : `--require-hashes --disable-pip`. Rien n'est
  résolu : les versions sont celles du verrou, et seul le service des avis (pypi.org) est
  interrogé. Les marqueurs sont évalués pour le Python du runner, épinglé (`ubuntu-24.04` :
  Python 3.12, Linux, celui de l'image) pour que ce qui est lu ne dérive pas sans bruit. Une
  broche propre à 3.11 (numpy) n'est donc pas lue (#298).
- **pip-audit a son propre verrou**, `requirements/audit.txt` (issu de `requirements/audit.in`,
  version épinglée), avec empreintes. Il s'installe dans un venv à part, jamais dans l'image ni
  dans `dev.txt`. Le workflow utilise le Python du runner, sans action tierce. Son seul secret est
  le jeton du dépôt, avec les droits `contents: read` et `issues: write`.
- **Une issue par avis**, label `security` (`scripts/pip_audit_issues.py`). Elle donne le paquet,
  la version de chaque verrou touché, les versions corrigées, et les identifiants (GHSA, CVE,
  PYSEC) avec leurs liens.
  - **Le même avis ne donne jamais deux issues.** Le corps de l'issue garde une clé : le paquet,
    tous les identifiants vus, les verrous. Une issue ouverte par le workflow
    (`github-actions[bot]`) dont la clé nomme le paquet et partage un identifiant est celle de
    cet avis, ouverte ou fermée, quels que soient son titre et ses labels. Toutes les pages sont
    lues ; une PR ne compte pas. Les doublons de pip-audit et un même avis dans plusieurs verrous
    sont fusionnés.
  - **Seules les issues du workflow sont lues.** N'importe qui peut ouvrir une issue qui porte
    une clé. Celle d'un autre auteur ne fait taire aucun avis et n'est jamais modifiée ; ses
    identifiants n'entrent jamais dans une issue du bot. Une clé relue est vérifiée champ par
    champ (paquet, identifiants, verrous) : une clé dont un champ n'a pas sa forme est ignorée.
  - **Une issue ouverte** est réécrite quand ce qu'elle dit change : un verrou, une version, un
    correctif, un alias.
  - **Une issue fermée comme faite** alors que l'avis est toujours là est rouverte, avec un
    commentaire. Une issue fermée comme « non prévue », ou comme doublon, est une décision
    humaine : elle est laissée.
  - **Un avis qui n'est plus trouvé** reçoit un seul commentaire (« la montée est faite ? »). Le
    workflow ne ferme jamais l'issue : un humain la ferme. Cela ne vaut que si tous les verrous de
    l'issue ont été lus ce passage-là. Un audit en échec ne dit rien d'un avis.
  - Le texte venu du dehors (identifiants, nom, version) est vérifié sur sa forme. La description
    d'un avis n'est jamais écrite.
- **Jamais une PR de montée.** La montée passe par la procédure plus haut : `make lock`, une PR,
  puis le harnais (`make llm-compare … ATTEST=1`, Jonathan). Une montée de LiteLLM est le lot
  DEP1 (#282).
- **Le run est rouge** quand un humain a du neuf à voir : une issue ouverte ou rouverte, ou un avis
  revenu. Il l'est aussi quand un audit a échoué. `notify.yml` annonce ce run rouge dans `#ci`, avec
  une mention, parce qu'une issue ouverte par le jeton du workflow ne déclenche aucun workflow.
  Une erreur de GitHub sur un avis ou une issue n'arrête pas les autres : le run se finit, dit
  chaque erreur, et sort en 2. Dans les autres cas, le run est vert.
- **`make lock` dit les avis du verrou qu'il vient d'écrire** (`make audit`, N-16), sans jamais
  échouer : c'est une information pour la PR de montée. `make audit` seul fait la même chose à
  tout moment. La première fois, il crée `.venv-audit/` depuis `requirements/audit.txt`.

```bash
make audit                              # les avis connus des verrous, celui de pip-audit compris (lecture seule)
```

**Les alertes Dependabot** de GitHub, sans les PR automatiques, sont une décision de Jonathan. Au
29/10, elles ne sont pas activées. Pour les activer :
`gh api -X PUT repos/Vanyar53/eregion/vulnerability-alerts`. Les PR automatiques (« Dependabot
security updates », `automated-security-fixes`) restent désactivées : on ne les active pas.

---

## Packaging et version

```
name = "eregion", version dans pyproject.toml, Apache 2.0
entrypoints : annatar, glorfindel, gothmog, eregion (la console)
installation : depuis le dépôt (make install, ou pip install -e '.[console]')
```

**Une seule source de version** : `pyproject.toml`. `annatar.__version__` la lit (REL1) — le
`pyproject.toml` de l'arbre d'abord (une installation éditable garde la version de son installation :
mesuré le 29/10, un `.venv` installé à 0.3.0 la disait encore), sinon les métadonnées du paquet
installé, sinon `0+unknown`. `glorfindel --version` et la console lisent les métadonnées.

**Une release en deux commandes** (REL1, `scripts/release.py`, bibliothèque standard) :

```bash
make release VERSION=0.4.4 TITLE="…" DRY_RUN=1   # à blanc : les vérifications, la coupe, les commandes
make release VERSION=0.4.4 TITLE="…"             # la PR de version
make release-draft VERSION=0.4.4 [NOTES=notes.md] [DRY_RUN=1]   # après sa fusion : le brouillon
```

- **`make release`**, depuis `origin/main` à jour (`git switch --detach origin/main`), l'arbre propre.
  `[Unreleased]` devient `[X.Y.Z] — <date> — "<titre>"`, un `[Unreleased]` vide au-dessus. La version de
  `pyproject.toml` et la ligne « **Status — vX.Y.Z.** » du README suivent : `tests/unit/test_readme.py`
  échoue sinon (SEC6). Puis la branche `chore/release-X.Y.Z`, le commit
  `chore(release): X.Y.Z — CHANGELOG [X.Y.Z] « <titre> », version du paquet`, le push et la PR
  (`gh pr create`). Refusé, sans rien écrire :
  - un arbre modifié, ou un HEAD qui n'est pas `origin/main` ;
  - une version qui n'est pas X.Y.Z, ou pas plus grande que la courante ;
  - un `[Unreleased]` vide ou qui n'a que des titres, ou une section `[X.Y.Z]` déjà là ;
  - la branche ou le tag `vX.Y.Z` qui existe déjà ;
  - un titre vide, sur deux lignes, ou avec un guillemet droit.

  **Un échec en route n'est pas un refus.** Si le commit, le push ou la PR échoue après la création de la
  branche, la commande s'arrête en code 2. Elle dit ce qui reste, comment reprendre
  (`gh pr create --base main --head chore/release-X.Y.Z`…) et comment revenir en arrière :
  `git reset -q --hard && git checkout -q - && git branch -D chore/release-X.Y.Z`, plus
  `&& git push origin --delete chore/release-X.Y.Z` si la branche a été poussée. `reset --hard` retire
  aussi ce qui était déjà indexé ; `checkout -` ramène à un HEAD détaché (le départ conseillé, où
  `switch -` échoue). Les tests exécutent ce retour depuis un départ détaché : arbre propre, HEAD sur
  `origin/main`, la branche partie en local et sur l'origine.
- **`make release-draft`**, après la fusion : le **brouillon** `vX.Y.Z — <titre>`, sur le sha complet
  d'`origin/main`. Celui-ci doit tenir la version : son `pyproject.toml` et la section `[X.Y.Z]` de son
  CHANGELOG. Les notes : `NOTES=fichier`, sinon cette section, avec au moins une ligne qui n'est pas un
  titre. Refusé si le tag ou une release `vX.Y.Z` existe déjà, brouillon compris. Le brouillon est posé sur le tableau de `#agents`, avec un ping,
  et sa carte va dans `#releases`, avec le résumé de ses notes (REL2) ; le lien donné est la liste des
  releases du dépôt, où le brouillon est en tête : GitHub change l'URL d'un brouillon à chaque
  édition (mesuré sur la 0.4.4). La PR de version et la publication vont aussi dans `#releases`
  (`docs/atelier-discord.md`) ; sans configuration Discord, rien n'est envoyé et la commande réussit.
- **L'image de la release** (CI3) : le commit que vise le brouillon a déjà ses deux images publiées,
  attestées et signées (`publish.yml` tourne sur la tête de chaque push sur `main`, « Les images publiées »).
  Avant de cliquer « Publish », les checks `publish (glorfindel)` et `publish (annatar)` de ce commit
  doivent être verts : sinon le CD de H0 attend une heure, puis refuse la release, sans jamais la
  construire.
- **Aucun chemin ne publie** : rien ne fait d'un brouillon une release. `tests/unit/test_release.py`
  lit le code sur une liste blanche : quatre commandes `gh` seulement (`pr create`, `release list`,
  `release create` avec `--draft`, `release edit` des seules notes), jamais `gh api`. Une commande ne
  part que par `run()`, avec une liste littérale qui commence par `git` ou `gh` ; ni shell, ni
  `os.system`. Aucun texte ne dit
  `draft`, sauf ce `--draft`. Une URL de `releases` n'est jamais appelée qu'en lecture. Publier déploie H0 (son CD, H1) : **Jonathan publie**, sur GitHub.
- `DRY_RUN=1` : tout est montré, rien n'est écrit, poussé, créé ni envoyé.
- `VERSION`, `TITLE` et `NOTES` se donnent sur la ligne de commande. Venus de l'environnement, ils sont
  refusés, comme `REF` : le script les lit dans son environnement, make ne les développe pas.

Tests : `tests/unit/test_release.py`, sur un dépôt git jetable (un `origin` nu dans `tmp_path`) avec un
faux `gh` et le faux Discord. Mutants M1160–M1169, M1430–M1439, M1470.

---

## Les journaux d'activité et d'Entra ID au banc (ID1, #281)

AL1 (le journal d'activité) et C2 (Entra ID) sont livrés en détection seule, mais **aveugles** : leurs
tables (`AzureActivity`, `AuditLogs`, `AADServicePrincipalSignInLogs`) n'arrivent dans le workspace
du banc (`law-celebrimbor-amonsul`) que par deux paramètres de diagnostic qui ne vivent pas dans le
groupe du banc — l'un sur l'**abonnement** (`infra/terraform/activity_log.tf`), l'autre sur le
**tenant** Entra ID (`infra/terraform/entra_logs.tf`). Le Terraform est prêt, désactivé. Ce qui suit
se fait avec Jonathan : rien ici n'a été planifié ni appliqué. Les noms sont ceux du banc ; `<…>` est
à remplacer, rien de réel dans ce dépôt.

### Ce que le Terraform pose, et sous quelle variable

| Variable (`terraform.tfvars`) | Ressource | Catégories | Tables (lues par) |
|---|---|---|---|
| `activity_log_enabled = true` | `azurerm_monitor_diagnostic_setting.activity_log` (`diag-celebrimbor-activity`), sur l'abonnement du provider | `Administrative` | `AzureActivity` (les 3 règles d'AL1) |
| `entra_logs_enabled = true` | `azurerm_monitor_aad_diagnostic_setting.entra` (`diag-celebrimbor-entra`), sur le tenant du provider | `AuditLogs`, `ServicePrincipalSignInLogs` | `AuditLogs` (3 règles de C2), `AADServicePrincipalSignInLogs` (`entra-sp-unusual-signin`) |

- **Désactivées par défaut**, dans `terraform.tfvars` (ignoré par git) : jamais dans `config.yaml`
  (suivi, public — un fork qui applique enverrait les journaux de son tenant), jamais en `-var` d'une
  commande (le prochain apply sans lui retirerait le paramètre).
- **Instance canonique seule** (workspace Terraform `default`) : une autre instance ne les pose pas,
  et le plan le dit (`check "diagnostic_settings_on_the_canonical_instance"`).
- **Rien d'autre** : `Security` (Defender for Cloud), `SignInLogs`, `NonInteractiveUserSignInLogs`,
  `ManagedIdentitySignInLogs` ne sont lues par aucune règle. `tests/unit/test_bench_logs.py` vérifie
  que les catégories envoyées sont exactement celles que lisent les règles livrées ; un lot qui lira
  une autre table ajoutera sa catégorie avec sa règle.
- Le contrat planifié contre un faux azurerm, sans Azure : `terraform -chdir=infra/terraform test`
  (`infra/terraform/tests/diagnostic_settings.tftest.hcl`, après un `init -backend=false`).

### Les droits

| Paramètre | Qui l'applique | Droit | Source |
|---|---|---|---|
| Abonnement | l'opérateur sous `az login` (le Makefile ne passe que `ARM_SUBSCRIPTION_ID` : azurerm prend la CLI) | **Monitoring Contributor** sur l'abonnement (ou un rôle qui le contient) : `Microsoft.Insights/DiagnosticSettings/*`, et `Microsoft.OperationalInsights/workspaces/sharedKeys/action` pour le workspace | [Monitoring Contributor](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/monitor), [rôles d'Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/roles-permissions-security) |
| Tenant | l'opérateur sous `az login`, **rôle d'Entra actif** | **Administrateur de la sécurité** (« the least privileged role required to configure diagnostic settings »), ou Administrateur général — un rôle d'Entra, pas un rôle Azure sur l'abonnement. Un principal de service demanderait `Contributor` à la portée `/providers/Microsoft.aadiam`, attribué par un administrateur à l'accès élevé à la racine : ne pas le faire, appliquer sous `az login` | [Entra : accès aux journaux](https://learn.microsoft.com/entra/identity/monitoring-health/howto-access-activity-logs), [paramètres de diagnostic d'Entra](https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings), documentation du provider azurerm (`monitor_aad_diagnostic_setting`) |
| Lecture (Glorfindel, H0 compris) | — | rien de plus : `Log Analytics Reader` sur le workspace ; aucun droit sur Entra ID | |

Licence : la page des licences d'Entra donne « Audit logs : Yes » et « Sign-in logs : Yes » pour
Entra ID **Free** ([licences](https://learn.microsoft.com/entra/fundamentals/licensing), « Microsoft
Entra monitoring and health ») ; ce qu'exige l'**envoi** des connexions des principaux de service vers
un workspace n'y est pas dit. La doc d'AL1 et de C2 supposait P1 ou P2 : hypothèse E2, tranchée par
l'apply.

### Le coût

| Table | Prix | Volume attendu sur le banc | Par mois |
|---|---|---|---|
| `AzureActivity` | **gratuite** : « There are no data ingestion charges for activity logs » ([journal d'activité](https://learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log)) ; table exclue de la facturation ([coût des journaux](https://learn.microsoft.com/azure/azure-monitor/logs/cost-logs), `_IsBillable` faux) | quelques centaines d'opérations par jour | 0 |
| `AuditLogs` | Analytics Logs : **2,99 USD le Go** en West Europe (2,63 EUR), au-delà des 5 premiers Go du mois par compte de facturation | ~2 Ko par événement ; 50 à 500 événements par jour sur un tenant de banc → 0,1 à 1 Mo/jour | < 0,10 USD |
| `AADServicePrincipalSignInLogs` | idem | ~11,5 Ko par connexion ; 100 à 1 000 connexions de principaux par jour (console, bot, watch locale, Annatar, CI ; un jeton vit environ une heure) → 1 à 12 Mo/jour | < 1 USD |
| Rétention | 31 jours inclus ; au-delà 0,13 USD le Go par mois (West Europe) | le workspace garde 30 jours (`log_retention_days`) | 0 |

Sources : l'API publique des prix d'Azure, lue le 30/10/2026
(`https://prices.azure.com/api/retail/prices`, `serviceName eq 'Log Analytics'`, `westeurope` :
« Analytics Logs Data Ingestion » 2,99 USD au-delà de 5 Go, « Analytics Logs Data Retention » 0,13
USD le Go par mois ; francecentral 2,76 et 0,12) ; la [page des prix d'Azure
Monitor](https://azure.microsoft.com/pricing/details/monitor/) (« The first 5 GB/month per billing
account in this tier are free », « 31 days – data ingested into Analytics Logs ») ; les tailles par
événement : [Entra, options d'intégration](https://learn.microsoft.com/entra/identity/monitoring-health/concept-log-monitoring-integration-options-considerations)
(« Audit log events use around 2 KB », « Sign-in log events use on average 11.5 KB »). Les volumes
du banc sont une **estimation** : la mesure (requête `Usage`, ci-dessous) la remplace après 24 h,
puis 7 jours. Total attendu : moins de 2 USD par mois.

### Avant le plan (lecture seule, par Jonathan)

```bash
az account show --query "{tenant:tenantId, user:user.name, type:user.type}" -o table   # le tenant et l'identité que prendra Terraform
env | grep '^ARM_CLIENT' || echo "pas de principal : azurerm prendra az login"        # rien attendu
az monitor diagnostic-settings subscription list -o table                              # ≤ 4 déjà ; aucun n'envoie Administrative à law-celebrimbor-amonsul
az rest --method GET --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" \
  --query "value[].{name:name, ws:properties.workspaceId}" -o table                    # les paramètres du tenant déjà là
```

À trancher **avant** l'apply d'Entra : le paramètre envoie les journaux de **tout le tenant** de
l'abonnement du banc (celui du provider), pas seulement ceux du banc. Un tenant de test dédié
demanderait un banc dans ce tenant ; s'il n'y en a pas, c'est le tenant de l'abonnement, ou rien.

### Activer, vérifier le plan, appliquer

```bash
# 1. Dans infra/terraform/terraform.tfvars (persistant, ignoré par git) — l'un, l'autre, ou les deux :
#      activity_log_enabled = true
#      entra_logs_enabled   = true
make celebrimbor-logs-plan          # plan ciblé : ces deux paramètres seuls (lecture seule)
make celebrimbor-logs-up YES=1      # une fois le plan relu
```

`celebrimbor-logs-plan` / `-up` planifient et appliquent avec `-target` sur les deux paramètres, rien
d'autre du banc : une dérive en attente sur le baseline n'y passe pas. Instance `default` seulement :
une autre est refusée avant tout appel. **Le plan doit montrer**, et rien d'autre :
- `data.azurerm_subscription.current[0]` lu (journal d'activité seulement) ;
- `+ azurerm_monitor_diagnostic_setting.activity_log[0]` : `name = "diag-celebrimbor-activity"`,
  `target_resource_id = "/subscriptions/<…>"`, `log_analytics_workspace_id` qui finit par
  `/workspaces/law-celebrimbor-amonsul`, un seul `enabled_log { category = "Administrative" }` ;
- `+ azurerm_monitor_aad_diagnostic_setting.entra[0]` : `name = "diag-celebrimbor-entra"`, le même
  workspace, deux `enabled_log` : `AuditLogs`, `ServicePrincipalSignInLogs` ;
- `Plan: 1 to add` (ou 2), `0 to change, 0 to destroy`, et l'avertissement de Terraform sur le
  ciblage (« Resource targeting is in effect ») — attendu.

Un changement sur `azurerm_log_analytics_workspace.celebrimbor` ou sur le groupe (leurs dépendances,
une dérive de tags en attente) : **s'arrêter**, et le traiter à part par `make celebrimbor-plan`.

**Revenir en arrière** : la variable à `false` (ou la ligne retirée), puis `make
celebrimbor-logs-plan` — il doit montrer `1 to destroy` (ou 2) sur ces ressources seules — et `make
celebrimbor-logs-up YES=1`. Les lignes déjà ingérées restent jusqu'à la fin de la rétention (30
jours). `make celebrimbor-down CONFIRM=default` les retire aussi, avec le reste.

**Les premières lignes** : « within 90 minutes » après la création d'un paramètre (Azure Monitor,
[paramètres de diagnostic](https://learn.microsoft.com/azure/azure-monitor/data-collection/diagnostic-settings)) ;
pour Entra, « up to three days for the logs to start appearing » ([Entra](https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings)).
Attendre `AzureActivity | take 1` et `AuditLogs | take 1` non vides avant les opérations de test.

**Ce que H0 verra aussitôt** : la watch hébergée lit ce workspace ; chaque vraie opération du banc
devient une carte `control_plane_change` (un apply Terraform qui écrit le NSG, une attribution de
rôle, une sauvegarde si l'hypothèse A2 se vérifie) et chaque événement d'Entra retenu une carte
`identity_change` — jamais une action (détection seule, deux verrous). Une fois Entra activé, chaque
carte `identity_change` sur une action d'administration de **tout le tenant** part dans Discord,
avec l'UPN de l'acteur. Le paramètre lui-même
(`Microsoft.Insights/diagnosticSettings/write`) n'est lu par aucune règle ; le prochain
`celebrimbor-up` qui réécrit le NSG du banc, si.

### Les opérations de test

Chacune est connue, réversible, et défaite aussitôt. Noter l'heure UTC juste avant chacune
(`date -u +%FT%TZ`) : c'est le T0 de la latence de bout en bout.

**Droits des opérations de test — à vérifier avant de commencer**, pour ne pas s'arrêter au milieu
avec une application et un identifiant déjà créés :
- **C2** : Administrateur général actif ; ou bien Administrateur d'application cloud pour le
  consentement (`az ad app permission admin-consent` : « You must login as a global
  administrator » dans l'aide d'`az`, un rôle d'administration des applications suffit au
  portail) et Administrateur de rôle privilégié pour attribuer Security Reader ; plus le droit
  d'enregistrer une application (les utilisateurs du tenant l'ont par défaut ; sinon Développeur
  d'applications).
- **AL1** : `Contributor` sur `rg-celebrimbor` suffit pour la règle de NSG, l'instantané et la
  sauvegarde ; l'attribution de `Reader` demande User Access Administrator ou Owner sur ce groupe.

**C2 — Entra ID, d'abord** (dans le tenant tranché ; l'application de test sert aussi à AL1) :

```bash
APP=$(az ad app create --display-name eregion-id1-test --query appId -o tsv)          # « Add application »
APPOBJ=$(az ad app show --id "$APP" --query id -o tsv)                                 # pour le retrait définitif
SP=$(az ad sp create --id "$APP" --query id -o tsv)                                    # « Add service principal »
# entra-credential-added (T1098.001) : un certificat ajouté, valable 7 jours, sa clé gardée hors du dépôt en 0600.
# Un certificat plutôt qu'un secret : la connexion ci-dessous ne met que le chemin du fichier dans la ligne de
# commande, jamais la clé (un secret passé à `az login -p` serait visible par `ps`, az ne le lit pas d'un fichier).
PEM=$(az ad app credential reset --id "$APP" --append --create-cert --display-name id1 \
  --end-date "$(date -u -d '+7 days' +%Y-%m-%d)" --query fileWithCertAndPrivateKey -o tsv)
mv "$PEM" ~/.eregion-id1.pem && chmod 600 ~/.eregion-id1.pem
# entra-app-consent (T1528) : User.Read de Microsoft Graph (identifiants publics de Graph), puis le consentement d'administrateur
az ad app permission add --id "$APP" --api 00000003-0000-0000-c000-000000000000 --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope
az ad app permission admin-consent --id "$APP"
# entra-privileged-role-assigned (T1098.003) : Security Reader (un rôle qu'Entra marque privilégié, en lecture) au principal de test
RID=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\$filter=displayName eq 'Security Reader'" --query "value[0].id" -o tsv)
ASSIGN=$(az rest --method POST --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments \
  --body "{\"principalId\":\"$SP\",\"roleDefinitionId\":\"$RID\",\"directoryScopeId\":\"/\"}" --query id -o tsv)
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$ASSIGN"
# entra-sp-unusual-signin (T1078.004) : une connexion du principal, dans une config az jetable (ton az login n'est pas touché).
# Selon la version d'az : --certificate <fichier> (récente) ou -p <fichier> (ancienne) — le chemin, pas la clé.
AZURE_CONFIG_DIR=$(mktemp -d) sh -c 'az login --service-principal -u "$0" --certificate ~/.eregion-id1.pem --tenant <tenant> --allow-no-subscriptions -o none; rm -rf "$AZURE_CONFIG_DIR"' "$APP"
```

`entra-sp-unusual-signin` ne voit qu'un principal **qui a un historique** (vu au moins 3 jours de sa
base de 14 jours, la dernière heure exclue) : la connexion ci-dessus, une fois par jour depuis le poste
pendant au moins 3 jours, puis une fois depuis une autre adresse (Cloud Shell, le fichier `.pem` copié
le temps de la connexion, puis `rm ~/.eregion-id1.pem` dans Cloud Shell : son `$HOME` persiste sur
Azure Files) — c'est celle-là qui fait la carte. Le certificat expire au bout de 7 jours ;
pour une base plus longue, en ajouter un autre (une carte `entra-credential-added` de plus, attendue).

**AL1 — le journal d'activité** (sur le groupe du banc) :

```bash
# nsg-change-outside-glorfindel (T1562.007) : une règle de refus inoffensive, puis retirée → 2 opérations
az network nsg rule create -g rg-celebrimbor --nsg-name nsg-celebrimbor -n id1-test-deny --priority 4000 \
  --direction Inbound --access Deny --protocol Tcp --source-address-prefixes 203.0.113.0/24 --destination-port-ranges 9
az network nsg rule delete -g rg-celebrimbor --nsg-name nsg-celebrimbor -n id1-test-deny

# role-assignment-write (T1098.003) : Reader sur le groupe du banc au principal de test d'Entra ($APP, ci-dessus)
RG_ID=$(az group show -n rg-celebrimbor --query id -o tsv)
az role assignment create --assignee "$APP" --role Reader --scope "$RG_ID"
az role assignment delete --assignee "$APP" --role Reader --scope "$RG_ID"

# snapshot-by-unexpected-caller (T1578.001) : un instantané du disque de données de gondolin, un accès de téléchargement
DISK=$(az disk show -g rg-celebrimbor -n disk-celebrimbor-gondolin-data --query id -o tsv)
az snapshot create -g rg-celebrimbor -n snap-id1-test --source "$DISK" --incremental true -o none
az snapshot grant-access -g rg-celebrimbor -n snap-id1-test --duration-in-seconds 600 -o none   # l'URL SAS n'est pas affichée
az snapshot revoke-access -g rg-celebrimbor -n snap-id1-test
az snapshot delete -g rg-celebrimbor -n snap-id1-test

# Hypothèse A2 : une sauvegarde Azure Backup à la demande de gondolin (ce que fait l'action `snapshot` de Glorfindel)
az backup item list -g rg-celebrimbor -v rsv-celebrimbor-erebor --backup-management-type AzureIaasVM -o table
az backup protection backup-now -g rg-celebrimbor -v rsv-celebrimbor-erebor --backup-management-type AzureIaasVM \
  -c <conteneur de la liste> -i <élément de la liste> --retain-until <jj-mm-aaaa, dans 2 jours>
```

L'attribution de rôle et la règle de NSG n'ont pas besoin de Glorfindel. La règle `id1-test-deny`
n'est pas dans le Terraform du banc : retirée aussitôt (sinon le prochain `celebrimbor-up` la
retirerait). Facultatif, avec Jonathan, coûteux : un `glorfindel restore` de gondolin (hypothèse A3,
~20 min, la VM désallouée) ; une isolation puis une levée de gondolin par une watch locale (hypothèse
A4) — jamais par H0, qui est en lecture seule.

**Le retrait — un seul bloc**, à la fin des mesures, **ou dès un abandon en cours de route** (chaque
ligne tolère ce qui n'a pas encore été créé ; dans un nouveau shell, `APP` est retrouvée par son nom
exact ; dans Cloud Shell, s'il a servi, `rm ~/.eregion-id1.pem` aussi) :

```bash
# Ce qui ne dépend pas de l'application : le snapshot (l'accès SAS révoqué d'abord), la règle de NSG
az snapshot revoke-access -g rg-celebrimbor -n snap-id1-test 2>/dev/null
az snapshot delete -g rg-celebrimbor -n snap-id1-test 2>/dev/null
az network nsg rule delete -g rg-celebrimbor --nsg-name nsg-celebrimbor -n id1-test-deny 2>/dev/null
# L'application, retrouvée par son nom exact (--display-name filtre par « commence par »)
APP=${APP:-$(az ad app list --filter "displayName eq 'eregion-id1-test'" --query "[0].appId" -o tsv)}
if [ -n "$APP" ]; then
  APPOBJ=${APPOBJ:-$(az ad app show --id "$APP" --query id -o tsv)}
  SP=${SP:-$(az ad sp show --id "$APP" --query id -o tsv 2>/dev/null)}
  az role assignment delete --assignee "$APP" --scope "$(az group show -n rg-celebrimbor --query id -o tsv)" 2>/dev/null
  # Security Reader (ou tout rôle d'annuaire) encore attribué au principal : retiré explicitement
  if [ -n "$SP" ]; then
    for a in $(az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$SP'" --query "value[].id" -o tsv); do
      az rest --method DELETE --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$a"
    done
  fi
  for k in $(az ad app credential list --id "$APP" --cert --query "[].keyId" -o tsv); do
    az ad app credential delete --id "$APP" --key-id "$k" --cert
  done
  for k in $(az ad app credential list --id "$APP" --query "[].keyId" -o tsv); do
    az ad app credential delete --id "$APP" --key-id "$k"
  done
  az ad app delete --id "$APP"                       # l'application et son principal
  # Retrait définitif de l'application et du principal : sinon restaurables 30 jours, avec leurs identifiants.
  [ -n "$APPOBJ" ] && az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$APPOBJ"
  [ -n "$SP" ] && az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$SP" 2>/dev/null
fi
rm -f ~/.eregion-id1.pem
```

### Les requêtes de mesure

Dans le workspace du banc (portail : Logs), ou depuis le poste :
`az monitor log-analytics query -w <customerId de law-celebrimbor-amonsul> --analytics-query "<requête>" --timespan P1D -o table`
(une extension d'`az`, installée au premier appel). Le `--timespan` borne ce que la requête peut lire :
il doit couvrir son `ago(…)` le plus long — `P1D` pour les requêtes sur un jour, `P7D` pour le coût
sur une semaine, `P15D` pour les règles (la base de connexions remonte à 14 jours).

**Chaque règle voit son opération** — la requête de la règle, **telle qu'écrite** :

```bash
rule() { python -c "import sys,yaml; print(next(r['query'] for r in yaml.safe_load(open('glorfindel/rules/azure/detection_rules.yaml'))['rules'] if r['name']==sys.argv[1]))" "$1"; }
for r in nsg-change-outside-glorfindel role-assignment-write snapshot-by-unexpected-caller \
         entra-credential-added entra-app-consent entra-privileged-role-assigned entra-sp-unusual-signin; do
  # P15D : la base d'entra-sp-unusual-signin lit ago(14d) .. ago(1h) ; chaque règle borne elle-même sa fenêtre
  echo "== $r"; az monitor log-analytics query -w <customerId> --analytics-query "$(rule $r)" --timespan P15D -o table
done
```

Attendu : au moins une ligne par opération de test (`entra-sp-unusual-signin` après les 3 jours de
base), et sur H0 la carte correspondante (`control_plane_change`, `identity_change`) ;
`glorfindel rules check --live` sur H0 dit `ok` pour les sept.

**La latence, de l'événement à l'ingestion** (le T0 noté donne le bout en bout ; la carte de H0
ajoute l'intervalle de la règle, 60 s pour AL1, 120 à 300 s pour C2 ; `--timespan P1D`) :

```kusto
AzureActivity
| where TimeGenerated > ago(6h)
| where OperationNameValue has_any ("SECURITYRULES", "ROLEASSIGNMENTS", "SNAPSHOTS", "BEGINGETACCESS")
| extend Ingested = ingestion_time(), Delay_s = datetime_diff('second', ingestion_time(), TimeGenerated)
| project TimeGenerated, Ingested, Delay_s, OperationNameValue, ActivityStatusValue, CorrelationId
| order by TimeGenerated asc
```

```kusto
union withsource=Table AuditLogs, AADServicePrincipalSignInLogs
| where TimeGenerated > ago(6h)
| where tostring(TargetResources) has "eregion-id1-test" or tostring(InitiatedBy) has "eregion-id1-test"
     or ServicePrincipalName == "eregion-id1-test"
| extend Delay_s = datetime_diff('second', ingestion_time(), TimeGenerated)
| project Table, TimeGenerated, Ingested = ingestion_time(), Delay_s, OperationName, Category, Result, IPAddress, CorrelationId
| order by TimeGenerated asc
```

Sur 24 h, toute la table (le p95 contre `expected_latency_s` des règles : 1 200 s pour AL1, 1 800 s
pour C2 ; `--timespan P1D`) :

```kusto
union withsource=Table AzureActivity, AuditLogs, AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1d)
| extend Delay_s = datetime_diff('second', ingestion_time(), TimeGenerated)
| summarize Rows = count(), p50 = percentile(Delay_s, 50), p95 = percentile(Delay_s, 95), Max = max(Delay_s) by Table
```

**Le coût** (après 24 h, `--timespan P1D` ; puis 7 jours, `ago(7d)` et `--timespan P7D` ; `Quantity` en Mo) :

```kusto
Usage
| where TimeGenerated > ago(1d)
| where DataType in ("AzureActivity", "AuditLogs", "AADServicePrincipalSignInLogs")
| summarize MB = sum(Quantity), BillableMB = sumif(Quantity, IsBillable == true) by DataType
```

**Les hypothèses** (une requête chacune, ci-dessous ; `--timespan P1D`) :

```kusto
// A2, A3 : qui fait les snapshots et les accès de téléchargement (Azure Backup, un restore) ?
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue has_any ("SNAPSHOTS", "BEGINGETACCESS", "RECOVERYSERVICES")
| extend CallerAppId = tostring(parse_json(Claims).appid)
| summarize Ops = make_set(OperationNameValue), Rows = count() by Caller, CallerAppId, ResourceProviderValue

// A5, A6 : les lignes d'une opération, et les identifiants de l'appelant tirés de Claims
AzureActivity
| where TimeGenerated > ago(6h)
| where OperationNameValue has_any ("SECURITYRULES", "ROLEASSIGNMENTS", "SNAPSHOTS")
| extend CallerAppId = tostring(parse_json(Claims).appid),
         CallerObjectId = tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"])
| summarize Lines = count(), Statuses = make_set(ActivityStatusValue), Callers = make_set(Caller),
            AppIds = make_set(CallerAppId), ObjectIds = make_set(CallerObjectId) by CorrelationId, OperationNameValue

// E4, E5, E6 : les noms d'opérations et la forme de TargetResources / modifiedProperties
AuditLogs
| where TimeGenerated > ago(6h)
| where tostring(TargetResources) has "eregion-id1-test" or tostring(TargetResources) has "Security Reader"
| mv-expand T = TargetResources
| mv-expand P = T.modifiedProperties
| project TimeGenerated, OperationName, Category, Result, TType = tostring(T.type), TName = tostring(T.displayName),
          Prop = tostring(P.displayName), Old = tostring(P.oldValue), New = tostring(P.newValue), CorrelationId
```

### Les hypothèses à trancher

Chacune avec sa mesure et ce qui change selon le résultat. Un changement de règle ou d'adaptateur
est un lot de la session Glorfindel ; ID1 ne le fait pas.

| | Hypothèse (d'où) | Mesure | Si elle tient | Sinon |
|---|---|---|---|---|
| **D1** | L'apply de l'abonnement passe sous `az login` avec Monitoring Contributor (ou plus) | l'apply | rien | le rôle manquant, sur l'abonnement, pas plus |
| **D2** | Aucun paramètre de l'abonnement n'envoie déjà `Administrative` au workspace (5 au plus par ressource) | `az monitor diagnostic-settings subscription list` | apply | des lignes en double : retirer l'autre, ou ne pas appliquer celui-ci |
| **A1** | `AzureActivity` arrive en 3 à 20 min (Microsoft Learn), sous `expected_latency_s: 1200` et la fenêtre `ago(1h)` des règles d'AL1 | latence, p95 sur 24 h | rien | p95 > 20 min : relever `expected_latency_s` ; > 45 min : élargir la fenêtre |
| **A2** | Azure Backup (la sauvegarde planifiée, et l'action `snapshot` de Glorfindel) ne produit ni `SNAPSHOTS/WRITE` ni `BEGINGETACCESS` visibles dans le journal de l'abonnement (`snapshot-by-unexpected-caller`, `docs/azure.md`) | `backup-now`, la sauvegarde de la nuit, requête A2 | rien | une carte à chaque sauvegarde : exclure l'appelant d'Azure Backup (son `CallerAppId` mesuré), dans la couche du client ou dans la règle livrée |
| **A3** | Un `glorfindel restore` ne produit pas de `BEGINGETACCESS` sous l'identité de la console (sinon : `GlorfindelIdentity`, carte critique à chaque restore) | un restore (facultatif), requête A2 | rien | déclarer l'opération du restore dans les capacités, ou l'exclure pour l'identité de la console |
| **A4** | Les écritures de Glorfindel (isolation, levée) portent son `appid`/`oid` dans `Claims` et sont écartées | une isolation par une watch locale, requête A5 | rien | comparer `Caller`, `CallerAppId`, `CallerObjectId` à `GLORFINDEL_OWN_CALLERS` ; corriger la lecture de l'identité |
| **A5** | Une opération = plusieurs lignes (`Start`, `Accept`, `Success`) d'un même `CorrelationId` : une carte | requête A5 | rien | deux cartes pour une opération : revoir la clé de déduplication |
| **A6** | `Claims` porte `appid` et `objectidentifier`, pour un utilisateur comme pour un principal | requête A5 (`AppIds`, `ObjectIds` non vides) | rien | l'identité de Glorfindel n'est lue que par `Caller` : le dire dans l'adaptateur |
| **E1** | L'apply du tenant passe sous `az login` avec Administrateur de la sécurité actif, sans rôle Azure à `/providers/Microsoft.aadiam` | l'apply | rien | poser le paramètre au portail (mêmes nom et catégories), puis `terraform import 'azurerm_monitor_aad_diagnostic_setting.entra[0]' /providers/Microsoft.AADIAM/diagnosticSettings/diag-celebrimbor-entra` |
| **E2** | `ServicePrincipalSignInLogs` s'envoie sans P1/P2 (la page des licences : Free « Yes ») — la doc de C2 supposait P1/P2 | l'apply, puis `AADServicePrincipalSignInLogs \| take 1` après la connexion du principal de test | corriger la doc de C2 (aucune licence) | retirer la catégorie, `entra-sp-unusual-signin` dite aveugle sans P1/P2 ; les trois autres règles gardent `AuditLogs` |
| **E3** | Entra arrive en quelques minutes (lots d'environ 5 min), sous `expected_latency_s: 1800` et `ago(1h)` | latence, p95 sur 24 h | rien | relever `expected_latency_s` ; élargir la fenêtre au-delà de 45 min |
| **E4** | Les noms d'opérations des règles (« Add service principal », « Update application – Certificates and secrets management », « Consent to application », « Add delegated permission grant », « Add app role assignment to service principal », « Add member to role ») | requête E4 | rien | une règle aveugle sur ce nom : la corriger |
| **E5** | `modifiedProperties` : `KeyDescription` (ancien et nouvel ensemble), `Role.DisplayName`, `ConsentAction.Permissions`, `ConsentContext.IsAdminConsent`, `ServicePrincipal.ObjectID` | requête E4 | rien | `entra-credential-added` filtre sur `KeyDescription` : un autre nom la rend aveugle ; les autres cartes perdent une précision |
| **E6** | Le consentement d'administrateur par `az` donne « Consent to application », ou seulement l'octroi, dont la cible serait Microsoft Graph (`entra.py`) | requête E4 | rien | la carte ne propose pas de blocage (déjà le cas) ; noter le nom réel |
| **E7** | `entra-sp-unusual-signin` se tait les 3 premiers jours, puis voit une adresse nouvelle d'un principal connu | la connexion du principal de test, 3 jours puis Cloud Shell | rien | lire la base (`history`), le seuil `MIN_BASELINE_DAYS` |
| **E8** | La connexion de l'identité managée de H0 n'est pas dans `AADServicePrincipalSignInLogs` (autre catégorie, non envoyée) | `AADServicePrincipalSignInLogs` sur 24 h | la limite reste écrite | ses connexions visibles : la marque `GlorfindelIdentity` les lit |
| **E9** | Le volume d'Entra reste sous 1 Go par mois | `Usage` à 24 h, à 7 jours | rien | au-delà : retirer `ServicePrincipalSignInLogs`, ou décider d'en payer le prix |

Non mesuré par ID1 : `Company Administrator` (l'ancien nom de Global Administrator) dans les journaux
— il faudrait attribuer Administrateur général à un principal de test.

**La suite, R2 (#79)** : R2 attend d'ID1 les trois tables alimentées sur le banc, leur latence mesurée
et ces hypothèses tranchées, pour que les techniques de Stratus Red Team jouées depuis Orodruin sur le
plan de contrôle et sur Entra aient une détection attendue — et qu'un raté y soit celui d'une règle,
pas d'un journal absent.

---

## Coûts réels (West Europe)

- **Infra existante** : LLM API uniquement (Anthropic défaut), <$2/mois (~$0.05–0.10 par run)
- **Infra Celebrimbor (Terraform)** : ~$25–35/mois (VM ~6h/jour + disques + IP + backup + LAW). Jetable — `make celebrimbor-stop` pour pauser sans détruire. `make celebrimbor-up` montre le plan et demande « yes » ; `YES=1` l'applique sans le relire (SEC6, comme les autres cibles Terraform). ⚠️ **`celebrimbor-down` est GARDÉ** (suite incident 2026-06-25 où un `down` non scopé a emporté tout le baseline) : il est **symétrique de `up`** et **protège le baseline**. `make celebrimbor-down TOPO=multinic` → destruction **scopée** d'une topo (via `-target` sur son RG), baseline intact. `make celebrimbor-down` **sans arg refuse** et exige `CONFIRM=<instance>` pour un teardown total (baseline inclus). Retirer une topo proprement = `enabled: false` dans `config.yaml` + `make celebrimbor-up`. Convention : chaque topo définit `azurerm_resource_group.<topo>` (count) = la cible `-target`.
- **Journaux d'activité et d'Entra ID au banc (ID1)**, s'ils sont activés : `AzureActivity` gratuite ; `AuditLogs` et `AADServicePrincipalSignInLogs` à 2,99 USD le Go en West Europe au-delà des 5 Go gratuits du mois — estimés à moins de 2 USD par mois sur le banc, à mesurer (« Les journaux d'activité et d'Entra ID au banc », ci-dessus).
- **Chaos Studio (G0)** : facturé à l'usage des expériences (une panne de 5 min sur une VM). Feu vert du 15/10 sur une estimation de 11 à 42 € par mois pour 2 à 4 campagnes (ROADMAP) ; le coût réel est à relever sur la facture après le premier run.
