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
# TUI :       x:release  u:unblock  v:reset  r:restore
#
glorfindel release <resource_id> --yes       # lever isolation NSG (post-restore, VM de retour)
glorfindel unblock <ip> <resource_id> --yes  # supprimer une règle block IP
glorfindel reset <resource_id> --yes        # reset complet : release + unblock toutes IPs
glorfindel reset <resource_id> --from-azure  # source de vérité = Azure (sans état local) : retire les
                                             # glorfindel-* de CETTE VM sur ses NSG (noms déterministes,
                                             # segment IP qui ancre la correspondance) ; garde les blocages
                                             # de périmètre ; aperçu + confirmation ; --dry-run pour lister
glorfindel snapshot <resource_id> --yes      # backup on-demand RSV (setup scénario, ~5-20min)
glorfindel restore <resource_id> --yes       # Azure Backup fire-and-forget (--before auto-détecté)
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
glorfindel migrate-rules --from <modifié> --base <livré> [--dry-run]  # règles approuvées DANS la base avant P1
                                             # → couche du client, une règle au workspace en ligne liée à son
                                             # backend (H0 : infra/glorfindel-host/README.md)

glorfindel memory-stats                      # ChromaDB cycle count
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel dashboard                         # TUI full-screen : resources + feed + escalations
eregion console [--sections annatar,gothmog] # la console web sur http://localhost:7007 (pip install eregion[console]) ;
                                             # Glorfindel toujours, Annatar et Gothmog s'ils ont des runs sur l'hôte
                                             # (ou --sections) ; `glorfindel war-room` reste un alias caché
                                             # toujours un jeton : EREGION_CONSOLE_TOKEN, sinon tiré au premier démarrage
                                             # (~/.glorfindel/console_token, 600) et affiché avec l'URL à ouvrir une fois
glorfindel --version                         # 0.2.0

# Annatar et Gothmog exigent Glorfindel (V1, #214) : avant chaque run (chaque run d'une campagne aussi),
#   avant tout appel au cloud, l'injecteur lit le battement de la watch. Le canal retour fait foi s'il est
#   configuré (EREGION_WATCH_CHANNEL : la watch hébergée vue d'Orodruin — un fichier de cet hôte n'en dit
#   rien) ; sinon le fichier local ~/.glorfindel/watch_heartbeat (une watch sur le même hôte ; `make
#   annatar-run` le monte). Un battement de moins de 90 s, et pas daté de plus de 10 s dans le futur (le
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
#   Exception assumée : `annatar clean` (annatar/runner/initializer.py) arme le contrat et écrit sur la cible
#   (le disque de test de T1486) sans lire la watch — c'est de la préparation, pas une attaque.

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

# Simulation locale sans Azure
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
jamais sa valeur : avec `DISCORD_CHANNEL_ID`, leur webhook se tait) ; le principal de service
Azure aux trois (la watch, « Approve & execute », les boutons Restore / Revert du bot) ; les
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
recette choisit la valeur (`ANNATAR_AZURE_CLIENT_*` ou `GLORFINDEL_AZURE_CLIENT_*` d'abord, puis
`AZURE_CLIENT_*`) et la pose dans l'environnement de `docker run` seulement (`*_AZURE_PICK`, devant
la commande). Le canary, `tests/unit/test_makefile_secrets.py` : chaque cible rendue par `make -n`
avec des secrets factices, aucune valeur sur une ligne de commande ; puis les recettes des
conteneurs lancées contre un faux `docker` (le bon principal dans son environnement, rien dans
ses arguments). Une valeur que le shell développe (`-e NOM="$NOM"`) n'apparaît pas dans
`make -n`, mais bien dans `ps` : le texte rendu refuse aussi `-e NOM=`, `--env NOM=` et, sur une
ligne qui lance ssh, `export NOM=`, pour tout nom de secret. Une cible nouvelle qui passe un secret fait de même.

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
  construit. LiteLLM reste épinglée dans `pyproject.toml` (`==1.86.1`). Il monte nettement de
  versions par rapport aux postes et à la CI d'avant (anthropic 0.104 → 2.3, fastapi 0.136 →
  0.162, langgraph 1.2.1 → 1.2.17) : **le harnais avant le premier redéploiement de H0 sur ce
  verrou n'est pas facultatif** (`infra/glorfindel-host/README.md`, « Redéployer H0 après M-3 »,
  étape 4).

**Mettre à jour** (une PR, jamais directement sur H0) :

```bash
pip install uv                          # ou pipx install uv ; seulement pour générer
make lock                               # garde les versions verrouillées, ajoute ce qui manque (dépendance ajoutée à pyproject.toml)
make lock UPGRADE=1                     # monte tout à la résolution du jour (LOCK_DATE=AAAA-MM-JJ pour une autre date)
make install && pytest                  # la suite sur le nouveau verrou
```

La PR dit ce qui change (le diff du verrou : LiteLLM, anthropic, langgraph, chromadb surtout).
Avant de la fusionner, puis de redéployer H0, **Jonathan relance le harnais** (appels payants) :
`make llm-compare MODELS=<modèle en service> RUNS=3` (ou `python scripts/llm_smoke.py`) — les
décisions doivent rester celles d'avant ; puis `make glorfindel-host-start REF=<tag>`
(`infra/glorfindel-host/README.md`). Un test (`tests/unit/test_dependency_lock.py`) échoue si une
dépendance de `pyproject.toml` manque au verrou ou n'y satisfait plus sa plage : `make lock`.

L'image d'Annatar (Orodruin) s'installe encore depuis `pyproject.toml`, sans verrou.

---

## Packaging

```
name = "eregion", version = "0.2.0", Apache 2.0 ✓
entrypoints : annatar + glorfindel + gothmog CLIs
wheel : eregion-0.2.0-py3-none-any.whl ✓
```

---

## Coûts réels (West Europe)

- **Infra existante** : LLM API uniquement (Anthropic défaut), <$2/mois (~$0.05–0.10 par run)
- **Infra Celebrimbor (Terraform)** : ~$25–35/mois (VM ~6h/jour + disques + IP + backup + LAW). Jetable — `make celebrimbor-stop` pour pauser sans détruire. ⚠️ **`celebrimbor-down` est GARDÉ** (suite incident 2026-06-25 où un `down` non scopé a emporté tout le baseline) : il est **symétrique de `up`** et **protège le baseline**. `make celebrimbor-down TOPO=multinic` → destruction **scopée** d'une topo (via `-target` sur son RG), baseline intact. `make celebrimbor-down` **sans arg refuse** et exige `CONFIRM=<instance>` pour un teardown total (baseline inclus). Retirer une topo proprement = `enabled: false` dans `config.yaml` + `make celebrimbor-up`. Convention : chaque topo définit `azurerm_resource_group.<topo>` (count) = la cible `-target`.
- **Chaos Studio (G0)** : facturé à l'usage des expériences (une panne de 5 min sur une VM). Feu vert du 15/10 sur une estimation de 11 à 42 € par mois pour 2 à 4 campagnes (ROADMAP) ; le coût réel est à relever sur la facture après le premier run.
