# Opérations

_Extrait tel quel de `CLAUDE.md` le 2026-10-15 (lot DX1) : la CLI, les workflows opérateur, les variables d'environnement, le packaging et les coûts. Les règles de sûreté et les conventions restent dans `CLAUDE.md`._

## CLI — référence complète

```bash
# Workflow opérateur — Docker Compose (recommandé)
make glorfindel-start                        # lance watch + war-room → http://localhost:7007
                                             # refuse si AZURE_SUBSCRIPTION_ID est vide (watch aveugle) ; ALLOW_NO_AZURE=1 pour une démo
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
glorfindel approve-rule <id>                 # appliquer la règle → detection_rules.yaml
glorfindel reject-rule <id>                  # écarter la règle sans l'approuver

glorfindel memory-stats                      # ChromaDB cycle count
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel dashboard                         # TUI full-screen : resources + feed + escalations
glorfindel war-room                          # War Room web sur http://localhost:7007 (pip install eregion[war-room])
glorfindel --version                         # 0.2.0

# Annatar
annatar run annatar/scenarios/azure/<scenario>.yaml  # --dry-run disponible, --skip-preflight pour bypasser le check VM
#   Code de sortie (#158) : 0 seulement pour un run allé au bout (détecté, manqué ou non mesuré), un --dry-run ou un
#   « non » à la confirmation ; 1 pour tout refus (contrat d'Orodruin passif, cible non inscrite, départ sale, atomic
#   refusé ou sondes incomplètes, plafond, preflight, scénario invalide) et toute erreur (aucun effet observé, état
#   initial non restauré ou non vérifié, commande qui lève). Une ligne + un indice ; ANNATAR_DEBUG=1 pour la pile.
#   `annatar campaign run` n'est pas concerné : il lit RunOutcome.error, marque le scénario en erreur et continue.
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
make gothmog-preflight [FAULT=vm-shutdown]   # contrat, cibles relues dans l'expérience, état normal — rien d'écrit
make gothmog-run [FAULT=vm-shutdown]         # la panne, son retour vérifié par sonde (~15 min)
gothmog run vm-shutdown --dry-run            # la panne déclarée, sans appel Azure
gothmog report <run_id>                      # runs/<run_id>.json (même forme qu'Annatar)
#   Depuis Orodruin, avec EREGION_EXERCISE_CHANNEL (#193, pas encore mesuré sur le banc) : à la fin
#   de `annatar run` comme de `gothmog run`, le rapport du run part vers H0 (runs/<run_id>.json dans
#   le conteneur des fenêtres, sans droit nouveau), après la fermeture de sa fenêtre. La watch
#   hébergée le tire dans son runs/ (une forme refusée n'est pas écrite, un rapport local jamais
#   écrasé) : la console de l'atelier affiche son verdict. Un échec de publication est signalé
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
make orodruin-campaign-run CAMPAIGN=<id>     # joue la campagne (watch H0 en human_only — rien ne s'isole)
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
annatar campaign plan --target <resource_id> [--llm]   # en local (banc) ; --llm pour le planner LLM
annatar campaign run <campaign_id> --yes               # ratifie le budget/scope et exécute

# Simulation locale sans Azure
make annatar-simulate
make annatar-simulate-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...               # requis si provider Anthropic (défaut)
GLORFINDEL_LLM_MODEL=...            # ex: ollama/llama3.1, openai/gpt-4o, azure/gpt-4o (défaut : anthropic/claude-sonnet-5-5, eregion_core/models.py)
ANNATAR_LLM_MODEL=...               # planificateur de campagne d'Annatar (défaut : anthropic/claude-sonnet-4-6 — claude-sonnet-5-5 refuse ce prompt, 19/10)
EREGION_ANALYSIS_MODEL=...          # IA d'analyse, rapport de campagne (défaut : anthropic/claude-haiku-5-5 — un autre modèle que Glorfindel) ; passé à la watch par docker-compose.yml (rapport écrit sur H0, #167)
EREGION_ANALYSIS_INDEX=...          # index campaign_runs du rapport de campagne (défaut : ~/.eregion/analysis/chroma ; sur H0, le disque de la VM, monté)
EREGION_ANALYSIS_TIMEOUT_S=300      # borne d'un appel au modèle d'analyse (rapport de campagne), par tentative (défaut 300 ; illisible, ≤0, >3600 → 300) ; passée aux conteneurs (x-env) et à l'image d'Annatar ; sur H0, à poser à la main dans host.env (host_env.py ne la recopie pas)
GLORFINDEL_LLM_BASE_URL=...         # endpoint self-hosted/Ollama (ex: http://localhost:11434)
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams/Discord webhook — escalades ET actions autonomes
                                    # Discord : https://discord.com/api/webhooks/<id>/<token>/slack
DISCORD_BOT_TOKEN=...               # Bot Discord interactif (fils par VM, boutons Acquitter/Commande)
DISCORD_CHANNEL_ID=...              # ID du channel (clic droit → Copy Channel ID)
DISCORD_PING_ROLE=...               # ID du rôle à pinger à l'ouverture d'un fil (optionnel)
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h) : au-delà, une carte ttl_exceeded — jamais de levée automatique
GLORFINDEL_APPROVAL_MAX_AGE_H=2     # âge max d'une carte exécutable en un clic (War Room « Approve & execute ») ; nan/inf → 2 ; ≤0 → approbation en un clic fermée
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
GLORFINDEL_CONFIDENCE_THRESHOLD=0.7 # gate autonomie LLM (défaut 0.7 — en dessous → escalade forcée) ; illisible, hors [0, 1] → tout est retenu
GLORFINDEL_LLM_TIMEOUT_S=120        # borne d'un appel au modèle de Glorfindel (décision, autoring de règle), par tentative (défaut 120 ; illisible, ≤0, >3600 → 120) ; pas le rapport de campagne : EREGION_ANALYSIS_TIMEOUT_S
GLORFINDEL_DECISION_DRAWS=3         # D-1 : tirages qui doivent s'accorder avant une action disruptive autonome (défaut 3 ; entier de 2 à 10 ; illisible, 1, >10 → toute action disruptive autonome retenue) ; aucun tirage de plus en human_only
GLORFINDEL_READ_ONLY=1              # creds lecture seule (SP Reader) — mode observe-only ; toute valeur sauf vide/0/false/no/off = lecture seule
GLORFINDEL_DISCOVERY_RETENTION_H=8  # rétention d'une VM éteinte dans le registre avant éviction (défaut 8h)
EREGION_EXERCISE_CHANNEL=https://…/exercises  # O1 : canal des fenêtres d'exercice (Orodruin publie, la watch hébergée lit) ; vide → fenêtres locales. Porte aussi les campagnes finies (campaigns/<id>/…, #167) et le rapport d'un run seul (runs/<run_id>.json, #193) ; posé sur la watch, il démarre le thread campaign-report, qui tire les deux
# Orodruin seulement (orodruin.env) : EREGION_CHANNEL_SCOPE (le conteneur, seule attribution hors du banc acceptée),
# EREGION_MAX_INJECTIONS / EREGION_MAX_RUN_S (plafond du contrat), EREGION_BENCH_RG
# Gothmog : EREGION_BENCH_WORKSPACE (Log Analytics du banc pour la sonde Heartbeat, défaut law-celebrimbor-amonsul)
```

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
