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

# Gothmog (G0) — depuis Orodruin seulement (ailleurs le contrat est passif)
make gothmog-preflight [FAULT=vm-shutdown]   # contrat, cibles relues dans l'expérience, état normal — rien d'écrit
make gothmog-run [FAULT=vm-shutdown]         # la panne, son retour vérifié par sonde (~15 min)
gothmog run vm-shutdown --dry-run            # la panne déclarée, sans appel Azure
gothmog report <run_id>                      # runs/<run_id>.json (même forme qu'Annatar)

# Simulation locale sans Azure
make annatar-simulate
make annatar-simulate-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...               # requis si provider Anthropic (défaut)
GLORFINDEL_LLM_MODEL=...            # ex: ollama/llama3.1, openai/gpt-4o, azure/gpt-4o (défaut : anthropic/claude-sonnet-5-5, eregion_core/models.py)
ANNATAR_LLM_MODEL=...               # planificateur de campagne d'Annatar (défaut : anthropic/claude-sonnet-4-6 — claude-sonnet-5-5 refuse ce prompt, 19/10)
EREGION_ANALYSIS_MODEL=...          # IA d'analyse, rapport de campagne (défaut : anthropic/claude-haiku-5-5 — un autre modèle que Glorfindel)
GLORFINDEL_LLM_BASE_URL=...         # endpoint self-hosted/Ollama (ex: http://localhost:11434)
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams/Discord webhook — escalades ET actions autonomes
                                    # Discord : https://discord.com/api/webhooks/<id>/<token>/slack
DISCORD_BOT_TOKEN=...               # Bot Discord interactif (fils par VM, boutons Acquitter/Commande)
DISCORD_CHANNEL_ID=...              # ID du channel (clic droit → Copy Channel ID)
DISCORD_PING_ROLE=...               # ID du rôle à pinger à l'ouverture d'un fil (optionnel)
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h) : au-delà, une carte ttl_exceeded — jamais de levée automatique
GLORFINDEL_APPROVAL_MAX_AGE_H=2     # âge max d'une carte exécutable en un clic (War Room « Approve & execute »)
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
GLORFINDEL_CONFIDENCE_THRESHOLD=0.7 # gate autonomie LLM (défaut 0.7 — en dessous → escalade forcée)
GLORFINDEL_READ_ONLY=1              # creds lecture seule (SP Reader) — mode observe-only
GLORFINDEL_DISCOVERY_RETENTION_H=8  # rétention d'une VM éteinte dans le registre avant éviction (défaut 8h)
EREGION_EXERCISE_CHANNEL=https://…/exercises  # O1 : canal des fenêtres d'exercice (Orodruin publie, la watch hébergée lit) ; vide → fenêtres locales
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
