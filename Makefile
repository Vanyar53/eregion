PYTHON := .venv/bin/python
PIP    := .venv/bin/pip

IMAGE_ANNATAR   := eregion-annatar
IMAGE_GLORFINDEL := eregion-glorfindel
SCENARIO ?= annatar/scenarios/azure/ransomware-vm.yaml
SIGNALS  ?= $(shell ls runs/*_signals.jsonl 2>/dev/null | tail -1)

# ── Celebrimbor (infra de test modulaire, jetable) ─────────────────────────
# TF = module unifié infra/terraform/. INSTANCE = workspace Terraform (stack
# isolée pour pipelines parallèles). TOPO = topos à activer (surcharge les flags
# enabled: du config.yaml). Le baseline est toujours déployé.
# subscription_id n'est plus en dur dans le Terraform (repo public) : le provider
# azurerm lit ARM_SUBSCRIPTION_ID. On le dérive de l'AZURE_SUBSCRIPTION_ID déjà
# exporté par .envrc → les flux `make celebrimbor-*` marchent sans config en plus.
export ARM_SUBSCRIPTION_ID ?= $(AZURE_SUBSCRIPTION_ID)
TF       := terraform -chdir=infra/terraform
INSTANCE ?= default
TOPO     ?=

# L23 (#228) : chaque secret passe au conteneur PAR SON NOM (`-e AZURE_CLIENT_SECRET`), jamais
# par sa valeur (`-e AZURE_CLIENT_SECRET=…`, visible dans `ps`, l'historique et `make -n`).
# La valeur est choisie par le shell de la recette et posée dans l'environnement de
# `docker run` seulement (*_AZURE_PICK, devant la commande) : la ligne de commande ne porte
# que des noms. Le canary : tests/unit/test_makefile_secrets.py rend chaque cible par
# `make -n` avec des secrets factices, et aucune valeur ne doit y paraître.
#
# Annatar — ANNATAR_AZURE_CLIENT_* si définis, sinon fallback AZURE_CLIENT_*
# Annatar a besoin de Contributor (RunCommand). Définir ANNATAR_AZURE_CLIENT_*
# pour séparer ses creds de ceux de Glorfindel (Reader pour observe-only).
# AZURE_TENANT_ID et AZURE_SUBSCRIPTION_ID sont toujours partagés (même tenant).
ANNATAR_AZURE_PICK = \
	AZURE_CLIENT_ID="$${ANNATAR_AZURE_CLIENT_ID:-$${AZURE_CLIENT_ID:-}}" \
	AZURE_CLIENT_SECRET="$${ANNATAR_AZURE_CLIENT_SECRET:-$${AZURE_CLIENT_SECRET:-}}"
# GLORFINDEL_LLM_MODEL : le rapport de fin de `campaign run` s'écrit dans ce conteneur, et
# l'IA d'analyse y refuse le modèle de Glorfindel (IA1) — sans lui, elle ne verrait que le défaut.
ANNATAR_AZURE_ENV := \
	-e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID -e AZURE_SUBSCRIPTION_ID \
	-e ANTHROPIC_API_KEY -e ANNATAR_LLM_MODEL -e EREGION_ANALYSIS_MODEL \
	-e EREGION_ANALYSIS_TIMEOUT_S -e GLORFINDEL_LLM_MODEL

# Glorfindel — GLORFINDEL_AZURE_CLIENT_* si définis, sinon fallback AZURE_CLIENT_*
# Glorfindel peut tourner en Reader (GLORFINDEL_READ_ONLY=1 + SP Reader).
# AZURE_TENANT_ID et AZURE_SUBSCRIPTION_ID sont toujours partagés (même tenant).
GLORFINDEL_AZURE_PICK = \
	AZURE_CLIENT_ID="$${GLORFINDEL_AZURE_CLIENT_ID:-$${AZURE_CLIENT_ID:-}}" \
	AZURE_CLIENT_SECRET="$${GLORFINDEL_AZURE_CLIENT_SECRET:-$${AZURE_CLIENT_SECRET:-}}"
GLORFINDEL_AZURE_ENV := \
	-e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID -e AZURE_SUBSCRIPTION_ID

GLORFINDEL_STATE := \
	-v $(HOME)/.glorfindel:/root/.glorfindel \
	-v $(HOME)/.cache/chroma:/root/.cache/chroma

ANNATAR_STATE := \
	-v $(HOME)/.annatar:/root/.annatar

# ~/.glorfindel/injectors read-only, as ~/.glorfindel in the container: Annatar reads the
# watch heartbeat there (V1, its purple-team feedback). Without it, every Docker run printed
# "no active glorfindel watch detected" and skipped the feedback (constaté le 2026-10-07).
# Only that directory (SEC3): the rest of ~/.glorfindel — escalations, isolation state, the
# client's rules — stays out of the attacker's reach. Mounted once (ANNATAR_STATE no longer
# mounts it too: annatar-shell had the same mount point twice).
ANNATAR_VOLS := \
	-v $(PWD)/annatar/scenarios:/app/annatar/scenarios \
	-v $(PWD)/scripts:/app/scripts \
	-v $(PWD)/runs:/app/runs \
	$(if $(wildcard $(HOME)/.glorfindel/injectors),-v $(HOME)/.glorfindel/injectors:/root/.glorfindel:ro,)

GLORFINDEL_VOLS := \
	-v $(PWD)/runs:/app/runs \
	-v $(PWD)/glorfindel/rules:/app/glorfindel/rules:ro \
	$(if $(wildcard $(PWD)/glorfindel-config.yaml),-v $(PWD)/glorfindel-config.yaml:/app/glorfindel-config.yaml,)

# The images' CMD is the CLI itself: arguments REPLACE it, so the binary is named here
# (`make annatar-run` ran `run` as a command and failed).
DOCKER_ANNATAR = $(ANNATAR_AZURE_PICK) docker run --rm $(ANNATAR_AZURE_ENV) $(ANNATAR_VOLS) $(IMAGE_ANNATAR) annatar
GLORFINDEL_ENV := \
	-e AZURE_WORKSPACE_ID \
	-e AZURE_VM_RESOURCE_ID \
	-e ANTHROPIC_API_KEY \
	-e GLORFINDEL_LLM_MODEL \
	-e GLORFINDEL_LLM_BASE_URL \
	-e OPENAI_API_KEY \
	-e MISTRAL_API_KEY \
	-e AZURE_API_KEY \
	-e AZURE_API_BASE \
	-e AZURE_API_VERSION \
	-e GLORFINDEL_WEBHOOK_URL \
	-e DISCORD_BOT_TOKEN \
	-e DISCORD_CHANNEL_ID \
	-e DISCORD_PING_ROLE \
	-e GLORFINDEL_ISOLATION_TTL_H \
	-e GLORFINDEL_INCIDENT_TTL_S \
	-e ORT_LOGGING_LEVEL_DEFAULT=3

DOCKER_GLORFINDEL = $(GLORFINDEL_AZURE_PICK) docker run --rm $(GLORFINDEL_AZURE_ENV) $(GLORFINDEL_VOLS) $(GLORFINDEL_STATE) \
	$(GLORFINDEL_ENV) \
	$(IMAGE_GLORFINDEL) glorfindel

.PHONY: help build build-annatar build-glorfindel fix-state-ownership check-azure-env \
	annatar-run annatar-dry-run annatar-validate annatar-list \
	glorfindel-respond glorfindel-dry-run glorfindel-watch \
	glorfindel-release glorfindel-revert glorfindel-list \
	glorfindel-pending glorfindel-check-ttl \
	glorfindel-start glorfindel-stop glorfindel-restart glorfindel-dev glorfindel-logs glorfindel-ui console-url \
	annatar-shell glorfindel-shell \
	venv install lock audit test test-unit lint annatar-simulate annatar-simulate-gap clean release release-draft \
	canary-jit celebrimbor-init celebrimbor-plan celebrimbor-up celebrimbor-down celebrimbor-output celebrimbor-stop celebrimbor-start \
	glorfindel-host-init glorfindel-host-plan glorfindel-host-up glorfindel-host-down glorfindel-host-push \
	glorfindel-host-start glorfindel-host-stop glorfindel-host-logs glorfindel-host-tunnel glorfindel-host-ssh \
	glorfindel-host-cd-install glorfindel-host-cd-check glorfindel-host-cd-enable glorfindel-host-cd-disable \
	glorfindel-host-cd-status glorfindel-host-cd-retry glorfindel-host-cd-uninstall \
	glorfindel-host-env glorfindel-host-report glorfindel-host-url glorfindel-host-status glorfindel-host-pull \
	glorfindel-host-model glorfindel-host-campaign-report celebrimbor-workload \
	orodruin-init orodruin-plan orodruin-up orodruin-lock orodruin-push orodruin-check \
	orodruin-stop orodruin-start orodruin-kill orodruin-down orodruin-ssh \
	gothmog-preflight gothmog-run \
	orodruin-campaign-plan orodruin-campaign-run \
	profile-discover profile-detection profile-resilience profile-proven profiles-check \
	team-check team-init team-start team-stop team-logs team-config components-check images-check

# ── Help ──────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "Eregion $(shell cat pyproject.toml | grep '^version' | cut -d'"' -f2)"
	@echo ""
	@echo "Dev (local, no Docker)"
	@echo "  make venv           Create .venv (python3 -m venv)"
	@echo "  make install        Create .venv + install dev dependencies (from the lock, hashes checked)"
	@echo "  make lock           Regenerate the dependency lock (uv; UPGRADE=1 bumps all) — docs/operations.md"
	@echo "  make audit          Known advisories of the locks, pip-audit's own too (read as locked; CI2)"
	@echo "  make test           Run all tests (104, 0 Azure, 0 LLM calls)"
	@echo "  make lint           Ruff linter"
	@echo "  make clean          Remove build artifacts"
	@echo ""
	@echo "Release (REL1) — a draft only: Jonathan publishes (publishing deploys H0)"
	@echo "  make release VERSION=X.Y.Z TITLE=\"…\" [DRY_RUN=1]  The version's PR: CHANGELOG cut, version, README"
	@echo "  make release-draft VERSION=X.Y.Z [NOTES=file] [DRY_RUN=1]  After its merge: the draft, seen on #agents"
	@echo ""
	@echo "Build"
	@echo "  make build          Build both Docker images"
	@echo "  make build-annatar  Build eregion-annatar image only"
	@echo "  make build-glorfindel Build eregion-glorfindel image only"
	@echo ""
	@echo "Annatar (Docker)"
	@echo "  make annatar-run              SCENARIO=... Run scenario (--yes)"
	@echo "  make annatar-dry-run          Run scenario (--dry-run)"
	@echo "  make annatar-validate         Validate scenario YAML"
	@echo "  make annatar-list             List available scenarios"
	@echo "  make annatar-simulate         Simulate locally (no Azure): glorfindel respond --dry-run"
	@echo "  make annatar-simulate-gap     Simulate detection_timeout flow (same, no watch)"
	@echo ""
	@echo "Glorfindel (Docker)"
	@echo "  make glorfindel-start           Start watch + war-room (http://localhost:7007)"
	@echo "  make glorfindel-stop            Stop all services"
	@echo "  make glorfindel-restart         Rebuild + restart all services"
	@echo "  make glorfindel-dev             Start + watch files (auto-reload on change)"
	@echo "  make glorfindel-ui              Rebuild + restart war-room only (watch untouched)"
	@echo "  make console-url                The console's URL with its token (~/.glorfindel/console_token)"
	@echo "  make glorfindel-logs            Tail service logs"
	@echo "  make glorfindel-watch           Watch runs/ only (no web UI)"
	@echo "  make glorfindel-respond         SIGNALS=... Process signal file"
	@echo "  make glorfindel-dry-run         SIGNALS=... Dry-run (no actions)"
	@echo "  make glorfindel-list            Show active isolations + blocks"
	@echo "  make glorfindel-pending         Show pending escalations"
	@echo "  make glorfindel-revert          RESOURCE_ID=... Release + unblock all"
	@echo "  make glorfindel-release         RESOURCE_ID=... Release isolation only"
	@echo "  make glorfindel-check-ttl       Release expired isolations (TTL)"
	@echo "  make glorfindel-shell           Interactive shell in eregion-glorfindel"
	@echo ""
	@echo "Shells"
	@echo "  make annatar-shell      🔴 Interactive shell in eregion-annatar"
	@echo "  make glorfindel-shell   🔵 Interactive shell in eregion-glorfindel"
	@echo ""
	@echo "Celebrimbor (infra de test Terraform, jetable)"
	@echo "  make celebrimbor-plan [TOPO=] [INSTANCE=]   Plan (lecture seule, pas d'apply)"
	@echo "  make celebrimbor-up   [TOPO=] [INSTANCE=] [YES=1]  Apply baseline (+ topos) ; plan montré et confirmé, sauf YES=1"
	@echo "  make celebrimbor-down TOPO=x                Détruit UNE topo (baseline préservé)"
	@echo "  make celebrimbor-down CONFIRM=<instance>    Teardown TOTAL (gardé, baseline inclus)"
	@echo "  make celebrimbor-stop / celebrimbor-start         Éteint/rallume le banc (sans détruire) ; VM=<nom> pour une seule"
	@echo "                                                    VM ; stop épargne les VM always-on (bree), sauf ALL=1"
	@echo "  make celebrimbor-output [INSTANCE=]         Fragment glorfindel-config.yaml généré"
	@echo ""
	@echo "Glorfindel hébergé (H0 : pré-observation, état Terraform séparé)"
	@echo "  make glorfindel-host-plan [OPERATOR_CIDR=]   Plan (lecture seule)"
	@echo "  make glorfindel-host-up   [OPERATOR_CIDR=] [YES=1]  Crée la VM (confirmation, sauf YES=1)"
	@echo "  make glorfindel-host-env                     host.env depuis ton .envrc (sans secret Azure)"
	@echo "  make glorfindel-host-push                    host.env + config (human_only forcé) sur la VM"
	@echo "  make glorfindel-host-report [SINCE=7d]       Rapport d'observation"
	@echo "  make glorfindel-host-pull                    Copie locale des verdicts et de la mémoire (chaque semaine)"
	@echo "  make glorfindel-host-model MODEL=…           Changer le modèle qui décide (ou MODEL=default)"
	@echo "  make celebrimbor-workload                    Charge de bree (site + routine d'admin)"
	@echo "  make glorfindel-host-status                  Tout tourne ? VMs, sauvegardes, services, erreurs, cartes à juger"
	@echo "  make glorfindel-host-start [REF=tag|commit]  Déploie une référence (défaut : dernier tag v*), jamais une branche"
	@echo "  make glorfindel-host-stop / -logs            Glorfindel + la console sur la VM"
	@echo "  make glorfindel-host-tunnel                  Tunnel + URL de la console avec son jeton"
	@echo "  make glorfindel-host-url                     L'URL de la console avec son jeton"
	@echo "  make glorfindel-host-cd-install              Le CD de H0 (H1) : agent + timer (désactivé), webhook #deploy"
	@echo "  make glorfindel-host-cd-check                À blanc : vérifie, construit, préflight de la dernière release"
	@echo "  make glorfindel-host-cd-enable / -disable    Le timer (toutes les 5 min) : une release publiée se déploie"
	@echo "  make glorfindel-host-cd-status / -retry      Ce qui tourne, les derniers résultats / réessayer la release"
	@echo ""
	@echo "Orodruin (O1) — hôte des injecteurs, état séparé (infra/orodruin/README.md) :"
	@echo "  make orodruin-plan [OPERATOR_CIDR=]          Plan (lecture seule)"
	@echo "  make orodruin-up   [YES=1]                   1er apply, sortie ouverte (installe Docker)"
	@echo "  make orodruin-lock [YES=1]                   Referme la sortie (apply) ; YES=1 = sans confirmation"
	@echo "  make orodruin-push                           Image d'Annatar + orodruin.env sur la VM"
	@echo "  make orodruin-check                          Le contrat, lu depuis la VM : armed ou passive"
	@echo "  make orodruin-stop / orodruin-start          Désalloue / rallume la VM (entre les sessions)"
	@echo "  make orodruin-kill [DRY_RUN=1]               URGENCE : révoque l'identité, annule le chaos, désalloue, ferme les fenêtres"
	@echo "  make orodruin-down                           Détruit la VM et l'identité"
	@echo ""
	@echo "Gothmog (G0) — une panne déclarée, depuis Orodruin (gothmog/README.md) :"
	@echo "  make gothmog-preflight [FAULT=vm-shutdown]   Contrat, cibles, état normal — rien d'écrit"
	@echo "  make gothmog-run [FAULT=vm-shutdown]         La panne, son retour vérifié (~15 min)"
	@echo "    Sans watch de Glorfindel vivante, refusé (V1) ; WITHOUT_GLORFINDEL=1 : run de dév, dit au rapport"
	@echo ""
	@echo "Campagne (R1 + IA0) — kill-chain + rapport, depuis Orodruin :"
	@echo "  make orodruin-campaign-plan CAMPAIGN_TARGET=<rid> [CAMPAIGN_MAX=5]  Planifie (rend un id)"
	@echo "  make orodruin-campaign-run  CAMPAIGN=<id>    Joue la campagne (watch H0 en human_only)"
	@echo "  make glorfindel-host-campaign-report CAMPAIGN=<id>  Son rapport, écrit seul sur H0"
	@echo "    (#167 : code, tests et mutants — rien de mesuré sur le banc)"
	@echo ""
	@echo "Profils d'usage (D1) — Glorfindel toujours là ; docs/profils/ :"
	@echo "  make profile-discover       Glorfindel seul, en observation : découvrir"
	@echo "  make profile-detection      + Annatar : ma détection marche-t-elle ?"
	@echo "  make profile-resilience     + Gothmog : mon infra tient-elle ?"
	@echo "  make profile-proven         Tout : défense éprouvée (comme H0)"
	@echo "  make team-init  TEAM=<nom>  Plusieurs équipes : ~/.eregion/teams/<nom>/ (team.env, config)"
	@echo "  make team-start TEAM=<nom> [BOT=1]  Son Glorfindel, sa console sur son port ; team-stop, team-logs"
	@echo "  make profiles-check         Chaque profil compose rend ses services (docker, rien ne démarre)"
	@echo "  make components-check [COMPONENT=annatar]  Chaque composant tourne seul (ses tests, les autres absents)"
	@echo "  make images-check           Les deux images construites et éprouvées comme en CI (eregion-*:ci, rien ne démarre)"
	@echo ""
	@echo "Variables"
	@echo "  SCENARIO    Path to scenario YAML (default: $(SCENARIO))"
	@echo "  SIGNALS     Path to signals JSONL (default: latest in runs/)"
	@echo "  RESOURCE_ID Azure VM resource ID"
	@echo "  INSTANCE    Workspace/stack du bench (default: default)"
	@echo "  TOPO        Topos à activer, ex: TOPO=\"multinic,aks\""
	@echo ""

# ── Build ─────────────────────────────────────────────────────────────────

build: build-annatar build-glorfindel

# Bake the operator's UID/GID into the image so the container runs non-root as them →
# bind-mounted state (~/.glorfindel, ~/.cache/chroma, ./runs) stays owned by the
# operator, not root (the local CLI must be able to mutate what the container wrote).
DOCKER_UIDGID = --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g)

build-annatar:
	docker build $(DOCKER_UIDGID) -f annatar/Dockerfile -t $(IMAGE_ANNATAR) .

build-glorfindel:
	docker build $(DOCKER_UIDGID) -f glorfindel/Dockerfile -t $(IMAGE_GLORFINDEL) .

# One-time reclaim of state files written by the OLD root container (pre-non-root
# image). New images write as the operator, so this is only needed once after upgrade.
fix-state-ownership:
	sudo chown -R $(shell id -u):$(shell id -g) \
		$(HOME)/.glorfindel $(HOME)/.cache/chroma runs $(HOME)/.annatar 2>/dev/null || true
	@echo "✓ ~/.glorfindel, ~/.cache/chroma, runs/, ~/.annatar → $(shell id -un)"

# ── Annatar ───────────────────────────────────────────────────────────────

annatar-run: build
	@$(DOCKER_ANNATAR) run $(SCENARIO) --yes

annatar-dry-run: build
	@$(DOCKER_ANNATAR) run $(SCENARIO) --dry-run --yes

annatar-validate:
	docker run --rm -v $(PWD)/annatar/scenarios:/app/annatar/scenarios --entrypoint annatar $(IMAGE_ANNATAR) validate $(SCENARIO)

annatar-list:
	docker run --rm -v $(PWD)/annatar/scenarios:/app/annatar/scenarios --entrypoint annatar $(IMAGE_ANNATAR) list

# The signals of a run in a temporary file, then `glorfindel respond <file> --dry-run` — not
# runs/: the watch takes from there only what an injector emits (SEC3).
annatar-simulate:
	$(PYTHON) scripts/simulate_annatar.py

annatar-simulate-gap:
	$(PYTHON) scripts/simulate_annatar.py --ids-gap

# LLM provider smoke-test — runs the real `decide` against a provider (Ollama/Mistral)
# to prove provider-agnosticism (the mocked unit tests can't). No Azure.
#   make llm-smoke MODEL=ollama/llama3.1 [RUNS=5]
llm-smoke:
	GLORFINDEL_LLM_MODEL=$(or $(MODEL),ollama/llama3.1) $(PYTHON) scripts/llm_smoke.py --runs $(or $(RUNS),1)

# Compare several local models on the `decide` path and print a leaderboard.
# Defaults to a sensible Ollama set; override the set / repeats as needed:
#   make llm-compare
#   make llm-compare MODELS=ollama/gemma4,ollama/qwen3.5 RUNS=5
MODELS ?= ollama/gemma4,ollama/qwen3.5,ollama/qwen3,ollama/gemma3,ollama/qwen2.5,ollama/command-r7b
# IA0 — the campaign report: facts from the files, claims by the analysis model, each checked
# against the runs it cites. Writes runs/campaigns/<id>/report.md. Needs the model's API key.
campaign-report:
	@test -n "$(CAMPAIGN)" || { echo "CAMPAIGN=<id> requis (ls runs/campaigns)"; exit 1; }
	$(PYTHON) -m analysis.campaign_report runs/campaigns/$(CAMPAIGN)

# IA0 harness: fidelity and a planted instruction, against the real analysis model.
report-eval:
	$(PYTHON) scripts/report_eval.py --runs $(or $(RUNS),3)

llm-compare:
	$(PYTHON) scripts/llm_smoke.py --models $(MODELS) --runs $(or $(RUNS),3)$(if $(ATTEST), --attest requirements/harness.json)

# ── Glorfindel ────────────────────────────────────────────────────────────

glorfindel-watch: build
	@$(DOCKER_GLORFINDEL) watch runs/

glorfindel-respond: build
	@$(DOCKER_GLORFINDEL) respond $(SIGNALS)

glorfindel-dry-run: build
	@$(DOCKER_GLORFINDEL) respond $(SIGNALS) --dry-run

glorfindel-list: build
	@$(DOCKER_GLORFINDEL) list

glorfindel-pending: build
	@$(DOCKER_GLORFINDEL) pending

glorfindel-revert: build
	@test -n "$(RESOURCE_ID)" || (echo "Error: RESOURCE_ID is required" && exit 1)
	@$(DOCKER_GLORFINDEL) revert $(RESOURCE_ID) --yes

glorfindel-release: build
	@test -n "$(RESOURCE_ID)" || (echo "Error: RESOURCE_ID is required" && exit 1)
	@$(DOCKER_GLORFINDEL) release $(RESOURCE_ID) --yes

glorfindel-check-ttl: build
	@$(DOCKER_GLORFINDEL) check-ttl

# Without AZURE_SUBSCRIPTION_ID the containers start but see nothing: discovery, posture and
# detection fail with one warning in the logs, and an incident would go unnoticed (happened
# on a redeploy from a shell without .envrc). Stop here — unless wanted (a demo without Azure).
check-azure-env:
	@if [ -z "$(AZURE_SUBSCRIPTION_ID)" ] && [ -z "$(ALLOW_NO_AZURE)" ]; then \
	  echo "✗ AZURE_SUBSCRIPTION_ID is empty: Glorfindel would start blind (no discovery, no detection)."; \
	  echo "  Load your credentials first (direnv allow, or: set -a; . ./.envrc; set +a),"; \
	  echo "  or run with ALLOW_NO_AZURE=1 for a demo without Azure."; \
	  exit 1; \
	fi

glorfindel-start: check-azure-env build-glorfindel
	mkdir -p $(HOME)/.glorfindel $(HOME)/.glorfindel/injectors $(HOME)/.cache/chroma $(HOME)/.eregion/analysis runs
	docker compose up -d
	@echo ""
	@$(MAKE) --no-print-directory console-url || true
	@echo "  Logs      →  make glorfindel-logs"
	@echo "  Dev mode  →  make glorfindel-dev  (auto-reload on file change)"
	@echo "  Stop      →  make glorfindel-stop"
	@echo ""

glorfindel-stop:
	docker compose down

glorfindel-restart: check-azure-env build-glorfindel
	mkdir -p $(HOME)/.glorfindel $(HOME)/.glorfindel/injectors $(HOME)/.cache/chroma $(HOME)/.eregion/analysis runs
	docker compose up -d --build --force-recreate
	@$(MAKE) --no-print-directory console-url || true

glorfindel-dev: check-azure-env build-glorfindel
	mkdir -p $(HOME)/.glorfindel $(HOME)/.glorfindel/injectors $(HOME)/.cache/chroma $(HOME)/.eregion/analysis runs
	docker compose up -d
	@$(MAKE) --no-print-directory console-url || true
	@echo "  (watching for changes…)"
	docker compose watch

glorfindel-logs:
	docker compose logs -f

glorfindel-ui: build-glorfindel
	docker compose up -d --no-deps war-room
	@$(MAKE) --no-print-directory console-url || true
	@echo "  (watch untouched)"

# The console's URL with its token (SEC1): the one compose passes (EREGION_CONSOLE_TOKEN, else its
# former name, from the environment or .env), else the one the console drew at its first start,
# ~/.glorfindel/console_token — written by the container after `up -d`, so waited for
# (CONSOLE_WAIT seconds, 20 by default). The port: EREGION_CONSOLE_PORT, as compose publishes it.
CONSOLE_WAIT ?= 20
console-url:
	@t="$${EREGION_CONSOLE_TOKEN:-$${GLORFINDEL_WARROOM_TOKEN:-}}"; f="$(HOME)/.glorfindel/console_token"; \
	 for k in EREGION_CONSOLE_TOKEN GLORFINDEL_WARROOM_TOKEN; do \
	   [ -n "$$t" ] || t=$$(sed -n -E "/^$$k=/{s/^[^=]*=[[:space:]]*//;s/[[:space:]]+#.*$$//;s/[[:space:]]+$$//;p;}" .env 2>/dev/null | tail -1); \
	 done; \
	 if [ -z "$$t" ]; then i=0; while [ ! -s "$$f" ] && [ $$i -lt $(CONSOLE_WAIT) ]; do sleep 1; i=$$((i+1)); done; \
	   [ -s "$$f" ] && t=$$(head -n 1 "$$f"); fi; \
	 if [ -n "$$t" ]; then echo "  Console   →  http://localhost:$${EREGION_CONSOLE_PORT:-7007}/?token=$$t"; \
	 else echo "  ⚠ Console: no token yet — the console writes $$f at its first start (make glorfindel-logs)" >&2; exit 1; fi

# ── Shells ────────────────────────────────────────────────────────────────

annatar-shell: build-annatar
	@mkdir -p $(HOME)/.annatar
	@touch $(HOME)/.annatar/.bashrc
	@grep -q "alias ar=" $(HOME)/.annatar/.bashrc || echo "alias ar='annatar'" >> $(HOME)/.annatar/.bashrc
	@$(ANNATAR_AZURE_PICK) docker run --rm -it $(ANNATAR_AZURE_ENV) $(ANNATAR_VOLS) $(ANNATAR_STATE) \
		$(IMAGE_ANNATAR) bash --init-file /root/.annatar/.bashrc

glorfindel-shell: build-glorfindel
	@mkdir -p $(HOME)/.glorfindel
	@touch $(HOME)/.glorfindel/.bashrc
	@grep -q "alias gf=" $(HOME)/.glorfindel/.bashrc || echo "alias gf='glorfindel'" >> $(HOME)/.glorfindel/.bashrc
	@$(GLORFINDEL_AZURE_PICK) docker run --rm -it $(GLORFINDEL_AZURE_ENV) $(GLORFINDEL_VOLS) $(GLORFINDEL_STATE) \
		$(GLORFINDEL_ENV) \
		$(IMAGE_GLORFINDEL) bash --init-file /root/.glorfindel/.bashrc

# ── Celebrimbor (infra Terraform) ──────────────────────────────────────────
# Apply/destroy interactifs (Terraform demande la confirmation = la revue du plan).
#   make celebrimbor-up                       # baseline (+ topos enabled:true du config)
#   make celebrimbor-up TOPO="multinic,aks"   # n'active QUE ces topos
#   make celebrimbor-up INSTANCE=ci-1234       # stack isolée (workspace dédié)
#   make celebrimbor-up YES=1                  # sans confirmation (-auto-approve : le plan n'est pas relu) — SEC6
#   make celebrimbor-plan TOPO=multinic        # plan seul (lecture, pas d'apply)
#   make celebrimbor-stop / celebrimbor-start        # éteint/rallume le banc sans détruire
#     [VM=gondolin]                                  # une seule VM ; stop épargne les VM always-on (bree) sauf ALL=1
#   make celebrimbor-output                    # fragment glorfindel-config.yaml généré
#
# ⚠ celebrimbor-down est GARDÉ (incident 2026-06-25 : un down non scopé a emporté tout
#   le baseline). Il est SYMÉTRIQUE de up et protège le baseline :
#   make celebrimbor-down TOPO=multinic        # destruction SCOPÉE de la/les topo(s) — baseline préservé
#   make celebrimbor-down CONFIRM=<instance>   # teardown TOTAL (baseline INCLUS) — confirmation obligatoire
#   Retirer une topo proprement = enabled:false dans config.yaml + celebrimbor-up (reconcile).
#   Convention : chaque topo doit définir `azurerm_resource_group.<topo>` (count) → la cible -target.

# Canary of the just-in-time isolation: re-checks, on the latest azurerm provider, the
# Terraform behavior Glorfindel's isolation relies on (throwaway stack, own RG, ~5 min,
# free resources only). Exit 1 = the behavior changed. Also weekly in CI (canary-azurerm).
canary-jit:
	@infra/canary/jit-terraform/run.sh

celebrimbor-init:
	$(TF) init -upgrade

celebrimbor-plan: celebrimbor-init
	@$(TF) workspace select -or-create $(INSTANCE)
	@if [ -n "$(TOPO)" ]; then \
	   filter=$$(echo '$(TOPO)' | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"",(i>1?",":""),$$i}}'); \
	   $(TF) plan -var="topo_filter=[$$filter]"; \
	 else \
	   $(TF) plan; \
	 fi

celebrimbor-up: celebrimbor-init
	@$(TF) workspace select -or-create $(INSTANCE)
	@if [ -n "$(TOPO)" ]; then \
	   filter=$$(echo '$(TOPO)' | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"",(i>1?",":""),$$i}}'); \
	   $(TF) apply -var="topo_filter=[$$filter]"$(if $(YES), -auto-approve); \
	 else \
	   $(TF) apply$(if $(YES), -auto-approve); \
	 fi
	@echo "" && echo "  Fragment glorfindel-config → make celebrimbor-output"

celebrimbor-down:
	@$(TF) workspace select $(INSTANCE)
	@set -f; if [ -n "$(TOPO)" ]; then \
	   targets=$$(echo '$(TOPO)' | awk -F, '{for(i=1;i<=NF;i++) printf "-target=azurerm_resource_group.%s[0] ", $$i}'); \
	   filter=$$(echo '$(TOPO)' | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"",(i>1?",":""),$$i}}'); \
	   echo ">> Destruction SCOPÉE topo(s) '$(TOPO)' sur l'instance '$(INSTANCE)' (baseline préservé)"; \
	   $(TF) destroy $$targets -var="topo_filter=[$$filter]"; \
	 else \
	   echo "!! celebrimbor-down SANS TOPO = teardown TOTAL de l'instance '$(INSTANCE)'."; \
	   echo "!! → détruit le baseline (vm-celebrimbor-gondolin + law-celebrimbor-amonsul + rsv-celebrimbor-erebor) ET toutes les topos."; \
	   echo "!! Retirer une seule topo : make celebrimbor-down TOPO=<nom>  (ou enabled:false + celebrimbor-up)."; \
	   if [ "$(CONFIRM)" != "$(INSTANCE)" ]; then \
	     echo "!! Refus. Confirme la destruction totale avec :  make celebrimbor-down CONFIRM=$(INSTANCE)"; \
	     exit 1; \
	   fi; \
	   $(TF) destroy; \
	 fi

celebrimbor-output:
	@$(TF) workspace select $(INSTANCE)
	@$(TF) output -raw glorfindel_config_fragment

# H0 : la charge réelle de bree (petit site + routine d'admin), par Run Command —
# jamais par le custom_data (le changer remplace la VM). Idempotent.
celebrimbor-workload:
	az vm run-command invoke -g rg-celebrimbor$(if $(filter-out default,$(INSTANCE)),-$(INSTANCE)) \
	  -n vm-celebrimbor-$(or $(VM),bree)$(if $(filter-out default,$(INSTANCE)),-$(INSTANCE)) \
	  --command-id RunShellScript --scripts @infra/terraform/scripts/workload.sh \
	  --query 'value[0].message' -o tsv | tail -5

# Éteindre / rallumer le banc, tout ou partie, sans rien détruire. Les VM visées sont affichées
# avant d'agir.
#   VM=<nom>  une seule VM : nom court (gondolin, bree) ou complet (vm-celebrimbor-gondolin)
#   ALL=1     (stop) éteint aussi les VM au tag always-on=true (config.yaml : always_on) — bree,
#             la charge réelle que le Glorfindel hébergé (H0) observe ; sans VM ni ALL, stop les épargne.
BENCH_VMS = [?tags.project=='celebrimbor' && tags.instance=='$(INSTANCE)'$(if $(VM), && (name=='$(VM)' || ends_with(name, '-$(VM)')))
BENCH_KEEP = $(if $(or $(VM),$(ALL)),, && tags.\"always-on\" != 'true')

celebrimbor-stop:
	@case "$(VM)" in *[!A-Za-z0-9-]*) echo "VM invalide : $(VM)"; exit 1;; esac; \
	 vms=$$(az vm list --query "$(BENCH_VMS)$(BENCH_KEEP)].[id, name, tags.\"always-on\"]" -o tsv); \
	 [ -n "$$vms" ] || { echo "Aucune VM celebrimbor à éteindre (instance '$(INSTANCE)'$(if $(VM), VM '$(VM)'))"; exit 0; }; \
	 echo "$$vms" | awk -F'\t' '{ print "  az vm deallocate : " $$2 ($$3 == "true" ? "  (always-on)" : "") }'; \
	 $(if $(or $(VM),$(ALL)),,echo "  (les VM always-on sont épargnées ; ALL=1 pour les éteindre aussi)";) \
	 az vm deallocate --ids $$(echo "$$vms" | cut -f1)

celebrimbor-start:
	@case "$(VM)" in *[!A-Za-z0-9-]*) echo "VM invalide : $(VM)"; exit 1;; esac; \
	 vms=$$(az vm list --query "$(BENCH_VMS)].[id, name]" -o tsv); \
	 [ -n "$$vms" ] || { echo "Aucune VM celebrimbor à rallumer (instance '$(INSTANCE)'$(if $(VM), VM '$(VM)'))"; exit 0; }; \
	 echo "$$vms" | awk -F'\t' '{ print "  az vm start : " $$2 }'; \
	 az vm start --ids $$(echo "$$vms" | cut -f1)

# ── Glorfindel hébergé (H0) ───────────────────────────────────────────────
# La VM du défenseur, hors du banc : infra/glorfindel-host/README.md. Lecture seule sur le
# banc, human_only forcé au push. L'apply demande confirmation (pas d'--auto-approve).
HOST_TF       := terraform -chdir=infra/glorfindel-host
HOST_USER     ?= glorfindel
# Sans OPERATOR_CIDR, ton IP publique du moment, en /32 (seule source SSH autorisée).
OPERATOR_CIDR ?= $(shell curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null)/32
HOST_VARS      = -var-file=../terraform/terraform.tfvars -var="operator_cidr=$(OPERATOR_CIDR)"
HOST_IP        = $(shell $(HOST_TF) output -no-color -raw public_ip 2>/dev/null | grep -E '^[0-9.]+$$')
# HOST_SSH_KEY : la clé privée qui va avec admin_ssh_public_key (terraform.tfvars), si ton agent
# SSH ne la propose pas. accept-new : la clé d'hôte d'une VM neuve est acceptée au premier contact.
HOST_SSH_KEY  ?=
SSH_OPTS       = -o StrictHostKeyChecking=accept-new $(if $(HOST_SSH_KEY),-i $(HOST_SSH_KEY) -o IdentitiesOnly=yes)
HOST_SSH       = ssh $(SSH_OPTS) $(HOST_USER)@$(HOST_IP)
HOST_ENV      ?= infra/glorfindel-host/host.env
# Local copies of the VM's ~/.glorfindel (verdicts, memory, state): the observation's data
# lives on one disk otherwise. Outside the repo — they hold real cards.
HOST_BACKUPS  ?= $(HOME)/.eregion/host-backups
# Le jeton de la console dans host.env (UI-1c), à la règle de la console (eregion_console/api.py) :
# EREGION_CONSOLE_TOKEN s'il n'est pas vide, sinon son ancien nom, GLORFINDEL_WARROOM_TOKEN — le
# host.env de H0 n'a que lui, rien à renommer. Lu comme compose le lit : la dernière ligne d'une
# clé l'emporte, un « # … » après la valeur et un blanc est un commentaire. Affiché dans l'URL seulement.
HOST_ENV_VALUE = sed -n -E '/^$(1)=/{s/^[^=]*=[[:space:]]*//;s/[[:space:]]+\#.*$$//;s/[[:space:]]+$$//;p;}' $(HOST_ENV) | tail -1
CONSOLE_TOKEN  = $$(t=$$($(call HOST_ENV_VALUE,EREGION_CONSOLE_TOKEN)); [ -n "$$t" ] || t=$$($(call HOST_ENV_VALUE,GLORFINDEL_WARROOM_TOKEN)); printf '%s' "$$t")
NO_CONSOLE_TOKEN = $(HOST_ENV) : aucun jeton de la console (EREGION_CONSOLE_TOKEN, ou son ancien nom GLORFINDEL_WARROOM_TOKEN)

glorfindel-host-init:
	$(HOST_TF) init -upgrade

glorfindel-host-plan: glorfindel-host-init
	$(HOST_TF) plan $(HOST_VARS)

# YES=1 : sans confirmation (le plan n'est alors pas relu avant l'apply).
glorfindel-host-up: glorfindel-host-init
	$(HOST_TF) apply $(HOST_VARS)$(if $(YES), -auto-approve)
	@echo "" && echo "  Ensuite : make glorfindel-host-env (ou copier host.env.example et remplir), make glorfindel-host-push"

glorfindel-host-down:
	$(HOST_TF) destroy $(HOST_VARS)

# host.env depuis ton environnement (.envrc chargé) : abonnement, clé du modèle, webhook ;
# jamais de secret Azure (identité managée) ; READ_ONLY=1 et un jeton de la console tiré au sort
# (EREGION_CONSOLE_TOKEN ; un host.env existant sous l'ancien nom reste valide).
glorfindel-host-env:
	@.venv/bin/python infra/glorfindel-host/host_env.py infra/glorfindel-host/host.env

# host.env → ~/eregion/.env (lu par docker compose), et la config locale avec
# autonomy forcé à human_only (pré-observation : Glorfindel ne décide jamais seul).
glorfindel-host-push:
	@test -f infra/glorfindel-host/host.env || { echo "infra/glorfindel-host/host.env manquant (voir host.env.example)"; exit 1; }
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@.venv/bin/python infra/glorfindel-host/host_env.py --check infra/glorfindel-host/host.env
	@cfg=$$(mktemp); \
	 .venv/bin/python infra/glorfindel-host/host_config.py glorfindel-config.yaml $$cfg && \
	 scp -q $(SSH_OPTS) infra/glorfindel-host/host.env $(HOST_USER)@$(HOST_IP):eregion/.env && \
	 scp -q $(SSH_OPTS) $$cfg $(HOST_USER)@$(HOST_IP):eregion/glorfindel-config.yaml && \
	 $(HOST_SSH) 'chmod 600 eregion/.env eregion/glorfindel-config.yaml'; \
	 rc=$$?; rm -f $$cfg; exit $$rc
	@echo "  host.env et glorfindel-config.yaml (human_only) poussés sur $(HOST_IP)"

# M-3 (#183) : une référence nommée, jamais une branche — REF=<tag ou commit>, par défaut le
# dernier tag v*. Checkout détaché, image étiquetée avec la référence (deploy.sh, envoyé par
# ssh : celui du poste, quelle que soit la référence déployée).
# REF se donne sur la ligne de commande : une variable REF de l'environnement (un nom
# générique, posé pour autre chose) est refusée, jamais déployée en silence. Le shell la lit
# dans son environnement (EREGION_DEPLOY_REF), jamais recopiée dans la commande avant d'être
# validée, ni développée par make ($(value …), unexport) : « $(…) » n'y est pas exécuté. Une
# REF qui commence par « - » serait une option de deploy.sh (--checkout-only, --show) : refusée.
REF ?=
unexport REF
glorfindel-host-start: export EREGION_DEPLOY_REF = $(value REF)
glorfindel-host-start:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@case "$(origin REF)" in environment*) echo "REF vient de l'environnement (« $$EREGION_DEPLOY_REF ») : rien n'est déployé. La donner sur la ligne de commande : make glorfindel-host-start REF=<tag ou commit> (REF= : le dernier tag v*)." >&2; exit 1;; esac
	@case "$$EREGION_DEPLOY_REF" in -*|*[!A-Za-z0-9._-]*) echo "REF invalide : « $$EREGION_DEPLOY_REF » (un tag ou un commit)" >&2; exit 1;; esac
	$(HOST_SSH) 'test -f .eregion-host-ready && mkdir -p .eregion/analysis && cd eregion && bash -s -- '"$$EREGION_DEPLOY_REF" < infra/glorfindel-host/deploy.sh
	@echo ""
	@echo "  ⚠ Arrête le Glorfindel local (make glorfindel-stop) : deux watch sur le même banc = cartes en double ;"
	@echo "    et aucun autre bot avec le même DISCORD_BOT_TOKEN."
	@echo "  Console → make glorfindel-host-tunnel : il affiche l'URL avec son jeton, puis tient le tunnel"

glorfindel-host-stop:
	$(HOST_SSH) 'cd eregion && docker compose stop'

glorfindel-host-logs:
	$(HOST_SSH) 'cd eregion && docker compose logs --tail 100'

# Is everything running? Azure VMs and backups, containers, errors, discovery, bot, cards
# to judge — read-only, one look (infra/glorfindel-host/status.sh).
glorfindel-host-status:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@HOST_IP=$(HOST_IP) HOST_USER=$(HOST_USER) SSH_OPTS="$(SSH_OPTS)" HOST_BACKUPS=$(HOST_BACKUPS) bash infra/glorfindel-host/status.sh

# A copy of the VM's ~/.glorfindel on this machine (the verdicts of the observation, the
# memory, the state) — the 30 latest kept. The model cache (~/.cache/chroma) re-downloads.
glorfindel-host-pull:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@mkdir -p $(HOST_BACKUPS) && f=$(HOST_BACKUPS)/glorfindel-$$(date -u +%Y%m%dT%H%M%SZ).tgz && \
	 $(HOST_SSH) 'tar czf - -C $$HOME .glorfindel' > $$f && test -s $$f && \
	 ls -1t $(HOST_BACKUPS)/glorfindel-*.tgz | tail -n +31 | xargs -r rm -f && \
	 echo "  ✓ $$f ($$(du -h $$f | cut -f1)) — verdicts, mémoire, état ; les 30 dernières copies gardées"

# Change the model the hosted Glorfindel decides with, in one command: host.env here and the
# VM's .env, then a restart. MODEL=default goes back to the code default (eregion_core/models.py).
# Compare it first (make llm-compare) and run it end to end — README, « Changer de modèle ».
# IA1: then says whether the analysis AI still reasons with another model (analysis/separation.py):
# Glorfindel's model shared with the analysis makes every campaign report refused on H0. Its
# advice on a refusal (exit 2) only; an error (1, an image before IA1) is said; never fails.
glorfindel-host-model:
	@test -n "$(MODEL)" || { echo "MODEL=anthropic/<modèle> requis (ou MODEL=default)"; exit 1; }
	@case "$(MODEL)" in *[!A-Za-z0-9._/:-]*) echo "MODEL invalide : $(MODEL)"; exit 1;; esac
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@f=$(HOST_ENV); sed -i '/^GLORFINDEL_LLM_MODEL=/d' $$f; \
	 [ "$(MODEL)" = default ] || echo "GLORFINDEL_LLM_MODEL=$(MODEL)" >> $$f
	@$(HOST_SSH) 'cd eregion && sed -i "/^GLORFINDEL_LLM_MODEL=/d" .env && \
	 { [ "$(MODEL)" = default ] || echo "GLORFINDEL_LLM_MODEL=$(MODEL)" >> .env; } && \
	 docker compose --profile bot up -d watch war-room bot >/dev/null 2>&1 && sleep 5 && \
	 docker exec eregion-watch python -c "from eregion_core.models import glorfindel_model; print(\"  ✓ Glorfindel décide maintenant avec\", glorfindel_model())" && \
	 { docker exec eregion-watch python -m analysis.separation; rc=$$?; \
	   [ $$rc -ne 2 ] || echo "  → pose EREGION_ANALYSIS_MODEL=<un autre modèle> dans host.env (ici) et dans ~/eregion/.env (VM), puis docker compose up -d watch — docs/analysis.md"; \
	   [ $$rc -ne 1 ] || echo "  (contrôle de séparation indisponible sur cette image : avant IA1 ?)"; \
	   true; }'

glorfindel-host-report:
	$(HOST_SSH) 'docker exec eregion-watch glorfindel report --since $(or $(SINCE),7d)'

# IA0 (#167) : le rapport d'une campagne lancée depuis Orodruin, écrit par la watch de la VM.
glorfindel-host-campaign-report:
	@test -n "$(CAMPAIGN)" || { echo "CAMPAIGN=<id> requis (rendu par orodruin-campaign-plan)"; exit 1; }
	@case "$(CAMPAIGN)" in *[!A-Za-z0-9._-]*) echo "CAMPAIGN invalide : $(CAMPAIGN)"; exit 1;; esac
	$(HOST_SSH) 'cat eregion/runs/campaigns/$(CAMPAIGN)/report.md 2>/dev/null || { cat eregion/runs/campaigns/$(CAMPAIGN)/report.error 2>/dev/null; echo "pas encore de rapport pour $(CAMPAIGN)"; exit 1; }'

glorfindel-host-url:
	@test -f $(HOST_ENV) || { echo "$(HOST_ENV) manquant (make glorfindel-host-env)"; exit 1; }
	@t="$(CONSOLE_TOKEN)"; test -n "$$t" || { echo "$(NO_CONSOLE_TOKEN)" >&2; exit 1; }; \
	 echo "http://localhost:7007/?token=$$t"

# Affiche l'URL avec son jeton, puis tient le tunnel ouvert (Ctrl+C pour fermer).
glorfindel-host-tunnel:
	@if [ -f $(HOST_ENV) ]; then t="$(CONSOLE_TOKEN)"; \
	 if [ -n "$$t" ]; then echo "  Console → http://localhost:7007/?token=$$t"; else echo "  ⚠ $(NO_CONSOLE_TOKEN)"; fi; \
	 echo "  (Ctrl+C ferme le tunnel)"; fi
	ssh $(SSH_OPTS) -N -L 7007:127.0.0.1:7007 $(HOST_USER)@$(HOST_IP)

glorfindel-host-ssh:
	$(HOST_SSH)

# ── Le CD de H0 (H1, #244) : la release que Jonathan publie arrive seule sur H0 ──────────
# infra/glorfindel-host/README.md, « Le CD de H0 ». L'agent vit dans ~/.eregion-cd/ sur la VM,
# jamais dans le checkout qu'il déploie ; ses unités systemd s'installent avec sudo, le timer
# désactivé : -cd-check (à blanc), puis -cd-enable. Le webhook de #deploy et la mention viennent
# de ton environnement ou de ~/.config/eregion/discord.env, par stdin — jamais le jeton du bot.
HOST_CD_FILES = infra/glorfindel-host/cd/eregion_cd.py infra/glorfindel-host/cd/install.sh \
                infra/glorfindel-host/cd/eregion-cd.service infra/glorfindel-host/cd/eregion-cd.timer \
                infra/glorfindel-host/deploy.sh scripts/notify_discord.py
HOST_SSH_TTY   = ssh -t $(SSH_OPTS) $(HOST_USER)@$(HOST_IP)

glorfindel-host-cd-install:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@lines=$$(python3 infra/glorfindel-host/cd/eregion_cd.py export-discord-env) || exit 1; \
	 $(HOST_SSH) 'mkdir -p .eregion-cd && chmod 700 .eregion-cd' && \
	 scp -q $(SSH_OPTS) $(HOST_CD_FILES) $(HOST_USER)@$(HOST_IP):.eregion-cd/ && \
	 printf '%s\n' "$$lines" | $(HOST_SSH) 'umask 077 && cat > .eregion-cd/discord.env' && \
	 git rev-parse HEAD | $(HOST_SSH) 'cat > .eregion-cd/installed-from'
	$(HOST_SSH_TTY) 'sudo bash .eregion-cd/install.sh'

glorfindel-host-cd-check:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	$(HOST_SSH) 'python3 .eregion-cd/eregion_cd.py check'

glorfindel-host-cd-enable:
	$(HOST_SSH_TTY) 'sudo systemctl enable --now eregion-cd.timer && systemctl list-timers eregion-cd.timer --no-pager'

glorfindel-host-cd-disable:
	$(HOST_SSH_TTY) 'sudo systemctl disable --now eregion-cd.timer'

glorfindel-host-cd-status:
	@test -n "$(HOST_IP)" || { echo "Pas de VM : make glorfindel-host-up d'abord"; exit 1; }
	@$(HOST_SSH) 'python3 .eregion-cd/eregion_cd.py status; echo "  timer : $$(systemctl is-enabled eregion-cd.timer 2>/dev/null || echo absent)"; journalctl -u eregion-cd --since -1d -n 15 --no-pager -o cat 2>/dev/null | sed "s/^/  | /"'

glorfindel-host-cd-retry:
	$(HOST_SSH) 'python3 .eregion-cd/eregion_cd.py retry'

glorfindel-host-cd-uninstall:
	$(HOST_SSH_TTY) 'sudo bash .eregion-cd/install.sh --remove'

# ── Orodruin (O1) — l'hôte d'où les injecteurs agissent ───────────────────────
# État séparé de Celebrimbor et de Glorfindel. Le contrat est relu par la VM elle-même (son
# identité, son réseau) : docs/design/orodruin-contract.md.
ORO_TF        := terraform -chdir=infra/orodruin
ORO_USER      ?= orodruin
# watch_principal_id : l'identité du Glorfindel hébergé, lectrice du canal des fenêtres (partie C).
ORO_WATCH_ID   = $(shell $(HOST_TF) output -no-color -raw principal_id 2>/dev/null | grep -E '^[0-9a-f-]{36}$$')
ORO_VARS       = -var-file=../terraform/terraform.tfvars -var="operator_cidr=$(OPERATOR_CIDR)" -var="watch_principal_id=$(ORO_WATCH_ID)"
# SEC5 (V-31) : le sous-réseau et l'IP de H0, admis par le pare-feu du compte du canal — dans
# l'environnement de terraform, jamais sur la ligne affichée (l'id du sous-réseau nomme
# l'abonnement, M124).
ORO_WATCH_SUBNET = $(shell $(HOST_TF) output -no-color -raw subnet_id 2>/dev/null | grep -E '^/subscriptions/')
ORO_WATCH_IP   = $(shell $(HOST_TF) output -no-color -raw public_ip 2>/dev/null | grep -E '^[0-9.]+$$')
orodruin-plan orodruin-up orodruin-lock orodruin-down: export TF_VAR_watch_subnet_id = $(ORO_WATCH_SUBNET)
orodruin-plan orodruin-up orodruin-lock orodruin-down: export TF_VAR_watch_public_ip = $(ORO_WATCH_IP)
ORO_IP         = $(shell $(ORO_TF) output -no-color -raw public_ip 2>/dev/null | grep -E '^[0-9.]+$$')
ORO_SSH        = ssh $(SSH_OPTS) $(ORO_USER)@$(ORO_IP)
ORO_IMAGE     := eregion-annatar:orodruin
# Le conteneur prend l'identité de la VM (aucun secret Azure) ; orodruin.env porte
# l'abonnement, le plafond et la clé du modèle.
ORO_RUN        = docker run --rm --env-file orodruin.env -v $$HOME/runs:/app/runs $(ORO_IMAGE)
# PRINCIPAL / VM_ID : pour un kill même si l'état Terraform est illisible.
ORO_PRINCIPAL  = $(or $(PRINCIPAL),$(shell $(ORO_TF) output -no-color -raw principal_id 2>/dev/null))
ORO_VM_ID      = $(or $(VM_ID),$(shell $(ORO_TF) output -no-color -raw vm_id 2>/dev/null))
# Le kill vise l'abonnement du contrat (AZURE_SUBSCRIPTION_ID d'orodruin.env), jamais le contexte
# courant de ta CLI (M-1) ; SUBSCRIPTION= pour le forcer. CHANNEL= : le canal des fenêtres à fermer.
ORO_ENV        = infra/orodruin/orodruin.env
ORO_SUB        = $(or $(SUBSCRIPTION),$(shell sed -n 's/^AZURE_SUBSCRIPTION_ID=//p' $(ORO_ENV) 2>/dev/null))
ORO_BENCH_RG   = $(or $(shell sed -n 's/^EREGION_BENCH_RG=//p' $(ORO_ENV) 2>/dev/null),rg-celebrimbor)
ORO_CHANNEL    = $(or $(CHANNEL),$(shell $(ORO_TF) output -no-color -raw channel_url 2>/dev/null | grep -E '^https://'),$(shell sed -n 's/^EREGION_EXERCISE_CHANNEL=//p' $(ORO_ENV) 2>/dev/null))

orodruin-init:
	$(ORO_TF) init -upgrade

orodruin-plan: orodruin-init
	$(ORO_TF) plan $(ORO_VARS)

# Premier apply : sortie ouverte, le temps d'installer Docker. Ensuite orodruin-lock.
# YES=1 : sans confirmation (-auto-approve), pour un lancement non interactif.
orodruin-up: orodruin-init
	$(ORO_TF) apply $(ORO_VARS) -var="egress_locked=false"$(if $(YES), -auto-approve)
	@echo "" && echo "  VM prête quand ~/.orodruin-ready existe (make orodruin-ssh) ; puis make orodruin-lock"

orodruin-lock: orodruin-init
	$(ORO_TF) apply $(ORO_VARS)$(if $(YES), -auto-approve)

# L'image arrive par SSH : la sortie de la VM reste fermée. UID 1000 = l'utilisateur de la VM.
orodruin-push:
	@test -f infra/orodruin/orodruin.env || { echo "!! infra/orodruin/orodruin.env manquant (copier orodruin.env.example)"; exit 1; }
	docker build -f annatar/Dockerfile --build-arg UID=1000 --build-arg GID=1000 -t $(ORO_IMAGE) .
	docker save $(ORO_IMAGE) | gzip | $(ORO_SSH) 'gunzip | docker load'
	scp $(SSH_OPTS) infra/orodruin/orodruin.env $(ORO_USER)@$(ORO_IP):orodruin.env

orodruin-check:
	$(ORO_SSH) '$(ORO_RUN) python -m eregion_core.orodruin'

# @ : la commande porte l'identifiant d'abonnement, on ne la répète pas à l'écran.
orodruin-stop:
	@echo "az vm deallocate (vm-orodruin)" && az vm deallocate --ids "$(ORO_VM_ID)"

orodruin-start:
	@echo "az vm start (vm-orodruin)" && az vm start --ids "$(ORO_VM_ID)"

# Urgence, depuis ton az login : révoquer d'abord, puis annuler le chaos en cours, désallouer, fermer
# les fenêtres d'exercice ouvertes, et dire ce qui reste en vol (infra/orodruin/kill.py).
orodruin-kill:
	@.venv/bin/python infra/orodruin/kill.py "$(ORO_PRINCIPAL)" "$(ORO_VM_ID)" --subscription "$(ORO_SUB)" \
		--bench-rg "$(ORO_BENCH_RG)" --channel "$(ORO_CHANNEL)" $(if $(DRY_RUN),--dry-run)

orodruin-down:
	$(ORO_TF) destroy $(ORO_VARS)$(if $(YES), -auto-approve)

orodruin-ssh:
	$(ORO_SSH)

# ── Gothmog (G0) — une panne déclarée, lancée depuis Orodruin ─────────────────
# Même image et même identité qu'Annatar sur Orodruin. ServerAliveInterval : la panne et la
# vérification du retour durent ~15 min, plus que le délai d'inactivité d'une IP publique.
FAULT ?= vm-shutdown
# V1 (#214) : sans watch de Glorfindel vivante (le battement du canal retour), l'injecteur refuse
# avant tout appel au cloud, et la cible échoue avec lui. WITHOUT_GLORFINDEL=1 : un run de
# développement, que le rapport inscrit (« detection not measured, by choice ») ; 1, yes ou true
# seulement — WITHOUT_GLORFINDEL=0 (ou toute autre valeur) n'y touche pas.
ORO_WITHOUT    = $(if $(filter 1 yes true,$(WITHOUT_GLORFINDEL)), --without-glorfindel)

gothmog-preflight:
	$(ORO_SSH) '$(ORO_RUN) gothmog preflight $(FAULT)$(ORO_WITHOUT)'

gothmog-run:
	ssh $(SSH_OPTS) -o ServerAliveInterval=60 $(ORO_USER)@$(ORO_IP) '$(ORO_RUN) gothmog run $(FAULT) --yes$(ORO_WITHOUT)'

# ── Campagne (R1 + IA0) — planifier puis lancer depuis Orodruin ───────────────
# Même image, même identité qu'Annatar/Gothmog sur Orodruin. La campagne joue l'atomic
# (T1136.001) avec d'autres techniques du catalogue ; le manifeste se pose dans ~/runs
# (bind-monté). Le rapport (IA0) s'écrit seul sur H0 (#167 — code, tests et mutants M126–M149, M159–M169, M180–M186 ;
# rien de mesuré sur le banc) : à la fin, la campagne publie son
# manifeste et les rapports de ses runs sur le canal des fenêtres (EREGION_EXERCISE_CHANNEL,
# même conteneur, aucun droit de plus) ; la watch de H0 les tire et écrit
# runs/campaigns/<id>/report.md, avec les décisions de Glorfindel — make
# glorfindel-host-campaign-report CAMPAIGN=<id> pour le lire (docs/analysis.md).
# Deux temps : `campaign plan` rend un id, `campaign run <id>` le joue (la watch sur H0 est en
# human_only — rien ne s'isole). ServerAliveInterval : une campagne dure longtemps (plusieurs
# techniques et leurs fenêtres de détection), plus que le délai d'inactivité d'une IP publique.
#   make orodruin-campaign-plan CAMPAIGN_TARGET=<resource_id VM inscrite> [CAMPAIGN_MAX=5]
#   make orodruin-campaign-run  CAMPAIGN=<id rendu par le plan>
CAMPAIGN_MAX ?= 5

# @ : la commande porte CAMPAIGN_TARGET (un resource_id, avec l'abonnement) — on ne la répète
# pas à l'écran (même convention qu'orodruin-stop).
orodruin-campaign-plan:
	@test -n "$(CAMPAIGN_TARGET)" || { echo "CAMPAIGN_TARGET=<resource_id de la VM inscrite> requis"; exit 1; }
	@echo "annatar campaign plan (Orodruin, max $(CAMPAIGN_MAX))" && $(ORO_SSH) '$(ORO_RUN) annatar campaign plan --target "$(CAMPAIGN_TARGET)" --max-scenarios $(CAMPAIGN_MAX)'

orodruin-campaign-run:
	@test -n "$(CAMPAIGN)" || { echo "CAMPAIGN=<id> requis (rendu par orodruin-campaign-plan)"; exit 1; }
	ssh $(SSH_OPTS) -o ServerAliveInterval=60 $(ORO_USER)@$(ORO_IP) '$(ORO_RUN) annatar campaign run $(CAMPAIGN) --yes$(ORO_WITHOUT)'

# ── Profils d'usage (D1) — docs/profils/ ──────────────────────────────────────
# Glorfindel est toujours là (docs/design/console.md, §2) : chaque profil démarre sa watch et la
# console (glorfindel-start), puis prépare ce qu'il ajoute. Un injecteur n'agit que depuis un
# Orodruin armé : sur ce poste, son image et les commandes qui ne touchent rien.
# Les dossiers montés (~/.glorfindel, ~/.cache/chroma par glorfindel-start, ~/.annatar ici) sont
# créés au nom de l'opérateur : laissés à docker, ils seraient à root. depends_on démarre la
# watch, sans attendre son battement : la première minute, un injecteur peut refuser (V1).
profile-discover: glorfindel-start
	@echo "  Profil « découvrir » : Glorfindel seul, en observation — docs/profils/decouvrir.md"

profile-detection: glorfindel-start build-annatar
	@mkdir -p $(HOME)/.annatar
	@echo "  Profil « ma détection marche-t-elle ? » : Glorfindel + Annatar — docs/profils/detection.md"
	@echo "  Ici, rien ne touche le cloud : docker compose --profile annatar run --rm annatar list"
	@echo "  Les attaques : depuis Orodruin (make orodruin-up, orodruin-push, orodruin-campaign-plan)"

profile-resilience: glorfindel-start build-annatar
	@echo "  Profil « mon infra tient-elle ? » : Glorfindel + Gothmog — docs/profils/resilience.md"
	@echo "  Ici, le verdict sans rien écrire : docker compose --profile gothmog run --rm gothmog preflight vm-shutdown"
	@echo "  Les pannes : depuis Orodruin (make gothmog-preflight, gothmog-run)"

profile-proven: glorfindel-start build-annatar
	@mkdir -p $(HOME)/.annatar
	@echo "  Profil « défense éprouvée » : Glorfindel + Annatar + Gothmog — docs/profils/eprouvee.md"
	@echo "  Glorfindel hébergé : make glorfindel-host-up, glorfindel-host-start ; injecteurs : Orodruin"

# CI (.github/workflows/components.yml) : chaque profil compose rend ses services, Glorfindel
# dans tous ; une instance d'équipe prend son nom. docker compose config : rien ne démarre.
profiles-check:
	@check() { got=$$(docker compose $$1 config --services | LC_ALL=C sort | tr '\n' ' '); \
	  if [ "$$got" = "$$2" ]; then echo "  ✓ [$$1] $$got"; else echo "  ✗ [$$1] $$got (attendu : $$2)"; exit 1; fi; }; \
	check "" "war-room watch " && \
	check "--profile annatar" "annatar war-room watch " && \
	check "--profile gothmog" "gothmog war-room watch " && \
	check "--profile annatar --profile gothmog" "annatar gothmog war-room watch " && \
	check "--profile bot" "bot war-room watch "
	@d=$$(mktemp -d) && printf 'AZURE_SUBSCRIPTION_ID=team-sub\nEREGION_CONSOLE_PORT=7998\n' > "$$d/team.env" \
	  && AZURE_SUBSCRIPTION_ID=shell-sub $(MAKE) -s --no-print-directory team-config TEAM=check TEAM_DIR="$$d" > "$$d/out"; \
	  ok=0; grep -q "container_name: eregion-check-watch" "$$d/out" && grep -q 'published: "7998"' "$$d/out" \
	  && grep -q "AZURE_SUBSCRIPTION_ID: team-sub" "$$d/out" && ! grep -q "shell-sub" "$$d/out" && ok=1; rm -rf "$$d"; \
	  if [ $$ok = 1 ]; then echo "  ✓ une instance par équipe : ses noms, son port, son abonnement — pas celui du shell"; \
	  else echo "  ✗ l'instance d'une équipe ne prend pas son team.env seul"; exit 1; fi

# CI1 (#267) : les deux images construites comme le job de CI (.github/workflows/images.yml) —
# leur Dockerfile, le dépôt pour contexte, aucun build-arg, sans le cache de GitHub — puis
# éprouvées dedans (scripts/image_check.py : --version, imports, config d'exemple sous A3), sans
# réseau, rien ne démarre. Tags eregion-glorfindel:ci et eregion-annatar:ci : les images de
# make build (:latest, UID/GID de l'opérateur) ne bougent pas.
images-check:
	python3 scripts/image_check.py glorfindel --build
	python3 scripts/image_check.py annatar --build

# Plusieurs équipes : une instance de Glorfindel par équipe, tout son état dans
# ~/.eregion/teams/<équipe>/ — team.env, glorfindel-config.yaml, runs/, et le HOME que lit
# docker-compose.yml (.glorfindel, .cache/chroma, .eregion/analysis). env -i : ton shell (ton
# .envrc, ton abonnement) n'atteint jamais l'instance d'une équipe — docker compose préfère
# l'environnement au fichier --env-file ; seuls passent le PATH et l'accès à docker.
TEAM_DIR     = $(HOME)/.eregion/teams/$(TEAM)
TEAM_COMPOSE = env -i PATH="$$PATH" HOME="$(TEAM_DIR)" DOCKER_CONFIG="$${DOCKER_CONFIG:-$$HOME/.docker}" \
	DOCKER_HOST="$${DOCKER_HOST:-}" DOCKER_CONTEXT="$${DOCKER_CONTEXT:-}" \
	EREGION_INSTANCE="eregion-$(TEAM)" EREGION_RUNS="$(TEAM_DIR)/runs" \
	EREGION_CONFIG="$(TEAM_DIR)/glorfindel-config.yaml" \
	docker compose -p "eregion-$(TEAM)" --env-file "$(TEAM_DIR)/team.env"

# Le nom fait un chemin, un projet compose et des noms de conteneurs : minuscules, chiffres, tirets.
team-check:
	@case "$(TEAM)" in ""|-*|*[!a-z0-9-]*) echo "✗ TEAM=<nom> requis : minuscules, chiffres, tirets"; exit 1;; esac

team-init: team-check
	mkdir -p "$(TEAM_DIR)/runs"
	@[ -f "$(TEAM_DIR)/team.env" ] || { cp team.env.example "$(TEAM_DIR)/team.env" && chmod 600 "$(TEAM_DIR)/team.env"; }
	@[ -f "$(TEAM_DIR)/glorfindel-config.yaml" ] || cp glorfindel-config.yaml.example "$(TEAM_DIR)/glorfindel-config.yaml"
	@echo "  À remplir : $(TEAM_DIR)/team.env (abonnement, principal, port) et glorfindel-config.yaml"

team-start: team-check build-glorfindel
	@[ -f "$(TEAM_DIR)/team.env" ] && [ -f "$(TEAM_DIR)/glorfindel-config.yaml" ] \
	  || { echo "✗ $(TEAM_DIR)/team.env ou glorfindel-config.yaml manquant : make team-init TEAM=$(TEAM)"; exit 1; }
	@grep -qE '^AZURE_SUBSCRIPTION_ID=[^[:space:]#]' "$(TEAM_DIR)/team.env" || [ -n "$(ALLOW_NO_AZURE)" ] \
	  || { echo "✗ AZURE_SUBSCRIPTION_ID vide dans team.env : son Glorfindel démarrerait aveugle (ALLOW_NO_AZURE=1 : démo)"; exit 1; }
	@grep -qE '^EREGION_CONSOLE_PORT=[0-9]+' "$(TEAM_DIR)/team.env" \
	  || { echo "✗ EREGION_CONSOLE_PORT absent de team.env : un port par équipe (7007 : make glorfindel-start)"; exit 1; }
	mkdir -p "$(TEAM_DIR)/runs" "$(TEAM_DIR)/.glorfindel" "$(TEAM_DIR)/.cache/chroma" "$(TEAM_DIR)/.eregion/analysis"
	$(TEAM_COMPOSE)$(if $(BOT), --profile bot) up -d watch war-room$(if $(BOT), bot)
	@echo "  Console de $(TEAM) → http://localhost:$$(sed -n 's/^EREGION_CONSOLE_PORT=//p' "$(TEAM_DIR)/team.env" | tail -1)"

team-stop: team-check
	$(TEAM_COMPOSE) --profile bot down

team-logs: team-check
	$(TEAM_COMPOSE) logs -f

# Ce que reçoit l'instance d'une équipe, rendu par docker compose — les valeurs de team.env
# comprises : à ne pas coller ailleurs.
team-config: team-check
	@$(TEAM_COMPOSE) --profile bot config

# D1 : chaque composant tourne seul — ses tests, les autres composants et les dépendances de
# Glorfindel absents (scripts/component_check.py ; la CI : .github/workflows/components.yml).
components-check:
	@for c in $(or $(COMPONENT),core glorfindel annatar gothmog); do \
	  $(PYTHON) scripts/component_check.py $$c --imports && $(PYTHON) scripts/component_check.py $$c || exit 1; done

# ── Dev ───────────────────────────────────────────────────────────────────

venv:
	python3 -m venv .venv

# M-3 (#183) : les dépendances viennent du verrou, empreintes vérifiées (comme la CI et l'image).
install: venv
	$(PIP) install --require-hashes -r requirements/dev.txt
	$(PIP) install --no-deps --no-build-isolation -e .

# Regénérer le verrou (uv, résolution universelle : Python 3.11 et 3.12, Linux et macOS).
# Les versions déjà verrouillées restent ; UPGRADE=1 les monte toutes. Une PR, puis le harnais
# (make llm-compare) avant de redéployer H0 : docs/operations.md, « Verrou des dépendances ».
# Puis les avis connus des verrous écrits (make audit, CI2) : une information pour la PR,
# jamais un échec de make lock.
UV         ?= uv
LOCK_DATE  ?= $(shell date -u +%Y-%m-%d)
LOCK_FLAGS  = --universal --python-version 3.11 --generate-hashes \
              --exclude-newer $(LOCK_DATE)T00:00:00Z $(if $(UPGRADE),--upgrade)
lock:
	$(UV) pip compile pyproject.toml requirements/build.in --extra dev $(LOCK_FLAGS) -o requirements/dev.txt
	$(UV) pip compile pyproject.toml requirements/build.in --extra glorfindel --extra war-room \
	  -c requirements/dev.txt $(LOCK_FLAGS) -o requirements/glorfindel.txt
	$(UV) pip compile pyproject.toml requirements/build.in --extra annatar \
	  -c requirements/dev.txt $(LOCK_FLAGS) -o requirements/annatar.txt
	$(UV) pip compile requirements/audit.in $(LOCK_FLAGS) -o requirements/audit.txt
	-@$(MAKE) --no-print-directory audit

# CI2 (#268) : les avis connus des trois verrous et de celui de pip-audit, tels qu'ils sont
# (pip-audit --require-hashes --disable-pip : rien n'est résolu, seul le service des avis est
# interrogé). pip-audit vient de
# son propre verrou (requirements/audit.txt, empreintes), dans un venv à part ; le workflow
# hebdomadaire (pip-audit.yml) en fait une issue par avis. Ici, il le dit seulement.
AUDIT_VENV ?= .venv-audit
PIP_AUDIT  ?= $(AUDIT_VENV)/bin/pip-audit
LOCKS       = requirements/dev.txt requirements/glorfindel.txt requirements/annatar.txt requirements/audit.txt
audit:
	@[ -x "$(PIP_AUDIT)" ] || { python3 -m venv $(AUDIT_VENV) \
	  && $(AUDIT_VENV)/bin/pip install -q --require-hashes -r requirements/audit.txt; }
	@python3 scripts/pip_audit_issues.py report --pip-audit "$(PIP_AUDIT)" $(LOCKS)

test:
	$(PYTHON) -m pytest tests/ -v

test-unit:
	$(PYTHON) -m pytest tests/unit/ -v

lint:
	.venv/bin/ruff check .

# REL1 (#269) : une release en deux commandes (docs/operations.md, « Packaging et version »).
# `release` coupe [Unreleased], change la version et la ligne « Status » du README, ouvre la PR
# chore/release-X.Y.Z ; `release-draft`, après sa fusion, crée le BROUILLON sur le sha complet
# d'origin/main et le pose sur #agents. Aucune ne publie : Jonathan publie (son CD déploie H0).
# Comme REF : VERSION, TITLE et NOTES se donnent sur la ligne de commande, lus par le script
# dans son environnement, jamais développés par make ni recopiés dans la commande.
RELEASE_ARGS = VERSION TITLE NOTES
unexport VERSION TITLE NOTES
release release-draft: export EREGION_RELEASE_VERSION = $(value VERSION)
release release-draft: export EREGION_RELEASE_TITLE = $(value TITLE)
release release-draft: export EREGION_RELEASE_NOTES = $(value NOTES)
release release-draft: export EREGION_RELEASE_ORIGIN = $(foreach v,$(RELEASE_ARGS),$(v):$(firstword $(origin $(v))))
release:
	@case " $$EREGION_RELEASE_ORIGIN " in *:environment*) echo "VERSION, TITLE ou NOTES vient de l'environnement : rien n'est fait. Sur la ligne de commande : make release VERSION=X.Y.Z TITLE=\"…\"" >&2; exit 1;; esac
	python3 scripts/release.py prepare$(if $(DRY_RUN), --dry-run)

release-draft:
	@case " $$EREGION_RELEASE_ORIGIN " in *:environment*) echo "VERSION ou NOTES vient de l'environnement : rien n'est fait. Sur la ligne de commande : make release-draft VERSION=X.Y.Z" >&2; exit 1;; esac
	python3 scripts/release.py release-draft$(if $(DRY_RUN), --dry-run)

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/
