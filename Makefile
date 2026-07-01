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

# Annatar — ANNATAR_AZURE_CLIENT_* si définis, sinon fallback AZURE_CLIENT_*
# Annatar a besoin de Contributor (RunCommand). Définir ANNATAR_AZURE_CLIENT_*
# pour séparer ses creds de ceux de Glorfindel (Reader pour observe-only).
# AZURE_TENANT_ID et AZURE_SUBSCRIPTION_ID sont toujours partagés (même tenant).
ANNATAR_AZURE_ENV := \
	-e AZURE_CLIENT_ID=$(or $(ANNATAR_AZURE_CLIENT_ID),$(AZURE_CLIENT_ID)) \
	-e AZURE_CLIENT_SECRET=$(or $(ANNATAR_AZURE_CLIENT_SECRET),$(AZURE_CLIENT_SECRET)) \
	-e AZURE_TENANT_ID=$(AZURE_TENANT_ID) \
	-e AZURE_SUBSCRIPTION_ID=$(AZURE_SUBSCRIPTION_ID)

# Glorfindel — GLORFINDEL_AZURE_CLIENT_* si définis, sinon fallback AZURE_CLIENT_*
# Glorfindel peut tourner en Reader (GLORFINDEL_READ_ONLY=1 + SP Reader).
# AZURE_TENANT_ID et AZURE_SUBSCRIPTION_ID sont toujours partagés (même tenant).
GLORFINDEL_AZURE_ENV := \
	-e AZURE_CLIENT_ID=$(or $(GLORFINDEL_AZURE_CLIENT_ID),$(AZURE_CLIENT_ID)) \
	-e AZURE_CLIENT_SECRET=$(or $(GLORFINDEL_AZURE_CLIENT_SECRET),$(AZURE_CLIENT_SECRET)) \
	-e AZURE_TENANT_ID=$(AZURE_TENANT_ID) \
	-e AZURE_SUBSCRIPTION_ID=$(AZURE_SUBSCRIPTION_ID)

GLORFINDEL_STATE := \
	-v $(HOME)/.glorfindel:/root/.glorfindel \
	-v $(HOME)/.cache/chroma:/root/.cache/chroma

ANNATAR_STATE := \
	-v $(HOME)/.annatar:/root/.annatar \
	-v $(HOME)/.glorfindel:/root/.glorfindel:ro

ANNATAR_VOLS := \
	-v $(PWD)/annatar/scenarios:/app/annatar/scenarios \
	-v $(PWD)/scripts:/app/scripts \
	-v $(PWD)/runs:/app/runs

GLORFINDEL_VOLS := \
	-v $(PWD)/runs:/app/runs \
	-v $(PWD)/glorfindel/rules:/app/glorfindel/rules \
	$(if $(wildcard $(PWD)/glorfindel-config.yaml),-v $(PWD)/glorfindel-config.yaml:/app/glorfindel-config.yaml,)

DOCKER_ANNATAR := docker run --rm $(ANNATAR_AZURE_ENV) $(ANNATAR_VOLS) $(IMAGE_ANNATAR)
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

DOCKER_GLORFINDEL := docker run --rm $(GLORFINDEL_AZURE_ENV) $(GLORFINDEL_VOLS) $(GLORFINDEL_STATE) \
	$(GLORFINDEL_ENV) \
	$(IMAGE_GLORFINDEL)

.PHONY: help build build-annatar build-glorfindel fix-state-ownership \
	annatar-run annatar-dry-run annatar-validate annatar-list \
	glorfindel-respond glorfindel-dry-run glorfindel-watch \
	glorfindel-release glorfindel-revert glorfindel-list \
	glorfindel-pending glorfindel-check-ttl \
	glorfindel-start glorfindel-stop glorfindel-restart glorfindel-dev glorfindel-logs glorfindel-ui \
	annatar-shell glorfindel-shell \
	venv install test test-unit lint annatar-simulate annatar-simulate-gap clean \
	celebrimbor-init celebrimbor-plan celebrimbor-up celebrimbor-down celebrimbor-output celebrimbor-stop celebrimbor-start

# ── Help ──────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "Eregion $(shell cat pyproject.toml | grep '^version' | cut -d'"' -f2)"
	@echo ""
	@echo "Dev (local, no Docker)"
	@echo "  make venv           Create .venv (python3 -m venv)"
	@echo "  make install        Create .venv + install dev dependencies"
	@echo "  make test           Run all tests (104, 0 Azure, 0 LLM calls)"
	@echo "  make lint           Ruff linter"
	@echo "  make clean          Remove build artifacts"
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
	@echo "  make annatar-simulate         Simulate locally (no Azure)"
	@echo "  make annatar-simulate-gap     Simulate detection_timeout flow"
	@echo ""
	@echo "Glorfindel (Docker)"
	@echo "  make glorfindel-start           Start watch + war-room (http://localhost:7007)"
	@echo "  make glorfindel-stop            Stop all services"
	@echo "  make glorfindel-restart         Rebuild + restart all services"
	@echo "  make glorfindel-dev             Start + watch files (auto-reload on change)"
	@echo "  make glorfindel-ui              Rebuild + restart war-room only (watch untouched)"
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
	@echo "  make celebrimbor-up   [TOPO=] [INSTANCE=]   Apply baseline (+ topos)"
	@echo "  make celebrimbor-down TOPO=x                Détruit UNE topo (baseline préservé)"
	@echo "  make celebrimbor-down CONFIRM=<instance>    Teardown TOTAL (gardé, baseline inclus)"
	@echo "  make celebrimbor-stop / celebrimbor-start         Éteint/rallume les VMs (sans détruire)"
	@echo "  make celebrimbor-output [INSTANCE=]         Fragment glorfindel-config.yaml généré"
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
	$(DOCKER_ANNATAR) run $(SCENARIO) --yes

annatar-dry-run: build
	$(DOCKER_ANNATAR) run $(SCENARIO) --dry-run --yes

annatar-validate:
	docker run --rm -v $(PWD)/annatar/scenarios:/app/annatar/scenarios --entrypoint annatar $(IMAGE_ANNATAR) validate $(SCENARIO)

annatar-list:
	docker run --rm -v $(PWD)/annatar/scenarios:/app/annatar/scenarios --entrypoint annatar $(IMAGE_ANNATAR) list

annatar-simulate:
	$(PYTHON) scripts/simulate_annatar.py

annatar-simulate-gap:
	$(PYTHON) scripts/simulate_annatar.py --ids-gap

# LLM provider smoke-test — runs the real `decide` against a provider (Ollama/Mistral)
# to prove provider-agnosticism (the mocked unit tests can't). No Azure.
#   make llm-smoke MODEL=ollama/llama3.1
llm-smoke:
	GLORFINDEL_LLM_MODEL=$(or $(MODEL),ollama/llama3.1) $(PYTHON) scripts/llm_smoke.py

# ── Glorfindel ────────────────────────────────────────────────────────────

glorfindel-watch: build
	$(DOCKER_GLORFINDEL) watch runs/

glorfindel-respond: build
	$(DOCKER_GLORFINDEL) respond $(SIGNALS)

glorfindel-dry-run: build
	$(DOCKER_GLORFINDEL) respond $(SIGNALS) --dry-run

glorfindel-list: build
	$(DOCKER_GLORFINDEL) list

glorfindel-pending: build
	$(DOCKER_GLORFINDEL) pending

glorfindel-revert: build
	@test -n "$(RESOURCE_ID)" || (echo "Error: RESOURCE_ID is required" && exit 1)
	$(DOCKER_GLORFINDEL) revert $(RESOURCE_ID) --yes

glorfindel-release: build
	@test -n "$(RESOURCE_ID)" || (echo "Error: RESOURCE_ID is required" && exit 1)
	$(DOCKER_GLORFINDEL) release $(RESOURCE_ID) --yes

glorfindel-check-ttl: build
	$(DOCKER_GLORFINDEL) check-ttl

glorfindel-start: build-glorfindel
	mkdir -p $(HOME)/.glorfindel $(HOME)/.cache/chroma runs
	docker compose up -d
	@echo ""
	@echo "  War Room  →  http://localhost:7007"
	@echo "  Logs      →  make glorfindel-logs"
	@echo "  Dev mode  →  make glorfindel-dev  (auto-reload on file change)"
	@echo "  Stop      →  make glorfindel-stop"
	@echo ""

glorfindel-stop:
	docker compose down

glorfindel-restart: build-glorfindel
	docker compose up -d --build --force-recreate
	@echo "  War Room  →  http://localhost:7007"

glorfindel-dev: build-glorfindel
	mkdir -p $(HOME)/.glorfindel $(HOME)/.cache/chroma runs
	docker compose up -d
	@echo "  War Room  →  http://localhost:7007  (watching for changes…)"
	docker compose watch

glorfindel-logs:
	docker compose logs -f

glorfindel-ui: build-glorfindel
	docker compose up -d --no-deps war-room
	@echo "  War Room  →  http://localhost:7007  (watch untouched)"

# ── Shells ────────────────────────────────────────────────────────────────

annatar-shell: build-annatar
	@mkdir -p $(HOME)/.annatar
	@touch $(HOME)/.annatar/.bashrc
	@grep -q "alias ar=" $(HOME)/.annatar/.bashrc || echo "alias ar='annatar'" >> $(HOME)/.annatar/.bashrc
	docker run --rm -it $(ANNATAR_AZURE_ENV) $(ANNATAR_VOLS) $(ANNATAR_STATE) \
		$(IMAGE_ANNATAR) bash --init-file /root/.annatar/.bashrc

glorfindel-shell: build-glorfindel
	@mkdir -p $(HOME)/.glorfindel
	@touch $(HOME)/.glorfindel/.bashrc
	@grep -q "alias gf=" $(HOME)/.glorfindel/.bashrc || echo "alias gf='glorfindel'" >> $(HOME)/.glorfindel/.bashrc
	docker run --rm -it $(GLORFINDEL_AZURE_ENV) $(GLORFINDEL_VOLS) $(GLORFINDEL_STATE) \
		$(GLORFINDEL_ENV) \
		$(IMAGE_GLORFINDEL) bash --init-file /root/.glorfindel/.bashrc

# ── Celebrimbor (infra Terraform) ──────────────────────────────────────────
# Apply/destroy interactifs (Terraform demande la confirmation = la revue du plan).
#   make celebrimbor-up                       # baseline (+ topos enabled:true du config)
#   make celebrimbor-up TOPO="multinic,aks"   # n'active QUE ces topos
#   make celebrimbor-up INSTANCE=ci-1234       # stack isolée (workspace dédié)
#   make celebrimbor-plan TOPO=multinic        # plan seul (lecture, pas d'apply)
#   make celebrimbor-stop / celebrimbor-start        # éteint/rallume les VMs sans détruire
#   make celebrimbor-output                    # fragment glorfindel-config.yaml généré
#
# ⚠ celebrimbor-down est GARDÉ (incident 2026-06-25 : un down non scopé a emporté tout
#   le baseline). Il est SYMÉTRIQUE de up et protège le baseline :
#   make celebrimbor-down TOPO=multinic        # destruction SCOPÉE de la/les topo(s) — baseline préservé
#   make celebrimbor-down CONFIRM=<instance>   # teardown TOTAL (baseline INCLUS) — confirmation obligatoire
#   Retirer une topo proprement = enabled:false dans config.yaml + celebrimbor-up (reconcile).
#   Convention : chaque topo doit définir `azurerm_resource_group.<topo>` (count) → la cible -target.

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
	   $(TF) apply -var="topo_filter=[$$filter]" --auto-approve; \
	 else \
	   $(TF) apply --auto-approve; \
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

celebrimbor-stop:
	@ids=$$(az vm list --query "[?tags.project=='celebrimbor' && tags.instance=='$(INSTANCE)'].id" -o tsv); \
	 [ -n "$$ids" ] && az vm deallocate --ids $$ids || echo "Aucune VM celebrimbor pour l'instance '$(INSTANCE)'"

celebrimbor-start:
	@ids=$$(az vm list --query "[?tags.project=='celebrimbor' && tags.instance=='$(INSTANCE)'].id" -o tsv); \
	 [ -n "$$ids" ] && az vm start --ids $$ids || echo "Aucune VM celebrimbor pour l'instance '$(INSTANCE)'"

# ── Dev ───────────────────────────────────────────────────────────────────

venv:
	python3 -m venv .venv

install: venv
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/ -v

test-unit:
	$(PYTHON) -m pytest tests/unit/ -v

lint:
	.venv/bin/ruff check .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/
