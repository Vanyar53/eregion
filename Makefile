PYTHON := .venv/bin/python
PIP    := .venv/bin/pip

IMAGE_ANNATAR   := eregion-annatar
IMAGE_GLORFINDEL := eregion-glorfindel
SCENARIO ?= annatar/scenarios/azure/ransomware-vm.yaml
SIGNALS  ?= $(shell ls runs/*_signals.jsonl 2>/dev/null | tail -1)

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

.PHONY: help build build-annatar build-glorfindel \
	annatar-run annatar-dry-run annatar-validate annatar-list \
	glorfindel-respond glorfindel-dry-run glorfindel-watch \
	glorfindel-release glorfindel-revert glorfindel-list \
	glorfindel-pending glorfindel-check-ttl \
	glorfindel-start glorfindel-stop glorfindel-restart glorfindel-dev glorfindel-logs glorfindel-ui \
	annatar-shell glorfindel-shell \
	venv install test test-unit lint annatar-simulate annatar-simulate-gap clean

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
	@echo "Variables"
	@echo "  SCENARIO    Path to scenario YAML (default: $(SCENARIO))"
	@echo "  SIGNALS     Path to signals JSONL (default: latest in runs/)"
	@echo "  RESOURCE_ID Azure VM resource ID"
	@echo ""

# ── Build ─────────────────────────────────────────────────────────────────

build: build-annatar build-glorfindel

build-annatar:
	docker build -f annatar/Dockerfile -t $(IMAGE_ANNATAR) .

build-glorfindel:
	docker build -f glorfindel/Dockerfile -t $(IMAGE_GLORFINDEL) .

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
	docker run --rm -it $(ANNATAR_AZURE_ENV) $(ANNATAR_VOLS) $(ANNATAR_STATE) \
		$(IMAGE_ANNATAR) bash --init-file /root/.annatar/.bashrc

glorfindel-shell: build-glorfindel
	@mkdir -p $(HOME)/.glorfindel
	docker run --rm -it $(GLORFINDEL_AZURE_ENV) $(GLORFINDEL_VOLS) $(GLORFINDEL_STATE) \
		$(GLORFINDEL_ENV) \
		$(IMAGE_GLORFINDEL) bash --init-file /root/.glorfindel/.bashrc

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
