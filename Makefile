IMAGE    := eregion
SCENARIO ?= scenarios/azure/ransomware-vm.yaml
SIGNALS  ?= $(shell ls runs/*_signals.jsonl 2>/dev/null | tail -1)

AZURE_ENV := \
	-e AZURE_CLIENT_ID \
	-e AZURE_CLIENT_SECRET \
	-e AZURE_TENANT_ID \
	-e AZURE_SUBSCRIPTION_ID

GLORFINDEL_STATE := \
	-v $(HOME)/.glorfindel:/root/.glorfindel

COMMON_VOLS := \
	-v $(PWD)/scenarios:/app/scenarios \
	-v $(PWD)/scripts:/app/scripts \
	-v $(PWD)/runs:/app/runs

DOCKER_ANNATAR := docker run --rm $(AZURE_ENV) $(COMMON_VOLS) --entrypoint annatar $(IMAGE)
DOCKER_GLORFINDEL := docker run --rm $(AZURE_ENV) $(COMMON_VOLS) $(GLORFINDEL_STATE) \
	-e ANTHROPIC_API_KEY \
	-e GLORFINDEL_WEBHOOK_URL \
	-e GLORFINDEL_ISOLATION_TTL_H \
	-e GLORFINDEL_INCIDENT_TTL_S \
	--entrypoint glorfindel $(IMAGE)

.PHONY: help build \
	annatar-run annatar-dry-run annatar-validate annatar-list \
	glorfindel-respond glorfindel-dry-run glorfindel-watch \
	glorfindel-release glorfindel-revert glorfindel-list \
	glorfindel-pending glorfindel-check-ttl \
	test test-unit lint simulate simulate-gap clean

# ── Help ──────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "Eregion $(shell cat pyproject.toml | grep '^version' | cut -d'"' -f2)"
	@echo ""
	@echo "Dev (local, no Docker)"
	@echo "  make install        Install with dev dependencies"
	@echo "  make test           Run all tests (88, 0 Azure, 0 Claude API)"
	@echo "  make lint           Ruff linter"
	@echo "  make simulate       Simulate Annatar locally (no Azure)"
	@echo "  make simulate-gap   Simulate detection_timeout flow"
	@echo "  make clean          Remove build artifacts"
	@echo ""
	@echo "Build"
	@echo "  make build          Build Docker image"
	@echo ""
	@echo "Annatar (Docker)"
	@echo "  make annatar-run    SCENARIO=... Run scenario (--yes)"
	@echo "  make annatar-dry-run            Run scenario (--dry-run)"
	@echo "  make annatar-validate           Validate scenario YAML"
	@echo "  make annatar-list               List available scenarios"
	@echo ""
	@echo "Glorfindel (Docker)"
	@echo "  make glorfindel-watch           Watch runs/ in real-time"
	@echo "  make glorfindel-respond         SIGNALS=... Process signal file"
	@echo "  make glorfindel-dry-run         SIGNALS=... Dry-run (no actions)"
	@echo "  make glorfindel-list            Show active isolations + blocks"
	@echo "  make glorfindel-pending         Show pending escalations"
	@echo "  make glorfindel-revert          RESOURCE_ID=... Release + unblock all"
	@echo "  make glorfindel-release         RESOURCE_ID=... Release isolation only"
	@echo "  make glorfindel-check-ttl       Release expired isolations (TTL)"
	@echo ""
	@echo "Variables"
	@echo "  SCENARIO    Path to scenario YAML (default: $(SCENARIO))"
	@echo "  SIGNALS     Path to signals JSONL (default: latest in runs/)"
	@echo "  RESOURCE_ID Azure VM resource ID"
	@echo ""

# ── Build ─────────────────────────────────────────────────────────────────

build:
	docker build -t $(IMAGE) .

# ── Annatar ───────────────────────────────────────────────────────────────

annatar-run: build
	$(DOCKER_ANNATAR) run $(SCENARIO) --yes

annatar-dry-run: build
	$(DOCKER_ANNATAR) run $(SCENARIO) --dry-run --yes

annatar-validate:
	docker run --rm -v $(PWD)/scenarios:/app/scenarios --entrypoint annatar $(IMAGE) validate $(SCENARIO)

annatar-list:
	docker run --rm -v $(PWD)/scenarios:/app/scenarios --entrypoint annatar $(IMAGE) list

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

# ── Dev ───────────────────────────────────────────────────────────────────

install:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/unit/ -v

lint:
	ruff check .

simulate:
	python scripts/simulate_annatar.py

simulate-gap:
	python scripts/simulate_annatar.py --ids-gap

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/
