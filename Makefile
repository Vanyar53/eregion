IMAGE    := eregion
SCENARIO ?= scenarios/azure/ransomware-vm.yaml

AZURE_ENV := \
	-e AZURE_CLIENT_ID \
	-e AZURE_CLIENT_SECRET \
	-e AZURE_TENANT_ID \
	-e AZURE_SUBSCRIPTION_ID

COMMON_VOLS := \
	-v $(PWD)/scenarios:/app/scenarios \
	-v $(PWD)/scripts:/app/scripts \
	-v $(PWD)/runs:/app/runs

DOCKER_ANNATAR := docker run --rm $(AZURE_ENV) $(COMMON_VOLS) --entrypoint annatar $(IMAGE)
DOCKER_GLORFINDEL := docker run --rm $(AZURE_ENV) $(COMMON_VOLS) \
	-e ANTHROPIC_API_KEY \
	--entrypoint glorfindel $(IMAGE)

.PHONY: build \
	annatar-run annatar-dry-run annatar-validate annatar-list \
	glorfindel-respond glorfindel-dry-run glorfindel-release \
	test

build:
	docker build -t $(IMAGE) .

# ── Annatar ───────────────────────────────────────────────────────────────────

annatar-run: build
	$(DOCKER_ANNATAR) run $(SCENARIO) --yes

annatar-dry-run: build
	$(DOCKER_ANNATAR) run $(SCENARIO) --dry-run --yes

annatar-validate:
	docker run --rm -v $(PWD)/scenarios:/app/scenarios --entrypoint annatar $(IMAGE) validate $(SCENARIO)

annatar-list:
	docker run --rm -v $(PWD)/scenarios:/app/scenarios --entrypoint annatar $(IMAGE) list

# ── Glorfindel ────────────────────────────────────────────────────────────────

glorfindel-respond: build
	$(DOCKER_GLORFINDEL) respond $(SIGNALS)

glorfindel-dry-run: build
	$(DOCKER_GLORFINDEL) respond $(SIGNALS) --dry-run

glorfindel-release: build
	$(DOCKER_GLORFINDEL) release $(RESOURCE_ID)

# ── Dev ───────────────────────────────────────────────────────────────────────

test:
	python -m pytest tests/ -v
