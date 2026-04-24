IMAGE   := annatar
SCENARIO ?= scenarios/azure/ransomware-vm.yaml

AZURE_ENV := \
	-e AZURE_CLIENT_ID \
	-e AZURE_CLIENT_SECRET \
	-e AZURE_TENANT_ID \
	-e AZURE_SUBSCRIPTION_ID

DOCKER_RUN := docker run --rm $(AZURE_ENV) \
	-v $(PWD)/scenarios:/app/scenarios \
	-v $(PWD)/scripts:/app/scripts \
	$(IMAGE)

.PHONY: annatar-build annatar-run annatar-dry-run annatar-validate annatar-list

annatar-build:
	docker build -t $(IMAGE) .

annatar-run: annatar-build
	$(DOCKER_RUN) run $(SCENARIO) --yes

annatar-dry-run: annatar-build
	$(DOCKER_RUN) run $(SCENARIO) --dry-run --yes

annatar-validate:
	docker run --rm \
		-v $(PWD)/scenarios:/app/scenarios \
		$(IMAGE) validate $(SCENARIO)

annatar-list:
	docker run --rm \
		-v $(PWD)/scenarios:/app/scenarios \
		$(IMAGE) list
