# Pinned Stratus Red Team binary + warmup assets (R2)

Annatar's second adapter toward a public attack library is **[Stratus Red Team](https://github.com/DataDog/stratus-red-team)**
(DataDog, Apache-2.0; issue #79, R2 — after R1 Atomic Red Team). Where Atomic runs a shell test
**inside a target VM**, Stratus attacks the **Azure control plane**: each technique provisions
its own prerequisites, detonates against the cloud API, and tears them down. Its activity shows
up in the **Azure Activity Log** (`azure_activity`, detection lot AL1); the real bench
measurement of that detection is **ID1 (#281)**, with Jonathan.

## We call Stratus — we never write offensive logic

The adapter [`annatar/engines/stratus.py`](../engines/stratus.py) is the *only* thing that
resolves a technique, and it only ever **invokes the pinned Stratus binary** by its own
technique id, phase by phase. We do not reimplement any attack. Stratus's own cycle maps onto
the injector interface:

| Stratus verb | injector phase | what it does |
|---|---|---|
| `warmup`   | prepare | provision the technique's prerequisites (Terraform) |
| `detonate` | inject  | perform the attack against the Azure control plane |
| `revert`   | revert  | undo the detonation (where the technique supports it) |
| `cleanup`  | clean up | destroy the prerequisites |

Every phase runs from an **armed Orodruin** and is **journaled before it runs and counted
against the contract cap** ([`annatar/executors/stratus_host.py`](../executors/stratus_host.py),
`Session.before_call`), exactly like the VM executor.

## Fail closed

The adapter refuses, before anything runs:

- a technique id not shaped `azure.<tactic>.<name>` — we run **Azure only** (aws/gcp/kubernetes
  ids, a path separator, an option-looking segment, never reach a process argv);
- a technique id **not on the catalog's closed allow-list** — the `engine: stratus` entries of
  [`technique_catalog.yaml`](../../technique_catalog.yaml) are the contract; an id Stratus knows
  but the catalog does not is not ours to run;
- a Stratus binary whose sha256 is not the one in [`PIN`](PIN) — checked at **every** run.

The **read-only Graph probe** a technique declares (`graph_probe`) verifies the initial state
before `detonate` and after `cleanup`. It is held to a **GET of a Microsoft Graph read path** —
the probe can only read the directory, never change it.

## Offline — Orodruin has no Internet

Orodruin has [no Internet egress](../../docs/design/orodruin-contract.md). Stratus's `warmup`
provisions with Terraform, which would otherwise fetch the Terraform binary and the
azurerm/azuread provider plugins. Both are **staged into the image and pinned** ([`PIN`](PIN)):

- the exact Terraform version Stratus auto-installs (`1.3.10`) is pre-installed under the
  run-scoped `HOME`, so Stratus finds it and never downloads one;
- the provider plugins each technique's `.terraform.lock.hcl` pins are staged into a filesystem
  mirror; the adapter points `terraform init` at them offline via `TF_CLI_CONFIG_FILE`
  (a `provider_installation { filesystem_mirror { … }; direct { exclude = ["*/*"] } }`) and
  `TF_PLUGIN_CACHE_DIR` (`annatar/engines/stratus.py::airgap_env`).

`make stratus-stage` (ID1) downloads the pinned binary + assets, verifies each sha256 against
[`PIN`](PIN), and lays them out for the image. The binary is never committed to the repository.
