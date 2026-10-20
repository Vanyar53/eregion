# Vendored Atomic Red Team definitions (R1)

Annatar's first adapter toward a public attack library is **Atomic Red Team**
(decision of 2026-10-15; issue #65). This directory holds a **pinned, verbatim**
subset of [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team),
copied at the commit recorded in [`PIN`](PIN).

## Why the definitions live here

Orodruin — the host an injector runs from — has **no Internet egress**
([`docs/design/orodruin-contract.md`](../../docs/design/orodruin-contract.md)). Everything
an injector uses must already be inside the image that `make orodruin-push` loads. So the
atomics are vendored into the repo (and shipped by `COPY annatar/ annatar/` in
[`annatar/Dockerfile`](../Dockerfile)), not fetched at run time.

We vendor **only the techniques the catalog marks `implemented`** — the whole upstream tree
is large and mostly Windows.

## How they are run

The adapter [`annatar/engines/atomic.py`](../engines/atomic.py) is the *only* reader of these
files. For a given `engine_ref` (`"<technique>/<auto_generated_guid>"`) it:

1. loads `<technique>/<technique>.yaml` and finds the test by its `auto_generated_guid`;
2. refuses anything it will not run faithfully: a non-`linux` test, an executor other than
   `sh`/`bash`, a test with `dependencies` (prereqs), or an argument left unresolved;
3. substitutes the `input_arguments` defaults into `command` and `cleanup_command`;
4. runs both in the enrolled target VM through Azure Run Command — every call journaled and
   capped by the Orodruin contract (`AzureVMExecutor._before_call`).

We do **not** run the upstream `invoke-atomicredteam` runner, and we never edit the vendored
files. The experiment YAML that points at a test lives in
[`annatar/scenarios/azure/`](../scenarios/azure/) as an `engine: atomic` experiment (schema
E1); its `steady_state` probes verify the initial state before the attack and that cleanup
restored it after.

## Updating or adding a technique

1. Pick a new upstream commit. Re-fetch the technique file at that commit and replace it here.
2. Bump the commit + date in [`PIN`](PIN) and list any newly vendored technique.
3. Keep [`LICENSE.atomic-red-team`](LICENSE.atomic-red-team) alongside the files (MIT requires it).
4. Add an `engine: atomic` experiment and run it on the bench before relying on it.
