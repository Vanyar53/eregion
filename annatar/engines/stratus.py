"""Stratus Red Team adapter (R2): invoke a PINNED Stratus binary by technique id to drive the
warmup → detonate → revert → cleanup cycle on the enrolled bench — no home-grown offensive
logic. The adapter never writes an attack: it resolves a technique id against a CLOSED
allow-list (the catalog's ``engine: stratus`` entries) and, for a resolved technique, hands the
runner the exact argv of each phase of Stratus's own cycle. An injector runs those phases from
an armed Orodruin, every phase journaled and capped by the contract
(``annatar/executors/stratus_host.py``).

Where the Atomic adapter (``annatar/engines/atomic.py``) runs a shell test inside a target VM,
Stratus attacks the Azure control plane: each technique provisions its own prerequisites,
detonates against the cloud API and tears them down. Its activity shows in the Azure Activity
Log (detection lot AL1); the real bench run is ID1 (#281).

Fail closed, like the Atomic adapter:
  - a technique id not shaped ``azure.<tactic>.<name>`` is refused — we run only Azure
    control-plane techniques (an aws/gcp/kubernetes id, a path separator, an option-looking
    segment, never reach a process argv);
  - a technique id not on the catalog's closed allow-list is refused (the catalog is the
    contract; an id Stratus knows but the catalog does not is not ours to run);
  - the Stratus binary is checked against its sha256 in ``annatar/stratus/PIN`` at resolve time,
    and the injector (annatar/executors/stratus_host.py) re-checks it BEFORE EVERY phase (not
    only once per run): a binary that is not the pinned one, or one swapped mid-run, runs
    nothing. We pin the binary we exec; the upstream archive's published sha256 sits beside it
    as provenance (annatar/stratus/PIN);
  - the read-only Graph probe a technique declares is held to a GET of a Microsoft Graph read
    path — never a write — so verifying the initial state can only read the directory.

Orodruin has no Internet (docs/design/orodruin-contract.md). Stratus's ``warmup`` provisions
with Terraform, which would otherwise download the Terraform binary and the provider plugins.
Both are staged into the image and pinned (annatar/stratus/PIN); ``airgap_env`` points Stratus
at them offline (a run-scoped ``HOME`` with the pre-installed Terraform, a filesystem mirror of
the providers and the plugin cache), so ``terraform init`` never reaches the network.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

STRATUS_DIR = Path(__file__).resolve().parents[1] / "stratus"

# We run Azure only (the control plane). A Stratus technique id is ``platform.tactic.name``,
# each of platform/tactic/name a lower-case word of [a-z0-9] with '-' between inner words.
_TECHNIQUE_ID = re.compile(r"^azure\.[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*$")

# The cycle, in order — Stratus's own verbs, mapped onto the injector interface
# (prepare, inject, revert, clean up). ``cleanup`` always runs last, whatever the rest did.
PHASES = ("warmup", "detonate", "revert", "cleanup")

# A PIN line: "#   <sha256>  <label>" (same shape as annatar/atomics/PIN).
_PIN_LINE = re.compile(r"^#\s+([0-9a-f]{64})\s+(\S+)\s*$")
# The label of the binary the adapter execs; the other PIN lines are provenance / staging.
BINARY_LABEL = "stratus"

# A Microsoft Graph read path a probe may name: a v1.0 path (optionally with a query), fetched
# with GET only. The read-only guarantee is the GET method the executor hard-codes; this just
# pins Graph v1.0 and rejects anything malformed — no scheme, no host, no whitespace, no
# control character — so a probe can only read the directory.
_GRAPH_READ = re.compile(r"^/v1\.0/[A-Za-z0-9$()',./_=&?:@%+-]+$")


class StratusError(ValueError):
    """The technique cannot be run faithfully — refused before anything runs."""


@dataclass
class GraphProbe:
    """A read-only Microsoft Graph check of the initial state, run before ``detonate`` and after
    ``cleanup``. ``read`` is a Graph v1.0 path fetched with GET; ``expect_absent`` says the
    initial state is the target NOT existing (an empty listing) — the technique creates it, the
    cleanup removes it. Held to a read path, so the probe can only read."""

    name: str
    read: str
    expect_absent: bool = True

    def request(self) -> tuple[str, str]:
        """``(method, path)`` — always GET; raises if ``read`` is not a Graph read path."""
        if not _GRAPH_READ.fullmatch(self.read or ""):
            raise StratusError(
                f"graph probe {self.name!r}: {self.read!r} is not a Microsoft Graph v1.0 read "
                "path — a probe can only read the directory (GET), never change it"
            )
        return "GET", self.read

    def holds(self, body: dict) -> bool:
        """Does the initial state hold, given the Graph answer? An empty ``value`` list (or no
        object) means the target is absent; a non-empty one means it is present."""
        value = body.get("value") if isinstance(body, dict) else None
        present = bool(value) if isinstance(value, list) else bool(body)
        return (not present) if self.expect_absent else present


@dataclass
class StratusPhase:
    """One phase of the cycle, resolved to the exact process argv the injector will run."""

    name: str
    argv: list[str]
    label: str


@dataclass
class ResolvedTechnique:
    """One Stratus technique, resolved to the phases the runner will invoke and its read-only
    initial-state probe — ready to run, or refused."""

    technique_id: str
    tactic: str
    ttp: str
    name: str
    binary_digest: str
    phases: list[StratusPhase] = field(default_factory=list)
    graph_probe: GraphProbe | None = None

    def phase(self, name: str) -> StratusPhase:
        for p in self.phases:
            if p.name == name:
                return p
        raise StratusError(f"no phase {name!r} in {self.technique_id}")


def pinned_digests(stratus_dir: Path | None = None) -> dict[str, str]:
    """``{label: sha256}`` as ``PIN`` records them — ``{}`` when there is no PIN."""
    stratus_dir = stratus_dir or STRATUS_DIR
    try:
        text = (stratus_dir / "PIN").read_text(encoding="utf-8")
    except OSError:
        return {}
    return {m.group(2): m.group(1) for m in map(_PIN_LINE.match, text.splitlines()) if m}


def verify_binary(binary_path: str | Path, stratus_dir: Path | None = None) -> str:
    """The sha256 of the staged Stratus binary, checked against ``annatar/stratus/PIN`` at run
    time (SEC5): a binary that is not the pinned one refuses before any phase runs. Returns the
    digest."""
    path = Path(binary_path)
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise StratusError(
            f"the Stratus binary at {path} cannot be read ({type(e).__name__}) — not run; stage "
            "it into the Orodruin image (annatar/stratus/README.md)"
        ) from e
    pinned = pinned_digests(stratus_dir).get(BINARY_LABEL)
    if pinned is None:
        raise StratusError(
            f"annatar/stratus/PIN records no sha256 for the Stratus binary ({BINARY_LABEL!r}) "
            "— not run"
        )
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pinned:
        raise StratusError(
            "the Stratus binary does not match its sha256 in annatar/stratus/PIN — not the "
            "pinned binary (v2.38.0); not run"
        )
    return digest


def _stratus_entries(catalog: dict | None = None) -> dict[str, dict]:
    """``{engine_ref: entry}`` for every catalog technique on the ``stratus`` engine — the
    closed allow-list. Loads the shared catalog when none is given (best effort: ``{}``)."""
    if catalog is None:
        from annatar.campaign.catalog import load_catalog
        catalog = load_catalog()
    out: dict[str, dict] = {}
    for entry in catalog.values():
        if entry.get("engine") == "stratus" and entry.get("engine_ref"):
            out[str(entry["engine_ref"])] = entry
    return out


def allowed_techniques(catalog: dict | None = None) -> set[str]:
    """The closed allow-list: the Stratus technique ids the catalog vouches for (fail closed on
    the rest)."""
    return set(_stratus_entries(catalog))


def _graph_probe(entry: dict) -> GraphProbe | None:
    """The entry's read-only initial-state probe, or ``None``. Its shape is held (fail closed):
    a mapping with a ``name`` and a ``read`` path, an optional boolean ``expect_absent``."""
    spec = entry.get("graph_probe")
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise StratusError("graph_probe must be a mapping (name, read, expect_absent)")
    name, read = spec.get("name"), spec.get("read")
    if not isinstance(name, str) or not name.strip():
        raise StratusError("graph_probe needs a name")
    if not isinstance(read, str) or not read.strip():
        raise StratusError(f"graph_probe {name!r} needs a Graph v1.0 read path")
    absent = spec.get("expect_absent", True)
    if not isinstance(absent, bool):
        raise StratusError(f"graph_probe {name!r}: expect_absent must be true or false")
    probe = GraphProbe(name=name.strip(), read=read.strip(), expect_absent=absent)
    probe.request()   # hold it to a read path now (fail closed before any run)
    return probe


def _lookup(technique_id: str, catalog: dict | None) -> tuple[str, dict]:
    """``(technique_id, entry)`` for a technique on the closed allow-list — the two fail-closed
    checks shared by ``resolve`` and ``describe``: the id is an Azure Stratus id, and it is one
    the catalog vouches for. Raises ``StratusError`` otherwise, before anything runs."""
    tid = (technique_id or "").strip()
    if not _TECHNIQUE_ID.fullmatch(tid):
        raise StratusError(
            f"technique id {technique_id!r} is not an Azure Stratus id 'azure.<tactic>.<name>' "
            "(lower-case, dot-separated) — refused, never sent to a process"
        )
    entries = _stratus_entries(catalog)
    entry = entries.get(tid)
    if entry is None:
        raise StratusError(
            f"technique {tid!r} is not on the catalog's closed allow-list "
            f"({sorted(entries) or '(none)'}) — not ours to run"
        )
    return tid, entry


def resolve(technique_id: str, *, binary_path: str | Path,
            stratus_dir: Path | None = None, catalog: dict | None = None) -> ResolvedTechnique:
    """Resolve a Stratus technique id to the phases to run — or refuse (fail closed).

    ``binary_path`` is the staged Stratus binary; its sha256 is checked against the PIN here,
    so a resolved technique already carries a verified binary."""
    tid, entry = _lookup(technique_id, catalog)
    digest = verify_binary(binary_path, stratus_dir)
    binary = str(binary_path)
    phases = [
        StratusPhase(name=name, argv=[binary, name, tid], label=f"stratus {name} {tid}")
        for name in PHASES
    ]
    return ResolvedTechnique(
        technique_id=tid,
        tactic=str(entry.get("tactic") or ""),
        ttp=str(entry.get("ttp") or ""),
        name=str(entry.get("name") or tid),
        binary_digest=digest,
        phases=phases,
        graph_probe=_graph_probe(entry),
    )


def describe(technique_id: str, *, catalog: dict | None = None) -> dict:
    """What a dry run shows, from the catalog alone — no binary check, no process. Raises
    ``StratusError`` if the id is not on the closed allow-list (the same fail-closed checks)."""
    tid, entry = _lookup(technique_id, catalog)
    return {
        "technique_id": tid,
        "ttp": str(entry.get("ttp") or ""),
        "tactic": str(entry.get("tactic") or ""),
        "name": str(entry.get("name") or tid),
        "phases": list(PHASES),
        "graph_probe": _graph_probe(entry),
    }


def airgap_env(home: str | Path, *, plugin_cache: str | Path | None = None,
               terraformrc: str | Path | None = None) -> dict[str, str]:
    """The offline environment Stratus runs its warmup Terraform with — no network.

    ``home`` is a run-scoped ``HOME``: Stratus writes its state under ``<home>/.stratus-red-team``
    and finds the pre-installed Terraform there (pkg/stratus/config: ``os.UserHomeDir()``), so it
    never downloads one. ``plugin_cache`` (``TF_PLUGIN_CACHE_DIR``) and ``terraformrc``
    (``TF_CLI_CONFIG_FILE``, a filesystem mirror of the providers excluding direct installs) keep
    ``terraform init`` off the network. Stratus passes the inherited environment through to
    Terraform (pkg/stratus/runner/terraform.go), so these reach ``terraform init``; it drops the
    reserved ``TF_IN_AUTOMATION`` and the like, which tfexec sets itself.

    These are overrides layered over the process environment (the Azure credentials of Orodruin's
    identity stay); the injector merges them (annatar/executors/stratus_host.py)."""
    env = {"HOME": str(home)}
    if plugin_cache is not None:
        env["TF_PLUGIN_CACHE_DIR"] = str(plugin_cache)
    if terraformrc is not None:
        env["TF_CLI_CONFIG_FILE"] = str(terraformrc)
    return env
