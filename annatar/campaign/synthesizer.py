"""Synthesizer — materialize a schema-valid scenario YAML from a catalog technique.

Deterministic by design (Q2 answer): the *creativity* lives in the planner (which
techniques, what order); the synthesizer only assembles a vetted attack from the
catalog entry and refuses anything unsafe. The **engine of the entry decides** how it is
materialized, and an entry never falls back to another engine:

  - ``engine: atomic`` (R1) ⇒ an E1 experiment with NO steps; the attack is a pinned
    Atomic Red Team test, resolved at plan time against the vendored atomics
    (``annatar/engines/atomic.py``, ``resolve_ref``). An ``engine_ref`` that is unknown or
    refused by the adapter, or an entry with no steady-state probes, is NOT synthesized.
  - ``local-script`` (or absent) ⇒ today's script-driven scenario. It NEVER writes inline
    shell — it references only existing ``scripts/vm/`` scripts.

Shared guards: the catalog entry exists and ``status == implemented``; destructive ⇒
``budget.allow_destructive`` and a ``safe_target`` (checked before the engine dispatch); the
target resource is inside the campaign scope (hard allowlist); the produced YAML is what the
run accepts (``ScenarioParser().validate``, plus the atomic engine's probe check for an
atomic). Script-only guards: ``reference_script``/``setup_scripts`` exist on disk;
destructive + ``requires_testdata`` ⇒ setup_scripts non-empty.

No ``jsonschema`` at plan time: the synthesizer runs in the Orodruin image, which ships
neither ``jsonschema`` nor ``schemas/`` (schema validation is a dev/CI concern,
``eregion_core/experiment.py``). The tests check that what it writes passes the E1 schema.

A failure yields ``SynthesisResult(ok=False, reason=...)`` — the scenario is not written
(and a file written before a failed or raising validation is removed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from annatar.campaign.scope import Scope
from annatar.runner.parser import ScenarioParser

# Repo root = parents[2] of annatar/campaign/synthesizer.py
REPO_ROOT = Path(__file__).resolve().parents[2]

# Detection-window margin added on top of the catalog's P99 latency.
_LATENCY_MARGIN_S = 120

# Per-log-source detection-window floor (seconds): a window must NEVER be shorter
# than the empirical P99 ingestion latency for its source, or a slow-but-correct
# detection is mislabelled "missed" (→ spurious rule proposals). DCR-backed Syslog
# is nominally ~60s but spikes past 300s; the curated Syslog rules encode this as
# expected_latency_s: 480. A catalog entry with an optimistic latency (e.g. 120s →
# 240s window) would open a window below that floor — clamp it. See CLAUDE.md
# ("Syslog latence ~60s nominal") and the 2026-07-30 e2e finding.
_WINDOW_FLOOR_S = {
    "Syslog": 480,
}


@dataclass
class SynthesisResult:
    ok: bool
    reason: str = ""
    path: Path | None = None
    scenario: dict | None = None


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "scenario"


def _script_exists(rel: str) -> bool:
    return (REPO_ROOT / rel).is_file()


def _rg_and_vm(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    rg = vm = ""
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            rg = parts[i + 1]
    if parts:
        vm = parts[-1]
    return rg, vm


def synthesize(
    *,
    entry: dict[str, Any],
    target_resource_id: str,
    scope: Scope,
    out_dir: str | Path,
    seq: int = 1,
    allow_destructive: bool = False,
) -> SynthesisResult:
    """Materialize one scenario YAML for ``entry`` against ``target_resource_id``.

    ``entry`` is a technique-catalog entry (with ``resource_type`` merged in).
    ``out_dir`` is the campaign ``scenarios/`` directory.
    """
    ttp = entry.get("ttp", "")

    # 1. implemented-only
    if entry.get("status") != "implemented":
        return SynthesisResult(False, f"{ttp}: status != implemented — not synthesizable")

    # The engine of the entry decides how it is materialized — and it never falls back to
    # another engine (the catalog's engine is authoritative, even if a reference_script
    # lingers on an atomic entry for history).
    engine = entry.get("engine") or "local-script"

    # destructive guardrail — shared by every engine, BEFORE the dispatch: an atomic marked
    # destructive needs budget.allow_destructive and a safe_target exactly like a script.
    destructive = bool(entry.get("destructive"))
    safe_target = entry.get("safe_target") or ""
    if destructive:
        if not allow_destructive:
            return SynthesisResult(False, f"{ttp}: destructive but budget.allow_destructive is false")
        if not safe_target:
            return SynthesisResult(False, f"{ttp}: destructive without safe_target — refused")

    if engine == "atomic":
        return _synthesize_atomic(
            entry=entry, target_resource_id=target_resource_id, scope=scope,
            out_dir=out_dir, seq=seq,
        )
    if engine != "local-script":
        return SynthesisResult(
            False, f"{ttp}: engine {engine!r} is not synthesizable (local-script or atomic)"
        )

    # 2/3. scripts must exist on disk (no inline shell, ever)
    ref = entry.get("reference_script")
    if not ref:
        return SynthesisResult(False, f"{ttp}: no reference_script")
    if not _script_exists(ref):
        return SynthesisResult(False, f"{ttp}: reference_script not found: {ref}")
    setup_scripts = list(entry.get("setup_scripts") or [])
    for s in setup_scripts:
        if not _script_exists(s):
            return SynthesisResult(False, f"{ttp}: setup_script not found: {s}")

    # 4. destructive testdata (the allow_destructive/safe_target guard ran before the dispatch)
    if destructive and entry.get("requires_testdata") and not setup_scripts:
        return SynthesisResult(
            False, f"{ttp}: requires_testdata but no setup_scripts to provision it"
        )

    # 5. scope (hard allowlist)
    rg, vm = _rg_and_vm(target_resource_id)
    guard = scope.check(target_resource_id, rg)
    if not guard.allowed:
        return SynthesisResult(False, f"{ttp}: out of scope — {guard.reason}")
    if not vm:
        return SynthesisResult(False, f"{ttp}: cannot derive vm_name from {target_resource_id}")

    # ── build the scenario dict (schema: name/description/mitre/target/steps) ──
    timeout_s = _detection_timeout(entry)
    name = entry.get("name", ttp)
    scenario: dict[str, Any] = {
        "name": f"campaign-{_slug(ttp)}-{_slug(name)}"[:80],
        "description": f"{ttp} — {name} (generated by Annatar campaign — proposition)",
        "mitre": ttp,
        "version": "1.0.0",
        "target": {
            # Schema currently only admits azure_vm; Storage/Entra targets need a
            # schema extension before they become synthesizable (catalog notes this).
            "type": "azure_vm",
            "resource_group": rg,
            "vm_name": vm,
        },
        "steps": [
            {
                "name": f"execute-{_slug(ttp)}",
                "action": "run_script_on_vm",
                "script": ref,
                "record": "T0",
            }
        ],
        "detection": {
            "timeout": f"{timeout_s}s",
            "hints": _build_hints(entry),
        },
    }
    if setup_scripts:
        scenario["setup"] = [
            {
                "name": f"setup-{i}-{Path(s).stem}",
                "action": "run_script_on_vm",
                "script": s,
            }
            for i, s in enumerate(setup_scripts, 1)
        ]

    # normalize target.type: schema currently only allows azure_vm
    scenario["target"]["type"] = "azure_vm"

    # 6. write + final schema validation
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fname = f"{seq:02d}-{ttp}-{_slug(name)}.yaml"
    path = out / fname
    path.write_text(
        yaml.safe_dump(
            scenario, sort_keys=False, default_flow_style=False, allow_unicode=True
        )
    )

    res = ScenarioParser().validate(str(path))
    if not res.valid:
        path.unlink(missing_ok=True)
        return SynthesisResult(False, f"{ttp}: produced YAML failed schema: {res.errors}")

    return SynthesisResult(True, path=path, scenario=scenario)


def _detection_timeout(entry: dict[str, Any]) -> int:
    """Detection window (seconds): the catalog P99 latency plus a margin, never below the
    per-log-source floor (a slow-but-correct detection must not be mislabelled 'missed')."""
    latency = int(entry.get("expected_latency_s") or 300)
    log_source = entry.get("log_source", "")
    return max(latency + _LATENCY_MARGIN_S, _WINDOW_FLOOR_S.get(log_source, 0))


def _synthesize_atomic(
    *,
    entry: dict[str, Any],
    target_resource_id: str,
    scope: Scope,
    out_dir: str | Path,
    seq: int,
) -> SynthesisResult:
    """Materialize an ``engine: atomic`` entry (R1) as an E1 experiment with NO steps.

    The attack is a pinned Atomic Red Team test named by ``engine_ref``; the runner plays it
    through the atomic engine (Orodruin contract, exercise window, steady-state probes before
    and after, return channel). We refuse here — nothing is written — what the run could not
    play faithfully: a missing/invalid ``engine_ref``, an entry with no steady-state probes, or
    a ref the adapter (``annatar/engines/atomic.py``) cannot resolve. The engine_ref is resolved
    AT PLAN TIME, so an unknown test never reaches a run.
    """
    from annatar.engines.atomic import AtomicError, resolve_ref
    from annatar.runner.engine import Engine

    ttp = entry.get("ttp", "")

    # engine_ref required (an atomic is named by its test)
    engine_ref = entry.get("engine_ref")
    if not engine_ref:
        return SynthesisResult(False, f"{ttp}: engine 'atomic' requires an engine_ref")

    # steady-state probes required, each with a non-empty verify + expect — the initial state
    # is verified before and after. The check is the atomic engine's own
    # (Engine._atomic_probe_error), applied to the entry: the plan refuses what the run would.
    probe_error = Engine._atomic_probe_error(SimpleNamespace(raw=entry))
    if probe_error:
        return SynthesisResult(False, f"{ttp}: {probe_error}")
    probes = (entry.get("steady_state") or {}).get("probes") or []

    # resolve the ref against the vendored atomics — an unknown or refused test is NOT
    # synthesized (fail closed, at plan time).
    try:
        resolve_ref(engine_ref)
    except AtomicError as e:
        return SynthesisResult(False, f"{ttp}: engine_ref unresolved — {e}")

    # scope (hard allowlist)
    rg, vm = _rg_and_vm(target_resource_id)
    guard = scope.check(target_resource_id, rg)
    if not guard.allowed:
        return SynthesisResult(False, f"{ttp}: out of scope — {guard.reason}")
    if not vm:
        return SynthesisResult(False, f"{ttp}: cannot derive vm_name from {target_resource_id}")

    name = entry.get("name", ttp)
    timeout_s = _detection_timeout(entry)
    experiment: dict[str, Any] = {
        "schema_version": "1",
        "kind": "technique",
        "engine": "atomic",
        "engine_ref": engine_ref,
        "name": f"campaign-{_slug(ttp)}-{_slug(name)}"[:80],
        "description": f"{ttp} — {name} (generated by Annatar campaign — proposition)",
        "mitre": ttp,
        "version": "1.0.0",
        "destructive": bool(entry.get("destructive")),
        "target": {
            "type": "azure_vm",
            "resource_group": rg,
            "vm_name": vm,
        },
        "steady_state": {"probes": [dict(p) for p in probes]},
        "detection": {
            "timeout": f"{timeout_s}s",
            "hints": _build_hints(entry),
        },
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{seq:02d}-{ttp}-{_slug(name)}.yaml"
    path.write_text(
        yaml.safe_dump(
            experiment, sort_keys=False, default_flow_style=False, allow_unicode=True
        )
    )

    # Validate the produced experiment the way the run will read it — the ScenarioParser plus
    # the atomic engine's probe check — never with jsonschema: schema validation is a dev/CI
    # concern (eregion_core/experiment.py), and the Orodruin image ships neither jsonschema
    # nor schemas/. The E1 schema itself is checked by the tests. Nothing is left behind when
    # the validation fails OR raises: no half-planned file without its manifest.
    try:
        errors = _runtime_atomic_errors(path)
    except Exception as e:  # noqa: BLE001 — any failure here means "not synthesized"
        path.unlink(missing_ok=True)
        return SynthesisResult(False, f"{ttp}: produced experiment could not be validated — {e}")
    if errors:
        path.unlink(missing_ok=True)
        return SynthesisResult(False, f"{ttp}: produced experiment is invalid: {errors}")

    return SynthesisResult(True, path=path, scenario=experiment)


def _runtime_atomic_errors(path: Path) -> list[str]:
    """What the run would refuse in this experiment file ([] if it would play it): the
    ScenarioParser's validation, then the atomic engine's probe check on the loaded
    scenario. No jsonschema — the injector image does not depend on it at run time."""
    from annatar.runner.engine import Engine

    parser = ScenarioParser()
    res = parser.validate(str(path))
    if not res.valid:
        return list(res.errors)
    probe_error = Engine._atomic_probe_error(parser.load(str(path)))
    return [probe_error] if probe_error else []


def _build_hints(entry: dict[str, Any]) -> dict[str, Any]:
    """Build detection.hints from the catalog blue block (feeds propose_detection_rule
    only if the attack is MISSED — Annatar's own scenario metadata, not an announcement)."""
    cols = entry.get("indicator_columns") or []
    via = (
        f"atomic {entry.get('engine_ref')}"
        if (entry.get("engine") or "local-script") == "atomic"
        else entry.get("reference_script")
    )
    hints: dict[str, Any] = {
        "log_source": entry.get("log_source", ""),
        "attack_commands_summary": (
            f"Generated campaign step for {entry.get('ttp')} "
            f"({entry.get('name', '')}) via {via}."
        ),
    }
    if cols:
        src = entry.get("log_source", "")
        hints["expected_indicators"] = [f"{src}: column {c}" for c in cols]
    return hints
