"""Grounded detection-rule authoring engine.

This is the blue half of the generative purple loop (see
collab/design_generative_purple_loop.md). It turns detection from a hand-written
artifact into a *generated* one — while keeping the runtime deterministic.

Two callers share one grounded LLM call:
  - REACTIVE  : the ``propose_detection_rule`` node, after a ``detection_missed``
                signal (an attack that fired but no rule caught it).
  - PROACTIVE : ``glorfindel propose-rules`` — cold-start authoring for catalog
                techniques that have no detection rule yet (no attack required).

"Grounded" means the LLM is anchored on real facts, not free invention:
  1. the technique catalog entry (``technique_catalog.yaml``) — ``log_source``,
     ``indicator_columns``, ``expected_latency_s`` — the blue contract figé with Annatar;
  2. the REAL schema of the target LAW table (KQL ``getschema``), so the authored
     query references columns that actually exist instead of hallucinated ones.

INVARIANT (non-negotiable): the output is always a PROPOSAL. It is persisted via
``proposed_rules.record`` / surfaced as an escalation, and only enters the
deterministic ``RulePoller`` runtime after human (or, in sandbox, auto) approval.
No LLM ever sits on the detection hot-path.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger("glorfindel.detection_authoring")


# ── Query-language map (per monitoring source) ───────────────────────────────────
# Mirrors agent._SOURCE_LANGUAGES; kept here so the authoring engine stands alone.
SOURCE_LANGUAGES: dict[str, str] = {
    "azure_monitor": "KQL (Kusto Query Language)",
    "prometheus": "PromQL",
    "splunk": "SPL (Splunk Processing Language)",
    "datadog": "Datadog Query Language",
    "elasticsearch": "EQL / Lucene",
    "loki": "LogQL",
    "cloudwatch": "CloudWatch Logs Insights",
    "sentinel": "KQL (Microsoft Sentinel)",
}


# ── Technique catalog (shared contract with Annatar) ─────────────────────────────

def _catalog_candidates(path: str | Path | None) -> list[Path]:
    if path:
        return [Path(path)]
    return [
        Path("technique_catalog.yaml"),                       # cwd (repo root)
        Path(__file__).resolve().parent.parent / "technique_catalog.yaml",
        Path("glorfindel/technique_catalog.yaml"),
    ]


def load_catalog(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load ``technique_catalog.yaml`` → ``{ttp: entry}`` (resource_type merged in).

    Best-effort: a missing file or absent yaml dependency yields ``{}`` so the
    authoring engine degrades to the previous (un-catalog-grounded) behaviour
    rather than crashing. Each entry gains a ``resource_type`` key.
    """
    if yaml is None:
        return {}
    for candidate in _catalog_candidates(path):
        if not candidate.exists():
            continue
        try:
            data = yaml.safe_load(candidate.read_text()) or {}
        except Exception as e:  # malformed YAML — log, don't crash authoring
            logger.warning("technique_catalog unreadable (%s): %s", candidate, e)
            return {}
        out: dict[str, dict[str, Any]] = {}
        for rtype, body in (data.get("resource_types") or {}).items():
            for entry in (body.get("techniques") or []):
                ttp = entry.get("ttp")
                if not ttp:
                    continue
                out[ttp] = {**entry, "resource_type": rtype}
        return out
    return {}  # no catalog file found on any candidate path


def catalog_entry(ttp: str, *, path: str | Path | None = None) -> dict[str, Any] | None:
    """Return the catalog entry for a TTP, or None if absent."""
    return load_catalog(path).get(ttp)


def techniques_needing_rules(
    catalog: dict[str, dict[str, Any]],
    existing_ttps: set[str],
    *,
    include_planned: bool = False,
    only_ttps: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Select catalog techniques to cold-start author (proactive `propose-rules`).

    Skips TTPs already covered by a detection rule (``existing_ttps``). By default
    only ``status: implemented`` techniques qualify — a ``planned`` one has no real
    table to ground against — unless ``include_planned``. ``only_ttps`` restricts
    the selection. Ordered as the catalog (kill-chain-stable).
    """
    out: list[dict[str, Any]] = []
    for ttp, entry in catalog.items():
        if only_ttps and ttp not in only_ttps:
            continue
        if ttp in existing_ttps:
            continue
        if entry.get("status") != "implemented" and not include_planned:
            continue
        out.append(entry)
    return out


# ── Table-schema introspection (KQL getschema) ───────────────────────────────────

def fetch_table_schema(detector: Any, table: str) -> list[dict[str, str]]:
    """Return ``[{"name": col, "type": kqltype}]`` for a LAW table via ``getschema``.

    Best-effort: any failure (unreachable workspace, unknown table, detector that
    doesn't support ``run_query``, dry-run with no detector) yields ``[]`` — the
    caller then authors without the schema block. We never let schema introspection
    break authoring; the worst case is the prior, un-grounded behaviour.

    ``table`` is validated as a bare identifier to keep it out of injection range
    (it is interpolated into KQL, not parameterised).
    """
    if detector is None or not table or not table.replace("_", "").isalnum():
        return []
    query = f"{table} | getschema | project ColumnName, ColumnType"
    try:
        rows = detector.run_query(query)
    except Exception as e:
        logger.info("getschema failed for table %s: %s", table, e)
        return []
    schema: list[dict[str, str]] = []
    for r in rows or []:
        name = r.get("ColumnName") or r.get("columnName")
        ctype = r.get("ColumnType") or r.get("columnType") or r.get("DataType") or ""
        if name:
            schema.append({"name": str(name), "type": str(ctype)})
    return schema


def format_schema_block(schema: list[dict[str, str]]) -> str:
    if not schema:
        return "(table schema unavailable — use only well-known columns for this source)"
    return "\n".join(f"- {c['name']}: {c['type']}" for c in schema)


# ── LLM tool + system prompt (single source; agent.py imports these) ──────────────

RULE_PROPOSAL_TOOL = {
    "type": "function",
    "function": {
        "name": "propose_detection_rule",
        "description": (
            "Propose a detection query for the client's monitoring system. You must "
            "always call this tool — never respond in plain text."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "analysis": {
                    "type": "string",
                    "description": (
                        "Why the current detection failed (reactive), or how this technique "
                        "becomes observable in the target table (proactive): table/metric, "
                        "threshold, time window, filters, query-language constructs."
                    ),
                },
                "rule_name": {
                    "type": "string",
                    "description": (
                        "Short kebab-case identifier, e.g. 'ransomware-disk-write-v2'. Unique."
                    ),
                },
                "proposed_query": {
                    "type": "string",
                    "description": (
                        "The complete runnable query in the source's language (see system "
                        "prompt). Reference ONLY columns present in the provided table schema "
                        "when one is given. Calibrate thresholds to the observed/expected "
                        "attack behaviour."
                    ),
                },
                "interval_s": {
                    "type": "number",
                    "description": "Recommended polling interval in seconds (10–120).",
                },
                "explanation": {
                    "type": "string",
                    "description": (
                        "One or two sentences: what the query detects and why it is sound."
                    ),
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence 0.0–1.0 that this query would catch the attack.",
                },
            },
            "required": [
                "analysis", "rule_name", "proposed_query",
                "interval_s", "explanation", "confidence",
            ],
        },
    },
}

RULE_PROPOSAL_SYSTEM_PROMPT = """\
You are Glorfindel's detection engineering module.

Your job: author a detection query for the client's monitoring system, either after a \
missed attack (detection_timeout) or proactively for a technique with no rule yet.

The query language depends on the source — it is specified in the user message. Write the \
query in that language only (KQL for azure_monitor, PromQL for prometheus, SPL for splunk, etc.).

Grounding rules:
- When a table schema is provided, reference ONLY columns that appear in it. Do not invent \
columns. If a needed column is absent, parse it out of an existing text column (e.g. KQL \
extract/parse on a message field) rather than assuming it exists.
- Target the correct data source / table / metric for the monitoring system.
- Use thresholds calibrated to the observed/expected attack intensity, not arbitrary values.
- Keep the time window tight to minimise false positives.
- Include only filters that distinguish malicious from benign activity.
- If a prior query was close, fix only what was wrong; do not over-engineer.

You always call the propose_detection_rule tool — never respond in plain text.
"""


# ── Grounded user message + the shared LLM call ──────────────────────────────────

def build_user_message(
    *,
    ttp: str,
    resource_id: str,
    source: str,
    workspace_id: str,
    table_schema: list[dict[str, str]],
    catalog: dict[str, Any] | None,
    attack_summary: str = "",
    expected_indicators: list[str] | None = None,
    failed_query: str | None = None,
    detection_timeout_s: Any = None,
    past_summaries: list[str] | None = None,
    incident_context: str = "",
) -> str:
    """Assemble the grounded prompt shared by the reactive and proactive paths."""
    lang = SOURCE_LANGUAGES.get(source, source)
    cat = catalog or {}
    log_source = cat.get("log_source") or "(unknown)"
    indicator_cols = cat.get("indicator_columns") or []
    expected_latency = cat.get("expected_latency_s")

    lines = [
        f"Author a detection rule for TTP: {ttp}",
        f"Resource: {resource_id or '(any discovered asset)'}",
        f"Detection source: {source} — write your query in {lang}",
        f"Workspace / endpoint: {workspace_id or '(not specified)'}",
        "",
        "== Target table (from catalog) ==",
        f"{log_source}",
        "",
        "== Real columns in that table (KQL getschema) ==",
        format_schema_block(table_schema),
    ]
    if indicator_cols:
        lines += ["", "== Catalog indicator columns (what the rule should surface) ==",
                  ", ".join(indicator_cols)]
    if expected_latency:
        lines += ["", f"== Expected detection latency (P99) == {expected_latency}s "
                  f"(set interval_s and reasoning accordingly)"]
    if attack_summary:
        lines += ["", "== What the attacker executed ==", attack_summary]
    if expected_indicators:
        lines += ["", "== Expected indicators =="] + [f"- {i}" for i in expected_indicators]
    if failed_query:
        lines += ["", f"== Query that failed (timed out after {detection_timeout_s or '?'}s) ==",
                  failed_query]
    if past_summaries:
        lines += ["", "== Past detection history for this TTP =="] + list(past_summaries)
    if incident_context:
        lines += ["", incident_context]
    lines += ["", f"Propose a sound {lang} query for this technique."]
    return "\n".join(lines)


def _parse_proposal(response: Any) -> dict[str, Any]:
    """Extract the tool-call args defensively (mirrors decide's defensive parsing)."""
    import json
    try:
        tool_call = response.choices[0].message.tool_calls[0]
        d = json.loads(tool_call.function.arguments)
    except (AttributeError, IndexError, TypeError, ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"authoring model returned no usable proposal: {e}") from e
    return d


def author_rule(
    *,
    ttp: str,
    resource_id: str,
    source: str,
    workspace_id: str,
    model: str,
    detector: Any = None,
    attack_summary: str = "",
    expected_indicators: list[str] | None = None,
    failed_query: str | None = None,
    detection_timeout_s: Any = None,
    past_summaries: list[str] | None = None,
    incident_context: str = "",
    catalog_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run the grounded authoring LLM call and return a proposed-rule dict.

    Keys: rule_name, source, workspace_id, query, interval_s, explanation,
    confidence, analysis. The caller persists it (proposed_rules.record) and/or
    surfaces it as an escalation — this function performs no I/O beyond the LLM
    call and the (best-effort) getschema introspection.
    """
    import litellm

    cat = catalog_entry(ttp, path=catalog_path)
    table = (cat or {}).get("log_source", "") if cat else ""
    # Schema introspection only when the source speaks KQL and a detector is wired.
    table_schema: list[dict[str, str]] = []
    if detector is not None and source in ("azure_monitor", "sentinel") and table:
        table_schema = fetch_table_schema(detector, table)

    user_msg = build_user_message(
        ttp=ttp,
        resource_id=resource_id,
        source=source,
        workspace_id=workspace_id,
        table_schema=table_schema,
        catalog=cat,
        attack_summary=attack_summary,
        expected_indicators=expected_indicators,
        failed_query=failed_query,
        detection_timeout_s=detection_timeout_s,
        past_summaries=past_summaries,
        incident_context=incident_context,
    )

    kwargs: dict = {}
    base_url = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url

    response = litellm.completion(
        model=model,
        max_tokens=2048,
        messages=[
            {
                "role": "system",
                "content": [{"type": "text", "text": RULE_PROPOSAL_SYSTEM_PROMPT,
                             "cache_control": {"type": "ephemeral"}}],
            },
            {"role": "user", "content": user_msg},
        ],
        tools=[RULE_PROPOSAL_TOOL],
        tool_choice={"type": "function", "function": {"name": "propose_detection_rule"}},
        **kwargs,
    )

    d = _parse_proposal(response)
    return {
        "rule_name": d["rule_name"],
        "source": source,
        "workspace_id": workspace_id,
        "query": d["proposed_query"],
        "interval_s": float(d.get("interval_s", 30)),
        "explanation": d["explanation"],
        "confidence": float(d["confidence"]),
        "analysis": d["analysis"],
        "grounded_schema": bool(table_schema),  # audit: was the proposal schema-grounded?
    }
