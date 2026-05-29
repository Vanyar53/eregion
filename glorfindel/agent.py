from __future__ import annotations

import os
import time
from typing import TypedDict

from langgraph.graph import StateGraph, END
from rich.console import Console

from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED, CloudConnector
from glorfindel.incidents import IncidentRegistry
from glorfindel.memory import CycleMemory

_console = Console()


# ── State ─────────────────────────────────────────────────────────────────────

class GlorfindelState(TypedDict):
    signal: dict
    past_cycles: list[dict]
    incident: dict | None    # current incident context for this resource
    dry_run: bool
    reasoning: str
    confidence: float
    action: str
    reversible: bool
    explanation: str
    escalate: bool
    escalation_reason: str
    suggested_steps: list[str]
    outcome: dict | None
    proposed_rule: dict | None  # set by propose_detection_rule for detection_missed signals
    proposal_id: str            # UUID of the saved proposed rule (empty if not a rule proposal)


# ── LLM decision tool schema ──────────────────────────────────────────────────

_DECISION_TOOL = {
    "type": "function",
    "function": {
        "name": "security_decision",
        "description": (
            "Output a structured security response decision for an infrastructure threat signal. "
            "You must always call this tool — never respond in plain text."
        ),
        "parameters": {
        "type": "object",
        "properties": {
            "reasoning": {
                "type": "string",
                "description": "Step-by-step reasoning: what happened, what it means, what to do and why.",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in the decision, 0.0 to 1.0.",
            },
            "action": {
                "type": "string",
                "description": (
                    "The action to take. Use a known action if one fits: "
                    f"autonomous={sorted(AUTONOMOUS_ACTIONS)}, "
                    f"requires_approval={sorted(HUMAN_APPROVAL_REQUIRED)}. "
                    "If none fit, propose a new action name (snake_case) and explain it "
                    "in escalation_reason — it will always be escalated to a human."
                ),
            },
            "reversible": {
                "type": "boolean",
                "description": "True if the action can be undone without data loss.",
            },
            "explanation": {
                "type": "string",
                "description": "Plain-language explanation for the operator (1-3 sentences).",
            },
            "escalate": {
                "type": "boolean",
                "description": "True if human approval is required before acting.",
            },
            "escalation_reason": {
                "type": "string",
                "description": "Why human approval is needed (empty string if escalate=false).",
            },
            "suggested_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Concrete, context-aware next steps for the human operator. "
                    "ALWAYS return a JSON array (never null). "
                    "If escalate=true: 3-5 specific steps referencing the TTP, resource, "
                    "and past cycle history. If escalate=false: empty array []."
                ),
            },
        },
        "required": [
            "reasoning", "confidence", "action", "reversible",
            "explanation", "escalate", "escalation_reason", "suggested_steps",
        ],
        },
    },
}

_SYSTEM_PROMPT = f"""\
You are Glorfindel, a security response agent for cloud infrastructure.

Your role: analyze threat signals produced by Annatar (a controlled attack simulation) \
and decide how to respond.

Autonomy rules — you MUST follow these without exception:
- Known autonomous actions {sorted(AUTONOMOUS_ACTIONS)}: act alone, set escalate=false.
- Known destructive actions {sorted(HUMAN_APPROVAL_REQUIRED)}: ALWAYS escalate, set escalate=true.
- Unknown/proposed actions: if no known action fits the situation, propose a new action name
  (snake_case) and explain exactly what it should do in escalation_reason. Always set escalate=true
  for proposed actions — a human will review, approve, and potentially codify it.

Event-specific behavior — follow these rules before reasoning:
- event=detection: active or recent attack confirmed. Act immediately with the minimum
  effective reversible action. Choose based on the TTP:
  * Ransomware / disk encryption (T1486): isolate_vm — stop lateral spread.
  * Exfiltration from internal VM (T1041, internal CallerIpAddress): isolate_vm — cut
    the outbound channel at the VM level. block_suspicious_ip on an internal IP is
    ineffective at the NSG perimeter.
  * Brute force / credential attack from external IP (T1110): block_suspicious_ip —
    deny the attacker's IP at the NSG. Do NOT isolate_vm unless the VM is confirmed
    compromised. The SourceIP field in detected_data contains the attacker IP.
  * Privilege escalation / confirmed root access (T1548): isolate_vm — the attacker has
    OS-level control of the VM. There is no external IP to block (they are already inside).
    Isolating the VM cuts their access and prevents lateral movement or further exfiltration.
- event=detection_timeout: Azure Monitor did NOT fire during the attack — IDS gap confirmed.
  ALWAYS: action=snapshot (preserve forensic state, non-disruptive), escalate=true,
  escalation_reason must explain that the IDS missed the attack and name the TTP.
  Never take a disruptive action on a detection_timeout — the attack may have ended.
- event=recovery_complete: restore verified, VM back online. ALWAYS action=release_isolation,
  escalate=false. The VM is clean (restore succeeded) so the containment NSG rule is no
  longer needed. release_isolation is idempotent — safe even if isolation was already removed.
  Do not snapshot here: the VM is clean by definition and a baseline snapshot adds no value
  at this point.
- event=recovery_failed: escalate to human with the failure reasons from raw_signal.

When reasoning:
1. Identify the TTP (MITRE ATT&CK) and what it means for this resource.
2. Consider the severity and what the attacker likely achieved or is attempting.
3. Select the minimum effective action — prefer known reversible actions over proposing new ones.
4. Only propose a new action if no known action adequately addresses the threat.
5. If past cycles are available, use them to calibrate your confidence.

You always call the security_decision tool — never respond in plain text.
"""

# ── Rule-proposal tool (detection_missed events) ──────────────────────────────

# Maps detection source identifiers to their query language names.
# Used to give the LLM the right context when proposing detection rules.
_SOURCE_LANGUAGES: dict[str, str] = {
    "azure_monitor": "KQL (Kusto Query Language)",
    "prometheus": "PromQL",
    "splunk": "SPL (Splunk Processing Language)",
    "datadog": "Datadog Query Language",
    "elasticsearch": "EQL / Lucene",
    "loki": "LogQL",
    "cloudwatch": "CloudWatch Logs Insights",
    "sentinel": "KQL (Microsoft Sentinel)",
}

_RULE_PROPOSAL_TOOL = {
    "type": "function",
    "function": {
        "name": "propose_detection_rule",
        "description": (
            "Propose an improved detection query for the client's monitoring system "
            "after a missed attack. You must always call this tool — never respond in plain text."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "analysis": {
                    "type": "string",
                    "description": (
                        "Why the current detection failed: wrong table/metric, threshold too high, "
                        "time window too narrow, missing filter, wrong query language constructs, etc."
                    ),
                },
                "rule_name": {
                    "type": "string",
                    "description": (
                        "Short kebab-case identifier for the rule, e.g. "
                        "'ransomware-disk-write-v2'. Must be unique."
                    ),
                },
                "proposed_query": {
                    "type": "string",
                    "description": (
                        "The complete runnable query in the source's language (see system prompt). "
                        "Must target the correct data source and use thresholds calibrated to "
                        "the observed attack behavior."
                    ),
                },
                "interval_s": {
                    "type": "number",
                    "description": "Recommended polling interval in seconds (10–120).",
                },
                "explanation": {
                    "type": "string",
                    "description": (
                        "One or two sentences: what the new query detects and why it "
                        "improves on the previous one."
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

_RULE_PROPOSAL_SYSTEM_PROMPT = """\
You are Glorfindel's detection engineering module.

An attack was simulated but your detection rules failed to fire (detection_timeout). \
Your job: analyze the failure and propose a better detection query for the client's \
monitoring system.

The query language depends on the source — it is specified in the user message. \
Write the query in that language only (KQL for azure_monitor, PromQL for prometheus, \
SPL for splunk, etc.).

Rules:
- Target the correct data source / table / metric for the monitoring system
- Use thresholds calibrated to the observed attack intensity, not arbitrary values
- Keep the time window tight to minimize false positives
- Include only filters that distinguish malicious from benign activity
- If the original query was close, fix only what was wrong; do not over-engineer

You always call the propose_detection_rule tool — never respond in plain text.
"""


# ── Nodes ─────────────────────────────────────────────────────────────────────

def load_context(
    state: GlorfindelState,
    *,
    memory: CycleMemory,
    incidents: IncidentRegistry,
) -> GlorfindelState:
    """Retrieve past cycles from vector store and open/update the incident record."""
    from dataclasses import asdict

    past = memory.retrieve_similar(state["signal"], n=3)
    signal = state["signal"]
    inc = incidents.get_or_create(
        resource_id=signal.get("resource_id", ""),
        ttp=signal.get("ttp", ""),
    )
    return {**state, "past_cycles": past, "incident": asdict(inc)}


def _find_rule_for_ttp(ttp: str):
    """Look up the detection rule for a TTP from detection_rules.yaml.

    Returns the first matching DetectionRule or None.
    """
    from pathlib import Path
    from glorfindel.detection_rules import load_rules

    for candidate in (
        Path("glorfindel/rules/azure/detection_rules.yaml"),
        Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml",
    ):
        if candidate.exists():
            for rule in load_rules(candidate):
                if rule.ttp == ttp:
                    return rule
    return None


def resolve_attack_started(signal: dict) -> dict:
    """Poll the detection source for an attack_started signal and return the resolved signal.

    Detection config is resolved in priority order:
    1. Fields in the signal's raw_signal (backward compat / explicit override)
    2. Matching rule in glorfindel/rules/azure/detection_rules.yaml (primary source)

    Returns a signal with event='detection' (+ detection_time_s, detected_data) or
    event='detection_timeout'. Called by poll_detection (respond mode) and by
    watch poll threads (watch mode, so polling runs in parallel per resource).
    """
    from glorfindel.detectors import detector_for

    raw = signal.get("raw_signal", {})
    source = raw.get("detection_source", "")
    query = raw.get("detection_query", "")
    workspace_id = raw.get("log_analytics_workspace_id", "")
    timeout_s = float(raw.get("detection_timeout_s", 300))
    attack_time = float(raw.get("attack_time", time.time()))

    # Fall back to detection_rules.yaml when fields absent from signal
    if not query:
        rule = _find_rule_for_ttp(signal.get("ttp", ""))
        if rule:
            source = source or rule.source
            query = rule.query
            workspace_id = workspace_id or rule.workspace_id
            _console.print(
                f"  [dim]Using detection rule '{rule.name}' from detection_rules.yaml[/dim]"
            )

    if not query:
        _console.print(
            "  [yellow]No detection query found for this TTP"
            " — detection_timeout[/yellow]"
        )
        return {**signal, "event": "detection_timeout"}

    source = source or "azure_monitor"

    try:
        detector = detector_for(source, workspace_id=workspace_id)
    except ValueError as e:
        _console.print(f"[yellow]poll: {e} — skipping[/yellow]")
        return {**signal, "event": "detection_timeout"}

    _console.print(f"[cyan]->[/cyan] Polling {source} (timeout={int(timeout_s)}s)...")
    result = detector.poll_alert(query, since=attack_time, timeout_s=timeout_s)

    if result is not None:
        detection_s, detected_row = result
        return {
            **signal,
            "event": "detection",
            "raw_signal": {**raw, "detection_time_s": detection_s, "detected_data": detected_row},
        }

    _console.print(f"  [yellow]Detection timeout after {int(timeout_s)}s — IDS gap[/yellow]")
    return {**signal, "event": "detection_timeout"}


def poll_detection(state: GlorfindelState) -> GlorfindelState:
    """Resolve attack_started → detection/timeout (respond mode).

    No-op for all other events. In watch mode this node is never reached for
    attack_started — the watch poll thread calls resolve_attack_started directly
    and enqueues the resolved signal.
    """
    signal = state["signal"]
    if signal.get("event") != "attack_started":
        return state
    return {**state, "signal": resolve_attack_started(signal)}


def decide(state: GlorfindelState, *, model: str) -> GlorfindelState:
    """Call LLM to reason about the signal and produce a structured decision.

    Supports any provider via LiteLLM: anthropic/claude-*, openai/gpt-*, ollama/*,
    azure/*, or any OpenAI-compatible endpoint via GLORFINDEL_LLM_BASE_URL.
    """
    import json
    import litellm

    signal = state["signal"]
    past = state["past_cycles"]
    user_content = _build_user_message(signal, past, state.get("incident"))

    kwargs: dict = {}
    base_url = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url

    response = litellm.completion(
        model=model,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        tools=[_DECISION_TOOL],
        tool_choice={"type": "function", "function": {"name": "security_decision"}},
        **kwargs,
    )

    tool_call = response.choices[0].message.tool_calls[0]
    d = json.loads(tool_call.function.arguments)

    return {
        **state,
        "reasoning": d["reasoning"],
        "confidence": d["confidence"],
        "action": d["action"],
        "reversible": d["reversible"],
        "explanation": d["explanation"],
        "escalate": d["escalate"],
        "escalation_reason": d.get("escalation_reason", ""),
        "suggested_steps": d.get("suggested_steps") or [],
    }


def execute_action(
    state: GlorfindelState,
    *,
    connector: CloudConnector,
    incidents: IncidentRegistry,
) -> GlorfindelState:
    """Execute the autonomous action via the cloud connector."""
    import time
    resource_id = state["signal"].get("resource_id", "unknown")
    action = state["action"]

    t_start = time.time()
    if action == "isolate_vm":
        outcome = connector.isolate_vm(resource_id)
    elif action == "release_isolation":
        outcome = connector.release_isolation(resource_id)
    elif action == "block_suspicious_ip":
        raw = state["signal"].get("raw_signal", {})
        detected = raw.get("detected_data", {})
        ip = (
            state["signal"].get("context", {}).get("suspicious_ip")
            or detected.get("SourceIP")          # lateral movement / brute force
            or detected.get("DestIP_s")          # exfil via Traffic Analytics
            or detected.get("DestinationIp")
            or detected.get("DestinationIPAddress")
            or ""
        )
        outcome = connector.block_suspicious_ip(ip, resource_id)
    elif action == "snapshot":
        snap_id = connector.snapshot(resource_id)
        outcome = {"snapshot_id": snap_id}
    else:
        outcome = {"status": "no_op", "action": action}
    action_s = round(time.time() - t_start)

    incident = state.get("incident")
    if incident:
        incidents.record_action(
            incident["incident_id"],
            action,
            outcome.get("status", "unknown"),
        )

    return {**state, "outcome": {**outcome, "executed": True, "action_s": action_s}}


def escalate_to_human(state: GlorfindelState) -> GlorfindelState:
    """Mark the decision as escalated — human must approve before any action."""
    action = state["action"]
    if action in HUMAN_APPROVAL_REQUIRED:
        escalation_type = "destructive_action"
    elif action not in AUTONOMOUS_ACTIONS:
        escalation_type = "proposed_action"
    else:
        escalation_type = "low_confidence"

    signal = state["signal"]
    if not state.get("dry_run", False):
        from glorfindel import escalations
        escalations.record(
            signal_id=signal.get("signal_id", ""),
            resource_id=signal.get("resource_id", ""),
            action=action,
            escalation_type=escalation_type,
            reason=state.get("escalation_reason", ""),
            run_id=signal.get("context", {}).get("run_id", ""),
            suggested_steps=state.get("suggested_steps") or [],
            ttp=signal.get("ttp", ""),
            severity=signal.get("severity", ""),
            proposal_id=state.get("proposal_id", ""),
            proposed_query=(state.get("proposed_rule") or {}).get("query", ""),
        )

    return {
        **state,
        "outcome": {
            "status": "escalated",
            "escalation_type": escalation_type,
            "reason": state["escalation_reason"],
            "action_pending": action,
            "executed": False,
        },
    }


def verify_action(state: GlorfindelState, *, connector: CloudConnector) -> GlorfindelState:
    """Check that the executed action had the intended effect.

    verified=True  → action confirmed, proceed to store_cycle
    verified=False → action failed, escalate to human
    verified=None  → verification not implemented for this action, proceed without claim
    """
    action = state["action"]
    resource_id = state["signal"].get("resource_id", "")
    outcome = state.get("outcome") or {}

    if outcome.get("status") == "dry_run":
        return {**state, "outcome": {**outcome, "verified": None}, "escalate": False, "escalation_reason": ""}

    if action == "isolate_vm":
        verification = connector.verify_isolation(resource_id)
    elif action == "release_isolation":
        # verified=True means isolation is GONE (success), verified=False means still active (failure)
        iso = connector.verify_isolation(resource_id)
        verification = {"verified": not iso.get("verified", True), "method": iso.get("method")}
    elif action == "snapshot":
        verification = connector.verify_snapshot(outcome.get("snapshot_id", ""))
    elif action == "block_suspicious_ip":
        raw_s = state["signal"].get("raw_signal", {})
        detected_v = raw_s.get("detected_data", {})
        ip = (
            state["signal"].get("context", {}).get("suspicious_ip")
            or detected_v.get("SourceIP")
            or detected_v.get("DestIP_s")
            or detected_v.get("DestinationIp")
            or detected_v.get("DestinationIPAddress")
            or outcome.get("ip", "")
        )
        verification = connector.verify_block_ip(ip, resource_id)
    else:
        verification = {"verified": None, "method": "not_implemented"}

    verified = verification.get("verified")
    escalate = verified is False
    escalation_reason = (
        f"Action '{action}' executed but verification failed: {verification.get('error', 'check failed')}"
        if escalate
        else state.get("escalation_reason", "")
    )
    return {
        **state,
        "outcome": {**outcome, **verification},
        "escalate": escalate,
        "escalation_reason": escalation_reason,
    }


def store_cycle(state: GlorfindelState, *, memory: CycleMemory) -> GlorfindelState:
    """Persist the completed cycle to vector store and debug JSONL."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    signal = state["signal"]
    outcome = state.get("outcome") or {}
    run_id = signal.get("context", {}).get("run_id", "")

    cycle = {
        "signal_id": signal.get("signal_id", ""),
        "run_id": run_id,
        "ttp": signal.get("ttp", ""),
        "severity": signal.get("severity", ""),
        "resource_type": signal.get("resource_type", ""),
        "event": signal.get("event", ""),
        "reasoning": state["reasoning"],
        "confidence": state["confidence"],
        "action": state["action"],
        "escalate": state["escalate"],
        "escalation_reason": state.get("escalation_reason", ""),
        "outcome": str(outcome),
        "detection_s": signal.get("raw_signal", {}).get("detection_time_s", 0),
        "action_s": outcome.get("action_s", 0),
        "past_cycles_used": [c.get("summary", "") for c in state.get("past_cycles", [])],
    }
    memory.store(cycle)

    # Notify autonomous actions (not escalations, not dry-run)
    if (
        not state.get("dry_run")
        and not state.get("escalate")
        and outcome.get("executed")
        and outcome.get("status") != "dry_run"
        and outcome.get("verified") is not False
    ):
        from glorfindel.escalations import notify_action
        notify_action(
            action=state["action"],
            resource_id=signal.get("resource_id", ""),
            run_id=run_id,
            confidence=state["confidence"],
            explanation=state.get("explanation", ""),
            verified=outcome.get("verified"),
            ttp=signal.get("ttp", ""),
            severity=signal.get("severity", ""),
        )

    # Debug JSONL — full trace for post-mortem analysis
    if run_id:
        debug_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signal": signal,
            "past_cycles": state.get("past_cycles", []),
            "reasoning": state["reasoning"],
            "confidence": state["confidence"],
            "action": state["action"],
            "escalate": state["escalate"],
            "escalation_reason": state.get("escalation_reason", ""),
            "outcome": outcome,
        }
        out = Path("runs") / f"{run_id}_debug.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "a") as f:
            f.write(json.dumps(debug_record, default=str) + "\n")

    return state


def propose_detection_rule(state: GlorfindelState, *, model: str) -> GlorfindelState:
    """Call LLM to propose an improved detection rule after a detection_missed signal.

    Uses a focused prompt distinct from the main security_decision flow.
    The proposal is stored in state['proposed_rule'] and persisted by store_cycle.
    """
    import json
    import litellm

    signal = state["signal"]
    raw = signal.get("raw_signal", {})
    hints = raw.get("detection_hints", {})
    ctx = signal.get("context", {})

    failed_query = ctx.get("failed_query") or raw.get("failed_query", "(unknown)")
    workspace_id = ctx.get("workspace_id", "")
    source = raw.get("detection_source", "azure_monitor")
    query_lang = _SOURCE_LANGUAGES.get(source, source)

    user_msg = f"""Detection missed for TTP: {signal.get('ttp', '?')}
Resource: {signal.get('resource_id', '?')}
Detection source: {source} — write your query in {query_lang}
Workspace / endpoint: {workspace_id or '(not specified)'}

== What the attacker executed ==
{hints.get('attack_commands_summary', '(no attack summary provided)')}

== Expected log source / table ==
{hints.get('log_source', '(unknown)')}

== Expected indicators ==
{chr(10).join('- ' + i for i in (hints.get('expected_indicators') or []))}

== Query that failed (timed out after {ctx.get('detection_timeout_s', '?')}s) ==
{failed_query}

== Past detection history for this TTP ==
{chr(10).join(c.get('summary', '') for c in state.get('past_cycles', [])) or '(no history)'}

Propose a better {query_lang} query that would have caught this attack."""

    kwargs: dict = {}
    base_url = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url

    response = litellm.completion(
        model=model,
        max_tokens=2048,
        messages=[
            {"role": "system", "content": _RULE_PROPOSAL_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        tools=[_RULE_PROPOSAL_TOOL],
        tool_choice={"type": "function", "function": {"name": "propose_detection_rule"}},
        **kwargs,
    )

    tool_call = response.choices[0].message.tool_calls[0]
    d = json.loads(tool_call.function.arguments)

    proposed_rule = {
        "rule_name": d["rule_name"],
        "source": signal.get("raw_signal", {}).get("detection_source", "azure_monitor"),
        "workspace_id": workspace_id,
        "query": d["proposed_query"],
        "interval_s": float(d.get("interval_s", 30)),
        "explanation": d["explanation"],
        "confidence": float(d["confidence"]),
        "analysis": d["analysis"],
    }

    # Save the proposed rule immediately so proposal_id is available for the
    # escalation card (escalate_to_human runs before store_cycle).
    pid = ""
    if not state.get("dry_run"):
        from glorfindel import proposed_rules as _pr
        run_id = signal.get("context", {}).get("run_id", "")
        pid = _pr.record(
            run_id=run_id,
            signal_id=signal.get("signal_id", ""),
            ttp=signal.get("ttp", ""),
            resource_id=signal.get("resource_id", ""),
            **proposed_rule,
        )

    return {
        **state,
        "reasoning": d["analysis"],
        "confidence": d["confidence"],
        "action": "improve_detection",
        "reversible": True,
        "explanation": d["explanation"],
        "escalate": True,
        "escalation_reason": d["analysis"],
        "suggested_steps": [
            f"Review the proposed query for {signal.get('ttp', '')}",
            "Test it in Log Analytics against recent data",
            f"glorfindel approve-rule {pid or '<id>'}  (or Approve in War Room Incidents)",
            "Re-run the scenario to validate detection",
        ],
        "proposed_rule": proposed_rule,
        "proposal_id": pid,
        "outcome": None,
    }


def _route_after_verify(state: GlorfindelState) -> str:
    outcome = state.get("outcome") or {}
    # Only escalate on explicit False — None (not implemented) proceeds to store
    if outcome.get("verified") is False:
        return "escalate_to_human"
    return "store_cycle"


def _route_after_load_context(state: GlorfindelState) -> str:
    if state["signal"].get("event") == "detection_missed":
        return "propose_detection_rule"
    return "poll_detection"


def _route_after_decide(state: GlorfindelState) -> str:
    action = state["action"]
    if state["escalate"]:
        return "escalate_to_human"
    if action in HUMAN_APPROVAL_REQUIRED:
        return "escalate_to_human"
    if action not in AUTONOMOUS_ACTIONS:
        return "escalate_to_human"  # proposed unknown action — always escalate
    return "execute_action"


# ── Graph builder ─────────────────────────────────────────────────────────────

def _build_graph(
    memory: CycleMemory,
    connector: CloudConnector,
    model: str,
    incidents: IncidentRegistry | None = None,
):
    if incidents is None:
        incidents = IncidentRegistry(path=".glorfindel/incidents.jsonl")

    graph = StateGraph(GlorfindelState)

    graph.add_node("load_context", lambda s: load_context(s, memory=memory, incidents=incidents))
    graph.add_node("poll_detection", poll_detection)
    graph.add_node("decide", lambda s: decide(s, model=model))
    graph.add_node("execute_action", lambda s: execute_action(s, connector=connector, incidents=incidents))
    graph.add_node("verify_action", lambda s: verify_action(s, connector=connector))
    graph.add_node("escalate_to_human", escalate_to_human)
    graph.add_node("store_cycle", lambda s: store_cycle(s, memory=memory))
    graph.add_node(
        "propose_detection_rule",
        lambda s: propose_detection_rule(s, model=model),
    )

    graph.set_entry_point("load_context")
    graph.add_conditional_edges("load_context", _route_after_load_context)
    graph.add_edge("poll_detection", "decide")
    graph.add_conditional_edges("decide", _route_after_decide)
    graph.add_edge("execute_action", "verify_action")
    graph.add_conditional_edges("verify_action", _route_after_verify)
    graph.add_edge("propose_detection_rule", "escalate_to_human")
    graph.add_edge("escalate_to_human", "store_cycle")
    graph.add_edge("store_cycle", END)

    return graph.compile()


# ── Public API ────────────────────────────────────────────────────────────────

class GlorfindelAgent:
    def __init__(
        self,
        connector: CloudConnector | None = None,
        memory_path: str | None = None,
        incidents_path: str | None = None,
        model: str = "",
        dry_run: bool = False,
    ):
        from glorfindel.actions import AzureConnector

        self.dry_run = dry_run
        self.memory = CycleMemory(path=memory_path)
        self.connector = connector or AzureConnector(dry_run=dry_run)
        self.incidents = IncidentRegistry(path=incidents_path)
        self.model = model or os.environ.get("GLORFINDEL_LLM_MODEL") or "anthropic/claude-sonnet-4-6"
        self._graph = _build_graph(self.memory, self.connector, self.model, self.incidents)

    def respond(self, signal: dict) -> GlorfindelState:
        """Process a single signal and return the final state."""
        initial: GlorfindelState = {
            "signal": signal,
            "past_cycles": [],
            "incident": None,
            "dry_run": self.dry_run,
            "reasoning": "",
            "confidence": 0.0,
            "action": "",
            "reversible": True,
            "explanation": "",
            "escalate": False,
            "escalation_reason": "",
            "outcome": None,
        }
        return self._graph.invoke(initial)


def _build_user_message(
    signal: dict,
    past_cycles: list[dict],
    incident: dict | None = None,
) -> str:
    import json
    lines = ["## Signal reçu\n", "```json"]
    lines.append(json.dumps(signal, indent=2, default=str))
    lines.append("```")

    # Inject incident context when this is not the first signal for the resource
    if incident and (incident.get("signals_count", 0) > 1 or incident.get("actions_taken")):
        lines.append("\n## Incident en cours sur cette ressource\n")
        lines.append(f"- Signaux reçus : {incident['signals_count']}")
        ttps = incident.get("ttps", [])
        if ttps:
            lines.append(f"- TTPs observés : {', '.join(ttps)}")
        actions = incident.get("actions_taken", [])
        if actions:
            lines.append("- Actions déjà exécutées :")
            for a in actions:
                lines.append(f"  * {a['action']} → {a['outcome_status']} ({a['timestamp']})")
        else:
            lines.append("- Aucune action encore exécutée sur cet incident.")
        lines.append(
            "\nTiens compte des actions déjà prises — évite de re-isoler une VM déjà isolée, "
            "ou de bloquer une IP déjà bloquée."
        )

    if past_cycles:
        lines.append("\n## Cycles passés similaires (contexte)\n")
        for i, c in enumerate(past_cycles, 1):
            lines.append(f"**Cycle {i}:** {c.get('summary', str(c))}")
    else:
        lines.append("\n*Aucun cycle passé disponible — première décision.*")

    lines.append("\nAnalyse ce signal et prends une décision de réponse.")
    return "\n".join(lines)
