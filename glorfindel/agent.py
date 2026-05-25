from __future__ import annotations

import os
import time
from typing import TypedDict, Annotated

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
    outcome: dict | None


# ── LLM decision tool schema ──────────────────────────────────────────────────

_DECISION_TOOL = {
    "name": "security_decision",
    "description": (
        "Output a structured security response decision for an infrastructure threat signal. "
        "You must always call this tool — never respond in plain text."
    ),
    "input_schema": {
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
        },
        "required": [
            "reasoning", "confidence", "action", "reversible",
            "explanation", "escalate", "escalation_reason",
        ],
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


def poll_detection(state: GlorfindelState) -> GlorfindelState:
    """Poll the detection source when Annatar signals an attack_started.

    No-op for all other events — passes through unchanged.
    On detection: updates event to 'detection', adds detection_time_s to raw_signal.
    On timeout: updates event to 'detection_timeout'.
    """
    from glorfindel.detectors import detector_for

    signal = state["signal"]
    if signal.get("event") != "attack_started":
        return state

    raw = signal.get("raw_signal", {})
    source = raw.get("detection_source", "azure_monitor")
    query = raw.get("detection_query", "")
    timeout_s = float(raw.get("detection_timeout_s", 300))
    attack_time = float(raw.get("attack_time", time.time()))

    try:
        detector = detector_for(source, workspace_id=raw.get("log_analytics_workspace_id", ""))
    except ValueError as e:
        _console.print(f"[yellow]poll_detection: {e} — skipping[/yellow]")
        return {**state, "signal": {**signal, "event": "detection_timeout"}}

    _console.print(f"[cyan]->[/cyan] Polling {source} (timeout={int(timeout_s)}s)...")
    result = detector.poll_alert(query, since=attack_time, timeout_s=timeout_s)

    if result is not None:
        detection_s, detected_row = result
        updated_signal = {
            **signal,
            "event": "detection",
            "raw_signal": {**raw, "detection_time_s": detection_s, "detected_data": detected_row},
        }
    else:
        _console.print(f"  [yellow]Detection timeout after {int(timeout_s)}s — IDS gap signal[/yellow]")
        updated_signal = {**signal, "event": "detection_timeout"}

    return {**state, "signal": updated_signal}


def decide(state: GlorfindelState, *, model: str) -> GlorfindelState:
    """Call Claude API to reason about the signal and produce a structured decision."""
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    signal = state["signal"]
    past = state["past_cycles"]

    user_content = _build_user_message(signal, past, state.get("incident"))

    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        tools=[_DECISION_TOOL],
        tool_choice={"type": "tool", "name": "security_decision"},
        messages=[{"role": "user", "content": user_content}],
    )

    tool_result = next(
        block for block in response.content
        if block.type == "tool_use" and block.name == "security_decision"
    )
    d = tool_result.input

    return {
        **state,
        "reasoning": d["reasoning"],
        "confidence": d["confidence"],
        "action": d["action"],
        "reversible": d["reversible"],
        "explanation": d["explanation"],
        "escalate": d["escalate"],
        "escalation_reason": d.get("escalation_reason", ""),
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


def _route_after_verify(state: GlorfindelState) -> str:
    outcome = state.get("outcome") or {}
    # Only escalate on explicit False — None (not implemented) proceeds to store
    if outcome.get("verified") is False:
        return "escalate_to_human"
    return "store_cycle"


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

    graph.set_entry_point("load_context")
    graph.add_edge("load_context", "poll_detection")
    graph.add_edge("poll_detection", "decide")
    graph.add_conditional_edges("decide", _route_after_decide)
    graph.add_edge("execute_action", "verify_action")
    graph.add_conditional_edges("verify_action", _route_after_verify)
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
        model: str = "claude-sonnet-4-6",
        dry_run: bool = False,
    ):
        from glorfindel.actions import AzureConnector

        self.dry_run = dry_run
        self.memory = CycleMemory(path=memory_path)
        self.connector = connector or AzureConnector(dry_run=dry_run)
        self.incidents = IncidentRegistry(path=incidents_path)
        self.model = model
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
