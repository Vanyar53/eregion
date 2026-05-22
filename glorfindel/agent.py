from __future__ import annotations

import os
from typing import TypedDict, Annotated

from langgraph.graph import StateGraph, END

from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED, CloudConnector
from glorfindel.memory import CycleMemory


# ── State ─────────────────────────────────────────────────────────────────────

class GlorfindelState(TypedDict):
    signal: dict
    past_cycles: list[dict]
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

When reasoning:
1. Identify the TTP (MITRE ATT&CK) and what it means for this resource.
2. Consider the severity and what the attacker likely achieved or is attempting.
3. Select the minimum effective action — prefer known reversible actions over proposing new ones.
4. Only propose a new action if no known action adequately addresses the threat.
5. If past cycles are available, use them to calibrate your confidence.

You always call the security_decision tool — never respond in plain text.
"""


# ── Nodes ─────────────────────────────────────────────────────────────────────

def load_context(state: GlorfindelState, *, memory: CycleMemory) -> GlorfindelState:
    """Retrieve past similar cycles from vector store."""
    past = memory.retrieve_similar(state["signal"], n=3)
    return {**state, "past_cycles": past}


def decide(state: GlorfindelState, *, model: str) -> GlorfindelState:
    """Call Claude API to reason about the signal and produce a structured decision."""
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    signal = state["signal"]
    past = state["past_cycles"]

    user_content = _build_user_message(signal, past)

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


def execute_action(state: GlorfindelState, *, connector: CloudConnector) -> GlorfindelState:
    """Execute the autonomous action via the cloud connector."""
    resource_id = state["signal"].get("resource_id", "unknown")
    action = state["action"]

    if action == "isolate_vm":
        outcome = connector.isolate_vm(resource_id)
    elif action == "block_suspicious_ip":
        ip = state["signal"].get("context", {}).get("suspicious_ip", "")
        outcome = connector.block_suspicious_ip(ip, resource_id)
    elif action == "snapshot":
        snap_id = connector.snapshot(resource_id)
        outcome = {"snapshot_id": snap_id}
    else:
        outcome = {"status": "no_op", "action": action}

    return {**state, "outcome": {**outcome, "executed": True}}


def escalate_to_human(state: GlorfindelState) -> GlorfindelState:
    """Mark the decision as escalated — human must approve before any action."""
    action = state["action"]
    if action in HUMAN_APPROVAL_REQUIRED:
        escalation_type = "destructive_action"
    elif action not in AUTONOMOUS_ACTIONS:
        escalation_type = "proposed_action"  # LLM invented a new action
    else:
        escalation_type = "low_confidence"

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

    if action == "isolate_vm":
        verification = connector.verify_isolation(resource_id)
    elif action == "snapshot":
        verification = connector.verify_snapshot(outcome.get("snapshot_id", ""))
    elif action == "block_suspicious_ip":
        ip = state["signal"].get("context", {}).get("suspicious_ip", "")
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
    """Persist the completed cycle to vector store for future RAG retrieval."""
    signal = state["signal"]
    memory.store({
        "signal_id": signal.get("signal_id", ""),
        "ttp": signal.get("ttp", ""),
        "severity": signal.get("severity", ""),
        "resource_type": signal.get("resource_type", ""),
        "event": signal.get("event", ""),
        "reasoning": state["reasoning"],
        "action": state["action"],
        "outcome": str(state.get("outcome")),
    })
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

def _build_graph(memory: CycleMemory, connector: CloudConnector, model: str):
    graph = StateGraph(GlorfindelState)

    graph.add_node("load_context", lambda s: load_context(s, memory=memory))
    graph.add_node("decide", lambda s: decide(s, model=model))
    graph.add_node("execute_action", lambda s: execute_action(s, connector=connector))
    graph.add_node("verify_action", lambda s: verify_action(s, connector=connector))
    graph.add_node("escalate_to_human", escalate_to_human)
    graph.add_node("store_cycle", lambda s: store_cycle(s, memory=memory))

    graph.set_entry_point("load_context")
    graph.add_edge("load_context", "decide")
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
        model: str = "claude-sonnet-4-6",
        dry_run: bool = False,
    ):
        from glorfindel.actions import AzureConnector

        self.memory = CycleMemory(path=memory_path)
        self.connector = connector or AzureConnector(dry_run=dry_run)
        self.model = model
        self._graph = _build_graph(self.memory, self.connector, self.model)

    def respond(self, signal: dict) -> GlorfindelState:
        """Process a single signal and return the final state."""
        initial: GlorfindelState = {
            "signal": signal,
            "past_cycles": [],
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


def _build_user_message(signal: dict, past_cycles: list[dict]) -> str:
    lines = ["## Signal reçu\n", "```json"]
    import json
    lines.append(json.dumps(signal, indent=2, default=str))
    lines.append("```")

    if past_cycles:
        lines.append("\n## Cycles passés similaires (contexte)\n")
        for i, c in enumerate(past_cycles, 1):
            lines.append(f"**Cycle {i}:** {c.get('summary', str(c))}")
    else:
        lines.append("\n*Aucun cycle passé disponible — première décision.*")

    lines.append("\nAnalyse ce signal et prends une décision de réponse.")
    return "\n".join(lines)
