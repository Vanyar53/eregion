from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TypedDict

from langgraph.graph import StateGraph, END
from rich.console import Console

from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED, CloudConnector
from glorfindel.config import load_glorfindel_config
from glorfindel.incidents import IncidentRegistry
from glorfindel.memory import CycleMemory

_console = Console()


def _load_few_shot_examples() -> str:
    """Load and format few-shot examples from few_shot_examples.yaml.

    Falls back to an empty string if the file is missing or malformed so
    the agent still starts without crashing.
    """
    try:
        import yaml  # optional; only needed at startup
        candidates = [
            Path(__file__).parent / "few_shot_examples.yaml",
        ]
        for path in candidates:
            if path.exists():
                data = yaml.safe_load(path.read_text())
                examples = data.get("examples", [])
                if not examples:
                    return ""
                blocks: list[str] = []
                for i, ex in enumerate(examples, 1):
                    lines: list[str] = [
                        f"EXAMPLE {i} — {ex['title']}",
                        f"  Signal indicators: {ex['signal_indicators']}",
                    ]
                    for step in ex.get("reasoning", []):
                        lines.append(f"  {step}")
                    lines.append(f"  → {ex['conclusion']}")
                    lines.append(f"  confidence: {ex['confidence']}")
                    blocks.append("\n".join(lines))
                return "\n\n".join(blocks)
        return ""
    except Exception as exc:
        _console.print(f"[yellow]few-shot: failed to load examples — {exc}[/yellow]")
        return ""


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
    llm_usage: dict | None      # LLM token usage from last litellm.completion call (P1 observability)


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
                    "If escalate=true OR confidence < 0.7: 3-5 forensic investigation steps "
                    "specific to the observed TTP and resource — e.g. for account creation: "
                    "check /etc/passwd, ~/.ssh/authorized_keys, crontabs, active sessions. "
                    "For ransomware: check running processes, mounted shares, network connections. "
                    "For brute force: check successful auth after failed attempts, active sessions. "
                    "If escalate=false and confidence >= 0.7: empty array []."
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
You are Glorfindel, an autonomous incident response agent for cloud infrastructure.

Your role: analyze threat signals and decide the minimum effective response that contains
the threat without unnecessary disruption.

━━ Autonomy boundary (enforced by the graph — not negotiable) ━━
- Autonomous actions {sorted(AUTONOMOUS_ACTIONS)}: execute immediately, escalate=false.
- Destructive actions {sorted(HUMAN_APPROVAL_REQUIRED)}: ALWAYS set escalate=true.
- Unknown action: propose a new snake_case name, explain it in escalation_reason, escalate=true.

━━ How to reason ━━
Do NOT look up a TTP→action table. Instead, reason from the observable evidence:

1. WHAT HAPPENED TO THE RESOURCE?
   Read raw_signal carefully. Ask: what did the attacker actually do or achieve?
   - Disk write rate anomaly (>50 MB/s sustained) → likely encryption in progress.
     If encryption ran, disk contents are destroyed. Isolation does NOT recover data.
   - Outbound data upload to external storage from a VM private IP → data left the perimeter.
     The disk itself is intact. Cutting the network stops further leakage.
   - Repeated failed auth from an external IP → attacker is probing, not yet inside.
     The VM is likely uncompromised. Blocking the source IP is sufficient.
   - Successful privilege escalation to root (sudo confirmed) → attacker has OS-level control.
     Cutting network access revokes their remote foothold. Disk is likely intact.

2. WHAT DOES THE CHOSEN ACTION ACTUALLY DO?
   - isolate_vm: adds NSG deny-all. Cuts all network. VM still runs. Disk intact. Reversible.
   - block_suspicious_ip: adds NSG deny for one IP. VM stays online. Best for external threats.
   - restore_from_backup: replaces disk from last recovery point. Recovers destroyed data.
     Requires human approval — destructive and takes ~20 min. Only warranted when data is gone.
   - snapshot: disk image for forensics. Non-disruptive. Use when you need to preserve state
     but don't know what happened (detection_timeout).
   - release_isolation: removes NSG deny-all. Use only after VM is confirmed clean.

3. MINIMUM EFFECTIVE ACTION
   Choose the action that contains the threat while minimizing blast radius.
   Prefer reversible actions. Only escalate to destructive actions when reversible ones
   are provably insufficient (e.g. disk is encrypted — isolation cannot recover data).

━━ Event types ━━
- detection: active or recent threat confirmed. Act immediately.
- detection_timeout: monitoring missed the attack. Preserve forensic state (snapshot),
  escalate. Never take a disruptive action — the attack may have ended.
- recovery_complete: restore verified. Release isolation (release_isolation, escalate=false).
  VM is clean by definition — no snapshot needed.
- recovery_failed: escalate with failure context from raw_signal.

━━ Using past cycles ━━
CRITICAL: past_cycles are historical records from PREVIOUS runs — they describe decisions
made in the past, NOT the current VM state. The VM may have been released, reset, or
re-compromised since then. NEVER conclude that a VM is currently isolated or an IP currently
blocked based on past_cycles alone.
The ONLY authoritative source of current isolation/block state is the "État actuel de la VM"
section in the user message (derived from live filesystem state). If "État actuel" shows
isolated=NON, treat the VM as NOT isolated, regardless of what past_cycles say.
Use past_cycles only to calibrate confidence and reasoning patterns — not to infer state.

━━ Validated reasoning examples (production-verified) ━━
These are not rules — they are examples of correct reasoning chains for signals you may
encounter. Apply the same reasoning process to new or ambiguous signals.

{_load_few_shot_examples()}

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


def _find_rule_for_ttp(ttp: str, glorfindel_cfg=None):
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
            for rule in load_rules(candidate, glorfindel_cfg=glorfindel_cfg):
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
        rule = _find_rule_for_ttp(signal.get("ttp", ""), glorfindel_cfg=load_glorfindel_config())
        if rule:
            source = source or rule.source
            query = rule.query
            workspace_id = workspace_id or rule.workspace_id
            # expected_latency_s: DCR/Syslog ingestion takes up to 480s — override
            # the scenario timeout when the rule knows better.
            if rule.expected_latency_s > timeout_s:
                timeout_s = float(rule.expected_latency_s)
            _console.print(
                f"  [dim]Using detection rule '{rule.name}' from detection_rules.yaml"
                f" (timeout={int(timeout_s)}s)[/dim]"
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
        from glorfindel.detection_rules import normalize_row
        return {
            **signal,
            "event": "detection",
            "raw_signal": {
                **raw,
                "detection_time_s": detection_s,
                "detected_data": detected_row,
                "normalized_signal": normalize_row(detected_row, ttp=signal.get("ttp", "")),
            },
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


# ── Investigative queries (post-detection enrichment) ─────────────────────────

# Query templates — {vm} is replaced at runtime with the VM hostname.
# All queries use ago(5m) to stay within the detection window.
# Kept short: investigate must complete in <15s total.

_IQ_HEARTBEAT_GAP = """
Heartbeat
| where Computer == "{vm}"
| where TimeGenerated > ago(2h)
| order by TimeGenerated asc
| extend PrevBeat = prev(TimeGenerated)
| extend GapMin = datetime_diff('minute', TimeGenerated, PrevBeat)
| where GapMin > 10
| project TimeGenerated, GapMin
| order by TimeGenerated desc
| limit 1
"""

_IQ_DISK_PROCESSES = """
Perf
| where TimeGenerated > ago(5m)
| where Computer == "{vm}"
| where ObjectName == "Process"
| where CounterName == "IO Write Bytes/sec"
| where InstanceName !in ("_Total", "Idle", "System")
| where CounterValue > 1000000
| summarize MaxWriteMBs = round(max(CounterValue) / 1048576, 1) by InstanceName
| top 5 by MaxWriteMBs desc
"""

# Identifiable backup agents only — generic POSIX tools (rsync, cp, tar, gzip)
# are NOT included: a ransomware archiving before encryption would match them,
# producing a false-negative "legitimate backup" conclusion.
#
# KNOWN LIMITATION: \\Process(*)\\IO Write Bytes/sec is Windows-only.
# Linux AMA does not map this counter → ObjectName=Process data is never
# present in LAW on Linux VMs. This query always returns [] on Linux.
# The LLM handles empty results correctly (conservative: cannot exclude
# ransomware) — treat absence of results as ambiguous, not as "no backup".
_IQ_BACKUP_AGENT = """
Perf
| where TimeGenerated > ago(10m)
| where Computer == "{vm}"
| where ObjectName == "Process"
| where CounterName == "IO Write Bytes/sec"
| where InstanceName in~ ("waagent", "WALinuxAgent", "azure-backup", "snapd", "MicrosoftAzureRecoveryServices")
| summarize MaxWriteMBs = round(max(CounterValue) / 1048576, 1) by InstanceName
"""

_IQ_SUCCESS_AUTH = """
Syslog
| where TimeGenerated > ago(5m)
| where Computer == "{vm}"
| where Facility == "auth"
| where SyslogMessage has "Accepted" and SyslogMessage has "{ip}"
| project TimeGenerated, SyslogMessage
| limit 3
"""

# ago(10m) rather than ago(5m): privilege escalation takes ~40s, root commands
# follow immediately — a 5m window risks missing activity that started before
# the detection signal was processed.
_IQ_ROOT_COMMANDS = """
Syslog
| where TimeGenerated > ago(10m)
| where Computer == "{vm}"
| where Facility == "auth"
| where SyslogMessage has "sudo" and SyslogMessage has "USER=root"
    and SyslogMessage has "COMMAND="
| project TimeGenerated, SyslogMessage
| limit 10
"""

_IQ_DISK_AFTER_ESC = """
Perf
| where TimeGenerated > ago(10m)
| where Computer == "{vm}"
| where ObjectName in ("Logical Disk", "LogicalDisk")
| where CounterName == "Disk Write Bytes/sec"
| summarize MaxWriteMBs = round(max(CounterValue) / 1048576, 1),
            AvgWriteMBs = round(avg(CounterValue) / 1048576, 1)
"""


def _run_investigative_query(workspace_id: str, query: str) -> list[dict]:
    """Run a single investigative query. Returns [] on any failure."""
    try:
        from glorfindel.detectors import detector_for
        det = detector_for("azure_monitor", workspace_id=workspace_id)
        return det.run_query(query.strip()) or []
    except Exception:
        return []


def investigate(state: GlorfindelState) -> GlorfindelState:
    """Enrich the signal with targeted investigative queries before decide.

    Only runs on event=detection with a resolvable workspace_id.
    Queries are chosen based on signal content (not TTP label).
    Results land in raw_signal.investigative_context — the LLM sees them.
    Failures are silently swallowed: investigation is best-effort.
    """
    signal = state["signal"]

    if signal.get("event") != "detection":
        return state

    raw = signal.get("raw_signal", {})
    workspace_id = (
        raw.get("log_analytics_workspace_id")
        or signal.get("context", {}).get("workspace_id", "")
    )

    # RulePoller signals don't embed workspace_id — resolve from config
    if not workspace_id:
        cfg = load_glorfindel_config()
        for b in cfg.monitoring_backends:
            if b.workspace_id:
                workspace_id = b.workspace_id
                break

    if not workspace_id or state.get("dry_run"):
        return state

    first_row = raw.get("detected_data") or raw.get("first_result_row") or {}
    syslog_msg = str(first_row.get("SyslogMessage", ""))

    # Prefer the OS hostname from the query result (Computer field in LAW tables).
    # The ARM resource name (.split("/")[-1]) is a fallback only — it may differ
    # from the OS hostname, in which case Perf/Syslog queries return empty silently.
    hostname_from_signal = (
        first_row.get("Computer")
        or first_row.get("computer")
        or first_row.get("host")
    )
    using_arm_fallback = not hostname_from_signal
    vm = hostname_from_signal or signal.get("resource_id", "").split("/")[-1]

    if using_arm_fallback:
        _console.print(
            f"  [dim]investigate: Computer absent from signal — "
            f"using ARM name '{vm}' as hostname fallback "
            f"(queries may return empty if OS hostname differs)[/dim]"
        )

    ctx: dict[str, list[dict]] = {}

    # ── Disk write anomaly → which process is writing? backup agent present? recent reboot?
    if "MaxWrite" in first_row or "DiskWrite" in first_row:
        ctx["top_write_processes"] = _run_investigative_query(
            workspace_id, _IQ_DISK_PROCESSES.format(vm=vm)
        )
        ctx["backup_agent_check"] = _run_investigative_query(
            workspace_id, _IQ_BACKUP_AGENT.format(vm=vm)
        )
        # Azure Backup OriginalLocation restore causes high I/O during boot rewrite.
        # A Heartbeat gap > 10min indicates a recent VM reboot — raises suspicion of
        # legitimate post-restore I/O rather than active ransomware encryption.
        ctx["heartbeat_gap"] = _run_investigative_query(
            workspace_id, _IQ_HEARTBEAT_GAP.format(vm=vm)
        )

    # ── Brute force → did any attempt succeed from this IP?
    source_ip = first_row.get("SourceIP", "")
    if "FailedAttempts" in first_row and source_ip:
        ctx["successful_auth_from_ip"] = _run_investigative_query(
            workspace_id, _IQ_SUCCESS_AUTH.format(vm=vm, ip=source_ip)
        )

    # ── Privilege escalation → what ran as root after? disk writes?
    if "USER=root" in syslog_msg and "COMMAND=" in syslog_msg:
        ctx["root_commands"] = _run_investigative_query(
            workspace_id, _IQ_ROOT_COMMANDS.format(vm=vm)
        )
        ctx["disk_write_after_escalation"] = _run_investigative_query(
            workspace_id, _IQ_DISK_AFTER_ESC.format(vm=vm)
        )

    if not ctx:
        return state

    if all(len(v) == 0 for v in ctx.values()):
        if using_arm_fallback:
            _console.print(
                f"  [yellow]investigate: all queries empty for '{vm}' (ARM fallback) "
                f"— likely hostname mismatch, check OS hostname vs ARM name[/yellow]"
            )
        else:
            _console.print(
                f"  [dim]investigate: all queries empty for '{vm}' "
                f"— data not yet ingested (LAW latency ~60s, normal)[/dim]"
            )

    enriched = {
        **signal,
        "raw_signal": {**raw, "investigative_context": ctx},
    }
    return {**state, "signal": enriched}


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
            {
                "role": "system",
                "content": [{"type": "text", "text": _SYSTEM_PROMPT,
                              "cache_control": {"type": "ephemeral"}}],
            },
            {"role": "user", "content": user_content},
        ],
        tools=[_DECISION_TOOL],
        tool_choice={"type": "function", "function": {"name": "security_decision"}},
        **kwargs,
    )

    tool_call = response.choices[0].message.tool_calls[0]
    d = json.loads(tool_call.function.arguments)

    # Confidence gate: override LLM if confidence below threshold on autonomous actions.
    # Normalize to float first so all downstream d["confidence"] accesses are safe.
    raw_conf = d.get("confidence")
    confidence = float(raw_conf) if raw_conf is not None else 0.0
    d["confidence"] = confidence
    _threshold = float(os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD", "0.7"))
    if not d["escalate"] and d["action"] in AUTONOMOUS_ACTIONS:
        if raw_conf is None or confidence < _threshold:
            d["escalate"] = True
            d["escalation_reason"] = (
                f"Low confidence ({'unknown' if raw_conf is None else f'{confidence:.0%}'}) "
                "— human review required"
            )

    usage = getattr(response, "usage", None)
    llm_usage: dict | None = None
    if usage is not None:
        llm_usage = {
            "input_tokens": getattr(usage, "prompt_tokens", 0),
            "output_tokens": getattr(usage, "completion_tokens", 0),
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0),
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0),
        }

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
        "llm_usage": llm_usage,
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
        # Fire-and-forget on detection_timeout: we don't know if the VM is compromised,
        # and blocking the queue for a 3-4h initial RSV backup is operationally unacceptable.
        event = state["signal"].get("event", "")
        snap_id = connector.snapshot(resource_id, wait=event != "detection_timeout")
        outcome = {"snapshot_id": snap_id}
    else:
        outcome = {"status": "no_op", "action": action}
    action_s = round(time.time() - t_start)

    incident = state.get("incident")
    if incident:
        inv_ctx = state["signal"].get("raw_signal", {}).get("investigative_context")
        incidents.record_action(
            incident["incident_id"],
            action,
            outcome.get("status", "unknown"),
            investigative_context=inv_ctx or None,
        )

    return {**state, "outcome": {**outcome, "executed": True, "action_s": action_s}}


def escalate_to_human(state: GlorfindelState) -> GlorfindelState:
    """Mark the decision as escalated — human must approve before any action."""
    action = state["action"]
    if action in HUMAN_APPROVAL_REQUIRED:
        escalation_type = "destructive_action"
    elif action == "improve_detection":
        escalation_type = "proposed_rule"
    elif action not in AUTONOMOUS_ACTIONS:
        escalation_type = "proposed_action"
    else:
        escalation_type = "low_confidence"

    signal = state["signal"]
    steps = list(state.get("suggested_steps") or [])
    if action == "snapshot":
        resource_id = signal.get("resource_id", "")
        steps.append(
            f"Si tu confirmes la compromission après vérification : "
            f"`glorfindel snapshot {resource_id} --yes` pour capturer l'état forensique."
        )

    if not state.get("dry_run", False):
        from glorfindel import escalations
        escalations.record(
            signal_id=signal.get("signal_id", ""),
            resource_id=signal.get("resource_id", ""),
            action=action,
            escalation_type=escalation_type,
            reason=state.get("escalation_reason", ""),
            run_id=signal.get("context", {}).get("run_id", ""),
            suggested_steps=steps,
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
    # ChromaDB write — non-fatal: debug JSONL must still be written on failure
    try:
        memory.store(cycle)
    except Exception as exc:
        _console.print(f"[yellow]store_cycle: ChromaDB write failed: {exc}[/yellow]")

    # Notify autonomous actions (not escalations, not dry-run)
    # Non-fatal: webhook/notification failure must not suppress the debug file
    try:
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
    except Exception as exc:
        _console.print(f"[yellow]store_cycle: notify_action failed: {exc}[/yellow]")

    # Debug JSONL — always written, even if ChromaDB or webhook failed
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
            "llm_usage": state.get("llm_usage"),
        }
        out = Path("runs") / f"{run_id}_debug.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "a") as f:
            f.write(json.dumps(debug_record, default=str) + "\n")

    return state


def propose_detection_rule(
    state: GlorfindelState, *, model: str, incidents: IncidentRegistry | None = None
) -> GlorfindelState:
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

    # Skip if RulePoller already detected this TTP recently — detection_missed
    # is a false negative from Annatar's feedback watcher not finding the watch file
    # fast enough. No new rule needed.
    # detection_timeout_s is in context (Annatar puts metrics there), not raw_signal.
    # Annatar waits detection_timeout_s + 120s before emitting detection_missed, so
    # the RulePoller match could be up to (timeout + 180s) old when we get here.
    ttp = signal.get("ttp", "")
    detection_timeout_s = float(ctx.get("detection_timeout_s", 300))
    from glorfindel.detection_rules import rulepoller_recently_matched
    if rulepoller_recently_matched(ttp, detection_timeout_s + 180):
        _console.print(
            f"  [dim]propose_detection_rule: RulePoller matched '{ttp}' recently "
            f"— detection_missed is a false negative, skipping proposal[/dim]"
        )
        return state

    failed_query = ctx.get("failed_query") or raw.get("failed_query", "(unknown)")
    workspace_id = ctx.get("workspace_id", "")
    source = raw.get("detection_source", "azure_monitor")
    query_lang = _SOURCE_LANGUAGES.get(source, source)

    # Check if an action was already taken on this VM — timeout may be caused by
    # the action (e.g. isolate_vm cuts off AMA) rather than a bad detection rule.
    incident_context = ""
    if incidents is not None:
        inc = incidents.get_active(signal.get("resource_id", ""))
        if inc and inc.actions_taken:
            actions_summary = ", ".join(
                f"{a['action']} (at {a.get('timestamp', '?')})" for a in inc.actions_taken
            )
            incident_context = f"""
== IMPORTANT: actions already taken on this resource ==
{actions_summary}

If one of these actions (e.g. isolate_vm) could have cut off the monitoring agent (AMA/syslog),
the detection timeout may be caused by that action — not by a bad detection rule.
In that case, note this in your analysis and set confidence accordingly.
The existing rule may be correct and no change needed.
"""

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
{incident_context}
Propose a better {query_lang} query that would have caught this attack."""

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
                "content": [{"type": "text", "text": _RULE_PROPOSAL_SYSTEM_PROMPT,
                              "cache_control": {"type": "ephemeral"}}],
            },
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
    graph.add_node("investigate", investigate)
    graph.add_node("decide", lambda s: decide(s, model=model))
    graph.add_node("execute_action", lambda s: execute_action(s, connector=connector, incidents=incidents))
    graph.add_node("verify_action", lambda s: verify_action(s, connector=connector))
    graph.add_node("escalate_to_human", escalate_to_human)
    graph.add_node("store_cycle", lambda s: store_cycle(s, memory=memory))
    graph.add_node(
        "propose_detection_rule",
        lambda s: propose_detection_rule(s, model=model, incidents=incidents),
    )

    graph.set_entry_point("load_context")
    graph.add_conditional_edges("load_context", _route_after_load_context)
    graph.add_edge("poll_detection", "investigate")
    graph.add_edge("investigate", "decide")
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

    norm = signal.get("raw_signal", {}).get("normalized_signal", {})
    if norm and norm.get("indicator_key", "unknown") != "unknown":
        lines.append(
            f"\n**Indicateur principal** : `{norm['indicator_key']}` = "
            f"`{norm['indicator_value']}` (ressource : `{norm['resource']}`)"
        )

    inv_ctx = signal.get("raw_signal", {}).get("investigative_context")
    if inv_ctx:
        lines.append("\n## Contexte investigatif (requêtes post-détection)\n")
        lines.append(
            "Ces données ont été collectées automatiquement après la détection "
            "pour enrichir ton raisonnement. Utilise-les pour affiner ta décision.\n"
        )
        for key, rows in inv_ctx.items():
            label = key.replace("_", " ")
            if rows:
                lines.append(f"**{label}** ({len(rows)} résultat(s)) :")
                lines.append("```json")
                lines.append(json.dumps(rows, indent=2, default=str))
                lines.append("```")
            else:
                lines.append(f"**{label}** : aucun résultat (requête vide ou données absentes)")

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
                inv = a.get("investigative_context", {})
                for key, rows in inv.items():
                    label = key.replace("_", " ")
                    if rows:
                        lines.append(f"    Contexte — {label} ({len(rows)} résultat(s)) :")
                        lines.append(f"    {json.dumps(rows[0], default=str)}")
                    else:
                        lines.append(f"    Contexte — {label} : aucun résultat")
        else:
            lines.append("- Aucune action encore exécutée sur cet incident.")
        lines.append(
            "\nTiens compte des actions déjà prises DANS CET INCIDENT. "
            "Pour l'état d'isolation actuel, voir la section 'État actuel de la VM' — "
            "ne jamais inférer depuis past_cycles."
        )

    # Inject current VM state from filesystem — authoritative, never inferred from past_cycles.
    resource_id = signal.get("resource_id", "")
    vm_name = resource_id.split("/")[-1] if resource_id else ""
    if vm_name:
        from pathlib import Path as _Path
        _iso_file = _Path.home() / ".glorfindel" / "isolation" / f"{vm_name}.json"
        _blk_file = _Path.home() / ".glorfindel" / "blocks" / f"{vm_name}.json"
        isolated = _iso_file.exists()
        blocked_ips: list[str] = []
        if _blk_file.exists():
            try:
                blocked_ips = [e["ip"] for e in json.loads(_blk_file.read_text())]
            except Exception:
                pass
        lines.append("\n## État actuel de la VM (source de vérité — ne jamais inférer depuis past_cycles)\n")
        lines.append(f"- Isolée (NSG deny-all actif) : **{'OUI' if isolated else 'NON'}**")
        lines.append(
            f"- IPs bloquées : {', '.join(blocked_ips) if blocked_ips else 'aucune'}"
        )
        try:
            from glorfindel.jobs import get_last_restore as _get_last_restore
            _rec = _get_last_restore(vm_name)
            if _rec:
                from datetime import datetime as _dt
                _rt = _dt.fromisoformat(_rec["last_restore_at"])
                _age_min = int((_dt.now(__import__("datetime").timezone.utc) - _rt).total_seconds() / 60)
                lines.append(
                    f"- Restauration Azure Backup déclenchée il y a **{_age_min} minutes**"
                    f" — I/O disque élevée possible au boot post-restore (ne pas confondre avec ransomware)"
                )
        except Exception:
            pass

    if past_cycles:
        lines.append("\n## Cycles passés similaires (historique — NE PAS inférer état courant depuis ces cycles)\n")
        for i, c in enumerate(past_cycles, 1):
            lines.append(f"**Cycle {i}:** {c.get('summary', str(c))}")
    else:
        lines.append("\n*Aucun cycle passé disponible — première décision.*")

    lines.append("\nAnalyse ce signal et prends une décision de réponse.")
    return "\n".join(lines)
