from __future__ import annotations

from eregion_core.models import glorfindel_model

import math
import os
import time
from pathlib import Path
from typing import TypedDict

from langgraph.graph import StateGraph, END
from rich.console import Console
from rich.markup import escape as _esc_markup

from glorfindel.actions import (
    AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED, CloudConnector, PartialActionError, _first_line,
)
from glorfindel.config import load_glorfindel_config
from glorfindel.detection_authoring import author_rule
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
    autonomy_mode: str          # resolved autonomy mode for this asset (audit trail)
    mode_hold: bool             # True when an autonomous action was held back by human_only mode
    autonomy_gate: dict         # set when the VM is configured autonomous but held by its readiness
    cycle_error: str            # set when the cycle could not complete normally (→ cycle_failed escalation)
    held_by: str                # deterministic gate that escalated (→ its own escalation type)
    telemetry_gaps: list[str]   # investigative queries that FAILED (G2) — never shown to the model
    decision_temperature: float | None  # temperature of the first draw; None = model's default (D-1)
    decision_draws: list[dict]  # every draw asked before a disruptive autonomous action (D-1)
    uncontained: str            # a characterized detection a snapshot alone answers (V-11): its card's reason


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
Each past cycle carries its source. [EXERCICE]: a declared test (an injector's exercise
window covered that VM) — it shows how a technique looks, it is never a precedent for a real
incident. [RÉEL]: no exercise covered it — a real precedent. [source inconnue]: recorded
before sources existed. Never lower or raise your confidence in the CURRENT signal because a
similar exercise happened; whether the current signal belongs to an exercise is not given
to you and must not change your decision.

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

# Detection-rule authoring (tool schema, system prompt, grounded LLM call) lives in
# glorfindel/detection_authoring.py — the single source shared by this reactive node
# and the proactive `glorfindel propose-rules` cold-start command.


# ── Nodes ─────────────────────────────────────────────────────────────────────

def load_context(
    state: GlorfindelState,
    *,
    memory: CycleMemory,
    incidents: IncidentRegistry,
) -> GlorfindelState:
    """Retrieve past cycles from vector store and open/update the incident record.

    A control-plane detection (AL1) is decided without the model: no past cycles. And
    unless the RulePoller tied it to its VM (`attribution: asset`, a role assigned on the
    VM), it opens no incident and feeds none: its VM is an anchor, and the next data-plane
    cycle there would read « T1562.007, 2 signals » about a VM nothing happened to.

    An identity detection (Entra ID, C2) names no VM: it never opens nor feeds an incident,
    and is given no past cycle.

    The past cycles are real ones only, for every signal, an exercise's too (SEC4a, V-12):
    never an exercise's cycle, nor one of unknown source."""
    from dataclasses import asdict

    signal = state["signal"]
    if _is_identity(signal):
        return {**state, "past_cycles": [], "incident": None}
    if _is_control_plane(signal):
        if (signal.get("context") or {}).get("attribution") != "asset":
            return {**state, "past_cycles": [], "incident": None}
        inc = incidents.get_or_create(resource_id=signal.get("resource_id", ""),
                                      ttp=signal.get("ttp", ""))
        return {**state, "past_cycles": [], "incident": asdict(inc)}
    # SEC4a (V-12): real cycles only, for every signal (memory.retrieve_similar).
    past = memory.retrieve_similar(state["signal"], n=3)
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


def _row_reader(resource_id: str, ip_owners=None):
    """`row → True/False/None`: does a detection row name this VM — True, another VM —
    False, none — None. The RulePoller's reading (`detection_rules.RowAttribution`), over
    this VM and every VM whose private IP Azure lists (`ip_owners`): the host name of two
    of them names neither, and a call made from this VM's private IP names it (T1041)."""
    from glorfindel.detection_rules import RowAttribution
    try:
        owners = {ip: str(rid).lower() for ip, rid in ((ip_owners() if ip_owners else None) or {}).items()}
    except Exception as exc:            # unreadable: an address names no VM (held, never a guess)
        _console.print(f"  [yellow]IP privées des VMs illisibles ({_first_line(exc)}) — une ligne "
                       "sans ressource ni nom d'hôte reste non attribuée[/yellow]")
        owners = {}
    known = {rid: (rid, rid.rstrip("/").split("/")[-1]) for rid in set(owners.values())}
    if resource_id:
        known[resource_id.lower()] = (resource_id, resource_id.rstrip("/").split("/")[-1])
    index = RowAttribution(list(known.values()), lambda: owners)

    def names(row) -> bool | None:
        named, target = index.attribute(row)
        if not named:
            return None
        return target is not None and bool(resource_id) and target[0].lower() == resource_id.lower()
    return names


def resolve_attack_started(signal: dict, ip_owners=None) -> dict:
    """Poll the detection source for an attack_started signal and return the resolved signal.

    Detection config is resolved in priority order:
    1. Fields in the signal's raw_signal (backward compat / explicit override)
    2. Matching rule in glorfindel/rules/azure/detection_rules.yaml (primary source)

    Returns a signal with event='detection' (+ detection_time_s, detected_data) or
    event='detection_timeout'. Called by poll_detection (respond mode) and by
    watch poll threads (watch mode, so polling runs in parallel per resource).

    What comes from the line, what comes from the monitoring (SEC4a): the line names the
    VM and the moment; the detection is the row the rule finds. Its `attack_time` is
    bounded (`signal_origin.attack_time_refusal`: refused, a ValueError — the watch
    refuses the line before, `respond` makes it a cycle_failed card). On a data-plane
    detection the poll keeps the rows naming that VM or none (never one naming another
    VM); a row that does not name it is pinned to the VM all the same, `unattributed`: the
    attribution guard of `decide` holds the actions aimed at it. A row is read as the
    RulePoller reads it (`detection_rules.RowAttribution`): its resource, its host name,
    then the private IP that made the call — `ip_owners` (IP → VM id, the connector's
    `private_ip_owners`; none: an address names no VM).
    """
    from glorfindel.detectors import detector_for, is_control_plane_source, is_identity_source
    from glorfindel.detection_rules import _reads_activity_table, _reads_entra_table
    from glorfindel.signal_origin import attack_time_refusal

    raw = signal.get("raw_signal", {})
    source = raw.get("detection_source", "")
    query = raw.get("detection_query", "")
    workspace_id = raw.get("log_analytics_workspace_id", "")
    timeout_s = float(raw.get("detection_timeout_s", 300))
    if "attack_time" in raw:
        refused = attack_time_refusal(raw.get("attack_time"))
        if refused:
            raise ValueError(f"attack_started refusé : {refused}")
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

    # A query on one of Entra ID's tables, whatever its source (C2): an identity
    # detection — decided by the code, its UPN never sent to the model.
    entra_query = _reads_entra_table(query) and not is_control_plane_source(source)
    # The same for Azure's Activity Log read by another source (N-10): the control plane.
    activity_query = (not entra_query and not is_identity_source(source)
                      and not is_control_plane_source(source) and _reads_activity_table(query))
    # The data plane: a row says which VM it is about. The control plane and identities
    # are detection only, whatever row (AL1, C2): their rows name an NSG, a role, a user.
    data_plane = not (is_control_plane_source(source) or is_identity_source(source)
                      or entra_query or activity_query)
    vm_rid = signal.get("resource_id") or ""
    names_vm = _row_reader(vm_rid, ip_owners) if data_plane else None

    _console.print(f"[cyan]->[/cyan] Polling {source} (timeout={int(timeout_s)}s)...")
    if data_plane:
        result = detector.poll_alert(query, since=attack_time, timeout_s=timeout_s,
                                     match_row=lambda row: names_vm(row) is not False)
    else:
        result = detector.poll_alert(query, since=attack_time, timeout_s=timeout_s)

    if result is not None:
        detection_s, detected_row = result
        # Measure from the attack (Annatar's T0), not from when the signal arrived:
        # attack_started is emitted after the attack steps, so the poll's own elapsed
        # time said 42 s for ~135 s of real detection time (run 2026-10-05).
        since_attack = time.time() - attack_time
        if "attack_time" in raw and 0 < since_attack < 86400:
            detection_s = round(since_attack)
        from glorfindel.detection_rules import normalize_row
        context = dict(signal.get("context") or {})
        if entra_query:
            context["plane"] = "identity"
        elif activity_query:
            context["plane"] = "control"
        if data_plane and names_vm(detected_row) is not True:
            # The row names no VM (aggregated by address, a storage account): the line's
            # VM is a guess — the same hold as an unattributed row of the RulePoller.
            context.update(attribution="unattributed", attribution_from="attack_started",
                           candidates=[vm_rid.rstrip("/").split("/")[-1] or "?"])
        return {
            **signal,
            **({"context": context} if context != (signal.get("context") or {}) else {}),
            "event": "detection",
            "raw_signal": {
                **raw,
                # A control-plane source says so (AL1): the guard of `decide` reads it. A
                # data-plane signal is unchanged — what the model sees stays the same.
                **({"detection_source": source}
                   if is_control_plane_source(source) or is_identity_source(source) else {}),
                "detection_time_s": detection_s,
                "detected_data": detected_row,
                "normalized_signal": normalize_row(detected_row, ttp=signal.get("ttp", "")),
            },
        }

    _console.print(f"  [yellow]Detection timeout after {int(timeout_s)}s — IDS gap[/yellow]")
    return {**signal, "event": "detection_timeout"}


def poll_detection(state: GlorfindelState, ip_owners=None) -> GlorfindelState:
    """Resolve attack_started → detection/timeout (respond mode).

    No-op for all other events. In watch mode this node is never reached for
    attack_started — the watch poll thread calls resolve_attack_started directly
    and enqueues the resolved signal.
    """
    signal = state["signal"]
    if signal.get("event") != "attack_started":
        return state
    return {**state, "signal": resolve_attack_started(signal, ip_owners=ip_owners)}


# ── Investigative queries (post-detection enrichment) ─────────────────────────

# Query templates — {vm} is replaced at runtime with the VM hostname, {ip} with the
# detection's source address: each a KQL string literal (glorfindel/kql.py), checked for
# what it is first (SEC4c) — a value read from a log line never leaves its literal.
# All queries use ago(5m) to stay within the detection window.
# Kept short: investigate must complete in <15s total.

_IQ_HEARTBEAT_GAP = """
Heartbeat
| where Computer == {vm}
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
| where Computer == {vm}
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
| where Computer == {vm}
| where ObjectName == "Process"
| where CounterName == "IO Write Bytes/sec"
| where InstanceName in~ ("waagent", "WALinuxAgent", "azure-backup", "snapd", "MicrosoftAzureRecoveryServices")
| summarize MaxWriteMBs = round(max(CounterValue) / 1048576, 1) by InstanceName
"""

_IQ_SUCCESS_AUTH = """
Syslog
| where TimeGenerated > ago(5m)
| where Computer == {vm}
| where Facility == "auth"
| where ProcessName in ("sshd", "sshd-session")
// sshd's own wording, at the start of the line (SEC2): never a user name holding it.
| where SyslogMessage startswith "Accepted " and SyslogMessage has {ip}
| project TimeGenerated, SyslogMessage
| limit 3
"""

# ago(10m) rather than ago(5m): privilege escalation takes ~40s, root commands
# follow immediately — a 5m window risks missing activity that started before
# the detection signal was processed.
_IQ_ROOT_COMMANDS = """
Syslog
| where TimeGenerated > ago(10m)
| where Computer == {vm}
// sudo logs to authpriv (measured under AMA).
| where Facility in ("auth", "authpriv")
// sudo's own lines (SEC2): the word is its tag (ProcessName), not in the message.
| where ProcessName == "sudo"
| where SyslogMessage has "USER=root" and SyslogMessage has "COMMAND="
| project TimeGenerated, SyslogMessage
| limit 10
"""

_IQ_DISK_AFTER_ESC = """
Perf
| where TimeGenerated > ago(10m)
| where Computer == {vm}
| where ObjectName in ("Logical Disk", "LogicalDisk")
| where CounterName == "Disk Write Bytes/sec"
| summarize MaxWriteMBs = round(max(CounterValue) / 1048576, 1),
            AvgWriteMBs = round(avg(CounterValue) / 1048576, 1)
"""


def _run_investigative_query(workspace_id: str, query: str) -> list[dict] | None:
    """Run a single investigative query: its rows, or None when it FAILED (workspace
    unreachable, throttled, query refused).

    A failure used to come back as [] — "no rows": no backup agent writing, no reboot,
    no successful login. The model read an absence the telemetry never vouched for, and
    that absence argues for the disruptive action (G2). The model still sees [] (what it
    sees is unchanged); the failure is kept apart, for the telemetry guard of `decide`."""
    try:
        from glorfindel.detectors import detector_for
        det = detector_for("azure_monitor", workspace_id=workspace_id)
        return det.run_query(query.strip()) or []
    except Exception:
        return None


def investigate(state: GlorfindelState) -> GlorfindelState:
    """Enrich the signal with targeted investigative queries before decide.

    Only runs on event=detection with a resolvable workspace_id.
    Queries are chosen based on signal content (not TTP label).
    Results land in raw_signal.investigative_context — the LLM sees them.
    A failed query is best-effort for the model (it sees [] as before) but not for the
    gates: its name goes to `telemetry_gaps` (state and debug line, never the signal),
    a console line says so, and the telemetry guard of `decide` holds a disruptive
    action decided on it (G2).
    """
    signal = state["signal"]

    if signal.get("event") != "detection":
        return state
    # A control-plane detection (AL1): decided without the model, and its VM may be an
    # anchor — no Perf/Syslog query on it.
    if _is_control_plane(signal):
        return state
    # An identity detection (C2): decided without the model, its VM an anchor.
    if _is_identity(signal):
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
    vm = str(hostname_from_signal or signal.get("resource_id", "").split("/")[-1])

    if using_arm_fallback:
        _console.print(
            f"  [dim]investigate: Computer absent from signal — "
            f"using ARM name '{_esc_markup(vm)}' as hostname fallback "
            f"(queries may return empty if OS hostname differs)[/dim]"
        )

    ctx: dict[str, list[dict]] = {}
    gaps: list[str] = []
    refused: dict[str, str] = {}

    # Each value enters its query as a KQL literal, checked for what it is (SEC4c): a host
    # name, an address — read from a log line, which anyone on the VM can shape. A value
    # that is not one: its queries are not run, and the enquiry says so (a gap, like a
    # failed query: the guard of `decide` holds a disruptive action).
    from glorfindel import kql

    def value(check, raw_value) -> str | None:
        try:
            return kql.literal(check(raw_value))
        except kql.UnsafeValue as exc:
            refused.setdefault(str(raw_value)[:60], str(exc))
            return None

    vm_lit = value(kql.name, vm)

    def run(name: str, template: str, **values) -> None:
        if any(v is None for v in values.values()):
            gaps.append(name)             # not run: unknown, not "nothing found"
            ctx[name] = []
            return
        rows = _run_investigative_query(workspace_id, template.format(**values))
        if rows is None:              # failed: unknown, not "nothing found" (G2)
            gaps.append(name)
            rows = []
        ctx[name] = rows

    # ── Disk write anomaly → which process is writing? backup agent present? recent reboot?
    if "MaxWrite" in first_row or "DiskWrite" in first_row:
        run("top_write_processes", _IQ_DISK_PROCESSES, vm=vm_lit)
        run("backup_agent_check", _IQ_BACKUP_AGENT, vm=vm_lit)
        # Azure Backup OriginalLocation restore causes high I/O during boot rewrite.
        # A Heartbeat gap > 10min indicates a recent VM reboot — raises suspicion of
        # legitimate post-restore I/O rather than active ransomware encryption.
        run("heartbeat_gap", _IQ_HEARTBEAT_GAP, vm=vm_lit)

    # ── Brute force → did any attempt succeed from this IP?
    source_ip = first_row.get("SourceIP", "")
    if "FailedAttempts" in first_row and source_ip:
        run("successful_auth_from_ip", _IQ_SUCCESS_AUTH, vm=vm_lit,
            ip=value(kql.ip, source_ip))

    # ── Privilege escalation → what ran as root after? disk writes?
    if "USER=root" in syslog_msg and "COMMAND=" in syslog_msg:
        run("root_commands", _IQ_ROOT_COMMANDS, vm=vm_lit)
        run("disk_write_after_escalation", _IQ_DISK_AFTER_ESC, vm=vm_lit)

    if not ctx:
        return state

    if refused:
        _console.print(
            "  [yellow]investigate: valeur refusée, requête(s) non lancée(s) — "
            + "; ".join(_esc_markup(why) for why in refused.values())
            + " — aucune action disruptive autonome sur ce cycle[/yellow]"
        )
    if gaps:
        _console.print(
            f"  [yellow]investigate: {len(gaps)} requête(s) en échec pour '{_esc_markup(vm)}' "
            f"({', '.join(gaps)}) — télémétrie incomplète, aucune action disruptive "
            f"autonome sur ce cycle[/yellow]"
        )

    if all(len(v) == 0 for v in ctx.values()):
        if using_arm_fallback:
            _console.print(
                f"  [yellow]investigate: all queries empty for '{_esc_markup(vm)}' (ARM fallback) "
                f"— likely hostname mismatch, check OS hostname vs ARM name[/yellow]"
            )
        else:
            _console.print(
                f"  [dim]investigate: all queries empty for '{_esc_markup(vm)}' "
                f"— data not yet ingested (LAW latency ~60s, normal)[/dim]"
            )

    enriched = {
        **signal,
        "raw_signal": {**raw, "investigative_context": ctx},
    }
    # The gaps stay in the state, never in the signal: the whole signal is the model's
    # input (_build_user_message), and what the model sees is unchanged.
    return {**state, "signal": enriched, "telemetry_gaps": gaps}


# Autonomous actions that DISRUPT the VM / network / access (vs read-only `snapshot`
# or the reversal `release_isolation`). The deterministic signal guardrail refuses to
# run THESE autonomously on an uncharacterized signal.
_DISRUPTIVE_AUTONOMOUS = {"isolate_vm", "block_suspicious_ip", "revoke_temp_access"}

# Autonomous actions execute_action can actually run. An action announced in
# AUTONOMOUS_ACTIONS (so in the prompt) without an implementation used to end as a no_op
# recorded as executed, then notified (`revoke_temp_access`, removed from the list on
# 2026-10-06). The guard keeps that from happening again to the next one.
_EXECUTABLE_ACTIONS = {"isolate_vm", "release_isolation", "block_suspicious_ip", "snapshot"}

# Escalation type for each deterministic gate (escalate_to_human). Without it, a
# signal-guardrail or release hold fell through to `low_confidence`, labelled
# "detection timeout".
_HELD_BY_TYPE = {
    "not_implemented": "proposed_action",
    "confidence": "low_confidence",
    "signal_guardrail": "uncharacterized_signal",
    "release_precondition": "release_hold",
    "attribution": "unattributed_signal",
    "telemetry": "telemetry_gap",
    "agreement": "unstable_decision",
    "control_plane": "control_plane_change",
    "identity": "identity_change",
    "never_block": "protected_address",
}

# Actions aimed at ONE VM. On a detection the RulePoller could not tie to that VM (a row
# aggregated by attacker IP, several VMs monitored) they are held: the same row is
# dispatched for every VM. An IP block or a snapshot stays autonomous.
_VM_TARGETED_ACTIONS = {"isolate_vm", "revoke_temp_access"}


def _as_bool(v) -> bool:
    """Coerce an LLM-provided value to a real bool.

    Some models return JSON booleans as strings ("true"/"false") — and "false" is
    truthy in Python, which would silently defeat the escalation/confidence gate.
    Map the common textual forms; anything else falls back to Python truthiness."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes", "y"}
    return bool(v)


# Retries on the decision call (rate limit, timeout, transient provider error) before the
# cycle gives up and escalates as `cycle_failed`.
_LLM_RETRIES = 2


def _confidence_threshold() -> float:
    """The gate's threshold (`config.confidence_threshold`: infinite when malformed —
    every autonomous action held), with a console line when it is."""
    from glorfindel.config import confidence_threshold
    value = confidence_threshold()
    if math.isinf(value):
        raw = os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD", "")
        _console.print(
            f"[yellow]GLORFINDEL_CONFIDENCE_THRESHOLD={raw!r} invalide — toute action "
            f"autonome est retenue jusqu'à correction[/yellow]"
        )
    return value


def _parse_decision(response) -> tuple[dict, object]:
    """Extract and normalize the security_decision tool-call. Returns (d, raw_conf).

    Extract the tool-call defensively. Despite tool_choice forcing it, some models
    return NO tool-call (tool_calls None/[] → tool_calls[0] raises TypeError) or
    malformed JSON arguments. Treat any of these as "no decision" → empty d → the
    normalization below forces escalation (no action). Found by the provider smoke
    (mistral-nemo: <error: TypeError> when tool_calls was None).

    Hard-default + coerce EVERY decision field before anything reads it. A
    non-conforming model can (a) omit a required field → KeyError crashes the cycle,
    (b) return JSON booleans as STRINGS ("false" is truthy in Python → `not
    d["escalate"]` is False → the confidence gate is silently bypassed), (c) send a
    non-numeric confidence → float() raises. All seen in the multi-run provider smoke
    (scripts/llm_smoke.py): llama3.2 string booleans, command-r7b omitted a field.
    Defensive parsing so a quirky model can't crash or defeat a safety control.

    Every field is read for its type (SEC4a, V-23): an action that is not text (a list, a
    number, an object), a confidence that is not a number (a boolean among them), steps
    that are not a list of text — the field is unreadable, never an exception. An
    unreadable action is no action: escalated. Only the schema's fields are kept: a key
    the model adds (`held_by`…) never reaches the gates. Never raises.
    """
    import json
    try:
        tool_calls = getattr(response.choices[0].message, "tool_calls", None) or []
        args = tool_calls[0].function.arguments if tool_calls else {}
        raw = args if isinstance(args, dict) else json.loads(args)
    except Exception:              # no tool-call, arguments not JSON, nested too deep…
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    d: dict = {}
    action = raw.get("action")
    d["action"] = action.strip() if isinstance(action, str) else ""
    d["reasoning"] = _as_text(raw.get("reasoning"))
    d["explanation"] = _as_text(raw.get("explanation"))
    d["escalation_reason"] = _as_text(raw.get("escalation_reason"))
    d["suggested_steps"] = _as_steps(raw.get("suggested_steps"))
    d["escalate"] = _as_bool(raw.get("escalate"))
    d["reversible"] = _as_bool(raw.get("reversible")) if raw.get("reversible") is not None else True
    raw_conf = raw.get("confidence")
    try:
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float, str, type(None))):
            raise TypeError("confidence is not a number")
        confidence = float(raw_conf) if raw_conf is not None else 0.0
        # A confidence is a number of [0, 1] (SEC4a): NaN, an infinity, 5.0, 85 or -0.4
        # is no confidence at all — unknown, held by the confidence gate (G2 bounded them,
        # and an out-of-range value then read 100 %).
        if raw_conf is not None and not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence outside [0, 1]")
    except (TypeError, ValueError, OverflowError):
        raw_conf = None
        confidence = 0.0
    d["confidence"] = confidence
    # No action parsed → cannot act safely → force human review. `if not` rather than
    # setdefault: the schema asks for "" when there is nothing to say, and an explicit ""
    # used to survive setdefault → an escalation with no reason.
    if not d["action"]:
        d["escalate"] = True
        if action is not None and not isinstance(action, str):
            d["escalation_reason"] = (
                f"Action illisible (le modèle a rendu un {type(action).__name__}, pas un nom "
                "d'action) — revue humaine requise."
                + (f" {d['escalation_reason']}" if d["escalation_reason"] else ""))
        elif not d["escalation_reason"]:
            d["escalation_reason"] = "LLM returned no action — human review required"
    return d, raw_conf


def _as_text(v) -> str:
    """A text field of the decision: text as it came, nothing for None, anything else
    written out (a model returning an object for its reasoning) — never an exception."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        import json
        return json.dumps(v, default=str)[:4000]
    except Exception:
        return ""


def _as_steps(v) -> list[str]:
    """`suggested_steps`: a list of text. One text is one step; anything else, none."""
    if isinstance(v, str):
        return [v] if v.strip() else []
    if not isinstance(v, list):
        return []
    return [s if isinstance(s, str) else _as_text(s) for s in v if s is not None][:20]


def _apply_executable_guard(d: dict) -> None:
    """An autonomous action with no implementation is never "executed"."""
    if d["escalate"] or d["action"] not in AUTONOMOUS_ACTIONS:
        return
    if d["action"] in _EXECUTABLE_ACTIONS:
        return
    d["escalate"] = True
    d["held_by"] = "not_implemented"
    d["escalation_reason"] = (
        f"Action '{d['action']}' pas encore implémentée par Glorfindel — retenue pour "
        "revue humaine (à exécuter à la main si elle est justifiée)."
    )


def _apply_confidence_gate(d: dict, raw_conf, threshold: float) -> None:
    """An autonomous action below the confidence threshold is escalated."""
    if not d["escalate"] and d["action"] in AUTONOMOUS_ACTIONS:
        if raw_conf is None or not d["confidence"] >= threshold:
            shown = "unknown" if raw_conf is None else f"{d['confidence']:.0%}"
            d["escalate"] = True
            d["held_by"] = "confidence"
            d["escalation_reason"] = f"Low confidence ({shown}) — human review required"
            if math.isinf(threshold):
                d["escalation_reason"] = (
                    f"Seuil de confiance invalide (GLORFINDEL_CONFIDENCE_THRESHOLD) — action "
                    f"'{d['action']}' (confiance {shown}) retenue pour revue humaine. "
                    "Corriger la valeur (entre 0 et 1) pour qu'une action puisse partir seule.")


def _is_control_plane(signal: dict) -> bool:
    """A detection on what was done to the cloud's resources (AzureActivity, AL1): the
    RulePoller says so (`context.plane`), and so does the source it read. In depth, the
    row itself: an AzureActivity row read by a rule of another source (`azure_monitor`,
    a backend of another type) loses both — its `OperationNameValue`, its table (`Type`), or
    its normalised indicator, still says so; and a rule of another source whose query reads
    AzureActivity carries `plane: control` from its query (N-10), whatever it projects."""
    from glorfindel.detectors import is_control_plane_source
    ctx = signal.get("context") or {}
    raw = signal.get("raw_signal") or {}
    if ctx.get("plane") == "control" or is_control_plane_source(str(raw.get("detection_source") or "")):
        return True
    rows = [r for r in (raw.get("first_result_row"), raw.get("detected_data")) if isinstance(r, dict)]
    return (any(r.get("OperationNameValue") for r in rows)
            or any(str(r.get("Type") or "").lower() == "azureactivity" for r in rows)
            or (raw.get("normalized_signal") or {}).get("indicator_key") == "control_plane_operation")


def _control_plane_row(signal: dict) -> dict:
    raw = signal.get("raw_signal") or {}
    return raw.get("first_result_row") or raw.get("detected_data") or {}


def _control_plane_text(signal: dict) -> tuple[str, list[str]]:
    """What a control-plane detection says, from the row alone (AL1): the operation, its
    status as read, the caller, its address, the target, the gravest marks, the
    operations a summary card carries — and the next steps for a human."""
    from glorfindel.detection_rules import normalize_row
    row = _control_plane_row(signal)
    norm = (signal.get("raw_signal") or {}).get("normalized_signal") or normalize_row(row, signal.get("ttp", ""))
    op = norm.get("indicator_value") or "?"
    status = str(row.get("ActivityStatusValue") or "").strip()
    who = norm.get("caller") or "appelant inconnu"
    where = f" depuis {norm['caller_ip']}" if norm.get("caller_ip") else ""
    target = norm.get("resource") or "?"
    what = f"Plan de contrôle : {op}{f' ({status})' if status else ''} par {who}{where} sur {target}."
    # An operation seen at its Start may still fail: the card says the status it read.
    if status.lower() in ("start", "started", "accept", "accepted"):
        what += " Statut lu au stade « " + status + " » : l'opération a pu échouer ensuite."
    steps = ["Vérifier dans le journal d'activité qui a fait cette opération, et pourquoi"
             + (f" (CorrelationId {row['CorrelationId']})" if row.get("CorrelationId") else "") + "."]
    if norm.get("glorfindel_managed"):
        what += (" Une règle gérée par Glorfindel (isolation, quarantaine ou blocage) a été "
                 "écrite par un autre appelant : une isolation ou un blocage a pu être levé. "
                 "Vérifier l'état réel de l'isolation ou du blocage sur Azure avant tout.")
        steps.append("Vérifier sur Azure que l'isolation ou le blocage est toujours en place.")
    if norm.get("glorfindel_identity"):
        what += (" L'identité de Glorfindel a fait une opération qu'il ne fait pas, ou sur une "
                 "ressource qui n'est pas à lui : ses identifiants sont peut-être entre "
                 "d'autres mains.")
        steps.append("Si l'opération n'est pas expliquée : renouveler les identifiants de Glorfindel.")
    omitted = row.get("OmittedOperations") or []
    if omitted:
        listed = "; ".join(
            f"{o.get('OperationNameValue') or '?'} par {o.get('Caller') or '?'} sur "
            f"{o.get('_ResourceId') or '?'} ({str(o.get('TimeGenerated') or '')[:19]})"
            for o in omitted)
        what = (f"Plan de contrôle : {len(omitted)} opération(s) de plus dans le même relevé, "
                f"au-delà des cartes individuelles — chacune listée ici : {listed}.")
        if any(o.get("GlorfindelManaged") for o in omitted):
            what += " Au moins une écrit une règle gérée par Glorfindel."
        if any(o.get("GlorfindelIdentity") for o in omitted):
            what += " Au moins une est faite sous l'identité de Glorfindel."
    steps.append("Annuler le changement s'il n'est pas légitime ; s'il l'est (un pipeline connu), "
                 "l'exclure dans la couche du client.")
    return what, steps


def _control_plane_decision(state: GlorfindelState) -> GlorfindelState:
    """The decision on a control-plane detection (AL1), built by the code — no model.

    A row of the Activity Log says who did what to which resource: an NSG rule changed,
    a role assigned, a snapshot taken. The answer is a human's — revert a change, revoke an
    identity — and the VM the card is anchored on may have nothing to do with it. So no
    investigation (its Perf/Syslog queries would read the anchor VM), no call to the model
    (it would only add text, at a cost, and send an administrator's name to the provider),
    and no action recommended: an escalation `control_plane_change`, never approvable in
    one click, whose reason says the operation, the target, the caller, the gravest cases
    — a write by someone else on a rule Glorfindel manages (an isolation or a block may be
    gone), Glorfindel's identity outside what it does — and the severity."""
    signal = state["signal"]
    what, steps = _control_plane_text(signal)
    severity = "critique" if signal.get("severity") == "critical" else "haute"
    reason = (f"{what} Sévérité : {severity}. Détection seule : aucune action autonome sur le "
              "plan de contrôle — décision déterministe, sans appel au modèle ; revue humaine.")
    return {
        **state,
        "reasoning": "Plan de contrôle : décision déterministe (AL1), sans appel au modèle.",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": what,
        "escalate": True,
        "escalation_reason": reason,
        "suggested_steps": steps,
        "llm_usage": None,
        "autonomy_mode": "",
        "mode_hold": False,
        "held_by": "control_plane",
        "autonomy_gate": {},
        "decision_draws": [],
    }


def _is_identity(signal: dict) -> bool:
    """A detection on what was done to an identity (Entra ID's logs, C2): the RulePoller
    says so (`context.plane` — from the source, or from the query when a rule of another
    source reads an Entra table, whatever it projects), and so does the source it read. In
    depth, the row itself: its columns (`EntraOperation`, `InitiatedBy`, `TargetResources`,
    `ServicePrincipalId`…), its table (`Type`), or its normalised indicator."""
    from glorfindel.detectors import is_identity_source
    from glorfindel.providers.azure.entra import ENTRA_TABLES, IDENTITY_COLUMNS
    ctx = signal.get("context") or {}
    raw = signal.get("raw_signal") or {}
    if ctx.get("plane") == "identity" or is_identity_source(str(raw.get("detection_source") or "")):
        return True
    rows = [r for r in (raw.get("first_result_row"), raw.get("detected_data")) if isinstance(r, dict)]
    return (any(r.get(c) for r in rows for c in IDENTITY_COLUMNS)
            or any(str(r.get("Type") or "").lower() in ENTRA_TABLES for r in rows)
            or (raw.get("normalized_signal") or {}).get("indicator_key") == "identity_operation")


def _identity_decision(state: GlorfindelState) -> GlorfindelState:
    """The decision on an identity detection (C2), built by the code — no model, no action.

    A row of Entra ID's logs says who added a credential, consented to an application,
    assigned a privileged role, or which service principal signed in from where. The
    answer is a human's — revoke a credential, a consent, a role, block a sign-in — and an
    autonomous action on an identity is the costliest false positive there is (an
    administrator locked out); `revoke_service_principal` does not exist. So no
    investigation, no call to the model (its text would carry a user's name — a UPN — to the
    provider), no action recommended: an escalation `identity_change`, never approvable in
    one click, whose reason says what, who, on which identity, the gravest cases
    (Glorfindel's identity as the actor or the target) and the severity, and whose steps
    say how to check and how to revoke (`entra.describe`)."""
    from glorfindel.providers.azure.entra import describe
    signal = state["signal"]
    raw = signal.get("raw_signal") or {}
    row = dict(raw.get("first_result_row") or raw.get("detected_data") or {})
    norm = raw.get("normalized_signal") or {}
    # A row normalised with its marks (the RulePoller's) keeps them.
    row.setdefault("GlorfindelIdentity", norm.get("glorfindel_identity") is True)
    row.setdefault("GlorfindelManaged", norm.get("glorfindel_managed") is True)
    what, steps = describe(row)
    severity = "critique" if signal.get("severity") == "critical" else "haute"
    reason = (f"{what} Sévérité : {severity}. Détection seule : aucune action autonome sur une "
              "identité — décision déterministe, sans appel au modèle ; revue humaine.")
    return {
        **state,
        "reasoning": "Identité : décision déterministe (C2), sans appel au modèle.",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": what,                # the card's text, nothing for a model
        "escalate": True,
        "escalation_reason": reason,
        "suggested_steps": steps,
        "llm_usage": None,
        "autonomy_mode": "",
        "mode_hold": False,
        "held_by": "identity",
        "autonomy_gate": {},
        "decision_draws": [],
    }


def _apply_signal_guardrail(d: dict, signal: dict) -> None:
    """Deterministic signal guardrail (model-independent).

    The confidence gate trusts the model to report low confidence on a thin signal —
    but weak models report HIGH confidence on a vague signal (provider smoke: 0.85 on
    an uncharacterized row), defeating it. So, independently of the LLM: a DISRUPTIVE
    autonomous action on a signal with NO recognized threat indicator (normalize_row →
    generic-fallback / "unknown" / an uncurated Syslog line) is held for human review.
    A characterized-but-ambiguous signal (e.g. syslog account creation) is NOT caught
    here — that's the confidence gate's job. To "bless" a new indicator, add it to
    detection_rules._INDICATOR_COLUMNS (or a Syslog pattern to _CURATED_SYSLOG_PATTERNS).
    """
    if d["escalate"] or d["action"] not in _DISRUPTIVE_AUTONOMOUS:
        return
    from glorfindel.detection_rules import has_recognized_indicator
    raw = signal.get("raw_signal", {})
    first_row = raw.get("detected_data") or raw.get("first_result_row") or {}
    if not has_recognized_indicator(first_row, signal.get("ttp", "")):
        d["escalate"] = True
        d["held_by"] = "signal_guardrail"
        d["escalation_reason"] = (
            "Signal sans indicateur de menace reconnu — action disruptive "
            f"'{d['action']}' retenue pour revue humaine (garde-fou déterministe, "
            "indépendant de la confiance du LLM)."
        )


def _apply_attribution_guard(d: dict, signal: dict) -> None:
    """An action aimed at this VM, on a detection not attributed to it, is held.

    The RulePoller anchors an unattributed detection (no VM named, no VM's private IP
    behind the call) on one monitored VM so it has a card. Isolating that VM — or
    blocking the IP on its NSG only — would act on a guess (third review, L11/L13)."""
    if d["escalate"] or d["action"] not in _VM_TARGETED_ACTIONS | {"block_suspicious_ip"}:
        return
    ctx = signal.get("context") or {}
    if ctx.get("attribution") != "unattributed":
        return
    candidates = ", ".join(ctx.get("candidates") or []) or "?"
    d["escalate"] = True
    d["held_by"] = "attribution"
    if ctx.get("attribution_from") == "attack_started":
        # SEC4a: the line named the VM; the row the rule found does not.
        d["escalation_reason"] = (
            f"La ligne de détection trouvée ne nomme pas la VM que désigne le signal "
            f"attack_started ({candidates}) — '{d['action']}' retenue pour revue humaine. "
            "Vérifier dans la ligne de détection quelle VM elle concerne avant d'agir."
        )
        return
    d["escalation_reason"] = (
        f"Détection non attribuable à une VM (la ligne ne nomme aucune VM, et aucune IP "
        f"de VM surveillée n'est à l'origine) — '{d['action']}' retenue pour revue "
        f"humaine. VMs surveillées : {candidates}. Vérifier laquelle est concernée "
        "(ou bloquer au périmètre) avant d'agir."
    )


def _apply_never_block_guard(d: dict, signal: dict) -> None:
    """A block of an address on the never-block list is held, always (SEC2): Azure's
    platform, the private ranges, the loopback, glorfindel-config.yaml's `never_block`.
    Whatever the rule or the model said, and whichever gate held it first: the card says
    the address is protected (its own type), and the connector refuses the block anyway
    (`policy.blockable_ip`) — an approval of the card blocks nothing."""
    if d["action"] != "block_suspicious_ip":
        return
    from glorfindel.response.policy import protected_by
    ip = _extract_suspicious_ip(signal)
    try:
        held = protected_by(ip)
    except Exception as exc:          # the list unknown: never a block (fail closed)
        held = f"liste never_block illisible : {_first_line(exc)}"
    if not held:
        return
    before = d.get("escalation_reason") if d["escalate"] else ""
    d["escalate"] = True
    d["held_by"] = "never_block"
    d["escalation_reason"] = (
        f"Blocage de {ip} retenu : adresse protégée ({held}, liste never_block) — "
        "Glorfindel ne la bloque jamais, quelle que soit la règle ou le modèle. Vérifier "
        "d'où vient la détection (une ligne de journal peut nommer n'importe quelle adresse)."
        + (f" — {before}" if before else "")
    )


def _uncontained_floor(d: dict, signal: dict) -> str:
    """A characterized detection answered by a snapshot alone leaves a card (SEC4a, V-11).

    A snapshot is autonomous and contains nothing: the attack goes on, and the cycle used
    to end with a notification of the snapshot and no card — a detection no human was asked
    to judge, whatever the model's reason (a line of the log talking it down). A floor
    independent of the model: the snapshot still runs, and a card says what nothing
    contained. Returns the card's reason, or "" when the floor does not apply (the decision
    is escalated already: it has its card)."""
    if d["escalate"] or d["action"] != "snapshot" or signal.get("event") != "detection":
        return ""
    from glorfindel.detection_rules import has_recognized_indicator
    raw = signal.get("raw_signal") or {}
    row = raw.get("detected_data") or raw.get("first_result_row") or {}
    if not has_recognized_indicator(row, signal.get("ttp", "")):
        return ""
    # What a previous cycle already contains (the state files, the source of truth — never
    # the past cycles): an isolated VM, or this source already blocked, is contained.
    contained, note = _contained_now(signal)
    if contained:
        return ""
    return (
        f"Détection caractérisée ({signal.get('ttp') or '?'}) à laquelle seul un instantané a "
        f"répondu (confiance {d['confidence']:.0%}) : la VM n'est pas isolée"
        f"{note}, l'attaque peut continuer. Juger s'il faut isoler la VM ou bloquer la source "
        "(plancher déterministe, indépendant du modèle)."
    )


def _isolation_incomplete(iso: dict) -> str:
    """What leaves an isolation in place partial for the floor, or "" when it holds: not
    every NIC covered, a release under way, a release that failed halfway (SEC4c) — the VM
    may be reachable again."""
    if iso.get("partial"):
        return "isolation partielle"
    if iso.get("release_failed"):
        return "levée de l'isolation en échec : une partie des règles est déjà retirée"
    if iso.get("releasing_at"):
        return f"levée de l'isolation en cours depuis {str(iso['releasing_at'])[:25]}"
    return ""


def _contained_now(signal: dict) -> tuple[bool, str]:
    """(contained, note) from the state files: the VM isolated, or the detection's source
    already blocked on it → contained. Otherwise the note says what is blocked, or that the
    state could not be read (then the card is written: never a guess toward silence)."""
    from glorfindel.actions import _load_block_entries, _load_isolation_state
    rid = signal.get("resource_id") or ""
    try:
        iso = _load_isolation_state(rid)
        incomplete = _isolation_incomplete(iso) if iso is not None else ""
        if iso is not None and not incomplete:
            return True, ""
        if iso is not None:
            return False, f" entièrement ({incomplete})"
        blocked = [str(e.get("ip") or "") for e in _load_block_entries(rid)]
    except Exception as exc:
        return False, f" (état d'isolation illisible : {_first_line(exc)[:120]})"
    ip = _extract_suspicious_ip(signal)
    if ip and ip in blocked:
        return True, ""
    others = [b for b in blocked if b]
    return False, (f" (IP déjà bloquées sur cette VM, pas celle de cette détection : "
                   f"{', '.join(others[:5])})" if others else ", aucune source n'est bloquée")


def _apply_telemetry_guard(d: dict, gaps: list[str]) -> None:
    """A disruptive action decided while an investigative query failed is held (G2).

    The model read the failed queries as empty — no backup agent, no reboot, no login
    that succeeded — and those absences are what argue for isolating or blocking. The
    detection itself was read; the evidence around it was not. Independent of the
    model's confidence, like the signal guardrail. A snapshot stays autonomous.

    Already held by an earlier gate (low confidence…): that gate keeps the card, and its
    reason gains the failed queries — the operator approving it must know the evidence
    around the detection was not read (G2 review)."""
    if d["action"] not in _DISRUPTIVE_AUTONOMOUS or not gaps:
        return
    if d["escalate"]:
        d["escalation_reason"] = (
            f"{d.get('escalation_reason') or ''} — Télémétrie incomplète : {len(gaps)} "
            f"requête(s) d'enquête en échec ({', '.join(gaps)}), lues comme vides par le "
            "modèle. Les relancer dans Log Analytics avant d'approuver."
        ).lstrip(" —")
        return
    d["escalate"] = True
    d["held_by"] = "telemetry"
    d["escalation_reason"] = (
        f"Télémétrie incomplète : {len(gaps)} requête(s) d'enquête en échec "
        f"({', '.join(gaps)}). Le modèle les a lues comme vides : '{d['action']}' "
        "retenue pour revue humaine (garde déterministe, indépendante de sa confiance). "
        "Relancer les requêtes dans Log Analytics avant d'agir."
    )


def _apply_release_precondition(d: dict, signal: dict) -> None:
    """An autonomous release_isolation only answers a completed restore.

    Releasing un-contains a VM. The signal guardrail can't cover it: a recovery_complete
    signal carries no threat indicator, so putting release under that guardrail would
    hold the legitimate post-restore release (and break the restore → release flow).
    The rule is structural instead: `recovery_complete` — emitted by Glorfindel itself
    after a completed restore — is the only event that justifies releasing without a
    human. On any other signal, a model choosing release is held, whatever its
    confidence.
    """
    if d["escalate"] or d["action"] != "release_isolation":
        return
    from glorfindel.signal_origin import vouched
    if signal.get("event") == "recovery_complete" and not vouched(signal):
        # Not built by `glorfindel restore` in this process, nor read from where only the
        # defender writes it (SEC3, #274): who wrote it is unknown — a human decides.
        d["escalate"] = True
        d["held_by"] = "release_precondition"
        d["escalation_reason"] = (
            "Levée d'isolation proposée sur un recovery_complete que Glorfindel n'a pas émis "
            "(ni `glorfindel restore` sur cet hôte, ni ~/.glorfindel/recovery_signals/) — "
            "retenue pour revue humaine : vérifier que la restauration a eu lieu avant de lever "
            "l'isolation."
        )
        return
    neutralized = (signal.get("raw_signal") or {}).get("run_command_neutralized")
    # `is True`, not `is not False`: an absent flag (a restore that didn't neutralize,
    # a recovery_complete written by anything else) is an unknown, not a success.
    if signal.get("event") == "recovery_complete" and neutralized is True:
        return
    if signal.get("event") == "recovery_complete":
        # The restored disk may have replayed the attacker's last Run Command at boot
        # (seen 2026-10-05: the ransomware ran again, then the VM was released).
        d["escalate"] = True
        d["held_by"] = "release_precondition"
        vectors = [str(v) for v in (signal.get("raw_signal") or {}).get("replay_vectors") or []]
        if vectors:
            # Run Command v1 neutralized; what holds is another script the disk can run
            # again at boot (A3): say which, not "the last command".
            d["escalation_reason"] = (
                "Restauration terminée, mais la VM porte ce qu'un disque restauré peut rejouer au "
                "démarrage et que Glorfindel ne peut pas garantir : " + ", ".join(vectors) + ". "
                "Vérifier ces extensions (ou les retirer) et l'intégrité de la VM avant de lever "
                "l'isolation.")
            return
        d["escalation_reason"] = (
            ("Restauration terminée, mais la dernière commande Run Command n'a pas pu être "
             "neutralisée avant : " if neutralized is False else
             "Restauration terminée, mais la neutralisation de la dernière commande Run "
             "Command n'est pas confirmée (restore lancé hors `glorfindel restore --wait`) : ")
            + "le disque restauré a pu la rejouer au démarrage. "
            "Vérifier l'intégrité de la VM avant de lever l'isolation."
        )
        return
    d["escalate"] = True
    d["held_by"] = "release_precondition"
    d["escalation_reason"] = (
        f"Levée d'isolation proposée sur un événement '{signal.get('event', '?')}' — "
        "retenue pour revue humaine (garde-fou déterministe : seule une restauration "
        "terminée justifie une levée autonome)."
    )


def _apply_autonomy_mode(d: dict, mode: str, gate: dict | None = None) -> bool:
    """Autonomy mode policy layer (above the gates — never a bypass).

    human_only holds back EVERY autonomous action (even high-confidence ones) and
    escalates it as mode_hold instead. The destructive gate and the confidence gate
    remain active regardless. Returns True when the action was held by the mode.
    `gate`: the VM is configured autonomous but held by its readiness (`readiness.
    effective_mode`) — the reason says so, and how to lift it.
    """
    if mode == "human_only" and not d["escalate"] and d["action"] in AUTONOMOUS_ACTIONS:
        d["escalate"] = True
        if gate and gate.get("reason") == "config_unreadable":
            # The configured mode is unknown — the file holding it can't be read; only a
            # session --mode is known, and it is not applied (G2 review).
            session = gate.get("configured")
            d["escalation_reason"] = (
                f"{gate.get('message') or 'glorfindel-config.yaml illisible'} : mode "
                "configuré de la VM inconnu"
                + (f", `--mode {session}` de la session ignoré" if session else "")
                + f" — VM en human_only. Action '{d['action']}' recommandée (confiance "
                f"{d['confidence']:.0%}), approbation humaine requise. Corriger "
                "glorfindel-config.yaml : tant qu'il est illisible, aucune VM n'agit seule, "
                "`--mode` compris."
            )
        elif gate:
            lift = ("Corriger les points bloquants (`glorfindel activate`) pour qu'elle "
                    "agisse seule." if gate.get("reason") == "not_ready" else
                    "Confirmer la VM (console, page Glorfindel : « Review & turn on ») pour "
                    "qu'elle agisse seule la prochaine fois.")
            d["escalation_reason"] = (
                f"Réponse autonome configurée ({gate.get('configured', '?')}) mais VM "
                f"retenue en human_only — {gate.get('message', '')}. Action "
                f"'{d['action']}' recommandée (confiance {d['confidence']:.0%}), "
                f"approbation humaine requise. {lift}"
            )
        else:
            d["escalation_reason"] = (
                f"Mode human_only — action '{d['action']}' recommandée "
                f"(confiance {d['confidence']:.0%}) mais retenue : approbation humaine requise."
            )
        return True
    return False


# The first draw of a decision is asked at temperature 0 (D-1): reproducible where the
# model accepts it (claude-sonnet-4-6, local models). claude-sonnet-5-5, the default,
# refuses any temperature but its own (measured 26/10): there the first draw is the
# provider's default sampling, and the cycle records it (decision_temperature: None).
_DECISION_TEMPERATURE = 0.0


def _decision_draws() -> int:
    """The number of draws that must agree (`config.decision_draws`: 0 when malformed —
    every disruptive autonomous action held), with a console line when it is."""
    from glorfindel.config import decision_draws
    value = decision_draws()
    if not value:
        raw = os.environ.get("GLORFINDEL_DECISION_DRAWS", "")
        _console.print(
            f"[yellow]GLORFINDEL_DECISION_DRAWS={raw!r} invalide — toute action disruptive "
            f"autonome est retenue jusqu'à correction[/yellow]"
        )
    return value


def _draw_summary(d: dict) -> dict:
    return {"action": d["action"], "confidence": d["confidence"], "escalate": d["escalate"]}


def _draw_label(x: dict) -> str:
    if x.get("error"):
        return f"appel en échec ({x['error'][:80]})"
    label = f"{x.get('action') or 'aucune action'} {x.get('confidence', 0.0):.0%}"
    return f"{label}, escaladée" if x.get("escalate") else label


def _confirming_draws(litellm, call: dict, n: int, threshold: float) -> tuple[list[dict], list]:
    """`n` more draws of the same decision (same messages, same tool), at the model's default
    sampling: the variance the first draw's temperature removes is the one they probe. Each
    is parsed and passed through the executable guard and the confidence gate, like the
    first. A call that fails is a draw that did not agree. Returns (draws, responses)."""
    from concurrent.futures import ThreadPoolExecutor
    from eregion_core.llm_call import completion_with_tool

    def one(_):
        try:
            resp = completion_with_tool(litellm, "security_decision", **call)
        except Exception as exc:
            return {"action": "", "confidence": 0.0, "escalate": True,
                    "error": _first_line(exc)}, None
        x, raw_conf = _parse_decision(resp)
        _apply_executable_guard(x)
        _apply_confidence_gate(x, raw_conf, threshold)
        return _draw_summary(x), resp

    if n <= 0:
        return [], []
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(one, range(n)))
    return [r[0] for r in results], [r[1] for r in results if r[1] is not None]


def _apply_agreement_guard(d: dict, draws: list[dict], required: int) -> None:
    """A disruptive autonomous action runs only when every draw agrees (D-1).

    `draws`: the first draw, then the confirming ones. A draw agrees when it would have
    taken the same action alone — same action, not escalated (above the confidence
    threshold). Fewer draws than required, a failed call, or `required` 0 (malformed
    GLORFINDEL_DECISION_DRAWS): held. Independent of the first draw's confidence: the same
    brute force drew a block at 0.80 on 21/10 and an isolation at 0.78 on 23/10, both
    above the gate."""
    if d["escalate"] or d["action"] not in _DISRUPTIVE_AUTONOMOUS:
        return
    agree = [x for x in draws if not x.get("escalate") and x.get("action") == d["action"]]
    if required and len(draws) >= required and len(agree) == len(draws):
        return
    d["escalate"] = True
    d["held_by"] = "agreement"
    if not required:
        d["escalation_reason"] = (
            f"Nombre de tirages invalide (GLORFINDEL_DECISION_DRAWS) — action disruptive "
            f"'{d['action']}' (confiance {d['confidence']:.0%}) retenue pour revue humaine. "
            "Corriger la valeur (un entier de 2 à 10) pour qu'une action puisse partir seule.")
        return
    others = "; ".join(_draw_label(x) for x in draws if x not in agree) or "aucun"
    d["escalation_reason"] = (
        f"Décision instable : {len(agree)} tirage(s) sur {len(draws)} proposent "
        f"'{d['action']}' (les autres : {others}) — action disruptive retenue pour revue "
        "humaine (garde déterministe, indépendante de la confiance du LLM). Juger le signal "
        "avant d'agir."
    )


def _usage(responses: list) -> dict | None:
    """Token usage summed over every draw of the decision (P1 observability)."""
    usages = [u for u in (getattr(r, "usage", None) for r in responses) if u is not None]
    if not usages:
        return None
    fields = {"input_tokens": "prompt_tokens", "output_tokens": "completion_tokens",
              "cache_read_input_tokens": "cache_read_input_tokens",
              "cache_creation_input_tokens": "cache_creation_input_tokens"}
    return {k: sum(getattr(u, a, 0) or 0 for u in usages) for k, a in fields.items()}


_CYCLE_FAILED_STEPS = [
    "Trier le signal à la main : la menace a été détectée mais pas analysée jusqu'au bout.",
    "Vérifier le fournisseur LLM (GLORFINDEL_LLM_MODEL, clé API, quota, réseau) "
    "si l'erreur vient de la décision.",
    "Consulter runs/<run_id>_debug.jsonl et la console du watch pour l'erreur complète.",
]


def _decision_failed(state: GlorfindelState, exc: BaseException, mode: str = "") -> GlorfindelState:
    """State for a decision that could not be obtained (LLM call failed after retries).

    The cycle continues to escalate_to_human → store_cycle, so the detected threat
    reaches `pending` / the console / the debug file instead of one console line."""
    err = _first_line(exc)
    reason = (
        f"Décision impossible : l'appel LLM a échoué après {_LLM_RETRIES} nouvelles "
        f"tentatives ({err}). Le signal est détecté mais n'a pas été analysé — triage "
        "humain requis."
    )
    return {
        **state,
        "reasoning": "",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": "",
        "escalate": True,
        "escalation_reason": reason,
        "suggested_steps": list(_CYCLE_FAILED_STEPS),
        "llm_usage": None,
        "autonomy_mode": mode,
        "mode_hold": False,
        "cycle_error": f"decide: {err}",
    }


def decide(
    state: GlorfindelState, *, model: str, autonomy=None, autonomy_override: str | None = None,
    readiness_gate=None,
) -> GlorfindelState:
    """Call LLM to reason about the signal and produce a structured decision.

    Supports any provider via LiteLLM: anthropic/claude-*, openai/gpt-*, ollama/*,
    azure/*, or any OpenAI-compatible endpoint via GLORFINDEL_LLM_BASE_URL.

    autonomy: AutonomyConfig resolved per asset. A policy layer ABOVE the
    confidence gate (never a bypass): in human_only mode, every autonomous action
    is held back and escalated instead of executed.

    Hot-pickup: when autonomy is None (production), the config is reloaded FRESH
    each cycle from glorfindel-config.yaml — so a console dropdown change (which
    persists to disk) takes effect on the next signal without restarting watch.
    Tests inject an explicit AutonomyConfig to bypass the disk read.
    autonomy_override (session `glorfindel watch --mode`) is re-applied on top of
    the fresh config so it stays pinned for the session.
    readiness_gate (production: `readiness.ReadinessGate`): the configured mode is an
    intention — a VM configured autonomous runs in human_only until its readiness
    allows it (ready, or every reserve acknowledged). Covers the global default, the
    patterns and `--mode`, including VMs created after the setting.

    A control-plane detection (AL1: the Activity Log) never reaches the model: its
    decision is built by the code (`_control_plane_decision`), an escalation with no
    action — before the mode, the readiness, the call. Nor an identity detection (C2:
    Entra ID's logs, `_identity_decision`).

    Gates, in order (each a pure helper, testable on its own): parsing defaults →
    executable guard → confidence gate → deterministic signal guardrail → attribution
    guard → telemetry guard → release precondition → autonomy mode → agreement of the
    draws (D-1: a disruptive action about to run alone is drawn again, at the model's
    default sampling, and held unless every draw agrees). The first draw is asked at
    temperature 0, or at the model's default when it refuses one. A failed LLM call
    (after retries, each bounded by GLORFINDEL_LLM_TIMEOUT_S) escalates as
    `cycle_failed`. The gate that escalates is recorded (`held_by`) and gives the
    escalation its type. An unreadable glorfindel-config.yaml runs every VM in
    human_only, `--mode` included (G2).
    """
    if _is_identity(state["signal"]):
        return _identity_decision(state)
    if _is_control_plane(state["signal"]):
        return _control_plane_decision(state)

    import litellm

    signal = state["signal"]
    past = state["past_cycles"]
    user_content = _build_user_message(signal, past, state.get("incident"))

    # Resolve the mode for this asset first: the debug line of a failed decision
    # (cycle_failed) carries it too. Reload config fresh per cycle (hot-pickup)
    # unless one is injected (tests).
    config_error = ""
    if autonomy is None:
        try:
            autonomy = load_glorfindel_config().autonomy
        except Exception as exc:
            from glorfindel.config import AutonomyConfig
            autonomy = AutonomyConfig()
            config_error = _first_line(exc)
    # Session --mode pins the GLOBAL default; per-asset rules still win in resolve().
    # Not over an unreadable config (G2): its per-asset rules — a VM pinned human_only —
    # are lost with it, and --mode made every VM autonomous.
    if autonomy_override and not config_error:
        autonomy.default = autonomy_override
    resource_id = signal.get("resource_id", "")
    asset_name = resource_id.split("/")[-1] if resource_id else ""
    mode = autonomy.resolve(asset_name)
    gate: dict = {}
    if config_error:
        gate = {"configured": autonomy_override or "", "reason": "config_unreadable",
                "message": f"glorfindel-config.yaml illisible ({config_error[:200]})"}
    if readiness_gate is not None and mode != "human_only":
        try:
            mode, gate = readiness_gate(asset_name, resource_id, mode)
        except Exception as exc:              # the gate fails closed
            gate = {"configured": mode, "reason": "not_checked",
                    "message": f"préparation illisible ({_first_line(exc)})"}
            mode = "human_only"

    kwargs: dict = {}
    base_url = os.environ.get("GLORFINDEL_LLM_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url

    from eregion_core.llm_call import completion_with_tool, temperature_refused
    from glorfindel.config import llm_timeout_s
    call = dict(
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
        num_retries=_LLM_RETRIES,
        # Bounded (G2): a provider that hangs ends as a cycle_failed card, not hours
        # of a held decision queue (LiteLLM's own default is 6000 s an attempt).
        timeout=llm_timeout_s(),
        **kwargs,
    )
    try:
        response = completion_with_tool(
            litellm, "security_decision", temperature=_DECISION_TEMPERATURE, **call)
    except Exception as exc:
        # Rate limit, timeout, auth, network: previously this escaped the graph and
        # ended as one console line in the watch worker — a detected threat dropped
        # with no escalation and no debug file.
        return {**_decision_failed(state, exc, mode), "autonomy_gate": gate}
    temperature = None if temperature_refused(model) else _DECISION_TEMPERATURE

    d, raw_conf = _parse_decision(response)
    threshold = _confidence_threshold()
    _apply_executable_guard(d)
    _apply_confidence_gate(d, raw_conf, threshold)
    _apply_signal_guardrail(d, signal)
    _apply_attribution_guard(d, signal)
    _apply_telemetry_guard(d, state.get("telemetry_gaps") or [])
    _apply_release_precondition(d, signal)
    _apply_never_block_guard(d, signal)

    mode_hold = _apply_autonomy_mode(d, mode, gate)

    # Agreement last (D-1): only a disruptive action about to run alone pays for the other
    # draws — never a human_only VM (H0), never an action a gate already held.
    draws: list[dict] = []
    responses = [response]
    if not d["escalate"] and d["action"] in _DISRUPTIVE_AUTONOMOUS:
        required = _decision_draws()
        draws = [_draw_summary(d)]
        if required:
            more, more_responses = _confirming_draws(litellm, call, required - 1, threshold)
            draws += more
            responses += more_responses
        _apply_agreement_guard(d, draws, required)

    # Last, on the decision as it stands: a characterized detection a snapshot alone
    # answers gets its card (V-11) — store_cycle records it once the snapshot ran.
    uncontained = _uncontained_floor(d, signal)

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
        "llm_usage": _usage(responses),
        "autonomy_mode": mode,
        "mode_hold": mode_hold,
        "held_by": d.get("held_by", ""),
        "autonomy_gate": gate,
        "decision_temperature": temperature,
        "decision_draws": draws,
        "uncontained": uncontained,
    }


def _threat_port(signal: dict) -> int | None:
    """The port the attack targets, when the detection says so — read from the
    detection, never added to the signal (the LLM sees the signal as is).

    SSH (port 22): the RulePoller's rule name, the matched row, or the query of the
    rule covering this TTP (`sshd`, `Failed password`). None when unknown: every allow
    before a block's deny then counts as a bypass, as before."""
    ctx = signal.get("context") or {}
    raw = signal.get("raw_signal") or {}
    if "ssh" in str(ctx.get("rule_name", "")).lower():
        return 22
    rows = [raw.get("detected_data") or {}, raw.get("first_result_row") or {}]
    if any("ssh" in str(v).lower() for r in rows for v in r.values()):
        return 22
    try:
        rule = _find_rule_for_ttp(signal.get("ttp", ""), glorfindel_cfg=load_glorfindel_config())
    except Exception:
        rule = None
    query = (getattr(rule, "query", "") or "").lower()
    if "sshd" in query or "failed password" in query:
        return 22
    return None


def _extract_suspicious_ip(signal: dict) -> str:
    """Best-effort extraction of the suspicious IP for block_suspicious_ip.

    Checks an explicit context override, then both the detected row (detected_data)
    and the raw source row (first_result_row) for the common source/destination IP
    fields. Shared by execute_action (to act) and escalate_to_human (to carry the IP
    in the escalation payload so the console can approve & execute in one click).
    """
    raw = signal.get("raw_signal", {})
    explicit = signal.get("context", {}).get("suspicious_ip")
    if explicit:
        return explicit
    for row in (raw.get("detected_data") or {}, raw.get("first_result_row") or {}):
        for key in ("SourceIP", "DestIP_s", "DestinationIp", "DestinationIPAddress"):
            value = row.get(key)
            if value:
                return value
    return ""


def _backup_vault_target() -> tuple[str, str]:
    """(vault, vault_rg) from glorfindel-config.yaml — the source the CLI and the War
    Room already use. The connector's own default ("rsv-annatar") names the retired
    sandbox vault: an agent-side snapshot must never fall back on it silently."""
    try:
        rsv = load_glorfindel_config().backup_vault()
    except Exception:
        rsv = None
    vault = (rsv.vault_name if rsv and rsv.vault_name else "") \
        or os.environ.get("GLORFINDEL_BACKUP_VAULT", "")
    vault_rg = rsv.resource_group if rsv and rsv.resource_group else ""
    return vault, vault_rg


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
    try:
        if action == "isolate_vm":
            outcome = connector.isolate_vm(resource_id)
        elif action == "release_isolation":
            outcome = connector.release_isolation(resource_id)
        elif action == "block_suspicious_ip":
            ip = _extract_suspicious_ip(state["signal"])
            port = _threat_port(state["signal"])
            outcome = (connector.block_suspicious_ip(ip, resource_id, threat_port=port)
                       if port else connector.block_suspicious_ip(ip, resource_id))
        elif action == "snapshot":
            # Always fire-and-forget. The watch worker is serialized per VM, so a blocking
            # snapshot holds every later signal for that VM until the backup ends: 4h25 in
            # a real run (runs/watch-t1136-...-20260608T143425Z, an initial full backup) —
            # a ransomware detection behind it would have waited while the disk encrypted.
            # Completion is tracked as a job (jobs.reconcile_jobs); verify_snapshot reports
            # an InProgress job as "no claim" (verified=None), never as success.
            vault, vault_rg = _backup_vault_target()
            if not vault and not state.get("dry_run"):
                raise RuntimeError(
                    "aucun coffre de sauvegarde configuré (action_backends dans "
                    "glorfindel-config.yaml, ou GLORFINDEL_BACKUP_VAULT)"
                )
            snap_id = connector.snapshot(resource_id, vault=vault, wait=False, vault_rg=vault_rg)
            outcome = {"snapshot_id": snap_id, "vault": vault}
            if not state.get("dry_run") and getattr(connector, "dry_run", True) is False:
                from glorfindel.jobs import record_snapshot_job
                record_snapshot_job(resource_id, snap_id, vault, vault_rg, overwrite_running=False)
        else:
            # Unreachable through the graph (executable guard in decide); kept as a
            # guard so an action with no implementation can never pass as executed.
            raise NotImplementedError(f"action '{action}' non implémentée")
    except Exception as e:
        # The action could not run (or only partly). Never let it abort the cycle
        # silently — route to escalation so the operator sees it in `pending` / the War
        # Room, and store_cycle writes the debug file. This used to catch only
        # PermissionError + Azure HttpResponseError: the connector's own RuntimeErrors
        # ("Snapshot trigger failed", "no NSG", job not found…) and `requests` errors
        # escaped to the watch worker and ended as one console line.
        #   PermissionError / 403 / AuthorizationFailed → write_blocked (capability gap)
        #   anything else                               → action_failed
        status_code = getattr(e, "status_code", None)
        is_auth = (
            isinstance(e, PermissionError)
            or status_code == 403
            or "AuthorizationFailed" in str(e)
        )
        out_status = "write_blocked" if is_auth else "action_failed"
        # Azure HttpResponseError.__str__ repeats the message (summary line + a
        # "Message:" section) — take only the first line for the escalation reason so
        # the console's modal doesn't show the same text twice. Full text → outcome.error.
        err_summary = _first_line(e)
        outcome = {
            "status": out_status,
            "executed": False,
            "action_pending": action,
            "error": str(e),
            "action_s": round(time.time() - t_start),
        }
        if isinstance(e, PartialActionError):
            # Some NICs are covered and recorded in state; the escalation says so.
            outcome.update(partial=True, covered=e.covered, failed_nic=e.failed_nic)
        return {
            **state,
            "escalate": True,
            "escalation_reason": f"Action '{action}' {'bloquée' if is_auth else 'échouée'} — {err_summary}",
            "mode_hold": False,
            "outcome": outcome,
        }
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
    # An action attempted but not completed carries its own escalation type:
    #   write_blocked  → credentials can't write (read-only SP / IAM 403) — capability gap
    #   action_failed  → other Azure failure during execution (transient / config)
    _out_status = (state.get("outcome") or {}).get("status")
    # An identity detection (C2) is always its own type, whatever reached here: never a
    # type the console approves in one click.
    if _is_identity(state["signal"]):
        escalation_type = "identity_change"
    elif _out_status in ("write_blocked", "action_failed"):
        escalation_type = _out_status
    # Executed but the check failed (rule missing, an allow evaluated before the deny,
    # a NIC left open) or couldn't conclude (Q11): the type the Revert / reset buttons
    # answer to.
    elif (state.get("outcome") or {}).get("verified") is False or (state.get("outcome") or {}).get("unverified"):
        escalation_type = "verification_failed"
    # The cycle itself could not complete (LLM decision unavailable, internal error):
    # the signal is real but unanalyzed — its own type so it is never mistaken for a
    # judgment ("unknown action", "low confidence").
    elif state.get("cycle_error"):
        escalation_type = "cycle_failed"
    # mode_hold takes precedence: the action would have run autonomously but was
    # held back by the asset's human_only mode — NOT by low confidence. The
    # operator must understand it's a policy hold, with a one-click approve path.
    elif state.get("mode_hold"):
        escalation_type = "mode_hold"
    # A deterministic gate held the action: its own type, not the generic fallback.
    elif state.get("held_by") in _HELD_BY_TYPE:
        escalation_type = _HELD_BY_TYPE[state["held_by"]]
    elif action in HUMAN_APPROVAL_REQUIRED:
        escalation_type = "destructive_action"
    elif action == "improve_detection":
        escalation_type = "proposed_rule"
    # A miss on a TTP an existing rule covers: not a rule gap, a prevented
    # detection (isolation / ingestion latency / backend down) — distinct type so
    # the operator investigates posture instead of reviewing a duplicate rule.
    elif action == "investigate_detection_gap":
        escalation_type = "detection_blocked"
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

    # Carry action parameters so the console can approve & execute parameterised
    # actions in one click (not just resource_id-only actions like isolate_vm).
    # block_suspicious_ip needs the IP — extracted from the signal, same source as
    # execute_action uses, so the approved action matches what would have run.
    action_params: dict | None = None
    if action == "block_suspicious_ip":
        ip = _extract_suspicious_ip(signal)
        if ip:
            action_params = {"ip": ip}
            port = _threat_port(signal)
            if port:
                action_params["port"] = port

    if not state.get("dry_run", False):
        from glorfindel import escalations
        source, exercise_run = _cycle_source(signal)
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
            confidence=state.get("confidence", 0.0),
            action_params=action_params,
            rule_name=(signal.get("context") or {}).get("rule_name", ""),
            source=source,
            exercise_run=exercise_run,
            explanation=state.get("explanation", ""),
        )

    # An action that ran (verification failed, or it failed midway) keeps what its
    # outcome says — verified, shadowed_by, uncovered NICs, drain — in the debug file
    # and ChromaDB; it used to be replaced wholesale (third review, T14).
    prior = state.get("outcome") or {}
    kept = prior if escalation_type in ("verification_failed", "write_blocked", "action_failed") else {}
    return {
        **state,
        "outcome": {
            **kept,
            "status": "escalated",
            "escalation_type": escalation_type,
            "reason": state["escalation_reason"],
            "action_pending": action,
            "executed": bool(kept.get("executed", False)),
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

    # A check that raises (an Azure read failing mid-verification) used to leave the
    # graph: the watch's safety net made it a cycle_failed with an empty action and
    # executed False — an isolation that did happen, mislabelled, with no Revert
    # (sixth review, S9). It is an action that could not be verified, like an
    # unreadable list: the action and its outcome are kept.
    try:
        if action == "isolate_vm":
            # The drain's result counts: rules in place but sessions still open is not a
            # contained VM (measured 2026-10-05).
            from glorfindel.actions import isolation_verdict
            verification = isolation_verdict(connector.verify_isolation(resource_id), outcome)
        elif action == "release_isolation":
            # verified=True only when NO NIC carries an isolation rule any more. The former
            # `not verify_isolation()` meant "at least one NIC uncovered": a release that
            # failed on one NIC (or one direction) passed as verified.
            verification = connector.verify_release(resource_id)
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
    except Exception as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        verification = {"verified": None, "method": "raised",
                        "error": f"vérification en erreur : {first[:200]}"}

    verified = verification.get("verified")
    # An action that changes the network and can't be checked (a list unreadable, a
    # subnet NSG that couldn't be read) is not a success either: the cycle was stored
    # silently, the VM perhaps open (fourth review, Q11). A snapshot in progress stays
    # "no claim" — its job is followed elsewhere.
    unverified = verified is None and action in _CHECKED_ACTIONS
    escalate = verified is False or unverified
    if verified is False:
        escalation_reason = (f"Action '{action}' executed but verification failed: "
                             f"{verification.get('error', 'check failed')}")
    elif unverified:
        escalation_reason = (f"Action '{action}' executed but could not be verified: "
                             f"{verification.get('error', 'Azure unreadable')} — check it by hand")
    else:
        escalation_reason = state.get("escalation_reason", "")
    # BL1: when Azure was read back — the end of the time to contain (analysis/containment.py),
    # the debug line itself being written later (memory, notification).
    from datetime import datetime, timezone
    verified_at = datetime.now(timezone.utc).isoformat()
    return {
        **state,
        "outcome": {**outcome, **verification, **({"unverified": True} if unverified else {}),
                    "verified_at": verified_at},
        "escalate": escalate,
        "escalation_reason": escalation_reason,
    }


# Actions whose effect on the network is read back from Azure: unverifiable = escalated.
_CHECKED_ACTIONS = ("isolate_vm", "release_isolation", "block_suspicious_ip")


def _platform_note(outcome: dict) -> str:
    """What an isolation by rules left open, for its notification (sixth review, S7)."""
    nics = outcome.get("platform_open") or []
    if not nics:
        return ""
    from glorfindel.actions import PLATFORM_OPEN_NOTE
    return f"{PLATFORM_OPEN_NOTE} — {', '.join(map(str, nics))}"


def _cycle_source(signal: dict) -> tuple[str, str]:
    """B2: (`exercise`, run_id) when an injector's window covers the signal's VM at its
    time, else (`real`, "") — eregion_core/exercise.py. Recorded in the memory and on the
    card; never shown to the model yet. Unreadable → (`unknown`, "").

    An identity detection (C2), and a control-plane one the RulePoller says
    `unattributed` (AL1), are `real` (a `respond` signal on the Activity Log has no
    attribution, and keeps its declared window):
    their VM is an anchor, and an exercise window on it says nothing of an identity or of
    an operation elsewhere — until an identity can be enrolled, nothing ties one to an
    exercise (an attack on it would otherwise be labelled one)."""
    if _is_identity(signal) or (
            # `unattributed` is the RulePoller's own word; a respond signal (an
            # attack_started resolved on the Activity Log) has none, and keeps its window.
            _is_control_plane(signal) and (signal.get("context") or {}).get("attribution") == "unattributed"):
        return "real", ""
    try:
        from eregion_core.exercise import source_of
        return source_of(signal.get("resource_id", ""), signal.get("timestamp"),
                         run_id=(signal.get("context") or {}).get("run_id", ""))
    except Exception:  # labelling must never break a cycle
        return "unknown", ""


def store_cycle(state: GlorfindelState, *, memory: CycleMemory) -> GlorfindelState:
    """Persist the completed cycle to vector store and debug JSONL."""
    signal = state["signal"]
    outcome = state.get("outcome") or {}
    run_id = signal.get("context", {}).get("run_id", "")
    source, exercise_run = _cycle_source(signal)

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
        "resolved_autonomy_mode": state.get("autonomy_mode", ""),
        "autonomy_gate": state.get("autonomy_gate") or {},
        "source": source,
        "exercise_run": exercise_run,
    }
    # ChromaDB write — non-fatal: debug JSONL must still be written on failure. Never a
    # control-plane cycle (AL1): decided by the code, not the model, on a VM that may be an
    # anchor — retrieved by similarity (TTP, severity…), it would be served as a precedent
    # to a data-plane decision. Its debug line is written. Nor an identity cycle (C2): its
    # text names a user (a UPN), and the memory feeds the model.
    try:
        if not (_is_control_plane(signal) or _is_identity(signal)):
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
            and outcome.get("status") not in ("dry_run", "no_op")
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
                # An isolation by rules leaves Azure's DNS / IMDS reachable: said where the
                # autonomous action is announced, not only buried in the outcome (S7).
                note=(_platform_note(outcome) if state["action"] == "isolate_vm" else ""),
            )
    except Exception as exc:
        _console.print(f"[yellow]store_cycle: notify_action failed: {exc}[/yellow]")

    _record_uncontained(state, source, exercise_run)

    # Debug JSONL — always written, even if ChromaDB or webhook failed
    _write_debug_record(state)
    return state


def _record_uncontained(state: GlorfindelState, source: str, exercise_run: str) -> None:
    """The card of a characterized detection a snapshot alone answered (V-11), once the
    snapshot ran: no action on it (it has run; nothing is approvable in one click), its
    id in the reason. A decision escalated on the way (the snapshot failed, its check
    failed) has its own card already."""
    outcome = state.get("outcome") or {}
    if (not state.get("uncontained") or state.get("dry_run") or state.get("escalate")
            or not outcome.get("executed")):
        return
    signal = state["signal"]
    snap = outcome.get("snapshot_id") or ""
    try:
        from glorfindel import escalations
        escalations.record(
            signal_id=signal.get("signal_id", ""),
            resource_id=signal.get("resource_id", ""),
            action="",
            escalation_type="uncontained_detection",
            reason=state["uncontained"] + (f" Instantané pris : {snap}." if snap else ""),
            run_id=(signal.get("context") or {}).get("run_id", ""),
            suggested_steps=list(state.get("suggested_steps") or []),
            ttp=signal.get("ttp", ""),
            severity=signal.get("severity", ""),
            confidence=state.get("confidence", 0.0),
            rule_name=(signal.get("context") or {}).get("rule_name", ""),
            source=source,
            exercise_run=exercise_run,
            explanation=state.get("explanation", ""),
        )
    except Exception as exc:          # said, and the debug line still written
        _console.print(f"[red]store_cycle: carte de la détection non contenue non écrite — {exc}[/red]")


def _write_debug_record(state: GlorfindelState) -> None:
    """Append the cycle to runs/<run_id>_debug.jsonl (no-op without a run_id)."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    signal = state["signal"]
    run_id = signal.get("context", {}).get("run_id", "")
    if not run_id:
        return
    debug_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signal": signal,
        "past_cycles": state.get("past_cycles", []),
        "reasoning": state.get("reasoning", ""),
        "confidence": state.get("confidence", 0.0),
        "action": state.get("action", ""),
        "escalate": state.get("escalate", False),
        "escalation_reason": state.get("escalation_reason", ""),
        "outcome": state.get("outcome") or {},
        "llm_usage": state.get("llm_usage"),
        "resolved_autonomy_mode": state.get("autonomy_mode", ""),
    }
    if state.get("autonomy_gate"):
        debug_record["autonomy_gate"] = state["autonomy_gate"]
    if state.get("cycle_error"):
        debug_record["cycle_error"] = state["cycle_error"]
    if state.get("telemetry_gaps"):
        debug_record["telemetry_gaps"] = state["telemetry_gaps"]
    # D-1: whether the first draw was fixed (0) or the model's default sampling (None), and
    # the draws asked before a disruptive autonomous action.
    if "decision_temperature" in state:
        debug_record["decision_temperature"] = state["decision_temperature"]
    if state.get("decision_draws"):
        debug_record["decision_draws"] = state["decision_draws"]
    if state.get("uncontained"):
        debug_record["uncontained"] = state["uncontained"]
    out = Path("runs") / f"{run_id}_debug.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "a") as f:
        f.write(json.dumps(debug_record, default=str) + "\n")


def _detection_blocked(
    state: GlorfindelState, rule, actions_summary: str
) -> GlorfindelState:
    """State for a miss on a TTP an existing rule already covers.

    No LLM call, no proposal recorded: the deterministic finding is "a rule for
    this TTP exists, so authoring another one is noise". What the operator needs
    is the reason detection was PREVENTED — an isolation cutting the agent off,
    ingestion latency above the rule's expected_latency_s, or an unreachable
    backend. escalate_to_human turns this into a `detection_blocked` escalation.
    """
    signal = state["signal"]
    ttp = signal.get("ttp", "")
    reasons = [
        f"Le TTP {ttp} est déjà couvert par la règle '{rule.name}' "
        f"(expected_latency_s={rule.expected_latency_s or 'non défini'}) — "
        f"aucune règle manquante, la détection a été EMPÊCHÉE."
    ]
    if actions_summary:
        reasons.append(
            f"Actions déjà prises sur cette ressource : {actions_summary}. "
            f"Une isolation NSG coupe l'agent (AMA/Syslog) et le trafic sortant "
            f"— cause la plus probable du raté."
        )
    if not rule.enabled or not rule.workspace_id:
        reasons.append(
            "⚠ La règle est chargée mais NON pollable (aucun backend de monitoring "
            "résolu) — elle ne peut pas fire tant que glorfindel-config.yaml n'est "
            "pas corrigé."
        )

    resource_id = signal.get("resource_id", "")
    return {
        **state,
        "reasoning": " ".join(reasons),
        # Déterministe (présence d'une règle), pas une confiance de modèle.
        "confidence": 1.0,
        "action": "investigate_detection_gap",
        "reversible": True,
        "explanation": (
            f"Règle '{rule.name}' existante pour {ttp} : pas de proposition de règle. "
            f"Vérifier posture, latence d'ingestion et état du backend."
        ),
        "escalate": True,
        "escalation_reason": " ".join(reasons),
        "suggested_steps": [
            f"glorfindel list  — vérifier qu'aucune isolation/block résiduel ne "
            f"coupe {resource_id}",
            f"glorfindel reset {resource_id} --yes  — si l'isolation est résiduelle",
            f"Rejouer la query de '{rule.name}' dans Log Analytics sur la fenêtre "
            f"de l'attaque (latence d'ingestion > expected_latency_s ?)",
            "Vérifier l'état du backend (nœud DETECT de la console, page Glorfindel / rule_status.json)",
        ],
        "proposed_rule": None,
        "proposal_id": "",
        "outcome": None,
    }


def propose_detection_rule(
    state: GlorfindelState, *, model: str, incidents: IncidentRegistry | None = None
) -> GlorfindelState:
    """Call LLM to propose an improved detection rule after a detection_missed signal.

    Uses a focused prompt distinct from the main security_decision flow.
    The proposal is stored in state['proposed_rule'] and persisted by store_cycle.
    Delegates the grounded LLM call to detection_authoring.author_rule.
    """
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
        # Nothing for a human to do: route straight to store_cycle (debug trail kept).
        # Returning the bare state used to flow into escalate_to_human and record an
        # empty `proposed_action` escalation — the noise this path exists to avoid.
        return {
            **state,
            "escalate": False,
            "escalation_reason": "",
            "outcome": {"status": "skipped", "reason": "rulepoller_recently_matched",
                        "executed": False},
        }

    failed_query = ctx.get("failed_query") or raw.get("failed_query", "(unknown)")
    workspace_id = ctx.get("workspace_id", "")
    source = raw.get("detection_source", "azure_monitor")

    # Check if an action was already taken on this VM — timeout may be caused by
    # the action (e.g. isolate_vm cuts off AMA) rather than a bad detection rule.
    actions_summary = ""
    if incidents is not None:
        inc = incidents.get_active(signal.get("resource_id", ""))
        if inc and inc.actions_taken:
            actions_summary = ", ".join(
                f"{a['action']} (at {a.get('timestamp', '?')})" for a in inc.actions_taken
            )

    # Gate: a rule already covers this TTP → the miss is NOT a rule gap.
    # Authoring here duplicates a curated rule (first e2e campaign run: T1110 and
    # T1041 both re-authored while ssh-brute-force / data-exfiltration-blob existed,
    # the misses being caused by a leftover isolation cutting AMA + egress).
    # A miss on a covered TTP means detection was PREVENTED — posture, ingestion
    # latency or an unreachable backend — so escalate that instead of a duplicate.
    # Fail OPEN (author as before) if the config/rules can't be read: a broken
    # config must not silence the purple loop, only the gate.
    try:
        existing_rule = _find_rule_for_ttp(ttp, glorfindel_cfg=load_glorfindel_config())
    except Exception as e:
        _console.print(f"  [dim]rule-coverage gate unavailable: {e}[/dim]")
        existing_rule = None
    if existing_rule is not None:
        return _detection_blocked(state, existing_rule, actions_summary)

    incident_context = ""
    if actions_summary:
        incident_context = f"""\
== IMPORTANT: actions already taken on this resource ==
{actions_summary}

If one of these actions (e.g. isolate_vm) could have cut off the monitoring agent (AMA/syslog),
the detection timeout may be caused by that action — not by a bad detection rule.
In that case, note this in your analysis and set confidence accordingly.
The existing rule may be correct and no change needed."""

    # Grounded authoring: introspect the real table schema (getschema) when we have a
    # live workspace. dry_run / no workspace → detector=None → engine authors without
    # the schema block (prior behaviour), no Azure call.
    detector = None
    if not state.get("dry_run") and workspace_id and source in ("azure_monitor", "sentinel"):
        try:
            from glorfindel.detectors import detector_for
            detector = detector_for(source, workspace_id=workspace_id)
        except Exception as e:  # never let detector wiring break authoring
            _console.print(f"  [dim]schema introspection unavailable: {e}[/dim]")

    past_summaries = [c.get("summary", "") for c in state.get("past_cycles", []) if c.get("summary")]
    proposed_rule = author_rule(
        ttp=ttp,
        resource_id=signal.get("resource_id", ""),
        source=source,
        workspace_id=workspace_id,
        model=model,
        detector=detector,
        attack_summary=hints.get("attack_commands_summary", ""),
        expected_indicators=hints.get("expected_indicators") or [],
        failed_query=failed_query,
        detection_timeout_s=ctx.get("detection_timeout_s"),
        past_summaries=past_summaries,
        incident_context=incident_context,
    )
    d = proposed_rule  # field access below mirrors the proposal dict

    # Save the proposed rule immediately so proposal_id is available for the
    # escalation card (escalate_to_human runs before store_cycle).
    pid = ""
    if not state.get("dry_run"):
        from glorfindel import proposed_rules as _pr
        run_id = signal.get("context", {}).get("run_id", "")
        # grounded_schema is audit metadata (kept in state/debug.jsonl), not a
        # record() field — strip it from the persisted-proposal kwargs.
        record_kwargs = {k: v for k, v in proposed_rule.items() if k != "grounded_schema"}
        pid = _pr.record(
            run_id=run_id,
            signal_id=signal.get("signal_id", ""),
            ttp=signal.get("ttp", ""),
            resource_id=signal.get("resource_id", ""),
            **record_kwargs,
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
            f"glorfindel approve-rule {pid or '<id>'}  (or Approve on its card in the console, Glorfindel page)",
            "Re-run the scenario to validate detection",
        ],
        "proposed_rule": proposed_rule,
        "proposal_id": pid,
        "outcome": None,
    }


def _route_after_propose(state: GlorfindelState) -> str:
    # A proposal / detection_blocked escalates; a skipped false negative only stores.
    return "escalate_to_human" if state.get("escalate") else "store_cycle"


def _route_after_verify(state: GlorfindelState) -> str:
    outcome = state.get("outcome") or {}
    # False, or None on an action whose effect must be read back (Q11): escalate.
    # None elsewhere (a snapshot in progress, not implemented) proceeds to store.
    if outcome.get("verified") is False or outcome.get("unverified"):
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
    # Never an action on an identity detection (C2), whatever the decision says: the
    # second lock, after `decide`'s.
    if _is_identity(state["signal"]):
        return "escalate_to_human"
    if action in HUMAN_APPROVAL_REQUIRED:
        return "escalate_to_human"
    if action not in AUTONOMOUS_ACTIONS:
        return "escalate_to_human"  # proposed unknown action — always escalate
    return "execute_action"


def _route_after_execute(state: GlorfindelState) -> str:
    # An action that could not run (read-only guard, IAM 403, other Azure failure)
    # must be escalated (visible), not verified.
    if (state.get("outcome") or {}).get("status") in ("write_blocked", "action_failed"):
        return "escalate_to_human"
    return "verify_action"


# ── Graph builder ─────────────────────────────────────────────────────────────

def _build_graph(
    memory: CycleMemory,
    connector: CloudConnector,
    model: str,
    incidents: IncidentRegistry | None = None,
    autonomy=None,
    autonomy_override: str | None = None,
    readiness_gate=None,
):
    if incidents is None:
        incidents = IncidentRegistry(path=".glorfindel/incidents.jsonl")

    graph = StateGraph(GlorfindelState)

    graph.add_node("load_context", lambda s: load_context(s, memory=memory, incidents=incidents))
    graph.add_node("poll_detection", lambda s: poll_detection(
        s, ip_owners=getattr(connector, "private_ip_owners", None)))
    graph.add_node("investigate", investigate)
    graph.add_node("decide", lambda s: decide(
        s, model=model, autonomy=autonomy, autonomy_override=autonomy_override,
        readiness_gate=readiness_gate))
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
    graph.add_conditional_edges("execute_action", _route_after_execute)
    graph.add_conditional_edges("verify_action", _route_after_verify)
    graph.add_conditional_edges("propose_detection_rule", _route_after_propose)
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
        autonomy=None,
        autonomy_default: str | None = None,
        readiness_gate=True,
    ):
        from glorfindel.actions import AzureConnector

        self.dry_run = dry_run
        self.memory = CycleMemory(path=memory_path)
        self.connector = connector or AzureConnector(dry_run=dry_run)
        self.incidents = IncidentRegistry(path=incidents_path)
        self.model = model or glorfindel_model()

        # Autonomy policy. autonomy_default is the session override (watch --mode).
        # When an explicit AutonomyConfig is injected (tests), the graph uses it as-is.
        # Otherwise the graph reloads config FRESH each cycle (hot-pickup of console
        # dropdown changes) — self.autonomy here is only for the startup banner / display.
        self._autonomy_explicit = autonomy if autonomy is not None else None
        self._autonomy_override = autonomy_default
        # Set when glorfindel-config.yaml can't be read at startup: decide() then runs
        # every VM in human_only, --mode included — the banner says so (G2 review).
        self.config_error = ""
        if autonomy is None:
            try:
                from glorfindel.config import load_glorfindel_config
                autonomy = load_glorfindel_config().autonomy
            except Exception as exc:
                from glorfindel.config import AutonomyConfig
                autonomy = AutonomyConfig()
                self.config_error = _first_line(exc)
        if autonomy_default and not self.config_error:
            autonomy.default = autonomy_default
        self.autonomy = autonomy

        # Readiness gate (L6): on by default whenever actions are real. In dry-run
        # nothing executes, so there is nothing to hold back.
        if readiness_gate is True:
            from glorfindel.readiness import ReadinessGate
            readiness_gate = None if dry_run else ReadinessGate(self.connector)
        self._graph = _build_graph(
            self.memory, self.connector, self.model, self.incidents,
            autonomy=self._autonomy_explicit,          # None in prod → decide reloads fresh
            autonomy_override=self._autonomy_override,  # --mode stays pinned across reloads
            readiness_gate=readiness_gate or None,
        )

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
            "autonomy_mode": "",
            "mode_hold": False,
            "cycle_error": "",
            "telemetry_gaps": [],
        }
        try:
            return self._graph.invoke(initial)
        except Exception as exc:
            return record_cycle_failure(signal, exc, stage="graph", dry_run=self.dry_run)


def record_cycle_failure(
    signal: dict, exc: BaseException, *, stage: str, dry_run: bool = False
) -> GlorfindelState:
    """Last-resort boundary: a cycle that raised still leaves a visible trace.

    Before this, an exception anywhere in a cycle (an unreadable file, a connector
    error in verify, a detection backend down while polling an attack) reached the
    watch worker's catch-all and ended as a single console line: a detected threat
    dropped with no escalation, invisible in `pending` and the console. Records a
    `cycle_failed` escalation (unless dry-run) and the debug line, then returns a
    terminal state. Also used by the watch poll threads (stage="detection").
    """
    err = _first_line(exc)
    reason = (
        f"Cycle interrompu ({stage}) : {err} — le signal n'a pas été traité jusqu'au "
        "bout, triage humain requis."
    )
    state: GlorfindelState = {
        "signal": signal,
        "past_cycles": [],
        "incident": None,
        "dry_run": dry_run,
        "reasoning": "",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": "",
        "escalate": True,
        "escalation_reason": reason,
        "suggested_steps": list(_CYCLE_FAILED_STEPS),
        "outcome": {
            "status": "escalated",
            "escalation_type": "cycle_failed",
            "reason": reason,
            "executed": False,
            "error": str(exc)[:2000],
        },
        "autonomy_mode": "",
        "mode_hold": False,
        "cycle_error": f"{stage}: {err}",
    }
    if not dry_run:
        try:
            from glorfindel import escalations
            source, exercise_run = _cycle_source(signal)
            escalations.record(
                signal_id=signal.get("signal_id", ""),
                resource_id=signal.get("resource_id", ""),
                action="",
                escalation_type="cycle_failed",
                reason=reason,
                run_id=signal.get("context", {}).get("run_id", ""),
                suggested_steps=list(_CYCLE_FAILED_STEPS),
                ttp=signal.get("ttp", ""),
                severity=signal.get("severity", ""),
                source=source,
                exercise_run=exercise_run,
            )
        except Exception as rec_exc:  # the trace must not raise in turn
            _console.print(f"[red]cycle_failed: escalation non enregistrée — {rec_exc}[/red]")
    try:
        _write_debug_record(state)
    except Exception as dbg_exc:
        _console.print(f"[red]cycle_failed: debug non écrit — {dbg_exc}[/red]")
    return state


_SOURCE_TAGS = {"exercise": "[EXERCICE]", "real": "[RÉEL]"}


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
        # Read through the state helpers, by resource id: files are keyed by name AND
        # resource id (two VMs may share a name) — reading `<name>.json` directly would
        # tell the model a VM isolated under the new key is NOT isolated.
        from glorfindel.actions import _load_block_entries, _load_isolation_state
        isolated = _load_isolation_state(resource_id) is not None
        blocked_ips: list[str] = []
        try:
            blocked_ips = [e["ip"] for e in _load_block_entries(resource_id)]
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
            # B2: each past cycle says whether it was an exercise; the current signal never
            # does (an attack during an exercise window must not be relaxed).
            tag = _SOURCE_TAGS.get(c.get("source") or "", "[source inconnue]")
            lines.append(f"**Cycle {i}** {tag} : {c.get('summary', str(c))}")
    else:
        lines.append("\n*Aucun cycle passé disponible — première décision.*")

    lines.append("\nAnalyse ce signal et prends une décision de réponse.")
    return "\n".join(lines)
