"""One way to ask a model for a tool call, across models that accept a forced choice or not.

Glorfindel forces its decision tool (`tool_choice` naming it). Some models refuse that:
claude-sonnet-5-5 answers « tool_choice: type "tool" and "any" are not supported for this
model » (measured 19/10) — every decision then failed before the model saw the signal. On
that refusal the call is retried once with `tool_choice="auto"`, and the model remembered.
A model that then answers without the tool gives no decision: the defensive parse
(`agent._parse_decision`) makes it an escalation, never an action. A model that accepts the
forced choice (the default, claude-sonnet-4-6) is called exactly as before.
"""
from __future__ import annotations

_AUTO_TOOL_CHOICE: set[str] = set()


def _refuses_forced_choice(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "tool_choice" in msg and ("not supported" in msg or "unsupported" in msg)


def completion_with_tool(litellm, tool_name: str, **kwargs):
    # litellm prints a « Give Feedback / Get Help » banner on every refused call: the expected
    # refusal of a forced choice read as an error in the logs (and in glorfindel-host-status).
    litellm.suppress_debug_info = True
    model = str(kwargs.get("model", ""))
    if model not in _AUTO_TOOL_CHOICE:
        try:
            return litellm.completion(
                tool_choice={"type": "function", "function": {"name": tool_name}}, **kwargs)
        except Exception as exc:
            if not _refuses_forced_choice(exc):
                raise
            _AUTO_TOOL_CHOICE.add(model)
    return litellm.completion(tool_choice="auto", **kwargs)
