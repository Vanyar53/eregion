"""One way to ask a model for a tool call, across models that accept a forced choice or not.

Glorfindel forces its decision tool (`tool_choice` naming it). Some models refuse that:
claude-sonnet-5-5 answers « tool_choice: type "tool" and "any" are not supported for this
model » (measured 19/10) — every decision then failed before the model saw the signal. On
that refusal the call is retried once with `tool_choice="auto"`, and the model remembered.
A model that then answers without the tool gives no decision: the defensive parse
(`agent._parse_decision`) makes it an escalation, never an action. A model that accepts the
forced choice (claude-sonnet-4-6, the default until 19/10) is called exactly as before.

A `temperature` (D-1) is sent the same way: as asked, and dropped once for good on a model
that refuses it. claude-sonnet-5-5 answers « `temperature` is deprecated for this model. »
to 0 and accepts only its default (measured 26/10); claude-sonnet-4-6 accepts 0. On such a
model the draw cannot be fixed — `temperature_refused` says so, and the caller writes it.
"""
from __future__ import annotations

_AUTO_TOOL_CHOICE: set[str] = set()
_NO_TEMPERATURE: set[str] = set()


def _refuses_forced_choice(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "tool_choice" in msg and ("not supported" in msg or "unsupported" in msg)


def _refuses_temperature(exc: Exception) -> bool:
    """Anthropic: « `temperature` is deprecated for this model. »; OpenAI's reasoning models:
    « Unsupported value: 'temperature' does not support 0 … »; LiteLLM's own check:
    « … does not support parameters: ['temperature'] »."""
    msg = str(exc).lower()
    return "temperature" in msg and any(
        w in msg for w in ("deprecated", "not supported", "unsupported", "does not support"))


def temperature_refused(model: str) -> bool:
    """True once `model` has refused a temperature in this process: its draws are the
    provider's default sampling, not the temperature asked."""
    return str(model) in _NO_TEMPERATURE


def _complete(litellm, tool_name: str, **kwargs):
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


def completion_with_tool(litellm, tool_name: str, *, temperature: float | None = None, **kwargs):
    # litellm prints a « Give Feedback / Get Help » banner on every refused call: the expected
    # refusal of a forced choice read as an error in the logs (and in glorfindel-host-status).
    litellm.suppress_debug_info = True
    model = str(kwargs.get("model", ""))
    if temperature is not None and model not in _NO_TEMPERATURE:
        try:
            return _complete(litellm, tool_name, temperature=temperature, **kwargs)
        except Exception as exc:
            if not _refuses_temperature(exc):
                raise
            _NO_TEMPERATURE.add(model)
    return _complete(litellm, tool_name, **kwargs)
