"""A model that refuses a forced tool choice is asked again with "auto" (19/10).

claude-sonnet-5-5 rejected every decision call: « tool_choice: type "tool" and "any" are not
supported for this model ». A model that accepts the forced choice is called as before.
"""
import pytest

from glorfindel import llm_call


class _Litellm:
    def __init__(self, refuse_forced: bool, error: str = ""):
        self.refuse_forced, self.error, self.calls = refuse_forced, error, []

    def completion(self, **kw):
        self.calls.append(kw["tool_choice"])
        if self.error:
            raise RuntimeError(self.error)
        if self.refuse_forced and kw["tool_choice"] != "auto":
            raise RuntimeError('AnthropicException - tool_choice: type "tool" and "any" are not '
                               "supported for this model.")
        return "response"


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(llm_call, "_AUTO_TOOL_CHOICE", set())


def test_a_model_that_accepts_the_forced_choice_is_called_as_before():
    lm = _Litellm(refuse_forced=False)
    assert llm_call.completion_with_tool(lm, "security_decision", model="anthropic/claude-sonnet-4-6") == "response"
    assert lm.calls == [{"type": "function", "function": {"name": "security_decision"}}]


def test_a_refusal_is_retried_with_auto_and_remembered():
    lm = _Litellm(refuse_forced=True)
    assert llm_call.completion_with_tool(lm, "security_decision", model="anthropic/claude-sonnet-5-5") == "response"
    assert lm.calls[-1] == "auto" and len(lm.calls) == 2
    llm_call.completion_with_tool(lm, "security_decision", model="anthropic/claude-sonnet-5-5")
    assert lm.calls[-1] == "auto" and len(lm.calls) == 3          # straight to auto next time


def test_any_other_failure_is_not_retried():
    lm = _Litellm(refuse_forced=False, error="rate limit exceeded")
    with pytest.raises(RuntimeError, match="rate limit"):
        llm_call.completion_with_tool(lm, "security_decision", model="m")
    assert len(lm.calls) == 1
