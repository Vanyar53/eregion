"""The model Eregion reasons with, defined once.

DEFAULT_LLM_MODEL is the only model name written in the code — a test fails if another one
appears (`tests/unit/test_models.py`): Glorfindel's decisions and rule proposals, the War
Room, the CLI and Annatar's campaign planner all read it. A deployment overrides it with
GLORFINDEL_LLM_MODEL (Glorfindel) or ANNATAR_LLM_MODEL (the planner); an empty variable
(docker compose passes one) means the default.

Changing the default is this one line, after the harness (`make llm-compare`) and an
end-to-end run. 19/10: claude-sonnet-5-5 scored 36/36 with no overconfident error against
32/36 and 4 for claude-sonnet-4-6, and the end-to-end run on the bench decided right (T1486
→ isolate 0.80, T1110.001 → block 0.88): it is the default since (#139). It refuses a forced
tool choice — eregion_core/llm_call.py falls back to "auto".
"""
from __future__ import annotations

import os

DEFAULT_LLM_MODEL = "anthropic/claude-sonnet-5-5"
# Annatar's campaign planner keeps its own: claude-sonnet-5-5 declines the red-team planning
# prompt (finish_reason content_filter, measured 19/10) — the planner then fell back to its
# deterministic order without a word. The planner is optional (`--llm`). ANNATAR_LLM_MODEL
# overrides it.
DEFAULT_ANNATAR_MODEL = "anthropic/claude-sonnet-4-6"
# The analysis AI (IA0, the campaign report) reasons with another model than Glorfindel's:
# a report must not share the defender's blind spots. EREGION_ANALYSIS_MODEL overrides it.
DEFAULT_ANALYSIS_MODEL = "anthropic/claude-haiku-5-5"


def glorfindel_model() -> str:
    return os.environ.get("GLORFINDEL_LLM_MODEL") or DEFAULT_LLM_MODEL


def annatar_model() -> str:
    return os.environ.get("ANNATAR_LLM_MODEL") or DEFAULT_ANNATAR_MODEL


def analysis_model() -> str:
    return os.environ.get("EREGION_ANALYSIS_MODEL") or DEFAULT_ANALYSIS_MODEL


# ── The variables a model needs, by its provider (OL1, #525) ───────────────────────────────
# LiteLLM names a model <provider>/<model> and reads its provider's key from the environment.
# H0 required ANTHROPIC_API_KEY whatever the model — even a local one (ollama/…), whose logs
# never leave the machine. The rule, defined once: H0's host.env (infra/glorfindel-host/
# host_env.py) requires what it names; `make doctor` (GS1) is meant to read it too.
PROVIDER_ENV = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "azure": ("AZURE_API_KEY", "AZURE_API_BASE"),
    "mistral": ("MISTRAL_API_KEY",),
    "ollama": (),
    "ollama_chat": (),
}
# Served where the model runs: no key, an address. LiteLLM's default (localhost:11434) is, in
# a container, the container itself — the watch reads GLORFINDEL_LLM_BASE_URL (glorfindel/agent.py).
LOCAL_PROVIDERS = ("ollama", "ollama_chat")
BASE_URL = "GLORFINDEL_LLM_BASE_URL"


class UnknownProvider(ValueError):
    """The model names no provider of PROVIDER_ENV: which key it needs is unknown."""


def model_provider(model: str) -> str:
    """The provider LiteLLM reads in `model` — its prefix, before the first « / » — or raise
    UnknownProvider. An empty model is the default's (DEFAULT_LLM_MODEL). The message never
    repeats the value: a key pasted in the wrong variable is not printed."""
    name = (model or "").strip() or DEFAULT_LLM_MODEL
    provider, sep, rest = name.partition("/")
    if sep and rest and provider in PROVIDER_ENV:
        return provider
    raise UnknownProvider(
        "the model names no known provider — write it <provider>/<model>, the provider one of: "
        f"{', '.join(PROVIDER_ENV)}")


def required_env(model: str, base_url: str = "") -> tuple[str, ...]:
    """The variables `model` needs, by its provider: its key (Azure OpenAI: its address too); a
    local model (Ollama), GLORFINDEL_LLM_BASE_URL alone; an OpenAI-compatible model served at
    GLORFINDEL_LLM_BASE_URL (self-hosted, `openai/<model>`: the OpenAI client sends no key when
    there is none), nothing. Raises UnknownProvider."""
    provider = model_provider(model)
    if provider in LOCAL_PROVIDERS:
        return () if base_url else (BASE_URL,)
    if provider == "openai" and base_url:
        return ()
    return PROVIDER_ENV[provider]


def missing_env(model: str, environ) -> list[str]:
    """The names of the variables `model` needs that `environ` leaves empty — never a value."""
    return [k for k in required_env(model, environ.get(BASE_URL) or "") if not environ.get(k)]
