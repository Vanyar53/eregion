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
