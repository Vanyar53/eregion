"""The model Eregion reasons with, defined once.

DEFAULT_LLM_MODEL is the only model name written in the code — a test fails if another one
appears (`tests/unit/test_models.py`): Glorfindel's decisions and rule proposals, the War
Room, the CLI and Annatar's campaign planner all read it. A deployment overrides it with
GLORFINDEL_LLM_MODEL (Glorfindel) or ANNATAR_LLM_MODEL (the planner); an empty variable
(docker compose passes one) means the default.

Changing the default is this one line, after the harness (`make llm-compare`) and an
end-to-end run. 19/10: claude-sonnet-5-5 scored 36/36 with no overconfident error against
32/36 and 4 for claude-sonnet-4-6; the hosted observation VM already runs it.
"""
from __future__ import annotations

import os

DEFAULT_LLM_MODEL = "anthropic/claude-sonnet-4-6"


def glorfindel_model() -> str:
    return os.environ.get("GLORFINDEL_LLM_MODEL") or DEFAULT_LLM_MODEL


def annatar_model() -> str:
    return os.environ.get("ANNATAR_LLM_MODEL") or DEFAULT_LLM_MODEL
