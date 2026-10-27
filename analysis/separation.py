"""IA1 — the analysis AI keeps its own memory and its own model, never Glorfindel's.

A report or a triage that reasons with the defender's model shares its blind spots, and one
that reads or writes the defender's memory (its decision cycles, `~/.glorfindel/cycles`)
could teach the defender what the analysis guessed. Both are refused here, at the call:

- ``check_model``: the analysis model (``EREGION_ANALYSIS_MODEL``, Haiku 5.5 by default) must
  not be Glorfindel's decision model (``GLORFINDEL_LLM_MODEL``, else the default). Compared
  without case and without the provider's prefix: ``anthropic/claude-sonnet-5-5`` and
  ``claude-sonnet-5-5`` are one model, so are ``azure/gpt-4o`` and ``openai/gpt-4o``.
- ``check_index``: the analysis index (``EREGION_ANALYSIS_INDEX``, else
  ``~/.eregion/analysis/chroma``) must lie outside Glorfindel's state (``~/.glorfindel``),
  read once the path is resolved (``..``, a symbolic link).
- ``check_collection``: its collection is never Glorfindel's (``cycles``).

A refusal raises ``SharedWithGlorfindel``: the report or the triage is not written (on H0, an
attempt that failed, analysis/hosted_report.py), and the message says which setting to change.
"""
from __future__ import annotations

import os
from pathlib import Path

# Glorfindel's memory: its ChromaDB collection (glorfindel/memory.py) and its state.
GLORFINDEL_COLLECTION = "cycles"


class SharedWithGlorfindel(RuntimeError):
    """The analysis would share Glorfindel's model or memory: refused."""


def glorfindel_state() -> Path:
    """Glorfindel's state, its memory among it (``~/.glorfindel``), read at the call."""
    return Path(os.path.expanduser("~")) / ".glorfindel"


def _model_name(model: str) -> str:
    return str(model or "").strip().lower().rsplit("/", 1)[-1]


def check_model(model: str) -> str:
    """``model``, when it is not Glorfindel's decision model — else raise."""
    from eregion_core.models import glorfindel_model
    defender = glorfindel_model()
    if _model_name(model) == _model_name(defender):
        # The instruction first: a caller that cuts the message (annatar/cli.py) keeps it.
        raise SharedWithGlorfindel(
            f"set EREGION_ANALYSIS_MODEL to another model than Glorfindel's: the analysis model "
            f"({model}) is its decision model ({defender}) — an analysis must not share the "
            "defender's blind spots")
    return model


def check_index(path: Path) -> Path:
    """``path``, when it lies outside Glorfindel's state — else raise."""
    p = Path(path).expanduser().resolve()
    state = glorfindel_state().resolve()
    if p == state or state in p.parents:
        raise SharedWithGlorfindel(
            f"set EREGION_ANALYSIS_INDEX outside Glorfindel's state: the analysis index ({path}) "
            f"lies in it ({state}) — the analysis never reads nor writes the defender's memory")
    return Path(path)


def check_collection(name: str) -> str:
    """``name``, when it is not Glorfindel's collection — else raise."""
    if str(name).strip().lower() == GLORFINDEL_COLLECTION:
        raise SharedWithGlorfindel(f"the analysis collection would be Glorfindel's ({name})")
    return name


def main() -> int:
    """``python -m analysis.separation``: does the analysis AI, where it runs, reason with
    another model than Glorfindel's? 0 when it does, else 1 and what to set. ``make
    glorfindel-host-model`` runs it in H0's watch: a model shared with the analysis there
    makes every campaign report refused (and given up after 3 attempts)."""
    from eregion_core.models import analysis_model
    try:
        check_model(analysis_model())
    except SharedWithGlorfindel as e:
        print(f"  ⚠ les rapports et les tris de campagne seront refusés : {e}")
        return 1
    print(f"  ✓ l'IA d'analyse raisonne avec un autre modèle ({analysis_model()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
