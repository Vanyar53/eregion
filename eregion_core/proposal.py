"""Annatar's proposals as drills (DG-e, #351; docs/design/console.md §7, decision 3 of 30/10):
a campaign of Annatar becomes a drill whose author is Annatar.

Two ways in, one format — the drill's (``eregion_core.drill``), read by its one exact reader:

- **Dagorlad, « Ask Annatar for a drill »**: the chain of the catalogue's implemented techniques,
  in kill-chain order, on the VM the operator chose (``chain``) — laid on the board as a draft,
  nothing written. The operator corrects it, keeps it (« Save as drill », author ``annatar``),
  then writes its request.
- **The command line, ``annatar campaign plan``** (on Orodruin, which never writes the console's
  drills): the campaign's chain, written as a drill beside its manifest (``campaign_drill``),
  which the operator brings to Dagorlad (« Import YAML », Jonathan's decision A of 04/11).

The proposal stays blind (decision 3): it reads the catalogue and the target, never Glorfindel's
rules nor its modes. It never chooses a target in the operator's place: the chain aims at the VM
given. A proposal from the console holds no destructive technique — the operator draws one by
hand, typing its name at the request, as for any wire —, and the model is never called here: the
LLM planner stays Annatar's (``annatar campaign plan --llm``), a gesture of the operator's.

D1: the shared core. The kill-chain order lives here, Annatar's planner reads it from here
(``annatar/campaign/catalog.py``); the console reads this module, never Annatar's package.
"""
from __future__ import annotations

from datetime import datetime

from eregion_core import drill as _drill

# ATT&CK's tactics in kill-chain order: access → execution → persistence → … → impact.
CANONICAL_TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

AUTHOR = "annatar"
VM_TYPE = "azure_vm"         # the catalogue's resource type of a VM: what a board's target is
DEFAULT_WIRES = 5            # as `annatar campaign plan --max-scenarios`


def tactic_rank(tactic: str) -> int:
    """Kill-chain ordering index; unknown tactics sort last (stable)."""
    try:
        return CANONICAL_TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(CANONICAL_TACTIC_ORDER)


def chain(catalog: dict, *, max_wires: int = DEFAULT_WIRES, available: set[str] | None = None,
          resource_type: str = VM_TYPE) -> list[str]:
    """Annatar's deterministic chain for a target of ``resource_type``: the catalogue's
    implemented techniques that say they destroy nothing (``destructive: false`` — an entry that
    does not say is never taken as harmless), those ``available`` here when given (the board's: an
    injector set up), in kill-chain order then by id, at most ``max_wires`` (1 to the drill's
    ceiling). ``catalog``: ``eregion_core.exercise_plan.load_catalog``'s."""
    n = max(1, min(int(max_wires), _drill.MAX_WIRES))
    picked = [e for e in catalog.values()
              if e.kind == "technique" and e.status == "implemented" and e.destructive is False
              and e.resource_type == resource_type and (available is None or e.id in available)]
    picked.sort(key=lambda e: (tactic_rank(e.tactic), e.id))
    return [e.id for e in picked[:n]]


def drill_name(campaign_id: str) -> str:
    """The drill of campaign ``20261104T101500Z``: ``annatar-20261104t101500z``."""
    return f"{AUTHOR}-{str(campaign_id).lower()}"


def _one_line(text: str) -> str:
    """A description the drill's reader takes: one printable line, at most its bound."""
    line = " ".join("".join(c if c.isprintable() else " " for c in str(text or "")).split())
    return line[:_drill.MAX_DESCRIPTION]


def campaign_drill(campaign_id: str, pairs: list[tuple[str, str]], *, objective: str = "",
                   now: datetime | None = None) -> _drill.Drill:
    """The drill of a campaign of Annatar: its (experiment, VM name) pairs in its order, author
    ``annatar``, named after the campaign — passed through the drill's one reader, as any other
    (``DrillRefused`` when it is not one: more wires than the ceiling, a pair twice…)."""
    return _drill.new(drill_name(campaign_id), list(pairs), author=AUTHOR,
                      description=_one_line(objective), now=now)
