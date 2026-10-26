"""D-2 (#184): what changed since the previous campaign, computed by the code.

The previous campaign is chosen by a rule, never by a similarity search: the latest ``done``
campaign that started before this one and shares at least one key with it — a technique
played on a target VM (analysis/campaign_report.py ``previous_campaign``, read from the index
of past campaigns' facts). The executed runs of both are then joined exactly by key: the n-th
run of a technique on a VM (in ``seq`` order) faces the n-th run of the same technique on the
same VM, the VM compared without case. Each pair is a typed fact, ``ChangeFact``: detection,
latency, action, confidence and escalation, before and after. A key on one side only is a
fact too, and said as such.

The section « Ce qui a changé depuis la campagne précédente » is rendered from these facts by
the code (``render_section``); the model writes none of it. It may only cite them, in claims
of kind ``change``, and every number such a claim writes must be one of the cited facts'
(``ChangeFact.numbers``, checked by analysis/campaign_report.py ``verify``).

Nothing here reads a file or the index: the facts come in, the facts go out.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# A number of seconds written in a claim matches a fact's within this (a model rounds
# 106,9 s to 107 s); a confidence, within half a point (0,78 → « 78 % »).
SECONDS_TOLERANCE = 1.0
FRACTION_TOLERANCE = 0.005
PERCENT_TOLERANCE = 0.5


# The actions a decision may name (glorfindel/actions.py AUTONOMOUS_ACTIONS and
# HUMAN_APPROVAL_REQUIRED, written again here: the report also runs where Glorfindel's
# package is not, the Annatar image — tests/unit/test_campaign_changes.py keeps both the
# same), and the detections a run may have. A claim citing a change fact names only those of
# its cited facts (analysis/campaign_report.py ``verify``).
ACTIONS = ("isolate_vm", "release_isolation", "snapshot", "block_suspicious_ip",
           "delete_resource", "modify_network_rule", "escalate_permissions", "wipe_storage",
           "restore_from_backup")
DETECTIONS = ("detected", "missed", "unknown")


def run_key(fact) -> tuple[str, str] | None:
    """The key a run is compared by: its technique and its target VM (lower case) — an
    executed run only (a skipped or failed scenario played nothing), with both known. A run
    without a run id has a key too: it was played (``ChangeFact.side`` reads the run, not its
    id)."""
    if getattr(fact, "status", "") != "executed":
        return None
    ttp, vm = getattr(fact, "ttp", "") or "", (getattr(fact, "target", "") or "").lower()
    return (ttp, vm) if ttp and vm else None


def keys(facts) -> set[tuple[str, str]]:
    """The keys of a campaign's runs (``run_key``)."""
    return {k for f in facts if (k := run_key(f))}


@dataclass
class ChangeFact:
    """One key (a technique on a VM, its n-th run) before — in the previous campaign — and
    after — in this one. A side without the key has no run (``played_before`` or
    ``played_after`` false): the key is on the other side only. A run played without a run id
    is still played: its side is told by the run, never by its id (``before_run`` or
    ``after_run`` empty)."""
    fact_id: str                       # what a claim cites: « chg-1 »
    ttp: str
    vm: str                            # the target VM's resource id, lower case
    nth: int                           # 1: the first run of this key in each campaign
    previous_campaign: str
    before_run: str = ""
    after_run: str = ""
    detection_before: str = ""
    detection_after: str = ""
    latency_before: float | None = None
    latency_after: float | None = None
    decision_before: str = ""
    decision_after: str = ""
    confidence_before: float | None = None
    confidence_after: float | None = None
    escalated_before: bool | None = None
    escalated_after: bool | None = None
    unknown_before: str = ""           # a decision sought, not found: why (an unknown, never « none »)
    unknown_after: str = ""
    played_before: bool = False        # a run of the key in the previous campaign
    played_after: bool = False         # one in this campaign

    @property
    def side(self) -> str:
        """``both``, or the only side the key is on: ``before`` or ``after``."""
        if self.played_before and self.played_after:
            return "both"
        return "before" if self.played_before else "after"

    @property
    def latency_delta(self) -> float | None:
        if self.latency_before is None or self.latency_after is None:
            return None
        return self.latency_after - self.latency_before

    @property
    def confidence_delta(self) -> float | None:
        if self.confidence_before is None or self.confidence_after is None:
            return None
        return self.confidence_after - self.confidence_before

    @property
    def decision_unknown(self) -> str:
        """Why a side's decision is unknown, when one is."""
        return self.unknown_before or self.unknown_after

    def numbers(self) -> list[tuple[float, float]]:
        """The numbers a claim citing this fact may write, each with its tolerance: the
        latencies and their difference (seconds), the confidences and their difference, as
        a fraction (0,78) or in percent (78)."""
        out = [(abs(v), SECONDS_TOLERANCE)
               for v in (self.latency_before, self.latency_after, self.latency_delta) if v is not None]
        for v in (self.confidence_before, self.confidence_after, self.confidence_delta):
            if v is not None:
                out += [(abs(v), FRACTION_TOLERANCE), (abs(v) * 100, PERCENT_TOLERANCE)]
        return out

    def words(self) -> set[str]:
        """The actions and detections a claim citing this fact may name, in its ``value`` or
        its sentence — « unknown » too, when a side's decision is."""
        out = {w for w in (self.decision_before, self.decision_after,
                           self.detection_before, self.detection_after) if w}
        return out | ({"unknown"} if self.decision_unknown else set())

    def known_beside_unknown(self) -> bool:
        """One side's decision is unknown, the other's known: an action a claim says
        Glorfindel took may be the known side's (analysis/campaign_report.py ``verify``, the
        rule of #167). Unknown on both sides, or beside a side with no action: not so."""
        return any(unknown and not other_unknown and bool(other)
                   for unknown, other_unknown, other in (
                       (self.unknown_before, self.unknown_after, self.decision_after),
                       (self.unknown_after, self.unknown_before, self.decision_before)))

    def transitions(self) -> set[tuple[str, str]]:
        """What a claim may say changed, before → after: the action, the detection, the
        latency and the confidence (as a fraction and in percent), each with both sides
        known."""
        out: set = set()
        if self.decision_before and self.decision_after and not self.decision_unknown:
            out.add((self.decision_before, self.decision_after))
        if self.detection_before and self.detection_after:
            out.add((self.detection_before, self.detection_after))
        return out

    def ordered_numbers(self) -> list[tuple[float, float, float]]:
        """The (before, after, tolerance) of the latency and the confidence (as a fraction
        and in percent), each with both sides known: what « de X à Y » may say."""
        out = []
        if self.latency_before is not None and self.latency_after is not None:
            out.append((self.latency_before, self.latency_after, SECONDS_TOLERANCE))
        if self.confidence_before is not None and self.confidence_after is not None:
            out += [(self.confidence_before, self.confidence_after, FRACTION_TOLERANCE),
                    (self.confidence_before * 100, self.confidence_after * 100, PERCENT_TOLERANCE)]
        return out

    def row(self) -> dict:
        """What the model sees of the fact (data)."""
        out = {"fact": self.fact_id, "technique": self.ttp, "vm": self.vm, "nth": self.nth,
               "previous_campaign": self.previous_campaign}
        if self.side != "both":
            out["only_in"] = "previous campaign" if self.side == "before" else "this campaign"
        out.update({
            "runs": [self.before_run or None, self.after_run or None],
            "detection": [self.detection_before or None, self.detection_after or None],
            "latency_s": [self.latency_before, self.latency_after],
            "latency_delta_s": self.latency_delta,
            "decision": [None if self.unknown_before else self.decision_before or None,
                         None if self.unknown_after else self.decision_after or None],
            "confidence": [self.confidence_before, self.confidence_after],
            "confidence_delta": self.confidence_delta,
            "escalated": [self.escalated_before, self.escalated_after],
        })
        if self.decision_unknown:  # unknown, not « none »
            out["decision_unknown_because"] = [self.unknown_before or None, self.unknown_after or None]
        return out


@dataclass
class Comparison:
    """The previous campaign (``""`` when there is none, and ``why_none`` says why) and the
    change facts against it."""
    previous: str = ""
    why_none: str = ""
    changes: list[ChangeFact] = field(default_factory=list)


def _by_key(facts) -> dict[tuple[str, str, int], object]:
    """The executed runs of a campaign by (technique, VM, n): the n-th run of the key in
    ``seq`` order."""
    grouped: dict[tuple[str, str], list] = {}
    for f in sorted(facts, key=lambda f: (f.seq, f.run_id)):
        if (k := run_key(f)):
            grouped.setdefault(k, []).append(f)
    return {(ttp, vm, n): f for (ttp, vm), runs in grouped.items() for n, f in enumerate(runs, 1)}


def pair(before, after, previous: str) -> list[ChangeFact]:
    """The change facts of this campaign (``after``) against the previous one (``before``),
    joined exactly by key: this campaign's keys in its order, then the previous campaign's
    keys it does not have."""
    b, a = _by_key(before), _by_key(after)
    order = sorted(set(b) | set(a), key=lambda k: (0, a[k].seq) if k in a else (1, b[k].seq))
    out = []
    for i, (ttp, vm, n) in enumerate(order, 1):
        x, y = b.get((ttp, vm, n)), a.get((ttp, vm, n))
        out.append(ChangeFact(
            fact_id=f"chg-{i}", ttp=ttp, vm=vm, nth=n, previous_campaign=previous,
            before_run=x.run_id if x else "", after_run=y.run_id if y else "",
            detection_before=x.detection if x else "", detection_after=y.detection if y else "",
            latency_before=x.latency_s if x else None, latency_after=y.latency_s if y else None,
            decision_before=x.decision if x else "", decision_after=y.decision if y else "",
            confidence_before=x.confidence if x else None, confidence_after=y.confidence if y else None,
            escalated_before=x.escalated if x else None, escalated_after=y.escalated if y else None,
            unknown_before=x.decision_unknown if x else "", unknown_after=y.decision_unknown if y else "",
            played_before=x is not None, played_after=y is not None))
    return out


# ── The section, rendered by the code ───────────────────────────────────────────────────

TITLE = "## Ce qui a changé depuis la campagne précédente"
RULE = ("*Calculé par le code, pas par le modèle. La campagne précédente est la dernière "
        "campagne `done` antérieure à celle-ci qui partage au moins une clé avec elle : une "
        "technique jouée sur la même VM. Les runs des deux campagnes sont joints par clé.*")
_ESCALATED = {True: "escaladé", False: "sans escalade"}


def _vm_name(vm: str) -> str:
    return vm.rstrip("/").rsplit("/", 1)[-1] or vm


def _seconds(v: float | None) -> str:
    return "—" if v is None else f"{v:.1f}".replace(".", ",") + " s"


def _signed(v: float, text: str) -> str:
    return ("+" if v > 0 else "−" if v < 0 else "±") + text


def _decision(action: str, unknown: str) -> str:
    if unknown:
        return f"inconnue ({unknown})"
    return action or "—"


def _arrow(before: str, after: str) -> str:
    return f"{before} → {after}"


def _cells(c: ChangeFact) -> list[str]:
    latency = _arrow(_seconds(c.latency_before), _seconds(c.latency_after))
    if (d := c.latency_delta) is not None:
        latency += f" ({_signed(d, _seconds(abs(d)))})"
    conf = _arrow(*("—" if v is None else f"{v:.0%}" for v in (c.confidence_before, c.confidence_after)))
    if (d := c.confidence_delta) is not None:
        conf += f" ({_signed(round(d * 100), f'{abs(d) * 100:.0f} pts')})"
    return [
        _arrow(c.detection_before or "—", c.detection_after or "—"),
        latency,
        _arrow(_decision(c.decision_before, c.unknown_before), _decision(c.decision_after, c.unknown_after)),
        conf,
        _arrow(*(_ESCALATED.get(v, "—") if isinstance(v, bool) else "—"
                 for v in (c.escalated_before, c.escalated_after))),
    ]


def render_section(comparison: Comparison) -> list[str]:
    """The section's lines: the previous campaign, a row per key on both sides, then the
    keys on one side only — or, without a previous campaign, why."""
    lines = [TITLE, ""]
    if not comparison.previous:
        return lines + [f"*Aucune campagne précédente : {comparison.why_none}.*"]
    lines += [RULE, "", f"Campagne précédente : `{comparison.previous}`.", ""]
    both = [c for c in comparison.changes if c.side == "both"]
    lines += ["| Fait | Technique | VM | Détection | Latence | Action | Confiance | Escalade |",
              "|---|---|---|---|---|---|---|---|"]
    for c in both:
        nth = f" ({c.nth}ᵉ run)" if c.nth > 1 else ""
        lines.append(f"| `{c.fact_id}` | {c.ttp}{nth} | {_vm_name(c.vm)} | " + " | ".join(_cells(c)) + " |")
    for side, label in (("before", "Seulement dans la campagne précédente"),
                        ("after", "Seulement dans celle-ci")):
        only = [c for c in comparison.changes if c.side == side]
        if only:
            lines += ["", f"{label} ({len(only)}) : " + " ; ".join(
                f"`{c.fact_id}` {c.ttp} sur {_vm_name(c.vm)} ("
                + (f"run `{rid}`" if (rid := c.before_run or c.after_run) else "run sans identifiant") + ")"
                for c in only) + "."]
    if any(c.decision_unknown for c in both):
        lines += ["", "*Décision « inconnue » : non rattachée au run, pour la raison dite — ce "
                      "n'est pas dire que Glorfindel n'a pas agi.*"]
    return lines
