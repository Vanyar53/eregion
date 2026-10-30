"""BL1 (#280) — the two indicators of the finality the bench had never filled: the time to
contain and the share contained alone, computed by the code from a campaign's traces.

    python -m analysis.containment runs/campaigns/<campaign_id> [--fault-run <run_id> …] [--json]

Definitions (docs/analysis.md, « Temps pour contenir et part contenue seule ») :

- **An incident** is an executed technique run of the campaign. Its first malicious action is
  dated by the injector: ``attack_time``, Annatar's T0, the time ``attack_started`` carries.
- **Contained alone**: Glorfindel's decision on the detection the run counted — attached as the
  campaign report attaches it (the rule of #157, analysis/campaign_report.py ``run_decision``)
  — is an isolation or a block, executed in its own cycle (an action a human approves runs
  from a card, never in the cycle), read back on Azure (``verified`` true), and it held: no
  card of the reassertion says, on that VM, that it disappeared or is bypassed, from the
  read-back to the end of the run's exercise window, grace included (without a window: 15 min).
- **The time to contain** of an incident contained alone runs from T0 to that read-back
  (``outcome.verified_at``, else the cycle's own line, written just after). The campaign's is
  the median over its incidents contained alone; none contained, it is ``None`` — never 0.
- **The share contained alone** is the incidents contained alone over every incident of the
  campaign, missed ones included. A decision the files do not give is not counted as
  contained, but not as « not contained » either: the share is then a lower bound, and said.
- **A fault** is a Gothmog run of the campaign, never an incident. A decision to isolate or to
  block on one of its targets, seen during its window, is « a fault taken for an attack »:
  counted apart and said, executed or only recommended; executed, a disruptive action wrongly
  taken.

Every other ending of an incident is said by its own outcome (``OUTCOMES``): missed, decision
unknown, held by a guard (a mode, the readiness, the signal guards…), escalated (low
confidence, unknown action…), action failed, verification failed, isolation that did not hold,
a decision that contains nothing (a snapshot), a dry run.

Pure functions over records (the watch's debug lines, or the console's slim cycles) and cards:
no Azure, no model, no other component imported here (D1 — the console and the campaign
report feed it).
"""
from __future__ import annotations

import json
import statistics
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from eregion_core import run_report
from eregion_core.run_report import CONTAINING as DISRUPTIVE   # C1: one list of what contains

# The exercise window's grace (eregion_core/exercise.py GRACE_AFTER_S): how long after the
# read-back a containment is watched when the run has no window.
HOLD_WATCH_S = 15 * 60
# Cards of the reassertion saying a containment no longer holds on its VM (glorfindel/reassert.py:
# the rules gone, re-applied once or not; reassert_cards.py: an allow evaluated before the deny).
NOT_HOLDING_TYPES = ("verification_failed", "bypassed")
# A deterministic gate held the action (glorfindel/agent.py escalate_to_human): its card says
# which. The others — low confidence, an unknown action, a destructive one, a cycle that failed —
# are an escalation, a human's call.
GUARD_TYPES = frozenset({
    "mode_hold", "readiness_hold", "uncharacterized_signal", "unattributed_signal",
    "telemetry_gap", "unstable_decision", "protected_address", "release_hold",
    "control_plane_change", "identity_change",
})

# An action attempted that did not complete (glorfindel/agent.py execute_action).
FAILED_TYPES = ("write_blocked", "action_failed")
# The reassertion's cards about a release or an unblock that was interrupted (glorfindel/
# reassert.py): an isolate_vm / block_suspicious_ip card like those of a disappearance, but they
# speak of a lifting a human started — never of a containment that did not hold. Told apart by
# the reassertion's own words, the only mark they carry.
RELEASE_SAID = ("La levée de l'isolation", "Le déblocage de")
# What lifts a containment, as the watch and the operator write it: the manual actions
# (runs/manual_actions.jsonl, glorfindel/cli.py _record_manual_action) and the watch's own
# release on a recovery (recovery_complete → release_isolation).
LIFTING = ("release_isolation", "reset", "unblock_ip")

CONTAINED = "contained_alone"
NOT_HOLDING = "not_holding"
VERIFICATION_FAILED = "verification_failed"
ACTION_FAILED = "action_failed"
HELD = "held_by_guard"
ESCALATED = "escalated"
NOT_CONTAINING = "not_containing"
DRY_RUN = "dry_run"
MISSED = "missed"
UNKNOWN = "decision_unknown"

# Each ending, as the report and the console say it.
OUTCOMES = {
    CONTAINED: "contenu seul",
    NOT_HOLDING: "contenu, puis l'isolation n'a pas tenu",
    VERIFICATION_FAILED: "exécuté, vérification échouée",
    ACTION_FAILED: "action tentée, en échec",
    HELD: "retenu par un garde-fou",
    ESCALATED: "escaladé à un humain",
    NOT_CONTAINING: "aucune action qui contient",
    DRY_RUN: "à blanc (dry run), rien d'exécuté",
    MISSED: "non détecté",
    UNKNOWN: "décision inconnue",
}


def _ts(value) -> float | None:
    """Epoch seconds from a number or an ISO time (C1's reader, ``run_report.epoch``)."""
    return run_report.epoch(value) if value is not None and value != "" else None


def _same(a, b) -> bool:
    """Two Azure resource ids name the same resource — without case, as ARM compares them (the
    rule of annatar/runner/detection.py ``same_resource``, not imported: D1)."""
    a, b = str(a or "").strip().rstrip("/").lower(), str(b or "").strip().rstrip("/").lower()
    return bool(a) and a == b


def view(rec: dict) -> dict:
    """One decision, from a debug line of the watch (``signal``, ``outcome``) or a console slim
    cycle (``eregion_console/api.py`` ``_slim_cycle``) — the fields this module reads."""
    if isinstance(rec.get("signal"), dict):
        sig = rec["signal"]
        out = rec.get("outcome") if isinstance(rec.get("outcome"), dict) else {}
        raw = sig.get("raw_signal") if isinstance(sig.get("raw_signal"), dict) else {}
        # When the watch saw it (annatar/runner/detection.py detection_time): the attack time
        # plus the latency a run's own poll measured, else the signal's stamp.
        seen = None
        if _ts(raw.get("attack_time")) is not None and _ts(raw.get("detection_time_s")) is not None:
            seen = float(raw["attack_time"]) + float(raw["detection_time_s"])
        return {"event": sig.get("event", ""), "ttp": sig.get("ttp", ""),
                "resource_id": sig.get("resource_id", ""), "signal_id": sig.get("signal_id", ""),
                "seen_at": seen if seen is not None else _ts(sig.get("timestamp")),
                "at": _ts(rec.get("timestamp")), "action": rec.get("action") or "",
                "confidence": rec.get("confidence"), "escalate": rec.get("escalate"),
                "mode": rec.get("resolved_autonomy_mode", ""),
                "status": out.get("status", ""), "executed": out.get("executed"),
                "verified": out.get("verified"), "unverified": bool(out.get("unverified")),
                "verified_at": _ts(out.get("verified_at")),
                "escalation_type": out.get("escalation_type", "")}
    return {"event": rec.get("event", ""), "ttp": rec.get("ttp", ""),
            "resource_id": rec.get("resource_id", ""), "signal_id": rec.get("signal_id", ""),
            "seen_at": _ts(rec.get("signal_at")), "at": _ts(rec.get("at")),
            "action": rec.get("action") or "", "confidence": rec.get("confidence"),
            "escalate": rec.get("escalate"), "mode": rec.get("mode", ""),
            "status": rec.get("status", ""), "executed": rec.get("executed"),
            "verified": rec.get("verified"), "unverified": bool(rec.get("unverified")),
            "verified_at": _ts(rec.get("verified_at")),
            "escalation_type": rec.get("escalation_type", "")}


def outcome_of(decision: dict) -> tuple[str, str]:
    """``(outcome, why)`` of a decision before the holding check: ``CONTAINED`` means executed
    in the cycle and read back on Azure. ``decision``: a ``view``."""
    action, status = decision["action"], decision["status"]
    kind = decision["escalation_type"]
    if status == "dry_run":
        return DRY_RUN, ""
    if action not in DISRUPTIVE:      # a snapshot, an investigation, no action at all
        return NOT_CONTAINING, ", ".join(
            x for x in (action or "aucune action", "exécuté" if decision["executed"] is True else "",
                        kind) if x)
    if decision["executed"] is True:
        if decision["verified"] is True and not decision["unverified"]:
            return CONTAINED, ""
        return VERIFICATION_FAILED, ("non vérifiable" if decision["verified"] is None
                                     else "relue fausse sur Azure")
    # escalate_to_human rewrites the status to "escalated" and keeps the failure in the card's
    # type: both are read (the status alone, as the action wrote it, too).
    if status in FAILED_TYPES or kind in FAILED_TYPES:
        return ACTION_FAILED, kind if kind in FAILED_TYPES else status
    if kind in GUARD_TYPES:
        return HELD, kind
    return ESCALATED, kind or "escalade"


def contained_at(decision: dict) -> float | None:
    """When the containment was read back on Azure: ``verified_at``, else the cycle's line —
    the rule of C1's ``run_report.timeline``, before it is bounded by the attack."""
    return decision["verified_at"] if decision["verified_at"] is not None else decision["at"]


def time_to_contain(t0: float, decision: dict) -> float | None:
    """From the attack to the read-back, as C1's ``run_report.timeline`` gives it (one
    definition for the run format, the coverage matrix and BL1): None before the attack."""
    return run_report.timeline({"at": t0, "detected_at": None}, decision)["contain_s"]


def not_holding(resource_id: str, since: float, until: float, cards) -> dict | None:
    """The first card of the reassertion that says, on this VM, between ``since`` and ``until``,
    that its containment no longer holds: a card about an isolation or a block (a check that
    failed after an approved release, ``release_isolation``, speaks of the release), or one that
    says it is bypassed — never one about a release or an unblock interrupted."""
    found = [c for c in cards or () if isinstance(c, dict)
             and c.get("escalation_type") in NOT_HOLDING_TYPES
             and (c.get("action") in DISRUPTIVE or c.get("escalation_type") == "bypassed")
             and not str(c.get("reason") or "").startswith(RELEASE_SAID)
             and _same(c.get("resource_id"), resource_id)
             and (t := _ts(c.get("timestamp"))) is not None and since <= t <= until]
    return min(found, key=lambda c: _ts(c["timestamp"])) if found else None


def first_lifting(resource_id: str, since: float, liftings) -> float | None:
    """When the containment of this VM was first lifted after ``since`` — a release, a reset, an
    unblock, by an operator or by the watch on a recovery (``liftings``: ``(resource id, epoch)``
    pairs, ``read_liftings``) — else None. Its watch ends there: what follows is not its."""
    found = [t for rid, t in liftings or () if t is not None and t >= since and _same(rid, resource_id)]
    return min(found) if found else None


def lifting_of(rec: dict) -> tuple[str, float | None] | None:
    """``(resource id, when)`` when this line lifts a containment: a manual action of the
    operator, or the watch's own release on a recovery; else None."""
    if not isinstance(rec, dict):
        return None
    d = view(rec)
    if d["action"] not in LIFTING and d["event"] != "recovery_complete":
        return None
    if d["executed"] is False:          # a release held (release_hold), or that failed to start
        return None
    return d["resource_id"], d["at"]


@dataclass
class Incident:
    run_id: str
    ttp: str
    target: str
    t0: float | None                    # attack_time (Annatar's T0); None: unknown
    outcome: str
    why: str = ""
    action: str = ""
    confidence: float | None = None
    mode: str = ""
    contained_at: float | None = None
    time_to_contain_s: float | None = None

    @property
    def label(self) -> str:
        return OUTCOMES[self.outcome] + (f" ({self.why})" if self.why else "")


def incident(run_id: str, ttp: str, target: str, t0, detection: str, decision: dict | None,
             unknown_why: str = "", until: float | None = None, cards=(),
             liftings=()) -> Incident:
    """One technique run of the campaign and how it ended. ``decision``: Glorfindel's on the
    detection the run counted (a debug line or a slim cycle), ``None``/``{}`` when not
    attached; ``unknown_why``: why not (analysis/campaign_report.py REASONS); ``until``: the
    end of the run's exercise window, grace included (epoch); ``liftings``: when containments
    were lifted (``read_liftings``) — the watch stops at the first one on the VM."""
    t0 = _ts(t0)
    base = {"run_id": run_id, "ttp": ttp, "target": target, "t0": t0}
    if detection == "missed":
        return Incident(**base, outcome=MISSED)
    if not decision:
        return Incident(**base, outcome=UNKNOWN,
                        why=unknown_why or ("détection inconnue" if detection != "detected"
                                            else "décision non retrouvée"))
    d = view(decision)
    conf = d["confidence"] if isinstance(d["confidence"], (int, float)) \
        and not isinstance(d["confidence"], bool) else None
    out, why = outcome_of(d)
    inc = Incident(**base, outcome=out, why=why, action=d["action"], confidence=conf, mode=d["mode"])
    if out != CONTAINED:
        return inc
    at = contained_at(d)
    inc.contained_at = at
    if at is not None:
        end = until if until is not None else at + HOLD_WATCH_S
        lifted = first_lifting(target or d["resource_id"], at, liftings)
        if lifted is not None:
            end = min(end, lifted)
        card = not_holding(target or d["resource_id"], at, end, cards)
        if card is not None:
            inc.outcome, inc.why = NOT_HOLDING, card.get("escalation_type", "")
            return inc
    if t0 is None:
        inc.why = "attack_time absent : temps inconnu"
    elif at is None:
        inc.why = "heure de la vérification absente : temps inconnu"
    else:
        inc.time_to_contain_s = time_to_contain(t0, d)
        if inc.time_to_contain_s is None:
            inc.why = "vérifiée avant l'attaque (horloges des deux hôtes ?) : temps inconnu"
    return inc


@dataclass
class FaultRun:
    run_id: str
    fault: str
    targets: list[str]
    start: float | None
    until: float | None
    why: str = ""                       # the fault could not be checked: why (start unknown…)
    mistaken: list[dict] = field(default_factory=list)   # decisions to isolate / block on it
    attached: str = ""                  # how it belongs to the campaign (NAMED, AROUND)

    @property
    def executed(self) -> int:
        return sum(1 for m in self.mistaken if m.get("executed"))


def fault_run(run_id: str, fault: str, targets, start, end, records, *, window_until=None,
              taken: set[str] = frozenset(), without_glorfindel: bool = False,
              played=()) -> FaultRun:
    """A Gothmog run of the campaign, and Glorfindel's decisions to isolate or to block on one
    of its targets seen between its start and the end of its window (else its end plus the
    grace) — a fault taken for an attack. ``taken``: the signal ids already attached to an
    incident (never counted twice); ``played``: ``(technique, from, until)`` of the campaign's
    technique runs — a decision on that technique inside that run's window is the run's (late,
    or not attached), never the fault's."""
    targets = [str(t) for t in targets or () if t]
    start = _ts(start)
    until = _ts(window_until)
    if until is None and _ts(end) is not None:
        until = _ts(end) + HOLD_WATCH_S
    fr = FaultRun(run_id, fault, targets, start, until)
    if without_glorfindel:
        fr.why = "sans Glorfindel, par choix : sa réaction n'est pas mesurée"
        return fr
    if start is None or until is None or not targets:
        fr.why = ("début inconnu" if start is None else "fin inconnue" if until is None
                  else "cibles inconnues") + " : la panne n'a pas pu être vérifiée"
        return fr
    for rec in records or ():
        d = view(rec)
        if d["event"] != "detection" or d["action"] not in DISRUPTIVE:
            continue
        if d["signal_id"] and d["signal_id"] in taken:
            continue
        if not any(_same(d["resource_id"], t) for t in targets):
            continue
        if d["seen_at"] is None or not start <= d["seen_at"] <= until:
            continue
        if any(d["ttp"] == ttp and a is not None and b is not None and a <= d["seen_at"] <= b
               for ttp, a, b in played):
            continue
        fr.mistaken.append({"action": d["action"], "executed": d["executed"] is True,
                            "resource_id": d["resource_id"], "signal_id": d["signal_id"],
                            "seen_at": d["seen_at"], "confidence": d["confidence"]})
    fr.mistaken.sort(key=lambda m: m["seen_at"])
    return fr


@dataclass
class Containment:
    incidents: list[Incident] = field(default_factory=list)
    faults: list[FaultRun] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def contained(self) -> list[Incident]:
        return [i for i in self.incidents if i.outcome == CONTAINED]

    @property
    def times(self) -> list[float]:
        return [i.time_to_contain_s for i in self.contained if i.time_to_contain_s is not None]

    @property
    def median_s(self) -> float | None:
        return round(statistics.median(self.times), 1) if self.times else None

    @property
    def share(self) -> float | None:
        return len(self.contained) / len(self.incidents) if self.incidents else None

    @property
    def lower_bound(self) -> bool:
        """Some decisions are unknown: the share is at least what it says."""
        return any(i.outcome == UNKNOWN for i in self.incidents)

    @property
    def faults_mistaken(self) -> int:
        return sum(1 for f in self.faults if f.mistaken)

    def summary(self) -> dict:
        """The figures, as the console shows them and ``--json`` writes them."""
        by = {k: sum(1 for i in self.incidents if i.outcome == k) for k in OUTCOMES}
        return {"incidents": len(self.incidents), "contained": len(self.contained),
                "share": self.share, "lower_bound": self.lower_bound,
                "median_s": self.median_s, "timed": len(self.times),
                "by_outcome": {k: v for k, v in by.items() if v},
                "faults": len(self.faults), "faults_mistaken": self.faults_mistaken,
                "disruptive_on_faults": sum(f.executed for f in self.faults),
                "unchecked_faults": sum(1 for f in self.faults if f.why)}

    def as_dict(self) -> dict:
        return {"summary": self.summary(),
                "incidents": [{**asdict(i), "label": i.label} for i in self.incidents],
                "faults": [{**asdict(f), "executed": f.executed} for f in self.faults],
                "notes": list(self.notes)}


def compute(incidents: list[Incident], faults: list[FaultRun] = (), notes=()) -> Containment:
    return Containment(list(incidents), list(faults), list(notes))


# ── Rendering (the campaign report's section; French, as the report) ─────────────────────

def _secs(s: float | None) -> str:
    if s is None:
        return "—"
    if s < 60:
        return f"{s:.1f}".replace(".", ",") + " s"
    m, r = divmod(int(round(s)), 60)
    return f"{m} min {r:02d} s"


def _iso(ts: float | None) -> str:
    if ts is None:
        return "—"
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return "—"


def _vm(rid: str) -> str:
    return str(rid or "").rstrip("/").rsplit("/", 1)[-1] or "—"


def render(c: Containment) -> list[str]:
    """The report's section: computed, never written by the model."""
    s = c.summary()
    lines = ["## Réponse : temps pour contenir, part contenue seule", "",
             "*Calculés par le code depuis les fichiers de la campagne (analysis/containment.py), "
             "jamais par le modèle. Un incident = un run de technique exécuté ; une panne n'en "
             "est jamais un.*", ""]
    if not c.incidents:
        lines.append("Aucun incident : aucun run de technique exécuté.")
    else:
        share = f"{s['contained']} sur {s['incidents']}"
        if s["lower_bound"]:
            share = f"au moins {share} (une décision inconnue n'est pas comptée contenue)"
        med = (f"**{_secs(s['median_s'])}** (médiane sur {s['timed']} incident(s) contenu(s) seul(s))"
               if s["median_s"] is not None else "**—** (aucun incident contenu seul)")
        lines += [f"**Part contenue seule : {share}** · temps pour contenir : {med}.", "",
                  "| Run | Technique | VM | Issue | Action | T0 | Temps pour contenir |",
                  "|---|---|---|---|---|---|---|"]
        for i in c.incidents:
            act = i.action + (f" ({i.confidence:.0%})" if i.confidence is not None else "") if i.action else "—"
            lines.append(f"| `{i.run_id}` | {i.ttp} | {_vm(i.target)} | {i.label} | {act} | "
                         f"{_iso(i.t0)} | {_secs(i.time_to_contain_s)} |")
    if c.faults:
        lines += ["", f"**Pannes : {s['faults']}** · prise(s) pour une attaque : "
                      f"**{s['faults_mistaken']}** · action(s) disruptive(s) exécutée(s) sur une "
                      f"panne : **{s['disruptive_on_faults']}**."]
        for f in c.faults:
            head = (f"- `{f.run_id}` ({f.fault or 'panne'}, {', '.join(_vm(t) for t in f.targets) or '—'}"
                    + (f" ; rattachée : {f.attached}" if f.attached else "") + ")")
            if f.why:
                lines.append(f"{head} : non vérifiée — {f.why}.")
            elif not f.mistaken:
                lines.append(f"{head} : aucune décision d'isoler ou de bloquer pendant sa fenêtre.")
            for m in f.mistaken:
                lines.append(f"{head} : **prise pour une attaque** — {m['action']} sur {_vm(m['resource_id'])} "
                             f"à {_iso(m['seen_at'])}, "
                             + ("exécutée (une action disruptive à tort)." if m["executed"]
                                else "recommandée, non exécutée."))
    else:
        lines += ["", "*Aucune panne rattachée à cette campagne (nommée, ou sur une de ses VM dans "
                      "l'heure qui l'entoure).*"]
    if c.notes:
        lines += ["", *[f"*{n}*" for n in c.notes]]
    return lines


# ── Loading a campaign's traces ───────────────────────────────────────────────────────────

def _cards_file() -> Path:
    """Glorfindel's cards, read only (analysis/separation.py: never its memory)."""
    from analysis import separation
    return separation.glorfindel_state() / "escalations.jsonl"


def read_cards(path: Path | None = None) -> list[dict]:
    try:
        text = Path(path or _cards_file()).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def read_liftings(runs_dir: Path, since: float = 0.0) -> list[tuple[str, float | None]]:
    """When containments were lifted, from the files: the operator's manual actions
    (``runs/manual_actions.jsonl``), the watch's own releases (the debug files of ``runs/``
    written since ``since``, a minute of slack) — ``(resource id, epoch)``."""
    out = []
    paths = [Path(runs_dir) / "manual_actions.jsonl", *sorted(Path(runs_dir).glob("*_debug.jsonl"))]
    for path in paths:
        try:
            if path.stat().st_mtime < since - 60:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if (lift := lifting_of(rec)) is not None:
                out.append(lift)
    return out


def _gothmog_reports(runs_dir: Path) -> dict[str, dict]:
    out = {}
    for path in sorted(Path(runs_dir).glob("*.json")):
        try:
            r = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(r, dict) and isinstance(r.get("metrics"), dict) \
                and run_report.kind_of(r) == "fault":       # C1's word, else Gothmog's
            out[str(r.get("run_id") or path.stem)] = r
    return out


def campaign_span(manifest: dict) -> tuple[float | None, float | None]:
    """From the first scenario's start to the last one's end — as the manifest says them."""
    starts = [t for s in manifest.get("scenarios") or [] if isinstance(s, dict)
              if (t := _ts(s.get("started_at"))) is not None]
    ends = [t for s in manifest.get("scenarios") or [] if isinstance(s, dict)
            if (t := _ts(s.get("finished_at"))) is not None]
    return (min(starts) if starts else None, max(ends) if ends else None)


def load(campaign_dir: Path, runs_dir: Path | None = None, *, fault_runs=(), cards=None,
         warn=None) -> Containment:
    """The containment of a campaign, from its files: each executed technique run with
    Glorfindel's decision as the campaign report attaches it (``run_decision``), and the
    Gothmog runs of the campaign — named (``fault_runs``), or on one of its VMs within the hour
    around it (``around``). ``cards``: Glorfindel's cards, else read from its state (read
    only)."""
    from analysis import campaign_report as cr
    from eregion_core.exercise import last_moment, window_refusal

    campaign_dir = Path(campaign_dir)
    runs_dir = Path(runs_dir) if runs_dir else campaign_dir.parent.parent
    warn = warn or (lambda m: None)
    manifest = cr._read_json(campaign_dir / "manifest.json")
    cards = read_cards() if cards is None else list(cards)
    watch_records = cr._watch_files(runs_dir)
    channel = cr.from_channel(campaign_dir)
    incidents, taken, notes = [], set(), []

    def until_of(rid: str) -> float | None:
        window = cr._read_json(cr.windows_dir(runs_dir) / f"{rid}.json")
        last = None if not window or window_refusal(window) else last_moment(window)
        return last.timestamp() if last else None

    rows = []
    liftings = read_liftings(runs_dir, campaign_span(manifest)[0] or 0.0)
    for s, rid in cr._scenarios(manifest, warn):
        if s.get("status") != "executed" or not rid:
            continue
        if channel and (why := cr.channel_refusal(s, rid, campaign_dir, runs_dir)):
            notes.append(f"run {rid} écarté : {why}")
            continue
        report = cr._read_json(campaign_dir / "runs" / f"{rid}.json", runs_dir / f"{rid}.json")
        dec, why, _ = cr.run_decision(s, rid, campaign_dir, runs_dir, watch_records)
        rows.append((s, rid, _ts((report.get("metrics") or {}).get("attack_time")), dec, why))
    # One decision, one incident (the earliest run): a later run whose search falls on the same
    # signal has no decision of its own in the files — unknown, said.
    rows.sort(key=lambda r: (r[2] is None, r[2] or 0.0, r[1]))
    owner: dict[str, str] = {}
    for i, (s, rid, t0, dec, why) in enumerate(rows):
        sid = ((dec.get("signal") or {}).get("signal_id")) if dec else ""
        if sid and sid in owner:
            rows[i] = (s, rid, t0, {}, f"décision déjà rattachée à {owner[sid]}")
        elif sid:
            owner[sid] = rid
            taken.add(sid)
    played = []
    for s, rid, t0, dec, why in rows:
        target = str(s.get("target_resource_id") or "")
        # A containment is watched until the end of its run's window — and never into the next
        # run on the same VM: what happens to that one's isolation is that one's.
        until = until_of(rid)
        later = [t for s2, r2, t, *_ in rows
                 if r2 != rid and t is not None and t0 is not None and t > t0
                 and _same(s2.get("target_resource_id"), target)]
        if later:
            until = min(later) if until is None else min(until, min(later))
        played.append((s.get("ttp") or "", t0, until if until is not None
                       else (t0 + HOLD_WATCH_S if t0 is not None else None)))
        incidents.append(incident(rid, s.get("ttp") or "", target, t0,
                                  s.get("detection") or "unknown", dec, why, until, cards,
                                  liftings))

    start, end = campaign_span(manifest)
    reports = _gothmog_reports(runs_dir)
    named = [r for r in fault_runs or () if r]
    for rid in named:
        if rid not in reports:
            notes.append(f"panne {rid} nommée, son rapport est introuvable sous {runs_dir}")
    targets = [str(s.get("target_resource_id") or "") for s, *_ in rows]
    attached = {rid: NAMED for rid in named if rid in reports}
    for rid in sorted(reports):
        if rid not in attached and around(reports[rid]["metrics"], targets, start, end):
            attached[rid] = AROUND
    faults = []
    for rid, how in attached.items():
        m = reports[rid]["metrics"]
        # The watch's files written since the fault started (or the campaign, the earlier).
        since = min(x for x in (start, _ts(m.get("fault_start")), float("inf")) if x is not None)
        fr = fault_run(rid, str(m.get("experiment_id") or m.get("fault") or ""), m.get("targets") or [],
                       m.get("fault_start"), m.get("fault_end"),
                       watch_records(since if since != float("inf") else 0.0),
                       window_until=until_of(rid), taken=taken,
                       without_glorfindel=m.get("without_glorfindel") is True, played=played)
        fr.attached = how
        faults.append(fr)
    return compute(incidents, faults, notes)


# How a fault run belongs to a campaign, until a campaign plays its faults itself: named
# by the operator, or a fault on one of the campaign's VMs that overlaps the campaign or the hour
# around it (a declared campaign plays its fault just before or after its techniques, BL1).
NAMED = "nommée"
AROUND = "sur une de ses VM, dans l'heure qui l'entoure"
ATTACH_S = 3600.0


def around(metrics: dict, targets, start: float | None, end: float | None) -> bool:
    """A Gothmog run on one of ``targets`` whose fault overlaps ``[start - 1 h, end + 1 h]``."""
    if start is None or end is None:
        return False
    fs, fe = _ts(metrics.get("fault_start")), _ts(metrics.get("fault_end"))
    if fs is None:
        return False
    fe = fe if fe is not None else fs
    if fs > end + ATTACH_S or fe < start - ATTACH_S:
        return False
    return any(_same(t, x) for t in metrics.get("targets") or [] for x in targets)


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m analysis.containment",
                                 description="BL1 : temps pour contenir et part contenue seule d'une campagne.")
    ap.add_argument("campaign_dir")
    ap.add_argument("--runs-dir", default=None)
    ap.add_argument("--fault-run", action="append", default=[],
                    help="un run de Gothmog à rattacher (répétable) ; en plus de ceux sur une de ses VM dans l'heure qui l'entoure")
    ap.add_argument("--json", action="store_true", help="les chiffres et chaque incident, en JSON")
    args = ap.parse_args(argv)
    cdir = Path(args.campaign_dir)
    if not (cdir / "manifest.json").is_file():
        print(f"{cdir} : pas de manifest.json", file=sys.stderr)
        return 2
    c = load(cdir, Path(args.runs_dir) if args.runs_dir else None, fault_runs=args.fault_run,
             warn=lambda m: print(f"[containment] {m}", file=sys.stderr))
    print(json.dumps(c.as_dict(), indent=2, ensure_ascii=False) if args.json else "\n".join(render(c)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
