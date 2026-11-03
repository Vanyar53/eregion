from __future__ import annotations

import json
import math
import time
import uuid
from pathlib import Path


_DEFAULT_PATH = Path.home() / ".glorfindel" / "cycles"
# How many more cycles the retrieval reads than it returns, so that the copies of a
# replayed cycle, dropped, still leave N distinct ones.
_DUPLICATE_SLACK = 4
# SEC17 (V-12): how old a past cycle may be to be given as a precedent — 90 days unless the
# config says otherwise (`memory.max_age_days`, glorfindel/config.py), never more than ten years.
DEFAULT_MAX_AGE_DAYS = 90.0
MAX_AGE_CEILING_DAYS = 3650.0
_DAY_S = 86400
# SEC17 (V-12, decision of Jonathan, 03/11): the date given to a real cycle stored before cycles
# were dated (no `stored_at`). A cycle is `real` only since B2 — commit d4e51fa, 2026-10-16
# 14:30 +0200, « chaque cycle sait s'il vient d'un exercice » — and the only writer of this
# collection is `store`: before B2 no cycle carried `source`, and the search takes `source=real`
# only (a cycle without the field is left out by the filter). So no real cycle is older than B2.
# Midnight UTC that day, earlier than the commit: such a cycle is given an age at least its true
# one (A0), never today's, never a date it carries. With the default bound, kept until about
# 2027-01-14, then aged out.
B2_FLOOR = 1792108800          # 2026-10-16T00:00:00Z


def checked_max_age(days) -> float:
    """``days`` as a bound of age: a finite number, positive, at most the ceiling — else ValueError."""
    if isinstance(days, bool) or not isinstance(days, (int, float)):
        raise ValueError(f"un nombre de jours est attendu, pas {days!r}")
    if not math.isfinite(days) or not 0 < days <= MAX_AGE_CEILING_DAYS:
        raise ValueError(f"un nombre de jours entre 0 (exclu) et {MAX_AGE_CEILING_DAYS:g} est attendu, pas {days}")
    return float(days)


class CycleMemory:
    """Persistent vector store for Glorfindel decision cycles.

    Each cycle is (signal → reasoning → action → outcome).
    At decision time, retrieve the N most similar past cycles as context.
    No model weights change — the LLM learns from context, not fine-tuning.
    """

    def __init__(self, path: str | Path | None = None, max_age_days: float | None = None,
                 clock=time.time):
        import chromadb

        # SEC17 (V-12): the age past which a cycle is no precedent; the clock that dates a cycle
        # when it is stored, and measures its age at retrieval — Glorfindel's, never the signal's.
        self.max_age_days = checked_max_age(DEFAULT_MAX_AGE_DAYS if max_age_days is None else max_age_days)
        self._clock = clock
        storage_path = Path(path) if path else _DEFAULT_PATH
        storage_path.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(storage_path))
        self._collection = self._client.get_or_create_collection(
            name="cycles",
            metadata={"hnsw:space": "cosine"},
        )

    def store(self, cycle: dict) -> None:
        """Persist a completed cycle, under an identifier of its own (SEC4a, V-12).

        Drawn here, never taken from the signal: a cycle is added, never overwritten.
        The copies of a replayed cycle are folded at retrieval (`retrieve_similar`)."""
        cycle_id = f"cycle-{uuid.uuid4().hex}"
        document = _cycle_to_text(cycle)
        self._collection.add(
            ids=[cycle_id],
            documents=[document],
            metadatas=[{
                "ttp": cycle.get("ttp", ""),
                "action": cycle.get("action", ""),
                "outcome": str(cycle.get("outcome", "")),
                "signal_id": cycle.get("signal_id", ""),
                "run_id": cycle.get("run_id", ""),
                # B2: `exercise` or `real` (eregion_core/exercise.py) — shown to the model
                # with each past cycle, and what the retrieval filters on (SEC4a).
                "source": cycle.get("source", ""),
                "exercise_run": cycle.get("exercise_run", ""),
                "event": cycle.get("event", ""),
                "detection_s": cycle.get("detection_s", 0),
                "action_s": cycle.get("action_s", 0),
                "confidence": float(cycle.get("confidence", 0.0)),
                "past_cycles_used": json.dumps(cycle.get("past_cycles_used", [])),
                # SEC17 (V-12): when the cycle was stored, by this host's clock — its age at
                # retrieval. Never taken from the cycle: a log line does not date a precedent.
                "stored_at": int(self._clock()),
            }],
        )

    def _cutoff(self) -> int:
        """The oldest ``stored_at`` a precedent may carry (SEC17, V-12)."""
        return int(self._clock() - self.max_age_days * _DAY_S)

    def _b2_within(self) -> bool:
        """Whether a cycle dated by the B2 floor (stored before SEC17) is still within the bound."""
        return B2_FLOOR >= self._cutoff()

    def retrieve_similar(self, signal: dict, n: int = 3) -> list[dict]:
        """Return the N past cycles most similar to this signal — real cycles only, for
        every signal (SEC4a, V-12), and of a bounded age (SEC17, V-12).

        A cycle stored more than ``max_age_days`` ago is no precedent: a year-old decision
        weighed as much as yesterday's. One stored before SEC17 carries no date: it is dated by
        the B2 floor (``B2_FLOOR``, an age at least its true one), given while that floor is
        within the bound, left out after. Nothing is erased: ``age_census`` counts what the age
        leaves out, and `glorfindel report` says it.

        An exercise's cycle, or one of unknown source (recorded before B2, labelling
        unreadable), is never a precedent. Not for an exercise either: what the model is
        shown must not tell it whether the current signal is one (the prompt says it is
        not given). The cost: a bench's memory, made of exercises, shows nothing.

        One cycle per (signal_id, action, run_id), the most similar: a `respond` replayed
        on the same file stores its cycles again (the identifiers are drawn, never the
        signal's), and the same cycle never fills the N places."""
        if self._collection.count() == 0:
            return []
        query_text = _signal_to_text(signal)
        size = min(n * _DUPLICATE_SLACK, self._collection.count())
        cutoff = self._cutoff()
        results = self._collection.query(
            query_texts=[query_text], n_results=size, include=["documents", "metadatas", "distances"],
            where={"$and": [{"source": "real"}, {"stored_at": {"$gte": cutoff}}]},
        )
        found = list(zip(results["distances"][0], results["documents"][0], results["metadatas"][0]))
        if self._b2_within():
            # The undated ones (stored before SEC17), dated by the B2 floor — which is within the
            # bound: the filter cannot name a missing field, so they are read among the real ones.
            real = self._collection.query(query_texts=[query_text], n_results=size, where={"source": "real"},
                                          include=["documents", "metadatas", "distances"])
            found += [(d, doc, meta) for d, doc, meta in
                      zip(real["distances"][0], real["documents"][0], real["metadatas"][0])
                      if not _dated(meta)]
            found.sort(key=lambda row: row[0])
        cycles, seen = [], set()
        for _distance, doc, meta in found:
            key = (meta.get("signal_id", ""), meta.get("action", ""), meta.get("run_id", ""))
            if key in seen:
                continue
            seen.add(key)
            cycles.append({"summary": doc, **meta})
            if len(cycles) == n:
                break
        return cycles

    def count(self) -> int:
        return self._collection.count()

    def age_census(self) -> dict:
        """The real cycles — the only ones a search can give — by age (SEC17, V-12): ``within``
        the bound, ``too_old`` (stored before it: left out of the search, never erased). Among
        them, ``b2_dated``: stored before SEC17, no date of their own, dated by the B2 floor."""
        cutoff = self._cutoff()
        got = self._collection.get(where={"source": "real"}, include=["metadatas"])
        within = too_old = b2_dated = 0
        for meta in got.get("metadatas") or []:
            at = _stored_at(meta or {})
            b2_dated += not _dated(meta or {})
            if at >= cutoff:
                within += 1
            else:
                too_old += 1
        return {"max_age_days": self.max_age_days, "real": within + too_old,
                "within": within, "too_old": too_old, "b2_dated": b2_dated,
                "b2_floor": "2026-10-16"}


def _dated(meta: dict) -> bool:
    """The cycle carries the date `store` gave it (SEC17)."""
    at = meta.get("stored_at")
    return isinstance(at, (int, float)) and not isinstance(at, bool) and math.isfinite(at)


def _stored_at(meta: dict) -> float:
    """When the cycle was stored — its own date, else the B2 floor: never later than the truth."""
    return float(meta["stored_at"]) if _dated(meta) else float(B2_FLOOR)


def age_census(path: str | Path | None = None, max_age_days: float | None = None) -> dict:
    """``CycleMemory.age_census`` for `glorfindel report`, without making a memory where there is
    none (``absent``); a memory that cannot be read is said (``error``), never counted as empty."""
    storage_path = Path(path) if path else _DEFAULT_PATH
    days = checked_max_age(DEFAULT_MAX_AGE_DAYS if max_age_days is None else max_age_days)
    if not storage_path.is_dir():
        return {"max_age_days": days, "absent": True}
    try:
        return CycleMemory(path=storage_path, max_age_days=days).age_census()
    except Exception as exc:  # chromadb missing, a store it cannot open
        return {"max_age_days": days, "error": f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"}


def _signal_to_text(signal: dict) -> str:
    return (
        f"TTP: {signal.get('ttp')} | "
        f"severity: {signal.get('severity')} | "
        f"resource_type: {signal.get('resource_type')} | "
        f"event: {signal.get('event')} | "
        f"provider: {signal.get('provider')}"
    )


def _cycle_to_text(cycle: dict) -> str:
    return (
        f"TTP: {cycle.get('ttp')} | "
        f"severity: {cycle.get('severity')} | "
        f"resource_type: {cycle.get('resource_type')} | "
        f"event: {cycle.get('event')} | "
        f"action: {cycle.get('action')} | "
        f"reasoning: {cycle.get('reasoning', '')[:200]} | "
        f"outcome: {cycle.get('outcome')}"
    )
