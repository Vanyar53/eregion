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

    def retrieve_similar(self, signal: dict, n: int = 3) -> list[dict]:
        """Return the N past cycles most similar to this signal — real cycles only, for
        every signal (SEC4a, V-12), and of a bounded age (SEC17, V-12).

        A cycle stored more than ``max_age_days`` ago is no precedent: a year-old decision
        weighed as much as yesterday's. One stored before SEC17 carries no date: its age is
        unknown, never young — it is left out too. Nothing is erased: ``age_census`` counts
        what the age leaves out, and `glorfindel report` says it.

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
        results = self._collection.query(
            query_texts=[query_text],
            n_results=min(n * _DUPLICATE_SLACK, self._collection.count()),
            where={"$and": [{"source": "real"}, {"stored_at": {"$gte": self._cutoff()}}]},
        )
        cycles, seen = [], set()
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
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
        the bound, ``too_old`` (stored before it), ``undated`` (stored before SEC17). The two
        last are left out of the search, never erased."""
        cutoff = self._cutoff()
        got = self._collection.get(where={"source": "real"}, include=["metadatas"])
        within = too_old = undated = 0
        for meta in got.get("metadatas") or []:
            at = (meta or {}).get("stored_at")
            if isinstance(at, bool) or not isinstance(at, (int, float)):
                undated += 1
            elif at >= cutoff:
                within += 1
            else:
                too_old += 1
        return {"max_age_days": self.max_age_days, "real": within + too_old + undated,
                "within": within, "too_old": too_old, "undated": undated}


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
