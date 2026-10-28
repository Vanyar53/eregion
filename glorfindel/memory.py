from __future__ import annotations

import json
import uuid
from pathlib import Path


_DEFAULT_PATH = Path.home() / ".glorfindel" / "cycles"
# How many more cycles the retrieval reads than it returns, so that the copies of a
# replayed cycle, dropped, still leave N distinct ones.
_DUPLICATE_SLACK = 4


class CycleMemory:
    """Persistent vector store for Glorfindel decision cycles.

    Each cycle is (signal → reasoning → action → outcome).
    At decision time, retrieve the N most similar past cycles as context.
    No model weights change — the LLM learns from context, not fine-tuning.
    """

    def __init__(self, path: str | Path | None = None):
        import chromadb

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
            }],
        )

    def retrieve_similar(self, signal: dict, n: int = 3) -> list[dict]:
        """Return the N past cycles most similar to this signal — real cycles only, for
        every signal (SEC4a, V-12).

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
            where={"source": "real"},
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
