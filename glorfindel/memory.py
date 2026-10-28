from __future__ import annotations

import json
import uuid
from pathlib import Path


_DEFAULT_PATH = Path.home() / ".glorfindel" / "cycles"


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

        It was `<signal_id>_<action>`, upserted: a signal id comes from the signal — a line
        could reuse a real cycle's, and its cycle replaced the real one. Drawn here, never
        reused: a cycle is added, never overwritten."""
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

    def retrieve_similar(self, signal: dict, n: int = 3, *, exercise: bool = False) -> list[dict]:
        """Return the N past cycles most similar to this signal.

        A real signal is given real cycles only (SEC4a, V-12): an exercise, a cycle of
        unknown source (recorded before B2, or unreadable labelling) is never a precedent
        for a real incident. `exercise`: the signal is one — every cycle, real ones too."""
        if self._collection.count() == 0:
            return []
        query_text = _signal_to_text(signal)
        results = self._collection.query(
            query_texts=[query_text],
            n_results=min(n, self._collection.count()),
            **({} if exercise else {"where": {"source": "real"}}),
        )
        cycles = []
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            cycles.append({"summary": doc, **meta})
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
