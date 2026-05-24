from __future__ import annotations

import json
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
        """Persist a completed cycle."""
        cycle_id = f"{cycle['signal_id']}_{cycle['action']}"
        document = _cycle_to_text(cycle)
        self._collection.upsert(
            ids=[cycle_id],
            documents=[document],
            metadatas=[{
                "ttp": cycle.get("ttp", ""),
                "action": cycle.get("action", ""),
                "outcome": str(cycle.get("outcome", "")),
                "signal_id": cycle.get("signal_id", ""),
                "run_id": cycle.get("run_id", ""),
                "event": cycle.get("event", ""),
                "detection_s": cycle.get("detection_s", 0),
                "action_s": cycle.get("action_s", 0),
                "confidence": float(cycle.get("confidence", 0.0)),
                "past_cycles_used": json.dumps(cycle.get("past_cycles_used", [])),
            }],
        )

    def retrieve_similar(self, signal: dict, n: int = 3) -> list[dict]:
        """Return the N past cycles most similar to this signal."""
        if self._collection.count() == 0:
            return []
        query_text = _signal_to_text(signal)
        results = self._collection.query(
            query_texts=[query_text],
            n_results=min(n, self._collection.count()),
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
