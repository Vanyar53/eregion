"""CI8 (#566): ChromaDB's embedding model, fetched before the tests that use it.

    python scripts/chroma_model.py          # the CI: bash scripts/retry.sh python scripts/chroma_model.py

A step of its own, before the tests, the mutation or the invariants, so that its download alone is
retried (scripts/retry.sh) — never the tests. ChromaDB's default embedding function, called on a
word, fetches the model (about 80 MB, into ~/.cache/chroma) only when one of its files is missing,
checks the archive's SHA-256, and loads it as a test would (CI6b, scripts/mutation_check.py,
prepare_embedding_model). The cache restored, nothing leaves the runner.

Exits 0 when the model is ready, or when ChromaDB is not installed (nothing to fetch); otherwise
the error, and a non-zero exit, which retry.sh tries again.
"""
from __future__ import annotations

import importlib
import sys

EMBEDDING = "chromadb.utils.embedding_functions"


def main() -> int:
    try:
        functions = importlib.import_module(EMBEDDING)
    except ImportError:
        print("ChromaDB is not installed: no model to fetch")
        return 0
    functions.DefaultEmbeddingFunction()(["eregion"])
    print("ChromaDB's embedding model: ready in ~/.cache/chroma (CI8)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
