"""Validate experiments and the technique catalog against their versioned schemas (E1).

One schema (``schemas/experiment.schema.json``) describes a technique and a fault with
the same shape: ``kind`` absent means ``technique``, ``engine`` absent means
``local-script``, so the existing Annatar scenarios validate unchanged. The catalog
(``schemas/technique_catalog.schema.json``) now holds faults too, in their own ``faults``
list: a fault has no ATT&CK id, and the technique loaders of Annatar and Glorfindel read
``techniques`` only. A technique on another engine than local-script (Stratus, Atomic) is run
by its ``engine_ref`` and needs no steps.

Validation is a dev/CI concern (``tests/unit/test_experiment_schema.py`` — "the CI
validates the catalog"), so ``jsonschema`` is imported lazily and the injectors do not
depend on it at run time.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
EXPERIMENT_SCHEMA = SCHEMA_DIR / "experiment.schema.json"
CATALOG_SCHEMA = SCHEMA_DIR / "technique_catalog.schema.json"
CATALOG = SCHEMA_DIR.parent / "technique_catalog.yaml"


@lru_cache(maxsize=None)
def _schema(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _errors(instance: Any, schema_path: Path) -> list[str]:
    from jsonschema import Draft7Validator

    validator = Draft7Validator(_schema(str(schema_path)))
    out = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in err.path) or "(root)"
        out.append(f"{where}: {err.message}")
    return out


def validate_experiment(doc: dict) -> list[str]:
    """Schema errors for one experiment (a loaded scenario or fault YAML); [] if valid."""
    return _errors(doc, EXPERIMENT_SCHEMA)


def validate_experiment_file(path: str | Path) -> list[str]:
    try:
        doc = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as e:
        return [f"could not read {path}: {e}"]
    return validate_experiment(doc)


def validate_catalog(path: str | Path = CATALOG) -> list[str]:
    """Schema errors for the technique/fault catalog; [] if valid."""
    try:
        doc = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as e:
        return [f"could not read {path}: {e}"]
    return _errors(doc, CATALOG_SCHEMA)
