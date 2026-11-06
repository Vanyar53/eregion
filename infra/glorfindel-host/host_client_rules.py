"""Rules of the repository merged into the client's layer of the hosted Glorfindel (H0) (WL1, #595).

    python infra/glorfindel-host/host_client_rules.py RULES.yaml H0_LAYER.yaml OUT.yaml

``make glorfindel-host-client-rules`` reads H0's layer (``~/.glorfindel/client_rules.yaml``) through
ssh into ``H0_LAYER.yaml`` (empty when H0 has none), runs this, then sends ``OUT.yaml`` back, put in
place on H0 only if the layer did not change in between (under the lock the watch and the console
take to write it).

- **Merged, never copied over**: each rule of ``RULES.yaml`` is added to H0's layer, or replaces the
  rule of its name there (``rule_layers``'s upsert, as an approval writes); every other rule, the
  ``disable`` list, the assets and backends of H0's layer stay as they are. A rule approved on H0
  is never lost by a push.
- **Said**: each rule, added, replaced or unchanged; what the layer does to the base once merged
  (the notes the watch will print at its start).
- **Refused, nothing written** (exit 1): H0's layer unreadable (``rule_layers.read_client_layer``:
  a layer we cannot read is never written over); ``RULES.yaml`` unreadable, with a key other than
  ``rules``, or a rule without a name; a rule of ``RULES.yaml`` the watch would skip (invalid), or a
  copy of a base rule whose shipped rule changed since, or is gone (``base_sha256``: drift; the
  watch would set the copy aside and run the shipped rule) — read against the base of this
  checkout, the one the watch of the same release ships.
- **Not refused**: a name H0's layer lists under ``disable``. Only the base rule of that name is
  not loaded; the pushed rule, a client rule, loads in its place (``merge_layers``), and the
  watch's note says the base rule is disabled — measured by
  ``test_a_disable_of_the_same_name_on_h0_does_not_stop_the_pushed_rule``.

Runs on the operator's machine, from the checkout: the glorfindel of this checkout is imported,
whatever is installed in the environment.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import yaml  # noqa: E402

from glorfindel import rule_layers  # noqa: E402
from glorfindel.detection_rules import load_config, shipped_rules_path  # noqa: E402


def _rules_to_push(path: Path) -> list[dict]:
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise rule_layers.ClientLayerError(f"{path} illisible : {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"rules"} or not isinstance(data.get("rules"), list):
        raise rule_layers.ClientLayerError(f"{path} : un dictionnaire avec `rules:` (une liste) seulement")
    rules = data["rules"]
    if not rules or not all(isinstance(r, dict) and isinstance(r.get("name"), str) and r["name"].strip()
                            for r in rules):
        raise rule_layers.ClientLayerError(f"{path} : chaque règle a un nom (et il en faut une)")
    return rules


def merge(rules_path: Path, h0_layer: Path, out: Path, base: Path | None = None) -> list[str]:
    """H0's layer with the rules of `rules_path` merged in, written to `out` → the lines said.
    Raises ClientLayerError (nothing written to `out`) when it must not be sent."""
    rules = _rules_to_push(rules_path)
    data = rule_layers.read_client_layer(h0_layer)
    items = list(data.get("rules") or [])
    said = []
    for rule in rules:
        how = rule_layers._upsert(items, rule)
        said.append({"added": "ajoutée", "replaced": "remplacée", "same": "inchangée"}[how]
                    + f" : « {rule['name']} »")
    data["rules"] = items
    # Read back as the watch will, before anything is written: the merged layer over the base.
    staged = out.with_name(f".{out.name}.check")
    rule_layers._write(staged, data)
    try:
        cfg = load_config(base or shipped_rules_path(), client_layer=staged)
    finally:
        staged.unlink(missing_ok=True)
    loaded = {r.name for r in cfg.rules if r.layer == "client"}
    names = [r["name"] for r in rules]
    wrong = []
    for n in names:
        if n in cfg.drifted:            # set aside by the watch (or its base gone): never pushed
            wrong.append(f"« {n} » est une copie périmée de la base (dérive, voir la note)")
        elif n not in loaded and any(r.get("name") == n and r.get("enabled", True) for r in rules):
            wrong.append(f"« {n} » serait ignorée par la watch (voir la note)")
    if wrong:
        raise rule_layers.ClientLayerError("rien d'envoyé : " + " ; ".join(wrong)
                                           + "".join(f"\n  · {note}" for note in cfg.notes))
    rule_layers._write(out, data)
    return said + [f"  · {note}" for note in cfg.notes]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    # Its notes are said below, once; the loader's log (no backend here, on the poste) is noise.
    logging.getLogger("glorfindel").setLevel(logging.ERROR)
    try:
        for line in merge(Path(argv[0]), Path(argv[1]), Path(argv[2])):
            print(f"  {line}")
    except rule_layers.ClientLayerError as exc:
        print(f"  ✗ {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
