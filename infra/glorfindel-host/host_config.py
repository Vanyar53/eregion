"""The Glorfindel config pushed to the hosted VM (H0): the local one, the default forced to
human_only, and each VM's mode kept as it is on H0 (BL1c, Jonathan's decision of 02/11).

    python infra/glorfindel-host/host_config.py glorfindel-config.yaml OUT.yaml [--h0 H0.yaml] [--human-only]

``make glorfindel-host-push`` reads H0's config through the ssh connection it already opens
(``--h0``), and says, VM by VM, the mode sent and where it comes from.

- **The default** is always ``human_only``, and ``allow_destructive`` always empty: the local
  config's ``non_disruptive`` (default or per asset) and its destructive list never reach H0.
- **Each VM's mode on H0** (an exact name, as the console writes it from its Glorfindel page) is
  kept: before, every push put every VM back in ``human_only`` (SEC7) — and the posture of H0
  on the bench (gondolin and bree in ``non_disruptive``, docs/design/modele-de-menace.md §5) had
  to be given again in the console after each push.
- **The safe side (A0)**: never a mode bolder than the one in place.
  - H0's config unread (absent, not YAML, of another shape), or one Glorfindel's strict reading
    would refuse at the watch's start (a default outside ``KNOWN_MODES``, a key more in
    ``autonomy`` or in an entry): every VM in ``human_only``, as before, and said.
  - An entry the watch would refuse — not a table, a key more, a ``match`` that is not text or
    is blank, a mode this code does not know (``KNOWN_MODES``: ``full_auto`` is deferred) —
    makes the whole config unknown: every VM in ``human_only``, said. A pattern (``vm-*``),
    which the watch reads: not kept, that VM said ``human_only``.
  - The same name twice on H0: the first entry, the one H0 resolves (``AutonomyConfig.resolve``).
  - A VM of the local config H0 does not know: ``human_only``, as before.
- **HUMAN_ONLY=1** (``--human-only``; only « 1 »): every VM back to ``human_only`` in one
  gesture — the emergency way back to an H0 that does nothing on its own.
- What H0's config says reaches the operator's terminal printable only (``printable``).

Backends and exceptions stay as they are. No Glorfindel import: this runs on the operator's
machine, beside the Makefile.
"""
from __future__ import annotations

import sys

import yaml

# glorfindel/config.py VALID_AUTONOMY_MODES (full_auto is deferred: refused there, not kept
# here) — tests/unit/test_glorfindel_host.py holds the two equal.
KNOWN_MODES = ("human_only", "non_disruptive")
# glorfindel/config.py _AUTONOMY_KEYS, _AUTONOMY_ASSET_KEYS — held equal by the same test.
AUTONOMY_KEYS = ("default", "assets", "allow_destructive")
ASSET_KEYS = ("match", "mode")
KEPT = "gardé de H0"
HUMAN = "human_only"
_PATTERN = set("*?[]")


def read_h0(text: str | None) -> tuple[dict | None, str]:
    """H0's config, as the push read it: ``(config, "")``, or ``(None, why)`` when it cannot be
    trusted — then nothing of it is kept."""
    if text is None or not text.strip():
        return None, "absente, vide ou non lue"
    try:
        cfg = yaml.safe_load(text)
    except yaml.YAMLError:
        return None, "illisible (YAML)"
    if not isinstance(cfg, dict):
        return None, "forme inconnue"
    why = refusal(cfg)
    return (None, why) if why else (cfg, "")


def refusal(cfg: dict) -> str:
    """Why H0's config keeps no mode — "" when its modes can be kept. What Glorfindel's strict
    reading refuses at the watch's start (glorfindel/config.py ``_check_autonomy``) is refused
    whole: a config the watch would not run is no config whose modes are kept — never one VM
    dropped and the others kept (a watch that would not run made one that acts)."""
    autonomy = cfg.get("autonomy")
    if autonomy is None:
        return ""
    if not isinstance(autonomy, dict) or not isinstance(autonomy.get("assets") or [], list):
        return "forme inconnue (autonomy)"
    if set(autonomy) - set(AUTONOMY_KEYS):
        return "forme inconnue (autonomy : une clé de plus)"
    if "default" in autonomy and autonomy["default"] not in KNOWN_MODES:
        return "forme inconnue (autonomy.default hors des modes connus)"
    for a in autonomy.get("assets") or []:
        if not isinstance(a, dict):
            return "forme inconnue (une entrée d'autonomy.assets n'est pas une table match, mode)"
        if set(a) - set(ASSET_KEYS):
            return "forme inconnue (une entrée d'autonomy.assets a d'autres clés que match et mode)"
        if not isinstance(a.get("match"), str) or not a["match"].strip():
            return "forme inconnue (une entrée d'autonomy.assets sans match)"
        if a.get("mode") not in KNOWN_MODES:
            return "forme inconnue (une entrée d'autonomy.assets hors des modes connus)"
    return ""


def _assets(cfg) -> list:
    autonomy = (cfg or {}).get("autonomy") if isinstance(cfg, dict) else None
    assets = autonomy.get("assets") if isinstance(autonomy, dict) else None
    return assets if isinstance(assets, list) else []


def host_config(cfg: dict, h0: dict | None = None, *, h0_why: str = "",
                human_only: bool = False) -> tuple[dict, list[tuple[str, str, str]]]:
    """``(config to push, report)`` — the report: ``(VM, mode sent, where it comes from)``, and
    ``("*", "human_only", why)`` for what concerns every VM. ``h0`` is checked by ``refusal``
    here too: a caller that did not go through ``read_h0`` gets the same rule."""
    if h0 is not None and (why := refusal(h0)):
        h0, h0_why = None, why
    out = dict(cfg or {})
    kept: list[dict] = []
    report: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    if human_only:
        report.append(("*", HUMAN, "HUMAN_ONLY=1 : toutes les VM remises en human_only"))
    elif h0 is None:
        report.append(("*", HUMAN, f"config de H0 {h0_why or 'non lue'} : toutes les VM en human_only"))
    for rule in _assets(h0):            # each a table {match: text, mode: known} (refusal)
        name, mode = rule["match"], rule["mode"]
        if name in seen:            # H0 resolves the first exact entry: the later ones never applied
            continue
        seen.add(name)
        if human_only:
            report.append((name, HUMAN, "HUMAN_ONLY=1"))
        elif _PATTERN & set(name):
            report.append((name, HUMAN, "motif sur H0, non reporté : human_only"))
        else:
            kept.append({"match": name, "mode": mode})
            report.append((name, mode, KEPT))
    for rule in _assets(cfg):
        name = rule.get("match") if isinstance(rule, dict) else None
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            report.append((name, HUMAN, "inconnue de H0 : human_only"))
    out["autonomy"] = {"default": HUMAN, "assets": kept}
    return out, report


def printable(text) -> str:
    """What H0's config says, shown in the operator's terminal: printable characters only — a
    name read on H0 never carries an escape sequence to it."""
    return "".join(c if c.isprintable() else "?" for c in str(text))


def render(report) -> list[str]:
    report = [(printable(vm), printable(mode), printable(why)) for vm, mode, why in report]
    width = max([len(vm) for vm, *_ in report] + [10])
    return [f"  {vm:<{width}}  {mode:<15} {why}" for vm, mode, why in report] or [
        "  aucune VM avec un mode à elle : toutes en human_only (le défaut)"]


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="host_config.py")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--h0", default=None, help="la config en place sur H0, lue par le push")
    ap.add_argument("--human-only", action="store_true", help="toutes les VM en human_only (HUMAN_ONLY=1)")
    args = ap.parse_args(argv)
    with open(args.src, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    text = None
    if args.h0:
        try:
            with open(args.h0, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            text = None
    h0, why = read_h0(text)
    out, report = host_config(cfg, h0, h0_why=why, human_only=args.human_only)
    with open(args.dst, "w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, sort_keys=False)
    print("  Modes envoyés à H0 (le défaut : human_only) :")
    print("\n".join(render(report)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
