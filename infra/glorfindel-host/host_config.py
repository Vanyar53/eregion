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
  - H0's config unread (absent, not YAML, of another shape): every VM in ``human_only``, as
    before, and said.
  - A mode on H0 this code does not know (``KNOWN_MODES``): that VM goes to ``human_only``,
    said. A pattern (``vm-*``) or an entry of another shape: not kept, said.
  - The same name twice on H0: the first entry, the one H0 resolves (``AutonomyConfig.resolve``).
  - A VM of the local config H0 does not know: ``human_only``, as before.
- **HUMAN_ONLY=1** (``--human-only``): every VM back to ``human_only`` in one gesture — the
  emergency way back to an H0 that does nothing on its own.

Backends and exceptions stay as they are. No Glorfindel import: this runs on the operator's
machine, beside the Makefile.
"""
from __future__ import annotations

import sys

import yaml

# glorfindel/config.py VALID_AUTONOMY_MODES (full_auto is deferred: refused there, not kept
# here) — tests/unit/test_glorfindel_host.py holds the two equal.
KNOWN_MODES = ("human_only", "non_disruptive")
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
    autonomy = cfg.get("autonomy")
    if autonomy is None:
        return cfg, ""
    if not isinstance(autonomy, dict) or not isinstance(autonomy.get("assets") or [], list):
        return None, "forme inconnue (autonomy)"
    return cfg, ""


def _assets(cfg) -> list:
    autonomy = (cfg or {}).get("autonomy") if isinstance(cfg, dict) else None
    assets = autonomy.get("assets") if isinstance(autonomy, dict) else None
    return assets if isinstance(assets, list) else []


def host_config(cfg: dict, h0: dict | None = None, *, h0_why: str = "",
                human_only: bool = False) -> tuple[dict, list[tuple[str, str, str]]]:
    """``(config to push, report)`` — the report: ``(VM, mode sent, where it comes from)``, and
    ``("*", "human_only", why)`` for what concerns every VM."""
    out = dict(cfg or {})
    kept: list[dict] = []
    report: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    if human_only:
        report.append(("*", HUMAN, "HUMAN_ONLY=1 : toutes les VM remises en human_only"))
    elif h0 is None:
        report.append(("*", HUMAN, f"config de H0 {h0_why or 'non lue'} : toutes les VM en human_only"))
    for rule in _assets(h0):
        if not isinstance(rule, dict) or not isinstance(rule.get("match"), str) or not rule["match"]:
            report.append(("?", HUMAN, f"entrée de H0 d'une autre forme, non reportée : {str(rule)[:60]}"))
            continue
        name, mode = rule["match"], rule.get("mode")
        if name in seen:            # H0 resolves the first exact entry: the later ones never applied
            continue
        seen.add(name)
        if human_only:
            report.append((name, HUMAN, "HUMAN_ONLY=1"))
        elif _PATTERN & set(name):
            report.append((name, HUMAN, "motif sur H0, non reporté : human_only"))
        elif mode not in KNOWN_MODES:
            report.append((name, HUMAN, f"mode inconnu sur H0 ({str(mode)[:30]!r}) : human_only"))
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


def render(report) -> list[str]:
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
