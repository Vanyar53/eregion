"""The client's layer of detection rules (P1): write, migrate.

The shipped base (`glorfindel/rules/azure/detection_rules.yaml`) is Glorfindel's: an
update replaces it. The rules of a deployment — approved after a miss, overriding a base
rule, disabling one — live in the client's layer, `~/.glorfindel/client_rules.yaml`
(`detection_rules.client_rules_path()`), outside the repository; `load_config` loads it
over the base (`detection_rules.merge_layers`). Here:

- `write_client_rule`: what an approval writes (`proposed_rules.approve`), never the base;
- `migrate`: rules approved INTO the base before P1 (a modified checkout, H0) → the layer.

Exporting a rule generalised, without any identifier, to propose it upstream is left to a
lot of P2 (a deterministic leak check, then a human review before anything is sent).
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import tempfile
from pathlib import Path

import yaml

from glorfindel.detection_rules import _named, client_rules_path

_HEADER = """\
# Couche du client de Glorfindel (P1) — les règles de CE déploiement.
# Chargée par-dessus la base livrée (glorfindel/rules/azure/detection_rules.yaml), que
# rien n'écrit plus : une mise à jour de Glorfindel remplace la base, jamais ce fichier.
#   rules:    règles du client ; une règle du nom d'une règle de base la remplace (dit au
#             chargement) ; `enabled: false` sous ce nom la désactive
#   disable:  noms de règles de base à ne pas charger
#   assets, monitoring_backends : comme dans la base, l'entrée du client gagne par nom
# Écrite par `glorfindel approve-rule`, la War Room et `glorfindel migrate-rules` ; éditable
# à la main (un commentaire ne survit pas à la prochaine écriture : mettre une description).
"""


class ClientLayerError(ValueError):
    """The client's layer cannot be read: nothing is written over it."""


class _Dumper(yaml.SafeDumper):
    pass


def _str_representer(dumper, value: str):
    # A query keeps its lines (block scalar), as in the base.
    return dumper.represent_scalar("tag:yaml.org,2002:str", value,
                                   style="|" if "\n" in value else None)


_Dumper.add_representer(str, _str_representer)


def _dump(data: dict) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True,
                     default_flow_style=False, width=1000)


def read_client_layer(path: Path | None = None) -> dict:
    """The layer as written (no ${VAR} expansion), {} when absent. Unreadable → raises:
    writing over a file we cannot read would lose the client's rules."""
    path = Path(path) if path else client_rules_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ClientLayerError(f"couche du client illisible ({path}) : {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ClientLayerError(f"couche du client illisible ({path}) : pas un dictionnaire YAML")
    for key in ("rules", "disable", "assets", "monitoring_backends"):
        if data.get(key) is not None and not isinstance(data[key], list):
            raise ClientLayerError(f"couche du client illisible ({path}) : `{key}` n'est pas une liste")
    return data


@contextlib.contextmanager
def _locked(path: Path):
    """The War Room and the CLI can approve at the same time: one writer at a time."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.parent / f".{path.name}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _write(path: Path, data: dict) -> None:
    """Atomic (tmp + rename): a reader never sees half a layer."""
    ordered = {k: data[k] for k in ("rules", "disable", "assets", "monitoring_backends") if data.get(k)}
    ordered.update({k: v for k, v in data.items() if k not in ordered and v})
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(_HEADER + "\n" + (_dump(ordered) if ordered else "rules: []\n"))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _upsert(items: list, entry: dict) -> str:
    """Replace the entry of the same name, or append it → 'added' | 'replaced' | 'same'."""
    for i, old in enumerate(items):
        if isinstance(old, dict) and old.get("name") == entry["name"]:
            if old == entry:
                return "same"
            items[i] = entry
            return "replaced"
    items.append(entry)
    return "added"


def write_client_rule(rule: dict, path: Path | None = None) -> str:
    """Add (or replace, by name) one rule in the client's layer → 'added' | 'replaced' | 'same'."""
    path = Path(path) if path else client_rules_path()
    with _locked(path):
        data = read_client_layer(path)
        rules = list(data.get("rules") or [])
        how = _upsert(rules, rule)
        data["rules"] = rules
        _write(path, data)
    return how


# ── Migration: rules approved into the base before P1 ─────────────────────────────

def backend_for_workspace(workspace_id: str, backends) -> str:
    """The name of the one monitoring backend (objects or dicts) that watches this workspace,
    "" if none or several do."""
    ws = os.path.expandvars(str(workspace_id or "")).strip().lower()
    if not ws or "${" in ws:
        return ""
    names = {(b.get("name") if isinstance(b, dict) else getattr(b, "name", "")) for b in backends or []
             if str((b.get("workspace_id") if isinstance(b, dict) else getattr(b, "workspace_id", "")) or "")
             .strip().lower() == ws}
    names.discard("")
    names.discard(None)
    return names.pop() if len(names) == 1 else ""


def _legacy(rule: dict) -> bool:
    """A rule in the inline form an approval wrote before P1: workspace in line, no assets —
    loaded as auto-apply on no backend, it applies to no discovered VM."""
    return bool(rule.get("workspace_id")) and not rule.get("assets")


def _bound(rule: dict, backend: str) -> dict:
    """The legacy rule bound to its backend: every discovered VM it watches (assets: [auto])."""
    out = {k: v for k, v in rule.items() if k not in ("workspace_id", "resource_id", "source", "monitoring_backend")}
    out["monitoring_backends"] = [backend]
    out["assets"] = ["auto"]
    return out


def migrate(from_path: str | Path, base_path: str | Path, dest: Path | None = None,
            dry_run: bool = False, glorfindel_cfg=None, config_error: str = "") -> dict:
    """Move what a modified base holds beyond the pristine base into the client's layer.

    `from_path`: the base file as the deployment modified it (rules approved into it before
    P1, a hand edit); `base_path`: the same file as shipped (on H0, `git show HEAD:…` of the
    reference the checkout is on). A rule of `from` that the base does not have, or has
    differently, goes to the layer (a changed base rule becomes a client rule of the same
    name: it overrides); a base rule `from` no longer has goes to `disable`; same for assets
    and monitoring_backends (no disable). Nothing else changes; running it twice changes
    nothing more. Returns what it did, per name.

    A moved rule in the inline form approvals wrote before P1 (workspace in line, no
    assets: it applied to no VM) is bound to the backend that watches its workspace
    (glorfindel-config.yaml's, or the files'): `assets: [auto]` — it detects from now on
    ("converted"). When no single backend watches it, it moves as it is and that is said
    ("legacy", with why).
    """
    src, base = _read_layer_raw(Path(from_path)), _read_layer_raw(Path(base_path))
    report: dict = {"added": [], "replaced": [], "same": [], "overrides": [], "disable": [],
                    "assets": [], "monitoring_backends": [], "converted": [], "legacy": [],
                    "dest": str(Path(dest) if dest else client_rules_path())}
    base_rules = {r["name"]: r for r in _named(base.get("rules"))}
    src_rules = {r["name"]: r for r in _named(src.get("rules"))}
    moved = [r for name, r in src_rules.items() if base_rules.get(name) != r]
    backends = list(getattr(glorfindel_cfg, "monitoring_backends", None) or []) \
        + _named(src.get("monitoring_backends")) + _named(base.get("monitoring_backends"))
    for i, r in enumerate(moved):
        if _legacy(r):
            backend = backend_for_workspace(r["workspace_id"], backends)
            if backend:
                moved[i] = _bound(r, backend)
                report["converted"].append(f"{r['name']} → monitoring_backends: [{backend}], assets: [auto]")
            else:
                why = (f"glorfindel-config.yaml illisible ({config_error})" if config_error else
                       "aucun backend unique ne surveille son workspace (glorfindel-config.yaml, "
                       "monitoring_backends)")
                report["legacy"].append(f"{r['name']} : {why} — migrée telle quelle, "
                                        "elle ne s'applique à aucune VM découverte")
    report["overrides"] = [r["name"] for r in moved if r["name"] in base_rules]
    disable = [name for name in base_rules if name not in src_rules]
    extra = {}
    for key in ("assets", "monitoring_backends"):
        known = {e["name"]: e for e in _named(base.get(key))}
        extra[key] = [e for e in _named(src.get(key)) if known.get(e["name"]) != e]
        report[key] = [e["name"] for e in extra[key]]

    path = Path(report["dest"])
    with _locked(path):
        data = read_client_layer(path)
        rules = list(data.get("rules") or [])
        for r in moved:
            report[_upsert(rules, r)].append(r["name"])
        data["rules"] = rules
        disabled = list(data.get("disable") or [])
        for name in disable:
            if name not in disabled:
                disabled.append(name)
                report["disable"].append(name)
        data["disable"] = disabled
        for key, entries in extra.items():
            items = list(data.get(key) or [])
            for e in entries:
                _upsert(items, e)
            data[key] = items
        if not dry_run:
            _write(path, data)
    return report


def _read_layer_raw(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ClientLayerError(f"{path} : YAML illisible — {exc}") from exc
    if data is not None and not isinstance(data, dict):
        raise ClientLayerError(f"{path} : pas un fichier de règles (un dictionnaire YAML)")
    return data or {}
