"""The client's layer of detection rules (P1): write, migrate, export.

The shipped base (`glorfindel/rules/azure/detection_rules.yaml`) is Glorfindel's: an
update replaces it. The rules of a deployment — approved after a miss, overriding a base
rule, disabling one — live in the client's layer, `~/.glorfindel/client_rules.yaml`
(`detection_rules.client_rules_path()`), outside the repository; `load_config` loads it
over the base (`detection_rules.merge_layers`). Here:

- `write_client_rule`: what an approval writes (`proposed_rules.approve`), never the base;
- `migrate`: rules approved INTO the base before P1 (a modified checkout, H0) → the layer;
- `export_rule`: one rule, generalised and without any identifier, to propose upstream.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import re
import tempfile
from pathlib import Path

import yaml

from glorfindel.detection_rules import _named, _read_layer, client_rules_path

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

def migrate(from_path: str | Path, base_path: str | Path, dest: Path | None = None,
            dry_run: bool = False) -> dict:
    """Move what a modified base holds beyond the pristine base into the client's layer.

    `from_path`: the base file as the deployment modified it (rules approved into it before
    P1, a hand edit); `base_path`: the same file as shipped (on H0, `git show HEAD:…` of the
    reference the checkout is on). A rule of `from` that the base does not have, or has
    differently, goes to the layer (a changed base rule becomes a client rule of the same
    name: it overrides); a base rule `from` no longer has goes to `disable`; same for assets
    and monitoring_backends (no disable). Nothing else changes; running it twice changes
    nothing more. Returns what it did, per name.
    """
    src, base = _read_layer_raw(Path(from_path)), _read_layer_raw(Path(base_path))
    report: dict = {"added": [], "replaced": [], "same": [], "overrides": [], "disable": [],
                    "assets": [], "monitoring_backends": [],
                    "dest": str(Path(dest) if dest else client_rules_path())}
    base_rules = {r["name"]: r for r in _named(base.get("rules"))}
    src_rules = {r["name"]: r for r in _named(src.get("rules"))}
    moved = [r for name, r in src_rules.items() if base_rules.get(name) != r]
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
    data = yaml.safe_load(path.read_text())
    return data if isinstance(data, dict) else {}


# ── Export: one rule, generalised, without any identifier ─────────────────────────

# What a generalised rule keeps. Everything else — assets, monitoring_backends,
# workspace_id, resource_id, any key we do not know — stays with the deployment: the
# exported rule has no assets, so it applies to every discovered VM (auto).
_EXPORTED_KEYS = ("name", "description", "source", "ttp", "interval_s", "expected_latency_s", "query")

# An Azure resource id, whatever it names (VM, workspace, vault, subscription…) — also one
# whose parts were replaced one by one (/subscriptions/<id>/resourceGroups/<name>/…): the
# guard refuses it rather than trust that every part was.
_RESOURCE_ID_RE = re.compile(r"/subscriptions/[^\s\"'`,;|()\[\]{}]+", re.IGNORECASE)
# A GUID: a workspace (customerId), a subscription, a tenant.
_GUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
# KQL columns whose literal value names a resource of the deployment.
_ID_COLUMNS = ("Computer", "_ResourceId", "ResourceId", "Resource", "ResourceGroup", "_ResourceGroup",
               "SubscriptionId", "_SubscriptionId", "TenantId", "WorkspaceId", "_WorkspaceId",
               "AccountName", "StorageAccountName", "VaultName", "HostName", "Hostname", "VMName",
               "VmName", "ResourceName", "HostIP")
_ID_COMPARISON_RE = re.compile(
    r"\b(?P<col>" + "|".join(_ID_COLUMNS) + r")\b(?P<op>\)?\s*(?:==|=~|!=|!~|"
    r"!?has(?:_cs)?|!?contains(?:_cs)?|!?startswith(?:_cs)?|!?endswith(?:_cs)?|!?in~?)\s*)"
    r"(?P<val>\"[^\"]*\"|'[^']*'|\([^)]*\))",
    re.IGNORECASE)
_LITERAL_RE = re.compile(r"\"[^\"]*\"|'[^']*'")
_PLACEHOLDER_RE = re.compile(r"^<[a-z_]+>$")
_MIN_NAME = 3   # shorter names would cut words of the query


class IdentifierLeft(ValueError):
    """The generalised rule still names something of the deployment: not exported.
    `found`: what is left (shown to the operator, never written anywhere)."""
    found: list[str] = []


def _real_literal(lit: str) -> bool:
    inner = lit[1:-1]
    return bool(inner) and not _PLACEHOLDER_RE.match(inner)


def _name_re(name: str) -> re.Pattern:
    # A hyphen or a dot is a boundary: "vm-a1-log-clearing" names vm-a1 (better a word too
    # many replaced than a name that leaves).
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", re.IGNORECASE)


def find_identifiers(text: str, known_names=()) -> list[str]:
    """Every identifier of a deployment still in `text`: a resource id, a GUID, a literal
    compared to an identifying column (Computer == "…"), a name the deployment knows."""
    found = _RESOURCE_ID_RE.findall(text) + _GUID_RE.findall(text)
    for m in _ID_COMPARISON_RE.finditer(text):
        found += [lit for lit in _LITERAL_RE.findall(m.group("val")) if _real_literal(lit)]
    for name in known_names:
        if len(name) >= _MIN_NAME and _name_re(name).search(text):
            found.append(name)
    return found


def _scrub(text: str, known_names, counts: dict) -> str:
    def sub(pattern, placeholder, key, s):
        out, n = pattern.subn(placeholder, s)
        counts[key] = counts.get(key, 0) + n
        return out

    text = sub(_RESOURCE_ID_RE, "<resource_id>", "identifiant de ressource", text)
    text = sub(_GUID_RE, "<id>", "GUID (espace de travail, abonnement…)", text)

    def literals(m):
        val = m.group("val")
        new = _LITERAL_RE.sub(lambda lm: '"<name>"' if _real_literal(lm.group(0)) else lm.group(0), val)
        if new != val:
            counts["valeur d'une colonne d'identité"] = counts.get("valeur d'une colonne d'identité", 0) + 1
        return m.group("col") + m.group("op") + new

    text = _ID_COMPARISON_RE.sub(literals, text)
    for name in sorted(known_names, key=len, reverse=True):
        if len(name) >= _MIN_NAME:
            text = sub(_name_re(name), "<name>", "nom connu du déploiement", text)
    return text


def known_names(raw_layers: list[dict], glorfindel_cfg=None, extra=()) -> set[str]:
    """The names this deployment gives its resources: assets, backends, inline ids of the
    rules, glorfindel-config's backends, the discovered VMs, the proposals' targets."""
    names: set[str] = set(extra)

    def add_id(rid: str) -> None:
        if not rid:
            return
        names.add(rid)
        parts = [p for p in str(rid).split("/") if p]
        for i, part in enumerate(parts):
            if part.lower() in ("resourcegroups", "virtualmachines", "workspaces", "vaults",
                                "storageaccounts", "networkinterfaces", "networksecuritygroups"):
                if i + 1 < len(parts):
                    names.add(parts[i + 1])
        if parts and not str(rid).startswith("/"):
            names.add(str(rid))

    for data in raw_layers:
        for a in _named(data.get("assets")):
            if a["name"] != "auto":
                names.add(a["name"])
            for k in ("resource_id", "vault_name", "resource_group"):
                if a.get(k):
                    add_id(a[k])
        for b in _named(data.get("monitoring_backends")):
            names.add(b["name"])
            for k in ("workspace_id", "endpoint"):
                if b.get(k):
                    names.add(str(b[k]))
        for r in _named(data.get("rules")):
            for k in ("workspace_id", "resource_id"):
                if r.get(k):
                    add_id(r[k])
            for k in ("assets", "monitoring_backends"):
                for n in r.get(k) or []:
                    if n != "auto":
                        names.add(str(n))
    if glorfindel_cfg is not None:
        for b in getattr(glorfindel_cfg, "monitoring_backends", []) or []:
            for k in ("name", "workspace_id", "endpoint"):
                if getattr(b, k, ""):
                    names.add(str(getattr(b, k)))
    try:
        from glorfindel.discovery import AssetRegistry
        for a in AssetRegistry().all():
            names.add(a.name)
            add_id(a.resource_id)
    except Exception:
        pass
    try:
        from glorfindel.proposed_rules import all_proposals
        for p in all_proposals():
            add_id(p.get("resource_id", ""))
            if p.get("workspace_id"):
                names.add(p["workspace_id"])
    except Exception:
        pass
    return {n for n in names if n and "${" not in n}


def generalize(rule: dict, names=()) -> tuple[dict, dict]:
    """The rule without anything of the deployment → (rule, what was replaced, counted)."""
    counts: dict = {}
    out = {}
    for key in _EXPORTED_KEYS:
        if key in rule and rule[key] not in (None, ""):
            value = rule[key]
            out[key] = _scrub(value, names, counts) if isinstance(value, str) else value
    out["enabled"] = True
    return out, {k: v for k, v in counts.items() if v}


def export_rule(name: str, base_path: str | Path, client_path: Path | None = None,
                glorfindel_cfg=None, extra_names=()) -> str:
    """One rule (the client's layer first, then the base), generalised, as YAML ready to
    propose upstream. Raises KeyError (no such rule) or IdentifierLeft (something of the
    deployment would leave: nothing is exported)."""
    base = _read_layer(Path(base_path))
    client = _read_layer(Path(client_path) if client_path else client_rules_path())
    rule = next((r for r in reversed(_named(client.get("rules"))) if r["name"] == name), None) \
        or next((r for r in _named(base.get("rules")) if r["name"] == name), None)
    if rule is None:
        raise KeyError(name)
    names = known_names([base, client], glorfindel_cfg=glorfindel_cfg, extra=extra_names)
    general, counts = generalize(rule, names)
    replaced = ", ".join(f"{what} ×{n}" for what, n in counts.items()) or "rien"
    text = ("# Règle exportée par `glorfindel export-rule` (P1) : généralisée, sans identifiant\n"
            "# de ressource ni d'espace de travail ; sans `assets`, elle s'applique à toute VM\n"
            f"# découverte. Remplacé : {replaced}.\n"
            "rules:\n" + _indent(_dump([general])))
    left = find_identifiers(text, names)
    if left:
        err = IdentifierLeft(f"« {name} » garde {len(left)} identifiant(s) du déploiement : rien n'est exporté")
        err.found = sorted(set(left))
        raise err
    return text


def _indent(text: str) -> str:
    return "".join(f"  {line}\n" if line else "\n" for line in text.splitlines())
