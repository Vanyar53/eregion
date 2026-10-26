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
# The segments of an ARM path, anywhere in the text — in a literal compared to any column, in a
# message: `resourceGroups/<x>`, `subscriptions/<x>`, `virtualMachines/<x>`…, and every name of
# a `providers/Microsoft.<A>/<type>/<x>[/<type>/<x>…]` path.
_ARM_SEGMENT_RE = re.compile(
    r"\b(?P<kind>subscriptions|resourceGroups|virtualMachines|virtualMachineScaleSets|"
    r"networkInterfaces|networkSecurityGroups|storageAccounts|vaults|workspaces|disks|"
    r"publicIPAddresses|virtualNetworks|subnets|managedClusters)/(?P<val>[^/\s\"'`,;|()\[\]{}\\]+)", re.IGNORECASE)
_PROVIDERS_RE = re.compile(
    r"\bproviders/(?P<ns>microsoft\.[a-z0-9]+)(?P<path>(?:/[a-z0-9]+/[^/\s\"'`,;|()\[\]{}\\]+)+)",
    re.IGNORECASE)

# KQL columns whose value names a resource or an identity of the deployment. A literal
# DIRECTLY compared to one of them (either side, any operator, the column bare or in one
# function call: `tolower(Computer)`) is replaced; anything that reaches such a column through
# an intermediate — a `let`, an alias, a function defined in the query, an expression — makes
# the export refuse: generalise that rule by hand (P1, second review: following KQL by regex
# does not converge, so what is not sure is refused, never guessed).
_ID_COLUMNS = ("Computer", "ComputerName", "_ResourceId", "ResourceId", "ResourceUri", "Resource",
               "ResourceGroup", "ResourceGroupName", "_ResourceGroup", "ResourceName",
               "SubscriptionId", "_SubscriptionId", "TenantId", "_TenantId", "AADTenantId",
               "WorkspaceId", "_WorkspaceId", "AccountName", "StorageAccountName", "VaultName",
               "HostName", "Hostname", "Host", "DeviceName", "VMName", "VmName", "HostIP",
               "Caller", "UserPrincipalName", "Identity")
_ID_COL_RE = re.compile(r"(?<![\w.])(?:" + "|".join(_ID_COLUMNS) + r")(?!\w)", re.IGNORECASE)
# A KQL string literal: "…", '…', verbatim @"…", obfuscated h"…" / h@"…" / H'…', and the
# multi-line ```…``` / ~~~…~~~ — a prefix only where no word goes on before it
# (`startswith"x"` is an operator, then a literal). Comments: // to the end of the line.
_KQL_TOKEN_RE = re.compile(
    r"(?P<lit>(?:(?<![\w@])(?:[hH]@?|@[hH]?))?(?:\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')"
    r"|```.*?```|~~~.*?~~~)"
    r"|(?P<comment>//[^\n]*)", re.DOTALL)
# The comparison operators of KQL (word operators not followed by a word character).
_KQL_OP = (r"(?:==|!=|=~|!~|<>|(?:matches\s+regex|!?(?:has_any|has_all|has_cs|hasprefix_cs|hasprefix|"
           r"hassuffix_cs|hassuffix|has|contains_cs|contains|startswith_cs|startswith|endswith_cs|"
           r"endswith|in~|in|between))(?![\w~]))")
_KQL_LET_RE = re.compile(r"\blet\s+(\w+)\s*=\s*")
_KQL_UDF_RE = re.compile(r"\([^()]*\)\s*\{")
_KQL_ALIAS_RE = re.compile(r"(?<![\w.!<>=~])(\w+)\s*=(?![=~])\s*")
# Functions whose argument names a workspace, a resource, an application, a cluster.
_KQL_SCOPE_FN_RE = re.compile(r"\b(workspace|resource|app|cluster|database)\s*\(\s*", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"^<[a-z_]+>$")
_MIN_NAME = 3   # shorter names would cut words of the query


class IdentifierLeft(ValueError):
    """The generalised rule still names something of the deployment: not exported.
    `found`: what is left (shown to the operator, never written anywhere)."""
    found: list[str] = []


class NotGeneralizable(IdentifierLeft):
    """The query reaches an identity through a form the export does not follow (a `let`, an
    alias, a function of the query, an expression): to generalise by hand, nothing exported."""


def _literal_value(lit: str) -> str:
    body = lit.lstrip("hH@")
    q = 3 if body[:3] in ("```", "~~~") else 1
    return body[q:-q]


def _real_literal(lit: str) -> bool:
    value = _literal_value(lit)
    return bool(value) and not _PLACEHOLDER_RE.match(value)


def _names_something(lit: str) -> bool:
    """A literal that can name something: not a placeholder, at least _MIN_NAME long, with a
    letter or a digit (`"/"`, `"@"`, `""` name nothing)."""
    value = _literal_value(lit)
    return _real_literal(lit) and len(value) >= _MIN_NAME and any(c.isalnum() for c in value)


def _kql_lex(query: str) -> tuple[str, list[tuple[int, int]], list[tuple[int, int]]]:
    """→ (code, literals, comments): `code` is the query with every literal and comment
    blanked (same length), so that operators, columns and names are read in code only."""
    code = list(query)
    literals, comments = [], []
    for m in _KQL_TOKEN_RE.finditer(query):
        s, e = m.span()
        (literals if m.group("lit") else comments).append((s, e))
        code[s:e] = ("\x00" if m.group("lit") else " ") * (e - s)
    return "".join(code), literals, comments


def _closing(code: str, start: int, opening: str = "(", closing: str = ")") -> int:
    """The index of the bracket that closes the one at `start` (len(code) if none)."""
    depth = 0
    for i in range(start, len(code)):
        if code[i] == opening:
            depth += 1
        elif code[i] == closing:
            depth -= 1
            if depth == 0:
                return i
    return len(code)


def _expression_end(code: str, start: int) -> int:
    """Where an expression that starts at `start` ends: `,` `|` `;` or `by` at depth 0."""
    depth = 0
    i = start
    while i < len(code):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and (c in ",|;\n" or re.match(r"by\b", code[i:]) and not code[i - 1:i].isalnum()):
            return i
        i += 1
    return i


def _kql_analysis(query: str) -> tuple[list[tuple[int, int]], list[str]]:
    """→ (literals to replace, forms that make the export refuse).

    Replaced, because sure: a literal directly compared to an identity column (either side,
    a list of literals too), and the literal argument of workspace()/resource()/app()/
    cluster()/database(). Refused, because they reach an identity through an intermediate:
    a `let` bound to a string (directly or through another `let`) used against an identity
    column or in such a function; a non-literal argument of such a function; an alias of an
    identity column compared to a value; a function defined in the query whose body touches
    an identity column; an identity column compared to an expression holding a literal."""
    code, literals, _ = _kql_lex(query)
    lit_at = {s: (s, e) for s, e in literals}
    replace: set[tuple[int, int]] = set()
    refused: list[str] = []

    def has_literal(a: int, b: int) -> bool:
        return "\x00" in code[a:b]

    # `let`: functions defined in the query, and the names bound to a string.
    string_lets: set[str] = set()
    pending: dict[str, str] = {}
    for m in _KQL_LET_RE.finditer(code):
        name, start = m.group(1), m.end()
        udf = _KQL_UDF_RE.match(code, start)
        if udf:
            body_end = _closing(code, udf.end() - 1, "{", "}")
            if _ID_COL_RE.search(code, udf.end(), body_end):
                refused.append(f"fonction « {name} » définie dans la requête, dont le corps touche une colonne d'identité")
            continue
        end = code.find(";", start)
        rhs = code[start:end if end >= 0 else len(code)]
        if "\x00" in rhs:
            string_lets.add(name)
        else:
            pending[name] = rhs
    grew = True
    while grew:   # a `let` bound to a `let` bound to a string
        grew = False
        for name, rhs in list(pending.items()):
            if set(re.findall(r"\w+", rhs)) & string_lets:
                string_lets.add(name)
                del pending[name]
                grew = True

    # Aliases of an identity column (or of an alias): `extend h = Computer`, `by M=Computer`…
    aliases: set[str] = set()
    found_alias = True
    while found_alias:
        found_alias = False
        for m in _KQL_ALIAS_RE.finditer(code):
            name = m.group(1)
            if name in aliases or name in string_lets or name.lower() == "let":
                continue
            if re.search(r"\blet\s*$", code[:m.start()]):
                continue
            rhs = code[m.end():_expression_end(code, m.end())]
            words = set(re.findall(r"\w+", rhs))
            if _ID_COL_RE.search(rhs) or words & aliases:
                aliases.add(name)
                found_alias = True

    def operand(pos: int, column: str, alias: bool) -> None:
        """The value compared to `column`, from `pos` (past the operator)."""
        while pos < len(code) and code[pos] in " \t\n":
            pos += 1
        if pos in lit_at:
            span = lit_at[pos]
            if _names_something(query[span[0]:span[1]]):
                if alias:
                    refused.append(f"alias « {column} » d'une colonne d'identité comparé à une valeur")
                else:
                    replace.add(span)
            return
        if code[pos:pos + 1] == "(":
            end = _closing(code, pos)
            inner = code[pos + 1:end]
            spans = [lit_at[s] for s in lit_at if pos < s < end]
            if spans and not re.sub(r"[\x00,\s]", "", inner):
                for span in spans:
                    if _names_something(query[span[0]:span[1]]):
                        if alias:
                            refused.append(f"alias « {column} » d'une colonne d'identité comparé à une valeur")
                        else:
                            replace.add(span)
            elif spans:
                refused.append(f"{column} comparé à une expression : {query[pos:end + 1].strip()[:60]}")
            else:
                for word in set(re.findall(r"\w+", inner)) & string_lets:
                    refused.append(f"let « {word} » (une chaîne) utilisé contre {column}")
            return
        m = re.match(r"(\w+)\s*(\()?", code[pos:])
        if not m:
            return
        if m.group(2):
            end = _closing(code, pos + m.end() - 1)
            if has_literal(pos, end) or set(re.findall(r"\w+", code[pos:end])) & string_lets:
                refused.append(f"{column} comparé à une expression : {query[pos:end + 1].strip()[:60]}")
        elif m.group(1) in string_lets:
            refused.append(f"let « {m.group(1)} » (une chaîne) utilisé contre {column}")

    def compared(names_re: str, alias: bool) -> None:
        side = r"(?<![\w.])(?:\w+\s*\(\s*)?(?P<col>" + names_re + r")(?!\w)(?:\s*\))?"
        for m in re.finditer(side + r"\s*" + _KQL_OP + r"\s*", code, re.IGNORECASE):
            operand(m.end(), m.group("col"), alias)
        # A literal on the left: "vm-1" == Computer.
        for s, e in literals:
            if re.match(r"\s*" + _KQL_OP + r"\s*" + side, code[e:], re.IGNORECASE) and \
                    _names_something(query[s:e]):
                if alias:
                    refused.append("alias d'une colonne d'identité comparé à une valeur")
                else:
                    replace.add((s, e))

    compared("|".join(_ID_COLUMNS), alias=False)
    if aliases:
        compared("|".join(re.escape(a) for a in sorted(aliases)), alias=True)

    for m in _KQL_SCOPE_FN_RE.finditer(code):
        pos, fn = m.end(), m.group(1).lower()
        if pos in lit_at:
            if _real_literal(query[lit_at[pos][0]:lit_at[pos][1]]):
                replace.add(lit_at[pos])
        elif code[pos:pos + 1] != ")":
            end = _closing(code, m.end() - 1)
            words = set(re.findall(r"\w+", code[pos:end]))
            if words & string_lets:
                refused.append(f"let « {sorted(words & string_lets)[0]} » (une chaîne) utilisé dans {fn}()")
            else:
                refused.append(f"argument non littéral de {fn}() : {query[pos:end].strip()[:60]}")
    return sorted(replace), sorted(set(refused))


def kql_refusals(query: str) -> list[str]:
    """The forms that make the export refuse this query (see _kql_analysis)."""
    return _kql_analysis(query)[1]


def _name_re(name: str) -> re.Pattern:
    # A hyphen or a dot is a boundary: "vm-a1-log-clearing" names vm-a1 (better a word too
    # many replaced than a name that leaves). A regex escape is allowed before any character
    # that is not a letter or a digit (`vm\-a1`).
    body = "".join(re.escape(c) if c.isalnum() else r"\\?" + re.escape(c) for c in name)
    return re.compile(r"(?<![A-Za-z0-9_])" + body + r"(?![A-Za-z0-9_])", re.IGNORECASE)


def _resource_type(text: str, m: re.Match) -> bool:
    """A `<type>/<x>` that is a resource TYPE, not an instance: in an operation name
    (`MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION`, `Microsoft.Network/
    networkSecurityGroups/securityRules/write`) or followed by an operation verb
    (`storageAccounts/listKeys/action`) — never an identifier."""
    if re.search(r"microsoft\.\w+/$", text[max(0, m.start() - 64):m.start()], re.IGNORECASE):
        return True
    return bool(re.match(r"/(?:action|write|read|delete)\b", text[m.end():], re.IGNORECASE))


def _arm_left(text: str) -> list[str]:
    found = [m.group(0) for m in _ARM_SEGMENT_RE.finditer(text)
             if not _PLACEHOLDER_RE.match(m.group("val")) and not _resource_type(text, m)]
    for m in _PROVIDERS_RE.finditer(text):
        names = m.group("path").split("/")[2::2]
        if any(not _PLACEHOLDER_RE.match(n) for n in names):
            found.append(m.group(0))
    return found


def find_identifiers(text: str, known_names=(), kql: bool = True) -> list[str]:
    """Every identifier of a deployment still in `text`: a resource id or an instance part of
    one, a GUID, a name the deployment knows (also behind regex escapes) and, `kql`: a literal
    the query compares directly to an identity column or gives workspace()…, and every form
    that reaches an identity through an intermediate (refused, see _kql_analysis)."""
    found = _RESOURCE_ID_RE.findall(text) + _GUID_RE.findall(text) + _arm_left(text)
    if kql:
        replace, refused = _kql_analysis(text)
        found += [text[s:e] for s, e in replace if _real_literal(text[s:e])] + refused
    unescaped = text.replace("\\", "")
    for name in known_names:
        if len(name) >= _MIN_NAME and (_name_re(name).search(text) or _name_re(name).search(unescaped)):
            found.append(name)
    return found


def _scrub(text: str, known_names, counts: dict, kql: bool = False) -> str:
    def sub(pattern, placeholder, key, s):
        out, n = pattern.subn(placeholder, s)
        counts[key] = counts.get(key, 0) + n
        return out

    def count(key, n=1):
        counts[key] = counts.get(key, 0) + n

    if kql:   # comments go: free text, nothing can tell what they name
        _, _, comments = _kql_lex(text)
        for s, e in reversed(comments):
            text = text[:s] + "\x01" + text[e:]
        if comments:   # a line that held only a comment goes with it
            text = "\n".join(line.replace("\x01", "").rstrip() for line in text.split("\n")
                             if "\x01" not in line or line.replace("\x01", "").strip())
            count("commentaire retiré", len(comments))
    text = sub(_RESOURCE_ID_RE, "<resource_id>", "identifiant de ressource", text)
    text = sub(_GUID_RE, "<id>", "GUID (espace de travail, abonnement…)", text)

    def segment(m):
        if _PLACEHOLDER_RE.match(m.group("val")) or _resource_type(m.string, m):
            return m.group(0)
        count("partie d'un chemin de ressource")
        return f"{m.group('kind')}/<name>"

    def providers(m):
        parts = m.group("path").split("/")
        for i in range(2, len(parts), 2):
            if not _PLACEHOLDER_RE.match(parts[i]):
                parts[i] = "<name>"
                count("partie d'un chemin de ressource")
        return f"providers/{m.group('ns')}" + "/".join(parts)

    text = _PROVIDERS_RE.sub(providers, text)
    text = _ARM_SEGMENT_RE.sub(segment, text)
    if kql:
        for s, e in reversed(_kql_analysis(text)[0]):
            if _real_literal(text[s:e]):
                text = text[:s] + '"<name>"' + text[e:]
                count("littéral comparé à une colonne d'identité ou argument de workspace()")
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
            out[key] = _scrub(value, names, counts, kql=key == "query") if isinstance(value, str) else value
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
    refused = kql_refusals(str(rule.get("query") or ""))
    if refused:
        err = NotGeneralizable(f"« {name} » atteint une identité par une forme que l'export ne suit pas "
                               f"({len(refused)}) : généraliser la règle à la main — rien n'est exporté")
        err.found = refused
        raise err
    names = known_names([base, client], glorfindel_cfg=glorfindel_cfg, extra=extra_names)
    general, counts = generalize(rule, names)
    replaced = ", ".join(f"{what} ×{n}" for what, n in counts.items()) or "rien"
    text = ("# Règle exportée par `glorfindel export-rule` (P1) : généralisée, sans identifiant\n"
            "# de ressource ni d'espace de travail ; sans `assets`, elle s'applique à toute VM\n"
            f"# découverte. Remplacé : {replaced}.\n"
            "rules:\n" + _indent(_dump([general])))
    # The last guard reads what is written: the whole text, and the query as KQL.
    [exported] = yaml.safe_load(text)["rules"]
    left = find_identifiers(text, names, kql=False) + find_identifiers(str(exported.get("query", "")), names)
    if left:
        err = IdentifierLeft(f"« {name} » garde {len(left)} identifiant(s) du déploiement : rien n'est exporté")
        err.found = sorted(set(left))
        raise err
    return text


def _indent(text: str) -> str:
    return "".join(f"  {line}\n" if line else "\n" for line in text.splitlines())
