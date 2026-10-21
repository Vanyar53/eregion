"""Glorfindel infrastructure configuration.

Separate from detection_rules.yaml which contains rules only.
Loaded from glorfindel-config.yaml (Docker volume or local dev).
Values are direct (no ${VAR} substitution needed — edit the file directly).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

# Default search paths, first match wins
_DEFAULT_PATHS = [
    Path("glorfindel-config.yaml"),
    Path(__file__).parent.parent / "glorfindel-config.yaml",
    Path.home() / ".glorfindel" / "config.yaml",
]


class ConfigError(ValueError):
    """glorfindel-config.yaml exists but can't be read or is invalid. Callers that act
    on Azure must STOP on it: falling back to the defaults made an isolation pick
    another quarantine NSG and record "no NSG" as the NIC's original (sixth review, S1).
    A missing file is not an error — the defaults apply."""


# ── Environment switches (G2): a malformed value never makes Glorfindel bolder ──

# GLORFINDEL_READ_ONLY is off only when it clearly says so. The connector accepted
# "1/true/yes" and the War Room "1/true/True": `on`, `TRUE` or `y` left the writes on
# — the observe-only deployment the operator asked for, silently not one.
_SWITCH_OFF = {"", "0", "false", "no", "off", "n"}


def read_only_requested(value: str | None = None) -> bool:
    """GLORFINDEL_READ_ONLY (or `value`): read-only unless unset, empty, or clearly off
    (0, false, no, off). Any other value — a typo included — keeps Glorfindel read-only."""
    import os
    raw = os.environ.get("GLORFINDEL_READ_ONLY", "") if value is None else value
    return str(raw).strip().lower() not in _SWITCH_OFF


CONFIDENCE_THRESHOLD = 0.7


def confidence_threshold() -> float:
    """GLORFINDEL_CONFIDENCE_THRESHOLD: 0.7 when unset or empty; a value in [0, 1]
    otherwise. Malformed, out of range or not a number → infinite: every autonomous
    action is held (G2, configuration fails closed).

    A malformed value used to raise inside decide() and drop the whole cycle, then fell
    back to 0.7 — more permissive than the 0.95 an operator mistyped as "O.95" — and
    `nan` parsed: `confidence < nan` is never true, the gate let everything through.
    Here, next to read_only_requested, so the War Room reads the gate's own value
    without importing the agent (G2 review): an import that failed there dropped the
    whole capability matrix, silently."""
    import math
    import os
    raw = (os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD") or "").strip()
    if not raw:
        return CONFIDENCE_THRESHOLD
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = math.nan
    if not 0.0 <= value <= 1.0:          # nan fails the comparison too
        return math.inf
    return value


# A decision call is bounded: LiteLLM's own default is 6000 s per attempt (measured with
# litellm 1.86.1), three attempts with the retries — a provider that hangs held the VM's
# decision queue for hours, with no card. Bounded, it ends as a cycle_failed card.
LLM_TIMEOUT_S = 120.0
_LLM_TIMEOUT_MAX_S = 3600.0


def llm_timeout_s() -> float:
    """GLORFINDEL_LLM_TIMEOUT_S, in (0, 3600]. Unset, malformed, zero, negative or
    infinite → 120 s: a malformed value never unbounds the call."""
    import math
    import os
    raw = os.environ.get("GLORFINDEL_LLM_TIMEOUT_S", "").strip()
    if not raw:
        return LLM_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        return LLM_TIMEOUT_S
    if not math.isfinite(value) or not 0 < value <= _LLM_TIMEOUT_MAX_S:
        return LLM_TIMEOUT_S
    return value


def _flock(f, exclusive: bool) -> None:
    try:
        import fcntl
        fcntl.flock(f, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    except (ImportError, OSError):
        pass


def _read_text(path: Path) -> str:
    """The config's text, under a shared lock: never half of an in-place write."""
    with open(path) as f:
        _flock(f, exclusive=False)
        return f.read()


def _write_atomic(path: Path, text: str, locked=None) -> None:
    """Temp file + os.replace: the watch never reads a half-written config (the War
    Room rewrites it — sixth review, S1).

    A file mounted on its own in a container — docker-compose mounts
    glorfindel-config.yaml alone — can't be replaced: a rename over a mount point fails
    with EBUSY (measured, seventh review U3: the War Room's mode change failed). Then it
    is written in place, under the exclusive lock `locked` the caller holds on it;
    readers take the shared one (_read_text), so none sees it half-written."""
    import errno
    import os
    import tempfile
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    except OSError:
        fd, tmp = None, None
    if fd is not None:
        try:
            with os.fdopen(fd, "w") as f:
                f.write(text)
            os.replace(tmp, path)
            return
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            if exc.errno not in (errno.EBUSY, errno.EXDEV) or locked is None:
                raise
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    if locked is None:
        raise OSError(errno.EBUSY, f"{path} can't be replaced and isn't held for an in-place write")
    locked.seek(0)
    locked.write(text)
    locked.truncate()
    locked.flush()
    os.fsync(locked.fileno())


def _update_config(cfg_path: Path, mutate) -> None:
    """Read, change and write the config under one exclusive lock: two War Room
    requests don't lose each other's change. If the file was replaced while we waited
    for the lock (an atomic write on the host), read the new one."""
    import os
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        cfg_path.touch(exist_ok=True)
        f = open(cfg_path, "r+")         # not "a+": every write there goes to the end
        try:
            _flock(f, exclusive=True)
            try:
                same = os.fstat(f.fileno()).st_ino == os.stat(cfg_path).st_ino
            except OSError:
                same = False
            if not same:
                continue
            f.seek(0)
            data = yaml.safe_load(f.read()) or {}
            mutate(data)
            _write_atomic(cfg_path, yaml.safe_dump(data, sort_keys=False, default_flow_style=False), locked=f)
            return
        finally:
            f.close()


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    interval_s: float = 1800.0   # 30 min default


@dataclass
class MonitoringBackendConfig:
    name: str
    type: str                    # "azure_monitor", "prometheus", ...
    workspace_id: str = ""       # LAW workspace GUID or Prometheus URL
    endpoint: str = ""
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)


@dataclass
class ActionBackendConfig:
    name: str
    type: str                    # "azure_backup_vault"
    vault_name: str = ""
    resource_group: str = ""
    # Staging storage account for Azure Backup IaaS restore (same region/subscription).
    # Namespaced per Celebrimbor instance → resolved from `make celebrimbor-output`, never
    # hardcoded. Empty → restore_from_backup raises a clear error rather than a stale name.
    restore_staging_storage: str = ""


@dataclass
class ExceptionConfig:
    """Opt-out rule: prevent a rule (or all rules) from being applied to an asset."""
    asset_pattern: str           # fnmatch pattern matched against VM name
    exclude_all: bool = False    # exclude from all rules
    exclude_rules: list[str] = field(default_factory=list)  # specific rule names

    def matches(self, asset_name: str) -> bool:
        return fnmatch.fnmatch(asset_name, self.asset_pattern)

    def excludes_rule(self, rule_name: str) -> bool:
        return self.exclude_all or rule_name in self.exclude_rules


# Autonomy modes — resolved per asset, defaults to the safest (human_only).
# full_auto is deferred: the mechanism resolves it but config validation refuses
# the value for now. Order of precedence: asset match > global default.
VALID_AUTONOMY_MODES = {"human_only", "non_disruptive"}
DEFERRED_AUTONOMY_MODES = {"full_auto"}


@dataclass
class AutonomyRule:
    """An asset-scoped autonomy mode override (fnmatch, like ExceptionConfig)."""
    match: str                   # fnmatch pattern matched against VM name
    mode: str

    def matches(self, asset_name: str) -> bool:
        return fnmatch.fnmatch(asset_name, self.match)


@dataclass
class AutonomyConfig:
    """Per-asset autonomy policy.

    - human_only (default): nothing executes autonomously — every action, even
      reversible ones (isolate_vm/block/snapshot), is recommended and escalated.
    - non_disruptive: current behaviour — AUTONOMOUS_ACTIONS run, destructive gated.

    allow_destructive is a SEPARATE axis from the mode (Review 2026-06-10):
    delete_resource/wipe_storage are NEVER controlled by a mode. Empty = never
    autonomous, regardless of mode.
    """
    default: str = "human_only"
    assets: list[AutonomyRule] = field(default_factory=list)
    allow_destructive: list[str] = field(default_factory=list)

    def resolve(self, asset_name: str) -> str:
        """Resolve the autonomy mode for an asset. Most specific match > global default.

        Precedence: an exact match (pattern == asset_name, e.g. an entry written by
        the War Room dropdown) wins over any wildcard. Among wildcard matches, the
        longest pattern wins (proxy for specificity) — so a broad "vm-*" never
        shadows a targeted "vm-prod-db". Unknown assets fall back to the global
        default — never an accidental inheritance toward a more permissive mode.
        """
        exact = next((r for r in self.assets if r.match == asset_name), None)
        if exact is not None:
            return exact.mode
        matches = [r for r in self.assets if r.matches(asset_name)]
        if matches:
            return max(matches, key=lambda r: len(r.match)).mode
        return self.default


@dataclass
class IsolationConfig:
    """How Glorfindel isolates a VM.

    quarantine_nsg: a NIC with no NSG of its own gets Glorfindel's quarantine NSG
      (deny-all in and out) attached for the time of the isolation — no customer rule
      touched, nothing evaluated before it, untouched by a `terraform apply` (lot L4).
      False → the deny goes into the subnet's NSG, as before.
    quarantine_rg: resource group where Glorfindel creates its quarantine NSGs (one per
      region, on first need). Empty → the isolated VM's resource group.
    """
    quarantine_nsg: bool = True
    quarantine_rg: str = ""
    # CIDRs allowed IN to an isolated VM (Bastion subnet, investigation jump host),
    # before the quarantine's deny: isolate while keeping investigation access. Only
    # what validate_forensic_sources keeps is ever applied.
    forensic_sources: list[str] = field(default_factory=list)
    # TCP ports those sources reach (SSH, RDP) — not every port of a compromised VM.
    forensic_ports: list[int] = field(default_factory=lambda: [22, 3389])


# The widest forensic source accepted: a Bastion subnet (/26), a jump host (/32), a
# small management subnet (/24). Wider would let a whole network into an isolated VM.
_FORENSIC_MAX_ADDRESSES = 256


def validate_forensic_sources(values) -> tuple[list[str], list[tuple[str, str]]]:
    """(accepted CIDRs in canonical form, [(rejected value, why)]).

    The value became an NSG allow before the quarantine's deny AND part of the shell
    filter of the session drain (fourth review, Q5): a service tag (`Internet`), `*`,
    a /0 or a stray quote opened the isolated VM to everyone, or broke the command.
    Only plain addresses and small prefixes pass, rewritten by `ipaddress`."""
    import ipaddress
    accepted: list[str] = []
    rejected: list[tuple[str, str]] = []
    for raw in values or []:
        text = str(raw).strip()
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            rejected.append((text, "ni une adresse ni un préfixe CIDR (tags et * refusés)"))
            continue
        if net.num_addresses > _FORENSIC_MAX_ADDRESSES:
            rejected.append((text, f"préfixe trop large ({net.num_addresses} adresses, "
                                   f"{_FORENSIC_MAX_ADDRESSES} au plus)"))
        elif (net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved
              or net.network_address.is_unspecified
              or (net.version == 4 and net.overlaps(ipaddress.ip_network("0.0.0.0/8")))):
            rejected.append((text, "adresse réservée"))
        elif str(net) not in accepted:
            accepted.append(str(net))
    return accepted, rejected


def validate_forensic_ports(values) -> list[int]:
    """TCP ports, 1–65535. A single port written without a list (`forensic_ports: 22`)
    raised TypeError and made the whole config unreadable; `"22"` iterated as "2", "2"
    (sixth review, S1/S8). Anything else than a port number is a config error."""
    if values is None:
        return []
    items = values if isinstance(values, (list, tuple)) else [values]
    ports: list[int] = []
    for raw in items:
        if isinstance(raw, bool):
            raise ValueError(f"isolation.forensic_ports : {raw!r} n'est pas un port")
        try:
            port = int(str(raw).strip())
        except ValueError:
            raise ValueError(f"isolation.forensic_ports : {raw!r} n'est pas un port") from None
        if not 0 < port < 65536:
            raise ValueError(f"isolation.forensic_ports : {port} hors de 1–65535")
        if port not in ports:
            ports.append(port)
    return ports


@dataclass
class GlorfindelConfig:
    monitoring_backends: list[MonitoringBackendConfig] = field(default_factory=list)
    action_backends: list[ActionBackendConfig] = field(default_factory=list)
    exceptions: list[ExceptionConfig] = field(default_factory=list)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    isolation: IsolationConfig = field(default_factory=IsolationConfig)

    def monitoring_backend(self, name: str) -> MonitoringBackendConfig | None:
        return next((b for b in self.monitoring_backends if b.name == name), None)

    def action_backend(self, name: str) -> ActionBackendConfig | None:
        return next((b for b in self.action_backends if b.name == name), None)

    def backup_vault(self) -> ActionBackendConfig | None:
        return next(
            (b for b in self.action_backends if b.type == "azure_backup_vault"),
            None,
        )

    def is_excluded(self, asset_name: str, rule_name: str) -> bool:
        """Return True if the asset should NOT be monitored by the given rule."""
        return any(
            exc.matches(asset_name) and exc.excludes_rule(rule_name)
            for exc in self.exceptions
        )


NO_VAULT_MSG = ("Aucun coffre de sauvegarde configuré : action_backends (type "
                "azure_backup_vault) dans glorfindel-config.yaml, GLORFINDEL_BACKUP_VAULT, "
                "ou --vault.")


def resolve_backup_vault(explicit: str | None = None) -> tuple[str, str, str]:
    """(vault, vault_rg, staging_storage). Name: explicit (--vault) > config > env
    GLORFINDEL_BACKUP_VAULT > "" — never the retired "rsv-annatar", which sent a restore
    to a vault that no longer exists (third review, details). The vault's resource group
    and the staging account come from config (a central vault lives outside the VM's
    resource group)."""
    import os
    vault, vault_rg, staging = (explicit or "").strip(), "", ""
    try:
        rsv = load_glorfindel_config().backup_vault()
    except Exception:
        rsv = None
    if rsv:
        vault = vault or rsv.vault_name or ""
        vault_rg = rsv.resource_group or ""
        staging = rsv.restore_staging_storage or ""
    vault = vault or os.environ.get("GLORFINDEL_BACKUP_VAULT", "").strip()
    return vault, vault_rg, staging


def load_glorfindel_config(path: str | Path | None = None) -> GlorfindelConfig:
    """Load infrastructure config from glorfindel-config.yaml.

    If path is None, searches default locations. Returns empty config if not found.
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")

    if path is not None:
        candidates = [Path(path)]
    else:
        candidates = _DEFAULT_PATHS

    cfg_path = next((p for p in candidates if p.exists()), None)
    if cfg_path is None:
        return GlorfindelConfig()
    try:
        return _parse_config(yaml.safe_load(_read_text(cfg_path)) or {})
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"{cfg_path} : {type(exc).__name__}: {exc}") from exc


def _parse_config(data: dict) -> GlorfindelConfig:
    if not isinstance(data, dict):
        raise ValueError("le fichier ne contient pas une table YAML")

    monitoring_backends = []
    for b in data.get("monitoring_backends", []):
        disc_raw = b.get("discovery", {})
        monitoring_backends.append(MonitoringBackendConfig(
            name=b["name"],
            type=b.get("type", "azure_monitor"),
            workspace_id=b.get("workspace_id", ""),
            endpoint=b.get("endpoint", ""),
            discovery=DiscoveryConfig(
                enabled=disc_raw.get("enabled", True),
                interval_s=float(disc_raw.get("interval_s", 1800)),
            ),
        ))

    action_backends = []
    for b in data.get("action_backends", []):
        action_backends.append(ActionBackendConfig(
            name=b["name"],
            type=b.get("type", "azure_backup_vault"),
            vault_name=b.get("vault_name", ""),
            resource_group=b.get("resource_group", ""),
            restore_staging_storage=b.get("restore_staging_storage", ""),
        ))

    exceptions = []
    for e in data.get("exceptions", []):
        exceptions.append(ExceptionConfig(
            asset_pattern=e["asset_pattern"],
            exclude_all=e.get("exclude_all", False),
            exclude_rules=e.get("exclude_rules", []),
        ))

    autonomy = _parse_autonomy(data.get("autonomy", {}))
    iso = data.get("isolation") or {}
    isolation = IsolationConfig(
        quarantine_nsg=bool(iso.get("quarantine_nsg", True)),
        quarantine_rg=str(iso.get("quarantine_rg", "") or ""),
        forensic_sources=[str(x) for x in (iso.get("forensic_sources") or [])],
        forensic_ports=validate_forensic_ports(iso.get("forensic_ports", [22, 3389])),
    )

    return GlorfindelConfig(
        monitoring_backends=monitoring_backends,
        action_backends=action_backends,
        exceptions=exceptions,
        autonomy=autonomy,
        isolation=isolation,
    )


def _validate_mode(mode: str, where: str) -> str:
    """Validate an autonomy mode value, raising a clear error for refused values."""
    if mode in VALID_AUTONOMY_MODES:
        return mode
    if mode in DEFERRED_AUTONOMY_MODES:
        raise ValueError(
            f"Autonomy mode '{mode}' ({where}) is not available yet — it is deferred. "
            f"Use one of {sorted(VALID_AUTONOMY_MODES)}."
        )
    raise ValueError(
        f"Unknown autonomy mode '{mode}' ({where}). "
        f"Valid modes: {sorted(VALID_AUTONOMY_MODES)}."
    )


def _parse_autonomy(raw: dict) -> AutonomyConfig:
    """Parse + validate the autonomy section. Empty/absent → safe defaults."""
    default = _validate_mode(raw.get("default", "human_only"), where="autonomy.default")
    assets = []
    for a in raw.get("assets", []):
        mode = _validate_mode(a["mode"], where=f"autonomy.assets[match={a.get('match', '?')}]")
        assets.append(AutonomyRule(match=a["match"], mode=mode))
    return AutonomyConfig(
        default=default,
        assets=assets,
        allow_destructive=list(raw.get("allow_destructive", [])),
    )


def set_default_mode(mode: str, path: str | Path | None = None) -> str:
    """Set the global default autonomy mode and persist to glorfindel-config.yaml.

    Backend for the War Room Config panel global dropdown. Validates the mode
    (refuses full_auto / unknown), updates ``autonomy.default``, and writes the
    file back. Returns the resolved path.
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    _validate_mode(mode, where="set_default_mode()")

    if path is not None:
        cfg_path = Path(path)
    else:
        cfg_path = next((p for p in _DEFAULT_PATHS if p.exists()), _DEFAULT_PATHS[0])

    _update_config(cfg_path, lambda data: data.setdefault("autonomy", {}).__setitem__("default", mode))
    return str(cfg_path)


def set_asset_mode(asset_name: str, mode: str, path: str | Path | None = None) -> str:
    """Set the autonomy mode for a single asset and persist to glorfindel-config.yaml.

    Backend for the War Room mode selector / change-mode endpoint. Validates the
    mode (refuses full_auto / unknown), upserts an exact-match `autonomy.assets`
    entry for asset_name, and writes the file back. Returns the resolved path.

    NOTE: this rewrites the YAML via safe_dump — inline comments are not preserved.
    Intended for UI-driven edits; hand-edited configs keep their comments as long
    as the mode is changed through the file directly.
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    _validate_mode(mode, where=f"set_asset_mode({asset_name})")

    if path is not None:
        cfg_path = Path(path)
    else:
        cfg_path = next((p for p in _DEFAULT_PATHS if p.exists()), _DEFAULT_PATHS[0])

    def mutate(data):
        autonomy = data.setdefault("autonomy", {})
        autonomy.setdefault("default", "human_only")
        assets = autonomy.setdefault("assets", [])
        for entry in assets:
            if entry.get("match") == asset_name:
                entry["mode"] = mode
                break
        else:
            assets.append({"match": asset_name, "mode": mode})

    _update_config(cfg_path, mutate)
    return str(cfg_path)
