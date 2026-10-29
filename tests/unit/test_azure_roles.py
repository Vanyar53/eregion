"""V-17 (SEC7): one Azure principal per service of Glorfindel, with only what its code calls.

Before, the watch, the console and the bot shared one service principal, and the README created
it **Contributor on the whole subscription**. Now:
- no document or script of the repository grants Contributor (or Owner) at a subscription's
  scope — an `az ad sp create-for-rbac` or `az role assignment create`, its lines joined;
- the response's role (infra/identities/glorfindel-response.json) holds every right the Azure
  adapter declares (glorfindel/providers/azure/capabilities.py) and nothing broad; the
  restore's role is never the watch's;
- compose gives each service its own principal, the former single one as its fallback.
Read from the files; no Azure.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "infra" / "identities"

# What is scanned: what a reader copies. History (CHANGELOG, ROADMAP, docs/historique.md) and
# the sessions' mailboxes say what was, not what to run; the mutants (scripts/mutation_check.py)
# hold on purpose the line this test must catch.
SKIP = {"CHANGELOG.md", "ROADMAP.md", "docs/historique.md", "scripts/mutation_check.py"}
SCANNED = ("*.md", "*.example", "Makefile", "docs/**/*.md", "infra/**/*.md", "infra/**/*.sh",
           "infra/**/*.tf", "scripts/*.sh", "scripts/*.py", "glorfindel/*.py", ".envrc.example")
BROAD = {"contributor", "owner"}


def _logical_lines(text: str) -> list[str]:
    """Commands as a shell reads them: a commented line stripped of its `#`, a line ending in
    `\\` joined to the next, adjacent Python string literals folded into one."""
    text = re.sub(r"""["']\s*\n\s*f?["']""", "", text)
    out, cur = [], ""
    for raw in text.splitlines():
        line = re.sub(r"^\s*#\s?", "", raw).rstrip()
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        out.append(cur + line)
        cur = ""
    return out + ([cur] if cur else [])


def _value(line: str, *flags: str) -> str | None:
    for flag in flags:
        m = re.search(rf"{flag}[ =]+(\"[^\"]*\"|'[^']*'|\S+)", line)
        if m:
            return m.group(1).strip("\"'")
    return None


def broad_grants(text: str) -> list[str]:
    """Each command that would grant Contributor or Owner on a whole subscription."""
    bad = []
    for line in _logical_lines(text):
        if not re.search(r"\baz\s+(ad\s+sp\s+create-for-rbac|role\s+assignment\s+create)\b", line):
            continue
        role = (_value(line, "--role") or "").lower()
        if role not in BROAD:
            continue
        scope = _value(line, "--scopes", "--scope") or ""
        if "/resourcegroups/" not in scope.lower():
            bad.append(line.strip())
    return bad


def _scanned_files() -> list[Path]:
    files = set()
    for pattern in SCANNED:
        files.update(p for p in ROOT.glob(pattern) if p.is_file())
    return sorted(p for p in files if str(p.relative_to(ROOT)) not in SKIP)


def test_no_document_or_script_grants_contributor_on_a_subscription():
    files = _scanned_files()
    assert ROOT / "README.md" in files and ROOT / ".envrc.example" in files
    assert ROOT / "docs" / "operations.md" in files
    found = {str(p.relative_to(ROOT)): b for p in files if (b := broad_grants(p.read_text(encoding="utf-8")))}
    assert found == {}
    tf = [p for p in files if p.suffix == ".tf"
          and re.search(r'role_definition_name\s*=\s*"(Contributor|Owner)"', p.read_text(encoding="utf-8"))]
    assert tf == []


@pytest.mark.parametrize("snippet", [
    'az ad sp create-for-rbac --name "eregion" --role Contributor \\\n  --scopes /subscriptions/$(az account show --query id -o tsv)',
    "# az ad sp create-for-rbac --name x --role Contributor \\\n#    --scopes /subscriptions/<SUBSCRIPTION_ID>",
    'az role assignment create --assignee <appId> --role "Contributor" --scope /subscriptions/$SUB',
    "az role assignment create --assignee a --role=Owner --scope=/subscriptions/s/",
    "az ad sp create-for-rbac --name x --role contributor",              # no scope: the subscription
    'fix = (f"az role assignment create --assignee $AZURE_CLIENT_ID "\n       f"--role Contributor --scope /subscriptions/$AZURE_SUBSCRIPTION_ID")',
])
def test_a_broad_grant_is_seen(snippet):
    assert broad_grants(snippet), snippet


@pytest.mark.parametrize("snippet", [
    "az role assignment create --assignee a --role Reader --scope /subscriptions/s",
    'az role assignment create --assignee a --role "Network Contributor" --scope /subscriptions/s/resourceGroups/rg',
    "az role assignment create --assignee a --role Contributor --scope /subscriptions/s/resourceGroups/rg-bench",
    'az role assignment create --assignee a --role "Eregion Glorfindel Response" --scope /subscriptions/s/resourceGroups/rg',
    'az ad sp create-for-rbac --name "eregion-glorfindel-watch"',
])
def test_a_scoped_or_narrow_grant_passes(snippet):
    assert broad_grants(snippet) == [], snippet


def _role(name: str) -> dict:
    return json.loads((ROLES / f"glorfindel-{name}.json").read_text(encoding="utf-8"))


def test_the_response_role_holds_what_the_adapter_declares_and_nothing_broad():
    from glorfindel.providers.azure.capabilities import CAPABILITIES
    response = _role("response")
    actions = set(response["Actions"])
    declared = set().union(*(c.rights for c in CAPABILITIES.capabilities))
    assert declared and declared <= actions
    # The snapshot: an on-demand backup of the vault, never its restore.
    assert "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action" in actions
    for role in (response, _role("restore")):
        assert role["IsCustom"] is True and not role["DataActions"] and not role["NotActions"]
        for a in role["Actions"]:
            assert "*" not in a and not a.lower().startswith("microsoft.authorization/"), a
            assert not a.lower().endswith("/delete") or "securityrules" in a.lower(), a
        assert role["AssignableScopes"] == ["/subscriptions/<SUBSCRIPTION_ID>"]   # a placeholder, never an id
    assert not any("restore" in a.lower() or "deallocate" in a.lower() for a in actions)


def test_the_restore_role_restores_and_nothing_of_the_network():
    actions = set(_role("restore")["Actions"])
    assert "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action" in actions
    assert {"Microsoft.Compute/virtualMachines/deallocate/action", "Microsoft.Compute/virtualMachines/start/action"} <= actions
    assert not [a for a in actions if a.startswith("Microsoft.Network/")]


def _render(spec: str, env: dict) -> str:
    """docker compose's `${VAR:-default}`, the default itself a `${…}` (measured with
    `docker compose config`, compose 5.5, 29/10)."""
    m = re.fullmatch(r"\$\{(\w+):-(.*)\}", spec)
    if not m:
        return spec
    return env.get(m.group(1)) or _render(m.group(2), env)


def test_each_service_of_glorfindel_has_its_own_principal_and_the_single_one_as_fallback(monkeypatch):
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    env = {name: s.get("environment") or {} for name, s in compose["services"].items()}
    own = {"watch": "GLORFINDEL_AZURE_CLIENT", "war-room": "EREGION_CONSOLE_AZURE_CLIENT",
           "bot": "GLORFINDEL_BOT_AZURE_CLIENT"}
    each = {k: f"{v}_SECRET-value" for k, v in own.items()}
    dotenv = {f"{v}_SECRET": each[k] for k, v in own.items()} | {"AZURE_CLIENT_SECRET": "shared-value"}
    for service, prefix in own.items():
        assert _render(str(env[service]["AZURE_CLIENT_SECRET"]), dotenv) == each[service], service
        assert _render(str(env[service]["AZURE_CLIENT_SECRET"]), {"AZURE_CLIENT_SECRET": "shared-value"}) \
            == "shared-value", service
        assert _render(str(env[service]["AZURE_CLIENT_ID"]), {f"{prefix}_ID": "x"}) == "x", service
    rendered = {s: {_render(str(v), dotenv) for v in e.values()} for s, e in env.items()}
    for service, value in each.items():
        assert {s for s, values in rendered.items() if value in values} == {service}, service
    # The console's and the bot's identities, so that their approved writes are Glorfindel's (AL1):
    # added to the operator's list, an empty one ignored.
    own = str(env["watch"]["GLORFINDEL_OWN_CALLERS"]).split(",")
    rendered = [_render(x, {"GLORFINDEL_OWN_CALLERS": "app-x", "EREGION_CONSOLE_AZURE_CLIENT_ID": "console-id",
                            "GLORFINDEL_BOT_AZURE_CLIENT_ID": "bot-id"}) for x in own]
    assert rendered == ["app-x", "console-id", "bot-id"]
    assert [_render(x, {}) for x in own] == ["", "", ""]
    from glorfindel.providers.azure.activity import configured_identities
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.setenv("GLORFINDEL_OWN_CALLERS", ",console-id,")
    assert configured_identities() == {"console-id"}


@pytest.mark.skipif(__import__("shutil").which("make") is None, reason="make not installed")
@pytest.mark.parametrize("env, said", [
    ({"EREGION_CONSOLE_AZURE_CLIENT_ID": "console-id"}, "EREGION_CONSOLE_AZURE_CLIENT_ID"),
    ({"GLORFINDEL_BOT_AZURE_CLIENT_SECRET": "x"}, "GLORFINDEL_BOT_AZURE_CLIENT_ID"),
    ({"GLORFINDEL_AZURE_CLIENT_ID": "w", "GLORFINDEL_AZURE_CLIENT_SECRET": "x"}, None),
    ({}, None),
])
def test_a_principal_without_its_pair_is_said_at_start(env, said):
    """SEC7 (V-17): the compose's fallbacks are drawn one variable at a time — an id without its
    secret would mix two principals. `make glorfindel-start` (check-azure-env) says so."""
    import os
    import subprocess
    base = {k: v for k, v in os.environ.items() if "AZURE_CLIENT" not in k}
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "check-azure-env",
                          "AZURE_SUBSCRIPTION_ID=s"], env={**base, **env}, capture_output=True, text=True,
                         timeout=60)
    assert res.returncode == 0, res.stderr
    if said:
        assert "paire incomplète" in res.stdout and said in res.stdout
    else:
        assert "paire incomplète" not in res.stdout
    secret = {"GLORFINDEL_BOT_AZURE_CLIENT_SECRET": "hy1-canary-bot"}
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "check-azure-env",
                          "AZURE_SUBSCRIPTION_ID=s"], env={**base, **secret}, capture_output=True, text=True,
                         timeout=60)
    assert "hy1-canary" not in res.stdout + res.stderr          # a secret's value is never said


BROAD_BUILT_IN = re.compile(r"\b(?:Network|Backup|Virtual Machine)?\s*Contributor\b|\bOwner\b")


def test_the_audit_and_the_readiness_advise_no_broad_role_and_never_the_restore_to_the_watch():
    """SEC7: what the audit and the readiness tell an operator to grant is Reader for a read
    that failed, « Eregion Glorfindel Response » for a write that is missing — never a broad
    built-in role (Contributor, Network, Backup, Virtual Machine Contributor). The restore's role
    is never advised to `$AZURE_CLIENT_ID` (the audit runs in the watch): the console and the bot
    only."""
    import inspect

    from glorfindel import audit, readiness
    names = {json.loads(p.read_text(encoding="utf-8"))["Name"] for p in ROLES.glob("*.json")}
    assert names == {"Eregion Glorfindel Response", "Eregion Glorfindel Restore"}
    for module in (audit, readiness):
        text = re.sub(r"""["']\s*\n\s*f?["']""", "", inspect.getsource(module))
        roles = re.findall(r"--role\s+(?:'([^']+)'|(\S+))", text)
        roles = [a or b for a, b in roles] + re.findall(r"« (Eregion Glorfindel \w+) »", text)
        assert roles, module.__name__
        for role in roles:
            assert not BROAD_BUILT_IN.search(role), (module.__name__, role)
            assert role in names | {"Reader", "Log Analytics Reader"}, (module.__name__, role)
        for m in re.finditer(r"--assignee \$AZURE_CLIENT_ID\s+--role\s+(?:'([^']+)'|(\S+))", text):
            assert "Restore" not in (m.group(1) or m.group(2)), (module.__name__, m.group(0))
        assert not re.search(r"\b(?:Network|Backup|Virtual Machine) Contributor\b", text), module.__name__
    fixes = {c.name: c.fix for c in _audit_checks_failing_on_iam()}
    assert set(fixes) == {"NSG access", "Backup vault", "Compute access"}
    for name, fix in fixes.items():
        assert "--role Reader " in fix, (name, fix)
    assert "Eregion Glorfindel Restore" in fixes["Backup vault"] and "console et au bot" in fixes["Backup vault"]


def _audit_checks_failing_on_iam():
    """The three reads of the audit, each refused by Azure (an IAM error)."""
    from unittest.mock import MagicMock

    from glorfindel import audit
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    c = MagicMock()
    c.check_nsg_access.return_value = {"ok": False, "iam": True, "error": "AuthorizationFailed"}
    c.check_backup_points.return_value = {"ok": False, "iam": True, "error": "AuthorizationFailed"}
    c.check_compute_access.return_value = {"ok": False, "iam": True, "error": "AuthorizationFailed"}
    out = []
    for fn, args in ((audit._check_nsg, (rid, c)), (audit._check_backup, (rid, c, "rsv", "rg-backup")),
                     (audit._check_compute, (rid, c))):
        got = fn(*args)
        out += got if isinstance(got, list) else [got]
    return [x for x in out if x.status == "fail"]
