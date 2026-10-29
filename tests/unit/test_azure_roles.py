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


def test_each_service_of_glorfindel_has_its_own_principal_and_the_single_one_as_fallback():
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
    # The console's and the bot's identities, so that their approved writes are Glorfindel's (AL1).
    assert "GLORFINDEL_OWN_CALLERS" in env["watch"]
