"""H0: what goes to the hosted Glorfindel keeps it an observer.

The config pushed to the VM is human_only whatever the local one says, and the VM's
Terraform grants it read rights on the bench only, without enrolling it as a target.
"""
import importlib.util
import re
from pathlib import Path

from glorfindel.config import _parse_autonomy

HOST = Path(__file__).resolve().parents[2] / "infra" / "glorfindel-host"
_spec = importlib.util.spec_from_file_location("host_config", HOST / "host_config.py")
host_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(host_config)


def test_pushed_config_is_human_only_for_every_asset():
    local = {
        "monitoring_backends": [{"type": "azure_monitor"}],
        "exceptions": [{"asset_pattern": "vm-x", "exclude_all": True}],
        "autonomy": {
            "default": "non_disruptive",
            "assets": [{"match": "vm-celebrimbor-*", "mode": "non_disruptive"}],
            "allow_destructive": ["vm-celebrimbor-*"],
        },
    }
    out = host_config.host_config(local)
    autonomy = _parse_autonomy(out["autonomy"])
    assert autonomy.default == "human_only"
    assert autonomy.assets == [] and autonomy.allow_destructive == []
    assert out["monitoring_backends"] == local["monitoring_backends"]
    assert out["exceptions"] == local["exceptions"]
    assert local["autonomy"]["default"] == "non_disruptive"  # the local file is untouched


def test_host_terraform_reads_the_bench_and_is_no_target():
    tf = (HOST / "main.tf").read_text(encoding="utf-8")
    roles = re.findall(r'role_definition_name\s*=\s*"([^"]+)"', tf)
    assert sorted(roles) == ["Log Analytics Reader", "Reader"]
    assert not re.search(r'"eregion-(target|zone)"\s*=', tf)
    assert 'source_address_prefix      = var.operator_cidr' in tf


_spec_env = importlib.util.spec_from_file_location("host_env", HOST / "host_env.py")
host_env = importlib.util.module_from_spec(_spec_env)
_spec_env.loader.exec_module(host_env)


def test_host_env_carries_no_azure_secret_and_is_read_only():
    operator = {
        "AZURE_SUBSCRIPTION_ID": "sub", "ANTHROPIC_API_KEY": "key",
        "AZURE_CLIENT_ID": "sp", "AZURE_CLIENT_SECRET": "secret", "AZURE_TENANT_ID": "t",
        "GLORFINDEL_AZURE_CLIENT_SECRET": "secret2", "DISCORD_BOT_TOKEN": "bot",
        "GLORFINDEL_WEBHOOK_URL": "https://hook", "GLORFINDEL_READ_ONLY": "",
    }
    env = host_env.host_env(operator)
    assert not [k for k in env if "CLIENT" in k or "TENANT" in k]
    assert env["DISCORD_BOT_TOKEN"] == "bot"  # the VM runs the bot
    assert env["GLORFINDEL_READ_ONLY"] == "1"
    assert env["GLORFINDEL_DISCOVERY_RETENTION_H"] == "168"   # gondolin, off, stays a week
    assert env["GLORFINDEL_WEBHOOK_URL"] == "https://hook"
    assert len(env["GLORFINDEL_WARROOM_TOKEN"]) >= 24


def test_every_host_env_variable_reaches_the_containers():
    """docker compose passes an explicit list (`x-env`), not the whole .env: a variable that
    host.env carries but the list omits never reaches the watch. #160 added
    EREGION_WATCH_CHANNEL to host.env and not to the list — the hosted watch would never
    have published its heartbeat (found 20/10, before deployment)."""
    passed = set().union(*_compose_env().values())
    operator = {k: "x" for k in host_env.COPIED}
    carried = set(host_env.host_env(operator))
    assert carried - passed == set()


# ── M-3 (#183) : un environnement par conteneur ───────────────────────────────────────────
# The oracle is written here, never read from docker-compose.yml: who must receive each
# secret, and what each container still needs to work.
SECRETS = {
    "DISCORD_BOT_TOKEN": {"bot"},
    "GLORFINDEL_WARROOM_TOKEN": {"war-room"},
    "ANTHROPIC_API_KEY": {"watch"}, "OPENAI_API_KEY": {"watch"},
    "MISTRAL_API_KEY": {"watch"}, "AZURE_API_KEY": {"watch"},
    # The service principal (empty on H0: managed identity): the watch, the War Room's
    # « Approve & execute », the bot's Restore / Revert buttons.
    "AZURE_CLIENT_SECRET": {"watch", "war-room", "bot"},
    # A webhook URL carries its token: the watch (decisions, actions) and the War Room (cards
    # it records), never the bot.
    "GLORFINDEL_WEBHOOK_URL": {"watch", "war-room"},
}
NEEDED = {
    "watch": {"AZURE_SUBSCRIPTION_ID", "ANTHROPIC_API_KEY", "GLORFINDEL_LLM_MODEL", "GLORFINDEL_READ_ONLY",
              "EREGION_EXERCISE_CHANNEL", "EREGION_WATCH_CHANNEL", "EREGION_ANALYSIS_MODEL",
              "DISCORD_CHANNEL_ID", "GLORFINDEL_WEBHOOK_URL", "GLORFINDEL_DISCOVERY_RETENTION_H"},
    "war-room": {"GLORFINDEL_WARROOM_TOKEN", "AZURE_SUBSCRIPTION_ID", "GLORFINDEL_READ_ONLY",
                 "GLORFINDEL_LLM_MODEL", "GLORFINDEL_APPROVAL_MAX_AGE_H", "GLORFINDEL_BACKUP_VAULT",
                 "EREGION_EXERCISE_CHANNEL", "EREGION_WATCH_CHANNEL", "DISCORD_CHANNEL_ID"},
    "bot": {"DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID", "DISCORD_PING_ROLE", "DISCORD_ALLOWED_USERS",
            "DISCORD_ALLOWED_ROLES", "AZURE_SUBSCRIPTION_ID", "GLORFINDEL_READ_ONLY"},
}
_SECRET_WORDS = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|WEBHOOK|SAS", re.I)


def _compose_env() -> dict[str, dict[str, str]]:
    """service → {variable: the ${…} it is filled from}, as docker compose builds it."""
    import yaml

    compose = yaml.safe_load((HOST.parents[1] / "docker-compose.yml").read_text(encoding="utf-8"))
    out = {}
    for name, service in compose["services"].items():
        env = service.get("environment") or {}
        assert isinstance(env, dict), f"{name}: environment as a mapping"
        out[name] = {k: str(v) for k, v in env.items()}
    return out


def test_each_container_receives_only_its_secrets():
    env = _compose_env()
    assert set(env) == {"watch", "bot", "war-room"}
    for secret, owners in SECRETS.items():
        assert {s for s, e in env.items() if secret in e} == owners, secret
    # A new secret-looking variable must be placed above, never handed to every container.
    passed = set().union(*env.values())
    unplaced = {v for v in passed if _SECRET_WORDS.search(v) and v not in SECRETS}
    assert unplaced <= {"AZURE_API_BASE", "AZURE_API_VERSION"}, unplaced
    for service, needed in NEEDED.items():
        assert needed - set(env[service]) == set(), service
    # No container takes the whole .env: env_file would hand it every secret.
    import yaml
    compose = yaml.safe_load((HOST.parents[1] / "docker-compose.yml").read_text(encoding="utf-8"))
    assert not any("env_file" in s for s in compose["services"].values())


def _interpolate(spec: str, dotenv: dict) -> str:
    """What docker compose puts in the container for `${VAR:-}` — or a literal value."""
    m = re.fullmatch(r"\$\{(\w+)(?::-([^}]*))?\}", spec)
    return dotenv.get(m.group(1)) or (m.group(2) or "") if m else spec


def test_the_generated_host_env_reaches_each_container_with_only_its_secrets():
    """host.env (host_env.py) is the one .env compose reads on H0: render each container's
    environment from it as compose would, then look for every secret's value."""
    operator = {k: f"value-of-{k}" for k in host_env.COPIED}
    dotenv = host_env.host_env(operator)
    rendered = {s: {k: _interpolate(v, dotenv) for k, v in e.items()} for s, e in _compose_env().items()}
    values = {s: set(e.values()) for s, e in rendered.items()}
    secrets = {k: dotenv[k] for k in dotenv if k in SECRETS}
    assert set(secrets) >= {"DISCORD_BOT_TOKEN", "GLORFINDEL_WARROOM_TOKEN", "ANTHROPIC_API_KEY",
                            "OPENAI_API_KEY", "GLORFINDEL_WEBHOOK_URL"}
    for secret, value in secrets.items():
        assert {s for s, v in values.items() if value in v} == SECRETS[secret], secret
    assert rendered["bot"]["DISCORD_ALLOWED_USERS"] == "value-of-DISCORD_ALLOWED_USERS"
    assert rendered["watch"]["DISCORD_CHANNEL_ID"] == rendered["war-room"]["DISCORD_CHANNEL_ID"] \
        == "value-of-DISCORD_CHANNEL_ID"


def test_host_env_warns_when_nobody_may_press_the_buttons(tmp_path, monkeypatch, capsys):
    for k in list(host_env.COPIED):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "bot")
    host_env.main(str(tmp_path / "a.env"))
    assert "fermé par défaut" in capsys.readouterr().err
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "111")
    host_env.main(str(tmp_path / "b.env"))
    assert capsys.readouterr().err == ""
    assert "DISCORD_ALLOWED_USERS=111" in (tmp_path / "b.env").read_text()


def test_the_watch_leaves_the_cards_to_the_bot_without_its_token(monkeypatch):
    """The watch no longer receives DISCORD_BOT_TOKEN: it reads DISCORD_CHANNEL_ID to know the
    bot posts the cards, or every card would also go to the webhook."""
    from glorfindel import escalations

    posted = []
    monkeypatch.setattr("requests.post", lambda url, **kw: posted.append(url))
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    monkeypatch.setenv("GLORFINDEL_WEBHOOK_URL", "https://hook.example/x")
    monkeypatch.setenv("DISCORD_CHANNEL_ID", "42")
    esc = {"resource_id": "/x/vm", "action": "isolate_vm", "escalation_type": "mode_hold",
           "reason": "held", "run_id": "r"}
    escalations._notify(esc)
    assert posted == []
    monkeypatch.delenv("DISCORD_CHANNEL_ID")
    escalations._notify(esc)
    assert posted == ["https://hook.example/x"]


def test_empty_service_principal_vars_leave_room_for_the_managed_identity():
    """docker compose passes AZURE_CLIENT_ID="" on the hosted VM: azure-identity then builds
    ClientSecretCredential("") and never reaches the managed identity (measured, 16/10)."""
    from glorfindel.cli import _drop_empty_service_principal_env

    environ = {"AZURE_CLIENT_ID": "", "AZURE_CLIENT_SECRET": " ", "AZURE_TENANT_ID": "",
               "AZURE_SUBSCRIPTION_ID": "sub"}
    assert _drop_empty_service_principal_env(environ) == [
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]
    assert environ == {"AZURE_SUBSCRIPTION_ID": "sub"}

    real = {"AZURE_CLIENT_ID": "app", "AZURE_CLIENT_SECRET": "s", "AZURE_TENANT_ID": "t"}
    assert _drop_empty_service_principal_env(real) == [] and len(real) == 3


def test_empty_vars_no_longer_break_the_credential_chain(monkeypatch):
    from azure.identity import EnvironmentCredential

    from glorfindel.cli import _drop_empty_service_principal_env

    for k in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"):
        monkeypatch.setenv(k, "")
    import os
    _drop_empty_service_principal_env(os.environ)
    EnvironmentCredential()  # raised ValueError("client_id should be …") before
