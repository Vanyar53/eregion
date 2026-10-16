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
    assert not [k for k in env if "CLIENT" in k or "TENANT" in k or k == "DISCORD_BOT_TOKEN"]
    assert env["GLORFINDEL_READ_ONLY"] == "1"
    assert env["GLORFINDEL_WEBHOOK_URL"] == "https://hook"
    assert len(env["GLORFINDEL_WARROOM_TOKEN"]) >= 24
