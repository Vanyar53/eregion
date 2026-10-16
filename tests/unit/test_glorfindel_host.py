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
