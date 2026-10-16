"""The Glorfindel config pushed to the hosted VM (H0): the local one, with autonomy forced to
human_only.

    python infra/glorfindel-host/host_config.py glorfindel-config.yaml OUT.yaml

Pre-observation: Glorfindel decides, a human judges, nothing acts on its own. The local
config may carry `non_disruptive` (default or per asset) and `allow_destructive`; both go.
Backends and exceptions stay as they are.
"""
from __future__ import annotations

import sys

import yaml


def host_config(cfg: dict) -> dict:
    out = dict(cfg or {})
    out["autonomy"] = {"default": "human_only"}
    return out


def main(src: str, dst: str) -> int:
    with open(src, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    with open(dst, "w", encoding="utf-8") as f:
        yaml.safe_dump(host_config(cfg), f, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
