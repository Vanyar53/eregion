#!/usr/bin/env python3
"""CI1 (#267): the images, built and proven in CI — a broken Dockerfile or lock seen in the pull
request, not at H0's preflight, where it burns a release (infra/glorfindel-host/README.md,
« Le CD de H0 »).

    python3 scripts/image_check.py glorfindel                   # checks eregion-glorfindel:ci
    python3 scripts/image_check.py annatar --build              # builds it first, as the CI does
    python3 scripts/image_check.py glorfindel --image <name>    # another image (a local build)

The CI (.github/workflows/images.yml) builds each image with docker/build-push-action — its
Dockerfile, the repository as context, no build argument, never pushed — then runs this script
on it; `--build` (make images-check) builds the same way, without the CI's cache.

In the image, each check is a `docker run --rm --network none`: nothing starts (a command, never
the image's CMD), no network, no environment from the host — no secret, no Azure. What H0's CD
checks in its candidate (infra/glorfindel-host/cd/eregion_cd.py, preflight, step 5) is checked
here first, with the same imports (tests/unit/test_image_check.py keeps them in step):

  glorfindel  `glorfindel --version` is pyproject.toml's version; the watch, the bot and the
              console import; glorfindel-config.yaml.example passes A3's strict reading (the file
              mounted read-only where compose mounts the config, and read: an absent file would
              load as an empty config); the image does not run as root.
  annatar     `annatar --version` is pyproject.toml's version; Annatar and Gothmog import;
              neither Glorfindel, the console nor their dependencies are in it (D1); not root.

Exit 0 when every check passes, 1 otherwise (each failure says which, with the command's last
lines), 2 when docker cannot run at all. Python 3.11+, standard library only.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from component_check import GLORFINDEL_ONLY_DEPS  # noqa: E402  (D1's list, not a copy)

# The imports H0's CD runs in its candidate (eregion_cd.py, preflight): the watch, the bot, the console.
GLORFINDEL_IMPORTS = "glorfindel.cli, glorfindel.bot, eregion_console.api"
INJECTOR_IMPORTS = "annatar.cli, gothmog.cli"
EXAMPLE_CONFIG = "glorfindel-config.yaml.example"
CONFIG_IN_IMAGE = "/app/glorfindel-config.yaml"        # where compose mounts the config
# Opened first: load_glorfindel_config returns an empty config for a path that is not there.
READ_CONFIG = ("from glorfindel.config import load_glorfindel_config as load; "
               f"open({CONFIG_IN_IMAGE!r}).close(); load({CONFIG_IN_IMAGE!r})")
NOT_ROOT = "import os, sys; sys.exit(os.getuid() == 0)"
# The names given that the image holds, said and exit 1; a dotted name whose parent is absent is absent.
ABSENT = ("import importlib.util, sys\n"
          "def held(n):\n"
          "    try:\n"
          "        return importlib.util.find_spec(n) is not None\n"
          "    except ModuleNotFoundError:\n"
          "        return False\n"
          "found = [n for n in sys.argv[1:] if held(n)]\n"
          "print(' '.join(found))\n"
          "sys.exit(1 if found else 0)\n")
NOT_IN_INJECTORS = ("glorfindel", "eregion_console", *GLORFINDEL_ONLY_DEPS)
TAIL = 20


@dataclass(frozen=True)
class Check:
    name: str
    argv: tuple[str, ...]                        # what runs in the image
    mounts: tuple[tuple[Path, str], ...] = ()    # (host file, path in the image), read-only
    says_version: bool = False                   # its output's last word must be the version


@dataclass(frozen=True)
class Image:
    dockerfile: str
    default: str                                 # the tag the CI gives it
    checks: tuple[Check, ...] = field(default=())


IMAGES = {
    "glorfindel": Image("glorfindel/Dockerfile", "eregion-glorfindel:ci", (
        Check("glorfindel --version", ("glorfindel", "--version"), says_version=True),
        Check("la watch, le bot et la console importent", ("python", "-c", f"import {GLORFINDEL_IMPORTS}")),
        Check(f"{EXAMPLE_CONFIG} sous la lecture stricte d'A3", ("python", "-c", READ_CONFIG),
              mounts=((REPO / EXAMPLE_CONFIG, CONFIG_IN_IMAGE),)),
        Check("pas root", ("python", "-c", NOT_ROOT)),
    )),
    "annatar": Image("annatar/Dockerfile", "eregion-annatar:ci", (
        Check("annatar --version", ("annatar", "--version"), says_version=True),
        Check("Annatar et Gothmog importent", ("python", "-c", f"import {INJECTOR_IMPORTS}")),
        Check("ni Glorfindel, ni la console, ni leurs dépendances (D1)",
              ("python", "-c", ABSENT, *NOT_IN_INJECTORS)),
        Check("pas root", ("python", "-c", NOT_ROOT)),
    )),
}

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def version(pyproject: Path = REPO / "pyproject.toml") -> str:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]


def docker_run(image: str, check: Check) -> list[str]:
    """No network, no host environment, nothing started but the check's command."""
    argv = ["docker", "run", "--rm", "--network", "none"]
    for host, inside in check.mounts:
        argv += ["-v", f"{host}:{inside}:ro"]
    return [*argv, image, *check.argv]


def build(name: str, image: str, runner: Runner = run) -> bool:
    """As the CI's step: the image's Dockerfile, the repository as context, no build argument."""
    res = runner(["docker", "build", "-f", str(REPO / IMAGES[name].dockerfile), "-t", image, str(REPO)])
    if res.returncode != 0:
        print(f"✗ docker build {name}\n{tail(res)}")
        return False
    print(f"✓ docker build {name} → {image}")
    return True


def tail(res: subprocess.CompletedProcess[str]) -> str:
    lines = ((res.stdout or "") + (res.stderr or "")).strip().splitlines()
    return "\n".join("    " + line for line in lines[-TAIL:])


def failure(check: Check, res: subprocess.CompletedProcess[str], want: str) -> str:
    """Why a check failed, or "" when it passed."""
    if res.returncode != 0:
        return f"code {res.returncode}"
    if check.says_version:
        words = res.stdout.split()
        said = words[-1] if words else ""
        if said != want:
            return f"dit « {said} », pas {want}"
    return ""


def check_image(name: str, image: str, runner: Runner = run, want: str | None = None) -> bool:
    """Every check, even after a failure: the log says all that is wrong at once."""
    want = version() if want is None else want
    ok = True
    for check in IMAGES[name].checks:
        missing = [str(h) for h, _ in check.mounts if not h.is_file()]
        if missing:
            print(f"✗ {check.name} : {', '.join(missing)} absent du dépôt")
            ok = False
            continue
        res = runner(docker_run(image, check))
        why = failure(check, res, want)
        if why:
            print(f"✗ {check.name} — {why}\n{tail(res)}")
            ok = False
        else:
            print(f"✓ {check.name}")
    return ok


def main(argv: list[str] | None = None, runner: Runner = run) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("name", choices=sorted(IMAGES))
    p.add_argument("--image", help="the image to check (default: the CI's tag)")
    p.add_argument("--build", action="store_true", help="build it first, as the CI does (without its cache)")
    args = p.parse_args(argv)
    image = args.image or IMAGES[args.name].default
    try:
        if args.build and not build(args.name, image, runner):
            return 1
        return 0 if check_image(args.name, image, runner) else 1
    except FileNotFoundError as exc:          # no docker on this machine
        print(f"✗ docker introuvable : {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
