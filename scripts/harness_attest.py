#!/usr/bin/env python3
"""make llm-compare … ATTEST=1 — the harness on two locks, one attestation (H3, #324).

H0's CD deploys a new lock only with the harness's attestation (H1), and judges it against the
lock in service (H3): a case right on every draw there and wrong on every draw here is a
regression; a case that varies is said, never a refusal. So the harness runs twice, with the
same code and the same cases — only the dependencies differ:

  1. the reference: the lock of the release in service on H0 (the latest `v*` tag, or
     --base <tag>), installed with --require-hashes in a throwaway venv under
     ~/.cache/eregion/harness-reference/<sha256>/ (kept for the next time, never in the
     repository), this checkout's code on its PYTHONPATH;
  2. the candidate: this checkout's .venv (the interpreter running this script).

Then requirements/harness.json holds both passes (scripts/llm_smoke.py writes it). Paid calls,
twice those of one pass: Jonathan runs it (docs/operations.md, « Verrou des dépendances »).

    python scripts/harness_attest.py --models <H0's model> --runs 3 [--base v0.4.5]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LOCK = "requirements/glorfindel.txt"
SMOKE = REPO / "scripts" / "llm_smoke.py"
RELEASE_TAG = re.compile(r"v\d+\.\d+\.\d+")   # a published release; never a pre-release
MIN_RUNS = 3                                   # what H0's CD asks for


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=check)


def cache_dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "eregion" / "harness-reference"


def reference_tag(base: str = "", fetch: bool = True) -> str:
    """--base, else the latest `v*` tag of a release (version order). Tags fetched first, so
    the release Jonathan published last is the one found."""
    if base:
        if _git("rev-parse", "-q", "--verify", f"refs/tags/{base}^{{commit}}", check=False).returncode != 0:
            raise SystemExit(f"BASE={base} : tag introuvable (git fetch --tags)")
        return base
    if fetch and _git("fetch", "-q", "--tags", "origin", check=False).returncode != 0:
        print("git fetch --tags a échoué : les tags locaux font foi")
    tags = [t for t in _git("tag", "--list", "v*", "--sort=-v:refname").stdout.split() if RELEASE_TAG.fullmatch(t)]
    if not tags:
        raise SystemExit("aucun tag de release v* : BASE=<tag en service sur H0>")
    return tags[0]


def reference_lock(tag: str) -> bytes:
    res = subprocess.run(["git", "show", f"{tag}:{LOCK}"], cwd=REPO, capture_output=True, check=False)
    if res.returncode != 0:
        raise SystemExit(f"{tag} n'a pas de {LOCK}")
    return res.stdout


def reference_venv(lock: bytes, cache: Path, python: str = sys.executable) -> tuple[Path, Path]:
    """The venv of the reference lock: (its python, its lock file). Installed once per lock
    (its sha256 names the folder, `.installed` written last); a folder left half-made is
    started again."""
    try:
        cache.resolve().relative_to(REPO)
    except ValueError:
        pass
    else:
        raise SystemExit(f"{cache} est dans le dépôt : le venv de référence n'y va jamais")
    sha = hashlib.sha256(lock).hexdigest()
    home = cache / sha[:16]
    py, lock_file, done = home / "bin" / "python", home / "glorfindel.txt", home / ".installed"
    if done.is_file() and done.read_text().strip() == sha and py.exists():
        print(f"référence : venv déjà installé ({home})")
        return py, lock_file
    shutil.rmtree(home, ignore_errors=True)
    home.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([python, "-m", "venv", str(home)], check=True)
    lock_file.write_bytes(lock)
    print(f"référence : installation du verrou {sha[:12]} dans {home} (--require-hashes)")
    subprocess.run([str(py), "-m", "pip", "install", "--quiet", "--require-hashes", "-r", str(lock_file)],
                   check=True)
    done.write_text(sha + "\n")
    return py, lock_file


PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*([^\\]+?))?\s*\\?$")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def drift(lock_text: str, installed: dict[str, str] | None = None) -> list[str]:
    """What this interpreter has that the lock does not pin: « name: installed ≠ pinned ».
    The candidate pass runs here and is attested under the lock's sha256 — a .venv not
    reinstalled after `make lock` would attest a lock it never ran (make install). A pin under
    a marker counts only where the marker holds (its marker unreadable: skipped)."""
    if installed is None:
        from importlib import metadata
        installed = {_norm(d.metadata["Name"]): d.version for d in metadata.distributions() if d.metadata["Name"]}
    try:
        from packaging.markers import Marker
    except ImportError:   # pragma: no cover — pip's own environment always has it
        Marker = None
    out = []
    for line in lock_text.splitlines():
        m = PIN.match(line.strip())
        if not m:
            continue
        name, pinned, marker = _norm(m.group(1)), m.group(2), m.group(3)
        if marker:
            try:
                if Marker is None or not Marker(marker).evaluate():
                    continue
            except Exception:
                continue
        have = installed.get(name)
        if have != pinned:
            out.append(f"{name}: {have or 'absent'} ≠ {pinned}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--models", required=True, help="comma-separated; H0's model among them")
    ap.add_argument("--runs", type=int, default=MIN_RUNS)
    ap.add_argument("--base", default="", help="the release in service on H0 (default: the latest v* tag)")
    ap.add_argument("--out", default=str(REPO / "requirements" / "harness.json"))
    ap.add_argument("--cache", default="", help="where the reference venv goes (default ~/.cache/eregion/…)")
    ap.add_argument("--no-fetch", action="store_true", help="the local tags only")
    args = ap.parse_args(argv)
    if args.runs < MIN_RUNS:
        print(f"RUNS={args.runs} : le CD de H0 en demande {MIN_RUNS} au moins — rien lancé")
        return 2
    mine = (REPO / LOCK).read_bytes()
    off = drift(mine.decode("utf-8", "replace"))
    if off:
        print(f"→ ce Python ({sys.executable}) ne suit pas {LOCK} : {'; '.join(off[:5])}"
              + (f" ; et {len(off) - 5} autre(s)" if len(off) > 5 else "") + " — make install, puis relancer. Rien lancé")
        return 2
    tag = reference_tag(args.base, fetch=not args.no_fetch)
    lock = reference_lock(tag)
    if hashlib.sha256(lock).digest() == hashlib.sha256(mine).digest():
        print(f"ce verrou est déjà celui de {tag} : si H0 tourne sur une release d'avant, donne "
              f"BASE=<la release d'avant {tag}> ; sinon le CD n'a rien à attester — rien lancé")
        return 0
    cache = Path(args.cache) if args.cache else cache_dir()
    py, lock_file = reference_venv(lock, cache)
    cache.mkdir(parents=True, exist_ok=True)
    ref_pass = cache / f"reference-{tag}.json"
    ref_pass.unlink(missing_ok=True)
    common = ["--models", args.models, "--runs", str(args.runs)]
    print(f"\n══ 1/2 — la référence : le verrou de {tag} ══\n", flush=True)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)}
    ref = subprocess.run([str(py), str(SMOKE), *common, "--lock", str(lock_file), "--ref", tag,
                          "--pass-out", str(ref_pass)], cwd=REPO, env=env, check=False)
    if not ref_pass.is_file():
        print(f"→ la passe de référence n'a rien écrit (code {ref.returncode}) : rien d'attesté. Si elle a échoué "
              f"à l'import (ModuleNotFoundError ci-dessus), le code de ce checkout exige une dépendance que le verrou "
              f"de {tag} n'a pas. Une PR de verrou ne porte pas de code qui exige ses nouvelles dépendances : "
              "sépare les PR — le verrou d'abord, attesté et déployé, puis le code qui s'en sert.")
        return 1
    print(f"\n══ 2/2 — le candidat : {LOCK} de ce checkout ══\n", flush=True)
    cand = subprocess.run([sys.executable, str(SMOKE), *common, "--reference", str(ref_pass),
                           "--attest", args.out], cwd=REPO, check=False)
    return cand.returncode


if __name__ == "__main__":
    sys.exit(main())
