#!/usr/bin/env python3
"""CI3 (#267, step 2): the images the CI publishes, found and verified by their digest — on H0
by its CD (infra/glorfindel-host/cd/eregion_cd.py), on the operator's machine for Orodruin
(make orodruin-push), in the publishing workflow itself (.github/workflows/publish.yml).

    published_image.py resolve IMAGE --commit C            the digest published for commit C
    published_image.py verify IMAGE --commit C [--digest D]  its signature and its provenance
    published_image.py fetch IMAGE --ref REF --tag NAME    resolved, verified, pulled by digest, tagged NAME
    published_image.py loaded IMAGE --digest D --id ID     ID (docker's, on another host) is this image
    published_image.py install-cosign DEST                 cosign, pinned by its sha256
    published_image.py meta IMAGE --commit C               the workflow's names and labels ($GITHUB_OUTPUT)
    published_image.py pushed IMAGE --ref R                the workflow's push: R pushed, its digest said

What is trusted, and what is not (docs/operations.md, « Les images publiées ») :
- **A registry tag is a hint, never a proof.** The workflow pushes ghcr.io/vanyar53/eregion-<image>
  :sha-<commit> for the head of each push to main. Its digest is read anonymously (GHCR's public API, no
  token: the packages are public) and the manifest's own sha256 must be that digest.
- **The proof is the signature**, keyless (sigstore: a certificate from GitHub's OIDC, no
  long-lived key): `cosign verify` and `cosign verify-attestation` (SLSA provenance v1, made by
  actions/attest-build-provenance) both require the publishing workflow (its path, on
  refs/heads/main, triggered by a push), of this repository, at exactly that commit. An image
  signed by another workflow, another repository, another branch, another commit — refused.
- **The provenance is read again here**: its subject is this image and this digest, its
  workflow, repository, ref, trigger and source commit are the ones asked, on a GitHub-hosted runner.
- cosign is a pinned binary (version and sha256 below), checked before each use. It reads the
  registry and sigstore's trust root (tuf-repo-cdn.sigstore.dev); the transparency log is checked
  offline, in the bundle. Measured on 29/10 without any token: an attestation of
  actions/attest-build-provenance pushed to GHCR verified, a wrong commit or workflow refused.

Exit 0 when it holds, 1 when it does not (said why), 3 when the registry or the network does not
answer (nothing proven, try again). Python 3.10 (H0's), standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent
REGISTRY = os.environ.get("EREGION_REGISTRY") or "ghcr.io"            # the name in a reference
REGISTRY_API = (os.environ.get("EREGION_REGISTRY_API") or f"https://{REGISTRY}").rstrip("/")
OWNER = "vanyar53"                                                     # GHCR's names are lower case
SOURCE = "Vanyar53/eregion"                                            # the repository that signs
NAMES = {"glorfindel": "eregion-glorfindel", "annatar": "eregion-annatar"}
WORKFLOW = ".github/workflows/publish.yml"
BRANCH_REF = "refs/heads/main"
TRIGGER = "push"
ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE = "https://slsa.dev/provenance/v1"
# cosign, the verifier: the same version signs in the workflow (sigstore/cosign-installer).
COSIGN_VERSION = "v3.1.3"
COSIGN_SHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"   # cosign-linux-amd64
COSIGN_URL = f"https://github.com/sigstore/cosign/releases/download/{COSIGN_VERSION}/cosign-linux-amd64"
COSIGN_MAX = 300 * 1024 * 1024
# The user the published images run as: the first user of an Azure Ubuntu VM, H0's and Orodruin's.
UID = GID = 1000
MANIFEST_MAX = 4 * 1024 * 1024
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
LABELS = '{{index .Config.Labels "org.opencontainers.image.version"}} ' \
         '{{index .Config.Labels "org.opencontainers.image.revision"}}'


class Unverified(Exception):
    """The image is not the one asked for, or not proven so: refused. `detail`: what a tool said
    (cosign's last lines), for a journal."""

    def __init__(self, text: str, detail: str = ""):
        super().__init__(text)
        self.detail = detail


class Unavailable(Exception):
    """The registry, sigstore or the network did not answer: nothing proven, try again later.
    `detail`: what a tool said, for a journal."""

    def __init__(self, text: str, detail: str = ""):
        super().__init__(text)
        self.detail = detail


Runner = Callable[[list], "subprocess.CompletedProcess[str]"]
# A docker pull of an image of a gigabyte, cosign's two verifications: bounded (SEC4c). A tool
# cut at its bound is code 124, « timeout » — nothing proven, never a refusal.
TOOL_TIMEOUT_S = 600
COSIGN_TIMEOUT = "3m"
TIMEOUT_CODE = 124


def run(argv: list, timeout: float = TOOL_TIMEOUT_S) -> subprocess.CompletedProcess:
    argv = [str(a) for a in argv]
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, TIMEOUT_CODE, "", f"timeout: cut after {timeout:g} s")


def repository(image: str) -> str:
    return f"{OWNER}/{NAMES[image]}"


def reference(image: str) -> str:
    return f"{REGISTRY}/{repository(image)}"


def commit_tag(commit: str) -> str:
    return f"sha-{commit}"


def identity(slug: str = SOURCE) -> str:
    """The certificate's subject: the publishing workflow of `slug`, on main."""
    return f"https://github.com/{slug}/{WORKFLOW}@{BRANCH_REF}"


def _last(res, n: int = 3) -> str:
    text = ((res.stderr or "") + "\n" + (res.stdout or "")).strip()
    return " | ".join(text.splitlines()[-n:])[:400]


# ── the registry, read anonymously ───────────────────────────────────────────────────

def _open(url: str, headers: dict, limit: int):
    req = urllib.request.Request(url, headers={"User-Agent": "eregion-published-image", **headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(limit + 1)
            if len(body) > limit:
                raise Unverified(f"réponse démesurée du registre ({url.split('?')[0]})")
            return body, r.headers
    except urllib.error.HTTPError as e:
        raise e
    except (urllib.error.URLError, OSError) as e:
        raise Unavailable(f"registre injoignable : {type(e).__name__}") from None


def _token(image: str, api: str) -> str:
    url = f"{api}/token?scope=repository:{repository(image)}:pull&service={REGISTRY}"
    try:
        body, _ = _open(url, {}, 64 * 1024)
    except urllib.error.HTTPError as e:
        # GHCR refuses the anonymous token itself (403) for a private package, or one that does
        # not exist (measured on 29/10, review of CI3): a refusal, never a wait.
        if e.code in (401, 403):
            raise Unverified(f"{reference(image)} illisible sans jeton (HTTP {e.code}) : le paquet doit être "
                             "public, ou n'existe pas") from None
        raise Unavailable(f"jeton anonyme du registre refusé : HTTP {e.code}") from None
    try:
        token = json.loads(body).get("token") or json.loads(body).get("access_token")
    except ValueError:
        token = None
    if not isinstance(token, str) or not token:
        raise Unavailable("jeton anonyme du registre illisible")
    return token


def manifest(image: str, ref: str, api: str = "") -> tuple[str, dict]:
    """(its digest — the sha256 of the bytes read —, the manifest) of `ref`, a tag or a digest."""
    api = (api or REGISTRY_API).rstrip("/")
    token = _token(image, api)
    url = f"{api}/v2/{repository(image)}/manifests/{ref}"
    try:
        body, headers = _open(url, {"Authorization": f"Bearer {token}", "Accept": ACCEPT}, MANIFEST_MAX)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise Unverified(f"aucune image {reference(image)}:{ref} publiée") from None
        if e.code in (401, 403):
            raise Unverified(f"{reference(image)} illisible sans jeton (HTTP {e.code}) : le paquet "
                             "doit être public") from None
        raise Unavailable(f"registre : HTTP {e.code}") from None
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    said = (headers.get("Docker-Content-Digest") or "").strip()
    if said and said != digest:
        # What the registry says is quoted only when it is a digest (it may reach #deploy).
        shown = f"{said[:19]}…" if DIGEST_RE.fullmatch(said) else "un en-tête illisible"
        raise Unverified(f"le registre dit {shown} pour un manifeste de {digest[:19]}…")
    if ref.startswith("sha256:") and ref != digest:
        raise Unverified(f"le manifeste lu n'est pas {ref[:19]}…")
    try:
        doc = json.loads(body)
    except ValueError:
        raise Unverified("manifeste illisible") from None
    if not isinstance(doc, dict):
        raise Unverified("manifeste illisible")
    return digest, doc


def resolve(image: str, commit: str, api: str = "") -> str:
    """The digest the registry gives for the commit's tag — a hint, proven by verify()."""
    if not COMMIT_RE.fullmatch(commit or ""):
        raise Unverified(f"commit invalide : {commit!r}")
    return manifest(image, commit_tag(commit), api)[0]


def ids(image: str, digest: str, api: str = "") -> set[str]:
    """What docker may call this image once loaded elsewhere: the digest itself, its linux/amd64
    manifest, that manifest's config (the image id of docker's classic store) — each a content
    address under the verified digest."""
    out = {digest}
    d, doc = manifest(image, digest, api)
    if doc.get("manifests"):
        plat = [m for m in doc["manifests"] if isinstance(m, dict)
                and (m.get("platform") or {}).get("os") == "linux"
                and (m.get("platform") or {}).get("architecture") == "amd64"]
        if not plat or not DIGEST_RE.fullmatch(str(plat[0].get("digest") or "")):
            raise Unverified("pas d'image linux/amd64 sous ce digest")
        out.add(plat[0]["digest"])
        d, doc = manifest(image, plat[0]["digest"], api)
    config = str((doc.get("config") or {}).get("digest") or "")
    if not DIGEST_RE.fullmatch(config):
        raise Unverified("manifeste sans configuration lisible")
    out.add(config)
    return out


# ── the proof: cosign, then the provenance read again ────────────────────────────────

def cosign_ok(path: Path) -> bool:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest() == COSIGN_SHA256 and os.access(path, os.X_OK)
    except OSError:
        return False


def cosign_args(kind: str, ref: str, commit: str, slug: str = SOURCE) -> list[str]:
    """What cosign checks of the certificate: the workflow, the repository, the ref, the trigger,
    the commit — every one, or an image signed by another of them passes."""
    who = ["--certificate-identity", identity(slug), "--certificate-oidc-issuer", ISSUER,
           "--certificate-github-workflow-repository", slug, "--certificate-github-workflow-ref", BRANCH_REF,
           "--certificate-github-workflow-trigger", TRIGGER, "--certificate-github-workflow-sha", commit]
    if kind == "signature":
        return ["verify", *who, "--timeout", COSIGN_TIMEOUT, ref]
    return ["verify-attestation", "--type", PROVENANCE, *who, "--timeout", COSIGN_TIMEOUT, ref]


# What cosign says when what it read is absent or not what was asked (measured on 29/10, cosign
# v3.1.3): a refusal. Anything else — the network, sigstore's TUF mirror (« error updating to TUF
# remote mirror », review of CI3), a timeout — proves nothing either way: a wait.
COSIGN_REFUSALS = re.compile(r"no signatures found|no matching signatures|no matching attestations"
                             r"|none of the attestations matched|failed to verify certificate identity"
                             r"|\bexpected\b")
# What `cosign sign` writes; cosign v3's `verify` also accepts an attestation's bundle as a
# signature (measured on 29/10: an image attested, never signed, « verified » with type
# https://slsa.dev/provenance/v1) — the signature is one of this type.
SIGNATURE_TYPE = "https://sigstore.dev/cosign/sign/v1"


def _cosign_failed(res, what: str):
    said = f"{res.stderr or ''}\n{res.stdout or ''}"
    if res.returncode != TIMEOUT_CODE and COSIGN_REFUSALS.search(said):
        return Unverified(f"{what} absente, ou d'un autre workflow, dépôt, branche ou commit", _last(res))
    return Unavailable(f"cosign n'a rien pu prouver ({what}) : réseau, sigstore ou délai", _last(res))


def _lines(stdout: str) -> list[dict]:
    out = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        out.extend(d for d in (doc if isinstance(doc, list) else [doc]) if isinstance(d, dict))
    return out


def check_provenance(statement: dict, image: str, digest: str, commit: str, slug: str = SOURCE) -> None:
    """The statement cosign verified, read again: this image, this digest, built by the
    publishing workflow of `slug` on main, from a push, at `commit`, on GitHub's runners."""
    if statement.get("predicateType") != PROVENANCE:
        raise Unverified("provenance d'un autre type", repr(statement.get("predicateType"))[:200])
    hexd = digest.split(":", 1)[1]
    subjects = [s for s in statement.get("subject") or [] if isinstance(s, dict)]
    if not any(s.get("name") == reference(image) and (s.get("digest") or {}).get("sha256") == hexd for s in subjects):
        raise Unverified(f"la provenance ne porte pas sur {reference(image)}@{digest[:19]}…")
    bd = (statement.get("predicate") or {}).get("buildDefinition") or {}
    wf = ((bd.get("externalParameters") or {}).get("workflow") or {})
    gh = ((bd.get("internalParameters") or {}).get("github") or {})
    want = {"workflow": (wf.get("path"), WORKFLOW), "dépôt": (wf.get("repository"), f"https://github.com/{slug}"),
            "référence": (wf.get("ref"), BRANCH_REF), "événement": (gh.get("event_name"), TRIGGER),
            "runner": (gh.get("runner_environment"), "github-hosted")}
    wrong = [what for what, (got, ok) in want.items() if got != ok]
    if wrong:
        raise Unverified(f"provenance d'ailleurs : {', '.join(wrong)}",
                         "; ".join(f"{w} {want[w][0]!r}" for w in wrong)[:400])
    commits = {str((d.get("digest") or {}).get("gitCommit") or "") for d in bd.get("resolvedDependencies") or []
               if isinstance(d, dict)}
    if commits != {commit}:
        raise Unverified("provenance d'un autre commit", ", ".join(sorted(c[:40] for c in commits))[:400] or "aucun")


def verify(image: str, digest: str, commit: str, cosign: Path, slug: str = SOURCE, runner: Runner = run) -> None:
    """Signed and attested by the publishing workflow of `slug`, on main, at `commit`; raises
    Unverified otherwise. cosign is checked against its pinned sha256 first."""
    if not DIGEST_RE.fullmatch(digest or ""):
        raise Unverified(f"digest invalide : {digest!r}")
    if not COMMIT_RE.fullmatch(commit or ""):
        raise Unverified(f"commit invalide : {commit!r}")
    if not cosign_ok(cosign):
        raise Unverified(f"cosign absent ou altéré ({cosign}) : il doit être {COSIGN_VERSION}, sha256 {COSIGN_SHA256[:12]}…")
    ref = f"{reference(image)}@{digest}"
    res = runner([str(cosign), *cosign_args("signature", ref, commit, slug)])
    if res.returncode != 0:
        raise _cosign_failed(res, "signature")
    found = [d.get("critical") or {} for d in _lines(res.stdout)]
    signed = [(c.get("image") or {}).get("docker-manifest-digest") for c in found]
    if not signed or any(s != digest for s in signed):
        raise Unverified("la signature ne porte pas sur ce digest")
    if not any(c.get("type") == SIGNATURE_TYPE for c in found):
        raise Unverified("signature absente : seule une attestation porte sur ce digest")
    res = runner([str(cosign), *cosign_args("provenance", ref, commit, slug)])
    if res.returncode != 0:
        raise _cosign_failed(res, "provenance")
    statements = []
    for env in _lines(res.stdout):
        try:
            statements.append(json.loads(base64.b64decode(env.get("payload") or "")))
        except (ValueError, TypeError):
            continue
    if not statements:
        raise Unverified("aucune provenance lisible")
    for st in statements:
        check_provenance(st, image, digest, commit, slug)


def install_cosign(dest: Path) -> int:
    """cosign, downloaded once, kept only if its sha256 is the pinned one."""
    if cosign_ok(dest):
        print(f"✓ {dest} : cosign {COSIGN_VERSION}, déjà là")
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        body, _ = _open(COSIGN_URL, {}, COSIGN_MAX)
    except urllib.error.HTTPError as e:
        print(f"✗ cosign : HTTP {e.code}", file=sys.stderr)
        return 3
    if hashlib.sha256(body).hexdigest() != COSIGN_SHA256:
        print(f"✗ cosign téléchargé : sha256 {hashlib.sha256(body).hexdigest()[:12]}…, pas {COSIGN_SHA256[:12]}… — "
              "rien n'est installé", file=sys.stderr)
        return 1
    tmp.write_bytes(body)
    tmp.chmod(0o755)
    os.replace(tmp, dest)
    print(f"✓ {dest} : cosign {COSIGN_VERSION}, sha256 vérifié")
    return 0


# ── pulled by its digest ────────────────────────────────────────────────────────────

def labels(name: str, runner: Runner = run) -> tuple[str, str]:
    res = runner(["docker", "image", "inspect", "-f", LABELS, name])
    parts = [p for p in res.stdout.split() if p not in ("<no", "value>")] if res.returncode == 0 else []
    return (parts[0], parts[1]) if len(parts) == 2 else ("", "")


def pull(image: str, digest: str, name: str, commit: str, version: str = "", runner: Runner = run) -> None:
    """`docker pull` by the digest (docker checks the bytes against it), tagged `name`, the
    digest reference dropped (the image stays under `name`); its labels must be the commit (and
    the version, when given) — else the image is removed and refused."""
    ref = f"{reference(image)}@{digest}"
    res = runner(["docker", "pull", "-q", ref])
    if res.returncode != 0:
        raise Unavailable(f"docker pull {digest[:19]}… en échec (code {res.returncode})", _last(res))
    runner(["docker", "tag", ref, name])
    runner(["docker", "image", "rm", ref])
    ver, rev = labels(name, runner)
    if rev != commit or (version and ver != version):
        runner(["docker", "image", "rm", name])
        # The labels are quoted only when they are what a label of ours looks like.
        said_ver = ver if re.fullmatch(r"v?[0-9A-Za-z._-]{1,40}", ver) else "?"
        said_rev = rev[:12] if COMMIT_RE.fullmatch(rev) else "?"
        raise Unverified(f"l'image dit {said_ver} ({said_rev}), pas {version or '…'} ({commit[:12]})",
                         f"étiquettes : {ver!r} {rev!r}"[:400])


def commit_of(ref: str, runner: Runner = run) -> str:
    """A tag or a commit id of origin/main, as a full commit (a branch moves: refused)."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", ref or ""):
        raise Unverified(f"référence invalide : {ref!r} (un tag ou un commit)")
    res = runner(["git", "-C", str(REPO), "rev-parse", "-q", "--verify", f"refs/tags/{ref}^{{commit}}"])
    commit = res.stdout.strip() if res.returncode == 0 else ""
    if not commit and re.fullmatch(r"[0-9a-f]{7,40}", ref):
        res = runner(["git", "-C", str(REPO), "rev-parse", "-q", "--verify", f"{ref}^{{commit}}"])
        commit = res.stdout.strip() if res.returncode == 0 and res.stdout.strip().startswith(ref) else ""
    if not COMMIT_RE.fullmatch(commit):
        raise Unverified(f"« {ref} » n'est ni un tag ni un commit connu (git fetch --tags ?)")
    on_main = runner(["git", "-C", str(REPO), "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"])
    if on_main.returncode != 0:
        raise Unverified(f"« {ref} » ({commit[:12]}) n'est pas sur origin/main : seul main est publié")
    return commit


def latest_tag(runner: Runner = run) -> str:
    res = runner(["git", "-C", str(REPO), "tag", "-l", "v*", "--sort=-v:refname"])
    tags = res.stdout.split() if res.returncode == 0 else []
    if not tags:
        raise Unverified("aucun tag v* : préciser REF=<tag ou commit>")
    return tags[0]


# ── the workflow's side ─────────────────────────────────────────────────────────────

def project_version(pyproject: Path = REPO / "pyproject.toml") -> str:
    m = re.search(r'(?m)^version = "([^"]+)"$', pyproject.read_text(encoding="utf-8"))
    if not m:
        raise Unverified("pyproject.toml sans version")
    return m.group(1)


def meta(image: str, commit: str) -> dict:
    if not COMMIT_RE.fullmatch(commit or ""):
        raise Unverified(f"commit invalide : {commit!r}")
    return {"name": reference(image), "ref": f"{reference(image)}:{commit_tag(commit)}",
            "version": f"v{project_version()}", "uid": str(UID), "gid": str(GID)}


def pushed(image: str, ref: str, runner: Runner = run) -> str:
    """`docker push ref`, then the digest docker recorded for this repository: what was pushed is
    the image checked before, under that digest."""
    res = runner(["docker", "push", "-q", ref])
    if res.returncode != 0:
        raise Unavailable(f"docker push en échec (code {res.returncode})", _last(res))
    res = runner(["docker", "image", "inspect", "-f", "{{json .RepoDigests}}", ref])
    try:
        digests = json.loads(res.stdout) if res.returncode == 0 else []
    except ValueError:
        digests = []
    found = {d.split("@", 1)[1] for d in digests or [] if isinstance(d, str) and d.startswith(reference(image) + "@")}
    if len(found) != 1 or not DIGEST_RE.fullmatch(next(iter(found))):
        raise Unverified(f"digest poussé illisible : {digests!r}")
    return found.pop()


def _output(values: dict) -> None:
    for k, v in values.items():
        print(f"{k}={v}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.writelines(f"{k}={v}\n" for k, v in values.items())


def default_cosign() -> Path:
    return Path(os.environ.get("EREGION_COSIGN") or Path.home() / ".eregion" / "cosign" / f"cosign-{COSIGN_VERSION}")


def main(argv: list | None = None, runner: Runner = run) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("cmd", choices=["resolve", "verify", "fetch", "ids", "loaded", "install-cosign", "meta",
                                   "pushed"])
    p.add_argument("image", nargs="?", default="")
    p.add_argument("--commit", default="")
    p.add_argument("--digest", default="")
    p.add_argument("--ref", default="")
    p.add_argument("--tag", default="")
    p.add_argument("--id", default="")
    p.add_argument("--expect", default="", help="loaded: the ids `ids` printed before the image left")
    p.add_argument("--cosign", default="")
    a = p.parse_args(argv)
    cosign = Path(a.cosign) if a.cosign else default_cosign()
    try:
        if a.cmd == "install-cosign":
            return install_cosign(Path(a.image) if a.image else cosign)
        if a.image not in NAMES:
            p.error(f"image : {', '.join(NAMES)}")
        if a.cmd == "resolve":
            print(resolve(a.image, a.commit))
        elif a.cmd == "verify":
            digest = a.digest or resolve(a.image, a.commit)
            verify(a.image, digest, a.commit, cosign, runner=runner)
            print(f"✓ {reference(a.image)}@{digest} : signée et attestée par {WORKFLOW} sur main, au commit {a.commit[:12]}")
        elif a.cmd == "fetch":
            ref = a.ref or latest_tag(runner)
            commit = commit_of(ref, runner)
            digest = resolve(a.image, commit)
            verify(a.image, digest, commit, cosign, runner=runner)
            pull(a.image, digest, a.tag or f"{NAMES[a.image]}:{ref}", commit, runner=runner)
            _output({"ref": ref, "commit": commit, "digest": digest})
        elif a.cmd == "ids":
            print(" ".join(sorted(ids(a.image, a.digest))))
        elif a.cmd == "loaded":
            expected = set(a.expect.split()) if a.expect.strip() else ids(a.image, a.digest)
            if not all(DIGEST_RE.fullmatch(x) for x in expected) or a.id.strip() not in expected:
                print(f"✗ l'image chargée ({a.id.strip()[:19] or '?'}…) n'est pas {a.digest[:19]}…", file=sys.stderr)
                return 1
            print(f"✓ l'image chargée est {reference(a.image)}@{a.digest}")
        elif a.cmd == "meta":
            _output(meta(a.image, a.commit))
        elif a.cmd == "pushed":
            _output({"digest": pushed(a.image, a.ref, runner)})
    except Unverified as e:
        print(f"✗ {e}" + (f"\n  {e.detail}" if e.detail else ""), file=sys.stderr)
        return 1
    except Unavailable as e:
        print(f"✗ {e} — rien n'est prouvé, réessayer" + (f"\n  {e.detail}" if e.detail else ""), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
