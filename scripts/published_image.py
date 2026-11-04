#!/usr/bin/env python3
"""CI3 (#267, step 2): the images the CI publishes, found and verified by their digest — on H0
by its CD (infra/glorfindel-host/cd/eregion_cd.py), on the operator's machine for Orodruin
(make orodruin-push), in the publishing workflow itself (.github/workflows/publish.yml).

    published_image.py resolve IMAGE --commit C            the digest published for commit C
    published_image.py verify IMAGE --commit C [--digest D]  its signature and its provenance
    published_image.py fetch IMAGE --ref REF --tag NAME    resolved, verified, pulled by digest, tagged NAME
    published_image.py archive IMAGE --ref REF --tag NAME --out DIR   resolved, verified, its OCI archive
                                                           built from the registry's blobs (OI1)
    published_image.py loaded IMAGE --digest D --expect-file F --inspect J   the image docker read back
                                                           on another host (J, `docker image inspect`) is this one
    published_image.py age IMAGE (--read F [--no-marker] | --no-image) [--ref R]   OI3: the image in service
                                                           on Orodruin (F: its tag's labels, then its
                                                           ~/.eregion-image) against the latest release
    published_image.py install-cosign DEST                 cosign, pinned by its sha256
    published_image.py install-syft DEST                   syft (the SBOM), its archive pinned by its sha256
    published_image.py meta IMAGE --commit C               the workflow's names and labels ($GITHUB_OUTPUT)
    published_image.py pushed IMAGE --ref R                the workflow's push: R pushed, its digest said
    published_image.py harness-key [DIR]                   SEC19: the attestation's key pair (Jonathan, once)
    published_image.py sign-blob FILE [--key K]            FILE signed by that key, offline, FILE.sigstore.json
    published_image.py verify-blob FILE --pinned P | --pub F   FILE signed by the key P (host.env's form) or F

What is trusted, and what is not (docs/operations.md, « Les images publiées ») :
- **A registry tag is a hint, never a proof.** The workflow pushes ghcr.io/grootcyber/eregion-<image>
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
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent
REGISTRY = os.environ.get("EREGION_REGISTRY") or "ghcr.io"            # the name in a reference
REGISTRY_API = (os.environ.get("EREGION_REGISTRY_API") or f"https://{REGISTRY}").rstrip("/")
OWNER = "grootcyber"                                                     # GHCR's names are lower case
SOURCE = "grootcyber/eregion"                                            # the repository that signs
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
# SEC14 (R-14): syft, which writes the SBOM in the job that signs — pinned by the sha256 of its
# release archive (syft_<v>_checksums.txt of anchore's release, read on 02/11), never fetched at
# its latest by an action. The version anchore/sbom-action v0.24.2 ran: the same SBOM.
SYFT_VERSION = "v1.51.1"
SYFT_SHA256 = "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"   # syft_1.51.1_linux_amd64.tar.gz
SYFT_URL = (f"https://github.com/anchore/syft/releases/download/{SYFT_VERSION}/"
            f"syft_{SYFT_VERSION[1:]}_linux_amd64.tar.gz")
SYFT_MAX = 200 * 1024 * 1024
# The user the published images run as: the first user of an Azure Ubuntu VM, H0's and Orodruin's.
UID = GID = 1000
MANIFEST_MAX = 4 * 1024 * 1024
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))
# OI1: what an archive of the image may hold — a manifest, its config, its layers, of these media
# types only (a foreign layer, served from elsewhere, refused); and the bounds of their sizes,
# read in the manifest before a byte is fetched (the image of Annatar: ~630 MB, 03/11).
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
               "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"}
CONFIG_MAX = 4 * 1024 * 1024
LAYER_MAX = 2 * 1024 ** 3
IMAGE_MAX = 4 * 1024 ** 3                 # all its layers together
LAYERS_MAX = 128
CHUNK = 1 << 20
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
        with _OPENER.open(req, timeout=30) as r:       # a redirect elsewhere never carries the token (OI1)
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
    digest, doc, _raw, _type = _manifest(image, ref, api)
    return digest, doc


def _manifest(image: str, ref: str, api: str = "") -> tuple[str, dict, bytes, str]:
    """manifest(), with the bytes read (OI1: they go in the archive as they are, their sha256 the
    digest) and the media type the registry gave them."""
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
    return digest, doc, body, str(doc.get("mediaType") or headers.get("Content-Type") or "").split(";")[0].strip()


def resolve(image: str, commit: str, api: str = "") -> str:
    """The digest the registry gives for the commit's tag — a hint, proven by verify()."""
    if not COMMIT_RE.fullmatch(commit or ""):
        raise Unverified(f"commit invalide : {commit!r}")
    return manifest(image, commit_tag(commit), api)[0]


def ids(image: str, digest: str, api: str = "") -> set[str]:
    """What docker may call this image once loaded elsewhere: the digest itself, its linux/amd64
    manifest, that manifest's config (the image id of docker's classic store) — each a content
    address under the verified digest."""
    d, doc, _raw, _type = platform_manifest(image, digest, api)
    config = str((doc.get("config") or {}).get("digest") or "")
    if not DIGEST_RE.fullmatch(config):
        raise Unverified("manifeste sans configuration lisible")
    return {digest, d, config}


def platform_manifest(image: str, digest: str, api: str = "") -> tuple[str, dict, bytes, str]:
    """The linux/amd64 manifest under `digest` (itself, or the one its index names): its digest,
    its document, its bytes, its media type — each read by its digest."""
    d, doc, raw, mtype = _manifest(image, digest, api)
    if doc.get("manifests") or mtype in INDEX_TYPES:
        plat = [m for m in doc.get("manifests") or [] if isinstance(m, dict)
                and (m.get("platform") or {}).get("os") == "linux"
                and (m.get("platform") or {}).get("architecture") == "amd64"]
        if not plat or not DIGEST_RE.fullmatch(str(plat[0].get("digest") or "")):
            raise Unverified("pas d'image linux/amd64 sous ce digest")
        d, doc, raw, mtype = _manifest(image, plat[0]["digest"], api)
    return d, doc, raw, mtype


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


# ── SEC19 (R-13): the harness's attestation signed by its author's own key ─────────────
# A cosign key pair of the maintainer (`make harness-key`, Jonathan's decision of 03/11): its private
# half encrypted by a passphrase he types, kept off the repository (~/.config/eregion/harness/); its
# public half pinned in H0's config (EREGION_HARNESS_KEY in host.env), never in the repository. No
# certificate, no identity, nothing sent to a transparency log: signed and verified offline
# (measured on 03/11 with cosign v3.1.3, the network refused: `sign-blob --signing-config` with a
# config that names no service writes a bundle holding the signature and the key's hint only;
# `verify-blob --key … --insecure-ignore-tlog` verifies it, a wrong key or a changed file refused —
# « invalid signature when validating ASN.1 encoded signature »; without --insecure-ignore-tlog it
# fetches sigstore's trust root). v3.1.3 has no --tlog-upload any more (its help lists none), and
# `--use-signing-config=false` alone still posts to rekor.sigstore.dev (measured: the POST refused
# by the blocked network): only a signing config without Rekor keeps the signature off the log.
# --insecure-ignore-sct is a certificate's, and a key's bundle has none: not needed (measured).
BUNDLE_SUFFIX = ".sigstore.json"
HARNESS_KEY_ENV = "EREGION_HARNESS_KEY"
KEY_PREFIX = "cosign"                   # cosign.key, cosign.pub in the key's directory
# A signing config that names no service — no Fulcio, no Rekor, no timestamp authority: what
# `cosign signing-config create` writes without a service (measured, v3.1.3).
NO_SERVICES = '{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}'
_B64 = re.compile(r"[A-Za-z0-9+/]{40,2000}={0,2}")


def bundle_of(path: Path) -> Path:
    return path.with_name(path.name + BUNDLE_SUFFIX)


def harness_key_dir() -> Path:
    """Where `make harness-key` writes the pair: off the repository, the maintainer's own."""
    return Path(os.environ.get("EREGION_HARNESS_KEY_DIR") or Path.home() / ".config" / "eregion" / "harness")


def key_der(pinned: str) -> bytes:
    """EREGION_HARNESS_KEY — the base64 of the public key's DER (SubjectPublicKeyInfo), on one line:
    the body of cosign.pub without its two PEM lines. Raises Unverified when it is not one."""
    text = (pinned or "").strip()
    if not text:
        raise Unverified(f"aucune clé de l'attestation déclarée sur H0 ({HARNESS_KEY_ENV} dans host.env)")
    if not _B64.fullmatch(text):
        raise Unverified(f"{HARNESS_KEY_ENV} illisible dans host.env : la clé publique (base64 d'une ligne, sans les lignes PEM ; make harness-key la donne)")
    try:
        der = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise Unverified(f"{HARNESS_KEY_ENV} illisible dans host.env : pas du base64") from None
    if der[:1] != b"\x30":
        raise Unverified(f"{HARNESS_KEY_ENV} illisible dans host.env : pas une clé publique (DER)")
    return der


def pem_of(der: bytes) -> str:
    body = base64.b64encode(der).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) \
        + "\n-----END PUBLIC KEY-----\n"


def pinned_of_pem(pem: str) -> str:
    """The EREGION_HARNESS_KEY line of a cosign.pub."""
    return "".join(ln.strip() for ln in pem.splitlines() if ln.strip() and not ln.startswith("-----"))


def key_hint(der: bytes) -> str:
    """What cosign writes in a bundle as the key's hint: the base64 of the DER's sha256 (measured)."""
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def _bundle_hint(bundle: Path) -> str:
    try:
        doc = json.loads(Path(bundle).read_text(encoding="utf-8"))
        return str(((doc.get("verificationMaterial") or {}).get("publicKey") or {}).get("hint") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def bundle_refusal(bundle: Path) -> str:
    """Why this bundle may not go in the repository — "" when it may: a signature and a key's hint,
    never a certificate (it names its holder), never a transparency log's entry."""
    try:
        doc = json.loads(Path(bundle).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"illisible ({e})"
    vm = doc.get("verificationMaterial") if isinstance(doc, dict) else None
    if not isinstance(vm, dict) or not (vm.get("publicKey") or {}).get("hint"):
        return "sans la clé qui l'a signé"
    if "certificate" in vm or "x509CertificateChain" in vm:
        return "il porte un certificat"
    if vm.get("tlogEntries"):
        return "il porte une entrée du journal de transparence"
    return ""


def verify_blob(path: Path, bundle: Path, pinned: str, cosign: Path, runner: Runner = run) -> None:
    """`path` signed by the key pinned (EREGION_HARNESS_KEY's value), the signature in `bundle`
    covering exactly these bytes — offline: no transparency log, no trust root. Raises Unverified,
    said; cosign is never asked without a key, a bundle and a cosign that is the pinned one."""
    der = key_der(pinned)
    if not Path(bundle).is_file():
        raise Unverified(f"{Path(path).name} n'est pas signée ({Path(bundle).name} absent)")
    if not cosign_ok(cosign):
        raise Unverified(f"cosign absent ou altéré ({cosign}) : il doit être {COSIGN_VERSION}, sha256 {COSIGN_SHA256[:12]}…")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="harness-key-") as tmp:
        pub = Path(tmp) / "harness.pub"          # 0600 in a 0700 directory, gone with it
        fd = os.open(pub, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pem_of(der))
        res = runner([str(cosign), "verify-blob", "--key", str(pub), "--bundle", str(bundle),
                      "--insecure-ignore-tlog", "--timeout", COSIGN_TIMEOUT, str(path)])
    if res.returncode == 0:
        return
    hint, want = _bundle_hint(bundle), key_hint(der)
    if hint and hint != want:
        raise Unverified(f"{Path(path).name} signée d'une autre clé (empreinte {hint[:12]}…, épinglée "
                         f"{want[:12]}…)", _last(res))
    raise Unverified(f"la signature de {Path(path).name} ne tient pas : elle ne couvre pas ce fichier, ou "
                     "elle est illisible", _last(res))


# cosign reads the private key's passphrase from COSIGN_PASSWORD when it is set (and from stdin when
# stdin is no terminal): exported in a shell, it would sign — or draw a key — without anything typed.
TYPED_ONLY = ("COSIGN_PASSWORD",)


def typed_env(environ=None) -> dict:
    """The environment cosign runs in for a gesture with the key: the passphrase never passed."""
    return {k: v for k, v in (os.environ if environ is None else environ).items() if k not in TYPED_ONLY}


def sign_blob(path: Path, key: Path, cosign: Path, runner: Runner | None = None) -> int:
    """Jonathan's gesture: `path` signed by his key (cosign asks its passphrase, typed: never from
    COSIGN_PASSWORD), offline, the bundle written beside it — kept only if it holds no certificate
    and no log entry. Without --yes: a cosign that would send anything still asks first."""
    if not Path(path).is_file():
        print(f"✗ {path} absent : make llm-compare … ATTEST=1 d'abord", file=sys.stderr)
        return 1
    if Path(key).is_symlink() or not Path(key).is_file():
        print(f"✗ {key} absent (ou un lien) : make harness-key d'abord", file=sys.stderr)
        return 1
    if not cosign_ok(cosign):
        print(f"✗ cosign absent ou altéré ({cosign}) : python3 scripts/published_image.py install-cosign",
              file=sys.stderr)
        return 1
    import tempfile
    bundle = bundle_of(Path(path))
    with tempfile.TemporaryDirectory(prefix="harness-sign-") as tmp:
        config = Path(tmp) / "no-services.json"
        config.write_text(NO_SERVICES)
        argv = [str(cosign), "sign-blob", "--key", str(key), "--signing-config", str(config),
                "--bundle", str(bundle), str(path)]
        res = (runner or (lambda a: subprocess.run(a, env=typed_env(), check=False)))(argv)
    if res.returncode != 0:
        print(f"✗ cosign sign-blob a échoué (code {res.returncode}) : rien n'est signé", file=sys.stderr)
        return 1
    why = bundle_refusal(bundle)
    if why:
        bundle.unlink(missing_ok=True)
        print(f"✗ le paquet de signature ne va pas dans le dépôt : {why} — retiré, rien n'est signé", file=sys.stderr)
        return 1
    print(f"✓ {path} signée : {bundle} — à commiter avec elle, dans la PR du verrou")
    return 0


def generate_key(dest: Path, cosign: Path, run_in=None, tty: bool | None = None) -> int:
    """`make harness-key`, once: the pair drawn by cosign in `dest` (its private half encrypted by
    the passphrase Jonathan types at a terminal; 0600), never over a key already there, never
    through a link, never under the repository. Prints the line to pin in host.env and the key's
    hint."""
    dest = Path(dest)
    if not (sys.stdin.isatty() if tty is None else tty):
        print("✗ pas de terminal : cosign lirait la phrase de passe sur l'entrée standard — lancer "
              "make harness-key dans un terminal, et taper la phrase (vide, la clé n'est pas protégée)",
              file=sys.stderr)
        return 1
    real = dest.resolve()
    if real == REPO.resolve() or REPO.resolve() in real.parents:
        print(f"✗ {dest} est dans le dépôt : la clé privée n'y va jamais (le défaut : ~/.config/eregion/harness)",
              file=sys.stderr)
        return 1
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        print(f"✗ {dest} n'est pas un répertoire (un lien ?) : rien n'est écrit", file=sys.stderr)
        return 1
    key, pub = dest / f"{KEY_PREFIX}.key", dest / f"{KEY_PREFIX}.pub"
    if os.path.lexists(key) or os.path.lexists(pub):
        print(f"✗ {key} ou {pub} existe déjà : une clé n'est jamais remplacée ici (la retirer d'abord, puis "
              "réépingler la nouvelle sur H0)", file=sys.stderr)
        return 1
    if not cosign_ok(cosign):
        print(f"✗ cosign absent ou altéré ({cosign}) : python3 scripts/published_image.py install-cosign",
              file=sys.stderr)
        return 1
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    res = (run_in or (lambda a, cwd: subprocess.run(a, cwd=cwd, env=typed_env(), check=False)))(
        [str(cosign), "generate-key-pair", "--output-key-prefix", KEY_PREFIX], dest)
    if res.returncode != 0 or not key.is_file() or not pub.is_file():
        print(f"✗ cosign generate-key-pair a échoué (code {res.returncode}) : aucune clé", file=sys.stderr)
        return 1
    os.chmod(key, 0o600)
    pinned = pinned_of_pem(pub.read_text(encoding="utf-8"))
    print(f"✓ la paire de l'attestation : {key} (privée, chiffrée, 0600), {pub}")
    print("  À épingler dans infra/glorfindel-host/host.env, puis make glorfindel-host-push :")
    print(f"{HARNESS_KEY_ENV}={pinned}")
    print(f"# empreinte : {key_hint(key_der(pinned))}")
    return 0


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


def install_syft(dest: Path) -> int:
    """syft, from its release archive kept only if its sha256 is the pinned one (R-14): the binary
    ``syft`` alone taken out of it, nothing else written."""
    import io
    import tarfile

    try:
        body, _ = _open(SYFT_URL, {}, SYFT_MAX)
    except urllib.error.HTTPError as e:
        print(f"✗ syft : HTTP {e.code}", file=sys.stderr)
        return 3
    got = hashlib.sha256(body).hexdigest()
    if got != SYFT_SHA256:
        print(f"✗ syft téléchargé : sha256 {got[:12]}…, pas {SYFT_SHA256[:12]}… — rien n'est installé",
              file=sys.stderr)
        return 1
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.name == "syft" and m.isfile()), None)
        if member is None:
            print("✗ syft : pas de binaire « syft » dans l'archive — rien n'est installé", file=sys.stderr)
            return 1
        binary = tar.extractfile(member).read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(binary)
    tmp.chmod(0o755)
    os.replace(tmp, dest)
    print(f"✓ {dest} : syft {SYFT_VERSION}, archive au sha256 vérifié")
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


# ── OI1: the archive, built from the registry's blobs ────────────────────────────────
# `docker save` of a pulled image, on the operator's Docker Desktop (its containerd image store),
# gave its index and its manifest, without config or layers (~10 KB for ~630 MB, measured on
# 03/11): Orodruin loaded an image it could not tag. The archive no longer comes from the
# operator's docker: each blob is read from the registry by its digest, under the manifest whose
# digest cosign proved, its sha256 and its size checked against that manifest before it enters.

class _NoAuthElsewhere(urllib.request.HTTPRedirectHandler):
    """GHCR answers a blob with a redirect to its storage (pkg-containers.githubusercontent.com):
    the registry's token never follows to another host, as docker's own client does."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_OPENER = urllib.request.build_opener(_NoAuthElsewhere)


def _descriptor(desc, what: str, types: set, limit: int) -> tuple[str, int]:
    """A descriptor of the manifest: its digest, its size — a media type expected, a size bounded."""
    if not isinstance(desc, dict):
        raise Unverified(f"manifeste illisible : {what}")
    digest, size, mtype = str(desc.get("digest") or ""), desc.get("size"), str(desc.get("mediaType") or "")
    if not DIGEST_RE.fullmatch(digest):
        raise Unverified(f"{what} sans digest sha256 lisible")
    if mtype not in types:
        shown = mtype if re.fullmatch(r"[a-z0-9.+/-]{1,100}", mtype) else "?"
        raise Unverified(f"{what} {digest[:19]}… : média inattendu ({shown})")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise Unverified(f"{what} {digest[:19]}… sans taille lisible")
    if size > limit:
        raise Unverified(f"{what} {digest[:19]}… démesurée : {size} octets (au plus {limit})")
    return digest, size


def blob(image: str, digest: str, size: int, dest: Path, token: Callable[[bool], str], api: str = "") -> None:
    """The blob `digest` read from the registry into `dest`: exactly `size` bytes, whose sha256 is
    `digest` — else `dest` is removed and the blob refused. `token(fresh)`: the anonymous token,
    asked again once if the registry no longer takes it (a long download)."""
    api = (api or REGISTRY_API).rstrip("/")
    url = f"{api}/v2/{repository(image)}/blobs/{digest}"
    h, got = hashlib.sha256(), 0
    for fresh in (False, True):
        req = urllib.request.Request(url, headers={"User-Agent": "eregion-published-image",
                                                   "Authorization": f"Bearer {token(fresh)}"})
        try:
            with _OPENER.open(req, timeout=60) as r, open(dest, "wb") as f:
                h, got = hashlib.sha256(), 0
                while True:
                    chunk = r.read(min(CHUNK, size + 1 - got))
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > size:
                        raise Unverified(f"blob {digest[:19]}… plus long que les {size} octets du manifeste")
                    h.update(chunk)
                    f.write(chunk)
            break
        except urllib.error.HTTPError as e:
            dest.unlink(missing_ok=True)
            if e.code == 401 and not fresh:
                continue
            if e.code == 404:
                raise Unverified(f"blob {digest[:19]}… absent du registre") from None
            if e.code in (401, 403):
                raise Unverified(f"blob {digest[:19]}… illisible sans jeton (HTTP {e.code})") from None
            raise Unavailable(f"registre : HTTP {e.code} pour le blob {digest[:19]}…") from None
        except Unverified:
            dest.unlink(missing_ok=True)
            raise
        except (urllib.error.URLError, OSError) as e:
            dest.unlink(missing_ok=True)
            raise Unavailable(f"blob {digest[:19]}… interrompu : {type(e).__name__}") from None
    if got != size:
        dest.unlink(missing_ok=True)
        raise Unverified(f"blob {digest[:19]}… de {got} octets, pas les {size} du manifeste")
    if "sha256:" + h.hexdigest() != digest:
        dest.unlink(missing_ok=True)
        raise Unverified(f"blob {digest[:19]}… : son empreinte est sha256:{h.hexdigest()[:12]}…, pas la sienne")


def _not_root(user: str) -> bool:
    """A user other than root: neither empty, nor `root`, nor a uid that is 0 (`0`, `00`, `000:0`)."""
    name = user.split(":", 1)[0].strip()
    if name.isdigit():
        return int(name) != 0
    return name not in ("", "root")


def _tag_names(tag: str) -> tuple[str, str]:
    """`name:tag` as docker's loader reads it in an OCI archive's index (docker save writes both)."""
    m = re.fullmatch(r"([a-z0-9][a-z0-9._-]{0,127}):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})", tag or "")
    if not m:
        raise Unverified(f"tag invalide : {tag!r}")
    return f"docker.io/library/{tag}", m.group(2)


def _member(tar, name: str, data: bytes = b"", path: Path | None = None) -> None:
    import io
    import tarfile

    info = tarfile.TarInfo(name)
    info.mode, info.mtime = 0o644, 0
    if path is None:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    else:
        info.size = path.stat().st_size
        with open(path, "rb") as f:
            tar.addfile(info, f)


def build_archive(image: str, digest: str, commit: str, tag: str, out: Path, api: str = "") -> dict:
    """The OCI archive of the linux/amd64 image under `digest` (a digest cosign proved), written
    as out/image.tar — `oci-layout`, `index.json` naming `tag`, docker's `manifest.json`, then
    `blobs/sha256/…`: the manifest's own bytes, its config, its layers — and what Orodruin must
    read back once it is loaded, as out/expect.json (returned). Every blob is checked by its
    sha256 and its size against the manifest before it enters; the config must name `commit` and
    a user other than root. Anything else: nothing is written, the cause said."""
    import tarfile

    name, short = _tag_names(tag)
    mdigest, doc, raw, mtype = platform_manifest(image, digest, api)
    if mtype not in MANIFEST_TYPES:
        shown = mtype if re.fullmatch(r"[a-z0-9.+/-]{1,100}", mtype) else "?"
        raise Unverified(f"manifeste {mdigest[:19]}… : média inattendu ({shown or 'aucun'})")
    cdigest, csize = _descriptor(doc.get("config"), "configuration", CONFIG_TYPES, CONFIG_MAX)
    layers = doc.get("layers")
    if not isinstance(layers, list) or not layers or len(layers) > LAYERS_MAX:
        raise Unverified(f"manifeste {mdigest[:19]}… : {len(layers) if isinstance(layers, list) else 'aucune'} "
                         f"couches (de 1 à {LAYERS_MAX})")
    descs = [_descriptor(d, "couche", LAYER_TYPES, LAYER_MAX) for d in layers]
    if sum(s for _, s in descs) > IMAGE_MAX:
        raise Unverified(f"image démesurée : {sum(s for _, s in descs)} octets de couches (au plus {IMAGE_MAX})")
    if len({d for d, _ in descs}) != len(descs) or cdigest in {d for d, _ in descs}:
        raise Unverified(f"manifeste {mdigest[:19]}… : un blob nommé deux fois")
    out.mkdir(parents=True, exist_ok=True)
    final, part, scratch = out / "image.tar", out / "image.tar.part", out / "blob.part"
    for p in (final, out / "expect.json"):
        p.unlink(missing_ok=True)
    held: dict = {}

    def token(fresh: bool) -> str:
        if fresh or "t" not in held:
            held["t"] = _token(image, (api or REGISTRY_API).rstrip("/"))
        return held["t"]

    try:
        blob(image, cdigest, csize, scratch, token, api)
        try:
            config = json.loads(scratch.read_bytes())
        except ValueError:
            raise Unverified(f"configuration {cdigest[:19]}… illisible") from None
        if not isinstance(config, dict) or not isinstance(config.get("config") or {}, dict):
            raise Unverified(f"configuration {cdigest[:19]}… illisible")
        cfg = config.get("config") or {}
        diff_ids = (config.get("rootfs") or {}).get("diff_ids") if isinstance(config.get("rootfs"), dict) else None
        if (not isinstance(diff_ids, list) or len(diff_ids) != len(descs)
                or not all(isinstance(x, str) and DIGEST_RE.fullmatch(x) for x in diff_ids)):
            raise Unverified(f"configuration {cdigest[:19]}… : ses couches ne sont pas celles du manifeste")
        if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
            raise Unverified(f"configuration {cdigest[:19]}… : pas une image linux/amd64")
        labels_ = cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else {}
        rev = str(labels_.get("org.opencontainers.image.revision") or "")
        if rev != commit:
            said = rev[:12] if COMMIT_RE.fullmatch(rev) else "?"
            raise Unverified(f"la configuration dit le commit {said}, pas {commit[:12]}", f"étiquette : {rev!r}"[:400])
        user = cfg.get("User") if isinstance(cfg.get("User"), str) else ""
        if not _not_root(user):
            raise Unverified("l'image tourne en root : refusée (les injecteurs, jamais root)")
        with tarfile.open(part, "w") as tar:
            _member(tar, f"blobs/sha256/{mdigest.split(':', 1)[1]}", raw)
            _member(tar, f"blobs/sha256/{cdigest.split(':', 1)[1]}", path=scratch)
            for d, s in descs:
                blob(image, d, s, scratch, token, api)
                _member(tar, f"blobs/sha256/{d.split(':', 1)[1]}", path=scratch)
            index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                     "manifests": [{"mediaType": mtype, "digest": mdigest, "size": len(raw),
                                    "annotations": {"io.containerd.image.name": name,
                                                    "org.opencontainers.image.ref.name": short}}]}
            legacy = [{"Config": f"blobs/sha256/{cdigest.split(':', 1)[1]}", "RepoTags": [tag],
                       "Layers": [f"blobs/sha256/{d.split(':', 1)[1]}" for d, _ in descs]}]
            _member(tar, "index.json", json.dumps(index).encode())
            _member(tar, "manifest.json", json.dumps(legacy).encode())
            _member(tar, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    finally:
        scratch.unlink(missing_ok=True)
    expect = {"image": image, "digest": digest, "manifest": mdigest, "config": cdigest, "commit": commit,
              "ids": sorted({digest, mdigest, cdigest}), "user": user, "diff_ids": diff_ids,
              "os": "linux", "architecture": "amd64"}
    os.replace(part, final)
    (out / "expect.json").write_text(json.dumps(expect, indent=1) + "\n", encoding="utf-8")
    return expect


def check_loaded(expect: dict, inspected: str, digest: str) -> None:
    """What docker says of the image loaded on Orodruin (`docker image inspect`, its JSON), read
    against what the proven manifest announced: its id (the manifest's, under containerd's store;
    its config's digest, under the classic store), the layers and the user of its config, its
    platform and its commit. An image without its config reads back without layers nor user (docker's
    API answers its id alone: the CLI applies -f on its side), or not at all: refused. The layers
    are unpacked or not, docker's inspect does not say it: the control run of make orodruin-push,
    after this and before the tag, proves them (OI2, #490)."""
    if expect.get("digest") != digest or not DIGEST_RE.fullmatch(digest or ""):
        raise Unverified(f"l'attendu n'est pas celui de {digest[:19]}…")
    ids_ = expect.get("ids") or []
    if not ids_ or not all(isinstance(x, str) and DIGEST_RE.fullmatch(x) for x in ids_):
        raise Unverified("l'attendu est illisible")
    try:
        doc = json.loads(inspected or "")
    except ValueError:
        doc = None
    if isinstance(doc, list) and len(doc) == 1:
        doc = doc[0]
    if not isinstance(doc, dict) or not doc:
        raise Unverified("l'image arrivée ne se relit pas (docker image inspect) : sa configuration ou ses "
                         "couches manquent")
    got = str(doc.get("Id") or "").strip()
    if got not in ids_:
        shown = got[:19] if DIGEST_RE.fullmatch(got) else "?"
        raise Unverified(f"l'image chargée ({shown}…) n'est pas {digest[:19]}…")
    cfg = doc.get("Config") if isinstance(doc.get("Config"), dict) else {}
    layers = (doc.get("RootFS") or {}).get("Layers") if isinstance(doc.get("RootFS"), dict) else None
    wrong = []
    if layers != expect.get("diff_ids"):
        wrong.append("ses couches")
    if (cfg.get("User") or "") != expect.get("user"):
        wrong.append("son utilisateur")
    if (doc.get("Os"), doc.get("Architecture")) != (expect.get("os"), expect.get("architecture")):
        wrong.append("sa plateforme")
    labels_ = cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else {}
    if (labels_.get("org.opencontainers.image.revision") or "") != expect.get("commit"):
        wrong.append("son commit")
    if wrong:
        raise Unverified(f"l'image chargée n'est pas celle du manifeste prouvé : {', '.join(wrong)}")


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


# ── OI3 (#522): the image in service on Orodruin, against the latest release ───────────────────
# What `make orodruin-push` writes in ~/.eregion-image once the image is tagged (« commit digest »),
# and `make orodruin-push-dev` (« dev commit ») — read back by ssh, in read-only, at most MARKER_MAX
# bytes. The latest release: the highest tag v* by version order (git's v:refname: v0.5.10 after
# v0.5.9), as orodruin-push takes it without REF. The image against it: by commit, in git's history
# (merge-base --is-ancestor), never by comparing two strings. Only an image provably older — its
# commit an ancestor of the release's —, absent or unreadable is replaced; one newer, built here
# (dev) or off the release's history is kept: never replaced unless asked.
MARKER_MAX = 4096
READ_MAX = 4400                                   # the labels' line and the marker (the Makefile's ORO_READ_MAX)
VERIFIED_MARK = re.compile(r"([0-9a-f]{40}) (sha256:[0-9a-f]{64})\n?")
DEV_MARK = re.compile(r"dev ([0-9a-f]{40})\n?")
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
REPLACED = ("older", "absent", "unreadable")      # what make orodruin-start pushes the release over


def _ancestor(a: str, b: str, runner: Runner = run) -> bool:
    """`a` in the history of `b` (git merge-base --is-ancestor: 0 yes, 1 no, else unreadable)."""
    res = runner(["git", "-C", str(REPO), "merge-base", "--is-ancestor", a, b])
    if res.returncode not in (0, 1):
        raise Unverified(f"git ne compare pas {a[:12]} et {b[:12]} (code {res.returncode})", _last(res))
    return res.returncode == 0


def version_of(commit: str, runner: Runner = run) -> str:
    """`commit` as a reader names it: its tag v* (the highest by version order), else its first
    twelve characters after the last tag v* in its history."""
    res = runner(["git", "-C", str(REPO), "tag", "--points-at", commit, "-l", "v*", "--sort=-v:refname"])
    tags = [t for t in (res.stdout.split() if res.returncode == 0 else []) if REF_RE.fullmatch(t)]
    if tags:
        return f"{tags[0]} ({commit[:12]})"
    res = runner(["git", "-C", str(REPO), "describe", "--tags", "--abbrev=0", "--match", "v*", commit])
    after = res.stdout.strip() if res.returncode == 0 else ""
    return f"{commit[:12]} (après {after})" if REF_RE.fullmatch(after) else commit[:12]


def labelled(line: str) -> str:
    """The revision in the labels docker read back from :orodruin (« version revision », either
    perhaps `<no value>` or empty): a full commit, or ""."""
    return next((w for w in (line or "").split() if COMMIT_RE.fullmatch(w)), "")


def image_age(marker: str | None, ref: str = "", image: bool = True, revision: str | None = None,
              runner: Runner = run) -> dict:
    """The image in service on Orodruin (`marker`: the text of its ~/.eregion-image, None when the
    file is absent; `image`: False when eregion-annatar:orodruin itself is absent; `revision`: the
    commit its tag's label says, "" when it says none, None when not read) against the latest
    release (or `ref`): {"state", "release", "release_commit", "said"}. state: equal, older, newer,
    dev, diverged (kept), absent, unreadable (replaced) — a verified marker whose tag says another
    commit is unreadable (a dev build loaded over it, its marker never written). Raises Unverified
    when the release, or the image's commit, cannot be read here — nothing is decided."""
    release = ref or latest_tag(runner)
    if not REF_RE.fullmatch(release):
        raise Unverified(f"release illisible : {release[:40]!r}")
    rcommit = commit_of(release, runner)
    named = f"{'dernière release' if not ref else 'release visée'} {release} ({rcommit[:12]})"
    out = {"release": release, "release_commit": rcommit}
    verified = VERIFIED_MARK.fullmatch(marker or "")
    dev = DEV_MARK.fullmatch(marker or "")
    if not image:
        return {**out, "state": "absent", "said": f"aucune image eregion-annatar:orodruin sur Orodruin, {named}"}
    if marker is None:
        return {**out, "state": "absent",
                "said": f"image sans ~/.eregion-image (un envoi coupé ?), {named}"}
    if dev:
        return {**out, "state": "dev",
                "said": f"image dev {dev.group(1)[:12]}, construite sur un poste, non vérifiée "
                        f"(make orodruin-push-dev), {named}"}
    if not verified:
        return {**out, "state": "unreadable", "said": f"~/.eregion-image illisible, {named}"}
    commit = verified.group(1)
    if revision is not None and revision != commit:
        said = revision[:12] if revision else "aucun commit"
        return {**out, "state": "unreadable",
                "said": f"~/.eregion-image dit {commit[:12]}, le tag eregion-annatar:orodruin {said} : "
                        f"illisible, {named}"}
    if commit == rcommit:
        return {**out, "state": "equal", "said": f"image {version_of(commit, runner)}, {named} : à jour"}
    known = runner(["git", "-C", str(REPO), "cat-file", "-e", f"{commit}^{{commit}}"])
    if known.returncode != 0:
        raise Unverified(f"le commit de l'image en service ({commit[:12]}) est inconnu ici : git fetch origin, "
                         f"ou make orodruin-push REF={release} pour la remplacer")
    said = f"image {version_of(commit, runner)}, {named}"
    if _ancestor(commit, rcommit, runner):
        return {**out, "state": "older", "said": f"{said} : plus ancienne"}
    if _ancestor(rcommit, commit, runner):
        return {**out, "state": "newer", "said": f"{said} : plus récente"}
    return {**out, "state": "diverged", "said": f"{said} : ni plus ancienne ni plus récente (hors de son histoire)"}


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
    p.add_argument("cmd", choices=["resolve", "verify", "fetch", "archive", "ids", "loaded", "age", "install-cosign",
                                   "install-syft", "meta", "pushed", "harness-key", "sign-blob", "verify-blob"])
    p.add_argument("image", nargs="?", default="")
    p.add_argument("--commit", default="")
    p.add_argument("--digest", default="")
    p.add_argument("--ref", default="")
    p.add_argument("--tag", default="")
    p.add_argument("--out", default="", help="archive: the directory of image.tar and expect.json")
    p.add_argument("--expect-file", default="", help="loaded: the expect.json `archive` wrote before the image left")
    p.add_argument("--inspect", default="", help="loaded: `docker image inspect` of the image arrived (a file, - for stdin)")
    p.add_argument("--read", default="", help="age: what Orodruin read back — the labels of :orodruin, a line, "
                                              "then its ~/.eregion-image")
    p.add_argument("--no-marker", action="store_true", help="age: ~/.eregion-image absent on Orodruin")
    p.add_argument("--no-image", action="store_true", help="age: eregion-annatar:orodruin absent on Orodruin")
    p.add_argument("--cosign", default="")
    p.add_argument("--key", default="", help="sign-blob: the private key (default: harness-key's)")
    p.add_argument("--pinned", default="", help="verify-blob: the key as host.env pins it (EREGION_HARNESS_KEY)")
    p.add_argument("--pub", default="", help="verify-blob: a cosign.pub (default: harness-key's)")
    a = p.parse_args(argv)
    cosign = Path(a.cosign) if a.cosign else default_cosign()
    try:
        if a.cmd == "harness-key":
            return generate_key(Path(a.image) if a.image else harness_key_dir(), cosign)
        if a.cmd == "sign-blob":
            key = Path(a.key) if a.key else harness_key_dir() / f"{KEY_PREFIX}.key"
            return sign_blob(Path(a.image), key, cosign, None if runner is run else runner)
        if a.cmd == "verify-blob":
            pub = Path(a.pub or harness_key_dir() / f"{KEY_PREFIX}.pub")
            if not a.pinned and not pub.is_file():
                print(f"✗ aucune clé à vérifier : {pub} absent — make harness-key, ou PINNED=<la valeur de "
                      f"{HARNESS_KEY_ENV} dans host.env> (make harness-verify PINNED=…)", file=sys.stderr)
                return 1
            pinned = a.pinned or pinned_of_pem(pub.read_text())
            verify_blob(Path(a.image), bundle_of(Path(a.image)), pinned, cosign, runner)
            print(f"✓ {a.image} : signée par la clé {key_hint(key_der(pinned))[:12]}…, la signature couvre ce fichier")
            return 0
        if a.cmd == "install-cosign":
            return install_cosign(Path(a.image) if a.image else cosign)
        if a.cmd == "install-syft":
            if not a.image:
                p.error("install-syft DEST")
            return install_syft(Path(a.image))
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
        elif a.cmd == "archive":
            if not a.out or not a.tag:
                p.error("archive IMAGE --ref REF --tag NAME --out DIR")
            ref = a.ref or latest_tag(runner)
            commit = commit_of(ref, runner)
            digest = resolve(a.image, commit)
            verify(a.image, digest, commit, cosign, runner=runner)
            expect = build_archive(a.image, digest, commit, a.tag, Path(a.out))
            print(f"✓ archive de {reference(a.image)}@{digest[:19]}… : son manifeste, sa configuration et ses "
                  f"{len(expect['diff_ids'])} couches, chacun vérifié par son sha256", file=sys.stderr)
            _output({"ref": ref, "commit": commit, "digest": digest})
        elif a.cmd == "loaded":
            if not a.expect_file or not a.inspect:
                p.error("loaded IMAGE --digest D --expect-file F --inspect J")
            try:
                expect = json.loads(Path(a.expect_file).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                expect = None
            if not isinstance(expect, dict):
                raise Unverified("attendu illisible (expect.json)")
            try:
                inspected = sys.stdin.read() if a.inspect == "-" else Path(a.inspect).read_text(encoding="utf-8")
            except (OSError, ValueError):
                inspected = ""
            check_loaded(expect, inspected, a.digest)
            print(f"✓ l'image chargée est {reference(a.image)}@{a.digest} : son id, ses couches, son utilisateur")
        elif a.cmd == "age":
            if bool(a.read) == a.no_image:
                p.error("age IMAGE (--read F [--no-marker] | --no-image) [--ref REF]")
            marker, revision = None, None
            if a.read:
                try:
                    with open(a.read, "rb") as f:
                        raw = f.read(READ_MAX + 1)
                    labels_, _, rest = raw.decode("utf-8").partition("\n")
                    revision = labelled(labels_)
                    marker = rest if len(raw) <= READ_MAX and len(rest.encode()) <= MARKER_MAX else "\0"
                except (OSError, UnicodeDecodeError):
                    marker = "\0"                 # unreadable: never taken for a commit
                if a.no_marker:
                    marker = None
            age = image_age(marker, a.ref, image=not a.no_image, revision=revision, runner=runner)
            print(("✓ " if age["state"] == "equal" else "  ") + age["said"], file=sys.stderr)
            _output({k: age[k] for k in ("state", "release", "release_commit")})
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
