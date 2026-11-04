"""CI3 (#267, step 2): scripts/published_image.py — the published image found by its digest and
proven by its signature and provenance (H0's CD, Orodruin's push, the publishing workflow).

A fake registry (tests/unit/fake_discord.py, under /registry, as GHCR answers anonymously), a
fake cosign (tests/unit/fake_sigstore.py, as cosign v3.1.3 answers: measured on 29/10 on public
images) and a fake docker as a runner. No network, no Docker, no registry written.
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from . import fake_oci
from .fake_discord import FakeDiscord
from .fake_sigstore import Sigstore, claims, envelope, statement

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "published_image.py"
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
C1, C2 = "1" * 40, "2" * 40
GLOR = "grootcyber/eregion-glorfindel"
ANNATAR = "grootcyber/eregion-annatar"


@pytest.fixture
def pim(monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location("published_image_t", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fake():
    f = FakeDiscord()
    yield f
    f.close()


@pytest.fixture
def reg(pim, fake, monkeypatch):
    monkeypatch.setattr(pim, "REGISTRY_API", f"{fake.base}/registry")
    return fake


@pytest.fixture
def sig(pim, tmp_path, monkeypatch):
    s = Sigstore(tmp_path / "cosign", tmp_path / "cosign.json", tmp_path / "cosign.log")
    monkeypatch.setattr(pim, "COSIGN_SHA256", s.sha256)
    for k, v in s.env().items():
        monkeypatch.setenv(k, v)
    return s


def _done(argv, code=0, out="", err=""):
    return subprocess.CompletedProcess(argv, code, out, err)


def _manifest(commit, n=0):
    return {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": "sha256:" + hashlib.sha256(f"config {commit} {n}".encode()).hexdigest()}, "n": n}


# ── the registry: a tag is a hint, the bytes are the digest ─────────────────────────────────────

def test_the_digest_is_the_sha256_of_the_manifest_read(pim, reg):
    digest = reg.image(GLOR, f"sha-{C2}", _manifest(C2))
    assert pim.resolve("glorfindel", C2) == digest
    tokened = [r for r in reg.requests if "/registry/token" in r["path"]]
    assert tokened and "scope=repository:grootcyber/eregion-glorfindel:pull" in tokened[0]["path"]


@pytest.mark.parametrize("setup, said", [
    (lambda r, d: r.registry[GLOR]["tags"].clear(), "aucune image"),
    (lambda r, d: r.registry_private.add(GLOR), "doit être public"),
    (lambda r, d: r.registry_lie.update({d: "sha256:" + "0" * 64}), "pour un manifeste de"),
])
def test_a_tag_the_registry_does_not_give_as_published_is_unverified(pim, reg, setup, said):
    digest = reg.image(GLOR, f"sha-{C2}", _manifest(C2))
    setup(reg, digest)
    with pytest.raises(pim.Unverified, match=said):
        pim.resolve("glorfindel", C2)


def test_a_manifest_read_by_its_digest_must_be_that_digest(pim, reg):
    digest = reg.image(GLOR, None, _manifest(C2))
    other = "sha256:" + "9" * 64
    reg.registry[GLOR]["blobs"][other] = reg.registry[GLOR]["blobs"][digest]
    with pytest.raises(pim.Unverified, match="pour un manifeste de"):     # its header says `other`
        pim.manifest("glorfindel", other)
    reg.registry_lie[other] = digest                                     # a header that agrees with the bytes
    with pytest.raises(pim.Unverified, match="n'est pas"):
        pim.manifest("glorfindel", other)


@pytest.mark.parametrize("private", [True, False])
def test_a_private_or_absent_package_is_refused_at_its_token(pim, reg, private):
    """GHCR answers 403 at the anonymous token for a private package or one that does not exist
    (measured, review of CI3): a refusal, never a wait without end."""
    if private:
        reg.image(GLOR, f"sha-{C2}", _manifest(C2))
        reg.registry_private.add(GLOR)
    with pytest.raises(pim.Unverified, match="doit être public, ou n'existe pas"):
        pim.resolve("glorfindel", C2)
    assert not [r for r in reg.requests if "/manifests/" in r["path"]]


def test_a_digest_header_that_is_no_digest_is_never_quoted(pim, reg):
    digest = reg.image(GLOR, f"sha-{C2}", _manifest(C2))
    reg.registry_lie[digest] = "[x](https://evil.example) @everyone"
    with pytest.raises(pim.Unverified) as e:
        pim.resolve("glorfindel", C2)
    assert "en-tête illisible" in str(e.value) and "evil" not in str(e.value)


def test_a_registry_that_does_not_answer_is_unavailable_not_refused(pim, monkeypatch):
    monkeypatch.setattr(pim, "REGISTRY_API", "http://127.0.0.1:9")
    with pytest.raises(pim.Unavailable):
        pim.resolve("glorfindel", C2)


@pytest.mark.parametrize("commit", ["main", "2" * 39, "G" * 40, "", "2" * 40 + "\n"])
def test_only_a_full_commit_is_resolved(pim, reg, commit):
    with pytest.raises(pim.Unverified, match="commit invalide"):
        pim.resolve("glorfindel", commit)


def test_the_ids_of_an_image_are_its_digest_its_amd64_manifest_and_its_config(pim, reg):
    amd = _manifest(C2, 1)
    amd_digest = reg.image(GLOR, None, amd)
    arm = reg.image(GLOR, None, _manifest(C2, 2))
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"digest": arm, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": amd_digest, "platform": {"os": "linux", "architecture": "amd64"}}]}
    top = reg.image(GLOR, f"sha-{C2}", index)
    assert pim.ids("glorfindel", top) == {top, amd_digest, amd["config"]["digest"]}
    single = reg.image(GLOR, None, _manifest(C1))
    assert pim.ids("glorfindel", single) == {single, _manifest(C1)["config"]["digest"]}


# ── the proof: cosign asked for every claim, then the provenance read again ────────────────────

def test_cosign_is_asked_for_every_claim_of_the_publishing_workflow(pim):
    for kind in ("signature", "provenance"):
        args = pim.cosign_args(kind, "ghcr.io/x@sha256:" + "a" * 64, C2, "grootcyber/eregion")
        got = {args[i]: args[i + 1] for i, a in enumerate(args) if a.startswith("--certificate")}
        assert got == {
            "--certificate-identity": "https://github.com/grootcyber/eregion/.github/workflows/publish.yml@refs/heads/main",
            "--certificate-oidc-issuer": "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-repository": "grootcyber/eregion",
            "--certificate-github-workflow-ref": "refs/heads/main",
            "--certificate-github-workflow-trigger": "push", "--certificate-github-workflow-sha": C2}
        assert args[-1].startswith("ghcr.io/x@sha256:")
    assert pim.cosign_args("provenance", "r", C2)[:3] == ["verify-attestation", "--type", "https://slsa.dev/provenance/v1"]
    assert pim.cosign_args("signature", "r", C2)[0] == "verify"


def _signed(pim, sig, digest, commit=C2, slug="grootcyber/eregion", **over):
    name = f"ghcr.io/{GLOR}"
    sig.publish(name, digest, slug, commit, **over)


def test_an_image_signed_and_attested_by_the_publishing_workflow_at_its_commit_is_verified(pim, sig):
    digest = "sha256:" + "a" * 64
    _signed(pim, sig, digest)
    pim.verify("glorfindel", digest, C2, sig.path)
    assert [c[0] for c in sig.calls()] == ["verify", "verify-attestation"]


@pytest.mark.parametrize("over, said", [
    ({"workflow": ".github/workflows/images.yml"}, "signature absente, ou d'un autre"),
    ({"ref": "refs/heads/side"}, "signature absente, ou d'un autre"),
    ({"trigger": "workflow_dispatch"}, "signature absente, ou d'un autre"),
    ({"sha": C1}, "signature absente, ou d'un autre"),
    ({"slug": "grootcyber/fork"}, "signature absente, ou d'un autre"),
])
def test_an_image_signed_by_another_signer_is_unverified(pim, sig, over, said):
    digest = "sha256:" + "a" * 64
    slug = over.pop("slug", "grootcyber/eregion")
    _signed(pim, sig, digest, slug=slug, **over)
    with pytest.raises(pim.Unverified, match=said) as e:
        pim.verify("glorfindel", digest, C2, sig.path)
    assert "expected" in e.value.detail               # cosign's words, for the journal


def test_an_unsigned_image_is_unverified_and_its_provenance_never_asked(pim, sig):
    with pytest.raises(pim.Unverified, match="signature absente"):
        pim.verify("glorfindel", "sha256:" + "a" * 64, C2, sig.path)
    assert [c[0] for c in sig.calls()] == ["verify"]


def test_a_signature_over_another_digest_is_unverified(pim, sig):
    digest = "sha256:" + "a" * 64
    _signed(pim, sig, digest)
    sig.data["signed_digest"][digest] = "sha256:" + "b" * 64
    sig.save()
    with pytest.raises(pim.Unverified, match="ne porte pas sur ce digest"):
        pim.verify("glorfindel", digest, C2, sig.path)


def test_an_image_attested_but_never_signed_is_unverified(pim, sig):
    """cosign v3's `verify` takes an attestation's bundle for a signature (measured on 29/10: an
    image attested, never signed, verified with type …/provenance/v1): a signature is sign/v1."""
    digest = "sha256:" + "a" * 64
    _signed(pim, sig, digest)
    sig.data["signed_type"][digest] = "https://slsa.dev/provenance/v1"
    sig.save()
    with pytest.raises(pim.Unverified, match="seule une attestation"):
        pim.verify("glorfindel", digest, C2, sig.path)


@pytest.mark.parametrize("kind", ["network", "timeout"])
def test_a_cosign_that_could_not_reach_sigstore_proves_nothing_either_way(pim, sig, monkeypatch, kind):
    """Review of CI3, measured: sigstore's TUF mirror out of reach, cosign exits 1 even with its
    cache filled — a wait, never a refusal; a cut at its bound too, whatever it printed."""
    digest = "sha256:" + "a" * 64
    _signed(pim, sig, digest)
    if kind == "network":
        monkeypatch.setenv("FAKE_COSIGN_NETWORK", "1")
        runner = pim.run
    else:
        def runner(argv):
            return _done(argv, pim.TIMEOUT_CODE, "", "expected nothing: timeout: cut after 600 s")
    with pytest.raises(pim.Unavailable, match="rien pu prouver") as e:
        pim.verify("glorfindel", digest, C2, sig.path, runner=runner)
    assert ("TUF" if kind == "network" else "timeout") in e.value.detail


@pytest.mark.parametrize("said", ["Error: no signatures found", "Error: no matching signatures: x",
                                  "Error: no matching attestations: ",
                                  "Error: none of the attestations matched the predicate type: x",
                                  "failed to verify certificate identity", 'expected SAN value "x", got "y"'])
def test_what_cosign_says_of_an_absent_or_other_signature_is_a_refusal(pim, said):
    assert isinstance(pim._cosign_failed(_done([], 1, "", said), "signature"), pim.Unverified)
    assert isinstance(pim._cosign_failed(_done([], 1, "", "unexpected EOF"), "signature"), pim.Unavailable)


def test_a_tool_cut_at_its_bound_is_code_124(pim):
    res = pim.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
    assert res.returncode == pim.TIMEOUT_CODE and "timeout" in res.stderr
    assert pim.cosign_args("signature", "r", C2)[-3:] == ["--timeout", "3m", "r"]


def test_a_signed_image_without_provenance_is_unverified(pim, sig):
    digest = "sha256:" + "a" * 64
    sig.sign(digest, claims("grootcyber/eregion", C2))
    with pytest.raises(pim.Unverified, match="provenance absente"):
        pim.verify("glorfindel", digest, C2, sig.path)


@pytest.mark.parametrize("cosign", ["missing", "altered"])
def test_a_cosign_that_is_not_the_pinned_one_is_never_run(pim, sig, cosign):
    digest = "sha256:" + "a" * 64
    _signed(pim, sig, digest)
    if cosign == "missing":
        sig.path.unlink()
    else:
        sig.path.write_text(sig.path.read_text() + "\n# altered\n")
    with pytest.raises(pim.Unverified, match="cosign absent ou altéré"):
        pim.verify("glorfindel", digest, C2, sig.path)
    assert sig.calls() == []


def _st(**over):
    name = over.pop("name", f"ghcr.io/{GLOR}")
    digest = over.pop("digest", "sha256:" + "a" * 64)
    return statement(name, digest, over.pop("slug", "grootcyber/eregion"), over.pop("commit", C2), **over)


@pytest.mark.parametrize("st, said", [
    (_st(predicate_type="https://spdx.dev/Document/v2.3"), "autre type"),
    (_st(name="ghcr.io/grootcyber/eregion-annatar"), "ne porte pas sur"),
    (_st(digest="sha256:" + "b" * 64), "ne porte pas sur"),
    (_st(workflow=".github/workflows/images.yml"), "workflow"),
    (_st(slug="grootcyber/fork"), "dépôt"),
    (_st(ref="refs/heads/side"), "référence"),
    (_st(event="workflow_dispatch"), "événement"),
    (_st(runner="self-hosted"), "runner"),
    (_st(commit=C1), "autre commit"),
])
def test_a_provenance_that_says_otherwise_is_unverified(pim, st, said):
    with pytest.raises(pim.Unverified, match=said):
        pim.check_provenance(st, "glorfindel", "sha256:" + "a" * 64, C2)


def test_a_provenance_of_two_commits_is_unverified(pim):
    st = _st()
    st["predicate"]["buildDefinition"]["resolvedDependencies"].append({"digest": {"gitCommit": C1}})
    with pytest.raises(pim.Unverified, match="autre commit"):
        pim.check_provenance(st, "glorfindel", "sha256:" + "a" * 64, C2)


def test_every_provenance_cosign_returns_is_read(pim, sig):
    """Two attestations verified, one of them of another commit: refused (none is skipped)."""
    digest = "sha256:" + "a" * 64
    good = claims("grootcyber/eregion", C2)

    def runner(argv):
        if argv[1] == "verify":
            return _done(argv, 0, json.dumps([{"critical": {"image": {"docker-manifest-digest": digest},
                                                            "type": "https://sigstore.dev/cosign/sign/v1"}}]))
        return _done(argv, 0, envelope(_st()) + "\n" + envelope(_st(commit=C1)) + "\n")
    with pytest.raises(pim.Unverified, match="autre commit"):
        pim.verify("glorfindel", digest, C2, sig.path, runner=runner)
    assert good


# ── pulled by its digest ───────────────────────────────────────────────────────────────────────

class Docker:
    """A fake docker as a runner: images by reference; every call kept."""

    def __init__(self, labels):
        self.images, self.calls, self.labels = {}, [], labels

    def __call__(self, argv):
        self.calls.append(argv)
        cmd = argv[1]
        if cmd == "pull":
            self.images[argv[-1]] = dict(self.labels)
            return _done(argv)
        if cmd == "tag":
            self.images[argv[3]] = dict(self.images[argv[2]])
            return _done(argv)
        if argv[1:3] == ["image", "rm"]:
            self.images.pop(argv[3], None)
            return _done(argv)
        if argv[1:3] == ["image", "inspect"]:
            img = self.images.get(argv[-1])
            return _done(argv, 0, f"{img['version']} {img['revision']}\n") if img else _done(argv, 1)
        if cmd == "push":
            return _done(argv)
        raise AssertionError(argv)


def test_the_image_is_pulled_by_its_digest_tagged_and_its_digest_reference_dropped(pim):
    docker = Docker({"version": "v0.4.6", "revision": C2})
    digest = "sha256:" + "a" * 64
    pim.pull("glorfindel", digest, "eregion-glorfindel:v0.4.6", C2, version="v0.4.6", runner=docker)
    ref = f"ghcr.io/{GLOR}@{digest}"
    assert docker.calls[:3] == [["docker", "pull", "-q", ref], ["docker", "tag", ref, "eregion-glorfindel:v0.4.6"],
                                ["docker", "image", "rm", ref]]
    assert set(docker.images) == {"eregion-glorfindel:v0.4.6"}


@pytest.mark.parametrize("labels", [{"version": "v0.4.6", "revision": C1}, {"version": "v0.4.5", "revision": C2}])
def test_an_image_whose_labels_name_another_commit_or_version_is_removed_and_unverified(pim, labels):
    docker = Docker(labels)
    with pytest.raises(pim.Unverified, match="l'image dit"):
        pim.pull("glorfindel", "sha256:" + "a" * 64, "eregion-glorfindel:v0.4.6", C2, version="v0.4.6",
                 runner=docker)
    assert docker.images == {}


def test_a_failed_pull_is_unavailable_its_words_in_the_detail_only(pim):
    with pytest.raises(pim.Unavailable) as e:
        pim.pull("glorfindel", "sha256:" + "a" * 64, "x", C2,
                 runner=lambda argv: _done(argv, 1, "", "[x](https://evil.example) network"))
    assert "evil" not in str(e.value) and "evil" in e.value.detail


def test_labels_that_are_no_label_of_ours_are_never_quoted(pim):
    docker = Docker({"version": "[x](https://evil.example)", "revision": "@everyone"})
    with pytest.raises(pim.Unverified) as e:
        pim.pull("glorfindel", "sha256:" + "a" * 64, "n", C2, version="v0.4.6", runner=docker)
    assert "evil" not in str(e.value) and "everyone" not in str(e.value) and "evil" in e.value.detail


# ── OI1 (#488): the archive, built from the registry's blobs ──────────────────────────────────

def _archive(pim, reg, tmp_path, image=None, tag="eregion-annatar:incoming"):
    image = image or fake_oci.Image(C2)
    digest = image.publish(reg, ANNATAR, f"sha-{C2}")
    return image, pim.build_archive("annatar", digest, C2, tag, tmp_path / "out")


def _members(path):
    import tarfile
    with tarfile.open(path) as t:
        return {m.name: t.extractfile(m).read() for m in t.getmembers()}


def _blob_requests(reg):
    return [r for r in reg.requests if "/blobs/" in r["path"] or "/registry-cdn/" in r["path"]]


@pytest.mark.parametrize("oci", [False, True])
def test_the_archive_holds_the_manifest_its_config_and_its_layers_each_under_its_sha256(pim, reg, tmp_path, oci):
    image, expect = _archive(pim, reg, tmp_path, fake_oci.Image(C2, oci=oci))
    got = _members(tmp_path / "out" / "image.tar")
    blobs = {n: data for n, data in got.items() if n.startswith("blobs/sha256/")}
    assert set(blobs) == {f"blobs/sha256/{d.split(':', 1)[1]}" for d in image.blobs}
    assert all(hashlib.sha256(data).hexdigest() == n.rsplit("/", 1)[1] for n, data in blobs.items())
    index = json.loads(got["index.json"])
    assert index["manifests"] == [{"mediaType": image.manifest["mediaType"], "digest": image.digest,
                                   "size": len(image.raw), "annotations": {
                                       "io.containerd.image.name": "docker.io/library/eregion-annatar:incoming",
                                       "org.opencontainers.image.ref.name": "incoming"}}]
    assert json.loads(got["manifest.json"]) == [{
        "Config": f"blobs/sha256/{image.config_digest.split(':', 1)[1]}", "RepoTags": ["eregion-annatar:incoming"],
        "Layers": [f"blobs/sha256/{d.split(':', 1)[1]}" for d in image.layers]}]
    assert json.loads(got["oci-layout"]) == {"imageLayoutVersion": "1.0.0"}
    assert expect == json.loads((tmp_path / "out" / "expect.json").read_text())
    assert expect["ids"] == sorted({image.digest, image.config_digest})
    assert (expect["user"], expect["diff_ids"], expect["commit"]) == ("app", image.diff_ids, C2)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["expect.json", "image.tar"]


@pytest.mark.parametrize("store", ["containerd", "classic"])
def test_the_archive_loads_whole_and_reads_back_as_the_proven_manifest(pim, reg, tmp_path, store):
    """docker load of the archive, both stores (tests/unit/fake_oci.py): its id, its layers, its
    user and its commit read back by `docker image inspect` are the manifest's."""
    import os
    image, expect = _archive(pim, reg, tmp_path)
    env = {**os.environ, "DOCKER_STATE": str(tmp_path / "docker"), "FAKE_STORE": store}
    fake = [sys.executable, fake_oci.__file__, "docker"]
    res = subprocess.run([*fake, "load"], input=(tmp_path / "out" / "image.tar").read_bytes(), env=env,
                         capture_output=True, timeout=60)
    assert res.returncode == 0, res.stderr
    inspected = subprocess.run([*fake, "image", "inspect", "eregion-annatar:incoming"], env=env, capture_output=True,
                               text=True, timeout=60).stdout
    pim.check_loaded(expect, inspected, image.digest)
    assert json.loads(inspected)[0]["Id"] == (image.digest if store == "containerd" else image.config_digest)


def test_an_index_gives_its_linux_amd64_manifest_and_only_its_blobs(pim, reg, tmp_path):
    amd, arm = fake_oci.Image(C2), fake_oci.Image(C2, salt="arm", os_arch=("linux", "arm64"))
    amd.publish(reg, ANNATAR, None)
    arm.publish(reg, ANNATAR, None)
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {"digest": arm.digest, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": amd.digest, "platform": {"os": "linux", "architecture": "amd64"}}]}
    top = reg.image(ANNATAR, f"sha-{C2}", index)
    expect = pim.build_archive("annatar", top, C2, "eregion-annatar:incoming", tmp_path / "out")
    assert expect["manifest"] == amd.digest and expect["ids"] == sorted({top, amd.digest, amd.config_digest})
    fetched = {r["path"].rsplit("/", 1)[1] for r in _blob_requests(reg)}
    assert fetched == {amd.config_digest, *amd.layers}
    assert json.loads(_members(tmp_path / "out" / "image.tar")["index.json"])["manifests"][0]["digest"] == amd.digest


def _refused(pim, reg, tmp_path, image, said, before_any_blob=False):
    digest = image.publish(reg, ANNATAR, f"sha-{C2}")
    with pytest.raises(pim.Unverified, match=said):
        pim.build_archive("annatar", digest, C2, "eregion-annatar:incoming", tmp_path / "out")
    left = sorted(p.name for p in (tmp_path / "out").iterdir()) if (tmp_path / "out").exists() else []
    assert left == []                                     # no archive, no expectation, no part
    if before_any_blob:
        assert _blob_requests(reg) == []


def test_a_layer_altered_in_the_registry_is_refused_by_its_sha256(pim, reg, tmp_path):
    image = fake_oci.Image(C2)
    reg_blobs = reg.registry.setdefault(ANNATAR, {"tags": {}, "blobs": {}})["blobs"]
    image.publish(reg, ANNATAR, f"sha-{C2}")
    reg_blobs[image.layers[0]] = bytes(len(image.blobs[image.layers[0]]))
    with pytest.raises(pim.Unverified, match="son empreinte est"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == []


@pytest.mark.parametrize("which", ["config", "layer"])
def test_a_blob_missing_from_the_registry_is_refused(pim, reg, tmp_path, which):
    image = fake_oci.Image(C2)
    image.publish(reg, ANNATAR, f"sha-{C2}")
    del reg.registry[ANNATAR]["blobs"][image.config_digest if which == "config" else image.layers[-1]]
    with pytest.raises(pim.Unverified, match="absent du registre"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == []


def test_a_blob_longer_or_shorter_than_its_descriptor_is_refused(pim, reg, tmp_path):
    image = fake_oci.Image(C2)
    image.publish(reg, ANNATAR, f"sha-{C2}")
    reg.registry[ANNATAR]["blobs"][image.layers[0]] += b"tail"
    with pytest.raises(pim.Unverified, match="plus long que"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")
    reg.registry[ANNATAR]["blobs"][image.layers[0]] = image.blobs[image.layers[0]][:-4]
    with pytest.raises(pim.Unverified, match="pas les"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")


@pytest.mark.parametrize("where", ["layer", "config", "all"])
def test_a_size_out_of_bounds_is_refused_before_a_byte_is_fetched(pim, reg, tmp_path, monkeypatch, where):
    image = fake_oci.Image(C2)
    if where == "layer":
        image.manifest["layers"][0]["size"] = pim.LAYER_MAX + 1
    elif where == "config":
        image.manifest["config"]["size"] = pim.CONFIG_MAX + 1
    else:
        monkeypatch.setattr(pim, "IMAGE_MAX", sum(d["size"] for d in image.manifest["layers"]) - 1)
    image.seal()
    _refused(pim, reg, tmp_path, image, "démesurée", before_any_blob=True)


@pytest.mark.parametrize("spoil, said", [
    (lambda m: m["layers"][0].update(mediaType="application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"),
     "média inattendu"),
    (lambda m: m["config"].update(mediaType="application/vnd.example.evil+json"), "média inattendu"),
    (lambda m: m.update(mediaType="application/vnd.docker.distribution.manifest.v1+json"), "média inattendu"),
    (lambda m: m["layers"][0].update(digest="sha512:" + "a" * 128), "sans digest sha256"),
    (lambda m: m["layers"][0].update(size="12"), "sans taille lisible"),
    (lambda m: m.update(layers=[]), "couches"),
    (lambda m: m["layers"].append(dict(m["layers"][0])), "nommé deux fois"),
])
def test_a_manifest_that_is_not_one_of_ours_is_refused_before_a_byte_is_fetched(pim, reg, tmp_path, spoil, said):
    image = fake_oci.Image(C2)
    spoil(image.manifest)
    image.seal()
    _refused(pim, reg, tmp_path, image, said, before_any_blob=True)


@pytest.mark.parametrize("image, said", [
    (lambda: fake_oci.Image(C1), "dit le commit 111111111111"),
    (lambda: fake_oci.Image(C2, user="root"), "en root"),
    (lambda: fake_oci.Image(C2, user=""), "en root"),
    (lambda: fake_oci.Image(C2, user="0:0"), "en root"),
    (lambda: fake_oci.Image(C2, user="00"), "en root"),
    (lambda: fake_oci.Image(C2, user="000:0"), "en root"),
    (lambda: fake_oci.Image(C2, user="root:app"), "en root"),
    (lambda: fake_oci.Image(C2, os_arch=("linux", "arm64")), "linux/amd64"),
])
def test_a_config_that_says_otherwise_is_refused(pim, reg, tmp_path, image, said):
    _refused(pim, reg, tmp_path, image(), said)


def test_the_registrys_token_never_follows_a_redirect_to_another_host(pim, reg, tmp_path):
    """GHCR answers a blob by a redirect to its storage: the archive is built, the storage never
    sees the registry's token (as docker's own client)."""
    reg.registry_redirect = True
    image, expect = _archive(pim, reg, tmp_path)
    cdn = [r for r in reg.requests if r["path"].startswith("/registry-cdn/")]
    assert len(cdn) == 1 + len(image.layers)
    assert not [r for r in cdn if "Authorization" in r["headers"]]
    assert expect["config"] == image.config_digest


def test_the_registrys_token_never_follows_a_manifest_redirected_to_another_host(pim, reg, tmp_path):
    """The manifests too (the relecture of OI1): read through the same opener as the blobs."""
    reg.registry_redirect_manifests = True
    image = fake_oci.Image(C2)
    digest = image.publish(reg, ANNATAR, f"sha-{C2}")
    assert pim.resolve("annatar", C2) == digest
    cdn = [r for r in reg.requests if r["path"].startswith("/registry-cdn/")]
    assert len(cdn) == 1 and "Authorization" not in cdn[0]["headers"]


@pytest.mark.parametrize("user, ok", [("app", True), ("1000", True), ("1000:1000", True), ("app:0", True),
                                      ("0", False), ("00", False), ("000:0", False), ("root", False),
                                      ("root:1000", False), ("", False), (" 0", False)])
def test_root_is_root_whatever_its_spelling(pim, user, ok):
    assert pim._not_root(user) is ok


def test_a_token_the_registry_no_longer_takes_is_asked_again_once(pim, reg, tmp_path):
    image = fake_oci.Image(C2)
    image.publish(reg, ANNATAR, f"sha-{C2}")
    prefix = f"/registry/v2/{ANNATAR}/blobs/{image.layers[1]}"
    reg.fail[prefix] = 401
    reg.once.add(prefix)
    pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")
    # the manifest's, the blobs', then the blobs' asked again
    assert len([r for r in reg.requests if r["path"].startswith("/registry/token")]) == 3
    reg.fail[prefix] = 401                                   # every time: refused
    reg.once.discard(prefix)
    with pytest.raises(pim.Unverified, match="illisible sans jeton"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")


def test_a_registry_that_breaks_off_proves_nothing(pim, reg, tmp_path):
    image = fake_oci.Image(C2)
    image.publish(reg, ANNATAR, f"sha-{C2}")
    reg.fail[f"/registry/v2/{ANNATAR}/blobs/"] = 502
    with pytest.raises(pim.Unavailable, match="HTTP 502"):
        pim.build_archive("annatar", image.digest, C2, "eregion-annatar:incoming", tmp_path / "out")


@pytest.mark.parametrize("tag", ["Eregion:incoming", "eregion-annatar", "x:y;rm", ""])
def test_only_a_plain_tag_names_the_archive(pim, reg, tmp_path, tag):
    with pytest.raises(pim.Unverified, match="tag invalide"):
        _archive(pim, reg, tmp_path, tag=tag)


# ── OI1: what Orodruin reads back, against the proven manifest ─────────────────────────────────

def _expect(image, top=None):
    top = top or image.digest
    return {"image": "annatar", "digest": top, "manifest": image.digest, "config": image.config_digest, "commit": C2,
            "ids": sorted({top, image.digest, image.config_digest}), "user": "app", "diff_ids": image.diff_ids,
            "os": "linux", "architecture": "amd64"}


def _inspected(image, **over):
    doc = {"Id": image.digest, "Os": "linux", "Architecture": "amd64",
           "Config": {"User": "app", "Labels": {"org.opencontainers.image.revision": C2}},
           "RootFS": {"Type": "layers", "Layers": list(image.diff_ids)}}
    for k, v in over.items():
        if k in ("User", "Labels"):
            doc["Config"][k] = v
        elif k == "Layers":
            doc["RootFS"]["Layers"] = v
        else:
            doc[k] = v
    return json.dumps([doc])


def test_an_image_read_back_as_its_manifest_announces_is_loaded(pim):
    image = fake_oci.Image(C2)
    pim.check_loaded(_expect(image), _inspected(image), image.digest)
    pim.check_loaded(_expect(image), _inspected(image, Id=image.config_digest), image.digest)     # classic store


@pytest.mark.parametrize("over, said", [
    ({"Id": "sha256:" + "f" * 64}, "n'est pas"),
    ({"Layers": []}, "ses couches"),
    ({"User": "root"}, "son utilisateur"),
    ({"Architecture": "arm64"}, "sa plateforme"),
    ({"Labels": {"org.opencontainers.image.revision": C1}}, "son commit"),
])
def test_an_image_read_back_otherwise_is_refused(pim, over, said):
    image = fake_oci.Image(C2)
    with pytest.raises(pim.Unverified, match=said):
        pim.check_loaded(_expect(image), _inspected(image, **over), image.digest)


@pytest.mark.parametrize("partial", [{"Config": None, "RootFS": {"Type": "layers"}}, {}, {"Config": {}}])
def test_an_image_without_its_config_reads_back_without_layers_nor_user_and_is_refused(pim, partial):
    """docker's API answers the image without its config by its id alone (the CLI applies -f on its
    side: `-f {{.Id}}` answered, #488): no layers, no user — refused."""
    image = fake_oci.Image(C2)
    with pytest.raises(pim.Unverified, match="ses couches, son utilisateur"):
        pim.check_loaded(_expect(image), json.dumps([{"Id": image.digest, **partial}]), image.digest)


@pytest.mark.parametrize("inspected", ["", "[]", "not json", '[{"Id": 1}, {"Id": 2}]'])
def test_an_image_that_cannot_be_read_back_is_refused(pim, inspected):
    """docker image inspect of an image without its config fails, and says `[]` (#488)."""
    image = fake_oci.Image(C2)
    with pytest.raises(pim.Unverified, match="ne se relit pas"):
        pim.check_loaded(_expect(image), inspected, image.digest)


def test_an_expectation_of_another_digest_is_refused(pim):
    image = fake_oci.Image(C2)
    with pytest.raises(pim.Unverified, match="l'attendu"):
        pim.check_loaded(_expect(image), _inspected(image), "sha256:" + "e" * 64)
    with pytest.raises(pim.Unverified, match="illisible"):
        pim.check_loaded({**_expect(image), "ids": ["x"]}, _inspected(image), image.digest)


def test_loaded_on_the_command_line(pim, tmp_path, capsys):
    image = fake_oci.Image(C2)
    (tmp_path / "expect.json").write_text(json.dumps(_expect(image)))
    (tmp_path / "good.json").write_text(_inspected(image))
    (tmp_path / "other.json").write_text(_inspected(image, User="root"))
    args = ["loaded", "annatar", "--digest", image.digest, "--expect-file", str(tmp_path / "expect.json")]
    assert pim.main([*args, "--inspect", str(tmp_path / "good.json")]) == 0
    assert pim.main([*args, "--inspect", str(tmp_path / "other.json")]) == 1
    assert pim.main([*args, "--inspect", str(tmp_path / "absent.json")]) == 1
    assert "ne se relit pas" in capsys.readouterr().err
    with pytest.raises(SystemExit):                          # an id alone is no longer an answer
        pim.main(["loaded", "annatar", "--digest", image.digest, "--id", image.digest])


# ── the operator's side: a reference of main only ─────────────────────────────────────────────

def _git(**answers):
    def runner(argv):
        key = argv[3]
        if key == "rev-parse":
            ref = argv[-1]
            return _done(argv, 0, answers[ref] + "\n") if ref in answers else _done(argv, 1)
        if key == "merge-base":
            return _done(argv, 0 if answers.get("on_main", True) else 1)
        if key == "tag":
            return _done(argv, 0, answers.get("tags", ""))
        raise AssertionError(argv)
    return runner


def test_a_tag_of_main_is_its_commit(pim):
    assert pim.commit_of("v0.4.6", _git(**{"refs/tags/v0.4.6^{commit}": C2})) == C2
    assert pim.commit_of("2222222", _git(**{"2222222^{commit}": C2})) == C2


@pytest.mark.parametrize("ref, runner, said", [
    ("main", _git(), "ni un tag ni un commit"),
    ("v0.4.6", _git(**{"refs/tags/v0.4.6^{commit}": C2, "on_main": False}), "pas sur origin/main"),
    ("-x", _git(), "référence invalide"),
    ("a;b", _git(), "référence invalide"),
    ("3333333", _git(**{"3333333^{commit}": C2}), "ni un tag ni un commit"),     # not the commit it names
])
def test_anything_else_is_refused(pim, ref, runner, said):
    with pytest.raises(pim.Unverified, match=said):
        pim.commit_of(ref, runner)


def test_the_latest_tag(pim):
    assert pim.latest_tag(_git(tags="v0.4.6\nv0.4.5\n")) == "v0.4.6"
    with pytest.raises(pim.Unverified):
        pim.latest_tag(_git(tags=""))


# ── the workflow's side ──────────────────────────────────────────────────────────────────────

def test_the_workflows_names_and_labels(pim, tmp_path, monkeypatch):
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert pim.main(["meta", "annatar", "--commit", C2]) == 0
    got = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert got == {"name": "ghcr.io/grootcyber/eregion-annatar", "ref": f"ghcr.io/grootcyber/eregion-annatar:sha-{C2}",
                   "version": f"v{pim.project_version()}", "uid": "1000", "gid": "1000"}


def test_the_digest_pushed_is_the_one_docker_recorded_for_this_repository(pim):
    digest = "sha256:" + "d" * 64
    ref = f"ghcr.io/{GLOR}:sha-{C2}"

    def docker(argv):
        if argv[1] == "push":
            return _done(argv)
        return _done(argv, 0, json.dumps([f"ghcr.io/other/x@sha256:{'e' * 64}", f"ghcr.io/{GLOR}@{digest}"]))
    assert pim.pushed("glorfindel", ref, docker) == digest
    with pytest.raises(pim.Unverified):
        pim.pushed("glorfindel", ref, lambda argv: _done(argv, 0, json.dumps([f"ghcr.io/other/x@{digest}"])))
    with pytest.raises(pim.Unavailable):
        pim.pushed("glorfindel", ref, lambda argv: _done(argv, 1))


# ── cosign, installed only under its pinned sha256 ──────────────────────────────────────────────

@pytest.fixture
def served():
    body = {"data": b"cosign binary"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body["data"])))
            self.end_headers()
            self.wfile.write(body["data"])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield body, f"http://127.0.0.1:{srv.server_address[1]}/cosign"
    srv.shutdown()
    srv.server_close()


def test_cosign_is_installed_only_under_its_pinned_sha256(pim, served, tmp_path, monkeypatch):
    body, url = served
    monkeypatch.setattr(pim, "COSIGN_URL", url)
    dest = tmp_path / "bin" / "cosign"
    monkeypatch.setattr(pim, "COSIGN_SHA256", hashlib.sha256(b"something else").hexdigest())
    assert pim.install_cosign(dest) == 1 and not dest.exists() and not dest.with_name("cosign.part").exists()
    monkeypatch.setattr(pim, "COSIGN_SHA256", hashlib.sha256(body["data"]).hexdigest())
    assert pim.install_cosign(dest) == 0 and dest.read_bytes() == body["data"] and pim.cosign_ok(dest)
    body["data"] = b"changed upstream"
    assert pim.install_cosign(dest) == 0 and dest.read_bytes() == b"cosign binary"     # kept, not fetched again


def test_the_pinned_cosign_is_the_one_measured():
    """cosign v3.1.3, linux-amd64: the sha256 of sigstore's release (cosign_checksums.txt, 29/10)."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'COSIGN_VERSION = "v3.1.3"' in text
    assert 'COSIGN_SHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"' in text


# ── the CLI's exits: 1 refused, 3 nothing proven ──────────────────────────────────────────────

def test_the_cli_says_refused_or_unavailable(pim, reg, sig, monkeypatch, capsys):
    assert pim.main(["verify", "glorfindel", "--commit", C2, "--cosign", str(sig.path)]) == 1
    assert "doit être public, ou n'existe pas" in capsys.readouterr().err      # GHCR: 403 at the token
    monkeypatch.setattr(pim, "REGISTRY_API", "http://127.0.0.1:9")
    assert pim.main(["verify", "glorfindel", "--commit", C2, "--cosign", str(sig.path)]) == 3
    digest = reg.image(GLOR, f"sha-{C2}", _manifest(C2))
    monkeypatch.setattr(pim, "REGISTRY_API", f"{reg.base}/registry")
    _signed(pim, sig, digest)
    assert pim.main(["verify", "glorfindel", "--commit", C2, "--cosign", str(sig.path)]) == 0
    assert digest in capsys.readouterr().out


def _make_n(*args):
    import shutil
    if shutil.which("make") is None:
        pytest.skip("make not installed")
    res = subprocess.run(["make", "-n", "--no-print-directory", "-C", str(ROOT), *args, "ORO_IP=203.0.113.7"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    return res.stdout


def test_orodruin_gets_the_published_image_verified_here_never_one_built_here():
    """make orodruin-push: no build, no docker save of this machine (OI1) — the digest resolved and
    proven here, its archive built from the registry's blobs, loaded over SSH (Orodruin's egress
    stays closed), read back there against the proven manifest."""
    out = _make_n("orodruin-push", "REF=v0.4.6")
    assert "docker build" not in out and "docker save" not in out and "docker pull" not in out
    lines = out.splitlines()
    first = next(i for i, line in enumerate(lines) if "published_image.py archive annatar" in line)
    assert ('--ref "$EREGION_DEPLOY_REF" --tag eregion-annatar:incoming --out "$tmp"' in lines[first])
    rest = "\n".join(lines[first:])
    order = [rest.index(s) for s in ("published_image.py archive annatar", "rm -f .eregion-image",
                                     "'docker load' < \"$tmp/image.tar\"", "'docker image inspect eregion-annatar:incoming'",
                                     "published_image.py loaded annatar",
                                     "docker run --rm --read-only --tmpfs /tmp --cap-drop ALL",
                                     "docker tag eregion-annatar:incoming eregion-annatar:orodruin",
                                     "cat > .eregion-image")]
    assert order == sorted(order)
    assert '--expect-file "$tmp/expect.json" --inspect "$tmp/inspect.json"' in rest
    assert "trap 'rm -rf \"$tmp\"' EXIT" in out
    assert "install-cosign" in out and "environment*" in out


# The make target run for real, on fakes: the operator's docker and Orodruin's (tests/unit/fake_oci.py,
# each its own state), ssh running the remote command against Orodruin's, the registry and cosign
# (fake_discord.py, fake_sigstore.py), git; published_image.py itself, its pinned cosign's sha256 the fake's.
PUSH_FAKES = {
    "docker": '#!/bin/bash\nexec "$REAL_PYTHON" "$FAKE_OCI" docker "$@"\n',
    "ssh": '#!/bin/bash\ncmd="${!#}"\ncd "$REMOTE_HOME" && DOCKER_STATE="$REMOTE_STATE" bash -c "$cmd"\n',
    "scp": "#!/bin/sh\nexit 0\n",
    "git": '#!/bin/bash\n[ "$3" = rev-parse ] && { echo "$FAKE_COMMIT"; exit 0; }\nexit 0\n',
    "python3": '#!/bin/bash\nexec "$REAL_PYTHON" "$PIM_WRAPPER" "${@:2}"\n',
}
PIM_WRAPPER = '''import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("published_image", os.environ["REAL_SCRIPT"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.COSIGN_SHA256 = os.environ["FAKE_COSIGN_SHA256"]
sys.exit(mod.main(sys.argv[1:]))
'''


@pytest.fixture
def orodruin(tmp_path, reg, sig):
    """Orodruin before the push: eregion-annatar:orodruin, the image that ran (complete), and its
    ~/.eregion-image; the image of C2 published, signed and attested."""
    import os
    import shutil
    if shutil.which("make") is None:
        pytest.skip("make needed")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, text in PUSH_FAKES.items():
        (bin_ / name).write_text(text)
        (bin_ / name).chmod(0o755)
    (tmp_path / "pim_wrapper.py").write_text(PIM_WRAPPER)
    work, remote = tmp_path / "work", tmp_path / "orodruin"
    (work / "infra" / "orodruin").mkdir(parents=True)
    (work / "infra" / "orodruin" / "orodruin.env").write_text("X=1\n")
    for d in (remote / "home", remote / "docker", tmp_path / "local", tmp_path / "home", tmp_path / "tmp",
              tmp_path / "published"):
        d.mkdir(parents=True, exist_ok=True)
    old = fake_oci.Image(C1, salt="old")
    _load_on(remote / "docker", old, "eregion-annatar:orodruin")
    (remote / "docker" / "calls").unlink()
    (remote / "home" / ".eregion-image").write_text(f"{C1} {old.digest}\n")
    new = fake_oci.Image(C2)
    new.publish(reg, ANNATAR, f"sha-{C2}")
    new.write(tmp_path / "published")
    sig.publish(f"ghcr.io/{ANNATAR}", new.digest, "grootcyber/eregion", C2)
    env = {**os.environ, **sig.env(), "PATH": f"{bin_}:{os.environ['PATH']}", "HOME": str(tmp_path / "home"),
           "TMPDIR": str(tmp_path / "tmp"), "DOCKER_STATE": str(tmp_path / "local"),
           "REMOTE_HOME": str(remote / "home"), "REMOTE_STATE": str(remote / "docker"),
           "FAKE_OCI": str(Path(fake_oci.__file__)), "FAKE_PUBLISHED": str(tmp_path / "published"),
           "FAKE_COMMIT": C2, "REAL_PYTHON": sys.executable, "REAL_SCRIPT": str(SCRIPT),
           "PIM_WRAPPER": str(tmp_path / "pim_wrapper.py"), "EREGION_REGISTRY_API": f"{reg.base}/registry",
           "EREGION_COSIGN": str(sig.path), "FAKE_COSIGN_SHA256": sig.sha256}
    for k in ("REF", "FAKE_STORE", "FAKE_LOAD_DROP", "FAKE_LOAD_ID", "FAKE_LOAD_USER", "FAKE_RUN_HANG",
              "FAKE_RUN_EXIT"):
        env.pop(k, None)

    class Run:
        def __init__(self):
            self.tmp, self.remote, self.old, self.new, self.env = tmp_path, remote, old, new, env

        def push(self, *args, **more):
            return subprocess.run(["make", "--no-print-directory", "-C", str(work), "-f", str(ROOT / "Makefile"),
                                   "-o", "orodruin-known", "orodruin-push", "REF=v0.4.6", "ORO_IP=203.0.113.7",
                                   "ORO_SSH=ssh orodruin@203.0.113.7", *args], env={**env, **more},
                                  capture_output=True, text=True, timeout=120)

        def containers(self):
            p = remote / "docker" / "containers.json"
            return json.loads(p.read_text()) if p.exists() else {}

        def images(self, where="docker"):
            p = remote / where / "images.json" if where == "docker" else tmp_path / "local" / "images.json"
            return json.loads(p.read_text()) if p.exists() else {}

        def calls(self, where="docker"):
            p = (remote / "docker" if where == "docker" else tmp_path / "local") / "calls"
            return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

        def marker(self):
            p = remote / "home" / ".eregion-image"
            return p.read_text().split() if p.exists() else None
    return Run()


def _load_on(state, image, tag, store="containerd"):
    """`image` loaded in the fake docker of `state`, under `tag` (its archive, as OI1 builds it)."""
    import io
    import os
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        def add(n, data):
            info = tarfile.TarInfo(n)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for d, data in image.blobs.items():
            add(f"blobs/sha256/{d.split(':', 1)[1]}", data)
        add("index.json", json.dumps({"manifests": [{"digest": image.digest, "annotations": {
            "io.containerd.image.name": f"docker.io/library/{tag}"}}]}).encode())
        add("manifest.json", json.dumps([{"Config": f"blobs/sha256/{image.config_digest.split(':', 1)[1]}",
                                          "RepoTags": [tag], "Layers": [f"blobs/sha256/{d.split(':', 1)[1]}"
                                                                        for d in image.layers]}]).encode())
    env = {**os.environ, "DOCKER_STATE": str(state), "FAKE_STORE": store}
    for k in ("FAKE_LOAD_DROP", "FAKE_LOAD_ID", "FAKE_LOAD_USER"):
        env.pop(k, None)
    res = subprocess.run([sys.executable, fake_oci.__file__, "docker", "load"], input=buf.getvalue(),
                         capture_output=True, env=env, timeout=60)
    assert res.returncode == 0, res.stderr


@pytest.mark.parametrize("signal", ["INT", "TERM", "HUP"])
def test_an_interrupted_push_leaves_no_archive_behind(tmp_path, signal):
    """~630 MB in TMPDIR: removed at a Ctrl-C too — dash runs no EXIT trap on a signal (relecture)."""
    import os
    import re
    line = next(ln for ln in (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
                if "tmp=$$(mktemp -d)" in ln and "trap" in ln)
    head = re.sub(r"\\$", "", line.lstrip("\t@")).replace("$$", "$")
    (tmp_path / "t").mkdir()
    res = subprocess.run(["/bin/sh", "-c", f"{head} kill -{signal} $$; sleep 5; echo continued"],
                         env={**os.environ, "TMPDIR": str(tmp_path / "t")}, capture_output=True, text=True,
                         timeout=30)
    assert res.returncode != 0 and "continued" not in res.stdout
    assert list((tmp_path / "t").iterdir()) == []


@pytest.mark.parametrize("store", ["containerd", "classic"])
def test_the_image_arrives_whole_though_this_machines_docker_save_drops_config_and_layers(orodruin, store):
    """#488, red on main: the operator's docker (Docker Desktop, containerd's store) saves a pulled
    image as its index and its manifest, without config or layers. main sent that: Orodruin loaded
    an image its own `docker tag` could not read, `loaded` passed it on its id alone. The archive is
    now built from the registry's blobs: the operator's docker is never asked to save or pull."""
    res = orodruin.push(FAKE_STORE=store)
    assert res.returncode == 0, res.stdout + res.stderr
    img = orodruin.images()["eregion-annatar:orodruin"]
    assert img["id"] == (orodruin.new.digest if store == "containerd" else orodruin.new.config_digest)
    assert img["config"] == orodruin.new.config_digest
    assert "eregion-annatar:incoming" not in orodruin.images()
    assert orodruin.marker() == [C2, orodruin.new.digest]
    assert not [c for c in orodruin.calls("local") if c[0] in ("save", "pull")]
    assert list((orodruin.tmp / "tmp").iterdir()) == []            # the archive, removed
    assert "chacun vérifié par son sha256" in res.stderr


def test_an_image_whose_config_the_store_loses_is_refused_incoming_removed(orodruin):
    """`loaded` reads the image back (docker image inspect), not its id alone: an image without its
    config reads back as its id, without layers nor user (docker's API, the CLI applying -f on its
    side) — refused, eregion-annatar:incoming removed, :orodruin as it was, and ~/.eregion-image
    absent (never naming the old image as the new one)."""
    res = orodruin.push(FAKE_LOAD_DROP="config")
    assert res.returncode != 0 and "retirée" in res.stderr
    assert "ses couches" in res.stderr and "son utilisateur" in res.stderr
    images = orodruin.images()
    assert "eregion-annatar:incoming" not in images
    assert images["eregion-annatar:orodruin"]["manifest"] == orodruin.old.digest
    assert orodruin.marker() is None


@pytest.mark.parametrize("env, said", [
    ({"FAKE_LOAD_ID": "sha256:" + "f" * 64}, "n'est pas"),
    ({"FAKE_LOAD_USER": "root"}, "son utilisateur"),
])
def test_an_image_loaded_that_is_not_the_one_verified_is_removed_and_nothing_changes(orodruin, env, said):
    """…and never run, not even for the control run (OI2): only the image read back as the proven one
    starts."""
    res = orodruin.push(**env)
    assert res.returncode != 0 and "retirée" in res.stderr and said in res.stderr
    images = orodruin.images()
    assert "eregion-annatar:incoming" not in images
    assert images["eregion-annatar:orodruin"]["manifest"] == orodruin.old.digest
    assert orodruin.marker() is None
    assert not [c for c in orodruin.calls() if c[0] == "run"]


# ── OI2 (#490): a control run before the tag — the layers present and unpacked ──────────────────

CHECK_RUN = ["run", "--rm", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt",
             "no-new-privileges:true", "--pull", "never", "--network", "none", "--no-healthcheck", "--name",
             "eregion-annatar-check", "--entrypoint", "true", "eregion-annatar:incoming"]


def _refused_at_the_check(orodruin, res, said):
    assert res.returncode != 0, res.stdout + res.stderr
    images = orodruin.images()
    assert images["eregion-annatar:orodruin"]["manifest"] == orodruin.old.digest, res.stderr
    assert orodruin.marker() is None
    assert "eregion-annatar:incoming" not in images
    assert "ne démarre pas" in res.stderr and said in res.stderr and "retirée" in res.stderr
    assert orodruin.containers() == {}
    assert not [c for c in orodruin.calls() if c[0] == "tag"]


@pytest.mark.parametrize("store", ["containerd", "classic"])
def test_a_layer_lost_after_the_load_is_refused_by_the_control_run(orodruin, store):
    """#490, red on main: a layer the store lost after a load that succeeded. docker image inspect
    reads the config — its layers listed from it, its id, its user, all as proven —, `loaded` passes,
    and main tagged the image :orodruin, to fail at its first run. The control run creates a container
    from it: refused, the cause said (docker's own words, then ours), incoming removed, :orodruin
    unchanged, ~/.eregion-image absent (as under OI1: it never names the old image as the new one)."""
    res = orodruin.push(FAKE_STORE=store, FAKE_LOAD_DROP="layer")
    _refused_at_the_check(orodruin, res, "une couche absente ou non dépaquetée")
    assert "failed to prepare snapshot" in res.stderr


def test_the_control_run_takes_nothing_from_the_host_and_reaches_nothing(orodruin):
    """The control run, as run on Orodruin: true alone, no network, never pulled, no mount, no
    environment, no capability, read-only, hardened as every injector's run (ORO_HARDEN) — after the
    image is read back as the proven one, before its tag; and gone after (--rm)."""
    res = orodruin.push()
    assert res.returncode == 0, res.stdout + res.stderr
    calls = orodruin.calls()
    kinds = [c[0] if c[0] != "image" else c[1] for c in calls]
    runs = [c for c in calls[:kinds.index("tag")] if c[0] == "run"]     # then, the migration (ORO_MIGRATE)
    assert runs == [CHECK_RUN]
    assert kinds.index("load") < kinds.index("inspect") < kinds.index("run") < kinds.index("tag")
    assert orodruin.containers() == {}
    assert orodruin.images()["eregion-annatar:orodruin"]["manifest"] == orodruin.new.digest


def test_a_control_run_that_hangs_is_cut_at_its_bound_and_its_container_taken_off(orodruin):
    """Bounded: cut at ORO_CHECK_TIMEOUT, its container (left by the run killed) taken off — else it
    would hold incoming, which no `image rm` could remove."""
    import time
    started = time.monotonic()
    res = orodruin.push("ORO_CHECK_TIMEOUT=1", FAKE_RUN_HANG="20")
    assert time.monotonic() - started < 15
    _refused_at_the_check(orodruin, res, "délai de 1 s dépassé")


@pytest.mark.parametrize("bound", ["0", "00", "000", "", "1; touch pwned", "-5", "$(shell touch pwned)",
                                   "1'; touch pwned; '"])
def test_a_bound_that_is_no_number_of_seconds_sends_nothing(orodruin, bound):
    """ORO_CHECK_TIMEOUT goes into the remote command: seconds, at least one, or nothing is sent —
    `timeout 00` sets no bound at all. Taken as REF is, never expanded by make before it is checked:
    a `$(shell …)` given runs nowhere."""
    res = orodruin.push(f"ORO_CHECK_TIMEOUT={bound}")
    assert res.returncode != 0 and "ORO_CHECK_TIMEOUT invalide" in res.stderr
    assert orodruin.calls() == []
    assert not [p for p in orodruin.tmp.rglob("pwned")]
    assert orodruin.marker() == [C1, orodruin.old.digest]


@pytest.mark.parametrize("code, said", [("127", "true ne s'exécute pas"), ("1", "code 1")])
def test_a_control_run_that_fails_is_refused_its_cause_said(orodruin, code, said):
    res = orodruin.push(FAKE_RUN_EXIT=code)
    _refused_at_the_check(orodruin, res, said)


def test_a_check_container_left_by_a_push_before_is_taken_off_first(orodruin):
    """A push cut while its control run ran leaves its container: taken off with the incoming left,
    or the next push could never name its own."""
    (orodruin.remote / "docker" / "containers.json").write_text(
        json.dumps({"eregion-annatar-check": "eregion-annatar:incoming"}))
    res = orodruin.push()
    assert res.returncode == 0, res.stdout + res.stderr
    assert orodruin.containers() == {}
    assert orodruin.marker() == [C2, orodruin.new.digest]


@pytest.mark.parametrize("spoil, said", [
    (lambda reg, img: reg.registry[ANNATAR]["blobs"].update({img.layers[1]: bytes(len(img.blobs[img.layers[1]]))}),
     "son empreinte est"),
    (lambda reg, img: reg.registry[ANNATAR]["blobs"].pop(img.config_digest), "absent du registre"),
])
def test_a_blob_altered_or_missing_stops_everything_before_anything_is_sent(orodruin, reg, spoil, said):
    """Nothing reaches Orodruin — no ssh at all: its image, its ~/.eregion-image as they were."""
    spoil(reg, orodruin.new)
    res = orodruin.push()
    assert res.returncode != 0 and said in res.stderr and "rien n'est envoyé" in res.stderr
    assert orodruin.calls() == []
    assert orodruin.images()["eregion-annatar:orodruin"]["manifest"] == orodruin.old.digest
    assert orodruin.marker() == [C1, orodruin.old.digest]
    assert list((orodruin.tmp / "tmp").iterdir()) == []


def test_the_development_path_says_it_is_unverified():
    out = _make_n("orodruin-push-dev")
    assert "docker build -f annatar/Dockerfile --build-arg UID=1000" in out and "NON vérifiée" in out
    assert 'echo "dev ' in out


def test_the_module_runs_on_h0s_python_standard_library_only():
    """H0 runs Python 3.10 and nothing installed: no import beyond the standard library."""
    import ast
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= set(sys.stdlib_module_names) | {"__future__"}
    assert "tomllib" not in names                                     # 3.11+


# ── SEC14 (P-02): the base image pinned by its digest ─────────────────────────────────────────

def test_both_images_start_from_the_same_base_pinned_by_its_digest():
    import re
    froms = {}
    for name in ("annatar", "glorfindel"):
        lines = [ln for ln in (ROOT / name / "Dockerfile").read_text(encoding="utf-8").splitlines()
                 if ln.startswith("FROM ")]
        assert len(lines) == 1, (name, lines)
        froms[name] = lines[0]
        assert re.fullmatch(r"FROM python:3\.12-slim@sha256:[0-9a-f]{64}", lines[0]), lines[0]
    assert froms["annatar"] == froms["glorfindel"]


# ── SEC14 (R-14): syft, the SBOM's tool, pinned by its archive's sha256 ───────────────────────

def _syft_archive(binary: bytes) -> bytes:
    import io
    import tarfile
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in (("README.md", b"readme"), ("syft", binary)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def test_syft_is_installed_only_from_its_pinned_archive(pim, served, tmp_path, monkeypatch):
    body, url = served
    body["data"] = _syft_archive(b"syft binary")
    monkeypatch.setattr(pim, "SYFT_URL", url)
    dest = tmp_path / "bin" / "syft"
    monkeypatch.setattr(pim, "SYFT_SHA256", hashlib.sha256(b"another archive").hexdigest())
    assert pim.install_syft(dest) == 1 and not dest.exists() and not dest.with_name("syft.part").exists()
    monkeypatch.setattr(pim, "SYFT_SHA256", hashlib.sha256(body["data"]).hexdigest())
    assert pim.install_syft(dest) == 0 and dest.read_bytes() == b"syft binary"
    assert dest.stat().st_mode & 0o111 and sorted(p.name for p in dest.parent.iterdir()) == ["syft"]


def test_the_pinned_syft_is_the_one_read_on_its_release():
    """syft v1.51.1, linux-amd64: the sha256 of anchore's release archive (syft_1.51.1_checksums.txt,
    02/11) — the version anchore/sbom-action v0.24.2 fetched at run time."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("pim_pin", ROOT / "scripts" / "published_image.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.SYFT_VERSION == "v1.51.1"
    assert mod.SYFT_SHA256 == "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
    assert mod.SYFT_URL.endswith("/v1.51.1/syft_1.51.1_linux_amd64.tar.gz")


# ── SEC19 (R-13): the attestation signed by its author's own key, offline ───────────────

def _keys():
    from .fake_sigstore import pinned, placeholder_key
    me, other = placeholder_key("maintainer"), placeholder_key("someone else")
    return me, other, pinned(me)


def _blob(tmp_path, data=b'{"schema": "eregion.harness/2"}\n', key="me"):
    from .fake_sigstore import blob_bundle
    me, other, _ = _keys()
    f = tmp_path / "harness.json"
    f.write_bytes(data)
    if key:
        (tmp_path / "harness.json.sigstore.json").write_text(blob_bundle(data, me if key == "me" else other))
    return f


def test_a_file_signed_by_the_key_pinned_holds_offline(pim, sig, tmp_path):
    f = _blob(tmp_path)
    pim.verify_blob(f, pim.bundle_of(f), _keys()[2], sig.path)
    (call,) = sig.calls()
    assert call[:2] == ["verify-blob", "--key"] and call[-1] == str(f)
    assert "--insecure-ignore-tlog" in call and "--bundle" in call
    assert not any(a.startswith("--certificate") for a in call)          # no identity, no certificate


@pytest.mark.parametrize("key, said", [(None, "n'est pas signée"), ("other", "signée d'une autre clé")])
def test_a_file_unsigned_or_signed_by_another_key_is_refused(pim, sig, tmp_path, key, said):
    f = _blob(tmp_path, key=key)
    with pytest.raises(pim.Unverified, match=said):
        pim.verify_blob(f, pim.bundle_of(f), _keys()[2], sig.path)


def test_a_signature_of_another_file_is_refused(pim, sig, tmp_path):
    f = _blob(tmp_path)
    f.write_bytes(b'{"schema": "eregion.harness/2", "changed": true}\n')
    with pytest.raises(pim.Unverified, match="ne couvre pas ce fichier"):
        pim.verify_blob(f, pim.bundle_of(f), _keys()[2], sig.path)


@pytest.mark.parametrize("key", ["", "   ", "pas-une-clé", "AAAA", "QUJD" * 20])
def test_without_a_readable_key_nothing_is_believed_and_cosign_is_never_asked(pim, sig, tmp_path, key):
    """M3259: a key empty, not base64, too short, not a DER — refused before cosign runs."""
    f = _blob(tmp_path)
    with pytest.raises(pim.Unverified, match="EREGION_HARNESS_KEY"):
        pim.verify_blob(f, pim.bundle_of(f), key, sig.path)
    assert sig.calls() == []


def test_a_cosign_not_pinned_never_verifies_a_file(pim, sig, tmp_path, monkeypatch):
    f = _blob(tmp_path)
    monkeypatch.setattr(pim, "COSIGN_SHA256", "0" * 64)
    with pytest.raises(pim.Unverified, match="altéré"):
        pim.verify_blob(f, pim.bundle_of(f), _keys()[2], sig.path)


def test_the_pinned_form_is_the_body_of_cosign_pub_and_its_hint_cosign_s():
    """EREGION_HARNESS_KEY: cosign.pub without its PEM lines, on one line (a compose .env holds one
    line per key); its hint, the base64 of the DER's sha256 — what cosign writes in a bundle
    (measured on 03/11)."""
    import base64
    import hashlib
    spec = importlib.util.spec_from_file_location("published_image_form", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    me, _other, line = _keys()
    pem = mod.pem_of(me)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----\n") and max(map(len, pem.splitlines())) <= 64
    assert mod.pinned_of_pem(pem) == line and "\n" not in line
    assert mod.key_der(line) == me
    assert mod.key_hint(me) == base64.b64encode(hashlib.sha256(me).digest()).decode()


def test_signing_is_offline_and_keeps_a_bundle_without_certificate(pim, sig, tmp_path, capsys):
    """Jonathan's gesture: cosign sign-blob --key, with a signing config that names no service — no
    log, no certificate; a bundle that would carry one is removed, never committed."""
    from .fake_sigstore import blob_bundle
    me = _keys()[0]
    f = tmp_path / "harness.json"
    f.write_text("{}\n")
    key = tmp_path / "cosign.key"
    key.write_text("encrypted")
    seen = []

    def runner(argv):
        seen.append(argv)
        cfg = json.loads(Path(argv[argv.index("--signing-config") + 1]).read_text())
        assert cfg == {"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
                       "rekorTlogConfig": {}, "tsaConfig": {}}
        Path(argv[argv.index("--bundle") + 1]).write_text(blob_bundle(f.read_bytes(), me))
        return _done(argv)
    assert pim.sign_blob(f, key, sig.path, runner=runner) == 0
    assert seen[0][:4] == [str(sig.path), "sign-blob", "--key", str(key)] and seen[0][-1] == str(f)
    assert "--yes" not in seen[0]          # a cosign that would send anything still asks first
    assert pim.bundle_refusal(pim.bundle_of(f)) == "" and "à commiter" in capsys.readouterr().out

    def with_cert(argv):
        Path(argv[argv.index("--bundle") + 1]).write_text(json.dumps(
            {"verificationMaterial": {"publicKey": {"hint": "x"}, "certificate": {"rawBytes": "x"}}}))
        return _done(argv)
    assert pim.sign_blob(f, key, sig.path, runner=with_cert) == 1
    assert not pim.bundle_of(f).exists()
    assert pim.sign_blob(tmp_path / "absent.json", key, sig.path, runner=runner) == 1
    link = tmp_path / "link.key"
    link.symlink_to(key)
    assert pim.sign_blob(f, link, sig.path, runner=runner) == 1


@pytest.mark.parametrize("material, said", [({"publicKey": {"hint": "h"}, "tlogEntries": [{}]}, "journal"),
                                            ({"publicKey": {"hint": "h"}, "x509CertificateChain": {}}, "certificat"),
                                            ({}, "sans la clé")])
def test_a_bundle_with_a_certificate_or_a_log_entry_never_goes_in_the_repository(pim, tmp_path, material, said):
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"verificationMaterial": material}))
    assert said in pim.bundle_refusal(b)


def test_the_key_pair_is_drawn_once_off_the_repository_never_over_one(pim, sig, tmp_path, capsys):
    """make harness-key: cosign draws the pair in its directory (0700, the private half 0600, its
    passphrase typed — never passed); the line to pin printed; a link, or a key already there, refused."""
    me = _keys()[0]
    seen = []

    def run_in(argv, cwd):
        seen.append((argv, cwd))
        (Path(cwd) / "cosign.key").write_text("encrypted")
        (Path(cwd) / "cosign.pub").write_text(pim.pem_of(me))
        return _done(argv)
    d = tmp_path / "harness"
    assert pim.generate_key(d, sig.path, run_in=run_in, tty=True) == 0
    assert seen[0][0] == [str(sig.path), "generate-key-pair", "--output-key-prefix", "cosign"] and seen[0][1] == d
    import stat
    assert stat.S_IMODE(d.stat().st_mode) == 0o700 and stat.S_IMODE((d / "cosign.key").stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert f"EREGION_HARNESS_KEY={_keys()[2]}" in out and pim.key_hint(me)[:12] in out
    assert pim.generate_key(d, sig.path, run_in=run_in, tty=True) == 1 and len(seen) == 1      # never over a key
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "elsewhere")
    assert pim.generate_key(link, sig.path, run_in=run_in, tty=True) == 1 and len(seen) == 1


def test_the_command_line_verifies_a_file(pim, sig, tmp_path):
    f = _blob(tmp_path)
    me, other, line = _keys()
    from .fake_sigstore import pinned
    assert pim.main(["verify-blob", str(f), "--pinned", line, "--cosign", str(sig.path)]) == 0
    assert pim.main(["verify-blob", str(f), "--pinned", pinned(other), "--cosign", str(sig.path)]) == 1
    pub = tmp_path / "cosign.pub"
    pub.write_text(pim.pem_of(me))
    assert pim.main(["verify-blob", str(f), "--pub", str(pub), "--cosign", str(sig.path)]) == 0


def test_the_passphrase_is_never_passed_by_the_environment(pim, sig, tmp_path, monkeypatch):
    """COSIGN_PASSWORD exported would sign, or draw a key, without anything typed: filtered out of
    what cosign runs in, for the signature as for the key."""
    assert "COSIGN_PASSWORD" not in pim.typed_env({"COSIGN_PASSWORD": "x", "PATH": "/bin"})
    assert pim.typed_env({"PATH": "/bin"}) == {"PATH": "/bin"}
    monkeypatch.setenv("COSIGN_PASSWORD", "exported-by-mistake")
    seen = []

    def run(argv, **kw):
        seen.append(kw.get("env"))
        return _done(argv, code=1)
    monkeypatch.setattr(pim.subprocess, "run", run)
    f = tmp_path / "harness.json"
    f.write_text("{}\n")
    key = tmp_path / "cosign.key"
    key.write_text("encrypted")
    assert pim.sign_blob(f, key, sig.path) == 1
    assert pim.generate_key(tmp_path / "harness", sig.path, tty=True) == 1
    assert len(seen) == 2 and all(env is not None and "COSIGN_PASSWORD" not in env for env in seen)


def test_the_key_is_drawn_only_at_a_terminal_and_never_under_the_repository(pim, sig, tmp_path, capsys):
    calls = []

    def run_in(argv, cwd):
        calls.append(argv)
        return _done(argv)
    assert pim.generate_key(tmp_path / "harness", sig.path, run_in=run_in, tty=False) == 1
    assert "pas de terminal" in capsys.readouterr().err
    assert pim.generate_key(ROOT / "requirements" / "harness-key", sig.path, run_in=run_in, tty=True) == 1
    assert "dans le dépôt" in capsys.readouterr().err
    assert calls == [] and not (ROOT / "requirements" / "harness-key").exists()


def test_a_private_key_is_never_committed():
    ignored = (ROOT / ".gitignore").read_text().splitlines()
    assert "cosign.key" in ignored and "*.key" in ignored


def test_verifying_without_a_key_says_the_gesture(pim, sig, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("EREGION_HARNESS_KEY_DIR", str(tmp_path / "no-key-here"))
    f = _blob(tmp_path)
    assert pim.main(["verify-blob", str(f), "--cosign", str(sig.path)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("✗ aucune clé à vérifier") and "PINNED=" in err and "Traceback" not in err


# ── OI3 (#522): make orodruin-start brings Orodruin up to the latest release, verified ─────────
# The targets run for real on the fakes above (Orodruin's docker, ssh, the registry, cosign), az and
# ssh-keyscan faked, and a real git repository of its own: v0.5.9 and v0.5.10 (by version order the
# latest; by string order, v0.5.9), a commit of main after it, a branch beside them. The sub-makes
# (orodruin-update, orodruin-push) check Orodruin's host key for real (known_host.sh, the real
# ssh-keygen): a key made here, pinned. No network, no VM.

START_FAKES = {
    **PUSH_FAKES,
    "git": '#!/bin/bash\n[ "$1" = -C ] && shift 2\n[ "$1" = fetch ] && exit 0\nexec "$REAL_GIT" -C "$FAKE_REPO" "$@"\n',
    "az": '#!/bin/sh\necho "az $*" >> "$FAKE_AZ_LOG"\n',
    "ssh-keyscan": '#!/bin/sh\n[ -n "$FAKE_SILENT" ] || echo "$FAKE_KEYSCAN"\n',
    "sleep": "#!/bin/sh\nexit 0\n",
}
ORO_IP_T = "203.0.113.7"


@pytest.fixture
def start(tmp_path, reg, sig):
    """Orodruin stopped, v0.5.10 published, signed and attested; `.serve(name)` puts an image in
    service (its marker and :orodruin), `.run(*args, **env)` runs `make <target>` (orodruin-start)."""
    import os
    import shutil
    if not (shutil.which("make") and shutil.which("ssh-keygen") and shutil.which("git")):
        pytest.skip("make, ssh-keygen and git needed")
    real_git = shutil.which("git")
    repo = tmp_path / "repo"
    genv = {**os.environ, "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1"}

    def git(*a):
        return subprocess.run([real_git, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                               *a], env=genv, capture_output=True, text=True, check=True).stdout.strip()
    repo.mkdir()
    git("init", "-q", "-b", "main")
    commits = {}
    for name in ("v0.5.9", "v0.5.10", "head"):
        git("commit", "-q", "--allow-empty", "-m", name)
        commits[name] = git("rev-parse", "HEAD")
        if name.startswith("v"):
            git("tag", name)
    git("update-ref", "refs/remotes/origin/main", commits["head"])
    git("switch", "-q", "-c", "side", commits["v0.5.9"])
    git("commit", "-q", "--allow-empty", "-m", "side")
    commits["side"] = git("rev-parse", "HEAD")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, text in START_FAKES.items():
        (bin_ / name).write_text(text)
        (bin_ / name).chmod(0o755)
    (tmp_path / "pim_wrapper.py").write_text(PIM_WRAPPER)
    work, remote = tmp_path / "work", tmp_path / "orodruin"
    (work / "infra" / "orodruin").mkdir(parents=True)
    (work / "infra" / "orodruin" / "orodruin.env").write_text("X=1\n")
    (work / "infra" / "glorfindel-host").mkdir(parents=True)
    shutil.copy(ROOT / "infra" / "glorfindel-host" / "known_host.sh", work / "infra" / "glorfindel-host")
    (work / "Makefile").symlink_to(ROOT / "Makefile")        # the sub-makes read the Makefile of their directory
    for d in (remote / "home", remote / "docker", tmp_path / "local", tmp_path / "home", tmp_path / "tmp"):
        d.mkdir(parents=True, exist_ok=True)
    key = tmp_path / "hostkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pub = key.with_suffix(".pub").read_text().split()
    fp = subprocess.run(["ssh-keygen", "-lf", str(key.with_suffix(".pub"))], capture_output=True, text=True,
                        check=True).stdout.split()[1]
    known = tmp_path / "home" / "orodruin_known_hosts"
    known.write_text(f"{ORO_IP_T} {pub[0]} {pub[1]}\n")
    images = {n: fake_oci.Image(c, salt=n) for n, c in commits.items()}
    released = images["v0.5.10"]
    released.publish(reg, ANNATAR, f"sha-{commits['v0.5.10']}")
    sig.publish(f"ghcr.io/{ANNATAR}", released.digest, "grootcyber/eregion", commits["v0.5.10"])
    env = {**os.environ, **sig.env(), "PATH": f"{bin_}:{os.environ['PATH']}", "HOME": str(tmp_path / "home"),
           "TMPDIR": str(tmp_path / "tmp"), "DOCKER_STATE": str(tmp_path / "local"),
           "REMOTE_HOME": str(remote / "home"), "REMOTE_STATE": str(remote / "docker"),
           "FAKE_OCI": str(Path(fake_oci.__file__)), "REAL_PYTHON": sys.executable, "REAL_SCRIPT": str(SCRIPT),
           "PIM_WRAPPER": str(tmp_path / "pim_wrapper.py"), "EREGION_REGISTRY_API": f"{reg.base}/registry",
           "EREGION_COSIGN": str(sig.path), "FAKE_COSIGN_SHA256": sig.sha256, "REAL_GIT": real_git,
           "FAKE_REPO": str(repo), "FAKE_AZ_LOG": str(tmp_path / "az.log"),
           "FAKE_KEYSCAN": f"{ORO_IP_T} {pub[0]} {pub[1]}", "ORO_SSH_FINGERPRINT": fp,
           "ORO_KNOWN_HOSTS": str(known)}
    for k in ("REF", "NO_UPDATE", "MAKEFLAGS", "MAKELEVEL", "MFLAGS", "FAKE_STORE", "FAKE_LOAD_DROP",
              "FAKE_LOAD_ID", "FAKE_LOAD_USER", "FAKE_RUN_HANG", "FAKE_RUN_EXIT", "FAKE_SILENT"):
        env.pop(k, None)

    class Run:
        def __init__(self):
            self.tmp, self.remote, self.commits, self.images_, self.env = tmp_path, remote, commits, images, env

        def serve(self, name, marker="verified"):
            """`name`'s image in service on Orodruin, with its marker (verified, dev, or this text)."""
            _load_on(remote / "docker", images[name], "eregion-annatar:orodruin")
            (remote / "docker" / "calls").unlink()
            text = {"verified": f"{commits[name]} {images[name].digest}\n", "dev": f"dev {commits[name]}\n"}
            (remote / "home" / ".eregion-image").write_text(text.get(marker, marker))

        def run(self, *args, target="orodruin-start", **more):
            return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(work), target,
                                   f"ORO_IP={ORO_IP_T}", f"ORO_SSH=ssh orodruin@{ORO_IP_T}", "VM_ID=/subscriptions/00000000-0000-0000-0000-000000000000/vm-x", *args],
                                  env={**env, **more}, capture_output=True, text=True, timeout=120)

        def served(self):
            p = remote / "docker" / "images.json"
            rec = (json.loads(p.read_text()) if p.exists() else {}).get("eregion-annatar:orodruin")
            return rec and rec["manifest"]

        def marker(self):
            p = remote / "home" / ".eregion-image"
            return p.read_text().split() if p.exists() else None

        def calls(self):
            p = remote / "docker" / "calls"
            return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

        def loads(self):
            return [c for c in self.calls() if c[0] in ("load", "tag")]

        def az(self):
            p = tmp_path / "az.log"
            return p.read_text().splitlines() if p.exists() else []
    return Run()


def _updated(start, res):
    assert res.returncode == 0, res.stdout + res.stderr
    assert start.served() == start.images_["v0.5.10"].digest
    assert start.marker() == [start.commits["v0.5.10"], start.images_["v0.5.10"].digest]
    said = res.stdout + res.stderr
    # Said before it is done: the announcement, then the push's own lines (its archive).
    assert 0 <= said.index("make orodruin-push REF=v0.5.10") < said.index("chacun vérifié par son sha256")
    assert "✓ Orodruin à jour : v0.5.10" in res.stdout
    assert len(start.az()) == 1 and start.az()[0].startswith("az vm start --ids ")


def test_an_older_image_is_replaced_by_the_latest_release_verified(start):
    """v0.5.9 in service, v0.5.10 the latest release — by version order (by string order v0.5.9
    would be the latest, the image equal): pushed by orodruin-push, its control run included."""
    start.serve("v0.5.9")
    res = start.run()
    _updated(start, res)
    assert "image v0.5.9 (" in res.stderr and "dernière release v0.5.10 (" in res.stderr
    assert "plus ancienne" in res.stderr
    assert any(c[0] == "run" and "--network" in c and c[-1] == "eregion-annatar:incoming" for c in start.calls())


def _no_marker(s):
    (s.remote / "home" / ".eregion-image").unlink()


def _marker(text):
    return lambda s: (s.remote / "home" / ".eregion-image").write_text(text(s) if callable(text) else text)


def _no_image(s):
    (s.remote / "docker" / "images.json").write_text("{}")


@pytest.mark.parametrize("served, spoil, said", [
    ("v0.5.9", _no_marker, "sans ~/.eregion-image"),
    ("v0.5.9", _marker("garbage\n"), "illisible"),
    ("v0.5.9", _marker(lambda s: f"{s.commits['v0.5.10']} sha256:{'0' * 63}\n"), "illisible"),
    ("v0.5.9", _marker("x" * 5000), "illisible"),
    ("v0.5.10", _no_image, "aucune image eregion-annatar:orodruin"),   # its marker says the release
])
def test_an_image_absent_or_unreadable_is_replaced_by_the_latest_release(start, served, spoil, said):
    """No marker (a push cut after removing it), a marker that is no commit and digest, or no
    :orodruin at all even under a marker naming the release: pushed."""
    start.serve(served)
    spoil(start)
    res = start.run()
    assert said in res.stderr, res.stderr
    _updated(start, res)


def test_an_image_equal_to_the_latest_release_is_left_said_in_one_line(start):
    start.serve("v0.5.10")
    res = start.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert start.loads() == [] and start.served() == start.images_["v0.5.10"].digest
    c = start.commits["v0.5.10"][:12]
    assert [ln for ln in res.stderr.splitlines() if ln.strip()] == \
        [f"✓ image v0.5.10 ({c}), dernière release v0.5.10 ({c}) : à jour"]
    assert "orodruin-push" not in res.stdout


@pytest.mark.parametrize("name, marker, said", [
    ("head", "verified", "plus récente"),               # a commit of main pushed by hand
    ("v0.5.9", "dev", "non vérifiée"),                  # orodruin-push-dev, even from an older commit
    ("side", "verified", "ni plus ancienne ni plus récente"),
])
def test_an_image_newer_than_the_latest_release_is_never_replaced(start, name, marker, said):
    start.serve(name, marker)
    before = start.marker()
    res = start.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert said in res.stderr
    assert "jamais remplacée" in res.stdout and "make orodruin-push REF=v0.5.10" in res.stdout
    assert start.loads() == [] and start.served() == start.images_[name].digest
    assert start.marker() == before


def test_a_failed_push_stops_nonzero_nothing_armed_the_vm_said_started(start):
    """The control run fails (OI2): orodruin-push removes the image, :orodruin unchanged; start says
    the cause, that nothing is armed, that the VM stays started — and exits non-zero."""
    start.serve("v0.5.9")
    res = start.run(FAKE_RUN_EXIT="1")
    assert res.returncode != 0
    assert start.served() == start.images_["v0.5.9"].digest
    assert "ne démarre pas" in res.stderr and "rien n'est armé" in res.stderr
    assert "La VM reste démarrée" in res.stderr and "✓ Orodruin à jour" not in res.stdout


def test_an_image_whose_commit_is_unknown_here_decides_nothing(start):
    start.serve("v0.5.9", f"{'f' * 40} {start.images_['v0.5.9'].digest}\n")
    res = start.run()
    assert res.returncode != 0 and "inconnu ici" in res.stderr and "La VM reste démarrée" in res.stderr
    assert start.loads() == [] and start.served() == start.images_["v0.5.9"].digest


def test_a_vm_that_never_answers_stops_nonzero_nothing_sent(start):
    start.serve("v0.5.9")
    res = start.run(FAKE_SILENT="1")
    assert res.returncode != 0 and "ne répond pas" in res.stderr and "La VM reste démarrée" in res.stderr
    assert start.calls() == [] and len(start.az()) == 1


def test_no_update_starts_the_vm_and_says_it_reads_nothing(start):
    start.serve("v0.5.9")
    res = start.run("NO_UPDATE=1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "sans mise à jour (NO_UPDATE=1)" in res.stdout
    assert len(start.az()) == 1 and start.calls() == []
    assert start.marker() == [start.commits["v0.5.9"], start.images_["v0.5.9"].digest]


def test_ref_names_the_release_aimed_at(start):
    start.serve("v0.5.9")
    res = start.run("REF=v0.5.9")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "release visée v0.5.9" in res.stderr and start.loads() == []


@pytest.mark.parametrize("args, env, said", [
    (["NO_UPDATE=0"], {}, "NO_UPDATE invalide"),
    (["NO_UPDATE=yes"], {}, "NO_UPDATE invalide"),
    (["NO_UPDATE=$(shell touch pwned)"], {}, "NO_UPDATE invalide"),
    (["NO_UPDATE=1; touch pwned"], {}, "NO_UPDATE invalide"),
    (["REF=$(shell touch pwned)"], {}, "REF invalide"),
    (["REF=v1'; touch pwned; '"], {}, "REF invalide"),
    (["REF=--show"], {}, "REF invalide"),
    ([], {"REF": "v0.5.9"}, "vient de l'environnement"),
    ([], {"NO_UPDATE": "1"}, "vient de l'environnement"),
])
def test_values_refused_start_nothing_and_send_nothing(start, args, env, said):
    """Checked before anything: no az, nothing toward Orodruin, never expanded by make."""
    start.serve("v0.5.9")
    res = start.run(*args, **env)
    assert res.returncode != 0 and said in res.stderr
    assert start.az() == [] and start.calls() == []
    assert not list(start.tmp.rglob("pwned")) and not (ROOT / "pwned").exists()


@pytest.mark.parametrize("name, warned", [("v0.5.9", True), ("v0.5.10", False)])
def test_the_check_says_the_image_and_the_latest_release_a_warning_never_a_refusal(start, name, warned):
    start.serve(name)
    res = start.run(target="orodruin-check")
    assert res.returncode == 0, res.stdout + res.stderr           # the contract's code: armed here
    c = start.commits
    assert f"image {name} ({c[name][:12]}), dernière release v0.5.10 ({c['v0.5.10'][:12]})" in res.stderr
    assert ("plus ancienne : make orodruin-start ou make orodruin-push REF=v0.5.10" in res.stderr) == warned
    assert start.loads() == [] and start.az() == []
    assert start.calls()[-1][0] == "run" and start.calls()[-1][-3:] == ["python", "-m", "eregion_core.orodruin"]
