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

from .fake_discord import FakeDiscord
from .fake_sigstore import Sigstore, claims, envelope, statement

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "published_image.py"
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
C1, C2 = "1" * 40, "2" * 40
GLOR = "vanyar53/eregion-glorfindel"


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
    assert tokened and "scope=repository:vanyar53/eregion-glorfindel:pull" in tokened[0]["path"]


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
        args = pim.cosign_args(kind, "ghcr.io/x@sha256:" + "a" * 64, C2, "Vanyar53/eregion")
        got = {args[i]: args[i + 1] for i, a in enumerate(args) if a.startswith("--certificate")}
        assert got == {
            "--certificate-identity": "https://github.com/Vanyar53/eregion/.github/workflows/publish.yml@refs/heads/main",
            "--certificate-oidc-issuer": "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-repository": "Vanyar53/eregion",
            "--certificate-github-workflow-ref": "refs/heads/main",
            "--certificate-github-workflow-trigger": "push", "--certificate-github-workflow-sha": C2}
        assert args[-1].startswith("ghcr.io/x@sha256:")
    assert pim.cosign_args("provenance", "r", C2)[:3] == ["verify-attestation", "--type", "https://slsa.dev/provenance/v1"]
    assert pim.cosign_args("signature", "r", C2)[0] == "verify"


def _signed(pim, sig, digest, commit=C2, slug="Vanyar53/eregion", **over):
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
    ({"slug": "Vanyar53/fork"}, "signature absente, ou d'un autre"),
])
def test_an_image_signed_by_another_signer_is_unverified(pim, sig, over, said):
    digest = "sha256:" + "a" * 64
    slug = over.pop("slug", "Vanyar53/eregion")
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


def test_a_signed_image_without_provenance_is_unverified(pim, sig):
    digest = "sha256:" + "a" * 64
    sig.sign(digest, claims("Vanyar53/eregion", C2))
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
    return statement(name, digest, over.pop("slug", "Vanyar53/eregion"), over.pop("commit", C2), **over)


@pytest.mark.parametrize("st, said", [
    (_st(predicate_type="https://spdx.dev/Document/v2.3"), "autre type"),
    (_st(name="ghcr.io/vanyar53/eregion-annatar"), "ne porte pas sur"),
    (_st(digest="sha256:" + "b" * 64), "ne porte pas sur"),
    (_st(workflow=".github/workflows/images.yml"), "workflow"),
    (_st(slug="Vanyar53/fork"), "dépôt"),
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
    good = claims("Vanyar53/eregion", C2)

    def runner(argv):
        if argv[1] == "verify":
            return _done(argv, 0, json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}}}]))
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


def test_a_failed_pull_is_unavailable(pim):
    with pytest.raises(pim.Unavailable):
        pim.pull("glorfindel", "sha256:" + "a" * 64, "x", C2, runner=lambda argv: _done(argv, 1, "", "network"))


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


def test_loaded_accepts_only_an_id_under_the_verified_digest(pim, reg, capsys):
    top = reg.image(GLOR, f"sha-{C2}", _manifest(C2))
    config = _manifest(C2)["config"]["digest"]
    assert pim.main(["loaded", "glorfindel", "--digest", top, "--id", config + "\n"]) == 0
    assert pim.main(["loaded", "glorfindel", "--digest", top, "--id", "sha256:" + "f" * 64]) == 1


# ── the workflow's side ──────────────────────────────────────────────────────────────────────

def test_the_workflows_names_and_labels(pim, tmp_path, monkeypatch):
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert pim.main(["meta", "annatar", "--commit", C2]) == 0
    got = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert got == {"name": "ghcr.io/vanyar53/eregion-annatar", "ref": f"ghcr.io/vanyar53/eregion-annatar:sha-{C2}",
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
    assert "aucune image" in capsys.readouterr().err
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
    """make orodruin-push: no build — the digest resolved and proven on this machine, pulled by it,
    loaded over SSH (Orodruin's egress stays closed), its id read back there against the digest."""
    out = _make_n("orodruin-push", "REF=v0.4.6")
    assert "docker build" not in out
    lines = out.splitlines()
    fetch = next(i for i, line in enumerate(lines) if "published_image.py fetch annatar" in line)
    assert '--ref "$EREGION_DEPLOY_REF" --tag eregion-annatar:orodruin' in lines[fetch]
    assert "|| exit 1" in lines[fetch]
    rest = "\n".join(lines[fetch:])
    assert rest.index("docker save eregion-annatar:orodruin") < rest.index("published_image.py loaded annatar")
    assert 'docker image inspect -f "{{.Id}}" eregion-annatar:orodruin' in rest
    assert rest.index("published_image.py loaded annatar") < rest.index("cat > .eregion-image")
    assert "install-cosign" in out and "environment*" in out


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
