"""OI1 (#488): an image as the registry holds it — a manifest, its config, its layers, each by its
sha256 — and a fake docker that reads an archive as docker does, run as a program:

    python fake_oci.py docker load|save|pull|tag|image inspect|image rm|run …

Its state: $DOCKER_STATE/images.json ({name: record}) and $DOCKER_STATE/blobs/<hex>. Two stores,
as measured on 03/11 (#488), $FAKE_STORE:
- ``containerd`` (the default, Docker Desktop's and Orodruin's): an image's id is its manifest's
  digest. An archive without its config loads, an image nobody can tag or inspect (« failed to
  read config content: NotFound »), but `inspect -f {{.Id}}` answers; with its config, its layers
  are unpacked — one missing, or not the config's diff id, and the load fails.
- ``classic``: the id is the config's digest; the archive's manifest.json, its config and every
  layer must be there, each layer's diff id the config's.
`save` of an image pulled from a registry gives its index and its manifest only (the defect
measured under Docker Desktop: ~10 KB for ~630 MB); of an image loaded, the whole archive.
$FAKE_LOAD_DROP=config: the store loses the config after the load. $FAKE_LOAD_ID, $FAKE_LOAD_USER:
another id, another user than the archive's (a different image). Every call: $DOCKER_STATE/calls.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
CONFIG_V1 = "application/vnd.docker.container.image.v1+json"
LAYER_GZ = "application/vnd.docker.image.rootfs.diff.tar.gzip"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
LABELS = '{{index .Config.Labels "org.opencontainers.image.version"}} ' \
         '{{index .Config.Labels "org.opencontainers.image.revision"}}'


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def layer(files: dict) -> tuple[bytes, str]:
    """A layer: (its gzip bytes, its diff id — the sha256 of its tar)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            t.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0), sha(raw)


class Image:
    """A published image of Annatar: `n` layers, its config (its user, its commit), its manifest."""

    def __init__(self, commit: str, user: str = "app", n: int = 2, oci: bool = False, salt: str = "",
                 os_arch: tuple = ("linux", "amd64"), version: str = "v0.5.3"):
        self.blobs: dict[str, bytes] = {}
        descs, diff_ids = [], []
        for i in range(n):
            gz, diff = layer({f"layer{i}/file": f"{salt} layer {i} of {commit}".encode() * 50})
            self.blobs[sha(gz)] = gz
            descs.append({"mediaType": OCI_LAYER if oci else LAYER_GZ, "size": len(gz), "digest": sha(gz)})
            diff_ids.append(diff)
        self.config = {"architecture": os_arch[1], "os": os_arch[0],
                       "config": {"User": user, "Labels": {"org.opencontainers.image.revision": commit,
                                                           "org.opencontainers.image.version": version}},
                       "rootfs": {"type": "layers", "diff_ids": diff_ids}}
        self.config_raw = json.dumps(self.config, sort_keys=True).encode()
        self.blobs[sha(self.config_raw)] = self.config_raw
        self.manifest = {"schemaVersion": 2, "mediaType": OCI_MANIFEST if oci else MANIFEST_V2,
                         "config": {"mediaType": OCI_CONFIG if oci else CONFIG_V1, "size": len(self.config_raw),
                                    "digest": sha(self.config_raw)},
                         "layers": descs}
        self.diff_ids = diff_ids
        self.seal()

    def seal(self):
        """The manifest's bytes and digest, after a test changed it."""
        self.raw = json.dumps(self.manifest, sort_keys=True).encode()
        self.digest = sha(self.raw)
        self.blobs[self.digest] = self.raw
        return self.digest

    @property
    def config_digest(self) -> str:
        return self.manifest["config"]["digest"]

    @property
    def layers(self) -> list:
        return [d["digest"] for d in self.manifest["layers"]]

    def publish(self, fake, repo: str, tag: str | None) -> str:
        """In the fake registry (tests/unit/fake_discord.py): every blob, the manifest under `tag`."""
        entry = fake.registry.setdefault(repo, {"tags": {}, "blobs": {}})
        entry["blobs"].update(self.blobs)
        if tag:
            entry["tags"][tag] = self.digest
        return self.digest

    def write(self, where: Path) -> None:
        """For the operator's fake docker pull: the blobs, and which one is the manifest."""
        (where / "blobs").mkdir(parents=True, exist_ok=True)
        for d, data in self.blobs.items():
            (where / "blobs" / d.split(":", 1)[1]).write_bytes(data)
        (where / "manifest").write_text(self.digest)


# ── the fake docker, as a program ────────────────────────────────────────────────────────────────

def _state() -> Path:
    s = Path(os.environ["DOCKER_STATE"])
    (s / "blobs").mkdir(parents=True, exist_ok=True)
    return s


def _images(s: Path) -> dict:
    p = s / "images.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _save_images(s: Path, images: dict) -> None:
    (s / "images.json").write_text(json.dumps(images, indent=1))


def _blob(s: Path, digest: str):
    p = s / "blobs" / digest.split(":", 1)[1]
    return p.read_bytes() if p.exists() else None


def _put(s: Path, data: bytes) -> str:
    d = sha(data)
    (s / "blobs" / d.split(":", 1)[1]).write_bytes(data)
    return d


def _name(n: str) -> str:
    return n.removeprefix("docker.io/library/")


def _fail(text: str) -> None:
    sys.stderr.write(f"Error response from daemon: {text}\n")
    sys.exit(1)


def _load(s: Path) -> None:
    members = {}
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as t:
        for m in t:
            if m.isfile():
                members[m.name] = t.extractfile(m).read()
    for name, data in members.items():
        if name.startswith("blobs/sha256/") and sha(data) != "sha256:" + name.rsplit("/", 1)[1]:
            _fail(f"failed to ingest {name}: unexpected commit digest")
    store = os.environ.get("FAKE_STORE", "containerd")

    def by_digest(d):
        return members.get(f"blobs/sha256/{d.split(':', 1)[1]}")
    if store == "classic":
        if "manifest.json" not in members:
            _fail("open manifest.json: no such file or directory")
        legacy = json.loads(members["manifest.json"])[0]
        cfg_raw = members.get(legacy["Config"])
        if cfg_raw is None:
            _fail(f"open {legacy['Config']}: no such file or directory")
        cfg = json.loads(cfg_raw)
        for i, path in enumerate(legacy["Layers"]):
            data = members.get(path)
            if data is None:
                _fail(f"open {path}: no such file or directory")
            if sha(gzip.decompress(data)) != cfg["rootfs"]["diff_ids"][i]:
                _fail("invalid diffID for layer")
        name, mdigest, cdigest = legacy["RepoTags"][0], "", sha(cfg_raw)
        ident = cdigest
        _put(s, cfg_raw)
    else:
        index = json.loads(members.get("index.json") or b"{}")
        desc = (index.get("manifests") or [{}])[0]
        mraw = by_digest(desc.get("digest", "sha256:"))
        if mraw is None:
            _fail(f"content digest {desc.get('digest')}: not found")
        name = _name((desc.get("annotations") or {}).get("io.containerd.image.name", ""))
        mdigest = _put(s, mraw)
        doc = json.loads(mraw)
        cdigest = doc["config"]["digest"]
        cfg_raw = by_digest(cdigest)
        if cfg_raw is not None:
            _put(s, cfg_raw)
            cfg = json.loads(cfg_raw)
            for i, d in enumerate(x["digest"] for x in doc["layers"]):
                data = by_digest(d)
                if data is None:
                    _fail(f"failed to unpack image: content digest {d}: not found")
                if sha(gzip.decompress(data)) != cfg["rootfs"]["diff_ids"][i]:
                    _fail("failed to unpack image: wrong diff id")
                _put(s, data)
        ident = mdigest
    images = _images(s)
    rec = {"id": os.environ.get("FAKE_LOAD_ID") or ident, "manifest": mdigest,
           "config": None if os.environ.get("FAKE_LOAD_DROP") == "config" else cdigest,
           "user": os.environ.get("FAKE_LOAD_USER"), "loaded": True}
    if rec["config"] and _blob(s, rec["config"]) is None:
        rec["config"] = None
    images[name] = rec
    _save_images(s, images)
    print(f"Loaded image: {name}")


def _config(s: Path, rec: dict):
    raw = _blob(s, rec["config"]) if rec.get("config") else None
    if raw is None:
        _fail(f"failed to read config content: NotFound: content digest {rec.get('config') or '?'}: not found")
    cfg = json.loads(raw)
    if rec.get("user") is not None:
        cfg["config"]["User"] = rec["user"]
    return cfg


def _inspect(s: Path, args: list) -> None:
    fmt = args[args.index("-f") + 1] if "-f" in args else ""
    rec = _images(s).get(args[-1])
    if rec is None:
        _fail(f"No such image: {args[-1]}")
    if fmt == "{{.Id}}":
        print(rec["id"])                  # measured: answered, the config gone or not
        return
    cfg = _config(s, rec)
    labels = cfg["config"].get("Labels") or {}
    if fmt == LABELS:
        print(f"{labels.get('org.opencontainers.image.version', '<no value>')} "
              f"{labels.get('org.opencontainers.image.revision', '<no value>')}")
        return
    if fmt:
        _fail(f"unknown format {fmt}")
    print(json.dumps([{"Id": rec["id"], "RepoTags": [args[-1]], "Os": cfg["os"], "Architecture": cfg["architecture"],
                       "Config": cfg["config"], "RootFS": {"Type": "layers", "Layers": cfg["rootfs"]["diff_ids"]}}],
                     indent=4))


def _save(s: Path, name: str) -> None:
    rec = _images(s).get(name)
    if rec is None:
        _fail(f"No such image: {name}")
    mraw = _blob(s, rec["manifest"])
    doc = json.loads(mraw)
    blobs = {rec["manifest"]: mraw}
    if rec.get("loaded"):                 # an image loaded keeps its content; one pulled, not (#488)
        for d in [doc["config"]["digest"], *(x["digest"] for x in doc["layers"])]:
            blobs[d] = _blob(s, d)
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as t:
        def add(n, data):
            info = tarfile.TarInfo(n)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for d, data in blobs.items():
            add(f"blobs/sha256/{d.split(':', 1)[1]}", data)
        add("index.json", json.dumps({"schemaVersion": 2, "manifests": [
            {"mediaType": doc.get("mediaType"), "digest": rec["manifest"], "size": len(mraw),
             "annotations": {"io.containerd.image.name": f"docker.io/library/{name}"}}]}).encode())
        add("manifest.json", json.dumps([{"Config": f"blobs/sha256/{doc['config']['digest'].split(':', 1)[1]}",
                                          "RepoTags": [name], "Layers": []}]).encode())
        add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
    sys.stdout.buffer.write(out.getvalue())


def docker(args: list) -> None:
    s = _state()
    with open(s / "calls", "a") as f:
        f.write(json.dumps(args) + "\n")
    images = _images(s)
    if args[0] == "load":
        return _load(s)
    if args[0] == "save":
        return _save(s, args[-1])
    if args[0] == "pull":                 # from $FAKE_PUBLISHED: what the registry holds
        pub = Path(os.environ["FAKE_PUBLISHED"])
        mdigest = (pub / "manifest").read_text().strip()
        for p in (pub / "blobs").iterdir():
            _put(s, p.read_bytes())
        doc = json.loads(_blob(s, mdigest))
        images[args[-1]] = {"id": mdigest, "manifest": mdigest, "config": doc["config"]["digest"], "loaded": False}
        _save_images(s, images)
        print(args[-1])
        return None
    if args[0] == "tag":
        rec = images.get(args[1])
        if rec is None:
            _fail(f"No such image: {args[1]}")
        _config(s, rec)
        images[args[2]] = dict(rec)
        _save_images(s, images)
        return None
    if args[:2] == ["image", "rm"]:
        if images.pop(args[2], None) is None:
            _fail(f"No such image: {args[2]}")
        _save_images(s, images)
        return None
    if args[:2] == ["image", "inspect"]:
        return _inspect(s, args[2:])
    if args[0] == "run":
        return None
    _fail(f"fake docker: {args}")


if __name__ == "__main__":
    if sys.argv[1] == "docker":
        docker(sys.argv[2:])
