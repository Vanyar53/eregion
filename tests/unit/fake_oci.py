"""OI1 (#488): an image as the registry holds it — a manifest, its config, its layers, each by its
sha256 — and a fake docker that reads an archive as docker does, run as a program:

    python fake_oci.py docker load|save|pull|tag|image inspect|image rm|run|rm …

Its state: $DOCKER_STATE/images.json ({name: record}), $DOCKER_STATE/blobs/<hex>, the layers
unpacked ($DOCKER_STATE/snapshots/<diff id hex>) and the containers ($DOCKER_STATE/containers.json,
{name: image}). Two stores,
as measured on 03/11 (#488), $FAKE_STORE:
- ``containerd`` (the default, Docker Desktop's and Orodruin's): an image's id is its manifest's
  digest. An archive without its config loads, an image nobody can tag (« failed to read config
  content: NotFound »); `docker image inspect` answers a partial JSON — its id, no config, no
  layers (the CLI applies -f on its side: `-f {{.Id}}` answered, measured); with its config, its layers
  are unpacked — one missing, or not the config's diff id, and the load fails.
- ``classic``: the id is the config's digest; the archive's manifest.json, its config and every
  layer must be there, each layer's diff id the config's.
`save` of an image pulled from a registry gives its index and its manifest only (the defect
measured under Docker Desktop: ~10 KB for ~630 MB); of an image loaded, the whole archive.
$FAKE_LOAD_DROP=config: the store loses the config after the load; =layer (OI2, #490): its last
layer, the blob and the snapshot — the config still read, `docker image inspect` whole, its layers
listed from the config (`RootFS.Layers`). $FAKE_LOAD_ID, $FAKE_LOAD_USER: another id, another user
than the archive's (a different image). Every call: $DOCKER_STATE/calls.

`run` (OI2) creates its container as docker does: the image named, never pulled under `--pull never`
(and never reached otherwise: no registry), its config read, every layer of it unpacked (else exit
125, « failed to prepare snapshot »); then runs it — $FAKE_RUN_HANG=<s>: it hangs that long first;
$FAKE_RUN_EXIT=<n>: its command exits n — and, under `--rm`, removes it. A container left (its run
killed) holds its image: `image rm` of that name refuses, `rm -f` takes it off.

`info` (OI3) answers; $FAKE_DOCKER_DOWN: the daemon answers nothing, every call fails.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
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


def _fail(text: str, code: int = 1) -> None:
    sys.stderr.write(f"Error response from daemon: {text}\n")
    sys.exit(code)


def _unpack(s: Path, diff_id: str) -> None:
    (s / "snapshots").mkdir(exist_ok=True)
    (s / "snapshots" / diff_id.split(":", 1)[1]).touch()


def _unpacked(s: Path, diff_id: str) -> bool:
    return (s / "snapshots" / diff_id.split(":", 1)[1]).exists()


def _containers(s: Path) -> dict:
    p = s / "containers.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _save_containers(s: Path, containers: dict) -> None:
    (s / "containers.json").write_text(json.dumps(containers, indent=1))


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
            _put(s, data)
            _unpack(s, cfg["rootfs"]["diff_ids"][i])
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
                _unpack(s, cfg["rootfs"]["diff_ids"][i])
        ident = mdigest
    images = _images(s)
    rec = {"id": os.environ.get("FAKE_LOAD_ID") or ident, "manifest": mdigest,
           "config": None if os.environ.get("FAKE_LOAD_DROP") == "config" else cdigest,
           "user": os.environ.get("FAKE_LOAD_USER"), "loaded": True}
    if rec["config"] and _blob(s, rec["config"]) is None:
        rec["config"] = None
    if os.environ.get("FAKE_LOAD_DROP") == "layer":       # the last layer lost after the load
        lost = json.loads(_blob(s, cdigest))["rootfs"]["diff_ids"][-1]
        (s / "snapshots" / lost.split(":", 1)[1]).unlink()
        if mdigest:
            gone = json.loads(_blob(s, mdigest))["layers"][-1]["digest"]
            (s / "blobs" / gone.split(":", 1)[1]).unlink()
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
    if rec.get("config") is None or _blob(s, rec["config"]) is None:
        # Measured (#488): `-f {{.Id}}` answered for the image without its config — the CLI applies
        # -f on its side, so the API (GET /images/{name}/json) answered 200: a partial JSON, its id,
        # no config, no layers.
        if fmt == "{{.Id}}":
            print(rec["id"])
            return
        if fmt:
            _fail("template: :1:8: executing \"\" at <.Config.Labels>: nil pointer evaluating")
        print(json.dumps([{"Id": rec["id"], "RepoTags": [args[-1]], "Config": None,
                           "RootFS": {"Type": "layers"}}], indent=4))
        return
    if fmt == "{{.Id}}":
        print(rec["id"])
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
    if os.environ.get("FAKE_DOCKER_DOWN"):        # OI3: the daemon does not answer, to anything
        sys.stderr.write("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                         "Is the docker daemon running?\n")
        sys.exit(1)
    images = _images(s)
    if args[0] == "info":
        print("Server Version: fake")
        return None
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
        held = [c for c, img in _containers(s).items() if img == args[2]]
        if held:
            _fail(f'conflict: unable to remove repository reference "{args[2]}" (must force) - container '
                  f"{held[0]} is using its referenced image")
        if images.pop(args[2], None) is None:
            _fail(f"No such image: {args[2]}")
        _save_images(s, images)
        return None
    if args[:2] == ["image", "inspect"]:
        return _inspect(s, args[2:])
    if args[0] == "run":
        return _run(s, images, args[1:])
    if args[:2] == ["rm", "-f"]:
        containers = _containers(s)
        if containers.pop(args[2], None) is None:
            _fail(f"No such container: {args[2]}")
        _save_containers(s, containers)
        return None
    _fail(f"fake docker: {args}")


# The options of `docker run` that take a value (those the tests pass).
_RUN_VALUED = {"--network", "--name", "--entrypoint", "--pull", "--cap-drop", "--security-opt", "--tmpfs",
               "-v", "--volume", "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir"}


def _run(s: Path, images: dict, args: list) -> None:
    opts, i = {}, 0
    while i < len(args) and args[i].startswith("-"):
        valued = args[i] in _RUN_VALUED
        opts.setdefault(args[i], []).append(args[i + 1] if valued else True)
        i += 2 if valued else 1
    name = args[i]
    rec = images.get(name)
    if rec is None:
        sys.stderr.write(f"Unable to find image '{name}' locally\n")
        if (opts.get("--pull") or ["missing"])[-1] == "never":
            _fail(f"No such image: {name}", 125)
        _fail(f"pull access denied for {name.split(':')[0]}, repository does not exist", 125)
    raw = _blob(s, rec["config"]) if rec.get("config") else None
    if raw is None:
        _fail(f"failed to create container: content digest {rec.get('config') or '?'}: not found", 125)
    for diff_id in json.loads(raw)["rootfs"]["diff_ids"]:
        if not _unpacked(s, diff_id):
            _fail(f"failed to create container: failed to prepare snapshot: snapshot {diff_id} does not "
                  "exist: not found", 125)
    containers = _containers(s)
    cname = (opts.get("--name") or [f"c{len(containers)}"])[-1]
    if cname in containers:
        _fail(f'Conflict. The container name "/{cname}" is already in use by another container', 125)
    containers[cname] = name
    _save_containers(s, containers)
    time.sleep(float(os.environ.get("FAKE_RUN_HANG") or 0))
    if "--rm" in opts:
        containers = _containers(s)
        containers.pop(cname, None)
        _save_containers(s, containers)
    sys.exit(int(os.environ.get("FAKE_RUN_EXIT") or 0))


if __name__ == "__main__":
    if sys.argv[1] == "docker":
        docker(sys.argv[2:])
