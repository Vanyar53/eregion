"""SEC19 (N-03, #456): the watch's key — its heartbeat signed, verified by the injectors with a key
pinned on their side.

**The key.** An Ed25519 pair the watch alone holds. Its private half is drawn at the first start of
a watch that has none, in ``~/.eregion/watch-key/watch_ed25519`` (32 raw bytes, mode 0600, its
directory 0700): a directory only the watch's service mounts (docker-compose.yml) — never in
``~/.glorfindel`` (the console and the bot mount it, the injectors a part of it), never under
``runs/``. A key file readable by others, a link, another owner, a file of another size: refused,
never used, and said (``KeyUnavailable``). ``glorfindel watch-key`` prints its public half and its
fingerprint, for the operator to pin (``make watch-key``, ``make glorfindel-host-watch-key``).

**The heartbeat signed.** What the watch writes for the injectors (``~/.glorfindel/injectors/
watch_heartbeat``) and in the return channel (``heartbeat.json``) carries ``seq`` (a counter that
only goes up: the milliseconds of its date, one more than the last when two fall in the same one),
``key`` (the signer's fingerprint, said, never trusted) and ``sig``: the signature of the domain
``DOMAIN_BEAT`` followed by the canonical JSON of every other field (sorted keys, no spaces) —
the date, the perimeter, and on the channel ``since`` and ``windows`` as well.

**The injectors' side** (eregion_core/watch_gate.py): the public key comes from
``EREGION_WATCH_KEY`` only — the injector's environment (orodruin.env on Orodruin, the operator's on
a workstation), never the channel nor the heartbeat itself. Refused, before any call to the cloud:
no key pinned (the gesture said), a heartbeat unsigned, signed by another key, whose signature does
not hold, or whose counter is below one already seen (``remember``: the highest counter seen per
key, in ``runs/orodruin/.watch_seen.json``, the injectors' own directory; an older heartbeat
replayed after a newer one).

**The detections signed (SEC21, #530).** Each detection the watch publishes on the return channel
(``detections/<run_id>/<signal_id>.json``) carries ``key`` and ``sig`` too: the signature of the
domain ``DOMAIN_DETECTION`` — never the heartbeat's — followed by the canonical JSON of every
other field: the run (``exercise_run``), the signal (``signal_id``), what was seen (``event``,
``ttp``, ``resource_id``, ``rule``, ``watch_run_id``) and when (``detected_at``). An injector
believes one only when the pinned key signed it under that domain, for the run it reads and under
the signal's own name (``detection_refusal``): unsigned, another key, another domain, a field
changed, copied from another run or another signal — never counted, and said.

**FS1 takes this key up** (#413, docs/design/watch-key.md): one key, three uses, each signed under
its own domain — a heartbeat never reads as a detection nor as an action of the queue, nor the
reverse. FS1a (#551): the watch signs the proposal of each card that holds an action under
``DOMAIN_QUEUE`` (eregion_core/action_queue.py), with this key and its counter.

**One draw of a key, two uses (FS1a).** ``load_or_create`` draws and loads the watch's key and,
under another file name, each service's key of the action queue (the console's, the bot's:
``action_queue.load_service_key``) — the same rules for both, said in their holder's words
(``_HOLDERS``). The watch's key, its place, its messages and what it signs are unchanged.

``cryptography`` is imported where a key is drawn, used or checked, never at import: the
fingerprint of a public key, and reading the pin, need the standard library only.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

KEY_ENV = "EREGION_WATCH_KEY"
DOMAIN_BEAT = "eregion.watch-beat/1"
# SEC21 (#530): a detection of the return channel — the same key, its own domain.
DOMAIN_DETECTION = "eregion.watch-detection/1"
# FS1 (#413): what the watch signs for the action queue — a card's proposal, later its receipts and
# its status (eregion_core/action_queue.py) — another domain, the same key.
DOMAIN_QUEUE = "eregion.action-queue/1"
PREFIX = "ed25519:"
KEY_FILE = "watch_ed25519"
SEEN_NAME = ".watch_seen.json"
SIGNED = ("seq", "key", "sig")       # what signing adds to a heartbeat
SIGNED_DETECTION = ("key", "sig")    # what signing adds to a detection (SEC21)
_PIN = re.compile(r"^ed25519:([A-Za-z0-9+/]{43}=)$")
_SIG = re.compile(r"[A-Za-z0-9+/]{86}==")

# The tests point these at their own tmp dir (tests/unit/conftest.py): never the operator's.
KEY_DIR: Path | None = None
SEEN_FILE: Path | None = None

PIN_GESTURE = (f"pin the watch's public key: {KEY_ENV}=ed25519:… in orodruin.env (Orodruin) or in "
               "your environment (a workstation) — `make glorfindel-host-watch-key` (H0) or "
               "`make watch-key` (this host) gives it")


class KeyUnavailable(Exception):
    """The watch's key cannot be used: what is wrong, and what to do."""


@dataclass(frozen=True)
class _Holder:
    """Who holds a key drawn by ``load_or_create``, in the words its refusals use."""
    user: str       # whose user the key's file and directory must belong to
    redraw: str     # what to do once a key of another size is removed


# FS1a (#551): one draw of a key, two uses — by the name of the key's file. The watch's words are
# those of SEC19, unchanged; a service's of the queue (eregion_core/action_queue.py) its own.
SERVICE_KEY_FILE = "queue_ed25519"
_HOLDERS = {
    KEY_FILE: _Holder("the watch's user",
                      "let the watch draw another at its next start, then pin the new public key "
                      "(make watch-key, make glorfindel-host-watch-key)"),
    SERVICE_KEY_FILE: _Holder("the service's user",
                              "let the service draw another at its next start, then pin the new public "
                              "key at the watch (EREGION_QUEUE_KEYS)"),
}


def key_dir() -> Path:
    return KEY_DIR if KEY_DIR is not None else Path.home() / ".eregion" / "watch-key"


def fingerprint(public: bytes) -> str:
    """``SHA256:`` and the base64 of the sha256 of the 32 raw bytes, without padding — the form
    of an SSH fingerprint."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("=")


def public_text(public: bytes) -> str:
    return PREFIX + base64.b64encode(public).decode()


def message(domain: str, body: dict) -> bytes:
    """What is signed: the domain, a newline, then the canonical JSON of the body without ``sig``."""
    rest = {k: v for k, v in body.items() if k != "sig"}
    return domain.encode() + b"\n" + json.dumps(rest, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=True).encode()


# ── The watch's side ──────────────────────────────────────────────────────────────────

class Signer:
    """A private key in memory — the watch's, or a service's of the action queue (FS1a); ``sign``
    under a domain, ``next_seq`` that only rises."""

    def __init__(self, private: bytes):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._key = Ed25519PrivateKey.from_private_bytes(private)
        self.public = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = fingerprint(self.public)
        self._seq = 0
        self._lock = threading.Lock()

    def next_seq(self, at: datetime) -> int:
        with self._lock:
            self._seq = max(self._seq + 1, int(at.timestamp() * 1000))
            return self._seq

    def sign(self, domain: str, body: dict) -> str:
        return base64.b64encode(self._key.sign(message(domain, body))).decode()


def _misplaced(directory: Path) -> str:
    """Why the key may not live here — "" when it may: never in ~/.glorfindel (mounted by the
    console, the bot, the injectors for their part), never under a runs/ directory."""
    from eregion_core import runs_layout
    real = directory.resolve()
    for place, said in (((Path.home() / ".glorfindel").resolve(),
                         "~/.glorfindel, which the console, the bot and the injectors mount"),
                        (runs_layout.ROOT.resolve(), "runs/, which the injectors mount")):
        if real == place or place in real.parents:
            return f"{directory} is under {said}"
    return ""


def _held_dir(directory: Path, holder: _Holder = _HOLDERS[KEY_FILE]) -> None:
    """The key's directory: made 0700 when absent; a link or another owner's refused; its mode
    brought back to 0700 when it is ours and wider."""
    try:
        st = os.lstat(directory)
    except FileNotFoundError:
        directory.parent.mkdir(parents=True, exist_ok=True)
        os.mkdir(directory, 0o700)
        st = os.lstat(directory)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise KeyUnavailable(f"{directory} is not a directory (a link?): the key is not kept there")
    if st.st_uid != os.getuid():
        raise KeyUnavailable(f"{directory} belongs to uid {st.st_uid}, not to {holder.user} "
                             f"({os.getuid()}) — made by docker as root? `sudo chown {os.getuid()} {directory}`")
    if st.st_mode & 0o077:
        os.chmod(directory, 0o700)


def _read_key(path: Path) -> bytes:
    holder = _HOLDERS.get(path.name, _HOLDERS[KEY_FILE])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyUnavailable(f"{path} is not a regular file")
        if st.st_uid != os.getuid():
            raise KeyUnavailable(f"{path} belongs to uid {st.st_uid}, not to {holder.user}")
        if st.st_mode & 0o077:
            raise KeyUnavailable(f"{path} is readable by others (mode {stat.S_IMODE(st.st_mode):o}): "
                                 "never used — a key seen by others is drawn again (remove it, then pin "
                                 "the new public key)")
        data = os.read(fd, 64)
    finally:
        os.close(fd)
    if len(data) != 32:
        raise KeyUnavailable(f"{path} is not an Ed25519 key ({len(data)} bytes, 32 expected): remove it, "
                             f"{holder.redraw}")
    return data


def _sweep(directory: Path) -> None:
    """The temporaries of a draw a crash cut (between the link and the unlink): each a copy of the
    private key — removed, a link removed itself, never what it points to. Those of every key
    ``load_or_create`` draws (FS1a): a key's directory holds one key, and its temporaries only."""
    prefix = tuple(f".{name}." for name in _HOLDERS)
    with os.scandir(directory) as it:
        for e in it:
            if e.name.startswith(prefix) and not e.is_dir(follow_symlinks=False):
                os.unlink(os.path.join(directory, e.name))


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_or_create(directory: Path | None = None, *, name: str = KEY_FILE) -> Signer:
    """The watch's key: read from its directory, drawn there when absent — whole, in a file of its
    own (``O_EXCL``, a unique name), fsync'd, then published by a link and the directory fsync'd:
    a full disk or a crash never leaves a partial key under its name, and two watches starting
    together never write two. A temporary a crash left (``.watch_ed25519.*``, a copy of the private
    key) is swept first — removed, never followed. Raises KeyUnavailable.

    ``name`` (FS1a): the key's file — ``KEY_FILE``, the watch's, by default; a service's of the
    action queue (``SERVICE_KEY_FILE``) in its own directory, by the same code and the same rules."""
    holder = _HOLDERS[name]
    directory = Path(directory) if directory is not None else key_dir()
    why = _misplaced(directory)
    if why:
        raise KeyUnavailable(why)
    try:
        _held_dir(directory, holder)
        _sweep(directory)
        path = directory / name
        try:
            return Signer(_read_key(path))
        except FileNotFoundError:
            pass
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        # Drawn whole in a file of its own, then published by a link: the key's name never holds a
        # partial key (a full disk, a crash), and two watches starting together never write two.
        tmp = directory / f".{name}.{os.getpid()}.{os.urandom(6).hex()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            try:
                if os.write(fd, raw) != len(raw):
                    raise OSError(f"short write of {tmp}")
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, path)
            except FileExistsError:        # another watch drew it first: that one is the key
                pass
        finally:
            tmp.unlink(missing_ok=True)
        _fsync_dir(directory)
        return Signer(_read_key(path))
    except KeyUnavailable:
        raise
    except ImportError as e:
        raise KeyUnavailable(f"cryptography absent ({e}): no key") from None
    except OSError as e:
        raise KeyUnavailable(f"{directory}: {e}") from None


def read_public(directory: Path | None = None, *, name: str = KEY_FILE) -> bytes:
    """The public half of the key already drawn — never draws one. Raises KeyUnavailable.
    ``name`` (FS1b): a service's key of the action queue (``SERVICE_KEY_FILE``), for
    ``make queue-keys``."""
    directory = Path(directory) if directory is not None else key_dir()
    path = directory / name
    try:
        return Signer(_read_key(path)).public
    except FileNotFoundError:
        if name != KEY_FILE:
            raise KeyUnavailable(f"no key in {directory}: the service draws it at its first start with "
                                 "EREGION_ACTION_QUEUE=1 — or this container does not mount it") from None
        raise KeyUnavailable(f"no key in {directory}: the watch draws it at its first start "
                             "(make glorfindel-start, or H0 deployed) — or this container does not mount it "
                             "(only the watch's does: in make glorfindel-shell it is not mounted; make "
                             "watch-key on the host reads it)") from None
    except ImportError as e:
        raise KeyUnavailable(f"cryptography absent ({e})") from None
    except OSError as e:
        raise KeyUnavailable(f"{path}: {e}") from None


_shared: Signer | None = None
_shared_lock = threading.Lock()


def shared() -> tuple[Signer | None, str]:
    """The watch process's signer, loaded once it loads: (signer, "") or (None, why). Tried again
    at each call while it fails — a directory fixed is taken up without a restart."""
    global _shared
    with _shared_lock:
        if _shared is not None and KEY_DIR is None:
            return _shared, ""
        try:
            signer = load_or_create()
        except KeyUnavailable as e:
            return None, str(e)
        if KEY_DIR is None:
            _shared = signer
        return signer, ""


def sign_beat(body: dict, signer: Signer, at: datetime) -> dict:
    """The heartbeat with its counter, its signer's fingerprint and its signature."""
    out = {k: v for k, v in body.items() if k not in SIGNED}
    out["seq"] = signer.next_seq(at)
    out["key"] = signer.fingerprint
    out["sig"] = signer.sign(DOMAIN_BEAT, out)
    return out


def signature_bytes(sig) -> bytes | None:
    """The 64 bytes of a signature written in its one canonical form — None for any other: not a
    string, not 86 base64 characters and ``==`` (matched whole: no newline after), a character out
    of the alphabet, or a last character whose unused bits are set (FS1a review: 16 spellings of a
    single signature decoded alike, so one body had 16 digests). The watch writes this form only
    (``base64.b64encode``)."""
    if not isinstance(sig, str) or not _SIG.fullmatch(sig):
        return None
    try:
        raw = base64.b64decode(sig, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw).decode() == sig else None


def holds(public: bytes, domain: str, body) -> bool:
    """Does ``body["sig"]`` hold for ``public`` under ``domain`` (FS1a: the queue's requests and
    proposals)? Never raises: a body or a signature that is not one, a key that is not one,
    cryptography absent — False."""
    raw = signature_bytes(body.get("sig") if isinstance(body, dict) else None)
    if raw is None:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(raw, message(domain, body))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False
    return True


def sign_detection(body: dict, signer: Signer) -> dict:
    """SEC21: a detection of the return channel with its signer's fingerprint and its signature,
    under ``DOMAIN_DETECTION`` — every other field covered: its run, its signal, what was seen,
    when. No counter: what binds it is its run and its signal, which the reader compares with
    the blob it read."""
    out = {k: v for k, v in body.items() if k not in SIGNED_DETECTION}
    out["key"] = signer.fingerprint
    out["sig"] = signer.sign(DOMAIN_DETECTION, out)
    return out


# ── The injectors' side ───────────────────────────────────────────────────────────────

def parse_pin(text: str) -> tuple[bytes | None, str]:
    """``ed25519:<base64 of 32 bytes>`` → (the key, ""); else (None, why)."""
    text = (text or "").strip()
    if not text:
        return None, f"no watch key pinned ({KEY_ENV}): {PIN_GESTURE}"
    m = _PIN.match(text)
    if not m:
        return None, f"{KEY_ENV} is not a watch key (ed25519:<base64 of 32 bytes>): {PIN_GESTURE}"
    return base64.b64decode(m.group(1)), ""


def pinned() -> tuple[bytes | None, str]:
    """The key this injector trusts: its environment's, nothing else."""
    return parse_pin(os.environ.get(KEY_ENV, ""))


_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")


def _short(fp: str) -> str:
    """A fingerprint as said — the one a heartbeat or a detection claims is the channel's text:
    printable ASCII only (SEC21: never an escape sequence to the terminal nor the report)."""
    fp = _UNPRINTABLE.sub("?", fp)
    return fp[:19] + "…" if len(fp) > 19 else fp


def verify_beat(body: dict, key: bytes) -> str:
    """Why this heartbeat is not one the pinned key signed — "" when it is."""
    sig = body.get("sig")
    if sig is None:
        return ("unsigned: a watch older than this injector (update Glorfindel), or one whose key is "
                "unavailable (its log says why)")
    want = fingerprint(key)
    said = body.get("key")
    if said != want:
        return (f"signed by another key ({_short(str(said or 'none'))}) than the one pinned "
                f"({_short(want)}): another watch, or a key drawn again — pin the new one if it is yours")
    seq = body.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return "its counter (seq) is not a number"
    if signature_bytes(sig) is None:
        return "its signature is not one (64 bytes in base64)"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:
        return f"cryptography absent ({e}): the signature cannot be checked"
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(sig), message(DOMAIN_BEAT, body))
    except (InvalidSignature, ValueError, binascii.Error):
        return "its signature does not hold: changed after it was signed, or not signed by the pinned key"
    return ""


UNSIGNED_DETECTION = ("unsigned: a watch older than this injector (update Glorfindel — H0 by its CD, a "
                      "workstation's by make glorfindel-restart), or one whose key is unavailable (its "
                      "log says why)")


def detection_refusal(body, key: bytes, *, run_id: str, signal_id: str) -> str:
    """SEC21: why this detection, read as ``detections/<run_id>/<signal_id>.json``, is not one the
    pinned key signed for this run and this signal — "" when it is. Never counted for « seen »
    when it is not, whatever it says."""
    if not isinstance(body, dict):
        return "not a JSON object"
    sig = body.get("sig")
    if sig is None:
        return UNSIGNED_DETECTION
    want = fingerprint(key)
    if body.get("key") != want:
        return (f"signed by another key ({_short(str(body.get('key') or 'none'))}) than the one "
                f"pinned ({_short(want)}): another watch, or a key drawn again — pin the new one if it is yours")
    if signature_bytes(sig) is None:
        return "its signature is not one (64 bytes in base64)"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:
        return f"cryptography absent ({e}): the signature cannot be checked"
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(sig),
                                                       message(DOMAIN_DETECTION, body))
    except (InvalidSignature, ValueError, binascii.Error):
        return ("its signature does not hold: changed after it was signed, signed for another use "
                "(a heartbeat), or not by the pinned key")
    if body.get("exercise_run") != run_id:
        return f"a detection of another run ({str(body.get('exercise_run'))[:40]!r}) copied here"
    if body.get("signal_id") != signal_id:
        return f"a detection of another signal ({str(body.get('signal_id'))[:64]!r}) copied under this name"
    return ""


def seen_file() -> Path:
    if SEEN_FILE is not None:
        return SEEN_FILE
    from eregion_core import runs_layout
    return runs_layout.dir_of(runs_layout.ORODRUIN) / SEEN_NAME


def remember(body: dict) -> str:
    """Why this signed heartbeat is a replay — "" when it is not, and then its counter is kept as
    the highest seen for its key. The same heartbeat read twice (its counter and its signature
    those already seen) is no replay: the gate reads it before each action. Unwritable, the
    file is not a refusal: what was read is still checked."""
    path = seen_file()
    fp, seq, sig = str(body.get("key")), body.get("seq"), body.get("sig")
    try:
        seen = json.loads(path.read_text())
        if not isinstance(seen, dict):
            seen = {}
    except (OSError, ValueError):
        seen = {}
    last = seen.get(fp) if isinstance(seen.get(fp), dict) else {}
    top = last.get("seq")
    if isinstance(top, int) and not isinstance(top, bool):
        if seq < top or (seq == top and sig != last.get("sig")):
            return (f"its counter ({seq}) is not above one already seen ({top}): an older heartbeat "
                    "replayed — or the watch's clock went back across a restart (the counter is its "
                    "milliseconds): fix the clock, or wait until it passes the counter seen")
        if seq == top:
            return ""
    seen[fp] = {"seq": seq, "sig": sig}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(seen, sort_keys=True))
        os.replace(tmp, path)
    except OSError:
        pass
    return ""


def proof(body: dict | None, *, record: bool = True) -> str:
    """Why this heartbeat (as read: a dict, or None for a bare date) is not authenticated — ""
    when the pinned key signed it and it replays nothing seen. ``record``: keep its counter (an
    injector does; the console, which only shows the gate, does not)."""
    key, why = pinned()
    if key is None:
        return why
    if not isinstance(body, dict):
        return "unsigned: a bare date, the watch's own file or an older watch (update Glorfindel)"
    why = verify_beat(body, key)
    if why or not record:
        return why
    return remember(body)


def main(argv: list[str] | None = None) -> int:
    """``python -m eregion_core.watch_key public [DIR]``: the public key and its fingerprint."""
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "public":
        print("usage: python -m eregion_core.watch_key public [DIR]")
        return 2
    try:
        public = read_public(Path(args[1]) if len(args) > 1 else None)
    except KeyUnavailable as e:
        print(f"✗ {e}")
        return 1
    print(f"export {KEY_ENV}={public_text(public)}")
    print(f"# empreinte : {fingerprint(public)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
