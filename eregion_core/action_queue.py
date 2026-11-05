"""FS1a (#551, docs/design/file-actions-signee.md): the signed action queue — its format and its
verification. Nothing reads it yet to act: FS1b's watch picks the queue up and calls ``verify_request``
then ``proposal_refusal``; until then the console and the bot keep their direct call.

**A request** (§2.3) is one JSON file the console or the bot writes in its own directory of
``runs/`` (``runs/console/queue/``, ``runs/bot/queue/``): exactly ``REQUEST_FIELDS``, each of its
kind, at most ``MAX_BYTES``. It is signed by the service's own Ed25519 key (decision Q1 of 04/11)
under ``DOMAIN_REQUEST``: the domain, a newline, then the canonical JSON of every field but ``sig``
(``watch_key.message``). Its ``id`` is its nonce: 128 random bits.

**A proposal** (§2.4) is what the watch signs on a card that holds an action, with its own key
(SEC19) and its counter, under ``DOMAIN_QUEUE`` — ``kind`` signed, so a proposal never reads as a
receipt nor a status, which FS1b signs under the same domain. A request names the card and the
digest of its proposal: a card forged in ``escalations.jsonl`` has no proposal that holds.

**The verification** (§2.8, steps 1 to 9) runs from the cheapest to the dearest, with no network and
no call to the cloud: read (bounded, never through a link) → the form → a signature → the key pinned
for this directory → the signature holds → the service → the time → the nonce → the verb (and the
rate). Each refusal is one code of the closed list ``REFUSALS`` (§2.11), with its reason said. The
attachment to a card (step 10) is ``proposal_refusal``; the guards of the gesture (step 11), what the
watch holds (``nothing_to_undo``) and its posture (``read_only``) are FS1b's — their codes are here.

**The keys.** A service's key is drawn and loaded by the watch's own code (``watch_key.load_or_create``,
under ``SERVICE_KEY_FILE``), in the directory that service alone mounts (``~/.eregion/console/``,
``~/.eregion/bot/``). The watch pins their public halves in its environment only:
``EREGION_QUEUE_KEYS=console=ed25519:…,bot=ed25519:…`` (``pinned_keys``) — never read from the queue.

**The verbs** are a closed list (``VERBS``), and the verbs each service may ask are fixed here
(``SERVICE_VERBS``), never read in the request. The list is open to extension by these constants
alone (IR1 adds its own later). The restore is in none.

D1: the shared core — the watch, the console and the bot read this module, none importing another.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping, Protocol

from eregion_core import watch_key

VERSION = 1
# What a service signs (a request), and what the watch signs (a proposal, later a receipt, a
# status): two domains, never one another's — nor a heartbeat's, nor a detection's (SEC19, SEC21).
DOMAIN_REQUEST = "eregion.action-request/1"
DOMAIN_QUEUE = watch_key.DOMAIN_QUEUE
DOMAINS = (DOMAIN_REQUEST, DOMAIN_QUEUE)
# What the watch signs under DOMAIN_QUEUE, told apart by ``kind`` (signed).
WATCH_KINDS = ("proposal", "receipt", "status")

SERVICES = ("console", "bot")
# The closed list of verbs (§2.2). Open to extension by these constants only: a verb added here,
# and to the services allowed it, is the whole change.
VERBS = ("isolate_vm", "block_ip", "snapshot", "release_isolation", "reset", "unblock_ip", "promote_block")
SERVICE_VERBS: dict[str, frozenset[str]] = {
    "console": frozenset(VERBS),
    "bot": frozenset({"reset"}),
}
# A card's held action, and the verb that runs it (a card ``verification_failed``: its reset).
VERB_OF_ACTION = {"isolate_vm": "isolate_vm", "block_suspicious_ip": "block_ip",
                  "snapshot": "snapshot", "release_isolation": "release_isolation"}
# The cards whose held action a human may run in one click — the console's own list
# (eregion_console/api.py, _APPROVABLE_TYPES; tests/unit/test_action_proposal.py keeps them one).
APPROVABLE_TYPES = frozenset({"mode_hold", "low_confidence", "uncharacterized_signal", "release_hold",
                              "telemetry_gap", "unstable_decision"})
UNDO_TYPE = "verification_failed"

REQUEST_FIELDS = ("v", "kind", "id", "service", "by", "verb", "resource_id", "ip", "scope", "card",
                  "issued_at", "expires_at", "key", "sig")
SIGNATURE_FIELDS = ("key", "sig")
BY_FIELDS = ("via", "user", "name", "session")
CARD_FIELDS = ("id", "proposal")
PROPOSAL_FIELDS = ("v", "kind", "card", "action", "resource_id", "ip", "port", "escalation_type",
                   "issued_at", "seq", "key", "sig")

MAX_BYTES = 4 * 1024
MAX_LIFETIME_S = 120        # expires_at − issued_at, at most
SKEW_S = 30                 # the clock skew tolerated between a service and the watch (one host)
RATE_PER_MIN = 30           # requests per service per minute
SEEN_BYTES = 1024 * 1024

KEYS_ENV = "EREGION_QUEUE_KEYS"
PIN_GESTURE = (f"pin the service's public key at the watch: {KEYS_ENV}=console=ed25519:…,bot=ed25519:… "
               "in the watch's environment (host.env on H0, .envrc on a workstation)")

_ID = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")

# The tests point these at their own tmp dir (tests/unit/conftest.py): never the operator's.
KEY_ROOT: Path | None = None
QUEUE_DIR: Path | None = None

# The closed list of refusals (§2.11): a code, and what it says.
REFUSALS = {
    "malformed": "not a request of the queue: unreadable, too large, a link, a field more or less, "
                 "or a value of the wrong kind",
    "unsigned": "unsigned: someone writes in this service's queue without its key",
    "no_key_pinned": f"no key pinned for this service: {PIN_GESTURE}",
    "unknown_key": "signed by another key than the one pinned for this service: a key drawn again, "
                   "or another hand",
    "bad_signature": "its signature does not hold: a field changed after it was signed, or a "
                     "signature made for another use",
    "wrong_service": "a request of another service: its key, or its name, is not this directory's",
    "not_yet_valid": f"issued more than {SKEW_S} s ahead of the watch's clock",
    "too_long": f"valid for more than {MAX_LIFETIME_S} s",
    "expired": "expired: the watch was stopped or slow",
    "replayed": "its nonce was already seen: a request replayed",
    "seen_store_unavailable": "the watch's register of nonces cannot be read or written: no request "
                              "is taken until it can",
    "unknown_verb": "a verb out of the closed list",
    "verb_not_allowed": "a verb this service may not ask",
    "rate_limited": f"more than {RATE_PER_MIN} requests of this service in a minute",
    "proposal_missing": "no proposal of the watch on this card: a card written before FS1, or by "
                        "another hand — use the CLI, or wait for the detection to fire again",
    "proposal_mismatch": "the request does not match the proposal the watch signed on this card",
    "proposal_consumed": "this proposal was already judged, done or failed: one proposal, one execution — "
                         "after a failure, wait for the detection to fire again (a new proposal), or use "
                         "the CLI",
    "card_not_pending": "the card no longer waits",
    "nothing_to_undo": "nothing the watch holds on this VM or this address to undo",
    "guard": "a guard of the gesture refuses it",
    "read_only": "the watch is read-only (GLORFINDEL_READ_ONLY)",
}
# The refusals that say someone writes in a queue who should not (§2.11, « critique »): a card
# decided by the code, never by a model (FS1b writes it).
CRITICAL = frozenset({"unsigned", "unknown_key", "bad_signature", "wrong_service", "replayed",
                      "verb_not_allowed"})


class Refused(Exception):
    """A request the queue does not take: ``code`` (one of ``REFUSALS``), its ``reason`` said."""

    def __init__(self, code: str, detail: str = ""):
        if code not in REFUSALS:
            raise ValueError(f"not a refusal of the queue: {code!r}")
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {self.reason}")

    @property
    def reason(self) -> str:
        return self.detail or REFUSALS[self.code]

    @property
    def critical(self) -> bool:
        return self.code in CRITICAL


@dataclass(frozen=True)
class Request:
    """A request verified up to its verb (§2.8, steps 1 to 9)."""
    id: str
    service: str
    by: dict
    verb: str
    resource_id: str
    ip: str
    scope: str
    card_id: str | None
    proposal: str | None
    issued_at: datetime
    expires_at: datetime
    key: str


# ── The keys ─────────────────────────────────────────────────────────────────────────

def service_key_dir(service: str) -> Path:
    """Where a service's key lives: the directory that service alone mounts — the console's, beside
    its token (SEC10); the bot's, its own."""
    if service not in SERVICES:
        raise ValueError(f"not a service of the queue: {service!r}")
    root = KEY_ROOT if KEY_ROOT is not None else Path.home() / ".eregion"
    return root / service


def load_service_key(service: str) -> watch_key.Signer:
    """A service's key, drawn at its first use by the watch's own code and rules (SEC19:
    32 bytes, 0600, drawn apart then published by a link, never through a link, never another's,
    never readable by others). Raises watch_key.KeyUnavailable."""
    return watch_key.load_or_create(service_key_dir(service), name=watch_key.SERVICE_KEY_FILE)


def parse_pins(text: str) -> tuple[dict[str, bytes], list[str]]:
    """``console=ed25519:…,bot=ed25519:…`` → ({service: key}, what is wrong). A service named twice,
    one the queue does not know, a key that is not one: left out, and said."""
    named: list[tuple[str, str]] = []
    wrong: list[str] = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        service, sep, pin = part.partition("=")
        service = service.strip()
        if not sep or service not in SERVICES:
            wrong.append(f"{KEYS_ENV}: {service[:20]!r} is not a service of the queue ({', '.join(SERVICES)})")
            continue
        named.append((service, pin))
    times = collections.Counter(service for service, _ in named)
    pins: dict[str, bytes] = {}
    for service, pin in named:
        if times[service] > 1:
            said = f"{KEYS_ENV}: {service} named {times[service]} times — none kept"
            if said not in wrong:
                wrong.append(said)
            continue
        key, _why = watch_key.parse_pin(pin)
        if key is None:
            wrong.append(f"{KEYS_ENV}: {service}'s key is not one (ed25519:<base64 of 32 bytes>)")
            continue
        pins[service] = key
    return pins, wrong


def pinned_keys() -> tuple[dict[str, bytes], list[str]]:
    """The services' keys the watch trusts: its environment's, nothing else."""
    return parse_pins(os.environ.get(KEYS_ENV, ""))


# ── The request ─────────────────────────────────────────────────────────────────────

def _iso(at: datetime) -> str:
    return at.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def new_request(signer: watch_key.Signer, *, service: str, verb: str, resource_id: str,
                by: Mapping[str, str] | None = None, ip: str = "", scope: str = "",
                card: tuple[str, str] | None = None, now: datetime | None = None,
                lifetime_s: float = MAX_LIFETIME_S, nonce: str | None = None) -> dict:
    """A request, signed by ``signer`` (the service's key) under DOMAIN_REQUEST. ``card``: the card's
    id and the digest of its proposal (``digest``)."""
    now = now or datetime.now(timezone.utc)
    body = {
        "v": VERSION, "kind": "request", "id": nonce or secrets.token_hex(16), "service": service,
        "by": {f: str((by or {}).get(f, "")) for f in BY_FIELDS},
        "verb": verb, "resource_id": resource_id, "ip": ip, "scope": scope,
        "card": {"id": card[0], "proposal": card[1]} if card else None,
        "issued_at": _iso(now), "expires_at": _iso(now + timedelta(seconds=lifetime_s)),
        "key": signer.fingerprint,
    }
    body["sig"] = signer.sign(DOMAIN_REQUEST, body)
    return body


def read_request(path) -> bytes:
    """Step 1: the request's bytes — a regular file, never through a link, never blocking, at most
    MAX_BYTES (the one reader of runs/, SEC8). Refused ``malformed``; FileNotFoundError when gone."""
    from eregion_core import channel_reader
    try:
        return channel_reader.read_file(path, MAX_BYTES)
    except FileNotFoundError:
        raise
    except OSError as e:
        raise Refused("malformed", f"not read: {e}") from None


def _no_constant(name: str):
    raise ValueError(f"not JSON: {name}")


def _unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"a field twice: {k[:40]!r}")
        out[k] = v
    return out


def _parse(data) -> dict:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_BYTES:
            raise Refused("malformed", f"more than {MAX_BYTES} bytes")
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise Refused("malformed", "not UTF-8") from None
    elif isinstance(data, str):
        if len(data.encode("utf-8", "surrogatepass")) > MAX_BYTES:
            raise Refused("malformed", f"more than {MAX_BYTES} bytes")
    else:
        raise Refused("malformed", "not the bytes of a file")
    try:
        doc = json.loads(data, object_pairs_hook=_unique, parse_constant=_no_constant)
    except (ValueError, RecursionError) as e:
        raise Refused("malformed", f"not JSON ({str(e)[:80]})") from None
    if not isinstance(doc, dict):
        raise Refused("malformed", "not a JSON object")
    return doc


def _time(value, name: str) -> datetime:
    try:
        when = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        when = None
    if when is None or when.tzinfo is None:
        raise Refused("malformed", f"{name} is not an ISO time with its zone")
    return when


def _str(doc: dict, name: str) -> str:
    value = doc[name]
    if not isinstance(value, str):
        raise Refused("malformed", f"{name} is not a string")
    return value


def _form(doc: dict) -> tuple[datetime, datetime]:
    """Step 2: exactly its fields, each of its kind (``key`` and ``sig`` are the signature: their
    absence is step 3's)."""
    extra = sorted(set(doc) - set(REQUEST_FIELDS))
    if extra:
        raise Refused("malformed", f"a field it never holds: {', '.join(str(f)[:40] for f in extra)}")
    missing = [f for f in REQUEST_FIELDS if f not in doc and f not in SIGNATURE_FIELDS]
    if missing:
        raise Refused("malformed", f"lacks {', '.join(missing)}")
    if isinstance(doc["v"], bool) or doc["v"] != VERSION:
        raise Refused("malformed", f"not version {VERSION}")
    if doc["kind"] != "request":
        raise Refused("malformed", "not a request (kind)")
    if not isinstance(doc["id"], str) or not _ID.fullmatch(doc["id"]):
        raise Refused("malformed", "its id is not 128 bits in hex")
    for name in ("service", "verb", "resource_id", "ip", "scope"):
        _str(doc, name)
    by = doc["by"]
    if not isinstance(by, dict) or set(by) != set(BY_FIELDS) or not all(isinstance(v, str) for v in by.values()):
        raise Refused("malformed", f"by is not exactly {', '.join(BY_FIELDS)}, as strings")
    card = doc["card"]
    if card is not None:
        if not isinstance(card, dict) or set(card) != set(CARD_FIELDS):
            raise Refused("malformed", "card is neither null nor exactly its id and its proposal")
        if not isinstance(card["id"], str) or not card["id"]:
            raise Refused("malformed", "card's id is not a string")
        if not isinstance(card["proposal"], str) or not _DIGEST.fullmatch(card["proposal"]):
            raise Refused("malformed", "card's proposal is not sha256:<64 hex>")
    issued = _time(doc["issued_at"], "issued_at")
    expires = _time(doc["expires_at"], "expires_at")
    if expires <= issued:
        raise Refused("malformed", "expires_at is not after issued_at")
    if "key" in doc and not isinstance(doc["key"], str):
        raise Refused("malformed", "key is not a string")
    if doc.get("sig") is not None and "key" not in doc:
        raise Refused("malformed", "signed without naming its key")
    return issued, expires


class Seen(Protocol):
    """The watch's register of nonces: ``claim`` is True the first time, False after; it raises
    OSError or ValueError when it cannot be read or written — then nothing is taken."""

    def claim(self, nonce: str, until: datetime, now: datetime) -> bool: ...


class Rate:
    """At most ``per_min`` requests of each service per minute (sliding). Thread-safe."""

    def __init__(self, per_min: int = RATE_PER_MIN):
        self.per_min = per_min
        self._taken: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def take(self, service: str, now: datetime) -> bool:
        with self._lock:
            q = self._taken[service]
            while q and q[0] <= now - timedelta(seconds=60):
                q.popleft()
            if len(q) >= self.per_min:
                return False
            q.append(now)
            return True


def verify_request(data, *, service: str, pins: Mapping[str, bytes], now: datetime, seen: Seen,
                   rate: Rate) -> Request:
    """§2.8, steps 2 to 9, on the bytes read from ``runs/<service>/queue/`` (step 1, ``read_request``):
    the request verified — or ``Refused``, one code of REFUSALS. ``pins``: the services' keys the
    watch pins (``pinned_keys``), never a key read in the queue. No network, no call to the cloud;
    ``seen`` is written (the nonce claimed) before anything is executed."""
    if service not in SERVICES:
        raise ValueError(f"not a service of the queue: {service!r}")
    doc = _parse(data)
    issued, expires = _form(doc)
    # 3. a signature
    if doc.get("sig") is None:
        raise Refused("unsigned")
    # 4. the key pinned for this directory
    pin = pins.get(service)
    if pin is None:
        raise Refused("no_key_pinned", f"no key pinned for the {service}: {PIN_GESTURE}")
    want = watch_key.fingerprint(pin)
    said = doc["key"]
    if said != want:
        for other, key in pins.items():
            if other != service and watch_key.fingerprint(key) == said and watch_key.holds(key, DOMAIN_REQUEST, doc):
                raise Refused("wrong_service", f"signed by the {other}'s key, in the {service}'s queue")
        raise Refused("unknown_key", f"signed by another key ({watch_key._short(said)}) than the one "
                                     f"pinned for the {service} ({watch_key._short(want)}): a key drawn "
                                     f"again — pin the new one if it is yours — or another hand")
    # 5. the signature holds
    if not watch_key.holds(pin, DOMAIN_REQUEST, doc):
        raise Refused("bad_signature")
    # 6. the service is this directory's
    if doc["service"] != service:
        raise Refused("wrong_service", f"a request of {str(doc['service'])[:20]!r} in the {service}'s queue")
    # 7. the time
    if issued - now > timedelta(seconds=SKEW_S):
        raise Refused("not_yet_valid", f"issued {(issued - now).total_seconds():.0f} s ahead of the watch's "
                                       f"clock (at most {SKEW_S} s)")
    if expires - issued > timedelta(seconds=MAX_LIFETIME_S):
        raise Refused("too_long", f"valid for {(expires - issued).total_seconds():.0f} s (at most "
                                  f"{MAX_LIFETIME_S} s)")
    if now >= expires:
        raise Refused("expired", f"expired {(now - expires).total_seconds():.0f} s ago: the watch was "
                                 "stopped or slow")
    # 8. the rate — FS1b: before the register, so a service's claims are bounded as well (its key,
    # compromised, never fills the register with valid nonces until it refuses everything)
    if not rate.take(service, now):
        raise Refused("rate_limited")
    # 8. the nonce — claimed before anything runs; a register that cannot be kept refuses
    try:
        fresh = seen.claim(doc["id"], expires + timedelta(seconds=SKEW_S), now)
    except (OSError, ValueError) as e:
        raise Refused("seen_store_unavailable", f"{REFUSALS['seen_store_unavailable']} ({str(e)[:120]})") from None
    if not fresh:
        raise Refused("replayed")
    # 9. the verb
    verb = doc["verb"]
    if verb not in VERBS:
        raise Refused("unknown_verb", f"{verb[:40]!r} is not a verb of the queue ({', '.join(VERBS)})")
    if verb not in SERVICE_VERBS.get(service, frozenset()):
        raise Refused("verb_not_allowed", f"the {service} may not ask {verb}")
    card = doc["card"]
    return Request(id=doc["id"], service=service, by=dict(doc["by"]), verb=verb,
                   resource_id=doc["resource_id"], ip=doc["ip"], scope=doc["scope"],
                   card_id=card["id"] if card else None, proposal=card["proposal"] if card else None,
                   issued_at=issued, expires_at=expires, key=said)


# ── The watch's register of nonces ────────────────────────────────────────────────────

def queue_dir() -> Path:
    """The watch's own directory for the queue (§2.5): beside its key, mounted by the watch alone —
    never under ~/.glorfindel nor runs/."""
    return QUEUE_DIR if QUEUE_DIR is not None else Path.home() / ".eregion" / "watch-queue"


class MemorySeen:
    """A register in memory (the tests, a single run)."""

    def __init__(self):
        self._until: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str, until: datetime, now: datetime) -> bool:
        with self._lock:
            self._until = {n: u for n, u in self._until.items() if u > now}
            if nonce in self._until:
                return False
            self._until[nonce] = until
            return True


class SeenFile:
    """The register in a file of the watch's own directory (``queue_dir()/seen.json``): each nonce
    kept until its request's expiry plus the skew, then forgotten. Read and written whole, never
    through a link; unreadable, of another form, too large, or not written: OSError or ValueError,
    and the request is refused (``seen_store_unavailable``) — for an action, the register closes."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else queue_dir() / "seen.json"
        self._lock = threading.Lock()

    def _read(self) -> dict[str, str]:
        from eregion_core import channel_reader
        try:
            data = channel_reader.read_file(self.path, SEEN_BYTES)
        except FileNotFoundError:
            return {}
        doc = json.loads(data.decode("utf-8"))
        if not isinstance(doc, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in doc.items()):
            raise ValueError(f"{self.path} is not a register of nonces")
        for nonce, until in doc.items():
            when = datetime.fromisoformat(until)
            if when.tzinfo is None:          # compared with an aware time, it would raise TypeError
                raise ValueError(f"{self.path}: {nonce[:40]!r} is kept until a time without its zone")
        return doc

    def claim(self, nonce: str, until: datetime, now: datetime) -> bool:
        """FS1b: written durably — the file fsync'd, then its directory — before it returns: a
        nonce claimed is never lost to a crash of the host, its request never replayed in its
        window. Whatever the register holds, it refuses: OSError or ValueError, never another
        exception (a nesting too deep, a time of another form)."""
        from eregion_core import channel_reader
        with self._lock:
            try:
                seen = self._read()
                kept = {n: u for n, u in seen.items() if datetime.fromisoformat(u) > now}
            except (OSError, ValueError):
                raise
            except Exception as e:      # RecursionError, TypeError…: refused, never raised
                raise ValueError(f"{self.path} is not a register of nonces ({type(e).__name__})") from None
            if nonce in kept:
                return False
            kept[nonce] = _iso(until)
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600, sync=True)
            return True


# ── The watch's register of the proposals executed (FS1b) ─────────────────────────────

CONSUMED_KEEP_DAYS = 30         # longer than any card waits for its approval


class MemoryConsumed:
    """The proposals executed, in memory (the tests, a single run)."""

    def __init__(self):
        self._at: dict[str, str] = {}
        self._lock = threading.Lock()

    def digests(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._at)

    def consume(self, proposal: str, card: str, now: datetime) -> bool:
        with self._lock:
            if proposal in self._at:
                return False
            self._at[proposal] = _iso(now)
            return True


class ConsumedFile:
    """§2.4, « one proposal, one execution »: the digests of the proposals the watch executed
    (``queue_dir()/consumed.json``, beside ``seen.json``), each with its card and when — kept
    CONSUMED_KEEP_DAYS (a card that waits longer is refused by its age anyway). Consumed before
    the execution, written durably. Unreadable, of another form, too large, or not written:
    OSError or ValueError, never another exception — the request is refused
    (``seen_store_unavailable``)."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else queue_dir() / "consumed.json"
        self._lock = threading.Lock()

    def _read(self) -> dict[str, dict]:
        from eregion_core import channel_reader
        try:
            try:
                data = channel_reader.read_file(self.path, SEEN_BYTES)
            except FileNotFoundError:
                return {}
            doc = json.loads(data.decode("utf-8"))
            if not isinstance(doc, dict):
                raise ValueError(f"{self.path} is not a register of proposals")
            for done, entry in doc.items():
                if (not _DIGEST.fullmatch(str(done)) or not isinstance(entry, dict)
                        or not isinstance(entry.get("card"), str) or not isinstance(entry.get("at"), str)
                        or datetime.fromisoformat(entry["at"]).tzinfo is None):
                    raise ValueError(f"{self.path}: {str(done)[:40]!r} is not a proposal consumed")
            return doc
        except (OSError, ValueError):
            raise
        except Exception as e:          # RecursionError…: refused, never raised
            raise ValueError(f"{self.path} is not a register of proposals ({type(e).__name__})") from None

    def digests(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._read())

    def consume(self, proposal: str, card: str, now: datetime) -> bool:
        """True the first time ``proposal`` is consumed (then written durably), False after."""
        from eregion_core import channel_reader
        with self._lock:
            done = self._read()
            if proposal in done:
                return False
            cutoff = now - timedelta(days=CONSUMED_KEEP_DAYS)
            kept = {d: e for d, e in done.items() if datetime.fromisoformat(e["at"]) > cutoff}
            kept[proposal] = {"card": str(card)[:200], "at": _iso(now)}
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600, sync=True)
            return True


# ── The proposal the watch signs on a card ────────────────────────────────────────────

def proposed_verbs(card) -> frozenset[str]:
    """The verbs a card (or its proposal) lets a human ask: its held action's, on a card one may
    approve in one click; ``reset`` on a card ``verification_failed``; none on any other."""
    if not isinstance(card, dict):
        return frozenset()
    etype = card.get("escalation_type")
    if etype == UNDO_TYPE:
        return frozenset({"reset"})
    if etype in APPROVABLE_TYPES and card.get("action") in VERB_OF_ACTION:
        return frozenset({VERB_OF_ACTION[card["action"]]})
    return frozenset()


def proposable(card) -> bool:
    """Does the watch sign a proposal on this card (§2.4: a card that holds an action)?"""
    return bool(proposed_verbs(card))


def _card_ip(card: dict) -> str:
    params = card.get("action_params")
    ip = params.get("ip") if isinstance(params, dict) else ""
    return ip if isinstance(ip, str) else ""


def _card_port(card: dict) -> int | None:
    params = card.get("action_params")
    port = params.get("port") if isinstance(params, dict) else None
    return port if isinstance(port, int) and not isinstance(port, bool) else None


def sign_watch(kind: str, body: dict, signer: watch_key.Signer) -> dict:
    """What the watch signs for the queue — a proposal, a receipt, a status (``WATCH_KINDS``) —
    under DOMAIN_QUEUE, its ``kind`` signed with the rest: one never reads as another."""
    if kind not in WATCH_KINDS:
        raise ValueError(f"not a kind the watch signs: {kind!r}")
    out = {k: v for k, v in body.items() if k not in SIGNATURE_FIELDS}
    out["v"], out["kind"], out["key"] = VERSION, kind, signer.fingerprint
    out["sig"] = signer.sign(DOMAIN_QUEUE, out)
    return out


def watch_refusal(body, kind: str, watch_public: bytes) -> str:
    """Why ``body`` is not a ``kind`` the watch whose public key this is signed — "" when it is.
    The watch checks its own with the public half of the key in its memory, never one read on disk."""
    if not isinstance(body, dict):
        return "not a JSON object"
    if body.get("kind") != kind:
        return f"not a {kind} ({str(body.get('kind'))[:20]!r})"
    if body.get("key") != watch_key.fingerprint(watch_public):
        return "not signed by this watch's key"
    if not watch_key.holds(watch_public, DOMAIN_QUEUE, body):
        return "its signature does not hold"
    return ""


def sign_proposal(card: dict, signer: watch_key.Signer, at: datetime) -> dict:
    """The proposal the watch joins to a card that holds an action (§2.4), signed by its key with its
    counter: the card, its action, its target, its address and port, its type, when."""
    return sign_watch("proposal", {
        "card": str(card["id"]), "action": str(card.get("action") or ""),
        "resource_id": str(card.get("resource_id") or ""), "ip": _card_ip(card), "port": _card_port(card),
        "escalation_type": str(card.get("escalation_type") or ""),
        "issued_at": _iso(at), "seq": signer.next_seq(at),
    }, signer)


def digest(body: dict) -> str:
    """``sha256:`` and the hex digest of a proposal's canonical JSON, its signature included — what
    a request names."""
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def proposal_refusal(card, request: Request, *, watch_public: bytes, consumed=frozenset()) -> None:
    """§2.8, step 10, for a request bound to a card: the card still waits, carries the proposal this
    watch signed, unchanged since, the one the request names, for this verb, this target and this
    address — and never executed (``consumed``: the digests already run). Raises ``Refused``."""
    if request.card_id is None or request.proposal is None:
        raise Refused("proposal_missing", "the request names no card")
    if not isinstance(card, dict) or card.get("id") != request.card_id:
        raise Refused("card_not_pending", "no card of this id waits")
    if card.get("status") != "pending":
        raise Refused("card_not_pending")
    proposal = card.get("proposal")
    if not isinstance(proposal, dict):
        raise Refused("proposal_missing")
    if set(proposal) != set(PROPOSAL_FIELDS) or proposal.get("v") != VERSION:
        raise Refused("proposal_mismatch", "the card's proposal is not one the watch writes")
    why = watch_refusal(proposal, "proposal", watch_public)
    if why:
        raise Refused("proposal_mismatch", f"the card's proposal: {why}")
    if (proposal["card"] != card.get("id") or proposal["action"] != card.get("action")
            or str(proposal["resource_id"]).lower() != str(card.get("resource_id") or "").lower()
            or proposal["escalation_type"] != card.get("escalation_type") or proposal["ip"] != _card_ip(card)
            or proposal["port"] != _card_port(card)):
        raise Refused("proposal_mismatch", "the card changed since the watch proposed it")
    if digest(proposal) != request.proposal:
        raise Refused("proposal_mismatch", "the request names another proposal than the card's")
    if request.verb not in proposed_verbs(proposal):
        raise Refused("proposal_mismatch", f"the card proposes no {request.verb}")
    if request.resource_id.lower() != str(proposal["resource_id"]).lower():
        raise Refused("proposal_mismatch", "the request aims at another resource than the card")
    if proposal["ip"] and request.ip not in ("", proposal["ip"]):
        raise Refused("proposal_mismatch", "the request names another address than the card")
    if request.proposal in consumed:
        raise Refused("proposal_consumed")


def proposal_fresh(card, proposal, watch_public: bytes, now: datetime, max_age_s: float) -> bool:
    """FS1b: the proposal already on a card still stands — this watch signed it, for the card as
    it is now (its action, target, address, port, type), less than ``max_age_s`` ago. Then the
    watch does not sign it again when the card is seen again: re-signed at each refresh, its
    digest changed, and a request named just before a lasting detection refreshed its card was
    refused (``proposal_mismatch``)."""
    if not isinstance(card, dict) or not isinstance(proposal, dict) or set(proposal) != set(PROPOSAL_FIELDS):
        return False
    if watch_refusal(proposal, "proposal", watch_public):
        return False
    said = (proposal["card"], proposal["action"], str(proposal["resource_id"]).lower(),
            proposal["escalation_type"], proposal["ip"], proposal["port"])
    held = (card.get("id"), card.get("action"), str(card.get("resource_id") or "").lower(),
            card.get("escalation_type"), _card_ip(card), _card_port(card))
    if said != held:
        return False
    try:
        issued = datetime.fromisoformat(proposal["issued_at"])
    except (TypeError, ValueError):
        return False
    if issued.tzinfo is None:
        return False
    return timedelta(0) <= now - issued < timedelta(seconds=max_age_s)


# ── The queue on disk (FS1b): where a service deposits, where the watch answers ───────────

FLAG_ENV = "EREGION_ACTION_QUEUE"
REQUEST_KEEP_S = 3600            # a service removes its requests once answered, or after an hour
RECEIPT_BYTES = 64 * 1024
RECEIPT_STATES = ("received", "accepted", "done", "failed", "refused")
FINAL_STATES = ("done", "failed", "refused")
STATUS_NAME = "status.json"


def enabled(environ=None) -> bool:
    """FS1b: the console and the bot deposit a request, and the watch picks the queue up, only
    behind ``EREGION_ACTION_QUEUE=1`` — false by default: without it, nothing changes (the direct
    call stays, no queue is read)."""
    return (os.environ if environ is None else environ).get(FLAG_ENV, "") == "1"


def request_dir(service: str, root=None) -> Path:
    """``runs/<service>/queue/``: the service's own directory of runs/ (SEC18) — the console's,
    or the bot's, a writer of its own since FS1b."""
    from eregion_core import runs_layout
    if service not in SERVICES:
        raise ValueError(f"not a service of the queue: {service!r}")
    return runs_layout.dir_of(service, root) / "queue"


def receipts_dir(root=None) -> Path:
    """``runs/glorfindel/queue/``: the watch's own directory — its receipts
    (``<service>-<id>.json``) and its status (``status.json``), which it alone writes and signs."""
    from eregion_core import runs_layout
    return runs_layout.dir_of(runs_layout.GLORFINDEL, root) / "queue"


def receipt_path(service: str, request_id: str, root=None) -> Path:
    if service not in SERVICES or not _ID.fullmatch(str(request_id)):
        raise ValueError(f"not a request of the queue: {service!r} {str(request_id)[:40]!r}")
    return receipts_dir(root) / f"{service}-{request_id}.json"


def deposit(request: dict, root=None) -> Path:
    """Write a signed request in its service's directory: beside, then renamed (``write_file``:
    never through a link), 0600."""
    from eregion_core import channel_reader
    directory = request_dir(request["service"], root)
    if not _ID.fullmatch(str(request.get("id"))):
        raise ValueError("a request without its nonce")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{request['id']}.json"
    channel_reader.write_file(path, json.dumps(request, separators=(",", ":")), mode=0o600)
    return path


def withdraw(service: str, request_id: str, root=None) -> bool:
    """The service removes its own request once its receipt is read — never another's. True for
    the call that removed it (FS1c: the gesture is noted by that one read only)."""
    if not _ID.fullmatch(str(request_id)):
        return False
    try:
        (request_dir(service, root) / f"{request_id}.json").unlink()
    except FileNotFoundError:
        return False
    return True


def sweep_requests(service: str, root=None, keep_s: float = REQUEST_KEEP_S, now: float | None = None) -> int:
    """The service's own requests older than ``keep_s`` removed (an answer never read). Never
    raises; how many removed."""
    import stat as _stat
    import time as _time
    now = _time.time() if now is None else now
    n = 0
    try:
        with os.scandir(request_dir(service, root)) as it:
            for e in it:
                if not e.name.endswith(".json"):
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                    if _stat.S_ISREG(st.st_mode) and now - st.st_mtime > keep_s:
                        os.unlink(e.path)
                        n += 1
                except OSError:
                    continue
    except OSError:
        return n
    return n


def receipt_said(service: str, request_id: str, *, root=None, watch_public: bytes | None = None) -> tuple[dict | None, str]:
    """(the watch's receipt of a request, "") — or (None, why there is none to believe): ``""``
    while there is none at all; else what is there and is not one — unreadable, another request's,
    or (``watch_public``: the watch's key pinned, a service on another host) signed by another key
    than the pinned one: both fingerprints said, and the gesture (FS1c: never told as « no
    receipt »). The receipt never carries the request's signature."""
    from eregion_core import channel_reader
    try:
        doc = json.loads(channel_reader.read_file(receipt_path(service, request_id, root), RECEIPT_BYTES))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError, RecursionError) as e:
        return None, f"a receipt is there but unreadable ({type(e).__name__})"
    if (not isinstance(doc, dict) or doc.get("kind") != "receipt" or doc.get("request") != request_id
            or doc.get("service") != service or doc.get("state") not in RECEIPT_STATES):
        return None, "a receipt is there but is not this request's"
    if _believed(doc, watch_public) is None:
        said = doc.get("key") if isinstance(doc.get("key"), str) else "?"
        return None, (f"a receipt is there, but {watch_refusal(doc, 'receipt', watch_public)}: signed by "
                      f"{watch_key._short(said)}, the watch's key pinned here is "
                      f"{watch_key._short(watch_key.fingerprint(watch_public))} — the watch's key drawn again "
                      f"(pin the new one: {watch_key.KEY_ENV}, `make glorfindel-host-watch-key` or `make "
                      "watch-key`), or another hand")
    return doc, ""


def _believed(doc: dict, watch_public: bytes | None) -> dict | None:
    """The receipt, when nothing says not to believe it: signed by the watch's key when the service
    pins it (a service on another host); from the mount, on one host."""
    if watch_public is not None and watch_refusal(doc, "receipt", watch_public):
        return None
    return doc


def read_receipt(service: str, request_id: str, *, root=None, watch_public: bytes | None = None) -> dict | None:
    """The watch's receipt of a request — None while there is none, or when what is there is not
    one (``receipt_said`` says which)."""
    return receipt_said(service, request_id, root=root, watch_public=watch_public)[0]


def await_receipt(service: str, request_id: str, *, final: bool, timeout_s: float, root=None,
                  watch_public: bytes | None = None, poll_s: float = 0.2, clock=None, sleep=None) -> dict | None:
    """The receipt once it says ``accepted`` or a final state (``final``: a final state only) —
    or the last one read (None: none) after ``timeout_s``."""
    import time as _time
    clock, sleep = clock or _time.monotonic, sleep or _time.sleep
    deadline = clock() + timeout_s
    last = None
    while True:
        doc = read_receipt(service, request_id, root=root, watch_public=watch_public)
        if doc is not None:
            last = doc
            if doc["state"] in FINAL_STATES or (not final and doc["state"] == "accepted"):
                return doc
        if clock() >= deadline:
            return last
        sleep(poll_s)


TAKE_S = MAX_LIFETIME_S + SKEW_S    # a request is taken within its life, or never
RUN_S = 600                         # a lift of a multi-NIC VM takes minutes (the CLI's timeout)


NOT_TAKEN = (f"the watch did not take the request in {MAX_LIFETIME_S} s — is it running, with {FLAG_ENV}=1 "
             f"and this service's key pinned ({KEYS_ENV})?")


def deposit_request(service: str, verb: str, resource_id: str, *, by: Mapping[str, str], root=None,
                    ip: str = "", scope: str = "", card: tuple[str, str] | None = None) -> dict:
    """FS1c: a service's gesture as a request of the queue, deposited and never awaited — signed by
    its key (drawn at its first use), written in its directory. ``{"request": id}``, or
    ``{"error": …}`` when the service could not ask. Its fate is read by ``follow``."""
    try:
        signer = load_service_key(service)
    except watch_key.KeyUnavailable as e:
        return {"error": f"the {service}'s key of the action queue is unavailable: {e}"}
    sweep_requests(service, root)
    request = new_request(signer, service=service, verb=verb, resource_id=resource_id, by=by, ip=ip,
                          scope=scope, card=card)
    try:
        deposit(request, root)
    except OSError as e:
        return {"error": f"the request could not be written in runs/{service}/queue/: {e}"}
    return {"request": request["id"]}


def _issued(service: str, request_id: str, root=None) -> datetime | None:
    """When the service's own request was issued — None when it is no longer there (withdrawn,
    swept) or cannot be read as one."""
    from eregion_core import channel_reader
    try:
        doc = json.loads(channel_reader.read_file(request_dir(service, root) / f"{request_id}.json", MAX_BYTES))
        when = datetime.fromisoformat(doc["issued_at"])
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None
    return when if when.tzinfo is not None else None


def follow(service: str, request_id: str, *, root=None, watch_public: bytes | None = None,
           now: datetime | None = None) -> dict:
    """FS1c: where a request stands, read once — never waiting. ``state``: the receipt's
    (``received``, ``accepted``, ``done``, ``failed``, ``refused``), or ``waiting`` (deposited, no
    receipt yet, within its life), ``not_taken`` (no receipt within its life: the watch did not take
    it), ``untrusted`` (a receipt there that is not one to believe — another key than the watch's
    pinned one: said, never « no receipt »), ``unknown`` (neither the request nor a receipt).
    ``final``: nothing more will come of it."""
    if not _ID.fullmatch(str(request_id)):
        return {"request": "", "state": "unknown", "final": True, "error": "not a request of the queue"}
    doc, why = receipt_said(service, request_id, root=root, watch_public=watch_public)
    if doc is not None:
        return {"request": request_id, "state": doc["state"], "final": doc["state"] in FINAL_STATES,
                "receipt": doc}
    if why:
        return {"request": request_id, "state": "untrusted", "final": True, "error": why}
    issued = _issued(service, request_id, root)
    if issued is None:
        return {"request": request_id, "state": "unknown", "final": True,
                "error": "no request of this id here, and no receipt (withdrawn, or swept after an hour)"}
    now = now or datetime.now(timezone.utc)
    if (now - issued).total_seconds() > TAKE_S:
        return {"request": request_id, "state": "not_taken", "final": True, "error": NOT_TAKEN}
    return {"request": request_id, "state": "waiting", "final": False}


def ask(service: str, verb: str, resource_id: str, *, by: Mapping[str, str], root=None, ip: str = "",
        scope: str = "", card: tuple[str, str] | None = None, take_s: float | None = None,
        run_s: float | None = None, poll_s: float = 0.2) -> dict:
    """A service's gesture as a request of the queue (the console's, the bot's): signed by its key
    (drawn at its first use), deposited in its directory, then the watch's receipt awaited —
    ``accepted`` or ``refused`` within the request's life, then ``done`` or ``failed``.
    ``{"receipt": …, "request": id}``, or ``{"error": …}`` when the service could not ask or the
    watch did not take it. The request is withdrawn once answered. The receipt is believed from
    the mount (one host) — and checked with the watch's key when the service pins it
    (``EREGION_WATCH_KEY``, a service on another host)."""
    take_s = TAKE_S if take_s is None else take_s
    run_s = RUN_S if run_s is None else run_s
    deposited = deposit_request(service, verb, resource_id, by=by, root=root, ip=ip, scope=scope, card=card)
    if "error" in deposited:
        return deposited
    rid = deposited["request"]
    public, _ = watch_key.pinned()
    got = await_receipt(service, rid, final=False, timeout_s=take_s, root=root, watch_public=public,
                        poll_s=poll_s)
    if got is None or got["state"] not in ("accepted",) + FINAL_STATES:
        withdraw(service, rid, root)
        # FS1c: a receipt there but not one to believe is said as such, never « not taken ».
        _, why = receipt_said(service, rid, root=root, watch_public=public)
        return {"error": why or NOT_TAKEN, "request": rid}
    if got["state"] not in FINAL_STATES:
        got = await_receipt(service, rid, final=True, timeout_s=run_s, root=root, watch_public=public,
                            poll_s=poll_s) or got
    if got["state"] not in FINAL_STATES:
        return {"error": f"the watch is still running the request ({got['state']}): its receipt will say it",
                "request": rid, "state": got["state"]}
    withdraw(service, rid, root)
    return {"receipt": got, "request": rid}


def status_said(*, root=None, watch_public: bytes | None = None) -> tuple[dict | None, str]:
    """(the status the watch publishes for the queue, "") — or (None, why): "" when there is none;
    else unreadable, not a status, or signed by another key than the watch's pinned one."""
    from eregion_core import channel_reader
    try:
        doc = json.loads(channel_reader.read_file(receipts_dir(root) / STATUS_NAME, RECEIPT_BYTES))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError, RecursionError) as e:
        return None, f"the watch's status of the queue is unreadable ({type(e).__name__})"
    if not isinstance(doc, dict) or doc.get("kind") != "status":
        return None, "the watch's status of the queue is not one"
    if watch_public is not None:
        why = watch_refusal(doc, "status", watch_public)
        if why:
            said = doc.get("key") if isinstance(doc.get("key"), str) else "?"
            return None, (f"the watch's status of the queue: {why} ({watch_key._short(said)}, the watch's key "
                          f"pinned here is {watch_key._short(watch_key.fingerprint(watch_public))}) — pin the "
                          f"watch's new key ({watch_key.KEY_ENV}), or another hand writes it")
    return doc, ""


def read_status(*, root=None, watch_public: bytes | None = None) -> dict | None:
    """The status the watch publishes for the queue (its posture, the keys it pins, since when it
    picks the queue up) — None when there is none, or it is not one."""
    return status_said(root=root, watch_public=watch_public)[0]


STATUS_STALE_S = 60      # the watch rewrites its status every 10 s while it picks the queue up


def service_fingerprint(service: str) -> str:
    """The fingerprint of a service's key, read — never drawn: "" when it is not there yet."""
    try:
        return watch_key.fingerprint(watch_key.read_public(service_key_dir(service), name=watch_key.SERVICE_KEY_FILE))
    except watch_key.KeyUnavailable:
        return ""


def posture(service: str, *, root=None, watch_public: bytes | None = None, fingerprint: str | None = None,
            now: datetime | None = None) -> dict:
    """FS1c: may this service ask the watch now — read from the status the watch signs, never from
    the service's own environment. ``{"ok": bool, "why": …, "status": …}``: refused when the status
    is missing, not one to believe, older than STATUS_STALE_S, says the watch read-only, or pins
    no key — or another key — for this service. ``fingerprint``: the service's own key's (read
    by default, never drawn)."""
    doc, why = status_said(root=root, watch_public=watch_public)
    if doc is None:
        return {"ok": False, "why": why or (f"the watch publishes no status of the queue (runs/glorfindel/queue/"
                                            f"{STATUS_NAME}): is it running, with {FLAG_ENV}=1?"), "status": None}
    said = {k: doc.get(k) for k in ("posture", "since", "at")}
    try:
        at = datetime.fromisoformat(doc.get("at"))
        if at.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError):
        return {"ok": False, "why": "the watch's status of the queue carries no readable time", "status": said}
    age = ((now or datetime.now(timezone.utc)) - at).total_seconds()
    if age > STATUS_STALE_S:
        return {"ok": False, "why": (f"the watch's status of the queue is {age:.0f} s old: the watch is stopped, "
                                     "or no longer picks the queue up"), "status": said}
    if doc.get("posture") != "write":
        return {"ok": False, "why": REFUSALS["read_only"] + ": no gesture is taken", "status": said}
    pins = doc.get("pins") if isinstance(doc.get("pins"), dict) else {}
    pinned = pins.get(service) if isinstance(pins.get(service), str) else ""
    if not pinned:
        return {"ok": False, "why": f"the watch pins no key for the {service}: {PIN_GESTURE}", "status": said}
    own = service_fingerprint(service) if fingerprint is None else fingerprint
    if not own:
        return {"ok": False, "why": (f"the {service}'s key of the queue is not drawn yet (~/.eregion/{service}/"
                                     f"{watch_key.SERVICE_KEY_FILE}): restart it with {FLAG_ENV}=1"), "status": said}
    if pinned != own:
        return {"ok": False, "why": (f"the watch pins another key for the {service} ({watch_key._short(pinned)}) "
                                     f"than its own ({watch_key._short(own)}): a key drawn again — pin this one "
                                     f"({KEYS_ENV}, make queue-keys or make glorfindel-host-queue-keys)"),
                "status": said}
    return {"ok": True, "why": "", "status": said}


def pin_problems(pins: Mapping[str, bytes], wrong=(), services=SERVICES) -> list[str]:
    """FS1c: what the watch's pins lack, said — each line ``parse_pins`` found wrong, then a line
    per service of ``services`` without its key. Empty: every one of them may ask."""
    out = [str(w) for w in wrong]
    out += [f"no key pinned for the {s}: its requests are refused (no_key_pinned) — {PIN_GESTURE}"
            for s in services if s not in pins]
    return out


def main(argv: list[str] | None = None) -> int:
    """``python -m eregion_core.action_queue public [console|bot]``: the line to pin at the watch
    (``EREGION_QUEUE_KEYS=console=ed25519:…,bot=ed25519:…``), from the keys already drawn in
    ``~/.eregion/<service>/`` — never draws one, never the private half."""
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["pin"] and len(args) in (2, 3) and args[1] in SERVICES and args[2:] in ([], ["--draw"]):
        # ``pin <service> [--draw]``: that service's pin alone (``console=ed25519:…``) — make
        # glorfindel-host-queue-keys joins the console's and the bot's, read in their containers.
        # FS1c: ``--draw`` draws the key first when there is none, in the service's own container and
        # by its own code — the keys are pinned before the flag is set, never after.
        try:
            if args[2:] == ["--draw"]:
                public = load_service_key(args[1]).public
            else:
                public = watch_key.read_public(service_key_dir(args[1]), name=watch_key.SERVICE_KEY_FILE)
        except watch_key.KeyUnavailable as e:
            print(f"✗ {args[1]} : {e}", file=sys.stderr)
            return 1
        print(f"{args[1]}={watch_key.public_text(public)}")
        return 0
    if not args or args[0] != "public" or any(a not in SERVICES for a in args[1:]):
        print("usage: python -m eregion_core.action_queue public [console|bot] | pin console|bot [--draw]")
        return 2
    pins, missing = [], []
    for service in args[1:] or SERVICES:
        try:
            public = watch_key.read_public(service_key_dir(service), name=watch_key.SERVICE_KEY_FILE)
        except watch_key.KeyUnavailable as e:
            missing.append(f"# {service} : {e}")
            continue
        pins.append(f"{service}={watch_key.public_text(public)}")
        missing.append(f"# {service} : empreinte {watch_key.fingerprint(public)}")
    if pins:
        print(f"export {KEYS_ENV}={','.join(pins)}")
    for line in missing:
        print(line)
    return 0 if pins else 1


if __name__ == "__main__":
    raise SystemExit(main())
