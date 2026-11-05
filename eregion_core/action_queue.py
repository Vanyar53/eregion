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
    "proposal_consumed": "this proposal was already executed: one proposal, one execution",
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
    # 8. the nonce — claimed before anything runs; a register that cannot be kept refuses
    try:
        fresh = seen.claim(doc["id"], expires + timedelta(seconds=SKEW_S), now)
    except (OSError, ValueError) as e:
        raise Refused("seen_store_unavailable", f"{REFUSALS['seen_store_unavailable']} ({str(e)[:120]})") from None
    if not fresh:
        raise Refused("replayed")
    # 9. the verb, and the rate
    verb = doc["verb"]
    if verb not in VERBS:
        raise Refused("unknown_verb", f"{verb[:40]!r} is not a verb of the queue ({', '.join(VERBS)})")
    if verb not in SERVICE_VERBS.get(service, frozenset()):
        raise Refused("verb_not_allowed", f"the {service} may not ask {verb}")
    if not rate.take(service, now):
        raise Refused("rate_limited")
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
        from eregion_core import channel_reader
        with self._lock:
            seen = self._read()
            kept = {n: u for n, u in seen.items() if datetime.fromisoformat(u) > now}
            if nonce in kept:
                return False
            kept[nonce] = _iso(until)
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600)
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
