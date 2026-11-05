"""FS1a (#551, docs/design/file-actions-signee.md): the signed action queue — its format, its
domains, its signatures, its freshness, its nonce, and each refusal of its closed list.

The keys come from fixed seeds, or are drawn in tmp (tests/unit/conftest.py): never a real key. A
throwaway HOME, no Azure, no network, no model. Mutants M3865–M3879, M3945–M3954 (scripts/mutants/FS1a.py) are
measured here and in test_action_proposal.py.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

import eregion_core.action_queue as aq
import eregion_core.watch_gate as gate
import eregion_core.watch_key as watch_key

CONSOLE = watch_key.Signer(bytes(range(40, 72)))     # the console's key, a fixed seed
BOT = watch_key.Signer(bytes(range(80, 112)))        # the bot's
WATCH = watch_key.Signer(bytes(range(32)))           # the watch's (SEC19)
STRANGER = watch_key.Signer(bytes(range(120, 152)))  # another hand's
PINS = {"console": CONSOLE.public, "bot": BOT.public}
NOW = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)
VM = "/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"
DIGEST = "sha256:" + "ab" * 32


def _request(signer=CONSOLE, service="console", verb="isolate_vm", now=NOW, **kw) -> dict:
    kw.setdefault("card", ("card-1", DIGEST))
    return aq.new_request(signer, service=service, verb=verb, resource_id=VM, now=now,
                          by={"via": "console-token", "session": "0a1b2c3d"}, **kw)


def _bytes(doc: dict) -> bytes:
    return json.dumps(doc).encode()


def _resign(doc: dict, signer=CONSOLE, domain=aq.DOMAIN_REQUEST) -> dict:
    out = {k: v for k, v in doc.items() if k != "sig"}
    out["key"] = signer.fingerprint
    out["sig"] = signer.sign(domain, out)
    return out


def _verify(doc, service="console", now=NOW, pins=PINS, seen=None, rate=None):
    data = doc if isinstance(doc, (bytes, str)) else _bytes(doc)
    return aq.verify_request(data, service=service, pins=pins, now=now,
                             seen=seen if seen is not None else aq.MemorySeen(),
                             rate=rate if rate is not None else aq.Rate())


def _code(doc, **kw) -> str:
    with pytest.raises(aq.Refused) as e:
        _verify(doc, **kw)
    return e.value.code


# ── The format ───────────────────────────────────────────────────────────────────────

def test_a_request_signed_by_its_service_is_taken():
    req = _verify(_request())
    assert (req.service, req.verb, req.resource_id, req.card_id, req.proposal) == \
        ("console", "isolate_vm", VM, "card-1", DIGEST)
    assert req.key == CONSOLE.fingerprint and req.by["via"] == "console-token"


def test_a_request_carries_exactly_its_fields():
    doc = _request()
    assert tuple(doc) == aq.REQUEST_FIELDS
    assert len(doc["id"]) == 32 and int(doc["id"], 16) >= 0
    assert len(_bytes(doc)) < aq.MAX_BYTES


def test_each_request_has_its_own_nonce():
    assert _request()["id"] != _request()["id"]


def test_the_closed_lists_are_what_the_design_says():
    """§2.2 and §2.11: the verbs, each service's, the refusals — and none of the restore."""
    assert aq.VERBS == ("isolate_vm", "block_ip", "snapshot", "release_isolation", "reset",
                        "unblock_ip", "promote_block")
    assert aq.SERVICE_VERBS == {"console": frozenset(aq.VERBS), "bot": frozenset({"reset"})}
    assert not any("restore" in v for v in aq.VERBS)
    assert set(aq.REFUSALS) == {
        "malformed", "unsigned", "no_key_pinned", "unknown_key", "bad_signature", "wrong_service",
        "not_yet_valid", "too_long", "expired", "replayed", "seen_store_unavailable", "unknown_verb",
        "verb_not_allowed", "rate_limited", "proposal_missing", "proposal_mismatch", "proposal_consumed",
        "card_not_pending", "nothing_to_undo", "guard", "read_only"}
    assert aq.CRITICAL == {"unsigned", "unknown_key", "bad_signature", "wrong_service", "replayed",
                           "verb_not_allowed"}
    assert all(reason.strip() for reason in aq.REFUSALS.values())


def test_a_refusal_out_of_the_closed_list_cannot_be_made():
    with pytest.raises(ValueError, match="not a refusal"):
        aq.Refused("forbidden")
    r = aq.Refused("replayed")
    assert r.reason == aq.REFUSALS["replayed"] and r.critical and "replayed" in str(r)
    assert not aq.Refused("expired").critical


# ── malformed ────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("change", [
    lambda d: d.update(extra="x"),                       # a field more (M3876)
    lambda d: d.pop("verb"),                             # a field less
    lambda d: d.update(v=2),
    lambda d: d.update(v=True),
    lambda d: d.update(kind="proposal"),
    lambda d: d.update(id="not-hex"),
    lambda d: d.update(id="ab" * 15),
    lambda d: d.update(resource_id=7),
    lambda d: d.update(by={"via": "console-token"}),
    lambda d: d.update(by={"via": 1, "user": "", "name": "", "session": ""}),
    lambda d: d.update(card={"id": "card-1"}),
    lambda d: d.update(card={"id": "card-1", "proposal": "md5:00"}),
    lambda d: d.update(card="card-1"),
    lambda d: d.update(issued_at="yesterday"),
    lambda d: d.update(issued_at="2026-11-05T09:00:00"),          # no zone
    lambda d: d.update(expires_at=d["issued_at"]),                # never after
    lambda d: d.update(key=5),
    lambda d: d.pop("key"),                                       # signed without naming its key
])
def test_a_request_out_of_its_form_is_malformed(change):
    doc = _request()
    change(doc)
    assert _code(doc) == "malformed"


@pytest.mark.parametrize("data", [
    b"\xff\xfe", b"not json", b"[1, 2]", b'{"v": NaN}', b"x" * (aq.MAX_BYTES + 1),
    b'{"v": 1, "v": 1}',                                          # a field twice
])
def test_bytes_that_are_no_request_are_malformed(data):
    assert _code(data) == "malformed"


def test_an_extra_field_is_refused_even_signed():
    """M3876: a field more refuses the request, whoever signed it."""
    doc = _resign({**_request(), "extra": "x"})
    assert _code(doc) == "malformed"


def test_the_file_is_read_bounded_and_never_through_a_link(tmp_path):
    good = tmp_path / "good.json"
    good.write_bytes(_bytes(_request()))
    assert aq.read_request(good) == good.read_bytes()
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (aq.MAX_BYTES + 1))
    with pytest.raises(aq.Refused) as e:
        aq.read_request(big)
    assert e.value.code == "malformed"
    link = tmp_path / "link.json"
    link.symlink_to(good)
    with pytest.raises(aq.Refused) as e:
        aq.read_request(link)
    assert e.value.code == "malformed"
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(aq.Refused) as e:
        aq.read_request(fifo)
    assert e.value.code == "malformed"
    with pytest.raises(FileNotFoundError):
        aq.read_request(tmp_path / "gone.json")


# ── The signature, the key, the service ──────────────────────────────────────────────

def test_an_unsigned_request_is_refused_and_critical():
    """M3865."""
    doc = _request()
    doc.pop("sig")
    with pytest.raises(aq.Refused) as e:
        _verify(doc)
    assert e.value.code == "unsigned" and e.value.critical
    doc = _request()
    doc["sig"] = None
    assert _code(doc) == "unsigned"
    doc.pop("key")
    doc.pop("sig")
    assert _code(doc) == "unsigned"


def test_no_key_pinned_for_the_service_refuses_and_says_the_gesture():
    with pytest.raises(aq.Refused) as e:
        _verify(_request(), pins={"bot": BOT.public})
    assert e.value.code == "no_key_pinned" and aq.KEYS_ENV in e.value.reason
    assert not e.value.critical


def test_a_request_signed_by_another_key_is_refused_with_both_fingerprints():
    """M3866: a key drawn again, or another hand — its fingerprint and the pinned one said."""
    with pytest.raises(aq.Refused) as e:
        _verify(_request(signer=STRANGER))
    assert e.value.code == "unknown_key" and e.value.critical
    assert STRANGER.fingerprint[:19] in e.value.reason and CONSOLE.fingerprint[:19] in e.value.reason


def test_a_request_that_claims_the_pinned_key_but_was_signed_by_another_does_not_hold():
    """M3867: the fingerprint is said, never believed."""
    doc = _request(signer=STRANGER)
    doc = {**{k: v for k, v in doc.items() if k != "sig"}, "key": CONSOLE.fingerprint}
    doc["sig"] = STRANGER.sign(aq.DOMAIN_REQUEST, doc)
    with pytest.raises(aq.Refused) as e:
        _verify(doc)
    assert e.value.code == "bad_signature" and e.value.critical


@pytest.mark.parametrize("field,value", [
    ("verb", "release_isolation"), ("resource_id", VM + "-other"), ("ip", "198.51.100.7"),
    ("expires_at", "2026-11-05T09:01:00.000+00:00"), ("card", None),
    ("by", {"via": "console-token", "user": "", "name": "", "session": "ffffffff"}),
])
def test_a_field_changed_after_the_signature_does_not_hold(field, value):
    doc = {**_request(), field: value}
    assert _code(doc) == "bad_signature"


def test_a_signature_that_is_not_one_does_not_hold():
    assert _code({**_request(), "sig": "not base64"}) == "bad_signature"
    assert _code({**_request(), "sig": 12}) == "bad_signature"


def test_the_console_s_key_in_the_bot_s_queue_is_another_service():
    """§2.11: the key of the console in the bot's directory, or the reverse."""
    with pytest.raises(aq.Refused) as e:
        _verify(_request(signer=CONSOLE, service="console", verb="reset"), service="bot")
    assert e.value.code == "wrong_service" and e.value.critical and "console's key" in e.value.reason
    assert _code(_request(signer=BOT, service="bot", verb="reset"), service="console") == "wrong_service"


def test_a_request_naming_another_service_in_this_one_s_queue_is_refused():
    """M3868: the bot's key, its own directory, but the console's name."""
    doc = _request(signer=BOT, service="console", verb="reset")
    with pytest.raises(aq.Refused) as e:
        _verify(doc, service="bot")
    assert e.value.code == "wrong_service" and e.value.critical


def test_the_directory_s_service_must_be_one_of_the_queue():
    with pytest.raises(ValueError):
        _verify(_request(), service="watch")


# ── The domains: a signature made for one use never reads as another ─────────────────

@pytest.mark.parametrize("domain", [aq.DOMAIN_QUEUE, watch_key.DOMAIN_BEAT, watch_key.DOMAIN_DETECTION])
def test_a_request_signed_under_another_domain_is_refused(domain):
    """M3877: the service's key, the request's fields, another domain — never a request."""
    assert _code(_resign(_request(), CONSOLE, domain)) == "bad_signature"


def test_the_domains_are_distinct_and_named():
    assert aq.DOMAIN_REQUEST == "eregion.action-request/1"
    assert aq.DOMAIN_QUEUE == watch_key.DOMAIN_QUEUE == "eregion.action-queue/1"
    assert len({aq.DOMAIN_REQUEST, aq.DOMAIN_QUEUE, watch_key.DOMAIN_BEAT, watch_key.DOMAIN_DETECTION}) == 4


def test_a_request_s_signature_never_reads_as_a_heartbeat():
    """The same key pinned as the watch's, a request's signature: the gate refuses it."""
    beat = {**gate.beat_body(NOW, "00000000-0000-0000-0000-00000000aaaa"), "seq": 1, "key": WATCH.fingerprint}
    beat["sig"] = WATCH.sign(aq.DOMAIN_REQUEST, beat)
    assert "does not hold" in watch_key.verify_beat(beat, WATCH.public)


def test_a_heartbeat_s_signature_never_reads_as_a_request():
    """A request signed under the heartbeat's domain by the key pinned for the service."""
    assert _code(_resign(_request(), CONSOLE, watch_key.DOMAIN_BEAT)) == "bad_signature"


def test_a_request_s_signature_never_reads_as_a_proposal():
    """The watch's own key signing a request's body: never a proposal of the watch."""
    body = _resign(_request(), WATCH, aq.DOMAIN_REQUEST)
    body["kind"] = "proposal"
    assert aq.watch_refusal(body, "proposal", WATCH.public) == "its signature does not hold"


def test_a_proposal_never_reads_as_a_receipt_nor_the_reverse():
    proposal = aq.sign_watch("proposal", {"card": "card-1"}, WATCH)
    assert aq.watch_refusal(proposal, "proposal", WATCH.public) == ""
    assert "not a receipt" in aq.watch_refusal(proposal, "receipt", WATCH.public)
    relabelled = {**proposal, "kind": "receipt"}
    assert aq.watch_refusal(relabelled, "receipt", WATCH.public) == "its signature does not hold"
    with pytest.raises(ValueError):
        aq.sign_watch("request", {}, WATCH)


# ── The time, at its bounds ──────────────────────────────────────────────────────────

def test_issued_up_to_the_skew_ahead_is_taken_beyond_is_not_yet_valid():
    """M3869."""
    ahead = NOW + timedelta(seconds=aq.SKEW_S)
    assert _verify(_request(now=ahead)).id
    with pytest.raises(aq.Refused) as e:
        _verify(_request(now=ahead + timedelta(milliseconds=1)))
    assert e.value.code == "not_yet_valid" and not e.value.critical


def test_a_lifetime_up_to_its_bound_is_taken_beyond_is_too_long():
    """M3870."""
    assert _verify(_request(lifetime_s=aq.MAX_LIFETIME_S)).id
    assert _code(_request(lifetime_s=aq.MAX_LIFETIME_S + 0.001)) == "too_long"
    assert _code(_request(lifetime_s=3600)) == "too_long"


def test_a_request_is_taken_until_its_expiry_and_refused_from_it():
    """M3871: expired at expires_at, and after."""
    lifetime = timedelta(seconds=aq.MAX_LIFETIME_S)
    assert _verify(_request(), now=NOW + lifetime - timedelta(milliseconds=1)).id
    assert _code(_request(), now=NOW + lifetime) == "expired"
    with pytest.raises(aq.Refused) as e:
        _verify(_request(), now=NOW + timedelta(hours=1))
    assert e.value.code == "expired" and "stopped or slow" in e.value.reason


def test_a_stale_request_never_touches_the_register():
    seen = aq.MemorySeen()
    doc = _request()
    assert _code(doc, now=NOW + timedelta(hours=1), seen=seen) == "expired"
    assert _verify(doc, seen=seen).id == doc["id"]


# ── The nonce, the replay, the register ──────────────────────────────────────────────

def test_the_same_nonce_is_taken_once():
    """M3872."""
    seen, doc = aq.MemorySeen(), _request()
    assert _verify(doc, seen=seen).id == doc["id"]
    with pytest.raises(aq.Refused) as e:
        _verify(doc, seen=seen, now=NOW + timedelta(seconds=5))
    assert e.value.code == "replayed" and e.value.critical


def test_a_nonce_signed_again_in_another_request_is_still_a_replay():
    seen = aq.MemorySeen()
    first = _request()
    assert _verify(first, seen=seen).id
    again = _request(verb="snapshot", nonce=first["id"])
    assert _code(again, seen=seen) == "replayed"


def test_a_register_that_cannot_be_read_or_written_refuses():
    """M3873: for an action the register closes — the reverse of SEC19's counter."""
    class Broken:
        def claim(self, nonce, until, now):
            raise OSError("disk full")
    with pytest.raises(aq.Refused) as e:
        _verify(_request(), seen=Broken())
    assert e.value.code == "seen_store_unavailable" and "disk full" in e.value.reason


def test_the_register_in_its_file_remembers_across_a_restart(tmp_path):
    path = tmp_path / "watch-queue" / "seen.json"
    doc = _request()
    assert _verify(doc, seen=aq.SeenFile(path)).id
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert _code(doc, seen=aq.SeenFile(path)) == "replayed"            # a new watch, the same register
    kept = json.loads(path.read_text())
    assert datetime.fromisoformat(kept[doc["id"]]) == \
        datetime.fromisoformat(doc["expires_at"]) + timedelta(seconds=aq.SKEW_S)


def test_the_register_forgets_a_nonce_once_its_request_cannot_be_taken(tmp_path):
    path = tmp_path / "seen.json"
    old = _request()
    assert _verify(old, seen=aq.SeenFile(path)).id
    later = NOW + timedelta(seconds=aq.MAX_LIFETIME_S + aq.SKEW_S + 1)
    assert _verify(_request(now=later), now=later, seen=aq.SeenFile(path)).id
    assert old["id"] not in json.loads(path.read_text())


@pytest.mark.parametrize("content", ["not json", "[]", '{"a": 1}', '{"a": "not a time"}',
                                     '{"a": "2026-11-05T09:00:00"}'])     # a time without its zone
def test_an_unreadable_register_file_refuses(tmp_path, content):
    path = tmp_path / "seen.json"
    path.write_text(content)
    assert _code(_request(), seen=aq.SeenFile(path)) == "seen_store_unavailable"


def test_a_register_file_that_is_a_link_refuses(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    path = tmp_path / "seen.json"
    path.symlink_to(target)
    assert _code(_request(), seen=aq.SeenFile(path)) == "seen_store_unavailable"


def test_a_register_that_cannot_be_written_refuses(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        assert _code(_request(), seen=aq.SeenFile(ro / "seen.json")) == "seen_store_unavailable"
    finally:
        ro.chmod(0o700)


def test_the_register_lives_where_only_the_watch_mounts_it(tmp_path, monkeypatch):
    monkeypatch.setattr(aq, "QUEUE_DIR", None)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert aq.SeenFile().path == tmp_path / ".eregion" / "watch-queue" / "seen.json"


# ── The verb, the rate ───────────────────────────────────────────────────────────────

def test_a_verb_out_of_the_list_is_unknown():
    with pytest.raises(aq.Refused) as e:
        _verify(_request(verb="restore_from_backup"))
    assert e.value.code == "unknown_verb" and not e.value.critical


def test_the_bot_may_only_reset():
    """M3874: the verbs of each service are the code's, never the request's."""
    assert _verify(_request(signer=BOT, service="bot", verb="reset"), service="bot").verb == "reset"
    for verb in sorted(set(aq.VERBS) - {"reset"}):
        with pytest.raises(aq.Refused) as e:
            _verify(_request(signer=BOT, service="bot", verb=verb), service="bot")
        assert e.value.code == "verb_not_allowed" and e.value.critical, verb


def test_the_console_may_ask_every_verb_of_the_list():
    for verb in aq.VERBS:
        assert _verify(_request(verb=verb)).verb == verb


def test_more_than_thirty_requests_a_minute_are_rate_limited():
    """M3875: per service, over a sliding minute."""
    rate, seen = aq.Rate(), aq.MemorySeen()
    for i in range(aq.RATE_PER_MIN):
        assert _verify(_request(), seen=seen, rate=rate, now=NOW + timedelta(seconds=i)).id
    with pytest.raises(aq.Refused) as e:
        _verify(_request(now=NOW + timedelta(seconds=30)), seen=seen, rate=rate, now=NOW + timedelta(seconds=30))
    assert e.value.code == "rate_limited"
    # the bot's own minute is untouched
    assert _verify(_request(signer=BOT, service="bot", verb="reset"), service="bot", seen=seen, rate=rate,
                   now=NOW + timedelta(seconds=30)).id
    # a minute after the first, room again
    later = NOW + timedelta(seconds=60)
    assert _verify(_request(now=later), seen=seen, rate=rate, now=later).id


# ── The order: the cheapest first ────────────────────────────────────────────────────

def test_an_unsigned_or_forged_request_never_reaches_the_register():
    class Watching:
        claimed = 0

        def claim(self, nonce, until, now):
            Watching.claimed += 1
            return True
    for doc in ({k: v for k, v in _request().items() if k != "sig"}, _request(signer=STRANGER),
                {**_request(), "verb": "snapshot"}, _request(signer=BOT, service="bot", verb="reset")):
        with pytest.raises(aq.Refused):
            _verify(doc, seen=Watching())
    assert Watching.claimed == 0


# ── The pins ─────────────────────────────────────────────────────────────────────────

def test_the_pins_are_read_from_the_watch_s_environment_only(monkeypatch):
    assert aq.pinned_keys() == ({}, [])
    monkeypatch.setenv(aq.KEYS_ENV, f"console={watch_key.public_text(CONSOLE.public)}, "
                                    f"bot={watch_key.public_text(BOT.public)}")
    assert aq.pinned_keys() == (PINS, [])


@pytest.mark.parametrize("text,kept,said", [
    ("watch=ed25519:" + "A" * 43 + "=", {}, "not a service"),
    ("console=ed25519:short", {}, "is not one"),
    ("console", {}, "not a service"),
])
def test_a_pin_that_is_wrong_is_left_out_and_said(text, kept, said):
    pins, wrong = aq.parse_pins(text)
    assert pins == kept and len(wrong) == 1 and said in wrong[0]


def test_a_service_pinned_twice_keeps_neither():
    one, other = watch_key.public_text(CONSOLE.public), watch_key.public_text(STRANGER.public)
    pins, wrong = aq.parse_pins(f"console={one},console={other},bot={watch_key.public_text(BOT.public)}")
    assert pins == {"bot": BOT.public} and wrong == [f"{aq.KEYS_ENV}: console named 2 times — none kept"]


# ── The service's key: the watch's own code, drawn apart ─────────────────────────────

def test_a_service_s_key_is_drawn_once_by_the_watch_s_code(tmp_path):
    first = aq.load_service_key("console")
    d = aq.service_key_dir("console")
    path = d / watch_key.SERVICE_KEY_FILE
    assert d == tmp_path / "service-keys" / "console"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(d.stat().st_mode) == 0o700
    assert path.stat().st_size == 32 and sorted(p.name for p in d.iterdir()) == [watch_key.SERVICE_KEY_FILE]
    assert aq.load_service_key("console").public == first.public
    assert aq.load_service_key("bot").public != first.public
    assert _verify(aq.new_request(first, service="console", verb="snapshot", resource_id=VM, now=NOW),
                   pins={"console": first.public}).verb == "snapshot"


def test_a_service_s_key_lives_beside_the_console_s_token_and_in_the_bot_s_own_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(aq, "KEY_ROOT", None)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert aq.service_key_dir("console") == tmp_path / ".eregion" / "console"
    assert aq.service_key_dir("bot") == tmp_path / ".eregion" / "bot"
    with pytest.raises(ValueError):
        aq.service_key_dir("watch")


def test_a_service_s_key_readable_by_others_is_never_used():
    aq.load_service_key("console")
    path = aq.service_key_dir("console") / watch_key.SERVICE_KEY_FILE
    path.chmod(0o644)
    with pytest.raises(watch_key.KeyUnavailable, match="readable by others"):
        aq.load_service_key("console")


def test_a_service_s_key_that_is_a_link_is_never_followed(tmp_path):
    d = aq.service_key_dir("bot")
    d.mkdir(parents=True, mode=0o700)
    target = tmp_path / "elsewhere"
    target.write_bytes(bytes(32))
    target.chmod(0o600)
    (d / watch_key.SERVICE_KEY_FILE).symlink_to(target)
    with pytest.raises(watch_key.KeyUnavailable):
        aq.load_service_key("bot")


def test_a_service_s_key_of_another_size_says_its_own_gesture():
    d = aq.service_key_dir("console")
    d.mkdir(parents=True, mode=0o700)
    fd = os.open(d / watch_key.SERVICE_KEY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    with pytest.raises(watch_key.KeyUnavailable) as e:
        aq.load_service_key("console")
    assert aq.KEYS_ENV in str(e.value) and "make watch-key" not in str(e.value)


def test_a_service_s_key_never_lives_where_another_mounts_it(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(aq, "KEY_ROOT", tmp_path / ".glorfindel")
    with pytest.raises(watch_key.KeyUnavailable, match="glorfindel"):
        aq.load_service_key("console")


def test_a_crashed_draw_of_a_service_s_key_is_swept():
    d = aq.service_key_dir("bot")
    d.mkdir(parents=True, mode=0o700)
    (d / f".{watch_key.SERVICE_KEY_FILE}.123.abcdef").write_bytes(bytes(32))
    aq.load_service_key("bot")
    assert sorted(p.name for p in d.iterdir()) == [watch_key.SERVICE_KEY_FILE]


# ── The watch's key: unchanged, byte for byte ────────────────────────────────────────

def test_the_watch_signs_its_heartbeat_as_before_the_draw_was_shared():
    """A known answer, computed by the code of origin/main before FS1a: the same seed, the same
    body, the same counter, the same signature — Ed25519 is deterministic."""
    body = watch_key.sign_beat({"at": "2026-11-05T09:00:00+00:00", "perimeter": "sha256:00"},
                               watch_key.Signer(bytes(range(32))), NOW)
    assert body == {"at": "2026-11-05T09:00:00+00:00", "perimeter": "sha256:00", "seq": 1793869200000,
                    "key": "SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw",
                    "sig": "LiSsTnjH/pJM+qC3wqItugvX5VsTvqXUG5/aFFjSY+O4r2O+QrzfuemR5r0bNTtSvGLVku1c7joViNE3qQ3GBw=="}
    assert watch_key.verify_beat(body, WATCH.public) == ""


def test_the_watch_s_key_keeps_its_name_its_place_and_its_words(tmp_path):
    signer = watch_key.load_or_create()
    d = watch_key.key_dir()
    assert sorted(p.name for p in d.iterdir()) == ["watch_ed25519"]
    assert watch_key.load_or_create(d).public == signer.public
    other = tmp_path / "other-key"
    other.mkdir(mode=0o700)
    fd = os.open(other / watch_key.KEY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    with pytest.raises(watch_key.KeyUnavailable) as e:
        watch_key.load_or_create(other)
    assert str(e.value).endswith("remove it, let the watch draw another at its next start, then pin the "
                                 "new public key (make watch-key, make glorfindel-host-watch-key)")


def test_the_watch_and_a_service_draw_two_keys_never_one():
    assert watch_key.load_or_create().public != aq.load_service_key("console").public


# ── A signature in its one canonical form (FS1a review) ──────────────────────────────

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _spellings(sig: str) -> list[str]:
    """The 15 other spellings of a signature that a lax decoder reads alike: the last character
    before ``==`` carries 2 bits of the signature and 4 unused ones."""
    last = _B64.index(sig[85])
    return [sig[:85] + _B64[(last & 0b110000) | low] + "==" for low in range(16)
            if (last & 0b110000) | low != last]


def test_what_the_watch_and_a_service_sign_is_in_canonical_form():
    """Every signature the code writes (a heartbeat, a detection, a proposal, a request) is the
    one form now believed — the watch of today is not refused."""
    for seed in range(8):
        signer = watch_key.Signer(bytes((seed + i) % 256 for i in range(32)))
        for i in range(8):
            at = NOW + timedelta(seconds=i)
            sigs = [
                watch_key.sign_beat({"at": at.isoformat(), "perimeter": f"sha256:{i}"}, signer, at)["sig"],
                watch_key.sign_detection({"exercise_run": f"r{i}", "signal_id": f"s{seed}"}, signer)["sig"],
                aq.sign_proposal({"id": f"c{i}", "action": "isolate_vm", "resource_id": VM,
                                  "escalation_type": "mode_hold"}, signer, at)["sig"],
                aq.new_request(signer, service="console", verb="snapshot", resource_id=VM, now=at)["sig"],
            ]
            for sig in sigs:
                raw = watch_key.signature_bytes(sig)
                assert raw is not None and len(raw) == 64, sig


def test_the_fifteen_other_spellings_of_a_request_s_signature_are_refused():
    """M3953: one request, one signature, one digest — never 16 (the register of the proposals
    consumed would be gone round)."""
    doc = _request()
    variants = _spellings(doc["sig"])
    assert len(variants) == 15 and doc["sig"] not in variants
    for sig in variants:
        assert _code({**doc, "sig": sig}) == "bad_signature", sig
    for sig in (doc["sig"] + "\n", " " + doc["sig"], doc["sig"][:-2] + "=", doc["sig"].replace("+", "-")):
        if sig != doc["sig"]:
            assert _code({**doc, "sig": sig}) == "bad_signature", sig
    assert _verify(doc).id


def test_the_other_spellings_of_a_proposal_s_signature_are_refused():
    p = aq.sign_proposal({"id": "c1", "action": "isolate_vm", "resource_id": VM,
                          "escalation_type": "mode_hold"}, WATCH, NOW)
    assert aq.watch_refusal(p, "proposal", WATCH.public) == ""
    for sig in _spellings(p["sig"]):
        assert aq.watch_refusal({**p, "sig": sig}, "proposal", WATCH.public) == "its signature does not hold"


def test_the_other_spellings_of_a_heartbeat_s_or_a_detection_s_signature_are_refused():
    """SEC19, SEC21: the same canonical form for what the injectors believe."""
    beat = watch_key.sign_beat({"at": NOW.isoformat(), "perimeter": "sha256:00"}, WATCH, NOW)
    det = watch_key.sign_detection({"exercise_run": "r1", "signal_id": "s1", "event": "x"}, WATCH)
    assert watch_key.verify_beat(beat, WATCH.public) == ""
    assert watch_key.detection_refusal(det, WATCH.public, run_id="r1", signal_id="s1") == ""
    for sig in _spellings(beat["sig"]) + [beat["sig"] + "\n"]:
        assert "not one" in watch_key.verify_beat({**beat, "sig": sig}, WATCH.public), sig
    for sig in _spellings(det["sig"]) + [det["sig"] + "\n"]:
        assert "not one" in watch_key.detection_refusal({**det, "sig": sig}, WATCH.public,
                                                        run_id="r1", signal_id="s1"), sig


# ── FS1b: the queue on disk, the flag, the keys to pin ──────────────────────────────

def test_fs1b_a_request_is_deposited_in_its_services_directory_and_withdrawn(tmp_path):
    doc = _request()
    path = aq.deposit(doc, tmp_path)
    assert path == tmp_path / "console" / "queue" / f"{doc['id']}.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert _verify(aq.read_request(path)).id == doc["id"]
    bot = _request(signer=BOT, service="bot", verb="reset")
    assert aq.deposit(bot, tmp_path).parent == tmp_path / "bot" / "queue"
    aq.withdraw("console", doc["id"], tmp_path)
    assert not path.exists()
    with pytest.raises(ValueError):
        aq.deposit({**doc, "id": "../x"}, tmp_path)


def test_fs1b_requests_left_unanswered_are_swept_after_an_hour(tmp_path):
    old, new = aq.deposit(_request(), tmp_path), aq.deposit(_request(), tmp_path)
    os.utime(old, (0, 0))
    assert aq.sweep_requests("console", tmp_path) == 1
    assert not old.exists() and new.exists()


def test_fs1b_a_receipt_is_read_only_when_it_is_the_watchs_for_this_request(tmp_path):
    rid = "a" * 32
    body = {"request": rid, "service": "console", "state": "done", "verb": "isolate_vm"}
    path = aq.receipt_path("console", rid, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(aq.sign_watch("receipt", body, WATCH)))
    assert aq.read_receipt("console", rid, root=tmp_path, watch_public=WATCH.public)["state"] == "done"
    assert aq.read_receipt("console", rid, root=tmp_path, watch_public=STRANGER.public) is None
    assert aq.read_receipt("bot", rid, root=tmp_path) is None                  # another service's name
    path.write_text(json.dumps(aq.sign_watch("proposal", body, WATCH)))
    assert aq.read_receipt("console", rid, root=tmp_path) is None              # not a receipt
    path.write_text("[" * 60_000)
    assert aq.read_receipt("console", rid, root=tmp_path) is None              # never raises
    with pytest.raises(ValueError):
        aq.receipt_path("console", "../../x")


def test_fs1b_a_receipt_awaited_until_its_state_or_its_time(tmp_path):
    rid = "b" * 32
    clock = iter(range(100)).__next__
    assert aq.await_receipt("console", rid, final=False, timeout_s=3, root=tmp_path, clock=clock,
                            sleep=lambda s: None) is None
    path = aq.receipt_path("console", rid, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(aq.sign_watch("receipt", {"request": rid, "service": "console",
                                                          "state": "accepted"}, WATCH)))
    assert aq.await_receipt("console", rid, final=False, timeout_s=3, root=tmp_path, clock=clock,
                            sleep=lambda s: None)["state"] == "accepted"
    last = aq.await_receipt("console", rid, final=True, timeout_s=3, root=tmp_path, clock=clock,
                            sleep=lambda s: None)
    assert last["state"] == "accepted", "the last one read, once the time is out"


def test_fs1b_the_flag_is_one_and_nothing_else():
    for value, on in (("1", True), ("", False), ("0", False), ("true", False), ("yes", False), ("1 ", False)):
        assert aq.enabled({aq.FLAG_ENV: value}) is on, value
    assert aq.enabled({}) is False


def test_fs1b_queue_keys_prints_the_line_to_pin_never_a_private_key(capsys):
    assert aq.main(["public"]) == 1                                  # none drawn yet
    console = aq.load_service_key("console")
    assert aq.main(["public"]) == 0
    out = capsys.readouterr().out
    assert f"export {aq.KEYS_ENV}=console={watch_key.public_text(console.public)}" in out
    line = next(x for x in out.splitlines() if x.startswith("export "))
    pins, wrong = aq.parse_pins(line.split("=", 1)[1])
    assert pins == {"console": console.public} and not wrong
    bot = aq.load_service_key("bot")
    assert aq.main(["pin", "bot"]) == 0
    assert capsys.readouterr().out.strip() == f"bot={watch_key.public_text(bot.public)}"
    assert aq.main(["pin", "watch"]) == 2
    raw = (aq.service_key_dir("console") / watch_key.SERVICE_KEY_FILE).read_bytes()
    assert raw.hex() not in out


def test_fs1b_a_proposal_kept_only_while_it_stands_and_is_young():
    card = {"id": "c1", "action": "isolate_vm", "resource_id": VM, "escalation_type": "mode_hold"}
    p = aq.sign_proposal(card, WATCH, NOW)
    assert aq.proposal_fresh(card, p, WATCH.public, NOW + timedelta(seconds=10), 600)
    assert not aq.proposal_fresh(card, p, WATCH.public, NOW + timedelta(seconds=600), 600)
    assert not aq.proposal_fresh(card, p, WATCH.public, NOW - timedelta(seconds=1), 600)    # dated ahead
    assert not aq.proposal_fresh(card, p, STRANGER.public, NOW, 600)
    assert not aq.proposal_fresh({**card, "action_params": {"port": 22}}, p, WATCH.public, NOW, 600)
    assert not aq.proposal_fresh(card, None, WATCH.public, NOW, 600)
