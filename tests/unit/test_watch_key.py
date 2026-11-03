"""SEC19 (N-03, #456): the watch's heartbeat signed by its own key, verified by the injectors with
the public key pinned on their side — never read in the channel nor in the heartbeat.

The key is drawn in tmp (tests/unit/conftest.py, ``isolated_watch_key``), or from a fixed seed here:
never a real key. A throwaway HOME, no Azure, no network. Mutants M3240–M3259 (scripts/
mutation_check.py) are measured here, in test_watch_gate.py and in test_host_cd.py.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

import eregion_core.watch_channel as wc
import eregion_core.watch_gate as gate
import eregion_core.watch_key as watch_key
from tests.unit.fake_container import CRED, URL, FakeContainer

ROOT = Path(__file__).resolve().parents[2]
SUB = "00000000-0000-0000-0000-00000000aaaa"   # a placeholder, never a real subscription
WATCH = watch_key.Signer(bytes(range(32)))            # the watch's key, a fixed seed
OTHER = watch_key.Signer(bytes(range(1, 33)))         # another watch's
NOW = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def injector(tmp_path, monkeypatch):
    """An injector on this host: the gate's real readers, its key pinned, a throwaway HOME, its
    subscription; returns the injectors' copy of the heartbeat to write."""
    monkeypatch.setattr(gate, "READERS", {"channel": gate.channel_beat, "local": gate.local_beat,
                                          "own": gate.perimeter, "proof": watch_key.proof})
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv(gate.SUBSCRIPTION_ENV, SUB)
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(WATCH.public))
    beat = tmp_path / "home" / ".glorfindel" / "injectors" / "watch_heartbeat"
    beat.parent.mkdir(parents=True)
    return beat


def _write(path: Path, body: dict) -> None:
    path.write_text(json.dumps(body))


def _signed(at: datetime = NOW, signer=WATCH, **over) -> dict:
    return {**gate.beat_body(at, SUB, signer=signer), **over}


# ── The key: drawn once, kept by the watch alone ─────────────────────────────────────

def test_the_first_start_draws_a_key_kept_by_the_watch_alone(tmp_path):
    d = tmp_path / "watch-key"
    first = watch_key.load_or_create(d)
    path = d / watch_key.KEY_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(d.stat().st_mode) == 0o700
    assert path.stat().st_size == 32
    again = watch_key.load_or_create(d)
    assert again.public == first.public and again.fingerprint == first.fingerprint
    assert watch_key.read_public(d) == first.public


def test_a_key_readable_by_others_is_never_used(tmp_path):
    """M3240: a key others could read may have left — refused, said, never signing."""
    d = tmp_path / "watch-key"
    watch_key.load_or_create(d)
    os.chmod(d / watch_key.KEY_FILE, 0o640)
    with pytest.raises(watch_key.KeyUnavailable, match="readable by others"):
        watch_key.load_or_create(d)


def test_a_key_directory_that_is_a_link_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    (tmp_path / "watch-key").symlink_to(real)
    with pytest.raises(watch_key.KeyUnavailable, match="not a directory"):
        watch_key.load_or_create(tmp_path / "watch-key")
    assert list(real.iterdir()) == []


def test_a_key_file_that_is_a_link_is_never_followed(tmp_path):
    d = tmp_path / "watch-key"
    d.mkdir(mode=0o700)
    target = tmp_path / "planted"
    target.write_bytes(bytes(32))
    os.chmod(target, 0o600)
    (d / watch_key.KEY_FILE).symlink_to(target)
    with pytest.raises(watch_key.KeyUnavailable):
        watch_key.load_or_create(d)


@pytest.mark.parametrize("where", [".glorfindel/keys", ".glorfindel/injectors/key", "runs/keys"])
def test_the_key_never_lives_where_another_mounts_it(tmp_path, monkeypatch, where):
    """M3241: never in ~/.glorfindel (the console, the bot, the injectors mount it), never under
    runs/ — refused before anything is written."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    d = tmp_path / where
    with pytest.raises(watch_key.KeyUnavailable, match="is under"):
        watch_key.load_or_create(d)
    assert not d.exists()


def test_a_key_of_another_size_is_refused(tmp_path):
    d = tmp_path / "watch-key"
    d.mkdir(mode=0o700)
    fd = os.open(d / watch_key.KEY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"short")
    os.close(fd)
    with pytest.raises(watch_key.KeyUnavailable, match="32 expected"):
        watch_key.load_or_create(d)


def test_a_wide_directory_of_ours_is_brought_back_to_0700(tmp_path):
    d = tmp_path / "watch-key"
    d.mkdir()
    os.chmod(d, 0o755)
    watch_key.load_or_create(d)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_reading_the_public_key_never_draws_one(tmp_path):
    with pytest.raises(watch_key.KeyUnavailable, match="first start"):
        watch_key.read_public(tmp_path / "watch-key")
    assert not (tmp_path / "watch-key").exists()


def test_the_command_gives_the_public_key_and_its_fingerprint_never_the_private_one(tmp_path):
    """make watch-key: the line to pin, its fingerprint; the private key never printed."""
    from glorfindel.cli import cli
    res = CliRunner().invoke(cli, ["watch-key"])
    assert res.exit_code == 1 and "first start" in res.output and not (tmp_path / "watch-key").exists()
    res = CliRunner().invoke(cli, ["watch-key", "--create"])
    assert res.exit_code == 0, res.output
    signer = watch_key.load_or_create()
    assert f"export EREGION_WATCH_KEY={watch_key.public_text(signer.public)}" in res.output
    assert f"empreinte : {signer.fingerprint}" in res.output
    raw = (tmp_path / "watch-key" / watch_key.KEY_FILE).read_bytes()
    import base64
    assert base64.b64encode(raw).decode() not in res.output and raw.hex() not in res.output
    assert CliRunner().invoke(cli, ["watch-key"]).output == res.output


def test_the_module_says_the_public_key_with_the_standard_library_only(tmp_path):
    d = tmp_path / "k"
    signer = watch_key.load_or_create(d)
    out = subprocess.run([sys.executable, "-m", "eregion_core.watch_key", "public", str(d)], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    assert out.splitlines()[0] == f"export EREGION_WATCH_KEY={watch_key.public_text(signer.public)}"


def test_the_fingerprint_is_an_ssh_like_digest_of_the_public_key():
    fp = watch_key.fingerprint(WATCH.public)
    assert fp.startswith("SHA256:") and len(fp) == 50 and "=" not in fp
    assert fp != watch_key.fingerprint(OTHER.public)


# ── The heartbeat signed: refused before any call to the cloud ─────────────────────────

def test_a_heartbeat_signed_by_the_pinned_key_is_a_live_watch(injector):
    _write(injector, _signed(NOW - timedelta(seconds=20)))
    assert gate.refusal(NOW) == ""


def test_without_a_key_pinned_it_is_refused_and_the_gesture_said(injector, monkeypatch):
    """M3242: no key pinned on the injector's side — refused, the gesture named."""
    monkeypatch.delenv(watch_key.KEY_ENV)
    _write(injector, _signed(NOW - timedelta(seconds=20)))
    why = gate.refusal(NOW)
    assert why.startswith(f"{gate.LOCAL}: no watch key pinned (EREGION_WATCH_KEY)")
    assert "orodruin.env" in why and "make watch-key" in why and "make glorfindel-host-watch-key" in why


@pytest.mark.parametrize("pin", ["ed25519:abc", "ssh-ed25519 AAAA", watch_key.public_text(WATCH.public)[8:]])
def test_a_pin_that_is_no_key_is_refused(injector, monkeypatch, pin):
    monkeypatch.setenv(watch_key.KEY_ENV, pin)
    _write(injector, _signed(NOW - timedelta(seconds=20)))
    assert "is not a watch key" in gate.refusal(NOW)


def test_an_unsigned_heartbeat_is_refused(injector):
    """M3243: a watch older than SEC19, or a hand that writes there — the date and the perimeter
    right, no signature."""
    _write(injector, gate.beat_body(NOW - timedelta(seconds=20), SUB))
    why = gate.refusal(NOW)
    assert why.startswith(f"{gate.LOCAL}: unsigned") and "update Glorfindel" in why


def test_a_bare_date_is_unsigned(injector):
    injector.write_text((NOW - timedelta(seconds=20)).isoformat())
    assert gate.refusal(NOW).startswith(f"{gate.LOCAL}: unsigned: a bare date")


def test_a_heartbeat_signed_by_another_key_is_refused(injector):
    """M3244: another watch's key — its fingerprint said, the one pinned too."""
    _write(injector, _signed(NOW - timedelta(seconds=20), signer=OTHER))
    why = gate.refusal(NOW)
    assert "signed by another key" in why and watch_key.fingerprint(WATCH.public)[:19] in why


def test_a_heartbeat_that_claims_the_pinned_key_but_was_signed_by_another_is_refused(injector):
    """M3245: the fingerprint in the heartbeat is said, never trusted: the signature decides."""
    forged = _signed(NOW - timedelta(seconds=20), signer=OTHER)
    forged["key"] = WATCH.fingerprint
    forged["sig"] = OTHER.sign(watch_key.DOMAIN_BEAT, forged)
    _write(injector, forged)
    assert "its signature does not hold" in gate.refusal(NOW)


@pytest.mark.parametrize("field, value", [("perimeter", "0" * 16), ("at", None), ("seq", 1)])
def test_a_field_changed_after_the_signature_is_refused(injector, field, value):
    """M3246: every field is signed — the date pushed forward, the perimeter, the counter."""
    body = _signed(NOW - timedelta(minutes=10 if value is None else 0, seconds=20))
    body[field] = (NOW - timedelta(seconds=5)).isoformat() if value is None else value
    _write(injector, body)
    assert "its signature does not hold" in gate.refusal(NOW)


def test_a_signature_under_another_domain_never_reads_as_a_heartbeat(injector):
    """M3247: one key, two uses (FS1) — what it signs for its queue never passes for a heartbeat."""
    body = {k: v for k, v in _signed(NOW - timedelta(seconds=20)).items() if k != "sig"}
    body["sig"] = WATCH.sign("eregion.action-queue/1", body)
    _write(injector, body)
    assert "its signature does not hold" in gate.refusal(NOW)
    assert watch_key.message(watch_key.DOMAIN_BEAT, body).startswith(b"eregion.watch-beat/1\n")


def test_an_older_heartbeat_replayed_after_a_newer_one_is_refused(injector):
    """M3248, M3249: its counter below one already seen — refused, even fresh and well signed;
    the same heartbeat read again (before each action) is no replay."""
    old = _signed(NOW - timedelta(seconds=40))
    new = _signed(NOW - timedelta(seconds=10))
    assert new["seq"] > old["seq"]
    _write(injector, new)
    assert gate.refusal(NOW) == "" and gate.refusal(NOW) == ""
    _write(injector, old)
    assert "not above one already seen" in gate.refusal(NOW)
    assert json.loads(watch_key.seen_file().read_text())[WATCH.fingerprint]["seq"] == new["seq"]


def test_two_heartbeats_under_one_counter_are_refused(injector):
    first = _signed(NOW - timedelta(seconds=30))
    _write(injector, first)
    assert gate.refusal(NOW) == ""
    twin = {k: v for k, v in first.items() if k != "sig"}
    twin["perimeter"] = gate.perimeter(SUB)
    twin["at"] = (NOW - timedelta(seconds=20)).isoformat()
    twin["sig"] = WATCH.sign(watch_key.DOMAIN_BEAT, twin)
    _write(injector, twin)
    assert "not above one already seen" in gate.refusal(NOW)


def test_the_console_shows_the_gate_without_keeping_the_injectors_counter(injector):
    _write(injector, _signed(NOW - timedelta(seconds=20)))
    assert gate.refusal(NOW, record=False) == ""
    assert not watch_key.seen_file().exists()


def test_a_counter_that_cannot_be_kept_is_no_refusal(injector, monkeypatch, tmp_path):
    blocked = tmp_path / "a-file"
    blocked.write_text("")
    monkeypatch.setattr(watch_key, "SEEN_FILE", blocked / "seen.json")
    _write(injector, _signed(NOW - timedelta(seconds=20)))
    assert gate.refusal(NOW) == ""


def test_a_stale_signed_heartbeat_says_how_old_it_is(injector):
    _write(injector, _signed(NOW - timedelta(hours=2)))
    assert gate.refusal(NOW).startswith(f"{gate.LOCAL}: last heartbeat 2 h 00 min ago")


def test_a_signed_heartbeat_of_another_subscription_is_still_refused(injector):
    _write(injector, gate.beat_body(NOW - timedelta(seconds=20), "00000000-0000-0000-0000-0000000000ff",
                                    signer=WATCH))
    assert "another subscription" in gate.refusal(NOW)


def test_the_counter_rises_even_within_one_millisecond():
    s = watch_key.Signer(bytes(range(32)))
    seqs = [s.next_seq(NOW) for _ in range(3)]
    assert seqs == sorted(set(seqs)) and seqs[0] == int(NOW.timestamp() * 1000)
    assert s.next_seq(NOW - timedelta(hours=1)) == seqs[-1] + 1     # a clock set back: still up


# ── The channel: the hosted watch signs what Orodruin reads ───────────────────────────

def test_the_hosted_watch_signs_its_channel_heartbeat_and_orodruin_believes_it(injector, monkeypatch):
    """M3250: the publisher signs every field — since and windows too; the run reads it from
    the channel, the pinned key decides."""
    signer = watch_key.load_or_create()
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(signer.public))
    c = FakeContainer(URL)
    wc.Publisher(URL, credential=CRED, put=c.put, windows=lambda: []).tick()
    body = json.loads(c.body("heartbeat.json"))
    assert body["key"] == signer.fingerprint and {"since", "windows", "seq", "sig"} <= set(body)
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)
    monkeypatch.setattr(wc, "read_heartbeat", lambda **_: dict(body))
    assert gate.refusal() == ""
    monkeypatch.setattr(wc, "read_heartbeat", lambda **_: {**body, "windows": ["a-run-it-never-knew"]})
    assert gate.refusal().startswith(f"{gate.CHANNEL}: its signature does not hold")


def test_a_watch_without_its_key_beats_unsigned_and_says_it(monkeypatch, tmp_path, capsys):
    blocked = tmp_path / "blocked"
    blocked.write_text("")
    monkeypatch.setattr(watch_key, "KEY_DIR", blocked / "watch-key")
    c = FakeContainer(URL)
    wc.Publisher(URL, credential=CRED, put=c.put, windows=lambda: []).tick()
    assert "sig" not in json.loads(c.body("heartbeat.json"))
    assert "heartbeat not signed" in capsys.readouterr().out


def test_the_local_channel_of_verdicts_keeps_its_exact_fields(tmp_path):
    """SEC18's heartbeat holds BEAT_FIELDS only — the gate never reads it, nothing signs it."""
    (tmp_path / "verdicts").mkdir()
    v = wc.LocalVerdicts(tmp_path / "verdicts", windows=lambda: [])
    v.tick()
    assert set(json.loads((tmp_path / "verdicts" / "heartbeat.json").read_text())) == set(wc.BEAT_FIELDS)


# ── The watch writes its copy for the injectors signed ────────────────────────────────

def test_the_watch_signs_the_injectors_heartbeat(tmp_path, monkeypatch):
    """M3251: the copy the injectors read, signed by the key drawn at the watch's first start."""
    from glorfindel.response import state
    from tests.unit.test_signal_origin import _run_watch
    written: list[str] = []
    real = state._atomic_write_text

    def capture(path, text, mode=0o600):
        if Path(path).name == "watch_heartbeat" and Path(path).parent.name == "injectors":
            written.append(text)
        return real(path, text, mode=mode)
    monkeypatch.setattr(state, "_atomic_write_text", capture)
    monkeypatch.setenv(gate.SUBSCRIPTION_ENV, SUB)
    _run_watch(tmp_path, monkeypatch, [], 0)
    body = json.loads(written[0])
    signer = watch_key.load_or_create()
    assert body["key"] == signer.fingerprint
    assert watch_key.verify_beat(body, signer.public) == ""


# ── Where the key lives, where it is pinned ───────────────────────────────────────────

def _service(name: str) -> str:
    text = (ROOT / "docker-compose.yml").read_text()
    start = text.index(f"\n  {name}:\n")
    end = text.find("\n  # ", start + 1)
    return text[start:end if end > 0 else None]


def test_only_the_watch_mounts_its_key():
    """M3252: the key's directory in the watch's service, and in no other."""
    text = (ROOT / "docker-compose.yml").read_text()
    assert text.count("/.eregion/watch-key:") == 1
    assert "${HOME}/.eregion/watch-key:/root/.eregion/watch-key" in _service("watch")


def test_the_injectors_and_the_console_receive_the_pinned_key():
    """M3253: the injectors' anchor carries EREGION_WATCH_KEY; Orodruin's env-file too."""
    text = (ROOT / "docker-compose.yml").read_text()
    anchor = text[text.index("x-injector: &injector"):text.index("\nservices:")]
    assert "EREGION_WATCH_KEY: ${EREGION_WATCH_KEY:-}" in anchor
    assert "EREGION_WATCH_KEY: ${EREGION_WATCH_KEY:-}" in _service("war-room")
    assert "\nEREGION_WATCH_KEY=\n" in (ROOT / "infra" / "orodruin" / "orodruin.env.example").read_text()
    make = (ROOT / "Makefile").read_text()
    assert "-e EREGION_WATCH_KEY" in make


def test_the_watch_s_key_directory_is_made_by_its_owner_before_the_services_start():
    """Else docker makes it, as root, and the watch cannot draw its key."""
    make = (ROOT / "Makefile").read_text()
    for target in ("glorfindel-start:", "glorfindel-restart:", "glorfindel-dev:"):
        block = make[make.index(f"\n{target}"):]
        block = block[:block.index("\n\n")]
        assert "mkdir -p -m 700 $(HOME)/.eregion/watch-key" in block, target
    deploy = (ROOT / "infra" / "glorfindel-host" / "deploy.sh").read_text()
    assert 'mkdir -p -m 700 "$HOME/.eregion/watch-key"' in deploy


def test_cryptography_is_locked_in_both_images():
    """The injectors verify, the watch signs: both images carry it, pinned with its hashes."""
    for lock in ("glorfindel.txt", "annatar.txt"):
        text = (ROOT / "requirements" / lock).read_text()
        assert "\ncryptography==" in text, lock
    assert '"cryptography>=42"' in (ROOT / "pyproject.toml").read_text()


def test_a_full_disk_leaves_no_partial_key_and_the_next_start_draws_it(tmp_path, monkeypatch):
    """The key is drawn in a file of its own, then published by a link: a write that fails (ENOSPC)
    leaves nothing under the key's name, and the next start draws it."""
    import errno
    d = tmp_path / "watch-key"
    real = os.write

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(os, "write", full)
    with pytest.raises(watch_key.KeyUnavailable, match="No space left"):
        watch_key.load_or_create(d)
    assert list(d.iterdir()) == []                       # no key, no temporary file left
    monkeypatch.setattr(os, "write", real)
    signer = watch_key.load_or_create(d)
    assert (d / watch_key.KEY_FILE).stat().st_size == 32 and list(d.iterdir()) == [d / watch_key.KEY_FILE]
    assert watch_key.load_or_create(d).public == signer.public


def test_two_watches_drawing_together_keep_the_first_key(tmp_path, monkeypatch):
    """The link refused (another watch published first): that key is the one, both read it."""
    d = tmp_path / "watch-key"
    first = watch_key.load_or_create(d)
    real_read = watch_key._read_key
    calls = []

    def absent_once(path):
        calls.append(path)
        if len(calls) == 1:
            raise FileNotFoundError(path)                 # read before the other watch published
        return real_read(path)
    monkeypatch.setattr(watch_key, "_read_key", absent_once)
    assert watch_key.load_or_create(d).public == first.public
    assert sorted(p.name for p in d.iterdir()) == [watch_key.KEY_FILE]


def test_a_key_of_another_size_says_the_gesture(tmp_path):
    d = tmp_path / "watch-key"
    d.mkdir(mode=0o700)
    fd = os.open(d / watch_key.KEY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    with pytest.raises(watch_key.KeyUnavailable, match="remove it.*pin the new public key"):
        watch_key.load_or_create(d)


def test_a_clock_set_back_is_named_in_the_replay_refusal(injector):
    _write(injector, _signed(NOW - timedelta(seconds=10)))
    assert gate.refusal(NOW) == ""
    replay = {k: v for k, v in _signed(NOW - timedelta(seconds=20)).items() if k != "sig"}
    replay["seq"] = 1
    replay["sig"] = WATCH.sign(watch_key.DOMAIN_BEAT, replay)
    _write(injector, replay)
    assert "clock went back" in gate.refusal(NOW)


def test_the_console_reads_the_gate_without_recording(monkeypatch):
    """Dagorlad shows the gate as an injector reads it, never keeping the injectors' counter."""
    from eregion_console import api
    seen = {}
    monkeypatch.setattr(gate, "refusal", lambda now=None, **kw: seen.update(kw) or "")
    assert api._watch_refusal() == "" and seen == {"record": False}


def test_only_the_watch_s_docker_run_mounts_the_key():
    make = (ROOT / "Makefile").read_text()
    users = [ln for ln in make.splitlines() if "$(WATCH_KEY_VOL)" in ln]
    assert len(users) == 1
    block = make[make.index("DOCKER_GLORFINDEL_WATCH ="):]
    assert "$(WATCH_KEY_VOL)" in block[:block.index("\n\n")]
    assert make.count("@$(DOCKER_GLORFINDEL_WATCH) watch runs/") == 1


def test_the_shell_s_message_says_the_key_is_not_mounted_there(tmp_path):
    with pytest.raises(watch_key.KeyUnavailable, match="glorfindel-shell it is not mounted"):
        watch_key.read_public(tmp_path / "absent")


def test_a_temporary_a_crash_left_is_swept_never_followed(tmp_path):
    """A crash between the link and the unlink leaves a copy of the private key: swept at the next
    start; a link of that name removed itself, never what it points to."""
    d = tmp_path / "watch-key"
    d.mkdir(mode=0o700)
    orphan = d / f".{watch_key.KEY_FILE}.123.abcdef"
    fd = os.open(orphan, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, bytes(32))
    os.close(fd)
    outside = tmp_path / "outside"
    outside.write_text("kept")
    (d / f".{watch_key.KEY_FILE}.456.link").symlink_to(outside)
    watch_key.load_or_create(d)
    assert sorted(p.name for p in d.iterdir()) == [watch_key.KEY_FILE]
    assert outside.read_text() == "kept"
