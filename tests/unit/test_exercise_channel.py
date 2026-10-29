"""O1, part C: the exercise channel carries the windows from Orodruin to a watch on another
host — published by the injector, pulled by the watch, never fatal to either. And the
contract allows the identity's one assignment on that container, nothing wider.
Mutants M68–M70 (scripts/mutation_check.py) are measured here."""
import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import eregion_core.exercise as exercise
import eregion_core.exercise_channel as channel
import eregion_core.orodruin as orodruin

URL = "https://storodruin.blob.core.windows.net/exercises"
VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
CRED = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="tok"))


@pytest.fixture(autouse=True)
def fresh_channel(monkeypatch, tmp_path):
    monkeypatch.setattr(channel, "_last_pull", 0.0)
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setenv("EREGION_EXERCISES_DIR", str(tmp_path / "exercises"))


def _ok(content=b""):
    return SimpleNamespace(ok=True, status_code=200, content=content)


# ── publish ────────────────────────────────────────────────────────────────────

def test_without_a_channel_nothing_is_published():
    put = MagicMock()
    assert channel.publish({"run_id": "r1"}, channel="", put=put) is False
    put.assert_not_called()


def test_a_window_is_written_as_its_run_id_by_bearer_token():
    put = MagicMock(return_value=_ok())
    assert channel.publish({"run_id": "20261019T125749Z", "targets": [VM]},
                           channel=URL, credential=CRED, put=put)
    url = put.call_args.args[0]
    headers = put.call_args.kwargs["headers"]
    assert url == f"{URL}/20261019T125749Z.json"
    assert headers["Authorization"] == "Bearer tok" and headers["x-ms-blob-type"] == "BlockBlob"
    assert json.loads(put.call_args.kwargs["data"])["targets"] == [VM]


def test_a_refused_write_raises_to_its_caller():
    put = MagicMock(return_value=SimpleNamespace(ok=False, status_code=403))
    with pytest.raises(RuntimeError, match="403"):
        channel.publish({"run_id": "r1"}, channel=URL, credential=CRED, put=put)


def test_open_and_close_publish_the_window(monkeypatch, tmp_path):
    """M69: the injector writes the window locally AND carries it to the watch."""
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    sent = []
    monkeypatch.setattr(channel, "publish", lambda w: sent.append(dict(w)))
    exercise.open_window("r1", injector="annatar", kind="technique", experiment="T1136",
                         targets=[VM], directory=tmp_path)
    exercise.close_window("r1", directory=tmp_path)
    assert [w["run_id"] for w in sent] == ["r1", "r1"]
    assert sent[0]["end"] is None and sent[1]["end"]


def test_a_channel_that_fails_never_breaks_the_run(monkeypatch, tmp_path):
    def boom(window):
        raise RuntimeError("HTTP 403")
    monkeypatch.setattr(channel, "publish", boom)
    w = exercise.open_window("r1", injector="annatar", kind="technique", experiment="x",
                             targets=[VM], directory=tmp_path)
    assert (tmp_path / "r1.json").exists() and w["run_id"] == "r1"


# ── pull ───────────────────────────────────────────────────────────────────────

def _listing(*blobs):
    items = "".join(
        f"<Blob><Name>{n}</Name><Properties><Last-Modified>{m}</Last-Modified></Properties></Blob>"
        for n, m in blobs)
    return f"<EnumerationResults><Blobs>{items}</Blobs></EnumerationResults>".encode()


def _getter(listing, bodies):
    calls = []

    def get(url, headers, params=None, timeout=None):
        calls.append(url)
        if params:
            return _ok(listing)
        return _ok(bodies[url.rsplit("/", 1)[1]])
    return get, calls


def test_pull_copies_new_windows_and_skips_unsafe_names(tmp_path):
    body = json.dumps({"run_id": "r1", "start": "2026-10-19T12:57:49+00:00"}).encode()
    get, calls = _getter(_listing(("r1.json", "Mon, 19 Oct 2026 12:57:50 GMT"),
                                  ("../evil.json", "Mon, 19 Oct 2026 12:57:50 GMT")),
                         {"r1.json": body})
    assert channel.pull(tmp_path, channel=URL, credential=CRED, get=get) == 1
    assert json.loads((tmp_path / "r1.json").read_text())["run_id"] == "r1"
    assert not (tmp_path.parent / "evil.json").exists()
    assert all("evil" not in c for c in calls)


def test_pull_downloads_again_only_what_changed(tmp_path):
    local = tmp_path / "r1.json"
    opened = {"run_id": "r1", "start": "2026-10-19T12:57:49+00:00", "end": None}
    local.write_text(json.dumps(opened))
    os.utime(local, (1_000_000_000, 1_760_000_000))  # 2025-10-09
    get, calls = _getter(_listing(("r1.json", "Thu, 09 Oct 2025 08:00:00 GMT")), {"r1.json": b"{}"})
    assert channel.pull(tmp_path, channel=URL, credential=CRED, get=get) == 0
    # Changed since: its closure, the one rewrite a pulled window may take (SEC5, V-20).
    closed = {**opened, "end": "2026-10-19T12:58:29+00:00"}
    get, calls = _getter(_listing(("r1.json", "Mon, 19 Oct 2026 12:58:30 GMT")),
                         {"r1.json": json.dumps(closed).encode()})
    assert channel.pull(tmp_path, channel=URL, credential=CRED, get=get) == 1
    assert json.loads(local.read_text())["end"] == closed["end"]


def test_the_watch_pulls_before_it_labels(monkeypatch):
    """M70: a watch on another host labels an exercise only once the channel's windows
    are in its directory."""
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    start = datetime.now(timezone.utc) - timedelta(minutes=2)

    def fake_pull(directory, **kw):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "r1.json").write_text(json.dumps({
            "run_id": "r1", "targets": [VM.lower()], "start": start.isoformat(), "end": None,
            "expires": (start + timedelta(hours=2)).isoformat()}))
        return 1

    monkeypatch.setattr(channel, "pull", fake_pull)
    assert exercise.source_of(VM, datetime.now(timezone.utc)) == ("exercise", "r1")


def test_pull_is_throttled_and_never_raises(monkeypatch, tmp_path):
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    calls = []

    def failing(directory, **kw):
        calls.append(1)
        raise RuntimeError("HTTP 403")

    monkeypatch.setattr(channel, "pull", failing)
    channel.pull_if_due(tmp_path, now=100.0)
    channel.pull_if_due(tmp_path, now=110.0)  # within PULL_EVERY_S
    channel.pull_if_due(tmp_path, now=140.0)
    assert len(calls) == 2


# ── the contract and the channel ─────────────────────────────────────────────

SUB = "sub-123"
BENCH = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor"
CONTAINER = (f"/subscriptions/{SUB}/resourceGroups/rg-orodruin/providers/Microsoft.Storage"
             "/storageAccounts/storodruin/blobServices/default/containers/exercises")
# SEC5 (V-29): reads on the group, writes on an enrolled VM and an experiment.
RIGHTS = [{"actions": list(orodruin.READ_ACTIONS)}]
ENROLLED = (f"{BENCH}/providers/Microsoft.Compute/virtualMachines/vm-1",
            f"{BENCH}/providers/Microsoft.Chaos/experiments/exp-1")


def _assignment(scope):
    return {"properties": {"scope": scope, "roleDefinitionId": "/r/blob-data-contributor"}}


def _assess(scope, channel_scope):
    return orodruin.assess_identity([*map(_assignment, ENROLLED), _assignment(scope)],
                                    lambda _: ["*"], RIGHTS, BENCH, sees_subscription=True,
                                    channel=channel_scope)


def test_the_channel_container_is_the_one_assignment_allowed_outside_the_bench():
    assert _assess(CONTAINER, orodruin.channel_scope({"EREGION_CHANNEL_SCOPE": CONTAINER})) == []
    other = CONTAINER.replace("/containers/exercises", "/containers/other")
    assert _assess(other, orodruin.channel_scope({"EREGION_CHANNEL_SCOPE": CONTAINER}))


@pytest.mark.parametrize("declared", [
    f"/subscriptions/{SUB}",
    f"/subscriptions/{SUB}/resourceGroups/rg-orodruin",
    CONTAINER.rsplit("/blobServices", 1)[0],  # the whole storage account
])
def test_a_declared_channel_wider_than_a_container_allows_nothing(declared):
    """M68: the declared scope is checked for its shape — a subscription declared as the
    channel must never make a subscription-wide assignment acceptable."""
    assert orodruin.channel_scope({"EREGION_CHANNEL_SCOPE": declared}) == ""
    missing = _assess(declared, orodruin.channel_scope({"EREGION_CHANNEL_SCOPE": declared}))
    assert [m["code"] for m in missing] == ["identity_outside_bench"]
