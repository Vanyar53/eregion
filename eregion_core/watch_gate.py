"""V1 (#214): Annatar and Gothmog do not act without Glorfindel.

Glorfindel is the product; the injectors exist to prove it (docs/design/console.md, §2). So
before every run — each run of a campaign too — and before any call to the cloud, an
injector reads the watch's heartbeat, from two places:

- the return channel (eregion_core/watch_channel.py, ``EREGION_WATCH_CHANNEL``), when it is
  set: the watch hosted on H0, seen from Orodruin;
- the local file the watch rewrites every minute and removes when it stops: its copy for the
  injectors, ``~/.glorfindel/injectors/watch_heartbeat`` (mounted as the injectors'
  ``~/.glorfindel``, SEC3), else ``~/.glorfindel/watch_heartbeat``.

The channel decides when it is set — the watch is hosted elsewhere, and a file on this host
says nothing of it; the local file otherwise. A heartbeat younger than
``watch_channel.FRESH_S`` (and not dated further ahead than ``CLOCK_SKEW_S``) is a live
watch. Else the run is refused, and the refusal says how old the last one is, or that there
was never one. Reading the channel is the only network call made before that answer.

SEC5 (N-03): a heartbeat also says which perimeter the watch watches — the subscription it
reads (``AZURE_SUBSCRIPTION_ID``), as a digest, never the id itself (nothing shown names the
subscription). The injector compares it with its own: a live watch of another subscription is
no watch of its targets, and a heartbeat that names no perimeter (a watch older than this
injector) is refused. The subscription rather than the host, because it is the one thing both
sides know of the same targets: the injector acts in its subscription, the watch reads it; a
host name gives the injector nothing to compare (Orodruin and H0 are two hosts, the local
containers two more). What this proves, and what not (docs/design/orodruin-contract.md): a
watch configured for this subscription wrote this file or blob less than 90 s ago — or
someone who can write there did. The digest binds, it does not authenticate (it is no
secret), and it does not prove that the watch's workspaces see the target.

The gate is read again before each action of a run (each step, the atomic's command, the
fault's start), not only at its start: a watch that dies mid-run stops the run there, and the
campaign with it. ``annatar clean`` goes through it too.

``--without-glorfindel`` runs anyway, for development — never in zone ``production`` (the
engine refuses it once the target's zone is read), and it is written to Orodruin's journal as
well as to the run's report (``metrics.without_glorfindel``, ``metrics.detection_note``); its
detection is not measured — never ``missed``, never a rule proposed for it; H0 accepts that
report (``analysis/campaign_schema.run_report_refusal``) and the console shows it apart from
``unknown``. A campaign run that way carries ``without_glorfindel: true`` in its manifest, is
resumed only the same way, and has no analysis report (``NO_CAMPAIGN_REPORT``).

The engines read through ``READERS``, which the tests swap (tests/unit/conftest.py) the way
they swap Orodruin's; Annatar's wait for a detection reads ``local_beat`` itself.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from eregion_core import watch_channel

FLAG = "--without-glorfindel"
NOT_MEASURED = "detection not measured, by choice"
LOCAL = "local file ~/.glorfindel/watch_heartbeat"
CHANNEL = "return channel"
SUBSCRIPTION_ENV = "AZURE_SUBSCRIPTION_ID"


@dataclass(frozen=True)
class Beat:
    """The last heartbeat in one place: ``at`` None when there is none, ``why`` says why;
    ``perimeter`` the digest of the subscription the watch reads, "" when it names none."""

    where: str
    at: datetime | None
    why: str = ""
    perimeter: str = ""


def perimeter(subscription: str | None = None) -> str:
    """The digest a heartbeat carries of a subscription (``AZURE_SUBSCRIPTION_ID`` by default):
    16 hex of the sha256 of its lower-cased id — "" without one. Never the id itself."""
    sub = os.environ.get(SUBSCRIPTION_ENV, "") if subscription is None else subscription
    sub = (sub or "").strip().lower()
    return hashlib.sha256(sub.encode()).hexdigest()[:16] if sub else ""


def beat_body(at: datetime, subscription: str | None = None) -> dict:
    """What a watch writes as its heartbeat for the injectors: when, and its perimeter."""
    return {"at": at.isoformat(), "perimeter": perimeter(subscription)}


def heartbeat_path() -> Path:
    """The injectors' copy when the watch wrote one here, else the watch's own file — which,
    in an injector's container, IS that copy (``~/.glorfindel/injectors`` mounted there)."""
    home = Path.home() / ".glorfindel"
    copy = home / "injectors" / "watch_heartbeat"
    return copy if copy.is_file() else home / "watch_heartbeat"


def _parse_beat(text: str) -> tuple[datetime | None, str, str]:
    """(when, perimeter, why) from a heartbeat file: the JSON the watch writes for the
    injectors, or a bare date (the watch's own file, or an older watch: no perimeter)."""
    if text.startswith("{"):
        try:
            body = json.loads(text)
        except ValueError:
            return None, "", f"not JSON: {text[:40]!r}"
        if not isinstance(body, dict):
            return None, "", "not a JSON object"
        at = watch_channel._when(body.get("at"))
        return at, str(body.get("perimeter") or ""), "" if at else "its 'at' is not a date"
    at = watch_channel._when(text)
    return at, "", "" if at else f"not a date: {text[:40]!r}"


def local_beat() -> Beat:
    """The heartbeat a watch on this host writes (glorfindel/cli.py, ``watch``)."""
    path = heartbeat_path()
    try:
        text = path.read_text().strip()
    except FileNotFoundError:
        return Beat(LOCAL, None, "no file: no watch ran here, or it stopped and removed it")
    except OSError as e:
        return Beat(LOCAL, None, f"unreadable: {e}")
    at, scope, why = _parse_beat(text)
    return Beat(LOCAL, at, why, scope)


def channel_beat() -> Beat | None:
    """The hosted watch's heartbeat through the return channel; None when it is not set."""
    if not watch_channel.channel_url():
        return None
    try:
        body = watch_channel.read_heartbeat()
    except Exception as e:  # unreadable is no watch — said, never raised
        if "HTTP 404" in str(e):
            return Beat(CHANNEL, None, "no heartbeat.json in the channel")
        return Beat(CHANNEL, None, f"unreadable: {e}")
    at = watch_channel._when(body.get("at"))
    return Beat(CHANNEL, at, "" if at else "its 'at' is not a date",
                str(body.get("perimeter") or ""))


# "own": the perimeter of this injector's targets — the digest of its subscription.
READERS = {"channel": channel_beat, "local": local_beat, "own": perimeter}


def fresh(beat: Beat | None, now: datetime) -> bool:
    """Younger than FRESH_S, never dated further ahead than the clocks' skew."""
    return beat is not None and watch_channel.recent(beat.at, now)


def _age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {secs:02d} s"
    return f"{secs} s"


def describe(beat: Beat, now: datetime) -> str:
    if beat.at is None:
        return f"{beat.where}: last heartbeat never ({beat.why})"
    at = f"{beat.at.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S} UTC"
    age = (now - beat.at).total_seconds()
    if age < 0:
        return (f"{beat.where}: last heartbeat dated {_age(-age)} in the future ({at}) — "
                "a clock is wrong")
    return f"{beat.where}: last heartbeat {_age(age)} ago ({at})"


NO_OWN_PERIMETER = (f"this injector names no subscription ({SUBSCRIPTION_ENV}): no watch can "
                    "be bound to its targets")


def unbound(beat: Beat, own: str) -> str:
    """Why this live heartbeat is no watch of this injector's targets — "" when it is."""
    if not own:
        return NO_OWN_PERIMETER
    if not beat.perimeter:
        return (f"{beat.where}: the heartbeat names no perimeter — a watch older than this "
                "injector (update Glorfindel)")
    if beat.perimeter != own:
        return (f"{beat.where}: the live watch watches another subscription than this "
                "injector's targets")
    return ""


def refusal(now: datetime | None = None) -> str:
    """Why no live Glorfindel watch of this injector's targets stands behind this run — ""
    when one does. The return channel decides when it is set (the watch is hosted elsewhere: a
    file on this host says nothing of it); the local file otherwise. Fresh first, then bound
    to the same subscription (SEC5, N-03)."""
    now = now or datetime.now(timezone.utc)
    beat = READERS["channel"]()
    if beat is None:
        beat = READERS["local"]()
    if not fresh(beat, now):
        return describe(beat, now)
    return unbound(beat, READERS.get("own", perimeter)())


# A campaign run --without-glorfindel: its runs measured no detection, so it has no report of
# the analysis (IA0), here or on H0, and never enters the index nor a comparison (D-2).
NO_CAMPAIGN_REPORT = "campaign without Glorfindel: no detection report, by choice"


def without_metrics(without_glorfindel: bool) -> dict:
    """What a run's report says of a run without Glorfindel — {} for a run with it."""
    if not without_glorfindel:
        return {}
    return {"without_glorfindel": True, "detection_note": NOT_MEASURED}
