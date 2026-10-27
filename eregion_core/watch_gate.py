"""V1 (#214): Annatar and Gothmog do not act without Glorfindel.

Glorfindel is the product; the injectors exist to prove it (docs/design/console.md, §2). So
before every run — each run of a campaign too — and before any call to the cloud, an
injector reads the watch's heartbeat, from two places:

- the return channel (eregion_core/watch_channel.py, ``EREGION_WATCH_CHANNEL``), when it is
  set: the watch hosted on H0, seen from Orodruin;
- the local file ``~/.glorfindel/watch_heartbeat``, which a watch on this host rewrites every
  minute and removes when it stops.

Either one recent enough (``watch_channel.FRESH_S``) is a live watch. Neither: the run is
refused, and the refusal says how old the last heartbeat is in each place, or that there
was never one. Reading the channel is the only network call made before that answer.

``--without-glorfindel`` runs anyway, for development. The run's report says so
(``metrics.without_glorfindel``, ``metrics.detection_note``); its detection is not measured
— never ``missed``, never a rule proposed for it; H0 accepts that report
(``analysis/campaign_schema.run_report_refusal``) and the console shows it apart from
``unknown``.

The engines read through ``READERS``, which the tests swap (tests/unit/conftest.py) the way
they swap Orodruin's; Annatar's wait for a detection reads ``local_beat`` itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from eregion_core import watch_channel

FLAG = "--without-glorfindel"
NOT_MEASURED = "detection not measured, by choice"
LOCAL = "local file ~/.glorfindel/watch_heartbeat"
CHANNEL = "return channel"


@dataclass(frozen=True)
class Beat:
    """The last heartbeat in one place: ``at`` None when there is none, ``why`` says why."""

    where: str
    at: datetime | None
    why: str = ""


def heartbeat_path() -> Path:
    return Path.home() / ".glorfindel" / "watch_heartbeat"


def local_beat() -> Beat:
    """The heartbeat a watch on this host writes (glorfindel/cli.py, ``watch``)."""
    path = heartbeat_path()
    try:
        text = path.read_text().strip()
    except FileNotFoundError:
        return Beat(LOCAL, None, "no file: no watch ran here, or it stopped and removed it")
    except OSError as e:
        return Beat(LOCAL, None, f"unreadable: {e}")
    at = watch_channel._when(text)
    return Beat(LOCAL, at, "" if at else f"not a date: {text[:40]!r}")


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
    return Beat(CHANNEL, at, "" if at else "its 'at' is not a date")


READERS = {"channel": channel_beat, "local": local_beat}


def fresh(beat: Beat | None, now: datetime) -> bool:
    return (beat is not None and beat.at is not None
            and (now - beat.at).total_seconds() < watch_channel.FRESH_S)


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
    return (f"{beat.where}: last heartbeat {_age((now - beat.at).total_seconds())} ago "
            f"({beat.at.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S} UTC)")


def refusal(now: datetime | None = None) -> str:
    """Why no live Glorfindel watch stands behind this run — "" when one does."""
    now = now or datetime.now(timezone.utc)
    beats = [b for b in (READERS["channel"](), READERS["local"]()) if b is not None]
    if any(fresh(b, now) for b in beats):
        return ""
    return "; ".join(describe(b, now) for b in beats)


def without_metrics(without_glorfindel: bool) -> dict:
    """What a run's report says of a run without Glorfindel — {} for a run with it."""
    if not without_glorfindel:
        return {}
    return {"without_glorfindel": True, "detection_note": NOT_MEASURED}
