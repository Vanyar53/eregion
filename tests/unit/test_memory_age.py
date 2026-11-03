"""SEC17 (#451, V-12): the memory of past cycles has an age.

- A cycle is dated when it is stored, by the host's clock — never by what the cycle carries;
- the search gives only cycles stored within the bound (90 days by default), real ones only
  (SEC4a); a real cycle stored before cycles were dated is dated by the B2 floor (2026-10-16,
  when a cycle first could be `real`): an age at least its true one, never today's — given while
  that floor is within the bound, left out after (decision of Jonathan, 03/11);
- nothing is erased, and `glorfindel report` (and `memory-stats`) say how many real cycles the
  bound leaves out;
- the bound is a config key read strictly (`memory.max_age_days`: a finite number of days,
  positive, at most ten years), the watch's agent takes it.

No Azure call, no model call. Mutants M3200–M3206, M3260–M3261 (scripts/mutation_check.py) are
measured here.
"""
from __future__ import annotations

import json
import math
import textwrap
import time

import pytest
from click.testing import CliRunner

import glorfindel.config as config
import glorfindel.memory as memory
from glorfindel import agent
from glorfindel.config import ConfigError, load_glorfindel_config
from glorfindel.memory import CycleMemory

DAY = 86400
NOW = 1_800_000_000.0          # 2027-01-15: the B2 floor is past the default 90 days
B2 = memory.B2_FLOOR
SIG = {"ttp": "T1486", "severity": "high", "resource_type": "vm", "event": "detection"}


def _cycle(signal_id: str, source: str = "real", **over) -> dict:
    return {"signal_id": signal_id, "run_id": "r", "ttp": "T1486", "severity": "high",
            "resource_type": "vm", "event": "detection", "reasoning": signal_id,
            "action": "isolate_vm", "outcome": "x", "source": source, "confidence": 0.9, **over}


class _Clock:
    def __init__(self, at: float = NOW):
        self.at = at

    def __call__(self) -> float:
        return self.at


def _memory(tmp_path, clock, days=None) -> CycleMemory:
    return CycleMemory(path=tmp_path / "cycles", max_age_days=days, clock=clock)


def _stored_days_ago(mem: CycleMemory, clock: _Clock, signal_id: str, days: float, **over) -> None:
    now = clock.at
    clock.at = now - days * DAY
    mem.store(_cycle(signal_id, **over))
    clock.at = now


def _legacy(mem: CycleMemory, signal_id: str = "legacy") -> None:
    """A real cycle as stored before SEC17: no date."""
    mem._collection.add(ids=[f"cycle-{signal_id}"], documents=[f"TTP: T1486 | {signal_id}"],
                        metadatas=[{"source": "real", "signal_id": signal_id, "action": "isolate_vm",
                                    "run_id": "r", "ttp": "T1486"}])


# ── The search: a bounded age ────────────────────────────────────────────────────────────

def test_a_cycle_older_than_the_bound_is_no_precedent(tmp_path):
    """M3200: a year-old cycle weighed as much as yesterday's."""
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    _stored_days_ago(mem, clock, "a-year-ago", 365)
    _stored_days_ago(mem, clock, "last-quarter", 91)
    _stored_days_ago(mem, clock, "yesterday", 1)
    found = mem.retrieve_similar(SIG, n=3)
    assert [c["signal_id"] for c in found] == ["yesterday"]
    assert mem.count() == 3                      # nothing erased


def test_the_bound_is_90_days_by_default_and_the_one_given(tmp_path):
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    assert mem.max_age_days == 90
    _stored_days_ago(mem, clock, "day-89", 89)
    _stored_days_ago(mem, clock, "day-91", 91)
    assert [c["signal_id"] for c in mem.retrieve_similar(SIG, n=3)] == ["day-89"]
    short = _memory(tmp_path, clock, days=30)
    assert short.retrieve_similar(SIG, n=3) == []
    long = _memory(tmp_path, clock, days=120)
    assert sorted(c["signal_id"] for c in long.retrieve_similar(SIG, n=3)) == ["day-89", "day-91"]


def test_a_cycle_ages_out_as_the_clock_moves(tmp_path):
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    mem.store(_cycle("today"))
    assert [c["signal_id"] for c in mem.retrieve_similar(SIG)] == ["today"]
    clock.at += 91 * DAY
    assert mem.retrieve_similar(SIG) == []


def test_a_cycle_is_dated_by_the_host_never_by_what_it_carries(tmp_path):
    """M3201: a cycle that says when it was stored (or a signal's timestamp) stays young for ever."""
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    _stored_days_ago(mem, clock, "carries-its-date", 200, stored_at=int(NOW), timestamp="2099-01-01T00:00:00Z")
    assert mem.retrieve_similar(SIG) == []
    meta = mem._collection.get(include=["metadatas"])["metadatas"][0]
    assert meta["stored_at"] == int(NOW - 200 * DAY)


def test_the_b2_floor_is_the_day_a_cycle_first_could_be_real():
    """B2 (d4e51fa, 2026-10-16 14:30 +0200) first wrote `source`; midnight UTC that day."""
    from datetime import datetime, timezone
    assert datetime.fromtimestamp(B2, timezone.utc) == datetime(2026, 10, 16, tzinfo=timezone.utc)


def test_a_cycle_stored_before_cycles_were_dated_takes_the_b2_floor(tmp_path):
    """M3260, M3261: a real cycle with no date of its own is dated by the B2 floor — given while
    the floor is within the bound, left out after; never dated today, never left out at once."""
    clock = _Clock(B2 + 10 * DAY)
    mem = _memory(tmp_path, clock)
    _legacy(mem)
    mem.store(_cycle("dated"))
    assert sorted(c["signal_id"] for c in mem.retrieve_similar(SIG, n=3)) == ["dated", "legacy"]
    clock.at = B2 + 91 * DAY                     # the floor past 90 days: the cycle aged out
    assert [c["signal_id"] for c in mem.retrieve_similar(SIG, n=3)] == ["dated"]
    assert mem.count() == 2                      # nothing erased
    assert sorted(c["signal_id"] for c in _memory(tmp_path, clock, days=120).retrieve_similar(SIG, n=3)) \
        == ["dated", "legacy"]


def test_the_b2_floor_never_makes_a_dated_cycle_younger_or_older(tmp_path):
    """An old dated cycle stays out while undated ones are read; a recent one stays in."""
    clock = _Clock(B2 + 30 * DAY)
    mem = _memory(tmp_path, clock, days=40)
    _legacy(mem)
    _stored_days_ago(mem, clock, "two-months-ago", 60)
    _stored_days_ago(mem, clock, "yesterday", 1)
    assert sorted(c["signal_id"] for c in mem.retrieve_similar(SIG, n=3)) == ["legacy", "yesterday"]
    short = _memory(tmp_path, clock, days=20)    # the floor (30 days ago) past 20 days
    assert [c["signal_id"] for c in short.retrieve_similar(SIG, n=3)] == ["yesterday"]


def test_exercise_cycles_stay_out_whatever_their_age(tmp_path):
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    mem.store(_cycle("drill", source="exercise"))
    mem.store(_cycle("unknown", source=""))
    mem.store(_cycle("real"))
    assert [c["source"] for c in mem.retrieve_similar(SIG, n=3)] == ["real"]


def test_load_context_gives_the_model_cycles_of_a_bounded_age_only(tmp_path):
    from glorfindel.incidents import IncidentRegistry
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    _stored_days_ago(mem, clock, "old", 120)
    _stored_days_ago(mem, clock, "recent", 3)
    _legacy(mem)
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-age"
    signal = {**SIG, "signal_id": "s-now", "resource_id": rid, "context": {}, "raw_signal": {}}
    state = {"signal": signal, "past_cycles": [], "incident": None}
    out = agent.load_context(state, memory=mem, incidents=IncidentRegistry(path=tmp_path / "inc.jsonl"))
    assert [c["signal_id"] for c in out["past_cycles"]] == ["recent"]


# ── What is left out, counted and said ──────────────────────────────────────────────────

def test_the_census_counts_what_the_bound_leaves_out(tmp_path):
    """M3204: an undated cycle not counted apart, as dated by the B2 floor."""
    clock = _Clock()
    mem = _memory(tmp_path, clock)
    _stored_days_ago(mem, clock, "old-1", 100)
    _stored_days_ago(mem, clock, "old-2", 400)
    _stored_days_ago(mem, clock, "recent", 2)
    _stored_days_ago(mem, clock, "drill", 2, source="exercise")
    _legacy(mem)
    assert mem.age_census() == {"max_age_days": 90.0, "real": 4, "within": 1, "too_old": 3,
                                "b2_dated": 1, "b2_floor": "2026-10-16"}
    early = _memory(tmp_path / "early", _Clock(B2 + 5 * DAY))
    _legacy(early)
    assert early.age_census() == {"max_age_days": 90.0, "real": 1, "within": 1, "too_old": 0,
                                  "b2_dated": 1, "b2_floor": "2026-10-16"}


def test_the_census_makes_no_memory_where_there_is_none(tmp_path):
    """M3206: `glorfindel report` on a host without a memory created one."""
    where = tmp_path / "never-made"
    assert memory.age_census(path=where) == {"max_age_days": 90.0, "absent": True}
    assert not where.exists()


def test_a_memory_that_cannot_be_read_is_said_never_empty(tmp_path, monkeypatch):
    (tmp_path / "cycles").mkdir()

    def broken(*a, **k):
        raise RuntimeError("database disk image is malformed")
    monkeypatch.setattr(memory, "CycleMemory", broken)
    got = memory.age_census(path=tmp_path / "cycles")
    assert got["error"].startswith("RuntimeError: database disk image") and "real" not in got


def _report(monkeypatch, tmp_path, *args):
    from glorfindel.cli import cli
    return CliRunner().invoke(cli, ["report", "--since", "all", *args])


def test_the_report_says_the_cycles_left_out_for_their_age(tmp_path, monkeypatch):
    """M3205: the report silent on what the bound leaves out."""
    clock = _Clock(time.time())          # the report counts by the real clock
    mem = CycleMemory(path=memory._DEFAULT_PATH, clock=clock)
    _stored_days_ago(mem, clock, "old", 100)
    _stored_days_ago(mem, clock, "recent", 2)
    _legacy(mem)
    res = _report(monkeypatch, tmp_path, "--json")
    assert res.exit_code == 0, res.output
    b2_within = B2 >= time.time() - 90 * DAY     # until 2027-01-14
    assert json.loads(res.output)["memory"] == {"max_age_days": 90.0, "real": 3, "within": 1 + b2_within,
                                                "too_old": 2 - b2_within, "b2_dated": 1,
                                                "b2_floor": "2026-10-16"}
    res = _report(monkeypatch, tmp_path)
    assert res.exit_code == 0, res.output
    said = " ".join(res.output.split())
    assert (f"Memory: 3 real cycle(s), {1 + b2_within} within 90 days — {2 - b2_within} older left out "
            "of the search (kept, never erased)") in said
    assert "of them 1 dated by the B2 floor (2026-10-16: stored before SEC17" in said


def test_the_report_on_a_host_without_memory_says_so(tmp_path, monkeypatch):
    res = _report(monkeypatch, tmp_path)
    assert res.exit_code == 0, res.output
    assert "Memory: none yet (age bound 90 days)" in res.output
    assert not memory._DEFAULT_PATH.exists()


# ── The bound, a config key read strictly ───────────────────────────────────────────────

def _config(tmp_path, text: str):
    p = tmp_path / "glorfindel-config.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def test_the_bound_is_read_from_the_config(tmp_path):
    assert load_glorfindel_config(_config(tmp_path, "memory:\n  max_age_days: 30\n")).memory.max_age_days == 30
    assert load_glorfindel_config(_config(tmp_path, "memory:\n  max_age_days: 0.5\n")).memory.max_age_days == 0.5
    assert load_glorfindel_config(_config(tmp_path, "never_block: []\n")).memory.max_age_days == 90


@pytest.mark.parametrize("value, said", [
    ('"30"', "un nombre de jours est attendu"),
    ("true", "un nombre de jours est attendu"),
    ("30d", "un nombre de jours est attendu"),
    ("0", "entre 0 (exclu) et 3650"),
    ("-5", "entre 0 (exclu) et 3650"),
    (".inf", "entre 0 (exclu) et 3650"),
    (".nan", "entre 0 (exclu) et 3650"),
    ("3651", "entre 0 (exclu) et 3650"),
    ("1.0e+9", "entre 0 (exclu) et 3650"),
])
def test_a_bound_that_is_not_a_finite_bounded_number_of_days_refuses_the_file(tmp_path, value, said):
    """M3203: an infinite or huge bound made every cycle young again."""
    with pytest.raises(ConfigError) as e:
        load_glorfindel_config(_config(tmp_path, f"memory:\n  max_age_days: {value}\n"))
    assert "memory.max_age_days" in str(e.value) and said in str(e.value)


def test_an_unknown_key_of_the_memory_refuses_the_file(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_glorfindel_config(_config(tmp_path, "memory:\n  max_age: 30\n"))
    assert "memory.max_age" in str(e.value) and "max_age_days" in str(e.value)


@pytest.mark.parametrize("days", [0, -1, math.inf, math.nan, 3651, True, "90"])
def test_the_memory_refuses_a_bound_it_is_given_badly(tmp_path, days):
    with pytest.raises(ValueError):
        CycleMemory(path=tmp_path / "cycles", max_age_days=days)


def test_the_watch_s_agent_takes_the_config_s_bound(tmp_path, monkeypatch):
    """M3202: the agent left the bound of the config unread — always 90 days."""
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [_config(tmp_path, "memory:\n  max_age_days: 7\n")])
    a = agent.GlorfindelAgent(memory_path=str(tmp_path / "cycles"), dry_run=True, readiness_gate=False)
    assert a.memory.max_age_days == 7


def test_a_config_the_watch_refuses_leaves_the_default_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [_config(tmp_path, "memory:\n  max_age_days: forever\n")])
    assert config.memory_max_age_days() == 90
