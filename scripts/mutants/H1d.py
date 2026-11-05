"""H1d (#549): the health of the CD of H0 judges the watch's beat by its identity (inode, mtime in
ns), taken once the switch has returned — never by two readings of the wall clock. M3910–M3914,
measured by tests/unit/test_host_cd.py.
"""
CD = "infra/glorfindel-host/cd/eregion_cd.py"
_TESTS = "tests/unit/test_host_cd.py::"

MUTANTS = [
    # The identity never compared at all: M1019 (H1), its anchor moved here by H1d.
    ("M3910", "the beat known by its time alone: two beats at the same nanosecond (a clock set back) "
     "taken for one (H1d)", CD,
     "    return (st.st_ino, st.st_mtime_ns)\n", "    return (0, st.st_mtime_ns)\n"),
    ("M3911", "the beat taken before the switch: the old watch's last, left by a SIGKILL, passes for "
     "the new one's (H1d)", CD,
     "        activate(tag)\n        seen = beat()               # the switch returned: the watch before has stopped (H1d)\n",
     "        seen = beat()\n        activate(tag)\n"),
    ("M3912", "the way back's beat taken before its switch: the left release's last beat passes for "
     "the old one's (H1d)", CD,
     "    try:\n        activate(ref)\n    except Unhealthy as e:\n        return str(e)\n"
     "    seen = beat()                   # the release left has stopped: its last beat is no health (H1d)\n",
     "    seen = beat()\n    try:\n        activate(ref)\n    except Unhealthy as e:\n        return str(e)\n"),
    ("M3913", "a pass taken up asks no beat of the watch that runs: whatever beat is there passes (H1d)", CD,
     "    seen = beat()\n    why, proof = health(tag, float(cut.get(\"at\") or 0), seen,",
     "    seen = None\n    why, proof = health(tag, float(cut.get(\"at\") or 0), seen,"),
    ("M3914", "the beat's mtime compared again with a time.time() from before the switch: a clock set "
     "back sends H0 back (H1d)", CD,
     "        why = health_once(ref, seen)\n",
     "        why = health_once(ref, seen) or (\"la watch n'a pas battu depuis la bascule\"\n"
     "                                         if HEARTBEAT.stat().st_mtime < since else \"\")\n"),
]
TESTS = {
    "M3910": f"{_TESTS}test_a_beat_is_another_file_whatever_its_time",
    "M3911": f"{_TESTS}test_the_old_watchs_last_beat_is_no_health_for_a_watch_that_never_beats",
    "M3912": f"{_TESTS}test_the_way_back_is_not_judged_on_the_left_releases_last_beat",
    "M3913": f"{_TESTS}test_a_pass_taken_up_asks_a_beat_of_the_watch_that_runs",
    "M3914": f"{_TESTS}test_a_wall_clock_set_back_during_the_health_sends_nothing_back",
}
