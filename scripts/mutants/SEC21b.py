"""SEC21b (#535): the watch's signed heartbeat says which detections it covers (``covers``: for each
window it knows, the sorted signal_id of every detection delivered for it, MAX_COVERED at most), and
a run reads back, after it, every one it covers before it concludes a silence to a miss — a
detection missing is ``unknown``, said in the console, Orodruin's journal and the run's report;
a heartbeat without ``covers`` (a watch older than this lot) or that leaves the run out proves no
miss; the local channel of verdicts (SEC18) unchanged. M3740–M3749.
"""
WCH = "eregion_core/watch_channel.py"
ENG = "annatar/runner/engine.py"
_TESTS = "tests/unit/test_beat_covers.py"

MUTANTS = [
    ("M3740", "the watch's heartbeat says nothing of what it covers: every miss unknown (SEC21b)", WCH,
     "            COVERS: self._covers(known),\n", ""),
    ("M3741", "a window beyond MAX_COVERED listed whole: the heartbeat grows without bound (SEC21b)", WCH,
     "            if len(ids) <= MAX_COVERED:\n", "            if True:\n"),
    ("M3742", "the run never compares what it reads with what the heartbeat covers: a detection removed is a miss (SEC21b)",
     ENG, "                        why = self._covered(heartbeat, run_id, found)\n", '                        why = ""\n'),
    ("M3743", "a detection delivered after the heartbeat read as missing: a true silence unknown (SEC21b)", WCH,
     "    missing = sorted(set(listed) - read)\n", "    missing = sorted(set(listed) ^ read)\n"),
    ("M3744", "a heartbeat without covers (a watch older than this lot) proves a miss (SEC21b)", WCH,
     "    if covers is None:\n        return NOT_COVERING, [], 0\n", '    if covers is None:\n        return "", [], 0\n'),
    ("M3745", "a run the heartbeat leaves out (beyond MAX_COVERED) read as one with no detection: a miss (SEC21b)", WCH,
     "    listed = covers.get(run_id)\n", "    listed = covers.get(run_id, [])\n"),
    ("M3746", "the detections read before the heartbeat: one delivered in between reads as missing (SEC21b)", ENG,
     ("                heartbeat = watch_channel.read_heartbeat()\n",
      "                    found = self._vouched(run_id)\n"),
     ("                found = self._vouched(run_id)\n                heartbeat = watch_channel.read_heartbeat()\n",
      "                    pass\n")),
    ("M3747", "the local channel of verdicts judged by covers it never holds: every local miss unknown (SEC21b, SEC18)",
     ENG, "                    if watch_channel.source() == watch_channel.STORAGE:\n", "                    if True:\n"),
    ("M3748", "a detection missing never written in Orodruin's journal (SEC21b)", ENG,
     '                    self._session.declare("detection_missing", f"{name}: covered by the watch\'s heartbeat, absent")\n',
     "                    pass\n"),
    ("M3749", "a detection missing absent from the run's report (SEC21b)", ENG,
     '        if self._detection_missing:\n            metrics["detection_missing"]',
     '        if False:\n            metrics["detection_missing"]'),
]
TESTS = {f"M{n}": _TESTS for n in range(3740, 3750)}
TESTS["M3747"] = f"{_TESTS} tests/unit/test_local_verdicts.py"
