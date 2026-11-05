"""SEC21b (#535): the watch's signed heartbeat says which detections it covers (``covers``: for each
window it knows, the sorted signal_id of every detection delivered for it, MAX_COVERED at most), and
a run reads back, after it, every one it covers before it concludes a silence to a miss — a
detection missing is ``unknown``, said in the console, Orodruin's journal and the run's report;
a heartbeat without ``covers`` (a watch older than this lot) or that leaves the run out proves no
miss; the local channel of verdicts (SEC18) unchanged. M3740–M3749, M3760–M3767.
"""
WCH = "eregion_core/watch_channel.py"
ENG = "annatar/runner/engine.py"
_TESTS = "tests/unit/test_beat_covers.py"

MUTANTS = [
    ("M3740", "the watch's heartbeat says nothing of what it covers: every miss unknown (SEC21b)", WCH,
     "            COVERS: self._covers(known, self._sent),\n", ""),
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
    # After the review of 9dbad1d6: what was delivered at an earlier tick, the window's whole life,
    # each window its own, the arbitrage with SEC21 in the settling itself, a budget for them all.
    ("M3760", "the heartbeat covers only what was delivered at its own tick: a detection removed after an earlier beat is a miss (SEC21b)",
     WCH,
     ("        waiting = 0\n",
      '                    self._sent.add((run, r["signal_id"]))\n',
      "            COVERS: self._covers(known, self._sent),\n"),
     ("        waiting = 0\n        fresh = set()\n",
      '                    self._sent.add((run, r["signal_id"]))\n                    fresh.add((run, r["signal_id"]))\n',
      "            COVERS: self._covers(known, fresh),\n")),
    ("M3761", "a detection at a window's start forgotten at its last moment: a removal then is a miss (SEC21b)", WCH,
     "                           and (now - at).total_seconds() <= KEEP_S]\n",
     "                           and (now - at).total_seconds() < KEEP_S]\n"),
    ("M3762", "a missing detection left to the caller when some were refused: the settling says a timeout (SEC21b)", ENG,
     "                    if why:\n                        # Unknown here",
     "                    if why and not self._detection_refused_total:\n                        # Unknown here"),
    ("M3763", "each window lists every window's detections: one removed from a run covered by another's is never seen (SEC21b)",
     WCH, "            ids = sorted(s for r, s in sent if r == run)\n", "            ids = sorted({s for r, s in sent})\n"),
    ("M3764", "covers without a budget: past ~64 full windows the heartbeat outgrows what the injectors read, every run refused (SEC21b, V1)",
     WCH, "        while total > MAX_COVERS_BYTES:\n", "        while False:\n"),
    ("M3765", "beyond the budget the lightest windows left out first: more runs unknown than needed (SEC21b)", WCH,
     "            heaviest = max(sorted(out), key=weight)\n", "            heaviest = min(sorted(out), key=weight)\n"),
    ("M3766", "the windows left out of covers never said in the watch's log (SEC21b)", WCH,
     "            if left_out:\n                print(", "            if False:\n                print("),
    ("M3767", "a detection both refused and missing: the refusal (SEC21) no longer said in the run's reason (SEC21b)", ENG,
     '                            why = f"{self._refused_why()}; {why}"\n', "                            pass\n"),
]
TESTS = {f"M{n}": _TESTS for n in [*range(3740, 3750), *range(3760, 3768)]}
TESTS["M3747"] = f"{_TESTS} tests/unit/test_local_verdicts.py"
