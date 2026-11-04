"""SEC21 (#530): the detections of the return channel signed by the watch's key, under their own
domain, verified by the injectors with the key they pin — never counted for « seen » when they are
not the watch's, for this run and this signal; said in the console, Orodruin's journal and the
run's report; the heartbeat that proves a miss verified by that key too. M3700–M3720.
"""
WKEY = "eregion_core/watch_key.py"
WCH = "eregion_core/watch_channel.py"
ENG = "annatar/runner/engine.py"
REPORT = "annatar/runner/report.py"
_TESTS = "tests/unit/test_signed_detections.py"

MUTANTS = [
    ("M3700", "the watch publishes its detections unsigned: no run counts them (SEC21)", WCH,
     '                                self._signed_detection({**r, "exercise_run": run}))\n',
     '                                {**r, "exercise_run": run})\n'),
    ("M3701", "every detection of the channel counted, whatever its signature (SEC21)", WCH,
     "        if not why:\n            kept.append(record)\n",
     "        if True:\n            kept.append(record)\n"),
    ("M3702", "the watch signs its detections under the heartbeat's domain (SEC21)", WKEY,
     '    out["sig"] = signer.sign(DOMAIN_DETECTION, out)\n',
     '    out["sig"] = signer.sign(DOMAIN_BEAT, out)\n'),
    ("M3703", "a detection signed and checked under the heartbeat's domain: a heartbeat's signature reads as one (SEC21)",
     WKEY,
     ('    out["sig"] = signer.sign(DOMAIN_DETECTION, out)\n',
      "                                                       message(DOMAIN_DETECTION, body))\n"),
     ('    out["sig"] = signer.sign(DOMAIN_BEAT, out)\n',
      "                                                       message(DOMAIN_BEAT, body))\n")),
    ("M3704", "an unsigned detection believed (SEC21)", WKEY,
     "    if sig is None:\n        return UNSIGNED_DETECTION\n",
     '    if sig is None:\n        return ""\n'),
    ("M3705", "a detection's signer never compared with the key pinned (SEC21)", WKEY,
     '    if body.get("key") != want:\n', "    if False:\n"),
    ("M3706", "a detection's signature never checked: the fingerprint it claims believed (SEC21)", WKEY,
     "        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(sig),\n"
     "                                                       message(DOMAIN_DETECTION, body))\n",
     "        pass\n"),
    ("M3707", "a detection copied from another run counts in this one (SEC21)", WKEY,
     '    if body.get("exercise_run") != run_id:\n', "    if False:\n"),
    ("M3708", "a detection copied under another signal's name counts again (SEC21)", WKEY,
     '    if body.get("signal_id") != signal_id:\n', "    if False:\n"),
    ("M3709", "no key pinned: every detection believed (SEC21)", WCH,
     "        why = no_key if key is None else watch_key.detection_refusal(\n",
     '        why = "" if key is None else watch_key.detection_refusal(\n'),
    ("M3710", "the refusals of one read unbounded: a writer of the channel floods the run (SEC21)", WCH,
     "        elif len(refused) < MAX_REFUSED:\n", "        else:\n"),
    ("M3711", "the run counts the channel's detections as written, never vouched (SEC21)", ENG,
     "        found, refused = watch_channel.vouched_detections(run_id)\n",
     "        found, refused = watch_channel.read_detections(run_id), []\n"),
    ("M3712", "a run whose detections were all refused concludes to a miss: a rule proposed for it (SEC21)", ENG,
     '            if result_event == "detection_timeout" and self._detection_refused:\n',
     "            if False:\n"),
    ("M3713", "a detection refused never written in Orodruin's journal (SEC21)", ENG,
     '                    self._session.declare("detection_refused", why)\n', "                    pass\n"),
    ("M3714", "a detection refused absent from the atomic run's report (SEC21)", ENG,
     "        if self._detection_refused:   # SEC21: never counted, said in the atomic run's report too\n",
     "        if False:\n"),
    ("M3715", "a detection refused absent from the local-script run's report (SEC21)", ENG,
     "        if self._detection_refused:   # SEC21: never counted, said in the report\n",
     "        if False:\n"),
    ("M3716", "a detection refused said again at every read: the journal flooded (SEC21)", ENG,
     "            if why in self._detection_refused:\n                continue\n", ""),
    ("M3717", "a watch without its key says each detection unsigned, never once (SEC21)", WCH,
     "            if why != self._unsigned_detection:\n", "            if True:\n"),
    ("M3718", "the local channel of verdicts asks for the watch's key it never uses (SEC21, SEC18)", WCH,
     "        if self.SIGNS is False:      # the local channel of verdicts: its exact fields (SEC18)\n",
     "        if False:\n"),
    ("M3719", "Annatar's report never shows what the channel refused (SEC21)", REPORT,
     "        if isinstance(refused, list) and refused:   # SEC21: never counted, said\n",
     "        if False:\n"),
    # After the coordinator's review: the heartbeat that proves a miss, verified as the gate's is.
    ("M3720", "a heartbeat unsigned, of another key or replayed proves a miss: a rule proposed for a silence no watch vouched for (SEC21)",
     ENG, "                why = why or watch_gate.miss_proof(heartbeat)\n", "                why = why\n"),
]
TESTS = {f"M{n}": _TESTS for n in range(3700, 3721)}
