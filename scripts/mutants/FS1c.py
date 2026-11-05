"""FS1c (#571): the signed action queue, asynchronous — a request followed once deposited (its
receipt, not taken, a receipt of another key told apart), the watch's status that the write
buttons follow, what remains synchronous bounded (the console's gestures' own executor), the gesture
noted once, the card born of the queue bearing its request, the bot that says the receipt and no
longer writes runs/console, the keys drawn before the flag and held together by host_env.py --check.
M4040–M4069, measured by tests/unit/test_action_queue_async.py (and test_runs_mounts.py)."""
AQ = "eregion_core/action_queue.py"
API = "eregion_console/api.py"
QW = "glorfindel/queue_watch.py"
APPROVAL = "glorfindel/approval.py"
BOTF = "glorfindel/bot.py"
HOST = "infra/glorfindel-host/host_env.py"
_ASYNC = "tests/unit/test_action_queue_async.py"
_MOUNTS = "tests/unit/test_runs_mounts.py"

MUTANTS = [
    # ── A request followed, never awaited ──────────────────────────────────────────
    ("M4040", "a receipt of another key said as no receipt: « not taken », the fingerprints never said (FS1c)",
     AQ, '    if why:\n        return {"request": request_id, "state": "untrusted"',
     '    if False:\n        return {"request": request_id, "state": "untrusted"'),
    ("M4041", "ask says « not taken » of a receipt of another key (FS1c)", AQ,
     '        return {"error": why or NOT_TAKEN, "request": rid}\n',
     '        return {"error": NOT_TAKEN, "request": rid}\n'),
    ("M4042", "a request the watch never took followed for ever: never said not taken (FS1c)", AQ,
     "    if (now - issued).total_seconds() > TAKE_S:\n", "    if False:\n"),
    ("M4043", "a request withdrawn twice taken for two: the gesture noted at each read (FS1c)", AQ,
     "    except FileNotFoundError:\n        return False\n    return True\n",
     "    except FileNotFoundError:\n        return True\n    return True\n"),
    # ── The posture: the write buttons follow the watch's signed status ────────────
    ("M4044", "a status the watch stopped writing taken as fresh: the buttons open on a stopped watch (FS1c)",
     AQ, "    if age > STATUS_STALE_S:\n", "    if False:\n"),
    ("M4045", "a read-only watch's status opens the buttons (FS1c)", AQ,
     '    if doc.get("posture") != "write":\n', "    if False:\n"),
    ("M4046", "a status that pins no key for the console opens its buttons (FS1c)", AQ,
     "    if not pinned:\n        return {\"ok\": False, \"why\": f\"the watch pins no key",
     "    if False:\n        return {\"ok\": False, \"why\": f\"the watch pins no key"),
    ("M4047", "a status that pins another key than the console's opens its buttons (FS1c)", AQ,
     "    if pinned != own:\n", "    if False:\n"),
    ("M4048", "a status of another key believed, the watch's key pinned (FS1c)", AQ,
     '    if watch_public is not None:\n        why = watch_refusal(doc, "status", watch_public)\n',
     '    if False:\n        why = watch_refusal(doc, "status", watch_public)\n'),
    ("M4049", "no status at all opens the buttons: a console with no watch writes nothing, said nothing (FS1c)",
     AQ, '        return {"ok": False, "why": why or (f"the watch publishes no status',
     '        return {"ok": True, "why": why or (f"the watch publishes no status'),
    ("M4050", "the page's state says the console's own posture, never the watch's (FS1c)", API,
     '    return {"on": True, **action_requests.posture(root=_RUNS)}\n',
     '    return {"on": True, "ok": True, "why": ""}\n'),
    # ── What remains synchronous, bounded ──────────────────────────────────────────
    ("M4051", "the console's gestures never bounded: a burst of clicks takes the server's threads (FS1c)", API,
     "    if not _GESTURE_SLOTS.acquire(blocking=False):\n        raise GesturesBusy()\n", ""),
    ("M4052", "a gesture's slot never given back: the console refuses every gesture after four (FS1c)", API,
     "        _HOLDING.reset(token)\n        _GESTURE_SLOTS.release()\n", "        _HOLDING.reset(token)\n"),
    ("M4053", "the deposit off the gestures' executor: past the slots, a request written all the same (FS1c)",
     API, "    asked = await _gesture(action_requests.deposit, verb, resource_id,",
     "    asked = await asyncio.to_thread(action_requests.deposit, verb, resource_id,"),
    ("M4054", "a release's direct call off the gestures' executor (FS1c)", API,
     '    result = await _gesture(\n        subprocess.run,\n        [_bin(), "release", resource_id, "--yes"],',
     '    result = await asyncio.to_thread(\n        subprocess.run,\n        [_bin(), "release", resource_id, "--yes"],'),
    ("M4055", "an approval's isolation off the gestures' executor (FS1c)", API,
     "            result = await _gesture(connector.isolate_vm, resource_id)\n",
     "            result = await asyncio.to_thread(connector.isolate_vm, resource_id)\n"),
    ("M4056", "a promotion's slots full told as an Azure error: the call made (FS1c)", API,
     "    except GesturesBusy:      # FS1c: refused at once, said (503)\n        raise\n", ""),
    # ── The gesture noted once, by whoever reads the final receipt first ───────────
    ("M4057", "a gesture of the queue never noted: the feed and the indicators lose it (FS1c)", API,
     '        _note_queued(followed["receipt"])\n', "        pass\n"),
    ("M4058", "a gesture of the queue noted at each read of its receipt (FS1c)", API,
     '    if action_requests.withdraw(request_id, root=_RUNS) and "receipt" in followed:\n',
     '    action_requests.withdraw(request_id, root=_RUNS)\n    if "receipt" in followed:\n'),
    ("M4059", "a page closed before its receipt: its gesture never noted (FS1c)", API,
     "        _settle_waiting()\n", "        pass\n"),
    # ── The watch ──────────────────────────────────────────────────────────────────
    ("M4060", "a card verification_failed born of the queue bears the console's approve-<card> (FS1c)", QW,
     '                                        signal_id=f"queue-{req.service}-{req.id}")\n',
     "                                        )\n"),
    ("M4061", "the caller's signal_id never used: every check's card says approve-<card> (FS1c)", APPROVAL,
     "            signal_id=signal_id or f\"approve-{esc.get('id', '')}\"",
     "            signal_id=f\"approve-{esc.get('id', '')}\""),
    ("M4062", "the watch's start says no key missing (FS1c)", AQ,
     "            for s in services if s not in pins]\n", "            for s in services if False]\n"),
    # ── The bot says the receipt, and writes its own directory ─────────────────────
    ("M4063", "the bot says nothing of a receipt until its end (FS1c)", BOTF,
     "            await channel.send(_STATE_SAID[state].format(rid=rid[:8]))\n", "            pass\n"),
    ("M4064", "the bot follows a receipt for ever: an « accepted » cut by a stop never said (FS1c)", BOTF,
     "        if loop.time() - started > aq.TAKE_S + aq.RUN_S:\n", "        if False:\n"),
    ("M4065", "the CLI the bot runs writes the console's directory again (FS1c)", BOTF,
     "        env={**os.environ, runs_layout.WRITER_ENV: runs_layout.BOT},\n", ""),
    ("M4066", "the bot's hand noted in runs/console: a bot that writes the console's directory (FS1c)",
     "glorfindel/cli.py", "    if hand != runs_layout.CONSOLE:      # FS1c", "    if False:      # FS1c"),
    ("M4067", "the bot mounts runs/console again: it can replace or drown the console's requests (FS1c)",
     "docker-compose.yml",
     "      - ${EREGION_RUNS:-./runs}/annatar:/app/runs/annatar:ro\n      # FS1b : son propre répertoire",
     "      - ${EREGION_RUNS:-./runs}/console:/app/runs/console\n"
     "      - ${EREGION_RUNS:-./runs}/annatar:/app/runs/annatar:ro\n      # FS1b : son propre répertoire"),
    # ── The keys before the flag ───────────────────────────────────────────────────
    ("M4068", "the flag pushed to H0 without the keys it needs: every gesture refused there (FS1c)", HOST,
     "    return pin_problems(pins, wrong, services)\n", "    return []\n"),
    ("M4069", "pin --draw draws nothing: the keys pinned only after the flag (FS1c)", AQ,
     "                public = load_service_key(args[1]).public\n",
     "                public = watch_key.read_public(service_key_dir(args[1]), name=watch_key.SERVICE_KEY_FILE)\n"),
]
TESTS = {f"M{n}": _ASYNC for n in range(4040, 4070)}
TESTS["M4067"] = f"{_MOUNTS} {_ASYNC}"

# After the Opus 5.5 review of e157dbf7: one slot per gesture, held from its entry to its end; the
# bot's Revert by the queue noted in its own directory, once. M4155–M4164.
MUTANTS += [
    ("M4155", "an approval asks a slot at each step: isolated, then « busy » before its check and its note "
              "(FS1c review)", API,
     '@app.post("/api/action/approve/{esc_id}")\n@_one_slot\n', '@app.post("/api/action/approve/{esc_id}")\n'),
    ("M4156", "a gesture that holds its slot asks a second one: refused midway (FS1c review)", API,
     "    if _HOLDING.get():\n        yield\n        return\n", ""),
    ("M4157", "the slot of a gesture never marked held: each step asks its own (FS1c review)", API,
     "    token = _HOLDING.set(True)\n", "    token = _HOLDING.set(False)\n"),
    ("M4158", "a gesture refused at its entry acts all the same (FS1c review)", API,
     "    async def held(*args, **kwargs):\n        async with _slot():\n            return await route(*args, **kwargs)\n",
     "    async def held(*args, **kwargs):\n        return await route(*args, **kwargs)\n"),
    ("M4159", "the bot's Revert by the queue noted nowhere: the feed and the containment never see it "
              "(FS1c review)", BOTF,
     '        _note_revert(followed["receipt"])\n', "        pass\n"),
    ("M4160", "the bot's Revert noted though another read withdrew its request: noted twice (FS1c review)",
     BOTF, '    if aq.withdraw("bot", rid) and "receipt" in followed:\n',
     '    aq.withdraw("bot", rid)\n    if "receipt" in followed:\n'),
    ("M4161", "the bot's Revert noted in the console's directory (FS1c review)", BOTF,
     '"approved_escalation": receipt["card"]} if receipt.get("card") else {})}, hand=runs_layout.BOT)\n',
     '"approved_escalation": receipt["card"]} if receipt.get("card") else {})})\n'),
    ("M4162", "the CLI's note ignores the hand it is given (FS1c review)", "glorfindel/cli.py",
     "    hand = hand or runs_layout.hand()\n", "    hand = runs_layout.hand()\n"),
    ("M4163", "the bot's Revert noted before its end: « accepted » taken for its outcome (FS1c review)", BOTF,
     '    if receipt.get("state") not in ("done", "failed"):\n        return\n    try:\n        from eregion_core import runs_layout\n',
     '    try:\n        from eregion_core import runs_layout\n'),
    ("M4164", "the bot's Revert noted without its request: the note never tied to its receipt (FS1c review)",
     BOTF, '            "via": "queue", "request": str(receipt.get("request") or ""),\n',
     '            "via": "queue",\n'),
]
TESTS.update({f"M{n}": _ASYNC for n in range(4155, 4165)})
