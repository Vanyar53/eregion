"""CON-S (#534): the console marks each detection of the return channel as the injectors read it
(SEC21) — signed by the key pinned on the console (EREGION_WATCH_KEY), or refused with why; none
verified without a key pinned; the refused shown bounded, all counted; nothing of the blob written
raw. M3750–M3759, measured by tests/unit/test_console_signed_detections.py (and, for what the page
writes, tests/unit/test_console_escaping.py)."""
API = "eregion_console/api.py"
JS = "eregion_console/static/injector.js"
COMPOSE = "docker-compose.yml"
_TESTS = "tests/unit/test_console_signed_detections.py"

MUTANTS = [
    ("M3750", "every detection of the channel shown signed, whatever its signature (CON-S)", API,
     '        shown.append({"signal": signal, "state": "refused" if why else "signed", "why": why[:400],\n',
     '        shown.append({"signal": signal, "state": "signed", "why": why[:400],\n'),
    ("M3751", "a detection shown refused without why (CON-S)", API,
     '"state": "refused" if why else "signed", "why": why[:400],\n',
     '"state": "refused" if why else "signed", "why": "",\n'),
    ("M3752", "the console reads the channel as written: no signature checked, everything signed (CON-S)", API,
     "        why = no_key if key is None else watch_key.detection_refusal(\n"
     "            record, key, run_id=run_id, signal_id=signal)\n",
     '        why = no_key if key is None else ""\n'),
    ("M3753", "no key pinned on the console: every detection shown signed (CON-S)", API,
     "        why = no_key if key is None else watch_key.detection_refusal(\n",
     '        why = "" if key is None else watch_key.detection_refusal(\n'),
    ("M3754", "no key pinned, the route says one is (CON-S)", API,
     '           else {"pinned": False, "why": no_key})\n',
     '           else {"pinned": True, "why": no_key})\n'),
    ("M3755", "the refused shown unbounded: a writer of the channel floods the page (CON-S)", API,
     "            if refused > watch_channel.MAX_REFUSED:\n                continue\n",
     "            if False:\n                continue\n"),
    ("M3756", "past MAX_REFUSED refusals, a signed detection hidden too (CON-S)", API,
     "            refused += 1\n            if refused > watch_channel.MAX_REFUSED:\n                continue\n",
     "            refused += 1\n        if refused > watch_channel.MAX_REFUSED:\n            continue\n"),
    ("M3757", "the page says SIGNED without a key pinned, on the server's word alone (CON-S)", JS,
     "    const ok = pinned && x.state === 'signed';\n",
     "    const ok = x.state === 'signed';\n"),
    ("M3758", "the reason of a refusal written raw into the page (CON-S, #254)", JS,
     "<td>${ok ? '' : esc(x.why)}</td></tr>`;\n",
     "<td>${ok ? '' : x.why}</td></tr>`;\n"),
    ("M3759", "the console's service never receives the watch's public key: every detection refused (CON-S, SEC19)",
     COMPOSE,
     "      # SEC19 : la clé publique de la watch — Dagorlad montre la garde comme un injecteur la lit.\n"
     "      EREGION_WATCH_KEY: ${EREGION_WATCH_KEY:-}\n",
     ""),
]
TESTS = {f"M{n}": _TESTS for n in range(3750, 3760)}
TESTS["M3758"] = f"{_TESTS} tests/unit/test_console_escaping.py"
