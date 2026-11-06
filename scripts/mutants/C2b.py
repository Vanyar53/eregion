"""C2b (#607): the identity cards of Glorfindel — every command complete when the row or Graph
gives the id, else a template that says what to replace (never `//`); Graph not read, the ids the
row names fill the commands; Discord shows each command as code, whole; a consent said in one line
(the permission, the application, its nature, for whom), never its raw diff.
M4370–M4374, M4405–M4409 (the first review) and M4435–M4437 (the second), measured by tests/unit/test_identity_cards.py
(M4409 also by tests/unit/test_chat_escaping.py)."""
ITEMS = "glorfindel/providers/azure/entra_items.py"
GRANTS = "glorfindel/providers/azure/entra_grants.py"
CONSENT = "glorfindel/providers/azure/entra_consent.py"
ENTRA = "glorfindel/providers/azure/entra.py"
BOT = "glorfindel/bot.py"
_TESTS = "tests/unit/test_identity_cards.py"

MUTANTS = [
    ("M4370", "a parameter not read left empty in its command: `…/roleAssignments/`, `…/users//…` (C2b)", ITEMS,
     '    return p["value"] if p["read"] else placeholder(p["name"])\n',
     '    return p["value"]\n'),
    ("M4371", "Graph not read, the grant the consent's log names left aside: its command a template (C2b)",
     GRANTS,
     "    if logged:\n        return logged\n",
     "    if False:\n        return logged\n"),
    ("M4372", "a plan's command shown as prose in Discord: a link, a backslash for a `/` (C2b)", BOT,
     "    lines = [head + (f\" : {discord_code(i['command'])}\" if i.get(\"command\") else \"\")]\n",
     "    lines = [head + (f\" : {discord_text(i['command'])}\" if i.get(\"command\") else \"\")]\n"),
    ("M4373", "an application permission said delegated: « for all users » of what acts with no user (C2b)",
     CONSENT,
     '    if "app role assignment" in op:\n        return APPLICATION\n',
     '    if "app role assignment" in op:\n        return DELEGATED\n'),
    ("M4374", "the consent's raw diff back on the card: `[] => [[Id: …, ClientId: …]]` (C2b)", ENTRA,
     '                + f". {entra_consent.line(row)}")\n',
     '                + f". {entra_consent.line(row)} Permissions : {row.get(\'Permissions\')}")\n'),
    # Relecture 1 (06/11): M4405–M4409.
    ("M4405", "a grant the log gives to another application removed by a complete command (C2b r1)", GRANTS,
     '             if g["id"] and g["client"] == client]          # another application\'s grant: never\n',
     '             if g["id"]]\n'),
    ("M4406", "a diff read in pieces: a `]` in a scope forges a second grant, complete (C2b r1)", CONSENT,
     "    if not _SIDE_RE.fullmatch(text):\n        return None\n",
     ""),
    ("M4407", "Graph not read, the application permissions left out of Verify: « held » while one stands (C2b r1)",
     GRANTS,
     "            # Verify reads them too: the card is never « held » while an application permission stands.\n"
     '            check={"kind": "consent_gone", "client": client}))\n',
     "            check=None))\n"),
    ("M4408", "a widened scope that is no words taken for unchanged: « not named by the log » (C2b r1)", CONSENT,
     '        if any(e["scope"].strip() and not words(e["scope"]) for e in old + new):\n',
     "        if False:\n"),
    ("M4409", "a plan's step, a name from outside in it, posted raw to Discord (C2b r1)", BOT,
     "    head = f\"• {discord_text(i.get('n', '?'))}. {discord_text(i.get('what') or '')}\"\n",
     "    head = f\"• {discord_text(i.get('n', '?'))}. {i.get('what') or ''}\"\n"),
    # Relecture 2 (06/11): M4435–M4437 — a forged line never freezes the watch.
    ("M4435", "the diff's entries no longer atomic: an ambiguous entry backtracks ~2^n (C2b r2)", CONSENT,
     '    atomic = f"(?>{entry})"\n',
     '    atomic = f"(?:{entry})"\n'),
    ("M4436", "a Permissions value of any length parsed: no ceiling on what a forged line costs (C2b r2)", CONSENT,
     "    if len(s) > MAX_PERMISSIONS:\n",
     "    if False:\n"),
    ("M4437", "an empty PrincipalId's space read two ways: the entry ambiguous again (C2b r2)", CONSENT,
     "            rf\"PrincipalId:\\s*(?:{g('principal', _G)}\\s*)?,\\s*ResourceId:",
     "            rf\"PrincipalId:\\s*{g('principal', _G + '|')}\\s*,\\s*ResourceId:"),
]
TESTS = {f"M{n}": _TESTS for n in list(range(4370, 4375)) + list(range(4405, 4410)) + list(range(4435, 4438))}
TESTS["M4409"] = f"{_TESTS} tests/unit/test_chat_escaping.py"
