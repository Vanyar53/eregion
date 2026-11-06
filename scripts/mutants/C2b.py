"""C2b (#607): the identity cards of Glorfindel — every command complete when the row or Graph
gives the id, else a template that says what to replace (never `//`); Graph not read, the ids the
row names fill the commands; Discord shows each command as code, whole; a consent said in one line
(the permission, the application, its nature, for whom), never its raw diff.
M4370–M4374, measured by tests/unit/test_identity_cards.py."""
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
]
TESTS = {f"M{n}": _TESTS for n in range(4370, 4375)}
