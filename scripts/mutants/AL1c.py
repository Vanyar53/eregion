"""AL1c (#597): a card of the control plane or of an identity is filed on what it is about — never on
a VM it has nothing to do with. The NSG and the VMs it covers, a snapshot's source VM and the limit
said, a role's scope, an unknown resource's group, an identity by its object id; what Azure did not
answer said, never read as « nothing »; the card keeps its target; the Discord card names it and
says its paragraph once. M4270–M4279, measured by tests/unit/test_card_target.py."""
POLLER = "glorfindel/detection_rules.py"
TARGET = "glorfindel/card_target.py"
AGENT = "glorfindel/agent.py"
BOT = "glorfindel/bot.py"
_TESTS = "tests/unit/test_card_target.py"

MUTANTS = [
    ("M4270", "a card of the control plane anchored again on the first VM online (AL1c)", POLLER,
     '        if target is not None and (plane == "identity" or tgt is None):\n',
     '        if target is not None and plane == "identity":\n'),
    ("M4271", "the VMs an NSG covers looked up by its rule's id: none said (AL1c)", TARGET,
     '    covered = _lookup(topology, "nsg_vms", nsg_id)\n',
     '    covered = _lookup(topology, "nsg_vms", m.group(0))\n'),
    ("M4272", "a snapshot filed on its source's VM without saying the row names no source (AL1c)", TARGET,
     '                             limit=said + " Sa source a été lue sur Azure.")\n',
     '                             limit="")\n'),
    ("M4273", "a section Azure did not answer read as « nothing there » (AL1c)", TARGET,
     "        if part is None:\n            return UNREAD\n",
     "        if part is None:\n            return None\n"),
    ("M4274", "a role on a resource group filed on the control plane (AL1c)", TARGET,
     "        if _GROUP_RE.match(scope):\n            return _group_target(scope, row, via=via)\n",
     ""),
    ("M4275", "an identity's pseudo id made of its name, chosen by whoever registers it (AL1c)", TARGET,
     "    t[\"id\"] = f\"{IDENTITY_PREFIX}{ttype.lower()}:{t['object_id'] or 'unread'}\"\n",
     "    t[\"id\"] = f\"{IDENTITY_PREFIX}{ttype.lower()}:{t['name']}\"\n"),
    ("M4276", "the Discord card repeats its paragraph under « Pourquoi rien n'est exécuté » (AL1c)", BOT,
     '    why = reason.replace(explanation, "", 1).strip() if explanation and explanation in reason else reason\n',
     '    why = reason\n'),
    ("M4277", "the Discord card names the VM it is filed on, not its target (AL1c)", BOT,
     "        *_target_fields(esc),\n",
     '        ("Ressource", discord_code((esc.get("resource_id") or "").split("/")[-1]), True),\n'),
    ("M4278", "the card loses its target: the console and Discord no longer say it (AL1c)", AGENT,
     "            target=_card_target(signal),\n        )\n",
     "            target=None,\n        )\n"),
    ("M4279", "an unknown resource filed on the control plane, not on its group (AL1c)", TARGET,
     '    return _group_target(rid, row, via=_short(rid) if rid else "")\n',
     '    return control_plane_target()\n'),
]
TESTS = {f"M{n}": _TESTS for n in range(4270, 4280)}
