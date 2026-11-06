"""AL1c (#597): a card of the control plane or of an identity is filed on what it is about — never on
a VM it has nothing to do with. The NSG and the VMs it covers, a snapshot's source VM and the limit
said, a role's scope, an unknown resource's group, an identity by its object id; what Azure did not
answer said, never read as « nothing »; the card keeps its target; the Discord card names it and
says its paragraph once. M4270–M4279, and M4310–M4314 (the review: no VM watched, a limit that
says only what was read, the VMs of an NSG capped, a tile of its own), M4355–M4359 (the second:
the VM that made the call is the caller, a VM the rule does not watch, a field under 1024) and
M4418–M4419 (the third: a call from a VM the rule does not watch, never unsaid), measured by
tests/unit/test_card_target.py."""
POLLER = "glorfindel/detection_rules.py"
TARGET = "glorfindel/card_target.py"
AGENT = "glorfindel/agent.py"
BOT = "glorfindel/bot.py"
JS = "eregion_console/static/glorfindel.js"
_TESTS = "tests/unit/test_card_target.py"

MUTANTS = [
    ("M4270", "a card of the control plane anchored again on the first VM online (AL1c)", POLLER,
     '        if target is not None and (plane == "identity" or not named):\n',
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
    # The review (998c89f7): no VM watched, a limit that says only what was read, the VMs of an
    # NSG capped on both sides, a tile of its own never a VM's of the same name.
    ("M4310", "a rule of the control plane silent when no VM is watched: every VM excluded (AL1c)", POLLER,
     '        routed = self._route(rule, rows, targets) if targets or self._plane(rule) != "data" else {}\n',
     '        routed = self._route(rule, rows, targets) if targets else {}\n'),
    ("M4311", "a resource the listing does not hold said « gone », though out of the watch's reach (AL1c)", TARGET,
     '_GONE_OR_HIDDEN = "supprimé, ou hors des droits de la watch"\n',
     '_GONE_OR_HIDDEN = "supprimé depuis ?"\n'),
    ("M4312", "the Discord card names every VM an NSG covers: a field past Discord's limit (AL1c)", BOT,
     "_VMS_SHOWN = 8           # the VMs an NSG covers, named; beyond, counted\n",
     "_VMS_SHOWN = 1000        # the VMs an NSG covers, named; beyond, counted\n"),
    ("M4313", "the console names every VM an NSG covers, none counted (AL1c)", JS,
     "      ? ` · covers ${vms.slice(0, _VMS_SHOWN).map(v => _attr(v)).join(', ')}${more}` : '';\n",
     "      ? ` · covers ${vms.map(v => _attr(v)).join(', ')}${more}` : '';\n"),
    ("M4314", "a group's or the control plane's tile shares a VM's cards of the same name (AL1c)", JS,
     "  if (own || r.kind) return own === r.vm_name;\n",
     ""),
    # The second review (c3c4cb90): the VM that made the call is the caller, never the target;
    # a VM the rule does not watch is not « unknown to the discovery »; a field under 1024.
    ("M4355", "an NSG written from a watched VM filed on that VM, the NSG unsaid (AL1c)", TARGET,
     "    if tgt is not None and names_vm(row, tgt[0]):\n",
     "    if tgt is not None:\n"),
    ("M4356", "a card on what a VM wrote attributed to the VM that made the call (AL1c)", POLLER,
     "        named = tgt is not None and card_target.names_vm(row, tgt[0])\n",
     "        named = tgt is not None\n"),
    ("M4357", "a VM excluded from the rule said unknown to the discovery (AL1c)", TARGET,
     '_UNWATCHED_SHORT = "que la règle ne surveille pas"\n',
     '_UNWATCHED_SHORT = "que la découverte ne connaît pas"\n'),
    ("M4358", "the « Ressource visée » field past Discord's 1024: the embed refused (AL1c)", BOT,
     "            if len(value) <= 1024:\n",
     "            if True:\n"),
    ("M4359", "the VM that made the call left unsaid on a card filed on what it wrote (AL1c)", TARGET,
     "    caller = (f\"appel depuis {tgt[1] or _short(tgt[0])}\" if tgt is not None else\n",
     "    caller = (\"\" if tgt is not None else\n"),
    # The third review (3949289f): a row of the control plane routed by its caller's address to a
    # VM the rule does not watch is a card on what it names; one naming such a VM, dropped (AL1).
    ("M4418", "an NSG written from a VM the rule does not watch dropped, unsaid (AL1c)", POLLER,
     "            if named and tgt is None and (not control or _names_vm_resource(row)):\n",
     "            if named and tgt is None:\n"),
    ("M4419", "a row of the control plane on a VM the rule does not watch kept: an exclusion ignored (AL1c)", POLLER,
     "            if named and tgt is None and (not control or _names_vm_resource(row)):\n",
     "            if named and tgt is None and not control:\n"),
]
TESTS = {f"M{n}": _TESTS for n in [*range(4270, 4280), *range(4310, 4315), *range(4355, 4360), 4418, 4419]}
