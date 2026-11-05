"""FS1a (#551): the signed action queue — its format and its verification (eregion_core/action_queue.py):
one mutant per control of the verification of a request (§2.8, steps 2 to 9) and of the proposal the
watch signs on a card (step 10). M3865–M3879 and M3945–M3954, measured by tests/unit/test_action_queue.py and
tests/unit/test_action_proposal.py."""
AQ = "eregion_core/action_queue.py"
_QUEUE = "tests/unit/test_action_queue.py"
_PROPOSAL = "tests/unit/test_action_proposal.py"

MUTANTS = [
    ("M3865", "an unsigned request taken: anyone who writes in a service's queue asks for an action (FS1a)", AQ,
     '    if doc.get("sig") is None:\n        raise Refused("unsigned")\n',
     "    if False:\n        raise Refused(\"unsigned\")\n"),
    ("M3866", "the key a request names never compared with the one pinned: another hand's key said in its place (FS1a)",
     AQ, "    if said != want:\n        for other, key in pins.items():\n",
     "    if False:\n        for other, key in pins.items():\n"),
    ("M3867", "a request's signature never checked: the fingerprint it claims believed (FS1a)", AQ,
     "    if not watch_key.holds(pin, DOMAIN_REQUEST, doc):\n        raise Refused(\"bad_signature\")\n",
     "    if False:\n        raise Refused(\"bad_signature\")\n"),
    ("M3868", "a request naming another service taken in this one's queue (FS1a)", AQ,
     '    if doc["service"] != service:\n', "    if False:\n"),
    ("M3869", "a request issued ahead of the watch's clock taken: one signed now runs later (FS1a)", AQ,
     "    if issued - now > timedelta(seconds=SKEW_S):\n", "    if False:\n"),
    ("M3870", "a request valid for longer than its bound taken: a request kept for later (FS1a)", AQ,
     "    if expires - issued > timedelta(seconds=MAX_LIFETIME_S):\n", "    if False:\n"),
    ("M3871", "an expired request taken (FS1a)", AQ,
     "    if now >= expires:\n", "    if False:\n"),
    ("M3872", "a request replayed taken again: one approval, two executions (FS1a)", AQ,
     "    if not fresh:\n        raise Refused(\"replayed\")\n", ""),
    ("M3873", "a register of nonces that cannot be kept taken as no replay (FS1a)", AQ,
     '        raise Refused("seen_store_unavailable", f"{REFUSALS[\'seen_store_unavailable\']} ({str(e)[:120]})") from None\n',
     "        fresh = True\n"),
    ("M3874", "the verbs a service may ask never checked: the bot isolates (FS1a)", AQ,
     "    if verb not in SERVICE_VERBS.get(service, frozenset()):\n", "    if False:\n"),
    ("M3875", "no bound on the requests of a service: a flood of signed requests (FS1a)", AQ,
     "    if not rate.take(service, now):\n", "    if False:\n"),
    ("M3876", "a request with a field more taken (FS1a)", AQ,
     "    if extra:\n        raise Refused(\"malformed\", f\"a field it never holds:",
     "    if False:\n        raise Refused(\"malformed\", f\"a field it never holds:"),
    ("M3877", "a request signed under the watch's domain of the queue: a signature for another use reads as a request (FS1a)",
     AQ, 'DOMAIN_REQUEST = "eregion.action-request/1"\n', "DOMAIN_REQUEST = watch_key.DOMAIN_QUEUE\n"),
    ("M3878", "a card's proposal never checked against the watch's key: a forged card approved (FS1a)", AQ,
     '    why = watch_refusal(proposal, "proposal", watch_public)\n', '    why = ""\n'),
    ("M3879", "the proposal a request names never compared with the card's: an older proposal runs (FS1a)", AQ,
     "    if digest(proposal) != request.proposal:\n", "    if False:\n"),
]
# After the review of b43218ae: each control of the attachment to a card, the kinds of what the
# watch signs, the cards it proposes, and a signature in its one canonical form. M3945–M3954.
WKEY = "eregion_core/watch_key.py"
MUTANTS += [
    ("M3945", "a card that no longer waits still runs its proposal (FS1a)", AQ,
     '    if card.get("status") != "pending":\n', "    if False:\n"),
    ("M3946", "a proposal executed runs again: one approval, two executions (FS1a)", AQ,
     "    if request.proposal in consumed:\n", "    if False:\n"),
    ("M3947", "a request asks another verb than the card proposes: an isolation on a snapshot's card (FS1a)", AQ,
     "    if request.verb not in proposed_verbs(proposal):\n", "    if False:\n"),
    ("M3948", "a request aims at another VM than the card's (FS1a)", AQ,
     '    if request.resource_id.lower() != str(proposal["resource_id"]).lower():\n', "    if False:\n"),
    ("M3949", "a request names another address than the card proposes to block (FS1a)", AQ,
     '    if proposal["ip"] and request.ip not in ("", proposal["ip"]):\n', "    if False:\n"),
    ("M3950", "a card changed since its proposal (its action, target, address, port) still runs it (FS1a)", AQ,
     '    if (proposal["card"] != card.get("id") or proposal["action"] != card.get("action")\n',
     '    if False and (proposal["card"] != card.get("id") or proposal["action"] != card.get("action")\n'),
    ("M3951", "what the watch signs read as any of its kinds: a proposal reads as a receipt (FS1a)", AQ,
     '    if body.get("kind") != kind:\n        return f"not a {kind}',
     '    if False:\n        return f"not a {kind}'),
    ("M3952", "the watch proposes the action of any card: a control-plane card approved in one click (FS1a)", AQ,
     '    if etype in APPROVABLE_TYPES and card.get("action") in VERB_OF_ACTION:\n',
     '    if card.get("action") in VERB_OF_ACTION:\n'),
    ("M3953", "a signature read in any of its 16 spellings: one proposal, 16 digests (FS1a, SEC19, SEC21)", WKEY,
     "    return raw if base64.b64encode(raw).decode() == sig else None\n", "    return raw\n"),
    ("M3954", "the card read is not the one the request names (FS1a)", AQ,
     '    if not isinstance(card, dict) or card.get("id") != request.card_id:\n',
     "    if not isinstance(card, dict):\n"),
]
TESTS = {f"M{n}": _QUEUE for n in range(3865, 3878)}
TESTS.update({"M3878": _PROPOSAL, "M3879": _PROPOSAL})
TESTS.update({f"M{n}": _PROPOSAL for n in range(3945, 3953) if n != 3951})
TESTS.update({"M3951": _QUEUE, "M3953": _QUEUE, "M3954": _PROPOSAL})
