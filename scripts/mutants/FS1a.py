"""FS1a (#551): the signed action queue — its format and its verification (eregion_core/action_queue.py):
one mutant per control of the verification of a request (§2.8, steps 2 to 9) and of the proposal the
watch signs on a card (step 10). M3865–M3879, measured by tests/unit/test_action_queue.py and
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
TESTS = {f"M{n}": _QUEUE for n in range(3865, 3878)}
TESTS.update({"M3878": _PROPOSAL, "M3879": _PROPOSAL})
