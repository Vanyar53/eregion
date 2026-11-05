"""FS1b (#563): the watch picks the signed action queue up (glorfindel/queue_watch.py) — one mutant per
guard it replays (glorfindel/approval.py, the console's own) and per property of its register
(eregion_core/action_queue.py: the nonces and the proposals consumed, written durably, the claims
bounded, never raising), the receipts and the recovery after a stop, the flag, the console's and the
bot's deposits, the proposal kept while young, the bot's mount. M3975–M4014, measured by
tests/unit/test_action_queue_watch.py, test_action_queue.py, test_action_proposal.py and
test_runs_mounts.py."""
QW = "glorfindel/queue_watch.py"
AQ = "eregion_core/action_queue.py"
CR = "eregion_core/channel_reader.py"
ESC = "glorfindel/escalations.py"
_WATCH = "tests/unit/test_action_queue_watch.py"
_QUEUE = "tests/unit/test_action_queue.py"
_PROPOSAL = "tests/unit/test_action_proposal.py"
_MOUNTS = "tests/unit/test_runs_mounts.py"

MUTANTS = [
    # ── The request, attached to its card ─────────────────────────────────────────
    ("M3975", "a request under another name than its nonce taken: a copy of one runs again (FS1b)", QW,
     "            if req.id != request_id:\n", "            if False:\n"),
    ("M3976", "a request never attached to its card: a forged card approved (FS1b)", QW,
     "        aq.proposal_refusal(card, req, watch_public=self.signer.public, consumed=consumed)\n", ""),
    ("M3977", "an isolation asked without its card runs: the console isolates any VM (FS1b)", QW,
     '            if req.verb in CARD_ONLY or req.service == "bot":\n', "            if False:\n"),
    ("M3978", "the bot resets without its card verification_failed (FS1b)", QW,
     '            if req.verb in CARD_ONLY or req.service == "bot":\n', "            if req.verb in CARD_ONLY:\n"),
    # ── The guards of the gesture, replayed ────────────────────────────────────────
    ("M3979", "the guards of the one-click approval never replayed by the watch (FS1b)", QW,
     '            why = approval.approval_refusal(card, vm, dated=proposal["issued_at"], now=now)\n',
     "            why = None\n"),
    ("M3980", "the age of an approval read from last_seen, which the console writes (FS1b, §7)", QW,
     'approval.approval_refusal(card, vm, dated=proposal["issued_at"], now=now)',
     "approval.approval_refusal(card, vm, now=now)"),
    ("M3981", "the bot's human never read against the watch's own copy of the allowed (FS1b)", QW,
     '        if req.service == "bot":\n            why = approval.discord_refusal',
     "        if False:\n            why = approval.discord_refusal"),
    ("M3982", "an address the request names never judged: a range, a protected one (FS1b, §7)", QW,
     "            ip, why = approval.address_refusal(ip)\n", '            why = ""\n'),
    ("M3983", "a reach other than vm or subnet passed to the connector (FS1b, §7)", QW,
     "            why = approval.scope_refusal(req.scope)\n", '            why = ""\n'),
    ("M3984", "a VM out of the watch's perimeter acted on (FS1b)", QW,
     "        if not approval.in_perimeter(rid):\n", "        if False:\n"),
    ("M3985", "a release asked of a VM the watch holds no isolation of (FS1b)", QW,
     "            if not approval.held_isolation(rid):\n", "            if False:\n"),
    ("M3986", "a reset asked of a VM the watch holds nothing of (FS1b)", QW,
     "            if not (approval.held_isolation(rid) or approval.held_blocks(rid)):\n", "            if False:\n"),
    ("M3987", "an unblock of an address the watch does not hold on this VM (CON-K, FS1b)", QW,
     "            if block is None:\n", "            if False:\n"),
    ("M3988", "a block already on the subnet promoted again (FS1b)", QW,
     '            if ctx["scoped"] is False:\n', "            if False:\n"),
    ("M3989", "a read-only watch executes a request (FS1b)", QW,
     "            if self.read_only:                                   # 12. the posture\n", "            if False:\n"),
    # ── The register ───────────────────────────────────────────────────────────────
    ("M3990", "a proposal never consumed: one approval, two executions (FS1b)", QW,
     "                    fresh = self.consumed.consume(req.proposal, req.card_id, now)\n",
     "                    fresh = True\n"),
    ("M3991", "an unreadable register of proposals raises instead of refusing (FS1b)", AQ,
     "        except Exception as e:          # RecursionError…: refused, never raised\n"
     "            raise ValueError(f\"{self.path} is not a register of proposals ({type(e).__name__})\") from None\n",
     ""),
    ("M3992", "an unreadable register of nonces raises instead of refusing (FS1b)", AQ,
     "            except Exception as e:      # RecursionError, TypeError…: refused, never raised\n"
     "                raise ValueError(f\"{self.path} is not a register of nonces ({type(e).__name__})\") from None\n",
     ""),
    ("M3993", "a nonce claimed without fsync: lost to a crash, its request replayed (FS1b, §7)", AQ,
     "            kept[nonce] = _iso(until)\n            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
     "            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600, sync=True)\n",
     "            kept[nonce] = _iso(until)\n            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
     "            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600)\n"),
    ("M3994", "a proposal consumed without fsync: lost to a crash, run again (FS1b)", AQ,
     '            kept[proposal] = {"card": str(card)[:200], "at": _iso(now)}\n'
     "            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
     "            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600, sync=True)\n",
     '            kept[proposal] = {"card": str(card)[:200], "at": _iso(now)}\n'
     "            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)\n"
     "            channel_reader.write_file(self.path, json.dumps(kept, sort_keys=True), mode=0o600)\n"),
    ("M3995", "a durable write never syncs its directory: the rename lost to a crash (FS1b)", CR,
     "    if sync:\n        dfd = os.open(path.parent", "    if False:\n        dfd = os.open(path.parent"),
    ("M3996", "the claims of a service bounded after the register: a key fills it (FS1b, §7)", AQ,
     ('    if not rate.take(service, now):\n        raise Refused("rate_limited")\n    # 8. the nonce',
      '    card = doc["card"]\n    return Request('),
     ("    # 8. the nonce",
      '    if not rate.take(service, now):\n        raise Refused("rate_limited")\n    card = doc["card"]\n'
      "    return Request(")),
    # ── The cards, the receipts, a stop ────────────────────────────────────────────
    ("M3997", "a forged, replayed or foreign request makes no critical card (FS1b)", QW,
     '        if refused.critical or refused.code == "seen_store_unavailable":\n            self._card(service, refused, now)\n',
     ""),
    ("M3998", "a critical card at each refusal: a flood floods the cards (FS1b)", QW,
     "            if at - self._critical_at.get(key, -CRITICAL_EVERY_S) < CRITICAL_EVERY_S:\n                return\n",
     ""),
    ("M3999", "a request cut by a stop never said: its receipt waits forever (FS1b)", QW,
     '            if doc is None or doc["state"] not in ("received", "accepted"):\n                continue\n',
     "            continue\n"),
    ("M4000", "no receipt before the claim: the watch's own stop read as a replay, a critical card (FS1b)", QW,
     '        self._receipt(service, request_id, "received", now=now)\n', ""),
    ("M4001", "no receipt « accepted » before the execution: a kill midway leaves no trace of it (FS1b)", QW,
     '        accepted = self._receipt(service, request_id, "accepted", request=req, now=now)\n',
     "        accepted = {}\n"),
    ("M4002", "a receipt unsigned: another writer of runs/glorfindel says « done » (FS1b)", QW,
     '        doc = aq.sign_watch("receipt", body, self.signer)\n',
     '        doc = {**body, "kind": "receipt", "v": 1}\n'),
    ("M4003", "a request executed outside its VM's lock (FS1b)", QW,
     "            with _vm_lock(_vm(req.resource_id)):\n", "            if True:\n"),
    # ── The flag ───────────────────────────────────────────────────────────────────
    ("M4004", "the watch picks the queue up without EREGION_ACTION_QUEUE (FS1b)", QW,
     "    if not aq.enabled():\n        return None\n", ""),
    ("M4005", "the flag read loosely: « true », « yes » turn the queue on (FS1b)", AQ,
     '    return (os.environ if environ is None else environ).get(FLAG_ENV, "") == "1"\n',
     '    return (os.environ if environ is None else environ).get(FLAG_ENV, "").strip().lower() in ("1", "true", "yes")\n'),
    ("M4006", "the console deposits without the flag: the default changed (FS1b)", "eregion_console/api.py",
     "    from eregion_core.action_queue import enabled\n    return enabled()\n",
     "    from eregion_core.action_queue import enabled  # noqa: F401\n    return True\n"),
    ("M4007", "the bot deposits its Revert without the flag (FS1b)", "glorfindel/bot.py",
     '        if action_queue.enabled() and self.cli_args[:1] == ["revert"]:\n',
     '        if self.cli_args[:1] == ["revert"]:\n'),
    # ── The proposal kept while young (§7) ─────────────────────────────────────────
    ("M4008", "a proposal signed again at each refresh: a request just named refused (FS1b, §7)", ESC,
     '        if seen_again and action_queue.proposal_fresh(e, e.get("proposal"), signer.public, now, RESIGN_AFTER_S):\n'
     "            return\n", ""),
    ("M4009", "a proposal kept on a card changed since: its port, its address no longer the card's (FS1b)", AQ,
     "    if said != held:\n        return False\n", "    if False:\n        return False\n"),
    ("M4010", "a proposal kept whatever its age: the age of an approval read wrong (FS1b)", AQ,
     "    return timedelta(0) <= now - issued < timedelta(seconds=max_age_s)\n", "    return True\n"),
    ("M4011", "a proposal of another key kept on a card seen again (FS1b)", AQ,
     '    if watch_refusal(proposal, "proposal", watch_public):\n        return False\n', ""),
    # ── What the services read ─────────────────────────────────────────────────────
    ("M4012", "a proposal or a status read as a receipt (FS1b)", AQ,
     '    if (not isinstance(doc, dict) or doc.get("kind") != "receipt" or doc.get("request") != request_id\n',
     '    if (not isinstance(doc, dict) or doc.get("request") != request_id\n'),
    ("M4013", "a receipt believed whoever signed it, the watch's key pinned (FS1b)", AQ,
     '    if watch_public is not None and watch_refusal(doc, "receipt", watch_public):\n        return None\n', ""),
    ("M4014", "the bot mounts the whole of the watch's directory, its reasoning included (FS1b)", "docker-compose.yml",
     "      - ${EREGION_RUNS:-./runs}/glorfindel/queue:/app/runs/glorfindel/queue:ro\n",
     "      - ${EREGION_RUNS:-./runs}/glorfindel:/app/runs/glorfindel:ro\n"),
]
TESTS = {f"M{n}": _WATCH for n in range(3975, 4015)}
TESTS.update({"M3995": f"{_WATCH} {_QUEUE}", "M3996": _WATCH, "M4005": f"{_QUEUE} {_WATCH}",
              "M4008": _PROPOSAL, "M4009": f"{_PROPOSAL} {_QUEUE}", "M4010": _QUEUE, "M4011": f"{_PROPOSAL} {_QUEUE}",
              "M4012": _QUEUE, "M4013": _QUEUE, "M4014": _MOUNTS})
# After the Opus 5.5 review of 0c2370b0: a restore record there but unreadable, the queue's thread
# that never dies in silence, a team's receipts' directory. M4030–M4034.
_AP = "glorfindel/approval.py"
MUTANTS += [
    ("M4030", "a restore record there but unreadable (a list, a date without its zone) read as no restore: "
              "the approval runs on a restored VM (FS1b review)", _AP,
     '    except Exception as exc:\n        return f"Restore illisible ({type(exc).__name__}) : agir depuis la CLI."\n'
     "    if after:\n",
     "    except Exception:\n        return None\n    if after:\n"),
    ("M4031", "a restore record that cannot be read read as no restore (FS1b review)", _AP,
     '    except OSError as exc:\n        return f"Restore illisible ({type(exc).__name__}) : agir depuis la CLI."\n'
     "    # A record there",
     "    except OSError:\n        return None\n    # A record there"),
    ("M4032", "a pass of the queue's thread that raises goes unsaid (FS1b review)", QW,
     "                self.say(f\"file d'actions : passage en erreur — {type(exc).__name__}: {exc}\")\n",
     "                pass\n"),
    ("M4033", "a team's runs/glorfindel/queue left to docker, made as root: no receipt written (FS1b review)",
     "Makefile", '\tmkdir -p "$(TEAM_DIR)/runs/glorfindel/queue"\n', ""),
    ("M4034", "a team's runs/glorfindel/queue that is a link mounted (FS1b review)", "Makefile",
     '"$(TEAM_DIR)/runs/glorfindel/queue"; do test ! -L "$$d" \\\n',
     '"$(TEAM_DIR)/runs/glorfindel/queue"; do true \\\n'),
]
TESTS.update({f"M{n}": _WATCH for n in range(4030, 4035)})
