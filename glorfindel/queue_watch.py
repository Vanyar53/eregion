"""FS1b (#563, docs/design/file-actions-signee.md §2.5–§2.13): the watch picks the signed action
queue up — behind ``EREGION_ACTION_QUEUE=1`` only, like the console and the bot that deposit in it
(eregion_core/action_queue.py, ``enabled``): without the flag, no queue is read.

**Its own thread** (``start``): every second, ``runs/console/queue/`` and ``runs/bot/queue/`` are
read (each a writer's directory, read-only to the watch, SEC18), a bounded number of files per poll.
Never the watch's loop, never its heartbeat: a request in flight runs in a worker of its own (at most
``IN_FLIGHT``), under the VM's lock (``_vm_lock``), never cut midway.

**Each request, from the cheapest to the dearest, no call to the cloud before the execution**:
- its name is its nonce (``<id>.json``), else it is passed over and said once;
- a receipt ``received`` first — the watch never judges a request twice: a stop between its claim
  and its end leaves that receipt, and the next start says it ``failed`` (interrupted), never runs
  it again (``recover``);
- §2.8, steps 1 to 9 — read bounded, the form, the signature by the key pinned for this directory,
  the service, the time, the rate (before the register: a service's claims are bounded), the nonce
  claimed in a register written durably, the verb (``action_queue.verify_request``);
- step 10, the attachment: a card's proposal this watch signed and that is not consumed
  (``action_queue.proposal_refusal``), or what the watch holds for a verb without a card;
- step 11, the guards of the gesture, replayed — the console's own (glorfindel/approval.py): the
  approval in one click, its age read from the proposal's signed ``issued_at``, an address and a
  reach, the VM in the watch's perimeter, the block of this IP on this VM, the bot's human;
- step 12, the posture: a read-only watch refuses;
- the proposal consumed, written durably, before the execution — one proposal, one execution;
- the receipt ``accepted``, then ``done`` or ``failed`` — or ``refused`` at the first step that
  refuses, its code and its reason.

**What it writes**: its receipts and its status, in its own directory (``runs/glorfindel/queue/``),
signed by its key under ``eregion.action-queue/1`` (``kind`` signed: a receipt never reads as a
proposal). A refusal of ``action_queue.CRITICAL`` makes a critical card — decided by the code, never
by a model, no action, at most one per service and per hour; a register that cannot be kept, a
card too (not critical). Each refusal is counted in the status.

**What runs**: the watch's own functions — the connector's writes, the CLI's lifts
(glorfindel/gestures.py), the check after (``approval.verify_approved``) and a ``verification_failed``
card when it is not ``True``, the card settled. The guards of the model (the confidence gate, the
mode) are not replayed: a human's approval is what they wait for.
"""
from __future__ import annotations

import collections
import concurrent.futures
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from eregion_core import action_queue as aq
from eregion_core import channel_reader

POLL_S = 1.0
PER_POLL = 16                 # requests judged per service and per poll
SCAN_MAX = 512                # entries of a queue's directory looked at per poll
IN_FLIGHT = 4                 # requests executing at once (each under its VM's lock)
RECEIPT_KEEP_S = 2 * 3600     # a receipt kept while its request may still be there (an hour)
CRITICAL_EVERY_S = 3600       # at most one critical card per service and per hour
STATUS_EVERY_S = 10
RESULT_BYTES = 16 * 1024
# The verbs that need a card, and the verbs a card may be named for without (§2.2).
CARD_ONLY = frozenset({"isolate_vm", "block_ip"})
# A verb's action, as the connector, the cards and the feed name it.
ACTION_OF_VERB = {"isolate_vm": "isolate_vm", "block_ip": "block_suspicious_ip", "snapshot": "snapshot",
                  "release_isolation": "release_isolation", "reset": "reset", "unblock_ip": "unblock_ip",
                  "promote_block": "block_suspicious_ip"}


def _iso(at: datetime) -> str:
    return at.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _plain(value, limit: int = RESULT_BYTES):
    """What the connector returned, as JSON (a date said as text), bounded: a receipt is read by
    the console within its limit, and signed whole."""
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError, RecursionError):
        return {"unreadable": True}
    if len(text) > limit:
        status = value.get("status") if isinstance(value, dict) else None
        return {"truncated": True, "status": str(status)[:80] if status is not None else None}
    return json.loads(text)


def _vm(resource_id: str) -> str:
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1]


class _Guard(Exception):
    """A guard of the gesture refuses (§2.9) — said as ``guard``, with its reason."""


class QueueWatch:
    """The watch's side of the queue. ``poll`` judges what is waiting (the tests call it; ``start``
    runs it every POLL_S in a thread of its own). ``inline``: a request accepted runs in the poll
    itself (the tests), else in a worker of its own."""

    def __init__(self, signer, connector, *, root=None, pins: dict | None = None, pin_errors=(),
                 seen=None, consumed=None, rate=None, read_only: bool | None = None, say=print,
                 environ=None, inline: bool = False):
        self.signer = signer
        self.connector = connector
        self.root = root
        if pins is None:
            pins, pin_errors = aq.pinned_keys()
        self.pins = dict(pins)
        self.pin_errors = list(pin_errors)
        self.seen = seen if seen is not None else aq.SeenFile()
        self.consumed = consumed if consumed is not None else aq.ConsumedFile()
        self.rate = rate if rate is not None else aq.Rate()
        if read_only is None:
            read_only = bool(getattr(connector, "read_only", False))
        self.read_only = read_only
        self.say = say
        self.environ = os.environ if environ is None else environ
        self.inline = inline
        self.since = datetime.now(timezone.utc)
        self.refused: collections.Counter = collections.Counter()
        self._critical_at: dict[str, float] = {}
        self._judged: dict[tuple[str, str], float] = {}
        self._said: set[tuple[str, str, int]] = set()
        self._lock = threading.Lock()
        self._pool = None if inline else concurrent.futures.ThreadPoolExecutor(
            max_workers=IN_FLIGHT, thread_name_prefix="queue-run")
        self._in_flight = threading.BoundedSemaphore(IN_FLIGHT)
        self._last_status = 0.0

    # ── The receipts ─────────────────────────────────────────────────────────────────

    def _receipt(self, service: str, request_id: str, state: str, *, request: aq.Request | None = None,
                 code: str = "", reason: str = "", result=None, verification=None, now=None) -> dict:
        body = {
            "request": request_id, "service": service,
            "verb": request.verb if request else "", "resource_id": request.resource_id if request else "",
            "ip": request.ip if request else "", "scope": request.scope if request else "",
            "card": request.card_id if request else None,
            "state": state, "code": code, "reason": str(reason)[:1000],
            "result": _plain(result) if result is not None else None,
            "verification": _plain(verification) if verification is not None else None,
            "at": _iso(now or datetime.now(timezone.utc)),
        }
        doc = aq.sign_watch("receipt", body, self.signer)
        path = aq.receipt_path(service, request_id, self.root)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        channel_reader.write_file(path, json.dumps(doc, sort_keys=True), mode=0o644)
        return doc

    def recover(self, now: datetime | None = None) -> int:
        """At the start: a receipt still ``received`` or ``accepted`` was cut by a stop of the watch —
        between its claim and its end. Said ``failed``, never run again: the VM's state is to be
        checked, and the request asked again. How many."""
        now = now or datetime.now(timezone.utc)
        n = 0
        try:
            entries = list(os.scandir(aq.receipts_dir(self.root)))
        except OSError:
            return 0
        for e in entries:
            name = e.name
            if not name.endswith(".json") or "-" not in name:
                continue
            service, _, rest = name.partition("-")
            request_id = rest[:-5]
            if service not in aq.SERVICES:
                continue
            doc = aq.read_receipt(service, request_id, root=self.root)
            if doc is None or doc["state"] not in ("received", "accepted"):
                continue
            req = _Said(doc)
            self._receipt(service, request_id, "failed", request=req, code="interrupted",
                          reason=("the watch stopped while it judged or ran this request: nothing is run "
                                  "again — check the VM's state, then ask again"), now=now)
            n += 1
        return n

    # ── One poll ─────────────────────────────────────────────────────────────────────

    def _waiting(self, service: str) -> list[Path]:
        """The requests of this service not judged yet, oldest first — at most PER_POLL, among
        SCAN_MAX entries; a name that is not a nonce passed over and said once."""
        directory = aq.request_dir(service, self.root)
        found = []
        try:
            with os.scandir(directory) as it:
                for i, e in enumerate(it):
                    if i >= SCAN_MAX:
                        break
                    if e.name.startswith(".") or not e.name.endswith(".json"):
                        continue
                    stem = e.name[:-5]
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not aq._ID.fullmatch(stem):
                        key = (service, e.name, st.st_mtime_ns)
                        if key not in self._said:
                            self._said.add(key)
                            self.refused["malformed"] += 1
                            self.say(f"file d'actions : {service}/queue/{e.name[:60]!r} n'est pas une demande "
                                     "(son nom n'est pas son nonce) : jamais lue")
                        continue
                    if (service, stem) in self._judged:
                        continue
                    if aq.receipt_path(service, stem, self.root).exists():
                        self._judged[(service, stem)] = time.time()
                        continue
                    found.append((st.st_mtime_ns, e.name, Path(e.path)))
        except OSError:
            return []
        return [p for _, _, p in sorted(found)[:PER_POLL]]

    def poll(self, now: datetime | None = None) -> list[dict]:
        """Judge what waits in each service's queue; the receipts written now (accepted ones run:
        inline, or in a worker). Never raises."""
        out = []
        for service in aq.SERVICES:
            for path in self._waiting(service):
                try:
                    out.append(self.judge(service, path, now or datetime.now(timezone.utc)))
                except Exception as exc:   # a request never stops the queue
                    self.say(f"file d'actions : {service}/{path.name} — erreur {type(exc).__name__}: {exc}")
        try:
            self.status(now or datetime.now(timezone.utc))
        except Exception as exc:
            self.say(f"file d'actions : statut non écrit ({exc})")
        return out

    def judge(self, service: str, path: Path, now: datetime) -> dict:
        request_id = path.name[:-5]
        self._judged[(service, request_id)] = time.time()
        self._receipt(service, request_id, "received", now=now)
        req = None
        try:
            try:
                data = aq.read_request(path)
            except FileNotFoundError:
                raise aq.Refused("malformed", "gone before it was read") from None
            req = aq.verify_request(data, service=service, pins=self.pins, now=now, seen=self.seen, rate=self.rate)
            if req.id != request_id:
                raise aq.Refused("malformed", "its name is not its nonce")
            card, proposal = self._attach(req)
            ctx = self._guards(req, card, proposal, now)
            if self.read_only:                                   # 12. the posture
                raise aq.Refused("read_only")
            if proposal is not None:
                try:
                    fresh = self.consumed.consume(req.proposal, req.card_id, now)
                except (OSError, ValueError) as e:
                    raise aq.Refused("seen_store_unavailable", f"{aq.REFUSALS['seen_store_unavailable']} "
                                                               f"({str(e)[:120]})") from None
                if not fresh:
                    raise aq.Refused("proposal_consumed")
        except aq.Refused as r:
            return self._refuse(service, request_id, req, r, now)
        except _Guard as g:
            return self._refuse(service, request_id, req, aq.Refused("guard", str(g)), now)
        accepted = self._receipt(service, request_id, "accepted", request=req, now=now)
        self.say(f"file d'actions : {service} demande {req.verb} sur {_vm(req.resource_id)} — acceptée")
        if self._pool is None:
            return self._run(service, req, card, ctx)
        self._in_flight.acquire()

        def _done(_future):
            self._in_flight.release()
        self._pool.submit(self._run, service, req, card, ctx).add_done_callback(_done)
        return accepted

    def _refuse(self, service: str, request_id: str, req, refused: aq.Refused, now: datetime) -> dict:
        self.refused[refused.code] += 1
        self.say(f"file d'actions : {service} {request_id[:8]} refusée — {refused.code} : {refused.reason}")
        if refused.critical or refused.code == "seen_store_unavailable":
            self._card(service, refused, now)
        return self._receipt(service, request_id, "refused", request=req, code=refused.code,
                             reason=refused.reason, now=now)

    def _card(self, service: str, refused: aq.Refused, now: datetime) -> None:
        """A card decided by the code (§2.11): no model, no action — at most one per service and per
        hour."""
        critical = refused.critical
        key = f"{service}:{'critical' if critical else 'register'}"
        at = time.time()
        with self._lock:
            if at - self._critical_at.get(key, -CRITICAL_EVERY_S) < CRITICAL_EVERY_S:
                return
            self._critical_at[key] = at
        try:
            from glorfindel import escalations
            if critical:
                reason = (f"File d'actions de {service} : une demande refusée ({refused.code} — "
                          f"{refused.reason[:300]}). Quelqu'un écrit dans la file de ce service sans être lui, ou "
                          "la rejoue : examiner l'hôte (qui écrit runs/" + service + "/queue/), la clé épinglée "
                          "(EREGION_QUEUE_KEYS) et la clé du service. Aucune action n'est prise.")
                etype, severity = "queue_tampered", "critical"
            else:
                reason = (f"File d'actions : le registre de la watch ne se lit ou ne s'écrit pas "
                          f"({refused.reason[:300]}) — aucune demande n'est prise tant qu'il ne se tient pas "
                          "(~/.eregion/watch-queue/).")
                etype, severity = "queue_unavailable", "high"
            escalations.record(signal_id=f"queue-{service}-{refused.code}", resource_id=f"~/runs/{service}/queue",
                               action="none", escalation_type=etype, reason=reason, severity=severity,
                               source="real")
        except Exception as exc:
            self.say(f"file d'actions : carte non écrite ({exc})")

    # ── Step 10, the attachment ──────────────────────────────────────────────────────

    def _attach(self, req: aq.Request) -> tuple[dict | None, dict | None]:
        """(the card, its proposal) a request is bound to, or (None, None) for a verb that acts on
        what the watch holds. Raises Refused."""
        if req.card_id is None:
            if req.verb in CARD_ONLY or req.service == "bot":
                raise aq.Refused("proposal_missing", f"{req.verb} goes through its card, and its proposal")
            return None, None
        from glorfindel import escalations
        card = next((e for e in escalations.all_escalations() if e.get("id") == req.card_id), None)
        try:
            consumed = self.consumed.digests()
        except (OSError, ValueError) as e:
            raise aq.Refused("seen_store_unavailable", f"{aq.REFUSALS['seen_store_unavailable']} ({str(e)[:120]})") from None
        aq.proposal_refusal(card, req, watch_public=self.signer.public, consumed=consumed)
        return card, card["proposal"]

    # ── Step 11, the guards of the gesture (glorfindel/approval.py) ──────────────────

    def _guards(self, req: aq.Request, card, proposal, now: datetime) -> dict:
        from glorfindel import approval
        rid, vm = req.resource_id, _vm(req.resource_id)
        ctx: dict = {}
        # Step 10 for a verb without a card: what the watch holds for this VM, or this address.
        if req.verb == "release_isolation" and card is None:
            if not approval.held_isolation(rid):
                raise aq.Refused("nothing_to_undo", f"no isolation the watch holds on {vm[:64]}")
        elif req.verb == "reset" and card is None:
            if not (approval.held_isolation(rid) or approval.held_blocks(rid)):
                raise aq.Refused("nothing_to_undo", f"nothing the watch holds on {vm[:64]}")
        elif req.verb in ("unblock_ip", "promote_block"):
            block = approval.held_block(rid, req.ip)
            if block is None:
                raise aq.Refused("nothing_to_undo", f"no block of {req.ip[:45]!r} the watch holds on {vm[:64]}")
            ctx.update(ip=block["ip"], block_rid=block.get("resource_id") or rid, scoped=block.get("scoped", True))
        # Step 11, the guards of the gesture.
        if not approval.in_perimeter(rid):
            raise _Guard(f"{vm[:64]!r} n'est pas une VM du périmètre de la watch")
        if card is not None and req.verb != "reset":
            why = approval.approval_refusal(card, vm, dated=proposal["issued_at"], now=now)
            if why:
                raise _Guard(why)
        if req.service == "bot":
            why = approval.discord_refusal(req.by, self.environ)
            if why:
                raise _Guard(why)
        if req.verb == "block_ip":
            ip = proposal["ip"] or req.ip
            if not ip:
                raise _Guard("la carte ne porte pas l'adresse : la nommer (ip)")
            ip, why = approval.address_refusal(ip)
            if why:
                raise _Guard(why)
            why = approval.scope_refusal(req.scope)
            if why:
                raise _Guard(why)
            ctx.update(ip=ip, scope=req.scope, port=proposal["port"])
        elif req.verb == "snapshot":
            from glorfindel.config import NO_VAULT_MSG, resolve_backup_vault
            vault, vault_rg, _ = resolve_backup_vault()
            if not vault:
                raise _Guard(NO_VAULT_MSG)
            ctx.update(vault=vault, vault_rg=vault_rg)
        elif req.verb == "promote_block":
            if req.scope not in ("", "vm"):
                raise _Guard(f"une promotion part d'un blocage de la VM (scope vm), pas {req.scope[:20]!r}")
            if ctx["scoped"] is False:
                raise _Guard(f"{ctx['ip']} est déjà bloquée pour tout le sous-réseau")
        return ctx

    # ── The execution ────────────────────────────────────────────────────────────────

    def _run(self, service: str, req: aq.Request, card, ctx: dict) -> dict:
        """Under the VM's lock, with the watch's own functions; the receipt ``done`` or ``failed``.
        Never raises."""
        from glorfindel.response.locks import _vm_lock
        try:
            with _vm_lock(_vm(req.resource_id)):
                state, result, verification, reason = getattr(self, f"_do_{req.verb}")(req, card, ctx)
        except Exception as exc:
            state, result, verification = "failed", None, None
            reason = f"{type(exc).__name__}: {str(exc)[:300]}"
        self.say(f"file d'actions : {service} {req.verb} sur {_vm(req.resource_id)} → {state}"
                 + (f" ({reason[:200]})" if reason else ""))
        try:
            return self._receipt(service, req.id, state, request=req, result=result,
                                 verification=verification, reason=reason)
        except Exception as exc:
            self.say(f"file d'actions : reçu {req.id[:8]} non écrit ({exc})")
            return {}

    def _settle(self, card) -> None:
        if card is not None:
            from glorfindel import escalations
            escalations.resolve(card["id"], note="exécutée par la file d'actions (FS1b)")

    def _check(self, req, card, action: str, result, ip: str = "") -> dict:
        """``approval.verify_approved``; a card ``verification_failed`` it leaves bears the request's
        own signal (FS1c: ``queue-<service>-<id>``, as its receipt — never the console's
        ``approve-<card>``)."""
        from glorfindel import approval
        return approval.verify_approved(self.connector, card or {"id": ""}, action, req.resource_id, result, ip,
                                        signal_id=f"queue-{req.service}-{req.id}")

    def _do_isolate_vm(self, req, card, ctx):
        result = self.connector.isolate_vm(req.resource_id)
        self._settle(card)
        return "done", result, self._check(req, card, "isolate_vm", result), ""

    def _do_block_ip(self, req, card, ctx):
        result = self.connector.block_suspicious_ip(ctx["ip"], req.resource_id, ctx["scope"], False, ctx["port"])
        self._settle(card)
        return "done", result, self._check(req, card, "block_suspicious_ip", result, ctx["ip"]), ""

    def _do_snapshot(self, req, card, ctx):
        from glorfindel.jobs import start_snapshot
        job = start_snapshot(req.resource_id, self.connector, ctx["vault"], vault_rg=ctx["vault_rg"])
        self._settle(card)
        return "done", {"status": "started", "job_id": job.get("job_id")}, None, ""

    def _do_release_isolation(self, req, card, ctx):
        from glorfindel.gestures import release_needed
        if not release_needed(self.connector, req.resource_id):
            self._settle(card)
            return "done", {"status": "nothing_to_release"}, None, "no isolation rule on Azure: state cleared"
        result = self.connector.release_isolation(req.resource_id)
        if result.get("status") == "release_partial":
            return "failed", result, None, "released in part: rules still in place — " + "; ".join(
                str(x) for x in result.get("failed", []))[:600]
        self._settle(card)
        return "done", result, self._check(req, card, "release_isolation", {"status": "released"}), ""

    def _do_reset(self, req, card, ctx):
        from glorfindel.gestures import reset_apply, reset_targets
        isolations, blocks = reset_targets(req.resource_id)
        if not isolations and not blocks:
            self._settle(card)
            return "done", {"status": "clean", "note": "nothing to reset"}, None, ""
        leftovers = reset_apply(self.connector, req.resource_id, isolations, blocks)
        if leftovers:
            return "failed", {"status": "partial", "failed": leftovers}, None, "reset incomplete — " + "; ".join(
                str(x) for x in leftovers)[:600]
        self._settle(card)
        return "done", {"status": "clean"}, None, ""

    def _do_unblock_ip(self, req, card, ctx):
        result = self.connector.unblock_ip(ctx["ip"], ctx["block_rid"])
        if result.get("status") == "unblock_partial":
            return "failed", result, None, "unblocked in part: rules still in place"
        return "done", result, None, ("no block rule found (already removed?)"
                                      if result.get("status") == "not_found" else "")

    def _do_promote_block(self, req, card, ctx):
        result = self.connector.block_suspicious_ip(ctx["ip"], ctx["block_rid"], "subnet", True)
        return "done", result, None, ""

    # ── The status, the thread ───────────────────────────────────────────────────────

    def status(self, now: datetime, force: bool = False) -> dict | None:
        """``runs/glorfindel/queue/status.json``, signed: the posture, the keys pinned per service,
        since when the queue is picked up, the refusals counted. At most every STATUS_EVERY_S; the
        receipts older than RECEIPT_KEEP_S whose request is gone removed."""
        at = time.time()
        if not force and at - self._last_status < STATUS_EVERY_S:
            return None
        self._last_status = at
        from eregion_core import watch_key
        body = {"posture": "read_only" if self.read_only else "write",
                "pins": {s: (watch_key.fingerprint(self.pins[s]) if s in self.pins else "") for s in aq.SERVICES},
                "pin_errors": [str(e)[:200] for e in self.pin_errors][:10],
                "since": _iso(self.since), "at": _iso(now), "refused": dict(sorted(self.refused.items()))}
        doc = aq.sign_watch("status", body, self.signer)
        path = aq.receipts_dir(self.root) / aq.STATUS_NAME
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        channel_reader.write_file(path, json.dumps(doc, sort_keys=True), mode=0o644)
        self._sweep(at)
        return doc

    def _sweep(self, at: float) -> None:
        try:
            entries = list(os.scandir(aq.receipts_dir(self.root)))
        except OSError:
            return
        for e in entries:
            if e.name == aq.STATUS_NAME or not e.name.endswith(".json") or "-" not in e.name:
                continue
            service, _, rest = e.name.partition("-")
            try:
                if at - e.stat(follow_symlinks=False).st_mtime < RECEIPT_KEEP_S:
                    continue
                if service in aq.SERVICES and (aq.request_dir(service, self.root) / rest).exists():
                    continue
                os.unlink(e.path)
            except OSError:
                continue
        cutoff = at - RECEIPT_KEEP_S
        self._judged = {k: v for k, v in self._judged.items() if v > cutoff}

    def one_pass(self) -> None:
        """One pass of the thread: ``poll``, whatever it raises said — the thread never dies in
        silence."""
        try:
            self.poll()
        except Exception as exc:
            try:
                self.say(f"file d'actions : passage en erreur — {type(exc).__name__}: {exc}")
            except Exception:
                pass

    def start(self) -> threading.Thread:
        """The queue picked up every POLL_S, in a thread of its own — never the watch's loop."""
        self.recover()
        self.status(datetime.now(timezone.utc), force=True)

        def _loop():
            while True:
                self.one_pass()
                time.sleep(POLL_S)
        t = threading.Thread(target=_loop, daemon=True, name="action-queue")
        t.start()
        return t


class _Said:
    """A request as its receipt says it (``recover``): its fields, no more."""

    def __init__(self, doc: dict):
        self.verb, self.resource_id = doc.get("verb", ""), doc.get("resource_id", "")
        self.ip, self.scope, self.card_id = doc.get("ip", ""), doc.get("scope", ""), doc.get("card")


def start(connector, signer_of, *, say=print, root=None) -> QueueWatch | None:
    """The watch's queue (glorfindel/cli.py, ``watch``): started only behind EREGION_ACTION_QUEUE=1,
    and with the watch's key — without it, no proposal can be checked: nothing is picked up, said."""
    if not aq.enabled():
        return None
    signer = signer_of()
    if signer is None:
        say("File d'actions : la clé de la watch est indisponible — la file n'est pas relevée")
        return None
    pins, wrong = aq.pinned_keys()
    # FS1c: the start says each key that is missing or wrong — the same words as host_env.py --check.
    for line in aq.pin_problems(pins, wrong):
        say(f"File d'actions : {line}")
    q = QueueWatch(signer, connector, root=root, pins=pins, pin_errors=wrong, say=say)
    q.start()
    say(f"File d'actions relevée : runs/console/queue, runs/bot/queue → runs/glorfindel/queue "
        f"({'lecture seule' if q.read_only else 'écriture'})")
    return q
