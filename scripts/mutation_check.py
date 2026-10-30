"""Measure the invariant suite by mutation (sixth review, L26).

Each mutant re-introduces a bug Glorfindel actually had — the classes the reviews
found — or, for a lot of the eighth pass, a bug its specification names, as an exact
text replacement in a throwaway copy of the repository, then runs its tests on it:
tests/unit/test_invariants.py, or the tests named for it in TESTS. A mutant the suite fails on is CAUGHT; one it
passes on SURVIVES. A mutant whose text no longer matches the code is STALE (fix the
mutant, the code moved) — never counted as caught.

    python scripts/mutation_check.py                       # push budget (60), 3 rounds
    python scripts/mutation_check.py --examples 1000 --rounds 2
    python scripts/mutation_check.py --only M04,M13

Each round draws new seeds. The table says, per mutant, how many rounds caught it.
A mutant the invariants can't see by construction says why: EQUIVALENT (no behaviour
of the fake world tells it apart), MULTI-HOST (needs a second host writing between two of
our calls — the locks are per host; a unit test covers it).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# glorfindel/actions.py was split by concern (A1): each mutant follows its code.
STA = "glorfindel/response/state.py"
AZC = "glorfindel/providers/azure/connector.py"
NSG = "glorfindel/providers/azure/nsg.py"
NET = "glorfindel/providers/azure/network.py"
QUA = "glorfindel/providers/azure/quarantine.py"
ISO = "glorfindel/providers/azure/isolation.py"
REL = "glorfindel/providers/azure/release.py"
VER = "glorfindel/providers/azure/verify.py"
UNB = "glorfindel/providers/azure/unblock.py"
VBL = "glorfindel/providers/azure/verify_block.py"   # out of unblock.py (I4B)
SWP = "glorfindel/providers/azure/sweep.py"
SDK = "glorfindel/providers/azure/sdk.py"
FAC = "glorfindel/actions.py"                 # the façade (A1)
PIF = "glorfindel/providers/interface.py"
R = "glorfindel/reassert.py"
RQ = "glorfindel/reassert_quarantine.py"       # split out of reassert.py (RB1)
C = "glorfindel/config.py"
INS = "eregion_core/inscription.py"
ENG = "annatar/runner/engine.py"
EXE = "annatar/executors/azure_vm.py"
ATO = "annatar/engines/atomic.py"
SYN = "annatar/campaign/synthesizer.py"
CRUN = "annatar/campaign/runner.py"
MAKE = "Makefile"
CATSCHEMA = "schemas/technique_catalog.schema.json"
WCH = "eregion_core/watch_channel.py"
GOTH = "gothmog/runner/engine.py"
DET = "annatar/runner/detection.py"
CREP = "analysis/campaign_report.py"
KILL = "infra/orodruin/kill.py"
HREP = "analysis/hosted_report.py"
XCH = "eregion_core/exercise_channel.py"
ACLI = "annatar/cli.py"
GCLI = "glorfindel/cli.py"
CON = "eregion_console/api.py"
SEC = "eregion_console/sections.py"
IND = "eregion_console/indicators.py"
GJS = "eregion_console/static/glorfindel.js"      # the Glorfindel page's script (#257)
CESC = "scripts/console_escaping.py"
XW = "eregion_core/exercise.py"
INVARIANTS = "tests/unit/test_invariants.py"
INSCRIPTION_TESTS = "tests/unit/test_inscription.py tests/unit/test_engine.py"
DOCS_TESTS = "tests/unit/test_docs_budget.py"
BOUNDARY_TESTS = "tests/unit/test_provider_boundary.py"
DETECTION_TESTS = "tests/unit/test_annatar_detection.py tests/unit/test_engine.py"
# A mutant whose "old" text is RENAME renames its file to "new" instead of editing it.
RENAME = object()
# A mutant whose "old" and "new" are tuples makes several edits in its file, pair by pair
# (old[i] -> new[i]), each old text matching exactly once — for a bug that needs two places.

# D-2: the lines of analysis/campaign_report.py that read a date in words, a range of them too
# (M513, M537) — as D2b left them.
_DATES_FIRST = r'''    rf"|(?:\b(?:le|les|entre|du|des|aux|(?:on|from|between)\s+the|between|from|on)\s+{_DAY}{_TH}"''' + "\n"
_DATES_AU = r'''    rf"|\bau\s+{_DAY}{_TH}(?:\s*(?:,|\bet\b)\s*au\s+{_DAY}{_TH})+"''' + "\n"
_DATES_LINE = (_DATES_FIRST
               + r'''    rf"(?:\s*(?:,|-|–|\bet\b|\bau\b|\bà\b|\band\b|\bto\b)\s*(?:(?:le|du|des|au|aux|the)\s+)?{_DAY}{_TH})+"''' + "\n"
               + _DATES_AU
               + r'''    rf"|\b\d{{1,2}}(?:er|st|nd|rd|th)?)\s+(?:{_MONTHS})\b"''' + "\n")

# V1 (#214): the checks of a live Glorfindel watch, as they stand — M721 and M725 move them
# after the first call to the cloud (Orodruin's contract).
_V1_ANNATAR_GATE = (
    "        if self.without_glorfindel:\n"
    '            console.print(f"[yellow]{watch_gate.FLAG}: a development run — "\n'
    '                          f"{watch_gate.NOT_MEASURED}.[/yellow]")\n'
    "        else:\n"
    "            no_watch = watch_gate.refusal()\n"
    "            if no_watch:\n"
    '                console.print(f"[red]Refused — no live Glorfindel watch:[/red] {no_watch}")\n'
    '                return RunOutcome(run_id, "unknown", error=f"glorfindel: {no_watch}", refused=True)\n')
_V1_ANNATAR_ARM = '        verdict, session = arm(run_id, "annatar")\n'
_V1_GOTHMOG_GATE = (
    "        refused = self._no_watch(run_id, without_glorfindel)\n"
    "        if refused:\n"
    "            return refused\n"
    "        self._without = watch_gate.without_metrics(without_glorfindel)\n")
_V1_GOTHMOG_BENCH = "        bench = self._bench_factory(session)\n"
_V1_WAIT = ("not self.dry_run \\\n"
            "                and not self.without_glorfindel:  # not measured, by choice: no wait\n")

# (id, bug class, file, text in the code today, text that re-introduces the bug[, why
# the invariants can't see it])
MUTANTS = [
    ("M01", "rule name without the NIC hash (homonyms share a name)", NET,
     'base = f"{prefix}-{vm_name}-{nic_short}-{_nic_hash(nic_id, 6)}"',
     'base = f"{prefix}-{vm_name}-{nic_short}"'),
    ("M02", "deny any/any on a shared NIC NSG", NET,
     "        return len(nics) > 1 or len(subnets) > 0",
     "        return False"),
    ("M03", "deny scoped to the NIC's first IP only", ISO,
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"], src="*", dsts=ips)',
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"], src="*", dsts=ips[:1])'),
    ("M04", "outbound allows ignored by the precedence check", NSG,
     '        elif direction == "outbound":\n            src, dst = outbound_src, outbound_dst',
     '        elif direction == "outbound":\n            continue'),
    ("M05", "verify_release ignores a quarantine NSG still attached", VER,
     "                  for t0 in targets if t0.get(\"quarantine\")]",
     "                  for t0 in targets if False]"),
    ("M06", "state deleted right after it is written (C1's effect)", STA,
     "    _atomic_write_text(target, json.dumps(payload))\n",
     "    _atomic_write_text(target, json.dumps(payload))\n    if name != name.lower():\n        target.unlink()\n"),
    ("M07", "release sweeps the NICs only when there is no state", REL,
     "        failed += self._sweep_isolation(rg, vm_name, remaining, known, resource_id)",
     "        failed += [] if state.get(\"placements\") else self._sweep_isolation(rg, vm_name, remaining, known,"
     " resource_id)"),
    ("M08", "fallback deny any/any on an NSG that only looks dedicated", NSG,
     '    return bool(target.get("private_ips")) or _ip_scoped(target)',
     "    return _ip_scoped(target)"),
    ("M09", "a missing original tag read as 'no NSG' (Q7)", QUA,
     "        if not value:\n            raise OriginalUnknown(",
     "        if not value:\n            return None\n            raise OriginalUnknown("),
    ("M10", "an unreadable subnet read as 'no subnet NSG'", NET,
     "                subnet_nsg, subnet_unreadable = None, True",
     "                subnet_nsg, subnet_unreadable = None, False"),
    ("M11", "_is_not_found by substring", SDK,
     "    # No substring guess:",
     "    if \"not found\" in str(exc).lower():\n        return True\n    # No substring guess:",
     "EQUIVALENT: no call site sees a non-404 'not found' since the release re-reads the NIC"),
    ("M12", "isolation verified by rule name, not content", REL,
     '                    and _deny_isolates(r_in, "inbound", ips) and _deny_isolates(r_out, "outbound", ips)):',
     "                    ):"),
    ("M13", "reassertion ignores a release that has started", "glorfindel/reassert.py",
     "    return bool(state.get(\"partial\") or state.get(failed_key) or state.get(running_key))",
     "    return bool(state.get(\"partial\") or state.get(failed_key))"),
    ("M14", "release does not read the NIC back", QUA,
     "            if not _same_id(now or \"\", original or \"\"):",
     "            if False:"),
    ("M15", "an unreadable config falls back to the defaults (S1)", QUA,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except Exception:\n            return True, \"\"\n"),
    ("M16", "blocks verified by rule name, not content (S2)", VBL,
     "        altered = [n for n, r, d in zip(names, found, (\"inbound\", \"outbound\")) if not _deny_blocks(r, d, ip, ips)]",
     "        altered = []"),
    ("M17", "per-VM lock inoperative", AZC,
     "        with _vm_lock(rid.rstrip(\"/\").rsplit(\"/\", 1)[-1]):\n            return method(self, *args, **kwargs)",
     "        return method(self, *args, **kwargs)"),
    # Found by L26 itself (the world moving): kept so they stay found.
    ("M18", "a NIC's old-IP rule recognised by content only (L26)", NSG,
     "    if name in hashed:\n        # Only Glorfindel names a rule with a NIC's hash",
     "    if name in hashed and _deny_applies(rule, ips):\n        # Only Glorfindel names a rule with a NIC's hash"),
    ("M19", "a block verified against the IPs recorded at block time (L26)", VBL,
     "                now = current.get(nic) if current is not None and isinstance(nic, str) else None",
     "                now = None"),
    ("M20", "release asks for the original of a NIC no longer in quarantine (L26)", REL,
     "                        if now and not _same_id(now, p[\"nsg_id\"]):",
     "                        if False:"),
    ("M21", "a block counted on an NSG that no longer governs the NIC (L26)", VBL,
     '                    off = [p for p in ps if (p["nsg_rg"].lower(), p["nsg_name"].lower()) not in governing]',
     "                    off = []"),
    ("M22", "a partial release's flat fields read as a legacy state (L26)", REL,
     '        elif "placements" not in state and state.get("nsg_name") and not _is_quarantine_nsg(state["nsg_name"]):',
     '        elif state.get("nsg_name"):'),
    ("M23", "an unblock doesn't look behind the quarantine (L27)", UNB,
     # Followed into _original_away (U3F), which looks behind a bare NIC too.
     '        if not q and t0.get("own_nsg_id"):\n            return None',
     '        if q or t0.get("own_nsg_id"):\n            return None'),
    ("M24", "reset --from-azure reads the original from the tag only (L27)", SWP,
     # The state skipped: the tag decides (the code moved, I8S review — same bug).
     "                original = _recorded_original(t0[\"nic_id\"])\n                if original is _UNKNOWN:\n"
     "                    original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])\n",
     "                original = _UNKNOWN\n                if original is _UNKNOWN:\n"
     "                    original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])\n"),
    ("M25", "a partial reset leaves the state unmarked (L27)", SWP,
     "        elif not dry_run:\n            # Part of it is gone from Azure",
     "        elif False:\n            # Part of it is gone from Azure",
     "EQUIVALENT: since A0 the reset records its intent (releasing_at / unblocking_at) before "
     "touching Azure — a partial reset's state is held by that marker either way; the failure "
     "mark only changes the operator's wording"),
    ("M26", "a NIC left without an NSG: the release moves on (L28, U2)", REL,
     "                        if now is None:\n                            # Detached from our NSG",
     "                        if False:\n                            # Detached from our NSG"),
    ("M27", "an unreadable config hides an emptied quarantine NSG (L28, U4)", QUA,
     "            wanted = self._quarantine_wanted(with_forensic=False)\n            forensic_known = False",
     "            raise\n            forensic_known = False"),
    ("M28", "orphan rules not reported (L28, U1)", SWP,
     "                if (len(mark) not in (6, 8) or any(c not in \"0123456789abcdef\" for c in mark)\n"
     "                        or mark in marks or mark in live_names):",
     "                if True:"),
    ("M29", "a bare NIC isolated again records 'none' over its original (L28, U2)", QUA,
     "            if original is None:\n                # A bare NIC may have been in our quarantine before",
     "            if False:\n                # A bare NIC may have been in our quarantine before"),
    ("M30", "the quarantine swap is not read back (A0)", QUA,
     '            if not _same_id(now or "", q["nsg_id"]):',
     "            if False:"),
    ("M31", "one deny's priority used for both directions (A0)", VER,
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": out if isinstance(out, int) else prio},',
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": prio},'),
    ("M32", "an outbound allow before a block counted as exposure (A0)", NSG,
     '                    port is None or direction == "outbound" or _rule_covers_port(r, port)),',
     '                    port is None or (direction == "inbound" and _rule_covers_port(r, port))),'),
    ("M33", "an unowned old fixed-name rule on a non-dedicated NSG ignored (A0)", REL,
     '        if not (t.get("sharing_unknown") or _ip_scoped(t)):\n            return []',
     '        if True:\n            return []'),
    ("M34", "verify_release ignores the old single-NSG state (A0)", VER,
     "            rules = self._list_rules(cache, l_rg, l_name)\n            names =",
     "            rules = []\n            names ="),
    ("M35", "reset --from-azure records no intent (A0)", SWP,
     '            if state:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})',
     '            if False:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})'),
    ("M36", "the old state file removed after the new one is written (A0)", STA,
     "    if olds and not target.exists():",
     "    if False:"),
    ("M37", "reassertion alerts keyed by the VM's name (A0, L1)", "glorfindel/reassert.py",
     '    return f"reassert-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")',
     '    return f"reassert-{vm}" + (f"-{ip}" if ip else "")'),
    ("M38", "a block gone behind the quarantine not reported (A0, L1)", VBL,
     "                                    held_missing += names",
     "                                    pass"),
    ("M39", "reset reads a bare NIC's original from the tag only (A0)", SWP,
     "            if recorded is not _UNKNOWN:\n                original = recorded\n            elif q_bare is None:",
     "            if False:\n                original = recorded\n            elif q_bare is None:"),
    ("M40", "a deleted NSG's listing read as unreadable (A0, L1)", NET,
     "                cache[key] = [] if _is_not_found(exc) else None",
     "                cache[key] = None"),
    ("M41", "reset doesn't sweep the original it puts back on a bare NIC (A0)", SWP,
     '            bare[t0["nic_id"]] = (original, q_bare)\n            if original:\n                views.append(self._original_view(t0, original))',
     '            bare[t0["nic_id"]] = (original, q_bare)'),
    # O0 (eighth pass): the six bugs the inscription's specification names.
    ("M42", "the execution-time inscription check removed (O0)", ENG,
     '        if not guard.allowed:\n            console.print(f"[red]Safety check failed:[/red] {guard.reason}")',
     '        if False:\n            console.print(f"[red]Safety check failed:[/red] {guard.reason}")'),
    ("M43", "an empty bench id accepted (O0)", INS,
     "    if not bench or not bench.strip():\n        return GuardResult(False, \"empty bench id",
     "    if False:\n        return GuardResult(False, \"empty bench id"),
    ("M44", "a resource outside the bench's resource groups accepted (O0)", INS,
     "        if not (rg_ok or sandbox_ok):",
     "        if False:"),
    ("M45", "the tag value read without its case (O0)", INS,
     "        if value != bench:",
     "        if value.lower() != bench.lower():"),
    ("M46", "a destructive technique or a fault accepted in production (O0)", INS,
     '    if zone == "production":\n        if kind != "technique":',
     '    if False:\n        if kind != "technique":'),
    ("M47", "a missing zone read as the bench (O0)", INS,
     '    zone = target.zone or ("bench" if target.legacy else "")',
     '    zone = target.zone or "bench"'),
    # DX1: the two bugs its specification names.
    ("M48", "CLAUDE.md grows by 10 KB (DX1)", "CLAUDE.md",
     "## Ce qu'on ne fait PAS\n",
     "## Ce qu'on ne fait PAS\n\n" + "<!-- padding -->\n" * 640),
    ("M49", "a docs/ file the index points to is renamed (DX1)", "docs/azure.md",
     RENAME, "docs/azure-renamed.md"),
    # Sixth review, S8: the drain spared every session with the forensic host.
    ("M50", "the drain spares any session with a forensic source (S8)", ISO,
     'flt = flt[:-1] + f"and not ( dst {cidr} and ( {local} ) ) )"',
     'flt = flt[:-1] + f"and not dst {cidr} )"'),
    # Sixth review, S9: a verification that raised left the graph (cycle_failed, no Revert).
    ("M51", "a verification that raises leaves the graph (S9)", "glorfindel/agent.py",
     "    except Exception as exc:\n        first = str(exc).strip().splitlines()[0]",
     "    except Exception as exc:\n        raise\n        first = str(exc).strip().splitlines()[0]"),
    # Sixth review, S7: a quarantine refused at execution, unknown to the readiness gate.
    ("M52", "a quarantine refused at execution is not remembered (S7)", ISO,
     "        _remember_quarantine_outcome(resource_id, refused, placements)\n",
     "        pass\n"),
    ("M53", "the readiness gate ignores a remembered refusal (S7)", "glorfindel/readiness.py",
     "    refusal = quarantine_refusal(resource_id) if quarantine_nsg else None",
     "    refusal = None"),
    # H0: the hosted Glorfindel stays an observer.
    ("M54", "the pushed host config keeps the local autonomy (H0)", "infra/glorfindel-host/host_config.py",
     '    out["autonomy"] = {"default": "human_only"}\n', ""),
    ("M55", "the host gets a write role on the bench (H0)", "infra/glorfindel-host/main.tf",
     'role_definition_name = "Reader"', 'role_definition_name = "Contributor"'),
    ("M56", "empty service-principal vars stay set (H0: managed identity unreachable)", "glorfindel/cli.py",
     "    for k in dropped:\n        del environ[k]\n", ""),
    # B2 (storage side): an exercise window labels only what it names, for a bounded time.
    ("M57", "a window labels every VM, not its targets (B2)", "eregion_core/exercise.py",
     # The target check moved into _covers (O1 part C), then into _targets (H-1).
     "    return (resource_id.lower() in (window.get(\"targets\") or [])\n"
     "            and not window_refusal(window))\n",
     "    return not window_refusal(window)\n"),
    ("M58", "a window never closed never lapses (B2)", "eregion_core/exercise.py",
     "    end = _parse(window.get(\"end\")) or expires\n    # A window closed late still lapses at its expiry.\n"
     "    last = min(end, expires) + timedelta(seconds=GRACE_AFTER_S)\n",
     # #167: the bound now lives in last_moment, which has no `when` — a window never closed
     # gets no upper bound at all, a closed one keeps its own.
     "    end = _parse(window.get(\"end\"))\n"
     "    last = (min(end, expires) + timedelta(seconds=GRACE_AFTER_S)) if end else datetime.max.replace(tzinfo=timezone.utc)\n"),
    ("M59", "the observation report counts exercise cards (B2)", "glorfindel/escalations.py",
     "            exercises += 1\n            continue\n", "            exercises += 1\n"),
    ("M60", "an exercise card absorbs a real detection (B2)", "glorfindel/escalations.py",
     "                and (e.get(\"source\") or \"real\") == (source or \"real\")\n", ""),
    ("M61", "an Annatar run never closes its window (B2)", "annatar/runner/engine.py",
     "        try:\n            if scenario.engine == \"atomic\":\n                return self._run_atomic_enrolled(scenario, executor, run_id, session, resolved)\n            if scenario.engine == \"local-script\":\n                return self._run_enrolled(scenario, executor, run_id)\n            # Unreachable once validate did its job — the explicit table refuses the rest.\n            console.print(f\"[red]Engine not runnable:[/red] {scenario.engine!r}\")\n            return RunOutcome(run_id, \"unknown\", error=f\"engine: {scenario.engine!r} not runnable\")\n        finally:\n            close_window(run_id)\n",
     "        if scenario.engine == \"atomic\":\n            return self._run_atomic_enrolled(scenario, executor, run_id, session, resolved)\n        if scenario.engine == \"local-script\":\n            return self._run_enrolled(scenario, executor, run_id)\n        console.print(f\"[red]Engine not runnable:[/red] {scenario.engine!r}\")\n        return RunOutcome(run_id, \"unknown\", error=f\"engine: {scenario.engine!r} not runnable\")\n"),
    # #105: the boot batch's sub-second gaps set the step again (blind 10 min after a boot).
    ("M62", "the ransomware step reads the boot batch (#105)", "glorfindel/rules/azure/detection_rules.yaml",
     "summarize Step = minif(Gap, Gap >= 1s) by Vm, InstanceName", "summarize Step = min(Gap) by Vm, InstanceName"),
    # IA0: the check keeps a claim the cited runs contradict (« all detected » on a missed run).
    ("M63", "the report keeps a detected/missed claim the runs contradict (IA0)", "analysis/campaign_report.py",
     '        elif c.kind in ("detected", "missed") and any(x.detection != c.kind for x in cited):\n            c.rejected = f"a cited run was not {c.kind}"\n',
     ""),
    # O1: the three bugs its specification names (docs/design/orodruin-contract.md).
    ("M64", "a contract not verified still arms the run (O1)", "eregion_core/orodruin.py",
     "    if not verdict.armed:\n        return verdict, None\n", ""),
    ("M65", "the journal is written after the injector's first call (O1)", "annatar/executors/azure_vm.py",
     '        self._before_call("run_script", script_path)\n        self._ensure_vm_running()\n',
     '        self._ensure_vm_running()\n        self._before_call("run_script", script_path)\n'),
    ("M66", "the kill stops the VM without revoking the identity (O1)", "eregion_core/orodruin.py",
     '    for name, step in (("revoke", revoke), ("cancel", cancel), ("stop", stop), ("close", close)):',
     '    for name, step in (("cancel", cancel), ("stop", stop), ("close", close)):'),
    # O1, measured on the bench (19/10): Azure lists only what the caller may read — a
    # listing without subscription-wide read proves no absence.
    ("M67", "the identity check trusts a listing it cannot fully read (O1)", "eregion_core/orodruin.py",
     "    if not sees_subscription:\n", "    if False:\n"),
    # O1, part C: the exercise channel from Orodruin to the hosted watch.
    ("M68", "a declared channel wider than a container is allowed (O1)", "eregion_core/orodruin.py",
     '    return scope if _CONTAINER_SCOPE.match(scope.lower()) else ""\n', "    return scope\n"),
    ("M69", "an injector's window never reaches the channel (O1)", "eregion_core/exercise.py",
     '    _write((directory or exercises_dir()) / f"{run_id}.json", window)\n    _publish(window)\n',
     '    _write((directory or exercises_dir()) / f"{run_id}.json", window)\n'),
    ("M70", "the watch labels without pulling the channel (O1)", "eregion_core/exercise.py",
     "        exercise_channel.pull_if_due(exercises_dir())\n", "        pass\n"),
    # G0: the three bugs its plan names (validated 19/10), and where its signals land.
    ("M71", "a fault starts without the steady state verified before (G0)", GOTH,
     '        if not before_ok:\n            return seen, "steady state not verified before the fault — nothing injected"\n',
     ""),
    ("M72", "an experiment target not enrolled is accepted (G0)", GOTH,
     "            if not guard.allowed:\n", "            if False:\n"),
    ("M73", "the return to the initial state is declared without being verified (G0)", GOTH,
     "        revert_verified = all(holds(rs) for rs in after.values())\n", "        revert_verified = True\n"),
    ("M74", "fault signals land where Glorfindel's watch decides on them (G0)", "gothmog/signals/emitter.py",
     '        self.path = Path(runs_dir) / SIGNALS_SUBDIR / f"{run_id}_signals.jsonl"\n',
     '        self.path = Path(runs_dir) / f"{run_id}_signals.jsonl"\n'),
    # R1: the Atomic Red Team adapter — a test is run faithfully or refused, the initial
    # state is verified before and after the atomic's own cleanup.
    ("M75", "a non-linux atomic is run on the Linux target anyway (R1)", "annatar/engines/atomic.py",
     "    if LINUX not in platforms:\n", "    if False:\n"),
    ("M76", "an unresolved #{var} is sent to the VM instead of refused (R1)", "annatar/engines/atomic.py",
     '            raise AtomicError(f"unresolved atomic argument #{{{name}}} (no default, none given)")\n',
     '            return ""\n'),
    ("M77", "an atomic with no cleanup_command is accepted (R1)", "annatar/engines/atomic.py",
     '    if not cleanup:\n        raise AtomicError(\n'
     '            f"atomic {guid} has no cleanup_command — R1 requires a declared return to the "\n'
     '            "initial state (we never leave the target changed)"\n        )\n',
     ""),
    ("M78", "the atomic's cleanup_command is never run (R1)", ENG,
     "                executor.run_command(\n                    resolved.cleanup_command, label=f\"atomic {resolved.guid} cleanup\"\n                )\n",
     ""),
    ("M79", "the return to the initial state is declared without being verified (R1)", ENG,
     '                checks["initial_state_after"] = "PASS" if restored else "FAIL"\n',
     '                checks["initial_state_after"] = "PASS"\n'),
    ("M80", "the atomic runs over a dirty initial state (R1)", ENG,
     "        if not all(ok for _, ok, _ in before):\n", "        if False:\n"),
    # #158 — `annatar run` exits non-zero on a refusal (placed here, not at the end of the
    # list, so the branch merges beside #157's M98–M102). M103: the CLI drops the code;
    # M104–M108: one refusal or error no longer reaches RunOutcome.error, so the CLI exits 0.
    ("M103", "annatar run exits 0 whatever the run's outcome (#158)", "annatar/cli.py",
     '    if outcome is not None and getattr(outcome, "error", None):\n',
     "    if False:\n"),
    ("M104", "a passive Orodruin refusal exits 0 (#158)", ENG,
     'return RunOutcome(run_id, "unknown", error=f"passive: {verdict.reasons()}", refused=True)',
     'return RunOutcome(run_id, "unknown")'),
    ("M105", "a target not enrolled exits 0 (#158)", ENG,
     'return RunOutcome(run_id, "unknown", error=f"safety: {guard.reason}", refused=True)',
     'return RunOutcome(run_id, "unknown")'),
    ("M106", "a dirty start (atomic) exits 0 (#158)", ENG,
     'run_id, "unknown", error="initial state not clean before the atomic"',
     'run_id, "unknown"'),
    ("M107", "an atomic the adapter refuses exits 0 (#158)", ENG,
     'return RunOutcome(run_id, "unknown", error=f"atomic: {e}", refused=True)',
     'return RunOutcome(run_id, "unknown")'),
    ("M108", "an initial state not restored exits 0 (#158)", ENG,
     '            return RunOutcome(run_id, "unknown", error=error)\n',
     '            return RunOutcome(run_id, "unknown")\n'),
    # R1 review (Annatar session): the X-probes the reviewer proved survive, plus one per
    # fix 1–6. engines/atomic.py = ATO, runner/engine.py = ENG, executors/azure_vm.py = EXE.
    ("M81", "run_command writes without the Orodruin journal (R1 review, X1)", EXE,
     '        self._before_call("run_command", label)\n', ""),
    ("M82", "an atomic with dependencies is accepted (R1 review, X3)", ATO,
     '    if test.get("dependencies"):\n', "    if False:\n"),
    ("M83", "the cap ignores the probes (R1 review, X4 + fix 6)", ENG,
     "        return 2 + 3 * n_probes\n", "        return 2\n"),
    ("M84", "an atomic run happens outside its exercise window (R1 review, X5)", ENG,
     '        open_window(run_id, injector="annatar", kind="technique",\n',
     '        if scenario.engine == "atomic":\n'
     '            return self._run_atomic_enrolled(scenario, executor, run_id, session, resolved)\n'
     '        open_window(run_id, injector="annatar", kind="technique",\n'),
    ("M85", "run_command starts the VM before journaling (R1 review, X6)", EXE,
     '        self._before_call("run_command", label)\n        self._ensure_vm_running()\n'
     '        return self._run_shell(command, label, params)\n',
     '        self._ensure_vm_running()\n        self._before_call("run_command", label)\n'
     '        return self._run_shell(command, label, params)\n'),
    ("M86", "probes are sent with #{var} unsubstituted (R1 review, X7)", ENG,
     '            verify = resolved.substitute(probe.get("verify", ""))\n',
     '            verify = probe.get("verify", "")\n'),
    ("M87", "cleanup and the report are skipped when the command raises (R1 fix 1)", ENG,
     "        finally:\n            # Cleanup and the return check always run, whatever the command did (even when it\n",
     "        else:\n            # Cleanup and the return check always run, whatever the command did (even when it\n"),
    ("M88", "an unknown engine falls through to the local-script run (R1 fix 2)", ENG,
     '            if scenario.engine == "local-script":\n                return self._run_enrolled(scenario, executor, run_id)\n',
     "            return self._run_enrolled(scenario, executor, run_id)\n"),
    ("M89", "an unknown engine passes validation (R1 fix 2)", "annatar/runner/parser.py",
     "        if engine not in KNOWN_ENGINES:\n"
     "            errors.append(\n"
     "                f\"engine '{engine}' is not one of {sorted(KNOWN_ENGINES)} — Annatar cannot \"\n"
     "                \"run it (no run with zero steps and a bogus attack_started)\"\n"
     "            )\n",
     ""),
    ("M90", "the atomic's probe requirement is dropped (R1 fix 3)", ENG,
     "            probe_error = self._atomic_probe_error(scenario)\n            if probe_error:\n",
     "            probe_error = self._atomic_probe_error(scenario)\n            if False:\n"),
    ("M91", "a return unverified (None) or not restored stays invisible (R1 fix 4, recheck P11)", ENG,
     "        if restored is not True:\n", "        if restored is False:\n"),
    ("M92", "an unresolved #{...} after substitution is sent raw (R1 fix 5)", ATO,
     '    if "#{" in text:\n', "    if False:\n"),
    ("M93", "PathToAtomicsFolder is not refused (R1 fix 5)", ATO,
     "    if _NO_ATOMICS_FOLDER in text:\n", "    if False:\n"),
    ("M94", "elevation_required: false is accepted (R1 fix 5)", ATO,
     '    if executor.get("elevation_required") is False:\n', "    if False:\n"),
    ("M95", "the declared executor's shebang is not applied (R1 fix 5)", ATO,
     '    return f"#!/bin/{executor_name}\\n{text}"\n', "    return text\n"),
    ("M96", "the attack's effect is assumed, never observed (R1 fix 6)", ENG,
     "            if not any(not ok for _, ok, _ in effect):\n", "            if False:\n"),
    ("M97", "a vendored atomic is edited, the PIN no longer matches (R1 point 9)",
     "annatar/atomics/T1136.001/T1136.001.yaml",
     "attack_technique: T1136.001\n", "attack_technique: T1136.999\n"),
    # #157 — the run's detection latency, and only this run's detections count.
    ("M98", "the watch's resource id compared with its case (bench 20/10: every RulePoller detection missed)", DET,
     '    a, b = str(a or "").strip().lower(), str(b or "").strip().lower()\n',
     '    a, b = str(a or "").strip(), str(b or "").strip()\n'),
    ("M99", "a detection before the attack counts for the run (#157)", DET,
     "        if seen is None or seen < attack_time:", "        if seen is None:"),
    ("M100", "the poll path's latency read from attack_started's timestamp, not detection_time_s (#157)", DET,
     "        if _number(elapsed) and _number(start):\n", "        if False:\n"),
    ("M101", "the latency is not written in the atomic run's report (#157)", ENG,
     "        # proof, about a minute later).\n"
     "        metrics[\"detection\"] = self._detection_result\n"
     "        metrics[\"detection_latency_s\"] = self._detection_latency_s\n",
     "        # proof, about a minute later).\n"
     "        metrics[\"detection\"] = self._detection_result\n"),
    ("M102", "the atomic wait measures from its own start, not from T0 (#157, review R1 P12)", ENG,
     "                args=(run_id, emitter, scenario, detection_timeout_s, T0, threading.Event()),\n",
     "                args=(run_id, emitter, scenario, detection_timeout_s, time.time(), threading.Event()),\n"),
    # #159: the return channel from the hosted watch to a run on Orodruin — every failure
    # falls toward unknown, never a miss the watch did not vouch for.
    ("M109", "the watch beats while a detection waits to be delivered (#159)", WCH,
     "        if waiting:\n            return  # no heartbeat while a detection waits: it would vouch for a miss\n",
     ""),
    ("M110", "the watch publishes a VM no exercise window covers (#159)", WCH,
     '            for run in covering_runs(r["resource_id"], r["detected_at"], windows):\n',
     '            for run in [w["run_id"] for w in windows]:\n'),
    ("M111", "a heartbeat vouches for a run whose window the watch never knew (#159)", WCH,
     '    if run_id not in (heartbeat.get("windows") or []):\n', "    if False:\n"),
    ("M112", "a heartbeat from a watch restarted after the attack vouches (#159)", WCH,
     "    if since > attack:\n", "    if False:\n"),
    ("M113", "the contract lets Orodruin write the watch's channel (#159)", "eregion_core/orodruin.py",
     "            if actions and actions <= BLOB_READ_ONLY:\n", "            if True:\n"),
    ("M114", "the run reads the hosted watch's silence as a miss without its vouching (#159)", ENG,
     "        if result_event is None and channel and not _local_watch():\n", "        if False:\n"),
    ("M115", "an unreadable return channel is read as a miss (#159)", ENG,
     "                return None, None, why\n", '                return "detection_timeout", None, why\n'),
    # #165 — a campaign plays an atomic from the catalog. The synthesizer writes an E1
    # experiment for an atomic entry (SYN); the catalog schema requires its steady_state (CATSCHEMA).
    ("M116", "the synthesizer falls back to run_script_on_vm for an atomic entry (#165)", SYN,
     '    engine = entry.get("engine") or "local-script"\n', '    engine = "local-script"\n'),
    # M117 also neutralizes the post-write check (_runtime_atomic_errors), which would refuse
    # and delete the file on its own: the mutant measures the TESTS reading the written
    # experiment, not the synthesizer's self-check (review #165, second correction).
    ("M117", "the synthesizer writes an atomic without its steady-state probes, its post-write "
     "check neutralized (#165)", SYN,
     ('        "steady_state": {"probes": [dict(p) for p in probes]},\n',
      "        errors = _runtime_atomic_errors(path)\n"),
     ("", "        errors = []\n")),
    ("M118", "the synthesizer accepts an engine_ref the adapter cannot resolve (#165)", SYN,
     '    try:\n        resolve_ref(engine_ref)\n    except AtomicError as e:\n'
     '        return SynthesisResult(False, f"{ttp}: engine_ref unresolved — {e}")\n',
     "    pass\n"),
    ("M119", "the catalog schema accepts an implemented atomic without steady_state (#165)", CATSCHEMA,
     '                  "const": "atomic"\n', '                  "const": "atomic-never"\n'),
    # #165, review — the plan runs in the Orodruin image (no jsonschema, no schemas/); the
    # destructive guard is shared by every engine; a failed reset is not "reset"; the Make
    # target does not echo the subscription.
    ("M120", "the synthesizer validates the atomic with jsonschema at plan time (#165)", SYN,
     "        errors = _runtime_atomic_errors(path)\n",
     "        from eregion_core.experiment import validate_experiment_file\n"
     "        errors = validate_experiment_file(path)\n"),
    ("M121", "a raising validation leaves a half-planned experiment behind (#165)", SYN,
     "        path.unlink(missing_ok=True)\n"
     '        return SynthesisResult(False, f"{ttp}: produced experiment could not be validated — {e}")\n',
     '        return SynthesisResult(False, f"{ttp}: produced experiment could not be validated — {e}")\n'),
    ("M122", "a destructive atomic skips the allow_destructive/safe_target guard (#165)", SYN,
     "    if destructive:\n        if not allow_destructive:\n",
     '    if destructive and engine != "atomic":\n        if not allow_destructive:\n'),
    ("M123", "a reset that exits non-zero is recorded as reset (#165)", CRUN,
     "    if proc.returncode != 0:\n", "    if False:\n"),
    ("M124", "orodruin-campaign-plan echoes its target, subscription included (#165)", MAKE,
     '\t@echo "annatar campaign plan (Orodruin, max $(CAMPAIGN_MAX)$(if $(CAMPAIGN_DECLARED),$(BL1_COMMA) déclarée $(CAMPAIGN_DECLARED)))" && $(ORO_SSH) ',
     "\t$(ORO_SSH) "),
    # #165, second review — in the Orodruin image the glorfindel launcher is on PATH but the
    # package is not: the guard tests the package, not the launcher alone.
    ("M125", "the reset guard trusts the glorfindel launcher alone, not its package (#165)", CRUN,
     '    if find_spec("glorfindel") is None:\n', "    if False:\n"),
    # #167 — a campaign launched from Orodruin gets its report on H0. The decision of a run
    # comes from the watch's files by #157's rule (CREP; DET for the rule itself, measured
    # here through the report: M128, and M129 = M98's text); Orodruin publishes the campaign
    # and nothing else (XCH, ACLI); the thread beside the watch writes it once, and never
    # stops the watch (HREP, GCLI). M144–M148: the third review's findings; M159–M169 (after
    # #169's M150 and lot G2's M151–M158): the fourth review's; M180–M186 (after lot G2's
    # M170–M178): the fifth review's; M187–M188: the sixth review's.
    ("M126", "a decision seen after the run's window and its grace is attached to the run (#167)", CREP,
     "                          float(attack_time), until.timestamp()) or {}\n",
     "                          float(attack_time), None) or {}\n"),
    ("M127", "a decision seen before the run's attack is attached to the run (#167)", CREP,
     "                          float(attack_time), until.timestamp()) or {}\n",
     "                          0.0, until.timestamp()) or {}\n"),
    ("M128", "a decision on another VM is attached to the run (#167)", DET,
     '        if signal.get("ttp") != ttp or not same_resource(signal.get("resource_id"), resource_id):\n',
     '        if signal.get("ttp") != ttp:\n'),
    ("M129", "the resource id's case keeps the watch's decision from the run (#167)", DET,
     '    a, b = str(a or "").strip().lower(), str(b or "").strip().lower()\n',
     '    a, b = str(a or "").strip(), str(b or "").strip()\n'),
    ("M130", "Orodruin publishes the runs' debug files with the campaign (#167)", XCH,
     '_RUN_FILES = ("{run_id}.json",)\n', '_RUN_FILES = ("{run_id}.json", "{run_id}_debug.jsonl")\n'),
    ("M131", "a campaign-report thread that fails to start stops the watch (#167)", GCLI,
     "    except Exception as exc:  # the watch goes on without campaign reports\n",
     "    except ImportError as exc:  # the watch goes on without campaign reports\n"),
    ("M132", "a failing pass stops the campaign-report thread (#167)", HREP,
     '            _say(f"pass failed: {type(e).__name__}: {e}")\n', "            raise\n"),
    ("M133", "a failing report escapes write_report, its attempt not counted (#167)", HREP,
     "        except Exception as e:  # the model, the index, the files: noted, tried again later\n",
     "        except OSError as e:  # the model, the index, the files: noted, tried again later\n"),
    ("M134", "a report already written is written again (#167)", HREP,
     "        if (cdir / REPORT).exists():  # written by a pass that held the lock before us\n",
     "        if False:  # written by a pass that held the lock before us\n"),
    ("M135", "two passes write the same report at once, no lock (#167)", HREP,
     "            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n", "            pass\n"),
    ("M136", "a campaign's run reports published at the root, over the runs' windows (#167)", XCH,
     '                out.append((f"{CAMPAIGNS}/{cid}/runs/{name}", runs / name))\n',
     "                out.append((name, runs / name))\n"),
    ("M137", "a detection without an action is attached as the run's decision (#167)", CREP,
     '    decided = [r for r in watch_records(float(attack_time)) if r.get("action")]\n',
     "    decided = watch_records(float(attack_time))\n"),
    ("M138", "the windows' pull reads the listing's first page only (#167)", XCH,
     '        marker = (root.findtext("NextMarker") or "").strip()\n', '        marker = ""\n'),
    ("M139", "a campaign's manifest is pulled although one of its runs did not come (#167)", XCH,
     '        if m["rid"] is None and m["cid"] in failed:\n', "        if False:\n"),
    ("M140", "the thread writes the report of a local campaign, not pulled from the channel (#167)", HREP,
     "        if (cdir.name in failed or not (cdir / exercise_channel.PULLED).exists()\n",
     "        if (cdir.name in failed\n"),
    ("M141", "an aborted campaign gets its report written on H0 (#167)", HREP,
     # H-1: the shape is checked first (campaign_schema.manifest_refusal), then the state.
     '        if manifest.get("state") != "done":\n',
     '        if manifest.get("state") not in ("done", "aborted"):\n'),
    ("M142", "a failing report is tried again without end (#167)", HREP,
     "                or (cdir / REPORT).exists() or attempts(cdir) >= MAX_ATTEMPTS):\n",
     "                or (cdir / REPORT).exists()):\n"),
    ("M143", "the attempts are counted in report.error only: unwritable, the model is called without end (#167)",
     HREP, "        return max(noted, _failures.get(_key(cdir), 0))\n", "        return noted\n"),
    ("M144", "a detected run's decision not yet in the watch's files does not hold the report back (#167)",
     HREP, "            waiting = waits_for_decisions(cdir, runs_dir, now=now, say=say)\n",
     "            waiting = False\n"),
    ("M145", "a run of unknown detection without a decision reads as « none » (#167, review 3)", CREP,
     '_DECISION_SOUGHT = ("detected", "unknown")\n', '_DECISION_SOUGHT = ("detected",)\n'),
    ("M146", "the wait for a decision ends with the window, without the cycle's lag (#167, review 3)", HREP,
     "        deadline = min(seen_by + DECISION_LAG_S, cap)\n", "        deadline = min(seen_by, cap)\n"),
    ("M147", "a trend or an observation on an unknown decision is kept without saying so (#167, review 3)",
     CREP, "            if c.kind not in _DETECTION_KINDS and _RESPONSE.search(c.text) and not _UNKNOWN.search(c.text):\n",
     "            if False:\n"),
    ("M148", "the thread's messages of a campaign share one slot, said again every pull (#167, review 3)",
     HREP, "    k = (_key(cdir), sort)\n", "    k = _key(cdir)\n"),
    ("M149", "a failed publication raises into the campaign (#167)", ACLI,
     '    except Exception as exc:\n        console.print(f"[yellow]Campaign not published to H0',
     '    except OSError as exc:\n        console.print(f"[yellow]Campaign not published to H0'),
    # #167, fourth review — M151–M158 are lot G2's.
    ("M159", "the report's table leaves Glorfindel's escalation out (#167, review 4)", CREP,
     "        how += [_ESCALATED[x.escalated]] if isinstance(x.escalated, bool) else []\n",
     "        how += []\n"),
    ("M160", "the facts given to the model leave Glorfindel's escalation out (#167, review 4)", CREP,
     '"confidence": f.confidence, "escalated": f.escalated,\n', '"confidence": f.confidence,\n'),
    ("M161", "a claim that cites the reason given to the model reads as « Glorfindel did not act » "
     "(#167, review 4)", CREP,
     '    + "".join(r"|(?<!\\w)" + re.escape(r) for r in REASONS),\n',
     '    + "".join(r"|(?<!\\w)" + re.escape(r) for r in ()),\n'),
    ("M162", "a trend on the detection alone is removed because a cited run's decision is unknown "
     "(#167, review 4)", CREP,
     "            if c.kind not in _DETECTION_KINDS and _RESPONSE.search(c.text) and not _UNKNOWN.search(c.text):\n",
     "            if c.kind not in _DETECTION_KINDS and not _UNKNOWN.search(c.text):\n"),
    ("M163", "a claim that Glorfindel acted on a run whose decision is unknown is kept (#167, review 4)",
     CREP, "            elif _ACTED.search(told) and not all(\n",
     "            elif False and not all(\n"),   # followed D-2's change of the line (A1 merge)
    ("M164", "a missed run whose window holds a decision reads as « Glorfindel did not act » "
     "(#167, review 4)", CREP,
     '        return {}, (LATE_OR_OTHER if dec else ""), until\n', '        return {}, "", until\n'),
    ("M165", "a report waits for a decision that no file can bring, without an attack time or a "
     "resource (#167, review 4)", HREP,
     '        if set(why.split(", ")) & never_attached:  # the files are whole: no wait changes it\n',
     "        if False:\n"),
    ("M166", "a report.error that cannot be removed escapes write_report (#167, review 4)", HREP,
     "        except OSError:  # an error left behind: the report is written, its presence wins (ready)\n",
     "        except FileNotFoundError:  # an error left behind: the report is written, its presence wins (ready)\n"),
    ("M167", "a failed pull of the campaigns is said again every pass (#167, review 4)", HREP,
     '        _say_once(root, "pull", f"pull failed: {e}", say, key=_error_key(e))\n',
     '        say(f"pull failed: {e}")\n'),
    ("M168", "a campaign not all pulled is said again every pass (#167, review 4)", HREP,
     '        _say_once(root / cid, "pull", f"{cid}: not all pulled — its report waits for the next pull", say)\n',
     '        say(f"{cid}: not all pulled — its report waits for the next pull")\n'),
    ("M169", "a failed pull of the windows shares the campaigns' slot, said again every pass "
     "(#167, review 4)", HREP,
     '_say_once(root, "windows", f"windows not pulled', '_say_once(root, "pull", f"windows not pulled'),
    # #167, fifth review — M170–M178 are lot G2's.
    ("M180", "the reason given to the model reads as a nothing again: « Glorfindel n'a pris aucune "
     "décision dans la fenêtre » passes (#167, review 5)", CREP,
     'NONE_IN_WINDOW = "décision non retrouvée dans la fenêtre"\n',
     'NONE_IN_WINDOW = "aucune décision dans la fenêtre"\n'),
    ("M181", "a failure whose text changes at every call (a timed-out connection) is said again "
     "every pass (#167, review 5)", HREP,
     "    key = message if key is None else key\n", "    key = message\n"),
    ("M182", "a claim that Glorfindel quarantined, contained or neutralised a run whose decision "
     "is unknown is kept (#167, review 5)", CREP,
     '    r"|quarantaine|quarantine|conten|contain|interv|neutralis"\n', ""),
    # M183 is caught by the reason shown (the rejection's text), not by a claim kept or dropped.
    ("M183", "an observation on the containment of a run whose decision is unknown is not read "
     "as speaking of the response (#167, review 5)", CREP,
     '    r"|quarantaine|quarantine|conten|contain|neutralis",\n', '    ,\n'),
    ("M184", "a reason given to the model is taken out inside a word: « aucune décision dans la "
     "fenêtre d'un run manqué… » passes (#167, review 5)", CREP,
     '    + "".join(r"|(?<!\\w)" + re.escape(r) for r in REASONS),\n',
     '    + "".join(r"|" + re.escape(r) for r in REASONS),\n'),
    ("M185", "a lock that cannot be opened is said nowhere (#167, review 5)", HREP,
     '        _say_once(cdir, "lock", f"{cdir.name}: report not written, its lock cannot be opened "\n'
     '                                f"({type(e).__name__}: {e}) — tried again at the next pull",\n'
     "                  say, key=_error_key(e))\n", ""),
    ("M186", "a lock that cannot be opened again, after an open that went through, is not said "
     "(#167, review 5)", HREP,
     '    _said.pop((_key(cdir), "lock"), None)   # opened: a later failure is said again\n', ""),
    # #167, sixth review: the call to the analysis model is bounded (LiteLLM's own default is
    # 6000 s an attempt) — a hung provider held the campaign-report thread for hours.
    ("M187", "the call to the analysis model is unbounded: LiteLLM's 6000 s apply (#167, review 6)", CREP,
     "        timeout=timeout_s(),\n", ""),
    ("M188", "EREGION_ANALYSIS_TIMEOUT_S never reaches the watch's container (#167, review 6)",
     "docker-compose.yml",
     "  EREGION_ANALYSIS_TIMEOUT_S: ${EREGION_ANALYSIS_TIMEOUT_S:-}\n", ""),
    # #169 — Discord archives an idle thread without telling the bot: the cached thread reads
    # open, the edit is refused (50083). M126–M149 are reserved for lot 167.
    ("M150", "a card edit refused because Discord archived its thread is not reopened (#169)",
     "glorfindel/bot.py",
     "                    # THREAD_UPDATE (#169, 20/10): reopen it, try again once.\n"
     '                    await thread.edit(archived=False, reason="Card updated")\n',
     "                    # THREAD_UPDATE (#169, 20/10): reopen it, try again once.\n"),
    # G2 (#77) — the failures of Glorfindel's dependencies: each one fails closed. One
    # mutant at least per dependency (model, cloud API, telemetry, configuration).
    ("M151", "the model: the decision call is unbounded, a hung provider holds the VM's queue (G2)",
     "glorfindel/agent.py",
     "        timeout=llm_timeout_s(),\n", ""),
    ("M152", "the cloud API: a VM whose readiness check could not reach Azure acts alone (G2)",
     "glorfindel/readiness.py",
     '    if rec is None:\n        return {"reason": "not_checked", "codes": [],\n',
     '    if rec is None:\n        return {}\n        return {"reason": "not_checked", "codes": [],\n'),
    ("M153", "the telemetry: a failed investigative query is read as no rows (G2)",
     "glorfindel/agent.py",
     "    except Exception:\n        return None\n", "    except Exception:\n        return []\n"),
    ("M154", "the telemetry: a disruptive action runs on investigative queries that failed (G2)",
     "glorfindel/agent.py",
     '    _apply_telemetry_guard(d, state.get("telemetry_gaps") or [])\n', ""),
    ("M155", "the configuration: --mode makes every VM autonomous over an unreadable config (G2)",
     "glorfindel/agent.py",
     "    if autonomy_override and not config_error:\n", "    if autonomy_override:\n"),
    ("M156", "the configuration: a malformed confidence threshold lets the gate through (G2)",
     C,
     "    if not 0.0 <= value <= 1.0:          # nan fails the comparison too\n",
     "    if False:\n"),
    ("M157", "the configuration: a read-only switch not spelled 1/true/yes leaves the writes on (G2)",
     C,
     "    return str(raw).strip().lower() not in _SWITCH_OFF\n",
     '    return str(raw).strip().lower() in ("1", "true", "yes")\n'),
    ("M158", "the configuration: an approval age limit of nan or inf executes a card of any age (G2)",
     "eregion_console/api.py",
     "    if math.isnan(value) or value == math.inf:\n        return 2.0\n", ""),
    # G2, after the Opus 5.5 review (M159–M169 belong to lot 167).
    ("M170", "the configuration: an approval age limit of 0 or less is lifted to 2 h, reopening "
             "the one-click approval closed on purpose (G2 review)",
     "eregion_console/api.py",
     "    if math.isnan(value) or value == math.inf:\n",
     "    if math.isnan(value) or value == math.inf or value <= 0:\n"),
    ("M171", "the configuration: an approval age limit of 0 or less refuses no card of its own — "
             "a card dated ahead of the clock runs (G2 review)",
     "eregion_console/api.py",
     "    if max_age_h <= 0:\n", "    if False:\n"),
    ("M172", "the model: a NaN confidence passes the confidence gate (G2 review)",
     "glorfindel/agent.py",
     '        if raw_conf is None or not d["confidence"] >= threshold:\n',
     '        if raw_conf is None or d["confidence"] < threshold:\n'),
    ("M173", "the model: a confidence outside [0, 1] is kept as sent — 500 % on the card (G2 review, SEC4a)",
     "glorfindel/agent.py",
     "        if raw_conf is not None and not 0.0 <= confidence <= 1.0:\n"
     "            raise ValueError(\"confidence outside [0, 1]\")\n", ""),
    ("M174", "the telemetry: a card held by an earlier gate does not say the queries failed (G2 review)",
     "glorfindel/agent.py",
     '    if d["escalate"]:\n        d["escalation_reason"] = (\n',
     '    if d["escalate"]:\n        return\n        d["escalation_reason"] = (\n'),
    ("M175", "the configuration: GLORFINDEL_LLM_TIMEOUT_S never reaches the containers (G2 review)",
     "docker-compose.yml",
     "  GLORFINDEL_LLM_TIMEOUT_S: ${GLORFINDEL_LLM_TIMEOUT_S:-}\n", ""),
    ("M176", "the War Room reads the threshold from the agent: a failed import drops the "
             "capability matrix (G2 review)",
     "eregion_console/api.py",
     "        from glorfindel.config import confidence_threshold\n        _allow: list = []\n",
     "        from glorfindel.agent import _confidence_threshold as confidence_threshold\n"
     "        _allow: list = []\n"),
    ("M177", "the configuration: the watch banner shows --mode over an unreadable config (G2 review)",
     "glorfindel/agent.py",
     "        if autonomy_default and not self.config_error:\n", "        if autonomy_default:\n"),
    ("M178", "the configuration: the card of an unreadable config reads « Réponse autonome "
             "configurée » (G2 review)",
     "glorfindel/agent.py",
     '        if gate and gate.get("reason") == "config_unreadable":\n', "        if False:\n"),
    # The bench, all or part (21/10): `celebrimbor-stop` without VM= nor ALL=1 spares the VMs
    # tagged always-on — bree, the real load the hosted Glorfindel (H0) watches.
    ("M189", "make celebrimbor-stop also deallocates the always-on VMs (bree) without ALL=1", MAKE,
     "BENCH_KEEP = $(if $(or $(VM),$(ALL)),, && tags.\\\"always-on\\\" != 'true')\n", "BENCH_KEEP =\n"),
    # #174 — the report's table shows each run's detection latency, « — » without one.
    ("M190", "the report's table leaves the detection latency out (#174)", CREP,
     "| {x.detection} | {_latency(x.latency_s)} | {dec} |\")\n", "| {x.detection} | {dec} |\")\n"),
    # M-1 (ninth pass): the kill stops what runs, whatever the operator's CLI context.
    ("M191", "the kill lists the identity's assignments in the CLI's current subscription (M-1)", KILL,
     '        return json.loads(call(["role", "assignment", "list", "--all", "--subscription", sub,\n',
     '        return json.loads(call(["role", "assignment", "list", "--all",\n'),
    ("M192", "the kill leaves a running chaos experiment running (M-1)", KILL,
     '            call(["rest", "--method", "post", "--url", f"{ARM}{eid}/cancel?api-version={CHAOS_API}"])\n',
     ""),
    ("M193", "the kill leaves the open exercise windows open (M-1)", KILL,
     "                exercise_channel.publish(closed, channel=channel, credential=cred, put=put)\n",
     "                pass\n"),
    # M-1, measured on the bench (26/10): orodruin-check printed the subscription.
    ("M194", "what the contract shows names the subscription (M-1)", "eregion_core/orodruin.py",
     '    return {"code": code, "detail": _SUBSCRIPTION_PART.sub("/subscriptions/…", detail)}\n',
     '    return {"code": code, "detail": detail}\n'),
    # D-1 (#186) — the stability of the decision: the first draw at temperature 0 (the
    # model's default when it refuses one), a disruptive action run alone only when every
    # draw agrees. M191–M194 are lot M-1's (Orodruin).
    ("M200", "the first draw is asked at the provider's default sampling: nothing fixes it (D-1)",
     "glorfindel/agent.py",
     '            litellm, "security_decision", temperature=_DECISION_TEMPERATURE, **call)\n',
     '            litellm, "security_decision", **call)\n'),
    ("M201", "a model refusing the temperature fails every decision — claude-sonnet-5-5, the "
     "default, refuses it (D-1)", "eregion_core/llm_call.py",
     "            if not _refuses_temperature(exc):\n                raise\n"
     "            _NO_TEMPERATURE.add(model)\n",
     "            raise\n"),
    ("M202", "the cycle records a fixed draw on a model that refused the temperature (D-1)",
     "glorfindel/agent.py",
     "    temperature = None if temperature_refused(model) else _DECISION_TEMPERATURE\n",
     "    temperature = _DECISION_TEMPERATURE\n"),
    ("M203", "a disruptive action runs on one draw: the draws' agreement is never checked (D-1)",
     "glorfindel/agent.py",
     "        _apply_agreement_guard(d, draws, required)\n", ""),
    ("M204", "the confirming draws repeat the first draw's temperature: they probe nothing (D-1)",
     "glorfindel/agent.py",
     '            resp = completion_with_tool(litellm, "security_decision", **call)\n',
     '            resp = completion_with_tool(litellm, "security_decision", '
     "temperature=_DECISION_TEMPERATURE, **call)\n"),
    ("M205", "a confirming draw below the confidence threshold agrees (D-1)",
     "glorfindel/agent.py",
     "        _apply_confidence_gate(x, raw_conf, threshold)\n", ""),
    ("M206", "a confirming draw that failed is dropped, the ones that answered agree (D-1)",
     "glorfindel/agent.py",
     ("    return [r[0] for r in results], [r[1] for r in results if r[1] is not None]\n",
      "    if required and len(draws) >= required and len(agree) == len(draws):\n"),
     ("    return [r[0] for r in results if r[1] is not None], "
      "[r[1] for r in results if r[1] is not None]\n",
      "    if required and len(agree) == len(draws):\n")),
    ("M207", "fewer draws than required are an agreement (D-1)",
     "glorfindel/agent.py",
     "    if required and len(draws) >= required and len(agree) == len(draws):\n",
     "    if required and len(agree) == len(draws):\n"),
    ("M208", "the configuration: GLORFINDEL_DECISION_DRAWS=1 is one draw, no agreement (D-1)", C,
     "    if not 2 <= value <= _DECISION_DRAWS_MAX:\n",
     "    if not 1 <= value <= _DECISION_DRAWS_MAX:\n"),
    ("M209", "the configuration: a malformed GLORFINDEL_DECISION_DRAWS reads as the default "
     "instead of holding (D-1)", C,
     "    except ValueError:\n        return 0\n",
     "    except ValueError:\n        return DECISION_DRAWS\n"),
    ("M210", "an unstable decision's card reads « confiance insuffisante » (D-1)",
     "glorfindel/agent.py",
     '    "agreement": "unstable_decision",\n', ""),
    ("M211", "an unstable decision's card cannot be approved in one click (D-1)",
     "eregion_console/api.py",
     '                     "telemetry_gap", "unstable_decision"}\n',
     '                     "telemetry_gap"}\n'),
    ("M212", "GLORFINDEL_DECISION_DRAWS never reaches the watch's container (D-1)",
     "docker-compose.yml",
     "  GLORFINDEL_DECISION_DRAWS: ${GLORFINDEL_DECISION_DRAWS:-}\n", ""),
    # H-1 (#187) — an exercise window is no longer believed on its word: refused when too
    # long, declared for later or named like a RulePoller run; a VM only if enrolled; the
    # run_id shortcut on a VM the window names; purged a week on; an exercise card kept in
    # the list to judge; on H0, a campaign checked against its shape, its runs kept only with
    # a known window naming an enrolled VM. M200–M212 are D-1's, M191–M194 M-1's.
    ("M220", "a window longer than MAX_DURATION_S is believed (H-1)", XW,
     "    if not 0 < lasts <= MAX_DURATION_S:\n", "    if not 0 < lasts:\n"),
    ("M221", "a window that starts long after it was declared is believed (H-1)", XW,
     "    if refs and start > min(refs) + timedelta(seconds=FUTURE_SKEW_S):\n", "    if False:\n"),
    ("M222", "a window marks a VM that is not enrolled — the real load passed off as an "
     "exercise (H-1)", XW,
     "    return (_targets(window, resource_id) and live(window, when) and enrolled(resource_id)\n",
     "    return (_targets(window, resource_id) and live(window, when)\n"),
    ("M223", "the run_id shortcut marks a VM its window does not name (H-1)", XW,
     '            w.get("run_id") == run_id and _targets(w, resource_id)\n',
     '            w.get("run_id") == run_id\n'),
    ("M224", "an exercise card is hidden from the list to judge (H-1)", "glorfindel/escalations.py",
     '        if not is_decision(e) or e.get("verdict") in VERDICTS:\n',
     '        if not is_decision(e) or e.get("verdict") in VERDICTS or e.get("source") == "exercise":\n'),
    ("M225", "a window past its last moment by a week is never purged (H-1)", XW,
     "        if last is not None and last < now - timedelta(seconds=PURGE_AFTER_S):\n",
     "        if False:\n"),
    ("M226", "a window may take the RulePoller's run name: a detection becomes an exercise by "
     "its run_id (H-1)", XW,
     "    if rid.lower().startswith(_WATCH_RUN_PREFIX):\n", "    if False:\n"),
    ("M227", "without an enrollment check, every VM is enrolled (H-1)", XW,
     "    if check is None or not resource_id:\n        return False\n",
     "    if check is None or not resource_id:\n        return True\n"),
    ("M228", "a tag read that fails counts as enrolled (H-1)", "eregion_core/inscription.py",
     '            ok, ttl, why = False, self.FAIL_TTL_S, f"enrollment unreadable: {e}"\n',
     '            ok, ttl, why = True, self.FAIL_TTL_S, f"enrollment unreadable: {e}"\n'),
    ("M229", "a window written today for tomorrow is believed tomorrow (H-1)", XW,
     "    refs = [t for t in (now, declared_at) if t is not None]\n",
     "    refs = [t for t in (now,) if t is not None]\n"),
    ("M230", "a purged window is deleted: the channel brings it back at every pull (H-1)", XW,
     '        _write(path, {"run_id": window.get("run_id"), "purged_at": _now().isoformat()})\n'
     "        os.utime(path, (st.st_atime, st.st_mtime))\n",
     "        path.unlink()\n"),
    ("M231", "H0 writes the report of a manifest of the wrong shape (H-1)", HREP,
     "        if refused:\n", "        if False:\n"),
    ("M232", "a channel run without a known window stays in the facts (H-1)", CREP,
     "    if not window:\n        return f\"run {rid} refusé : fenêtre d'exercice inconnue\"\n", ""),
    ("M233", "a channel run on a VM not enrolled stays in the facts (H-1)", CREP,
     "    if not is_enrolled(vm):\n        return f\"run {rid} refusé : sa VM n'est pas inscrite\"\n", ""),
    ("M234", "a channel run on a VM its window does not name stays in the facts (H-1)", CREP,
     '    if not vm or vm.lower() not in (window.get("targets") or []):\n', "    if False:\n"),
    ("M235", "the report does not say which facts came through the channel (H-1)", CREP,
     '    if report.channel:\n        lines += ["", CHANNEL_NOTE]\n', ""),
    ("M236", "a channel scenario of the wrong shape stays in the facts (H-1)", CREP,
     "    why = scenario_refusal(scenario)\n", '    why = ""\n'),
    ("M237", "a channel run whose report is another run's stays in the facts (H-1)", CREP,
     "    report_why = run_report_refusal(\n", "    report_why = \"\" and run_report_refusal(\n"),
    ("M238", "a window longer than MAX_DURATION_S bounds a run's decisions (H-1)", CREP,
     "    until = None if window_refusal(window) else last_moment(window)\n",
     "    until = last_moment(window)\n"),
    # #193 — the report of a run launched alone goes to H0: published at the end of
    # `annatar run` and `gothmog run`, a failure said and never raised; pulled on H0 by the
    # watch's pass, refused when of the wrong shape, never over a report of H0's own. And
    # the probes' values before the fault in Gothmog's report.
    ("M240", "`annatar run` keeps its report on Orodruin (#193)", ACLI,
     "    engine = Engine(dry_run=dry_run, skip_preflight=skip_preflight, publish_report=True,\n",
     "    engine = Engine(dry_run=dry_run, skip_preflight=skip_preflight,\n"),
    ("M241", "`gothmog run` keeps its report on Orodruin (#193)", GOTH,
     "            carry_run(run_id, self.runs_dir)  # its report, to H0 with its window (#193)\n",
     "            pass\n"),
    ("M242", "a failed publication of a run's report raises into the run (#193)", XCH,
     '    except Exception as e:\n        print(f"[exercise-channel] run report {run_id} not published: {e}")\n',
     '    except ValueError as e:\n        print(f"[exercise-channel] run report {run_id} not published: {e}")\n'),
    ("M243", "H0 pulls a run's report of the wrong shape: the console shows it (#193)", XCH,
     "        why = refusal(report, rid)\n", '        why = ""\n'),
    ("M244", "H0 writes a pulled report over the report of a run of its own (#193)", XCH,
     "            if not mark.exists():\n", "            if False:\n"),
    ("M245", "the hosted watch's pass never pulls the runs' reports (#193)", HREP,
     "    pull_runs(runs_dir, say=say, **kw)\n", ""),
    ("M246", "Gothmog's report leaves the probes' values before the fault out (#193)", GOTH,
     '            **seen, "execution_id": (execution or {}).get("name"), "execution_status": status,\n',
     '            **{k: v for k, v in seen.items() if k != "before"},\n'
     '            "execution_id": (execution or {}).get("name"), "execution_status": status,\n'),
    # A1 — actions.py split, its import path a façade that is still one namespace; MC0 —
    # each provider declares its capabilities, the readiness reads them, no SDK outside
    # its adapter (tests/unit/test_actions_split.py, test_provider_boundary.py).
    ("M450", "a write through the façade reaches one module only: the locks under the real home (A1)",
     FAC,
     "        for module in binders:\n            setattr(module, name, value)\n",
     "        for module in binders[:1]:\n            setattr(module, name, value)\n"),
    ("M451", "the façade binds copies: a value its module changes reads stale (A1)", FAC,
     "_sys.modules[__name__].__class__ = _OneNamespace\n",
     "globals().update({n: v for m in _MODULES for n, v in vars(m).items() if not n.startswith(\"__\")})\n"
     "_sys.modules[__name__].__class__ = _OneNamespace\n"),
    ("M452", "a module of the split left out of the façade: its names unreachable (A1)", FAC,
     '    "glorfindel.providers.azure.sweep",\n', ""),
    ("M453", "the readiness reads the rules' rights from the quarantine's (MC0)", "glorfindel/readiness.py",
     "    rules_ok = caps.available(NETWORK_RULES, missing)\n",
     "    rules_ok = caps.available(NETWORK_QUARANTINE, missing)\n"),
    ("M454", "a capability whose rights are missing counts as available (MC0)", PIF,
     "        return cap is not None and not (set(missing_rights) & cap.rights)\n",
     "        return cap is not None\n"),
    ("M455", "a capability the provider doesn't declare counts as available (MC0)", PIF,
     "        return cap is not None and not (set(missing_rights) & cap.rights)\n",
     "        return cap is None or not (set(missing_rights) & cap.rights)\n"),
    ("M456", "a connector that declares nothing is read as Azure (MC0)", PIF,
     "    if isinstance(connector, CloudConnector):\n        raise TypeError(",
     "    if False:\n        raise TypeError("),
    ("M457", "the boundary lets any provider's SDK into any adapter of glorfindel/ (MC0)", BOUNDARY_TESTS,
     '        return rel.startswith(f"glorfindel/providers/{provider}/")\n',
     '        return rel.startswith("glorfindel/providers/")\n'),
    ("M458", "Azure's declaration drifts from what check_permissions reads (MC0)",
     "glorfindel/providers/azure/capabilities.py",
     '            "Microsoft.Network/networkSecurityGroups/securityRules/delete",\n', ""),
    ("M459", "a restore job read in the VM's group again, through the connector (A1)", "glorfindel/jobs.py",
     "            az_status = connector.restore_job_status(vault, rg, restore_job_name)\n",
     "            az_status = connector.restore_job_status(vault, job.get(\"rg\", \"\"), restore_job_name)\n"),
    # A1 review: a spec'd mock, an instance's declaration, the ceiling of the debt, mock.patch.
    ("M460", "capabilities read on type(): a MagicMock(spec=AzureConnector) breaks the readiness (A1 review)",
     PIF, '        declared = getattr(getattr(connector, "__class__", type(connector)), "CAPABILITIES", None)\n',
     '        declared = getattr(type(connector), "CAPABILITIES", None)\n'),
    ("M461", "an instance's own declaration ignored (A1 review)", PIF,
     '    declared = getattr(connector, "CAPABILITIES", None)\n', "    declared = None\n"),
    ("M462", "a debt of the shared core declared an adapter: the boundary no longer sees it (A1 review)",
     BOUNDARY_TESTS,
     ('ADAPTERS = {\n', '    "eregion_core/inscription.py": "credential for the ARM tag read of the inscription",\n'),
     ('ADAPTERS = {\n    "eregion_core/inscription.py": "azure",\n', "")),
    ("M463", "a delete through the façade silently ignored: mock.patch leaves its value everywhere (A1 review)",
     FAC, "        if _binders(name):\n            home = ", "        if _binders(name):\n            return\n            home = "),
    # D-2 (#184) — what changed since the previous campaign: the previous campaign chosen by
    # its rule (done, earlier, a shared key: a technique on a VM), the runs joined exactly by
    # key, the section rendered by the code, a difference that does not come from a fact
    # removed by the check, and the index of past campaigns put in without losing a fact.
    ("M260", "an aborted campaign is chosen as the previous one (D-2)", "analysis/campaign_report.py",
     ('    res = coll.get(where={"campaign_state": "done"}, limit=_MAX_ROWS)\n',
      '        if (meta.get("campaign_state") != "done" or not cid or cid == campaign.campaign_id\n'),
     ("    res = coll.get(limit=_MAX_ROWS)\n",
      "        if (not cid or cid == campaign.campaign_id\n")),
    ("M261", "a later campaign is chosen as the previous one (D-2)", "analysis/campaign_report.py",
     "                or not isinstance(started, (int, float)) or not started < campaign.started):\n",
     "                or not isinstance(started, (int, float))):\n"),
    ("M262", "a campaign with no key in common is chosen as the previous one (D-2)", "analysis/campaign_report.py",
     "    shared = [(started, cid) for cid, (started, runs) in found.items() if keys(runs) & mine]\n",
     "    shared = [(started, cid) for cid, (started, runs) in found.items()]\n"),
    ("M263", "the key leaves the VM out: a technique on another VM faces it (D-2)", "analysis/campaign_changes.py",
     "    return (ttp, vm) if ttp and vm else None\n", '    return (ttp, "") if ttp else None\n'),
    ("M264", "the earliest qualifying campaign is chosen, not the latest (D-2)", "analysis/campaign_report.py",
     "    _, cid = max(shared)\n", "    _, cid = min(shared)\n"),
    ("M265", "without a previous campaign, the section says nothing of why (D-2)", "analysis/campaign_changes.py",
     '        return lines + [f"*Aucune campagne précédente : {comparison.why_none}.*"]\n',
     "        return lines\n"),
    ("M266", "the VM of the key is compared with its case (D-2)", "analysis/campaign_changes.py",
     '    ttp, vm = getattr(fact, "ttp", "") or "", (getattr(fact, "target", "") or "").lower()\n',
     '    ttp, vm = getattr(fact, "ttp", "") or "", (getattr(fact, "target", "") or "")\n'),
    ("M267", "the keys of one side only are not listed (D-2)", "analysis/campaign_changes.py",
     "    order = sorted(set(b) | set(a),", "    order = sorted(set(b) & set(a),"),
    ("M268", "a skipped scenario is a key: it played nothing (D-2)", "analysis/campaign_changes.py",
     '    if getattr(fact, "status", "") != "executed":\n        return None\n', ""),
    ("M269", "the report indexes its runs without the campaign's state and start (D-2)",
     "analysis/campaign_report.py",
     "    index_facts(facts, index_path, info)\n", "    index_facts(facts, index_path)\n"),
    ("M270", "a key played twice pairs the last run with the first (D-2)", "analysis/campaign_changes.py",
     "for n, f in enumerate(runs, 1)}", "for n, f in enumerate(reversed(runs), 1)}"),
    ("M271", "the report leaves the computed section out (D-2)", "analysis/campaign_report.py",
     '        lines += ["", *render_section(report.comparison)]\n', "        pass\n"),
    ("M272", "the model never sees the change facts it may cite (D-2)", "analysis/campaign_report.py",
     '            rows = "\\n".join(json.dumps(x.row(), ensure_ascii=False) for x in comparison.changes)\n',
     '            rows = ""\n'),
    ("M273", "a change claim that cites no change fact stays (D-2)", "analysis/campaign_report.py",
     '        elif c.kind == "change" and not changed:\n            c.rejected = "a change claim cites no change fact"\n',
     ""),
    ("M274", "a difference no cited fact holds stays (D-2)", "analysis/campaign_report.py",
     "(stray := _stray_numbers(c, cited)):", "(stray := []):"),
    ("M275", "a trend's numbers are not checked against its facts (D-2)", "analysis/campaign_report.py",
     '        elif (c.kind in ("trend", "change") or changed) and (stray',
     '        elif (c.kind in ("change",) or changed) and (stray'),
    ("M276", "a technique, a run id or a VM name is read as a number (D-2)", "analysis/campaign_report.py",
     '    text = _NAMES.sub(" ", _without_ids(c))\n', "    text = _without_ids(c)\n"),
    ("M277", "a change claim's value names an action the cited facts do not hold (D-2)",
     "analysis/campaign_report.py",
     "              and c.value not in set().union(*(x.words() for x in changed))):",
     "              and False):"),
    ("M278", "putting a campaign in again recomputes the facts its report saw (D-2)", "analysis/campaign_index.py",
     "        if fact is not None and fact.run_id == rid and fact.campaign_id == info.campaign_id:\n",
     "        if False:\n"),
    ("M279", "a campaign still running is put into the index (D-2)", "analysis/campaign_index.py",
     "    if info.state not in ENDED:\n", "    if False:\n"),
    # D-2, after its review: an observation citing a change fact has its numbers checked; an
    # unknown decision is never said acted through a change fact; a true trend is never
    # barred (a difference of two cited runs, a date in words, a year, an ordinal, a count);
    # a change names its facts' actions and detections, the way it went; a run without its id
    # is on its side.
    ("M510", "an observation citing a change fact has its numbers unchecked (D-2)", "analysis/campaign_report.py",
     '        elif (c.kind in ("trend", "change") or changed) and (stray',
     '        elif c.kind in ("trend", "change") and (stray'),
    ("M511", "a change fact lets an unknown decision be said acted, whatever its sides (D-2)",
     "analysis/campaign_report.py",
     "            elif _ACTED.search(told) and not all(\n"
     "                    isinstance(x, ChangeFact) and x.known_beside_unknown() for x in unknown):\n",
     "            elif _ACTED.search(told) and not changed:\n"),
    ("M512", "a trend may not write the difference of two cited runs (D-2)", "analysis/campaign_report.py",
     "    allowed += _run_differences(runs)\n", ""),
    ("M513", "a date in words, a year or an ordinal is read as a number (D-2)", "analysis/campaign_report.py",
     (_DATES_LINE,
      r'''    rf"|\b(?:19|20)\d{{2}}\b(?![.,]\d)(?!\s*{_UNIT})"''' + "\n",
      r'''    r"|\b\d+(?:ᵉ|e|er|ère|re|ème|eme)\b"''' + "\n"),
     ("", "", "")),
    ("M514", "a count of what a claim cites is read as a number a fact must hold (D-2)",
     "analysis/campaign_report.py",
     "    most = len(runs) + 2 * (len(cited) - len(runs))\n", "    most = 0\n"),
    ("M515", "a count above the runs a claim cites stays (D-2)", "analysis/campaign_report.py",
     "            if not (count and 1 <= v <= most)\n", "            if not (count and 1 <= v)\n"),
    ("M516", "a change claim names an action or a detection its facts do not hold (D-2)",
     "analysis/campaign_report.py",
     '        elif (c.kind in ("trend", "change") or changed) and (alien := _alien_word(c, cited)):\n'
     """            c.rejected = f"{alien!r} is not in the cited {'change facts' if changed else 'runs'}"\n""", ""),
    ("M517", "a change from one action or detection to another no fact holds stays (D-2)",
     "analysis/campaign_report.py",
     "        if a != b and (a, b) not in held:\n", "        if False:\n"),
    ("M518", "a change said the wrong way round (« de 106,9 s à 91,9 s ») stays (D-2)",
     "analysis/campaign_report.py",
     "        if said and not any(_near(x, before, tol) and _near(y, after, tol) for before, after, tol in sides):\n",
     "        if False:\n"),
    ("M519", "a run without its id is said only in the previous campaign (D-2)", "analysis/campaign_changes.py",
     "        if self.played_before and self.played_after:\n", "        if self.before_run and self.after_run:\n"),
    # D-2, after its second review: « de X à Y » read without a unit; a trend says the way its
    # runs went and names their actions only, an observation citing a change fact its facts';
    # only what is counted makes a count; a number is of its unit's kind, a duration
    # converted; a range of dates is a date; a relative change in percent is a fact's; « de X
    # à Y » from a fact's side lands on its other side.
    ("M530", "« de 0,78 à 0,8 », without a unit, is not read the wrong way round (D-2)",
     "analysis/campaign_report.py",
     (r'''    rf"\bde\s+(?P<a>{_NUM})\s*(?:{_UNIT})?{_BRACKETS}\s+à\s+(?P<b>{_NUM})"''' + "\n",
      r'''    rf"|(?P<c>{_NUM})\s*(?:{_UNIT})?{_BRACKETS}\s*(?:→|->)\s*(?P<d>{_NUM})", re.IGNORECASE)''' + "\n"),
     (r'''    rf"\bde\s+(?P<a>{_NUM})\s*{_UNIT}?{_BRACKETS}\s+à\s+(?P<b>{_NUM})"''' + "\n",
      r'''    rf"|(?P<c>{_NUM})\s*{_UNIT}?{_BRACKETS}\s*(?:→|->)\s*(?P<d>{_NUM})", re.IGNORECASE)''' + "\n")),
    ("M531", "a trend is not read for the way its runs went (D-2)", "analysis/campaign_report.py",
     '        elif (sides := changed or (_faced(cited, own) if c.kind == "trend" else [])) and (\n',
     "        elif (sides := changed) and (\n"),
    ("M532", "a trend names an action or a detection its runs do not hold (D-2)", "analysis/campaign_report.py",
     '        elif (c.kind in ("trend", "change") or changed) and (alien',
     '        elif (c.kind in ("change",) or changed) and (alien'),
    ("M533", "an observation citing a change fact names an action its facts do not hold (D-2)",
     "analysis/campaign_report.py",
     '        elif (c.kind in ("trend", "change") or changed) and (alien',
     '        elif c.kind in ("trend", "change") and (alien'),
    ("M534", "any word after a whole number makes it a count (« 1 heure plus tard ») (D-2)",
     "analysis/campaign_report.py",
     r'''    r"|passages?|cibles?|targets?|exécutions?|tirages?)(?![^\W\d_])", re.IGNORECASE)''' + "\n",
     r'''    r"|passages?|cibles?|targets?|exécutions?|tirages?)(?![^\W\d_])|\s*[^\W\d_]", re.IGNORECASE)''' + "\n"),
    ("M535", "a number's unit is not read: « 2 s » passes for a 2-point difference (D-2)",
     "analysis/campaign_report.py",
     '    return written in ("", held)\n', "    return True\n"),
    ("M536", "a duration is not converted: « 15 ms » passes for 15 s (D-2)", "analysis/campaign_report.py",
     '        out.append((float(m.group().replace(",", ".")) * one,\n',
     '        out.append((float(m.group().replace(",", ".")),\n'),
    ("M537", "a range of dates is read as numbers: « entre le 21 et le 23 octobre » barred (D-2)",
     "analysis/campaign_report.py",
     _DATES_LINE, r'''    rf"|\b\d{{1,2}}(?:er)?\s+(?:{_MONTHS})\b"''' + "\n"),
    ("M538", "a relative change is no fact's number: « +16 % » barred (D-2)", "analysis/campaign_changes.py",
     "        out += [(r, RELATIVE_TOLERANCE, RELATIVE)\n", "        out += [] and [(r, RELATIVE_TOLERANCE, RELATIVE)\n"),
    ("M539", "« de 91,9 s à 15 s », from a fact's side to no other side, stays (D-2)",
     "analysis/campaign_report.py",
     "        if any(_near(x, before, tol) for before, _, tol in sides) and not any(\n",
     "        if False and not any(\n"),
    # D-2, after its third review: a trend over three campaigns says the way between its
    # earlier runs, in either order, on the same technique; a date in English is a date; a
    # number before a date is no day of a range. M540–M542 follow D2b's _faced (their order
    # unknown, two earlier runs face each other both ways).
    ("M540", "a trend over three campaigns is barred: two earlier runs never face each other (D-2)",
     "analysis/campaign_report.py",
     "                out += [facing(x, y), facing(y, x)]\n", "                pass\n"),
    ("M541", "two earlier runs face each other in the order they are cited only (D-2)",
     "analysis/campaign_report.py",
     "                out += [facing(x, y), facing(y, x)]\n", "                out += [facing(x, y)]\n"),
    ("M542", "two earlier runs of different techniques face each other (D-2)", "analysis/campaign_report.py",
     "            if x is y or x.ttp != y.ttp or (x.run_id in own and y.run_id in own):\n",
     "            if x is y or (x.run_id in own and y.run_id in own):\n"),
    ("M543", "a date in English is read as a number: « since October 21 » barred (D-2)",
     "analysis/campaign_report.py",
     ('''           "|january|february|march|april|may|june|july|august|september|october|november|december")\n''',
      r'''    rf"|\b(?:{_MONTHS})\s+\d{{1,2}}(?:st|nd|rd|th)?\b"''' + "\n"),
     ('''           )\n''', "")),
    ("M544", "a number before a date is a day of a range: « baisse de 12, le 23 octobre » kept (D-2)",
     "analysis/campaign_report.py",
     _DATES_FIRST, r'''    rf"|(?:\b{_DAY}{_TH}"''' + "\n"),
    # D-2, after its fourth review: « des 21 et 23 octobre » and « du 21 et du 23 octobre » are
    # ranges; a day of a range is from 1 to 31. M546 and M547 follow D2b's openings and
    # articles.
    ("M545", "a day of a range is any number: « between 70 and 60, 23 October » kept (D-2)",
     "analysis/campaign_report.py",
     r'''_DAY = r"(?:3[01]|[12]\d|0?[1-9])(?!\d)"''', r'''_DAY = r"\d{1,2}"'''),
    ("M546", "a range of dates after « des », « aux », « from the » is read as numbers (D-2)",
     "analysis/campaign_report.py",
     _DATES_FIRST, r'''    rf"|(?:\b(?:le|les|entre|du|between|from|on)\s+{_DAY}{_TH}"''' + "\n"),
    ("M547", "« du 21 et du 23 octobre » is read as numbers (D-2)", "analysis/campaign_report.py",
     r"(?:(?:le|du|des|au|aux|the)\s+)?{_DAY}{_TH})+", r"(?:(?:le|des|au|aux|the)\s+)?{_DAY}{_TH})+"),
    # D2b (#184, after D-2) — the runs a trend cites face each other the way they were played,
    # read on their campaigns' starts; a manifest from the channel has its start bounded by
    # what H0 saw; « au » and « the » alone open no range of dates, « au … et au … » and « from
    # the … to the … » do, with their st, nd, rd.
    ("M650", "the order of the runs a trend cites is not read: a pair of earlier runs is an alibi (D2b)",
     CREP, "            first = _came_first(x, y)\n", "            first = None\n"),
    ("M651", "the runs a trend cites face each other against time (D2b)", CREP,
     "                out.append(facing(x, y) if first else facing(y, x))\n",
     "                out.append(facing(y, x) if first else facing(x, y))\n"),
    ("M652", "a run of the index comes without its campaign's start (D2b)", CREP,
     '    fact.campaign_started = _seconds(meta.get("campaign_started"))\n', ""),
    ("M653", "this campaign's runs come without its start: a later campaign's run is cited as earlier (D2b)",
     CREP, "        f.campaign_started = info.started\n", "        pass\n"),
    ("M654", "a campaign id that is a date gives no order (D2b)", CREP,
     "    return f.campaign_started if f.campaign_started is not None else _id_date(f.campaign_id)\n",
     "    return f.campaign_started\n"),
    ("M655", "two runs of one campaign are not ordered by seq (D2b)", CREP,
     "        return None if x.seq == y.seq else x.seq < y.seq\n", "        return None\n"),
    ("M656", "a channel manifest's start after its first window is believed (D2b)", CREP,
     "    if first_window is not None and started > first_window + FUTURE_SKEW_S:\n", "    if False:\n"),
    ("M657", "a channel manifest's start long before its first window is believed (D2b)", CREP,
     "    if first_window is not None and started < first_window - START_LEAD_S - FUTURE_SKEW_S:\n",
     "    if False:\n"),
    ("M658", "a channel manifest's start after H0 pulled it is believed (D2b)", CREP,
     "    if pulled is not None and started > pulled + FUTURE_SKEW_S:\n", "    if False:\n"),
    ("M659", "a refused start is not said in the report (D2b)", CREP,
     "        warn(info.start_refused)\n", "        pass\n"),
    ("M660", "a refused start is kept: the forged date chooses the previous campaign (D2b)", CREP,
     "            info.started = first\n", "            pass\n"),
    ("M661", "a window H-1 refuses bounds a manifest's start (D2b)", CREP,
     '        if not window or window.get("purged_at") or window_refusal(window, declared_at=declared):\n',
     '        if not window or window.get("purged_at"):\n'),
    ("M662", "« au » opens a range: « tombe au 12, le 23 octobre » kept (D2b)", CREP,
     r"des|aux|(?:on|from|between)\s+the", r"des|aux|au|(?:on|from|between)\s+the"),
    ("M663", "« the » alone opens a range: « by the 12, 23 October » kept (D2b)", CREP,
     r"aux|(?:on|from|between)\s+the|between", r"aux|the|between"),
    ("M664", "« au 21 et au 23 octobre » is read as numbers (D2b)", CREP, _DATES_AU, ""),
    ("M665", "« au », « aux », « the » refused inside a range: « from the 21 to the 23 October » barred (D2b)",
     CREP, r"(?:(?:le|du|des|au|aux|the)\s+)?", r"(?:(?:le|du|des)\s+)?"),
    ("M666", "a day of a range takes no st, nd, rd: « on the 21st and 23rd October » barred (D2b)", CREP,
     '_TH = r"(?:er|st|nd|rd|th)?"', '_TH = r"(?:er)?"'),
    # D2b, after its review: a date no UTC date holds is said, never raised; an unknown start
    # replaces an indexed one; two runs of this campaign make no trend.
    ("M667", "a manifest's date of year 10000 makes the report raise (D2b)", CREP,
     "    except (ValueError, OverflowError, OSError):\n        return str(read)[:40]",
     "    except ():\n        return str(read)[:40]"),
    ("M668", "an unknown start is left out of the row: the start an earlier indexing gave stays (D2b)", CREP,
     '        meta["campaign_started"] = float(campaign.started) if campaign.started is not None else ""\n',
     '        if campaign.started is not None:\n            meta["campaign_started"] = float(campaign.started)\n'),
    ("M669", "two runs of this campaign face each other in a trend (D2b)", CREP,
     "            if x is y or x.ttp != y.ttp or (x.run_id in own and y.run_id in own):\n",
     "            if x is y or x.ttp != y.ttp:\n"),
    # M-3 (#183) — the host of Glorfindel: Discord buttons check who clicks (closed by
    # default), each container gets only its secrets, H0 deploys a named reference whose
    # image carries it, and the image installs from the lock.
    ("M280", "a Discord button runs for whoever clicks it (M-3)", "glorfindel/bot.py",
     "        if not (isinstance(policy, ButtonPolicy) and policy.allows(interaction.user)):\n",
     "        if False:\n"),
    ("M281", "with no allowed users nor roles, every click passes (M-3)", "glorfindel/bot.py",
     '        if getattr(user, "id", None) in self.users:\n',
     '        if not self.configured or getattr(user, "id", None) in self.users:\n'),
    ("M282", "any role allows a click, not only an allowed one (M-3)", "glorfindel/bot.py",
     "        return bool(held & self.roles)\n", "        return bool(held)\n"),
    ("M283", "a refused click is not logged (M-3)", "glorfindel/bot.py",
     '    _console.print(\n        f"[yellow]Button refused:',
     '    (lambda *a: None)(\n        f"[yellow]Button refused:'),
    ("M284", "the bot's token reaches every container again (M-3)", "docker-compose.yml",
     "  DISCORD_CHANNEL_ID: ${DISCORD_CHANNEL_ID:-}\n",
     "  DISCORD_CHANNEL_ID: ${DISCORD_CHANNEL_ID:-}\n  DISCORD_BOT_TOKEN: ${DISCORD_BOT_TOKEN:-}\n"),
    ("M285", "the War Room receives the models' keys (M-3)", "docker-compose.yml",
     "      <<: [*env, *console-azure, *webhook]\n", "      <<: [*env, *console-azure, *models, *webhook]\n"),
    ("M286", "the watch knows the bot only by its token: every card also goes to the webhook (M-3)",
     "glorfindel/escalations.py",
     '    token = env.get("GLORFINDEL_DISCORD_BOT") or env.get("DISCORD_BOT_TOKEN")\n',
     '    token = env.get("DISCORD_BOT_TOKEN")\n'),
    ("M287", "H0 deploys a branch: any revision resolves (M-3)", "infra/glorfindel-host/deploy.sh",
     '  if commit=$(git rev-parse -q --verify "refs/tags/$ref^{commit}" 2>/dev/null); then\n',
     '  if commit=$(git rev-parse -q --verify "$ref^{commit}" 2>/dev/null); then\n'),
    ("M288", "the image does not carry the reference it was built from (M-3)",
     "infra/glorfindel-host/deploy.sh",
     '    --label "$LABEL_REF=$ref" --label "$LABEL_REV=$commit" \\\n', ""),
    ("M289", "the image resolves its dependencies again, unlocked (M-3)", "glorfindel/Dockerfile",
     "RUN pip install --no-cache-dir --no-deps --no-build-isolation -e .\n",
     'RUN pip install --no-cache-dir -e ".[glorfindel,war-room]"\n'),
    # M-3, review: a refusal must stop the click; a Discord channel alone runs no bot, so the
    # webhook still posts and the watch still warns; the watch learns only that the bot's
    # token is set; REF is a tag or a commit given on make's command line; a rules file that
    # both the VM and the reference change stops the deployment with what to do.
    ("M520", "a refused click is said, then let through to its callback (M-3, review)", "glorfindel/bot.py",
     "            await _refuse(interaction, self.esc_id, policy)\n            return False\n",
     "            await _refuse(interaction, self.esc_id, policy)\n            return True\n"),
    ("M521", "a Discord channel alone silences the webhook, no bot running (M-3, review)",
     "glorfindel/escalations.py",
     '    return bool(token and env.get("DISCORD_CHANNEL_ID"))\n',
     '    return bool(token or env.get("DISCORD_CHANNEL_ID"))\n'),
    ("M522", "the watch and the War Room receive the bot's token, not only that it is set (M-3, review)",
     "docker-compose.yml",
     "  GLORFINDEL_DISCORD_BOT: ${DISCORD_BOT_TOKEN:+1}\n",
     "  GLORFINDEL_DISCORD_BOT: ${DISCORD_BOT_TOKEN:-}\n"),
    ("M523", "the watch counts a Discord channel alone as alerting: no warning (M-3, review)", GCLI,
     "    _has_alerting = alerting_configured()\n",
     '    _has_alerting = bool(os.environ.get("GLORFINDEL_WEBHOOK_URL") '
     'or os.environ.get("DISCORD_CHANNEL_ID"))\n'),
    ("M524", "REF=--checkout-only reaches deploy.sh as an option (M-3, review)", MAKE,
     'make glorfindel-host-start REF=<tag ou commit> (REF= : le dernier tag v*)." >&2; exit 1;; esac\n\t@case "$$EREGION_DEPLOY_REF" in -*|*[!A-Za-z0-9._-]*) echo "REF invalide',
     'make glorfindel-host-start REF=<tag ou commit> (REF= : le dernier tag v*)." >&2; exit 1;; esac\n\t@case "$$EREGION_DEPLOY_REF" in *[!A-Za-z0-9._-]*) echo "REF invalide'),
    ("M525", "a REF exported in the environment is deployed in silence (M-3, review)", MAKE,
     '@case "$(origin REF)" in environment*) echo "REF vient de l\'environnement (« $$EREGION_DEPLOY_REF ») : rien n\'est déployé',
     '@case "$(origin REF)" in nowhere*) echo "REF vient de l\'environnement (« $$EREGION_DEPLOY_REF ») : rien n\'est déployé'),
    ("M526", "make expands a refused REF while exporting it: $(shell …) runs (M-3, review)", MAKE,
     "REF ?=\nunexport REF\n", "REF ?=\n"),
    ("M527", "the ssh line copies REF into the recipe: make expands it before it is checked (M-3, review)",
     MAKE, """bash -s -- '"$$EREGION_DEPLOY_REF" < infra/glorfindel-host/deploy.sh""",
     "bash -s -- $(REF)' < infra/glorfindel-host/deploy.sh"),
    # P1 moved this check: a rules file modified on the VM is refused with what to do (migrate).
    ("M528", "rules the VM approved: refused in git's words, not with what to do (M-3, review; P1)",
     "infra/glorfindel-host/deploy.sh",
     '  [ -z "$rules" ] || die "$(echo', '  [ -z "$rules" ] || true "$(echo'),
    # P1 (#86): rule layers — the shipped base stays intact, the client's rules in their own
    # layer (~/.glorfindel/client_rules.yaml), an approved rule binds to its backend.
    ("M670", "an approved rule is written into the shipped base again (P1)", "glorfindel/proposed_rules.py",
     "    how = rule_layers.write_client_rule(rule)\n",
     "    how = rule_layers.write_client_rule(rule, path=Path(rules_yaml_path))\n"),
    ("M671", "the client's layer is not loaded: an update loses the client's rules (P1)",
     "glorfindel/detection_rules.py",
     "    if client_layer:\n        cpath =", "    if False:\n        cpath ="),
    ("M672", "a base rule wins over the client's rule of the same name (P1)", "glorfindel/detection_rules.py",
     "            rules[at] = entry\n", "            pass\n"),
    ("M673", "`disable` ignored: a client cannot disable a base rule (P1)", "glorfindel/detection_rules.py",
     '        if r["name"] in disabled:\n', "        if False:\n"),
    ("M674", "a client rule replacing a base rule is not said (P1)", "glorfindel/detection_rules.py",
     '                notes.append(f"règle de base « {name} » remplacée par celle de la couche du client")\n',
     "                pass\n"),
    ("M675", "the notes are not logged: the watch's log says nothing of the client's layer (P1)",
     "glorfindel/detection_rules.py",
     '            logger.warning("detection rules: %s", note)\n', "            pass\n"),
    ("M676", "an unreadable client layer stops the base from loading (P1)", "glorfindel/detection_rules.py",
     "        except Exception as exc:\n            client = {}\n",
     "        except ImportError as exc:\n            client = {}\n"),
    ("M677", "an unreadable client layer is read as empty, then written over (P1)", "glorfindel/rule_layers.py",
     '        raise ClientLayerError(f"couche du client illisible ({path}) : {exc}") from exc\n',
     "        return {}\n"),
    ("M678", "a proposal is approved before its rule is written: approved without a rule (P1)",
     "glorfindel/proposed_rules.py",
     "    rule = rule_from_proposal(proposal, Path(rules_yaml_path))\n"
     "    how = rule_layers.write_client_rule(rule)\n\n"
     '    proposal["status"] = "approved"\n'
     '    proposal["approved_at"] = datetime.now(timezone.utc).isoformat()\n'
     "    lines[at] = json.dumps(proposal)\n"
     "    _write(lines)\n",
     '    proposal["status"] = "approved"\n'
     '    proposal["approved_at"] = datetime.now(timezone.utc).isoformat()\n'
     "    lines[at] = json.dumps(proposal)\n"
     "    _write(lines)\n"
     "    rule = rule_from_proposal(proposal, Path(rules_yaml_path))\n"
     "    how = rule_layers.write_client_rule(rule)\n"),
    ("M685", "migrate moves only new rules: a base rule changed on the VM is lost (P1)", "glorfindel/rule_layers.py",
     "    moved = [r for name, r in src_rules.items() if base_rules.get(name) != r]\n",
     "    moved = [r for name, r in src_rules.items() if name not in base_rules]\n"),
    ("M686", "migrate forgets a base rule removed on the VM: it comes back (P1)", "glorfindel/rule_layers.py",
     "    disable = [name for name in base_rules if name not in src_rules]\n", "    disable = []\n"),
    ("M687", "H0: a rules file modified on the VM rides into the image again (P1)", "infra/glorfindel-host/deploy.sh",
     "  dirty=$(git status --porcelain --untracked-files=no | awk '{print $NF}')\n",
     "  dirty=$(git status --porcelain --untracked-files=no | awk '{print $NF}' | grep -v '^glorfindel/rules/' || true)\n"),
    ("M688", "the watch's container mounts the shipped base read-write again (P1)", "docker-compose.yml",
     "      # redéploiement ne la touche jamais.\n      - ./glorfindel/rules:/app/glorfindel/rules:ro\n",
     "      # redéploiement ne la touche jamais.\n      - ./glorfindel/rules:/app/glorfindel/rules\n"),
    # P1, review: a bad client entry never stops the detection; an approved rule binds to its
    # backend. (The export's mutants left with the export, for a lot of P2: lot/p1b-export.)
    ("M695", "a client entry is not validated: `interval_s: 30s` stops every rule (P1, review)",
     "glorfindel/detection_rules.py",
     "            reason = _invalid_client_entry(key, entry)\n", "            reason = None\n"),
    ("M696", "a key of the client's layer that is not a list is not said (P1, review)",
     "glorfindel/detection_rules.py",
     "            notes.append(f\"couche du client : `{key}` n'est pas une liste, ignoré\")\n", "            pass\n"),
    ("M697", "an approved rule takes the inline form again: it applies to no VM (P1, review)",
     "glorfindel/proposed_rules.py",
     '                if backend_name:\n                    asset_name = "auto"\n',
     '                if False:\n                    asset_name = "auto"\n'),
    ("M698", "migrate does not bind a rule approved before P1 to its backend (P1, review)",
     "glorfindel/rule_layers.py",
     '            backend = backend_for_workspace(r["workspace_id"], backends)\n', '            backend = ""\n'),
    ("M699", "a rule that applies to no VM is not said at load (P1, review)", "glorfindel/detection_rules.py",
     "            notes.append(note)\n", "            pass\n"),
    # P1, second review: an approved rule is bound only to its own workspace's backend; what is
    # inert or unreadable is said.
    ("M713", "glorfindel rules hides the backend of an auto rule: bound and inert look alike (P1, review 2)",
     GCLI, '            assets = (f"auto ({r.monitoring_backend_name})" if r.monitoring_backend_name\n',
     '            assets = ("auto" if r.monitoring_backend_name\n'),
    ("M714", "an approved rule of another workspace borrows the first rule's backend (P1, review 2)",
     "glorfindel/proposed_rules.py",
     "backend_for_workspace(workspace, cfg.backends) if workspace else next(",
     "backend_for_workspace(workspace, cfg.backends) or next("),
    ("M715", "migrate-rules reads an unreadable config as « no backend » (P1, review 2)", GCLI,
     "        gcfg, config_error = None, str(exc)\n", '        gcfg, config_error = None, ""\n'),
    ("M716", "glorfindel rules says an ignored layer « absente » (P1, review 2)", GCLI,
     "    elif client_rules_path().exists():\n", "    elif False:\n"),
    # UI-1 (#205) — the Eregion console: the former addresses, the token's two names, the
    # injectors' routes read only, every page behind the token, the sections.
    ("M400", "the atelier's address no longer leads anywhere (UI-1)", CON,
     '@app.get("/atelier", include_in_schema=False)\nasync def atelier_moved(',
     "async def atelier_moved("),
    ("M401", "a former address redirects without its query (UI-1)", CON,
     '    return path + (f"?{q}" if q else "")\n', "    return path\n"),
    ("M402", "compose's empty EREGION_CONSOLE_TOKEN drops the token on H0 (UI-1)", CON,
     '    return os.environ.get(TOKEN_ENV, "") or os.environ.get(LEGACY_TOKEN_ENV, "")\n',
     '    return os.environ[TOKEN_ENV] if TOKEN_ENV in os.environ else os.environ.get(LEGACY_TOKEN_ENV, "")\n'),
    ("M403", "an injector's route accepts a POST (UI-1)", CON,
     '@app.get("/api/exercises")\n', '@app.api_route("/api/exercises", methods=["GET", "POST"])\n'),
    ("M404", "a new page is served without the token (UI-1)", CON,
     '        if not (by_bearer or by_cookie):\n',
     '        if not (by_bearer or by_cookie) and scope.get("path") != "/dagorlad":\n'),
    ("M405", "/runs/<id> takes a path for a run id (UI-1)", CON,
     "    if not safe_part(run_id):\n", "    if not run_id:\n"),
    ("M406", "--sections removes Glorfindel (UI-1)", SEC,
     '            sections.append({**s, "active": True, "always": True, "setup": glorfindel_setup()})\n',
     '            sections.append({**s, "active": forced is None, "always": True, "setup": glorfindel_setup()})\n'),
    ("M407", "--sections is ignored: the detection wins (UI-1)", SEC,
     "        if forced is not None:\n", "        if False:\n"),
    # UI-2 (#206) — the five indicators: a run's own decision, nothing invented in human-only,
    # the shadow bounded by the verdicts, 30 days from the reports, a proof is detection AND
    # decision, coverage counts what was detected.
    # Retargeted at C1's review (30/10): the decision is found by bisection in an index; the
    # bug, as it was — any record of the technique after the attack, the oldest first.
    ("M560", "a run takes any decision of its technique, not the one at its detection (UI-2)", IND,
     ("    found = [(t, c) for t, c in zip(times[lo:hi], cands[lo:hi])\n",
      "    best = min(found, key=lambda tc: (abs(tc[0] - seen_at), tc[0]))[1] if found else None\n"),
     ("    found = [(t, c) for t, c in zip(times, cands) if t >= run[\"at\"]\n",
      "    best = min(found, key=lambda tc: tc[0])[1] if found else None\n")),
    ("M561", "a recommendation counts as contained alone in human-only (UI-2; since BL1, its check lives in analysis/containment.py)",
     "analysis/containment.py",
     '    if decision["executed"] is True:\n        if decision["verified"] is True and not decision["unverified"]:\n            return CONTAINED, ""\n',
     '    if True:\n        if True:\n            return CONTAINED, ""\n'),
    ("M562", "the shadow share ignores a verdict « wrong » (UI-2)", IND,
     '                and r["run_id"] not in judged_wrong):\n', "                ):\n"),
    ("M563", "the indicators take runs older than 30 days (UI-2)", IND,
     "        if at is None or at < since:\n", "        if at is None:\n"),
    ("M564", "a detection without a decision counts as a proof (UI-2)", IND,
     "        d = decision_of(r, cycles)\n        if d is None:\n            continue\n        proofs.append(r)\n",
     "        proofs.append(r)\n        d = decision_of(r, cycles)\n        if d is None:\n            continue\n"),
    ("M565", "coverage counts a missed technique as covered (UI-2)", IND,
     '    covered = {r["ttp"] for r in detected}\n', '    covered = {r["ttp"] for r in attacks}\n'),
    # The version beside the logo: the reference deploy.sh builds from, the deployed tag first.
    ("M566", "deploy.sh does not pass the reference to the build: the console cannot say what it runs (UI-2)",
     "infra/glorfindel-host/deploy.sh",
     '    --build-arg "EREGION_REF=$ref" --build-arg "EREGION_REVISION=$commit" \\\n', ""),
    ("M567", "the header shows the package's version over the deployed tag (UI-2)", SEC,
     '    label = ref or (f"v{package}" if package else "")', '    label = (f"v{package}" if package else "")'),
    # #222 — finitions: the content security policy on every response.
    ("M568", "the console's pages can be framed by another site, and talk to another origin (#222)", CON,
     '    response.headers.update(_HEADERS)\n', ""),
    ("M569", "glorfindel --version written by hand again: it drifts from the package (#222)", GCLI,
     '@click.version_option(package_name="eregion", prog_name="glorfindel")',
     '@click.version_option(version="0.2.0", prog_name="glorfindel")'),
    ("M570", "a new card type shows under its raw name: quarantine_altered unlabelled (#248)", GJS,
     "  quarantine_altered:  'quarantine NSG altered',\n", ""),
    ("M571", "a control-plane card gets the anchor VM's Restore and restore command back (#248)", GJS,
     "const _ANCHORED_TYPES = new Set(['control_plane_change', 'identity_change', 'unattributed_signal']);",
     "const _ANCHORED_TYPES = new Set(['identity_change', 'unattributed_signal']);"),
    ("M572", "a card on a quarantine NSG asks for a verdict, as if a decision (#248)", GJS,
     "const _NOT_DECISIONS = new Set(['posture_gap', 'orphan_rule', 'quarantine_altered', 'proposed_rule',",
     "const _NOT_DECISIONS = new Set(['posture_gap', 'orphan_rule', 'proposed_rule',"),
    ("M573", "the feed loses what held a decision without action: an empty « escalate → » (#248)", CON,
     '        "held_by": data.get("held_by", ""),\n', ""),
    ("M574", "what Glorfindel closed itself stays on its tile forever (#248)", CON,
     "if (now - at).total_seconds() <= _HANDLED_FOR_H * 3600:", "if True:"),
    ("M575", "a card a human acknowledged shows as done by Glorfindel (#248)", CON,
     'if e.get("status") != "resolved" or not e.get("resolution"):', 'if e.get("status") != "resolved":'),
    ("M576", "a card's reason written raw into the page: an Entra app's name runs in the console (XSS)", GJS,
     "line-height:1.6\">${_attr(e.reason || '')}</div>", "line-height:1.6\">${e.reason || ''}</div>"),
    ("M577", "a card's suggested steps written raw into the page (XSS)", GJS,
     "• ${_attr(s)}</div>", "• ${s}</div>"),
    ("M578", "a card's proposed query written raw into the page (XSS)", GJS,
     "${_attr(e.proposed_query.trim())}</pre>", "${e.proposed_query.trim()}</pre>"),
    ("M579", "an anchored card offers Restore on its anchor VM again (#248)", GJS,
     "const isRestore = e.action === 'restore_from_backup' && !_isAnchored(e);",
     "const isRestore = e.action === 'restore_from_backup';"),
    # #254: what comes from the outside is escaped where it lands — the page's text, an on…
    # attribute (_js), a URL — and the reader (scripts/console_escaping.py) finds it raw.
    ("M580", "a feed signal's event written raw: a run's report runs in the console (#254)", GJS,
     "${icon} ${_attr(entry.event)}</span>", "${icon} ${entry.event}</span>"),
    ("M581", "a feed action written raw: the model's invented action name runs in the console (#254)", GJS,
     '<span class="feed-event ${cls}">${icon} ${_attr(label)}</span>', '<span class="feed-event ${cls}">${icon} ${label}</span>'),
    ("M582", "a feed entry's technique and VM written raw (#254)", GJS,
     """      <span class="feed-meta">${_attr(entry.ttp || '')} ${_attr(entry.vm || '')}</span>\n      <span class="feed-pct">""",
     """      <span class="feed-meta">${entry.ttp || ''} ${entry.vm || ''}</span>\n      <span class="feed-pct">"""),
    ("M583", "a rule's query written raw in its window: a rule the model wrote runs in the console (#254)", GJS,
     "${_attr((rule.query || '').trim())}", "${(rule.query || '').trim()}"),
    ("M584", "a rule's description written raw in its window (#254)", GJS,
     "${_attr(rule.description || '—')}", "${rule.description || '—'}"),
    ("M585", "a rule's name written raw in its row (#254)", GJS,
     '<span style="color:${dc};font-size:9px">●</span>\n      <span style="flex:1;min-width:0;overflow:hidden;'
     'text-overflow:ellipsis;white-space:nowrap" title="${_attr(r.name)}">${_attr(r.name)}</span>',
     '<span style="color:${dc};font-size:9px">●</span>\n      <span style="flex:1;min-width:0;overflow:hidden;'
     'text-overflow:ellipsis;white-space:nowrap" title="${_attr(r.name)}">${r.name}</span>'),
    ("M586", "a decision's technique written raw on the VM card (#254)", GJS,
     '<span class="dec-ttp">${_attr(a.ttp)}</span>', '<span class="dec-ttp">${a.ttp}</span>'),
    ("M587", "a card's title written raw: the `|| e.action` fallback runs the model's text (#254)", GJS,
     '<span class="esc-action-label">${_attr(label)}</span>', '<span class="esc-action-label">${label}</span>'),
    ("M588", "a card's title written raw in its detail (#254)", GJS,
     'font-size:12px">${_attr(label)}</span>', 'font-size:12px">${label}</span>'),
    ("M589", "the configuration's error written raw (#254)", GJS,
     "Failed to load config: ${_attr(e.message)}</div>", "Failed to load config: ${e.message}</div>"),
    ("M590", "a handler's argument between quotes again: a VM name with a quote runs on click (#254)", GJS,
     "${_on('click', 'showEscModal', vm_name)}", "onclick=\"showEscModal('${vm_name}')\""),
    ("M591", "the IP to block written into the handler raw (#254)", GJS,
     "${_on('click', 'approveScoped', escId, vmName, 'vm', ip)}",
     "onclick=\"closeModal();doApproveAction('${escId}','${vmName}',{scope:'vm',ip:'${ip}'})\""),
    ("M592", "_attr raises on what is not a string: the card's window no longer opens (#254)", GJS,
     "  return String(s ?? '').replace(/&/g, '&amp;')", "  return (s || '').replace(/&/g, '&amp;')"),
    ("M593", "_attr lets a tag through (#254)", GJS, ".replace(/</g, '&lt;')", ""),
    ("M594", "_attr leaves a single quote: a value ends a single-quoted attribute (#254; _js is gone, #257)", GJS,
     ".replace(/'/g, '&#39;')", ""),
    ("M595", "the overview writes a section's label raw (#254)", "eregion_console/static/overview.js",
     "no ${esc(s.label)} window in the last 7 days", "no ${s.label} window in the last 7 days"),
    ("M596", "the reader takes `x || field` for the page's: the labels' fallback goes unseen (#254)", CESC,
     '            if node.text in ("||", "??"):', '            if node.text == "??":'),
    ("M597", "the reader takes an on… attribute for text: HTML escaping passes there (#254)", CESC,
     '            return "never"\n        if name in _URL_ATTRS', '            return "html"\n        if name in _URL_ATTRS'),
    ("M598", "the reader misses what goes into a Map: the cards' buttons go unseen (#254)", CESC,
     "                elif method not in _PURE:\n                    self._uses.extend((t.text, t.pos, a) for a in args)",
     "                elif False:\n                    self._uses.extend((t.text, t.pos, a) for a in args)"),
    ("M599", "the reader takes a promise's callback argument as the page's (#254)", CESC,
     "                if fn.escapes or not (fn.named or fn.feeds):", "                if fn.escapes:"),
    # #257: scripts from the console's files only — the CSP, the page's events without inline
    # handlers (data-on-*, a closed table), and the reader's S1–S8 (#256's review).
    ("M1080", "the CSP lets inline scripts and handlers run again (#257)", CON,
     """_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; \"""",
     """_CSP = ("style-src 'self' 'unsafe-inline'; img-src 'self'; \""""),
    ("M1081", "the CSP's script-src takes 'unsafe-inline': an injected handler runs (#257)", CON,
     """_CSP = ("default-src 'self'; script-src 'self'; style-src""",
     """_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src"""),
    ("M1082", "the CSP lets a plugin load (#257)", CON,
     """        "object-src 'none'; frame-ancestors 'none'; connect-src 'self'; base-uri 'none'; \"""",
     """        "frame-ancestors 'none'; connect-src 'self'; base-uri 'none'; \""""),
    ("M1083", "an inline handler back in a card: the CSP blocks it, the card no longer opens (#257)", GJS,
     "${_on('click', 'showEscModal', vmName)}", "onclick=\"showEscModal('${vmName}')\""),
    ("M1084", "an inline script back in the overview (#257)", "eregion_console/static/overview.html",
     '<script src="/static/overview.js"></script>', '<script src="/static/overview.js"></script><script>refresh()</script>'),
    ("M1085", "the page's events call a name the table only inherits (constructor, toString…) (#257)", GJS,
     "  if (!Object.hasOwn(ACTIONS, action)) return;", "  if (!(action in ACTIONS)) return;"),
    ("M1086", "a click on an action's text or icon does nothing: only the element itself takes the event (#257)", GJS,
     "  const el = ev.target instanceof Element ? ev.target.closest(`[data-on-${name}]`) : null;",
     "  const el = ev.target instanceof Element && ev.target.hasAttribute(`data-on-${name}`) ? ev.target : null;"),
    ("M1087", "the events dispatched after the document's other listeners: whether an action runs hangs on the order they were added (#257)", GJS,
     "document.addEventListener(type, ev => _dispatch(ev, name), true);", "document.addEventListener(type, ev => _dispatch(ev, name));"),
    ("M1088", "an element's arguments written raw into its attribute (#257)", GJS,
     '` data-${event}-args="${_attr(JSON.stringify(args))}"`', '` data-${event}-args="${JSON.stringify(args)}"`'),
    ("M1089", "a button names an action the table does not hold: it does nothing (#257)", GJS,
     "  showIsolationModal, showReasoning, showRuleByIdx, toggleAsset, toggleBackend, closeModal,",
     "  showIsolationModal, showReasoning, showRuleByIdx, toggleAsset, closeModal,"),
    ("M1090", "the reader reads a concatenation as text: an escaped javascript: URL goes unseen (S1, #257)", CESC,
     '            if node.text == "+":\n                return self._concat(node, ctx)',
     '            if node.text == "+":\n                return self.raw(kids[0], ctx) + self.raw(kids[1], ctx)'),
    ("M1091", "the reader lets document.write through (S2, #257)", CESC,
     '        return "document.write (not followed: innerHTML, escaped)"', "        return None"),
    ("M1092", "the reader lets setAttribute('onclick', …) through (S2, #257)", CESC,
     '            return "setAttribute of a handler, a URL, an action or a name not written in the page"', "            return None"),
    ("M1093", "the reader takes any .length for a number, a server object's too (S4, #257)", CESC,
     '            if node.text in ("length", "size") and self._built(kids[0]):', '            if node.text in ("length", "size"):'),
    ("M1094", "the reader takes srcdoc for an attribute like another (S5, #257)", CESC,
     '        if name.startswith("on") or name == "srcdoc" or name.startswith("data-on-"):',
     '        if name.startswith("on") or name.startswith("data-on-"):'),
    ("M1095", "the reader's count leaves out the nested templates: a skipped one would go unseen (S6, #257)", CESC,
     '    return sum(len(t.exprs) + sum(_count(e) for e in t.exprs) for t in toks if t.kind == "tpl")',
     '    return sum(len(t.exprs) for t in toks if t.kind == "tpl")'),
    ("M1096", "the reader lets an inline handler through (#257)", CESC,
     '_REFUSED = re.compile(r"(?<![\\w-])on[a-z]+\\s*=(?!=)|<script\\b|javascript:|(?<![\\w-])srcdoc\\s*=|<meta\\b", re.I)',
     '_REFUSED = re.compile(r"<script\\b|javascript:|(?<![\\w-])srcdoc\\s*=|<meta\\b", re.I)'),
    ("M1097", "the reader takes a function in a table (ACTIONS) as called by the page only (#257)", CESC,
     "            elif j == k + 1:\n                # Passed as a value",
     "            elif j == k + 1 and not (prev is not None and prev.text in ('{', ',') and nxt is not None\n"
     "                                     and nxt.text in (',', '}')):\n                # Passed as a value"),
    ("M1098", "the reader lets `href=\"/${esc(x)}\"` through: x = `/host` is another site (S8, #257)", CESC,
     '        if name in _URL_ATTRS and value in ("", "/"):', '        if name in _URL_ATTRS and value == "":'),
    ("M1099", "the overview links a section by its id escaped for HTML only (S8, #257)", "eregion_console/static/overview.js",
     '<div class="name"><a href="/${encodeURIComponent(s.id)}">', '<div class="name"><a href="/${esc(s.id)}">'),
    # #257's review (5.5): an action is a name the page wrote; what an injected element could still
    # make the page do; the rebindings and prefixes the reader missed.
    ("M1290", "the reader lets a data-on-* name its action from a card, escaped or not (#257)", CESC,
     '        if name.startswith("on") or name == "srcdoc" or name.startswith("data-on-"):',
     '        if name.startswith("on") or name == "srcdoc":'),
    ("M1291", "the reader lets setAttribute('data-on-click', …) name an action from a value (#257)", CESC,
     'r"(on|srcdoc$|style$|data-on-)|', 'r"(on|srcdoc$|style$)|'),
    ("M1292", "the reader lets dataset.onClick name an action from a value (#257)", CESC,
     '        return "an action set from a value (dataset.on…: only _on, in a template)"', "        return None"),
    ("M1293", "an injected element with a value changes a VM's mode: no <select> needed (#257)", GJS,
     "    if (!(_target instanceof HTMLSelectElement)) return;\n    if (_target.value === 'non_disruptive')",
     "    if (_target.value === 'non_disruptive')"),
    ("M1294", "an element's arguments may be an object: an approval skips its scope window (#257)", GJS,
     "  if (!Array.isArray(args) || !args.every(a => a === null || ['string', 'number', 'boolean'].includes(typeof a))) return;\n",
     ""),
    ("M1295", "the reader lets setAttributeNS through (#257)", CESC,
     '        return "setAttributeNS (not followed)"', "        return None"),
    ("M1296", "the reader lets a navigation through: location.assign(x) (#257)", CESC,
     '            return "a navigation the reader does not follow (a link, escaped, instead)"', "            return None"),
    ("M1297", "the reader takes a let's .length for a number: a destructuring rebinds it to the server's (#257)", CESC,
     "            return d.kind == \"var\" and d.const and d.init is not None and self._built(d.init, seen)",
     "            return d.kind == \"var\" and d.init is not None and self._built(d.init, seen)"),
    ("M1298", "the reader reads a const prefix as a value: `pre + _attr(u)` with pre = '<a href=\"' unseen (#257)", CESC,
     "            if (literal := self._literal(part)) is not None:",
     "            if part.kind == \"lit\" and (literal := self._literal(part)) is not None:"),
    ("M1299", "the reader misses a destructuring assignment: [a] = [card] goes unseen (#257)", CESC,
     "                for x in _pattern_names(toks, k, p.close[k]):\n"
     "                    self._uses.append((toks[x].text, toks[x].pos, value))\n"
     "                    self._reassigns.append((toks[x].text, toks[x].pos, value))",
     "                for x in _pattern_names(toks, k, p.close[k]):\n                    pass"),
    ("M408", "eregion console keeps compose's empty service principal: no managed identity (UI-1, H0)",
     "eregion_console/cli.py", "    _drop_empty_service_principal_env()\n", ""),
    ("M409", "the console looks for the shipped rules beside itself: none outside the repo's root (UI-1, P1 review)",
     CON, "    from glorfindel.cli import _find_rules_file\n    found = _find_rules_file()\n",
     '    found = next((str(p) for p in (Path("glorfindel/rules/azure/detection_rules.yaml"),\n'
     '                                   Path(__file__).parent / "rules" / "azure" / "detection_rules.yaml")\n'
     "                  if p.exists()), None)\n"),
    # V1 (#214): Annatar and Gothmog do not act without Glorfindel — the watch's heartbeat read
    # before any call to the cloud; --without-glorfindel said in the report.
    ("M720", "annatar run without a live watch is not refused (V1)", ENG,
     "            if no_watch:\n                console.print(", "            if False:\n                console.print("),
    ("M721", "annatar reads the watch after its first call to the cloud (V1)", ENG,
     (_V1_ANNATAR_GATE, _V1_ANNATAR_ARM), ("", _V1_ANNATAR_ARM + _V1_ANNATAR_GATE)),
    ("M722", "an atomic run --without-glorfindel does not say so in its report (V1)", ENG,
     "            **watch_gate.without_metrics(self.without_glorfindel),\n", ""),
    ("M723", "a local-script run --without-glorfindel does not say so in its report (V1)", ENG,
     "        metrics = watch_gate.without_metrics(self.without_glorfindel)\n", "        metrics = {}\n"),
    ("M724", "gothmog run without a live watch is not refused (V1)", GOTH,
     "        if not no_watch:\n            return None\n", "        return None\n"),
    ("M725", "gothmog reads the watch after its first call to the cloud (V1)", GOTH,
     (_V1_GOTHMOG_GATE, _V1_GOTHMOG_BENCH), ("", _V1_GOTHMOG_BENCH + _V1_GOTHMOG_GATE)),
    ("M726", "a fault --without-glorfindel does not say so in its report (V1)", GOTH,
     "                                    **self._without, **metrics},\n",
     "                                    **metrics},\n"),
    ("M727", "gothmog preflight without a live watch answers « could run » (V1)", GOTH,
     "        refused = self._no_watch(run_id, without_glorfindel)\n        if refused:\n"
     "            return refused\n        verdict, session = arm(run_id, \"gothmog\")\n",
     "        verdict, session = arm(run_id, \"gothmog\")\n"),
    ("M728", "a campaign without a live watch starts, and turns 'running' (V1)", CRUN,
     "        if not self.without_glorfindel:\n            no_watch = watch_gate.refusal()\n",
     "        if False:\n            no_watch = watch_gate.refusal()\n"),
    ("M729", "a campaign goes on after a run refused for no watch (V1)", CRUN,
     '            elif (entry.error or "").startswith("glorfindel:"):\n', "            elif False:\n"),
    ("M730", "campaign run --without-glorfindel does not reach its runs (V1)", CRUN,
     "            lambda: Engine(skip_preflight=False, without_glorfindel=without_glorfindel))\n",
     "            lambda: Engine(skip_preflight=False))\n"),
    ("M731", "a heartbeat of any age is a live watch (V1)", WCH,
     "    return -CLOCK_SKEW_S <= age < FRESH_S\n", "    return -CLOCK_SKEW_S <= age\n"),
    ("M732", "the return channel is not read: the hosted watch is never seen from Orodruin (V1)",
     "eregion_core/watch_gate.py", '    beat = READERS["channel"]()\n', "    beat = None\n"),
    ("M733", "an unreadable channel raises instead of refusing (V1)", "eregion_core/watch_gate.py",
     "    except Exception as e:  # unreadable is no watch — said, never raised\n",
     "    except ValueError as e:  # unreadable is no watch — said, never raised\n"),
    ("M734", "H0 accepts a run without Glorfindel that claims a verdict (V1)", "analysis/campaign_schema.py",
     '    if without is True and metrics.get("detection") in ("detected", "missed"):\n', "    if False:\n"),
    ("M735", "the console drops the flag: a run without Glorfindel shows as unknown (V1)", CON,
     '    if m.get("without_glorfindel") is True:  # V1: run --without-glorfindel, shown apart\n',
     "    if False:\n"),
    ("M736", "a local-script run --without-glorfindel still waits for a detection (V1)", ENG,
     "        if scenario.detection and detection_timeout_s > 0 and " + _V1_WAIT,
     "        if scenario.detection and detection_timeout_s > 0 and not self.dry_run:\n"),
    ("M737", "an atomic run --without-glorfindel still waits for a detection (V1)", ENG,
     "        if attack_started and detection_timeout_s > 0 and " + _V1_WAIT,
     "        if attack_started and detection_timeout_s > 0 and not self.dry_run:\n"),
    ("M738", "make gothmog-run drops WITHOUT_GLORFINDEL (V1)", MAKE,
     "'$(ORO_RUN) gothmog run $(FAULT) --yes$(ORO_WITHOUT)'", "'$(ORO_RUN) gothmog run $(FAULT) --yes'"),
    ("M739", "make orodruin-campaign-run drops WITHOUT_GLORFINDEL (V1)", MAKE,
     "annatar campaign run $(CAMPAIGN) --yes$(ORO_WITHOUT)'", "annatar campaign run $(CAMPAIGN) --yes'"),
    # V1, review: a campaign without Glorfindel says so, resumes only the same way, has no
    # analysis report and never enters the index; the channel decides; no heartbeat from the future.
    ("M750", "a campaign --without-glorfindel does not say so in its manifest (V1)", CRUN,
     "        m.without_glorfindel = self.without_glorfindel\n", ""),
    ("M751", "a campaign is resumed with another --without-glorfindel than it started with (V1)", CRUN,
     "        if m.state == \"running\" and m.without_glorfindel != self.without_glorfindel:\n",
     "        if False:\n"),
    ("M752", "a campaign without Glorfindel gets an analysis report, its decisions sought (V1)", CREP,
     "    if why := no_report(campaign_dir):\n        raise NoReport(why)\n", ""),
    ("M753", "H0 writes the report of a campaign without Glorfindel (V1)", HREP,
     "        if campaign_schema.without_glorfindel(manifest):  # V1: no report, by choice\n",
     "        if False:\n"),
    ("M754", "a campaign without Glorfindel enters the index: a previous campaign to compare (V1)",
     "analysis/campaign_index.py",
     "    if cr.without_glorfindel(manifest):  # V1: no detection measured — never compared\n",
     "    if False:\n"),
    ("M755", "an aborted campaign exits 0: make orodruin-campaign-run succeeds (V1)", ACLI,
     "        if result.state == \"aborted\":\n            raise SystemExit(EXIT_RUN_FAILED)\n", ""),
    ("M756", "a heartbeat dated in the future stays fresh for ever (V1)", WCH,
     "    return -CLOCK_SKEW_S <= age < FRESH_S\n", "    return age < FRESH_S\n"),
    ("M757", "WITHOUT_GLORFINDEL=0 waives the watch on Orodruin (V1)", MAKE,
     "$(if $(filter 1 yes true,$(WITHOUT_GLORFINDEL)), --without-glorfindel)",
     "$(if $(WITHOUT_GLORFINDEL), --without-glorfindel)"),
    ("M758", "a live local file counts though the return channel is set (V1)",
     "eregion_core/watch_gate.py", "    if beat is None:\n        beat = READERS[\"local\"]()\n",
     "    if beat is None or not fresh(beat, now):\n        beat = READERS[\"local\"]()\n"),
    ("M759", "the console counts a campaign without Glorfindel as unknown (V1)", CON,
     '            "without_glorfindel": m.get("without_glorfindel") is True,   # V1: counted apart\n', ""),
    # UI-1c (#205) — the console on the host: the token under its two names, from the operator's
    # machine (Makefile, status.sh) and in host.env (host_env.py), never shown.
    ("M740", "make glorfindel-host-url ignores EREGION_CONSOLE_TOKEN: a new host gets no URL (UI-1c)", MAKE,
     'CONSOLE_TOKEN  = $$(t=$$($(call HOST_ENV_VALUE,EREGION_CONSOLE_TOKEN)); [ -n "$$t" ] || t=',
     "CONSOLE_TOKEN  = $$(t="),
    ("M741", "make glorfindel-host-url without the former name: H0's host.env gives no URL (UI-1c)", MAKE,
     '; [ -n "$$t" ] || t=$$($(call HOST_ENV_VALUE,GLORFINDEL_WARROOM_TOKEN))', ""),
    ("M742", "the Makefile takes an empty EREGION_CONSOLE_TOKEN as the token (UI-1c)", MAKE,
     '[ -n "$$t" ] || t=$$($(call HOST_ENV_VALUE,GLORFINDEL_WARROOM_TOKEN))',
     "grep -q '^EREGION_CONSOLE_TOKEN=' $(HOST_ENV) || t=$$($(call HOST_ENV_VALUE,GLORFINDEL_WARROOM_TOKEN))"),
    ("M743", "the Makefile takes the first line of a key, compose the last (UI-1c)", MAKE,
     "p;}' $(HOST_ENV) | tail -1\n", "p;}' $(HOST_ENV) | head -1\n"),
    ("M744", "status.sh without the former name: H0's console never answers (UI-1c)",
     "infra/glorfindel-host/status.sh",
     '[ -n "$tok" ] || tok=$(env_value GLORFINDEL_WARROOM_TOKEN)\n', ""),
    ("M745", "status.sh ignores EREGION_CONSOLE_TOKEN (UI-1c)", "infra/glorfindel-host/status.sh",
     "tok=$(env_value EREGION_CONSOLE_TOKEN)\n", 'tok=""\n'),
    ("M746", "status.sh puts the token on curl's command line, where ps shows it (UI-1c)",
     "infra/glorfindel-host/status.sh",
     "printf 'Authorization: Bearer %s\\n' \"$tok\" | curl -s -H @- \"http://127.0.0.1:7007$1\"",
     'curl -s -H "Authorization: Bearer $tok" "http://127.0.0.1:7007$1"'),
    ("M747", "status.sh traces its remote script: the token is printed (UI-1c)",
     "infra/glorfindel-host/status.sh",
     'cd eregion || { echo "  ✗ dépôt absent"; exit 1; }\n',
     'set -x; cd eregion || { echo "  ✗ dépôt absent"; exit 1; }\n'),
    ("M748", "a new host's token is drawn under the former name (UI-1c)", "infra/glorfindel-host/host_env.py",
     "    out[TOKEN] = secrets.token_urlsafe(24)\n", "    out[LEGACY_TOKEN] = secrets.token_urlsafe(24)\n"),
    ("M749", "host_env.py --check refuses H0's host.env, under the former name (UI-1c)",
     "infra/glorfindel-host/host_env.py",
     "    for name in (TOKEN, LEGACY_TOKEN):\n", "    for name in (TOKEN,):\n"),
]

# I1F (#226): our quarantine NSG altered while its NICs' state is lost — read, and said.
MUTANTS += [
    ("M830", "the reassertion doesn't read the quarantine NSGs: one altered, its NICs' state lost, "
             "goes unsaid (I1F, L2)", R,
     "    _whatever_the_state(connector, autonomy, report)\n    return report\n\n\ndef reassert_pass(",
     "    return report\n\n\ndef reassert_pass("),
    ("M831", "a rule's signature leaves its protocol out: our quarantine deny turned to Udp reads as "
             "ours (I1F)", NSG,
     '            getattr(rule, "priority", None), _enum_text(getattr(rule, "protocol", "")),\n',
     '            getattr(rule, "priority", None),\n'),
    ("M832", "the quarantine denies are written for UDP only: TCP from the VNet reaches a VM "
             "in quarantine (I1F)", QUA,
     '                protocol="*", source_address_prefix="*", destination_address_prefix="*",\n',
     '                protocol="Udp", source_address_prefix="*", destination_address_prefix="*",\n'),
    ("M833", "the altered quarantine's card is closed at the next pass, its change standing (I1F)", RQ,
     "        if k in altered and altered[k][0] == sid:\n            said.add(sid)\n"
     "        elif k in altered or settled(k):\n",
     "        if k in altered or settled(k):\n"),
    # After the review (5.5): the watch's pass, an acknowledgement, an unknown.
    ("M834", "nothing recorded: the pass reads no quarantine NSG (I1F, review)", R,
     "    report: list[dict] = []\n    _whatever_the_state(connector, autonomy, report)\n    return report\n",
     "    return []\n"),
    ("M836", "an acknowledged quarantine card comes back at every pass (I1F, review)", RQ,
     "        if signal_id in said or (alerts.get(k) == signal_id and acknowledged(k, signal_id)):\n",
     "        if signal_id in said:\n"),
    ("M837", "a quarantine card closed on an NSG read as unknown (I1F, review)", RQ,
     '            return seen[k].get("status") != "unknown" and k not in altered\n',
     "            return k not in altered\n"),
    ("M835", "the watch's thread hands over only when something is recorded (I1F, review)", GCLI,
     "        _watch_reassert_pass(ttl_connector, mode_override, _output_lock, _reassert_seen)\n",
     "        from glorfindel.actions import active_blocks, active_isolations\n"
     "        if active_isolations() or active_blocks():\n"
     "            _watch_reassert_pass(ttl_connector, mode_override, _output_lock, _reassert_seen)\n"),
    ("M838", "the quarantine NSGs read in `quarantine_rg` only: one made in another group goes unseen "
             "(I1F, second review)", QUA,
     "            if (not _is_quarantine_nsg(nsg_id)\n",
     "            if (not _is_quarantine_nsg(nsg_id) or (self._quarantine_settings()[1] and "
     "f\"/resourcegroups/{self._quarantine_settings()[1].lower()}/\" not in nsg_id.lower())\n"),
    ("M839", "the watch's pass stops on an empty local state (I1F, second review)", GCLI,
     "    seen = seen if seen is not None else {}\n",
     "    seen = seen if seen is not None else {}\n"
     "    from glorfindel.actions import active_blocks, active_isolations\n"
     "    if not active_isolations() and not active_blocks():\n        return []\n"),
    ("M895", "the watch's pass raises on an empty local state, the error swallowed (I1F, second review)", GCLI,
     "        report = reassert_pass(connector, autonomy)\n",
     "        from glorfindel.actions import active_blocks, active_isolations\n"
     "        if not active_isolations() and not active_blocks():\n"
     "            raise RuntimeError(\"nothing recorded\")\n"
     "        report = reassert_pass(connector, autonomy)\n"),
    ("M896", "the watch's timer starts no pass when nothing is recorded (I1F, second review)", GCLI,
     "        if time.time() - _last_reassert[0] < _reassert_every_s:\n            return\n",
     "        if time.time() - _last_reassert[0] < _reassert_every_s:\n            return\n"
     "        from glorfindel.actions import active_blocks, active_isolations\n        if not active_isolations() and not active_blocks():\n"
     "            return\n"),
    ("M897", "a listing that fails reads as empty: every quarantine card closed (I1F, second review)", RQ,
     '        log.warning("reassert: quarantine NSGs not checked (%s)", exc)\n        return\n',
     '        log.warning("reassert: quarantine NSGs not checked (%s)", exc)\n        listing = []\n'),
    ("M898", "an unreadable configuration said at every pass (I1F, second review)", GCLI,
     '        if seen.get("config_error") != str(exc):\n', "        if True:\n"),
]

# I8F (#227): a bare NIC our state holds in quarantine, its original unknown — never "none".
MUTANTS += [
    ("M860", "a bare NIC isolated again records 'none' over an unknown original: released bare, an old "
             "isolation left without state (I8F, I8)", QUA,
     '                elif recorded is _UNKNOWN and prior is _UNKNOWN and _held_or_unreadable(t["nic_id"]):',
     "                elif False:"),
    ("M861", "reset skips a bare NIC whose original is unknown: swept, an old isolation left without "
             "state (I8F, I8)", SWP,
     '                if recorded is _UNKNOWN and _held_in_quarantine(t0["nic_id"]):\n'
     "                    # In quarantine for our state",
     "                if False:\n                    # In quarantine for our state"),
    ("M862", "a release drops the placement whose original is unknown: the next says released, "
             "an old isolation left without state (I8F, relecture)", REL,
     '                                          f"{_first_line(exc)[:_ERR_MAX]}")\n'
     "                            remaining.append(p)\n",
     '                                          f"{_first_line(exc)[:_ERR_MAX]}")\n'
     '                            if type(exc).__name__ != "OriginalUnknown" and not bare:\n'
     "                                remaining.append(p)\n"),
    ("M863", "an unreadable tag on a bare NIC reads as 'none': a 429 writes it over an unknown "
             "original (I8F, relecture)", QUA,
     "                        prior, unread = _UNKNOWN, True\n",
     "                        prior = None\n"),
    ("M864", "an unreadable tag counts as unknown only when a state holds the NIC: the state lost, a "
             "429 writes 'none' over a valid tag (I8F, second relecture)", QUA,
     "                elif unread and recorded is _UNKNOWN:\n",
     '                elif unread and recorded is _UNKNOWN and _held_in_quarantine(t["nic_id"]):\n'),
    ("M865", "a stateless release ignores the tag of a bare NIC: left without its NSG, an old isolation "
             "there (I8F, second relecture)", REL,
     "                    if q_bare is not None:\n                        if original:\n",
     "                    if False:\n                        if original:\n"),
]

# I8S (#245): two hosts, separate states — the state's "none" never wins over a tag that names
# an NSG, and a tag that can't be read is never "none". The machine has one state directory:
# measured by the two-host sequences frozen in test_invariant_regressions.py (TESTS below).
MUTANTS += [
    ("M1040", "the release follows the state's 'none' over a tag naming the NSG: the NIC left bare (I8S)",
     REL, '                        if original is None and "original_nsg_id" in p:\n',
     "                        if False:\n"),
    ("M1041", "the release's sweep follows the state's 'none' for a NIC in a quarantine its placement doesn't "
              "name (host 2's, another group): left bare (I8S)", REL,
     "                    elif original is None:\n                        original = self._tag_over_none(q, t0[\"nic_id\"])\n",
     "                    elif False:\n                        original = self._tag_over_none(q, t0[\"nic_id\"])\n"),
    ("M1042", "a 429 on our tag: the re-isolation writes the state's 'none' over it (I8S)", QUA,
     "            if original is not _UNKNOWN and not tag_unread:\n",
     "            if original is not _UNKNOWN:\n"),
    ("M1043", "a tag that can't be read reads as 'none' at the release: the NIC left bare (I8S)", REL,
     "            if _is_not_found(exc):\n                return None\n            raise\n",
     "            return None\n"),
    ("M1044", "reset follows the state's 'none' over the tag of a NIC in quarantine (I8S)", SWP,
     "                elif original is None:\n                    # The state's \"none\" yields to our tag",
     "                elif False:\n                    # The state's \"none\" yields to our tag"),
    ("M1045", "reset follows the state's 'none' over the tag of a bare NIC (I8S)", SWP,
     "            if recorded is None and q_bare is not None:\n", "            if False:\n"),
    ("M1046", "reset reads an unreadable tag of a bare NIC as the state's 'none': swept bare (I8S)", SWP,
     "                if recorded is _UNKNOWN or recorded is None:\n", "                if recorded is _UNKNOWN:\n"),
    ("M1047", "verify_release follows the state's 'none' over a tag naming the NSG: says released (I8S)", VER,
     "            if original is _UNKNOWN or original is None:\n", "            if original is _UNKNOWN:\n"),
    # Review of I8S (5.5): the reset recorded the state's "none" before reading the tag; a 429
    # there left it recorded — the NIC put back bare, the tag X deleted.
    ("M1048", "reset records the state's 'none' before reading the tag: a 429 there, the NIC put back "
              "bare and X deleted (I8S, review)", SWP,
     "                original = _recorded_original(t0[\"nic_id\"])\n",
     "                originals[t0[\"nic_id\"]] = original = _recorded_original(t0[\"nic_id\"])\n"),
    ("M1049", "a bare NIC's original: the first tag found, a 'none' in one group over X in another — two "
              "hosts, two quarantine groups (I8S, review)", QUA,
     "            if hit and hit[0]:\n                return hit\n            none = none or hit\n",
     "            if hit:\n                return hit\n"),
]


# I4F (#235): a NIC away from its NSG (in quarantine, or bare) still counts among the NSG's —
# or the NSG reads as another VM's alone, and the reset takes that VM's older isolation.
MUTANTS += [
    ("M960", "the original NSG's sharing read without the NIC away from it: an older version's "
             "isolation of the VM still on it swept by the reset (I4F)", REL,
     '        sharing = self._nsg_sharing(o_rg, o_name, away_nic=t0["nic_id"])\n',
     "        sharing = self._nsg_sharing(o_rg, o_name)\n"),
    ("M961", "a NIC away not counted among its NSG's (I4F)", NET,
     "        if away_nic and not any(_same_id(getattr(n, \"id\", \"\") or \"\", away_nic) for n in nics):\n"
     "            nics.append(away_nic)\n",
     ""),
]

# I4S (#239), the symmetric case: another VM's NIC away from the NSG (in our quarantine, or
# bare) is tied to it by our tag, or by the local state when the tag is lost — or the NSG
# reads as the new VM's alone, and its reset takes the other VM's older isolation. Range
# M1030–M1039.
MUTANTS += [
    ("M1030", "another VM's NIC away from the NSG not counted: the reset of a VM alone there takes "
              "the other's older isolation (I4S)", NET,
     "        if len(nics) < 2 and not subnets:\n",
     "        if False:\n"),
    ("M1031", "our quarantine tag ignored: only the local state ties a NIC away to its NSG (I4S)", NET,
     '            tied |= {tag for tag, value in tags.items() if tag.startswith("glorfindel-orig-") '
     "and names_this(value)}\n",
     ""),
    ("M1032", "the local state ignored when the quarantine's tag is lost (I4S)", NET,
     '        tied |= {self._orig_tag(p["nic_id"]) for iso in active_isolations()',
     '        tied |= {self._orig_tag(p["nic_id"]) for iso in []'),
    ("M1033", "an unreadable NSG listing read as no NIC away: the fixed names taken (I4S)", NET,
     "            listing = list(self._network.network_security_groups.list_all())\n"
     "        except Exception:\n            return None\n",
     "            listing = list(self._network.network_security_groups.list_all())\n"
     "        except Exception:\n            return False\n"),
    ("M1034", "a bare NIC tied by our tag not counted (I4S)", NET,
     "        if not tied:\n            return False\n",
     "        if True:\n            return False\n"),
    ("M1035", "every tag naming the NSG read as a NIC away, a stale one too: the older isolation of "
              "a VM alone on its NSG never goes (I4S)", NET,
     "        if not tied:\n            return False\n",
     "        if tied:\n            return True\n"),
    ("M1036", "an unreadable NIC listing read as no bare NIC: the fixed names taken (I4S)", NET,
     "        except Exception:\n            return None\n        return False\n",
     "        except Exception:\n            return False\n        return False\n"),
    ("M1037", "the NIC of the reset itself, away in quarantine, counted as another VM's: the older "
              "isolation of a VM alone on its NSG never goes (I4S)", NET,
     "        tied -= mine\n",
     ""),
    # After the 5.5 review: the plain block name is a fixed name too, and an unblock that
    # leaves one it can't attribute says so.
    ("M1038", "the block under the IP's name alone not a fixed name: the unblock of a VM alone on an "
              "NSG takes the older block of a VM away from it (I4S)", NET,
     " or bool(_PLAIN_BLOCK.match(low))",
     ""),
    ("M1039", "an older plain-named block left on an NSG whose sharing can't be read, in silence: "
              "`not_found` while the IP stays blocked (I4S, review)", UNB,
     "                failed += self._unattributable_plain_block(ip, t, rules)\n",
     ""),
]

# MC1 — the AWS adapter, written against the simulated world (tests/unit/fake_aws.py) and
# measured by the invariants on AWS (tests/unit/test_invariants_aws.py). Range M600–M649:
# M600–M629 the bugs met or named while building it, M630–M649 its control set (below).
AWS_NET = "glorfindel/providers/aws/network.py"
AWS_QUA = "glorfindel/providers/aws/quarantine.py"
AWS_ISO = "glorfindel/providers/aws/isolation.py"
AWS_BLK = "glorfindel/providers/aws/blocks.py"
AWS_CON = "glorfindel/providers/aws/connector.py"
AWS_INVARIANTS = "tests/unit/test_invariants_aws.py"
AWS_UNIT = "tests/unit/test_aws_adapter.py"
MUTANTS += [
    # Found by the machine on AWS while it was built.
    ("M600", "a block reuses an entry the customer's allow now precedes (MC1)", AWS_BLK,
     "                                  if eg == egress and n and n < first\n",
     "                                  if eg == egress and n\n"),
    ("M601", "a block is not read back: « blocked » with an allow ahead (MC1)", AWS_BLK,
     "                    held_back = acl is not None and cut(acl, False, ip) and cut(acl, True, ip)",
     "                    held_back = True"),
    ("M602", "an ENI left on `default` gets the state's original back, a group of it deleted (MC1)", AWS_ISO,
     '                self._put_back(eni, self._usable_original(eni, [rec, tag], e["vpc"], q), cur)',
     "                self._put_back(eni, prior, cur)"),
    ("M617", "the isolation verified on the ENIs as read before the swap (MC1)", AWS_ISO,
     "            check = self._check_isolation(self._instance_enis(iid))      # as it is now",
     "            check = self._check_isolation(enis)"),
    # Named by the design note (docs/design/monde-aws.md) and the classes Azure had.
    ("M603", "the quarantine turned off by the configuration is ignored: no fallback, but writes (MC1, I10)",
     AWS_QUA, "        return bool(load_glorfindel_config().isolation.quarantine_nsg)", "        return True"),
    ("M604", "Amazon's DNS and IMDS not declared by the isolation (MC1, H6)", AWS_ISO,
     '"bypass": bypass, "platform_open": [e["eni"] for e in enis],', '"bypass": bypass, "platform_open": [],'),
    ("M605", "an ENI someone left on `default` is not given its original back (MC1, U2)", AWS_ISO,
     "            if prior and default and same_groups(cur, [default]) and not same_groups(prior, cur):\n"
     "                # Taken out",
     "            if False:\n                # Taken out"),
    ("M606", "re-isolating an ENI left on `default` records `default` as its original (MC1, U2)", AWS_ISO,
     "            if prior is not _UNKNOWN and default and same_groups(cur, [default]) and not same_groups(prior, cur):\n"
     "                original = prior",
     "            if False:\n                original = prior"),
    ("M607", "an ENI already in quarantine: what it carries read as its original (MC1, S1)", AWS_ISO,
     "            original = prior\n            if same_groups(cur, [qid]):",
     "            original = cur\n            if same_groups(cur, [qid]):"),
    ("M608", "an allow someone added to the quarantine group is left there (MC1)", AWS_QUA,
     "            extra = [r for r in ingress if r not in wanted]", "            extra = []"),
    ("M609", "a verification that can't read an ENI says isolated (MC1)", AWS_ISO,
     '            except Exception:\n                unknown.append(e["eni"])\n        verified',
     "            except Exception:\n                pass\n        verified"),
    ("M610", "the isolation is not recorded (MC1, I8)", AWS_ISO,
     "        _state._save_isolation_state(resource_id, state)\n        try:", "        try:"),
    ("M611", "a release that failed clears the state (MC1, I8)", AWS_ISO,
     "        if failed:\n            _state._save_isolation_state(resource_id, {",
     "        if False:\n            _state._save_isolation_state(resource_id, {"),
    ("M612", "no lock on the network ACL: an unblock removes the entries a concurrent block reuses (MC1, I11)",
     AWS_BLK,
     '                stack.enter_context(_locks._quarantine_lock(f"aws/acl/{acl_id}"))', "                pass"),
    ("M613", "the instance's lock inoperative (MC1, the M17 of AWS)", AWS_CON,
     '        with _locks._vm_lock(rid.rstrip("/").rsplit("/", 1)[-1]):\n            return method(self, *args, **kwargs)',
     "        return method(self, *args, **kwargs)"),
    ("M614", "an entry read as Glorfindel's whatever address it refuses (MC1)", AWS_BLK,
     ' \\\n        and e.get("CidrBlock") == cidr', ""),
    ("M615", "an unblock keeps the block recorded (MC1)", AWS_BLK,
     "        _state._clear_block_state(resource_id, ip)\n", ""),
    ("M616", "verify_isolation vouches for an instance of another account (MC1, I12)", AWS_CON,
     'for _name in ("isolate_vm", "release_isolation", "verify_isolation", "verify_release",\n',
     'for _name in ("isolate_vm", "release_isolation", "verify_release",\n'),
]
# MC1, after its review: a block's reach is its ACL's, our quarantine group without its tag,
# the guard without an account or a region, an instance without interfaces.
MUTANTS += [
    ("M618", "a block names the instance's subnets only, not every subnet of its ACL (MC1, review)", AWS_BLK,
     '                affected = sorted({a.get("SubnetId") for a in acl.get("Associations") or []\n'
     '                                   if a.get("SubnetId")} | set(acls[acl_id]))',
     "                affected = sorted(acls[acl_id])"),
    ("M619", "an ENI carrying a group named like the quarantine, nothing recording it, said released (MC1, review)",
     AWS_ISO, "        named = self._named_quarantine(cur)\n        if named:", "        named = []\n        if named:"),
    ("M620", "the account guard open when no account or region is configured (MC1, review, I12)", AWS_CON,
     "            if not (self.account and self.region):", "            if False:"),
    ("M621", "an instance without interfaces verified isolated (MC1, review)", AWS_ISO,
     "(None if unknown or not enis else True)", "(None if unknown else True)"),
    ("M622", "the quarantine group the state records ignored once its tag is gone (MC1, review)", AWS_ISO,
     '        q = self._quarantine_sg(e["vpc"]) or self._recorded_quarantine(eni, cur, state)',
     '        q = self._quarantine_sg(e["vpc"])'),
    ("M623", "verify_release blind to a group named like the quarantine (MC1, review)", AWS_ISO,
     'if (q is not None and q["GroupId"] in e["groups"]) or self._named_quarantine(e["groups"]):',
     'if q is not None and q["GroupId"] in e["groups"]:'),
]
# A3 (#73): the orphan sweep (U1, removal after the alert), the extensions allowed at the
# restore (L23), the strict config. M760–M763 by the invariants (and their fixed sequence;
# M760, M762, M763 by test_orphan_sweep.py too), the others by their unit tests (TESTS below).
# The sweep left the posture pass for the watch's (orphans.py, D-B).
ORP = "glorfindel/orphans.py"
POS = "glorfindel/posture.py"
RST = "glorfindel/providers/azure/restore.py"
MUTANTS += [
    ("M760", "the orphan sweep alerts and never removes (A3, U1)", ORP,
     "        if alone:\n            out = _remove(connector, o, victims)",
     "        if False:\n            out = _remove(connector, o, victims)"),
    ("M761", "a live NIC's own rule taken for an orphan, and removed (A3, U1)", SWP,
     "                        or mark in marks or mark in live_names):",
     "                        or mark in live_names):"),
    ("M762", "the orphan sweep removes a rule of the deleted NIC's, any Glorfindel rule of that NSG (A3)", SWP,
     "        err = self._delete_rule(nsg_rg, nsg_name, orphan[\"rule\"])",
     "        err = None\n"
     "        for r in self._network.network_security_groups.get(nsg_rg, nsg_name).security_rules or []:\n"
     "            if _rule_name(r).lower().startswith(\"glorfindel-\"):\n"
     "                err = self._delete_rule(nsg_rg, nsg_name, _rule_name(r)) or err"),
    ("M763", "an orphan's address read on either side of the rule (A3)", SWP,
     "                side = \"destination\" if _enum_text(getattr(r, \"direction\", \"\")) == \"inbound\" else \"source\"\n"
     "                single = getattr(r, f\"{side}_address_prefix\", None)",
     "                side = \"source\" if _enum_text(getattr(r, \"direction\", \"\")) == \"inbound\" else \"destination\"\n"
     "                single = getattr(r, f\"{side}_address_prefix\", None)"),
    ("M764", "the holder's NSG not compared: an orphan behind another NSG removed too (A3)", SWP,
     "                cut = [h for h in now_on if nic_nsg.get(h[\"nic_id\"].rstrip(\"/\").lower()) == nsg_key\n"
     "                       or nic_subnets.get(h[\"nic_id\"].rstrip(\"/\").lower(), set()) & subnets]",
     "                cut = list(now_on)"),
    ("M765", "an NSG with a NIC the listing misses: its orphans removed anyway (A3)", SWP,
     "                elif attached - listed:", "                elif False:"),
    ("M766", "a NIC of our state, alive but missing from the listing, taken for gone (A3)", SWP,
     "                    if gone[mark] == \"alive\":\n                        continue",
     "                    if False:\n                        continue"),
    ("M767", "older names of a live NIC (its name, the id's case-preserving hash) taken for orphans (A3)", SWP,
     "                        or mark in marks or mark in live_names):",
     "                        or mark in {m for m in marks if len(m) == 6}):"),
    ("M768", "read-only credentials: the sweep tries to remove anyway (A3)", ORP,
     "    can_write = getattr(connector, \"read_only\", False) is False",
     "    can_write = True"),
    ("M769", "an orphan's card resolved though the removal failed (A3)", ORP,
     "        if out.get(\"removed\") is True:\n            # A card of another rule",
     "        if out:\n            # A card of another rule"),
    ("M770", "a key nobody reads accepted in silence (A3)", C,
     "        for k in raw:\n            if k in allowed:\n                continue",
     "        for k in raw:\n            if True:\n                continue"),
    ("M771", "\"false\" in quotes read as true (A3)", C,
     "        if isinstance(value, bool):\n            return value\n        if isinstance(value, str) and",
     "        if isinstance(value, (bool, str)):\n            return bool(value)\n        if isinstance(value, str) and"),
    ("M772", "a single text taken for a list, letter by letter (A3)", C,
     "        if not isinstance(value, list):\n            self.bad(f\"{where}.{k}\", f\"une liste est attendue",
     "        if isinstance(value, str):\n            value = list(value)\n"
     "        if not isinstance(value, list):\n            self.bad(f\"{where}.{k}\", f\"une liste est attendue"),
    ("M773", "the watch starts on a refused config (A3)", GCLI,
     "                      \"sur une configuration mal écrite.\\n\" + _esc_markup(str(exc)))\n        raise SystemExit(2)",
     "                      \"sur une configuration mal écrite.\\n\" + _esc_markup(str(exc)))"),
    ("M774", "the restore's extensions: back to the list of three CustomScript names (A3, L23)", RST,
     "                if key not in self._REPLAY_SAFE_EXTENSIONS:",
     "                if key[1] in (\"customscript\", \"customscriptextension\", \"customscriptforlinux\"):"),
    ("M775", "an extension whose kind can't be read allowed at the restore (A3, L23)", RST,
     "                if key not in self._REPLAY_SAFE_EXTENSIONS:",
     "                if all(key) and key not in self._REPLAY_SAFE_EXTENSIONS:"),
]
# A3, after its first review (5.5): the mode (D-A), the watch's pass (D-B), the VMs
# Glorfindel holds, a 404 told from a 403, the card's reason, the backend types.
MUTANTS += [
    ("M776", "the orphan rule taken off whatever the cut VM's mode: human_only writes (A3, D-A)", ORP,
     "        alone = (can_write and o.get(\"removable\") is True and bool(modes)\n"
     "                 and all(m in _ALONE for m in modes.values()))",
     "        alone = can_write and o.get(\"removable\") is True"),
    ("M777", "the orphan sweep left out of the watch's pass: it waits for a discovery that may be off (A3, D-B)",
     R, "    sweep_orphan_rules(connector, autonomy, report, nsgs)\n", ""),
    ("M778", "the rule of a recreated NIC under a VM Glorfindel isolates found removable (A3, first review)", SWP,
     "                elif why := self._held_reason(cut, held):\n                    kept = why\n", ""),
    ("M779", "the removal doesn't read the state again: an isolation recorded since is lifted (A3, first review)",
     SWP, "        why = self._held_reason(orphan.get(\"cut\") or [], self._held_vms()) or _turned_still(",
     "        why = \"\" or _turned_still("),
    ("M880", "any error reading a NIC of our state taken for a 404: gone (A3, first review, X1)", SWP,
     "            if _is_not_found(exc):\n                return None\n            return f\"carte",
     "            if True:\n                return None\n            return f\"carte"),
    ("M881", "a NIC of our state unreadable (403, 429): its rule removable anyway (A3, first review, X2)", SWP,
     "                elif mark in state_nics and gone.get(mark):", "                elif False:"),
    ("M882", "an unknown backend type accepted in silence (A3, first review)", C,
     "        if raw.get(k) is None or not isinstance(raw.get(k), str) or value in allowed:\n            return value",
     "        if True:\n            return value"),
    ("M883", "the orphan's card doesn't say why its rule was kept (A3, first review)", ORP,
     "            reason += f\" Gardée : {o.get('kept') or 'non retirable'}.\"", "            pass"),
    ("M884", "a release held by an extension: the card blames the last Run Command (A3, first review)",
     "glorfindel/agent.py", "        if vectors:\n", "        if False:\n"),
    ("M885", "Guest Configuration allowed at the restore: a policy's script comes back (A3, first review)", RST,
     "        (\"microsoft.compute\", \"bginfo\"),\n",
     "        (\"microsoft.compute\", \"bginfo\"),\n"
     "        (\"microsoft.guestconfiguration\", \"configurationforlinux\"),\n"),
    ("M886", "an orphan said again at every pass: a card a minute, an acknowledgement lost (A3, D-B)", ORP,
     "        if k in alerts:\n            continue", "        if False:\n            continue"),
    ("M887", "every orphan card closed at each pass, its rule standing (A3, D-B)", ORP,
     "    for k in [k for k in alerts if k not in current]:", "    for k in list(alerts):"),
    # A3, second review (5.5): guards that were right, now locked.
    ("M888", "the held VM compared by its exact id: a lowercase state misses it, its isolation lifted (A3)", SWP,
     '            if any(_same_id(h.get("vm_id") or "", rid) for rid in held):',
     '            if any((h.get("vm_id") or "") == rid for rid in held):'),
    ("M889", "an unreadable configuration read as non_disruptive: the sweep writes on a guessed mode (A3, D-A)",
     ORP, '        return "human_only" if autonomy is None else autonomy.resolve(name)',
     '        return "non_disruptive" if autonomy is None else autonomy.resolve(name)'),
    ("M700", "the reassertion off: nobody says the orphan rules any more, L28's alert lost (A3)", POS,
     '        if getattr(self._connector, "read_only", False) is not True and _reassertion_on():',
     '        if getattr(self._connector, "read_only", False) is not True:'),
    ("M701", "a rule cutting VMs of different modes removed when one may act alone (A3, D-A)", ORP,
     "                 and all(m in _ALONE for m in modes.values()))",
     "                 and any(m in _ALONE for m in modes.values()))"),
]
# L1F (#229): "already alerted" written before the card — a crash in between leaves the
# marker without the card, and every later pass is silent on a block gone from Azure.
MUTANTS += [
    ("M900", "a block that could not be put back marked alerted before its card (L1F, L1)", R,
     ('        outcome = "failed"\n    _alert(_alert_id(vm, rid, ip),',
      "        # silence (L1F, invariant machine).\n        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))\n"),
     ('        outcome = "failed"\n        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))\n'
      "    _alert(_alert_id(vm, rid, ip),",
      "        # silence (L1F, invariant machine).\n        pass\n")),
    ("M901", "an isolation that could not be put back marked alerted before its card (L1F)", R,
     ('        outcome = "failed"\n    _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm"',
      "(see blocks).\n        _mark_alerted(ref or vm, now)\n"),
     ('        outcome = "failed"\n        _mark_alerted(ref or vm, now)\n'
      '    _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm"',
      "(see blocks).\n        pass\n")),
    ("M902", "a block gone in human_only marked alerted before its card (L1F, L1)", R,
     ('        _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",\n'
      '               reason=reason, action_params={"ip": ip})\n'
      "        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))\n"
      "        episode(ref or vm, ip, over=False)\n        report.append(",),
     ("        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))\n"
      "        episode(ref or vm, ip, over=False)\n"
      '        _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",\n'
      '               reason=reason, action_params={"ip": ip})\n        report.append(',)),
]

# AL1 (#225) — Azure's Activity Log, detection only: Glorfindel's own writes excluded by its
# identity and its declared operations, its own rules marked, no autonomous action on the
# control plane, a row arriving late neither missed nor dispatched twice. Range M810–M829,
# measured by tests/unit/test_activity_logs.py.
ACT = "glorfindel/providers/azure/activity.py"
AGT = "glorfindel/agent.py"
DRU = "glorfindel/detection_rules.py"
MUTANTS += [
    ("M810", "Glorfindel's own writes not excluded: its own isolation escalates itself (AL1)", ACT,
     "        if is_own_call(row, own, recorded):\n            continue\n", ""),
    ("M811", "a control-plane detection decided by the model: it is called, and isolate_vm runs (AL1)", AGT,
     "    if _is_control_plane(state[\"signal\"]):\n        return _control_plane_decision(state)\n", ""),
    ("M812", "a user's token without idtyp read as an application's: the CLI's appid excludes everyone (AL1)",
     ACT, "    return not claims.get(\"scp\") and not claims.get(\"upn\")", "    return True"),
    ("M813", "a control-plane card folded into the pending one: a write on Glorfindel's rules unseen (AL1)",
     "glorfindel/escalations.py",
     "                and escalation_type != \"control_plane_change\"\n", ""),
    ("M814", "the control-plane decision ignores the source it read: respond asks the model (AL1)", AGT,
     "    if ctx.get(\"plane\") == \"control\" or is_control_plane_source(str(raw.get(\"detection_source\") or \"\")):",
     "    if ctx.get(\"plane\") == \"control\":"),
    ("M815", "a held control-plane decision typed low_confidence: approvable in one click (AL1)", AGT,
     "    \"control_plane\": \"control_plane_change\",\n", ""),
    ("M816", "a write on a glorfindel-* rule not seen as Glorfindel's (AL1)", ACT,
     "    if \"/securityrules/glorfindel-\" in rid:\n        return True\n", ""),
    ("M817", "a write on the quarantine NSG not seen as Glorfindel's (AL1)", ACT,
     "        return nsg.startswith(QUARANTINE_NSG_PREFIX)\n", "        return False\n"),
    ("M818", "Glorfindel's identity excluded whatever it does on its own: a role it assigns there is dropped (AL1)",
     ACT, "    return (bool(own) and bool(caller_ids(row) & own) and operation(row) in own_operations()\n",
     "    return (bool(own) and bool(caller_ids(row) & own)\n"),
    ("M819", "the identity in Glorfindel's token ignored (AL1)", ACT,
     "            return ids | self._token_ids\n", "            return ids\n"),
    ("M820", "the caller's ids in Claims ignored (AL1)", ACT,
     "    ids |= {str(claims[k]).strip().lower() for k in _CLAIM_KEYS if claims.get(k)}\n", ""),
    ("M821", "the caller compared case-sensitively (AL1)", ACT,
     "    ids = {str(row[c]).strip().lower() for c in _CALLER_COLUMNS if row.get(c)}",
     "    ids = {str(row[c]).strip() for c in _CALLER_COLUMNS if row.get(c)}"),
    ("M822", "a control-plane operation deduplicated by its line: Start then Success dispatched twice (AL1)", DRU,
     "    if row.get(\"OperationNameValue\") and row.get(\"CorrelationId\"):", "    if False:"),
    ("M823", "a control-plane rule shorter than the ingestion latency loads in silence (AL1)", DRU,
     "        if rule_enabled and _query_lookback_s(item[\"query\"]) < min_lookback:",
     "        if False:"),
    ("M824", "the shipped NSG rule looks back 10 minutes: a row ingested late is never seen (AL1)",
     "glorfindel/rules/azure/detection_rules.yaml",
     "      AzureActivity\n      | where TimeGenerated > ago(1h)\n      | where OperationNameValue in~ (\n"
     "          \"MICROSOFT.NETWORK",
     "      AzureActivity\n      | where TimeGenerated > ago(10m)\n      | where OperationNameValue in~ (\n"
     "          \"MICROSOFT.NETWORK"),
    ("M825", "a row on a VM's sub-resource (a role scoped on the VM) dropped, not attributed (AL1)", DRU,
     "            return True, self.by_rid.get(_vm_id_of(rid))",
     "            return True, self.by_rid.get(rid.lower())"),
    ("M826", "the newest operation first, before a write on Glorfindel's rules (AL1)", DRU,
     "    return sorted(by_op.values(), key=lambda r: (_grave(r), str(r.get(\"TimeGenerated\") or \"\")),",
     "    return sorted(by_op.values(), key=lambda r: str(r.get(\"TimeGenerated\") or \"\"),"),
    ("M827", "a write on Glorfindel's rules not critical (AL1)", DRU,
     "            \"severity\": \"critical\" if grave else \"high\",", "            \"severity\": \"high\","),
    ("M828", "a control-plane row normalised as a caller IP: no operation, no caller (AL1)", DRU,
     "    if row.get(\"OperationNameValue\"):\n        return {", "    if False:\n        return {"),
    ("M829", "an AzureActivity rule bound to no backend: disabled, it never polls (AL1)", DRU,
     "                backend_type_of(rule_source),\n            )", "                rule_source,\n            )"),
]

# AL1, after the 5.5 review (27/10): range M850–M859, measured by tests/unit/test_activity_logs.py.
MUTANTS += [
    ("M850", "a user's token: the Azure CLI's appid taken as Glorfindel's, everyone's az writes dropped (AL1)",
     ACT, "    keys = _CLAIM_KEYS if is_app_token(claims) else _OID_CLAIMS", "    keys = _CLAIM_KEYS"),
    ("M851", "its identity's write on a customer's rule dropped: a stolen credential unseen (AL1)", ACT,
     "    return (bool(own) and bool(caller_ids(row) & own) and operation(row) in own_operations()\n"
     "            and owned_target(row, recorded))",
     "    return (bool(own) and bool(caller_ids(row) & own) and operation(row) in own_operations())"),
    ("M852", "a customer rule its isolation moved not its own: its release escalates, critical (AL1)", ACT,
     "                    rule(sub, rg, nsg, b.get(\"name\"))\n", "                    pass\n"),
    ("M853", "control plane, one card per poll: the other operations marked sent, never seen (AL1)", DRU,
     "                    ops = _control_plane_operations(new)\n",
     "                    ops = _control_plane_operations(new)[:1]\n"),
    ("M854", "past the cap, no summary card: operations marked sent without a card (AL1)", DRU,
     "                    if rest:\n                        send.append(_control_plane_summary(rest))\n", ""),
    ("M855", "a button on a card anchored on a VM: one click restores a VM the detection never named (AL1)",
     "glorfindel/bot.py", "    if esc_type in _ANCHORED_TYPES:\n        return None\n", ""),
    ("M856", "the control-plane decision recommends isolating the anchor VM (AL1)", AGT,
     "        \"explanation\": what,\n", "        \"explanation\": what,\n        \"action\": \"isolate_vm\",\n"),
    ("M857", "an unattributed control-plane signal opens the anchor VM's incident (AL1)", AGT,
     "        if (signal.get(\"context\") or {}).get(\"attribution\") != \"asset\":", "        if False:"),
    ("M858", "a control-plane cycle stored in the decision memory: a precedent for a data-plane decision (AL1)",
     AGT, "        if not (_is_control_plane(signal) or _is_identity(signal)):\n            memory.store(cycle)",
     "        if True:\n            memory.store(cycle)"),
    ("M859", "what an isolation state recorded forgotten once the state is gone: the release escalates (AL1)",
     ACT, "            return frozenset(self._recorded)\n", "            return current\n"),
]

# AL1, after the second 5.5 review (27/10): range M890–M894, measured by tests/unit/test_activity_logs.py.
MUTANTS += [
    ("M890", "a glorfindel-* name is proof enough: a stolen credential hides an allow rule behind it (AL1)",
     ACT, "    if _in_quarantine_nsg(rid):\n        return True\n",
     "    if _in_quarantine_nsg(rid) or \"/securityrules/glorfindel-\" in rid:\n        return True\n"),
    ("M891", "the block states ignored: its own block escalates itself (AL1)", ACT,
     "    for e in blocks:\n", "    for e in []:\n"),
    ("M892", "the subscription left out of a recorded rule: the same names elsewhere taken as its own (AL1)",
     ACT, "    return (f\"{sub}/{rg}/{nsg}/{rule}\" if sub else f\"{rg}/{nsg}/{rule}\").lower()",
     "    return f\"{rg}/{nsg}/{rule}\".lower()"),
    ("M893", "an AzureActivity row read by another source goes to the model: a snapshot runs alone (AL1)", AGT,
     "    return (any(r.get(\"OperationNameValue\") for r in rows)\n"
     "            or any(str(r.get(\"Type\") or \"\").lower() == \"azureactivity\" for r in rows)\n"
     "            or (raw.get(\"normalized_signal\") or {}).get(\"indicator_key\") == \"control_plane_operation\")",
     "    return False"),
    ("M894", "a control-plane rule without CorrelationId loads in silence: two operations fold into one (AL1)",
     DRU, "                and \"correlationid\" not in item[\"query\"].lower():", "                and False:"),
]

# C2 (#199), the defensive half — Entra ID's logs, detection only: each rule escalates with
# its steps, never the model, never an action on an identity; thresholds in code; Glorfindel's
# identity marked, never an excuse to silence. Range M920–M939, measured by
# tests/unit/test_entra_detection.py.
ENT = "glorfindel/providers/azure/entra.py"
MUTANTS += [
    ("M920", "an identity detection decided by the model: it is called, with an administrator's UPN (C2)", AGT,
     "    if _is_identity(state[\"signal\"]):\n        return _identity_decision(state)\n", ""),
    ("M921", "the route after decide sends an identity detection to an action: a bypassed decide isolates (C2)",
     AGT, "    if _is_identity(state[\"signal\"]):\n        return \"escalate_to_human\"\n", ""),
    ("M922", "an identity detection known by its plane only: a row whose columns say nothing goes to the model (C2)",
     AGT, "    if ctx.get(\"plane\") == \"identity\" or is_identity_source(str(raw.get(\"detection_source\") or \"\")):",
     "    if ctx.get(\"plane\") == \"identity\":"),
    ("M923", "an Entra row read by another source goes to the model: no plane, no source (C2)", AGT,
     "    return (any(r.get(c) for r in rows for c in IDENTITY_COLUMNS)\n"
     "            or any(str(r.get(\"Type\") or \"\").lower() in ENTRA_TABLES for r in rows)\n"
     "            or (raw.get(\"normalized_signal\") or {}).get(\"indicator_key\") == \"identity_operation\")",
     "    return False"),
    ("M924", "every directory role a finding: Directory Readers escalates like Global Administrator (C2)", ENT,
     "        return not role or role in PRIVILEGED_ROLES", "        return True"),
    ("M925", "a service principal without history unusual: the first days after the setting flood (C2)", ENT,
     "        return days is None or days >= MIN_BASELINE_DAYS", "        return True"),
    ("M926", "a failed operation a finding (C2)", ENT, "    if not _succeeded(row):\n        return False\n", ""),
    ("M927", "Glorfindel's identity as the actor not marked: its stolen credential not critical (C2)", ENT,
     "\"GlorfindelIdentity\": bool(own) and bool(actor_ids(row) & own),", "\"GlorfindelIdentity\": False,"),
    ("M928", "Glorfindel's identity as the target not marked: a credential added to it not critical (C2)", ENT,
     "\"GlorfindelManaged\": bool(own) and bool(target_ids(row) & own)})", "\"GlorfindelManaged\": False})"),
    ("M929", "an identity card folded into the pending one: a credential added to Glorfindel unseen (C2)",
     "glorfindel/escalations.py", "                and escalation_type != \"identity_change\"\n", ""),
    ("M930", "an identity escalation past a bypassed decide typed low_confidence: approvable in one click (C2)",
     AGT, "    if _is_identity(state[\"signal\"]):\n        escalation_type = \"identity_change\"\n"
          "    elif _out_status in (\"write_blocked\", \"action_failed\"):",
     "    if _out_status in (\"write_blocked\", \"action_failed\"):"),
    ("M931", "a command aimed at the anchor VM on an identity card (C2)", "glorfindel/bot.py",
     "_ANCHORED_TYPES = {\"control_plane_change\", \"identity_change\", \"unattributed_signal\"}",
     "_ANCHORED_TYPES = {\"control_plane_change\", \"unattributed_signal\"}"),
    ("M932", "an identity cycle stored in the decision memory: its UPN served to the model later (C2)", AGT,
     "        if not (_is_control_plane(signal) or _is_identity(signal)):\n            memory.store(cycle)",
     "        if not _is_control_plane(signal):\n            memory.store(cycle)"),
    ("M933", "an identity detection opens the anchor VM's incident (C2)", AGT,
     "    if _is_identity(signal):\n        return {**state, \"past_cycles\": [], \"incident\": None}\n", ""),
    ("M934", "an identity finding deduplicated by its time: two consents in the same second, one card (C2)", DRU,
     "    if row.get(\"EntraOperation\") and row.get(\"EventId\"):", "    if False:"),
    ("M935", "identity findings one card per cycle: the second credential added in a poll never seen (C2)", DRU,
     "            control = is_control_plane_source(rule.source) or is_identity_source(rule.source)",
     "            control = is_control_plane_source(rule.source)"),
    ("M936", "an identity signal without its plane: a finding on Glorfindel's identity not critical (C2)", DRU,
     "        control = plane in (\"control\", \"identity\")", "        control = plane == \"control\""),
    ("M937", "an identity rule without EventId loads in silence (C2)", DRU,
     "        if rule_enabled and is_identity_source(source) and \"eventid\" not in item[\"query\"].lower():",
     "        if False:"),
    ("M938", "a role card without how to revoke the assignment (C2)", ENT,
     "            \"Non voulue : retirer l'attribution — portail, ou `az rest --method DELETE --url \"\n"
     "            \"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/<id>`.\",\n", ""),
    ("M939", "the tenant's diagnostic setting always on: the whole tenant's logs sent (C2)",
     "infra/terraform/entra_logs.tf", "  count = local.entra_logs_enabled ? 1 : 0", "  count = 1"),
]

# C2, after the 5.5 review (27/10): range M940–M949, measured by tests/unit/test_entra_detection.py.
RUL = "glorfindel/rules/azure/detection_rules.yaml"
MUTANTS += [
    ("M940", "under az login, the operator's oid taken as Glorfindel's in Entra: his actions read as theft (C2)",
     ENT, "        return prepare_rows(rows, self.app_identities())",
     "        return prepare_rows(rows, self.own_identities())"),
    ("M941", "a user's token taken as an application's: the operator marked as Glorfindel (C2)", ACT,
     "                    self._token_is_app = bool(claims) and is_app_token(claims)\n",
     "                    self._token_is_app = True\n"),
    ("M942", "the role rule filters on Role.DisplayName: an assignment without it gone before the adapter (C2)",
     RUL, "          summarize RoleName = take_anyif(trim(@'\"', tostring(Prop.newValue)), "
          "tostring(Prop.displayName) =~ \"Role.DisplayName\"))",
     "          where tostring(Prop.displayName) =~ \"Role.DisplayName\"\n"
     "          | extend RoleName = trim(@'\"', tostring(Prop.newValue)))"),
    ("M943", "a first credential's old value not an array: set_difference silences the row (C2)", RUL,
     "iff(isnull(array_length(OldSet)), dynamic([]), OldSet)", "iff(isnull(OldSet), dynamic([]), OldSet)"),
    ("M944", "a client rule on an Entra table without telling columns goes to the model: its UPN sent (C2)", DRU,
     "        if plane == \"data\" and _reads_entra_table(rule.query):\n            plane = \"identity\"\n", ""),
    ("M945", "respond on an Entra query of another source goes to the model (C2)", AGT,
     "    entra_query = _reads_entra_table(query) and not is_control_plane_source(source)",
     "    entra_query = False"),
    ("M946", "a consent card proposes to disable the resource's principal: the whole tenant cut (C2)", ENT,
     "        client = (tid if op.lower() == \"consent to application\" and row.get(\"TargetId\")\n"
     "                  else str(row.get(\"ClientId\") or \"\").strip())",
     "        client = tid"),
    ("M947", "an identity card labelled exercise by a window on its anchor VM (C2)", AGT,
     "    if _is_identity(signal) or (\n"
     "            # `unattributed` is the RulePoller's own word; a respond signal (an\n"
     "            # attack_started resolved on the Activity Log) has none, and keeps its window.\n"
     "            _is_control_plane(signal) and (signal.get(\"context\") or {}).get(\"attribution\") == \"unattributed\"):\n"
     "        return \"real\", \"\"\n", ""),
    ("M948", "Global Administrator's former name not privileged (C2)", ENT, "    \"Company Administrator\",\n", ""),
    ("M949", "the role's target not the fallback name: an assignment without Role.DisplayName unnamed (C2)", RUL,
     "      | extend RoleName = coalesce(RoleName, RoleTargetName)\n", ""),
]

# C2, after the second 5.5 review (27/10): range M955–M959, measured by
# tests/unit/test_entra_detection.py.
MUTANTS += [
    ("M955", "a respond signal on the Activity Log forced real: a declared exercise counted as an incident (C2)",
     AGT, "(signal.get(\"context\") or {}).get(\"attribution\") == \"unattributed\"):",
     "(signal.get(\"context\") or {}).get(\"attribution\") != \"asset\"):"),
]


# IA1 (#88): the analysis AI's own model and memory, never Glorfindel's; the triage computed
# from the runs, the catalog, the rules and the infrastructure code; nothing without a human.
SEP = "analysis/separation.py"
TRI = "analysis/triage.py"
MUTANTS += [
    ("M780", "the analysis may reason with Glorfindel's decision model (IA1)", SEP,
     "    if _model_name(model) == _model_name(defender):\n", "    if False:\n"),
    ("M781", "Glorfindel's model under another provider's prefix passes as another model (IA1)", SEP,
     '    return str(model or "").strip().lower().rsplit("/", 1)[-1]\n', '    return str(model or "")\n'),
    ("M782", "an index reaching Glorfindel's state through « .. » or a link is let through (IA1)", SEP,
     "    p = Path(path).expanduser().resolve()\n", "    p = Path(path).expanduser()\n"),
    ("M783", "the analysis index may lie in Glorfindel's memory (IA1)", SEP,
     "    if p == state or state in p.parents:\n", "    if False:\n"),
    ("M784", "the report opens its index without the separation's check (IA1)", CREP,
     "    p = separation.check_index(Path(path) if path else index_path())\n",
     "    p = Path(path) if path else index_path()\n"),
    ("M785", "the report calls its model without the separation's check (IA1)", CREP,
     "    mdl = separation.check_model(model or analysis_model())   # IA1: never Glorfindel's\n",
     "    mdl = model or analysis_model()\n"),
    ("M786", "an escalation is triaged before a missed technique (IA1)", TRI,
     '    "missed": (1, ', '    "missed": (3, '),
    ("M787", "a comment in the infrastructure code counts as collection (IA1)", TRI,
     '            elif ch == "#" or two == "//":\n                break\n',
     "            elif False:\n                break\n"),
    ("M788", "a base rule the client's layer disables still watches its technique (IA1)", TRI,
     '        merged = [r for r in merged if r["name"] not in disabled]\n', "        merged = list(merged)\n"),
    ("M789", "a proposal the computed facts do not support is kept (IA1)", TRI,
     '        elif (not_here := item.allowed()[e["proposal"]]):\n', '        elif (not_here := ""):\n'),
    ("M790", "a proposal that carries a rule is kept: the analysis writes a rule (IA1)", TRI,
     '        elif _RULE.search(e["explanation"]) or _RULE.search(e["text"]):\n', "        elif False:\n"),
    ("M791", "the model's status is kept: a proposal approved without a human (IA1)", TRI,
     '        item.proposal = Proposal(kind=e["proposal"], text=e["text"], status=PENDING)\n',
     '        item.proposal = Proposal(kind=e["proposal"], text=e["text"], status=str(raw.get("status") or PENDING))\n'),
    ("M792", "a decision that names no human is recorded (IA1)", TRI,
     '    if not str(by).strip():\n        raise ValueError("a decision names the human who takes it (--by)")\n', ""),
    ("M793", "a decided proposal is decided again (IA1)", TRI,
     "        if item.proposal.status != PENDING:\n", "        if False:\n"),
    ("M794", "a new triage writes over a human's decision (IA1)", TRI,
     "    if not replace_decided and old is not None and any(\n", "    if False and old is not None and any(\n"),
    ("M795", "an unknown decision said taken is kept (IA1)", TRI,
     "            elif cr._ACTED.search(told):\n", "            elif False:\n"),
    ("M796", "a second entry for an item replaces the first (IA1)", TRI,
     "        elif item.proposal is not None or item.explanation:\n", "        elif False:\n"),
    ("M797", "the triage calls Glorfindel's model (IA1)", TRI,
     "    mdl = separation.check_model(model or analysis_model())\n", "    mdl = model or analysis_model()\n"),
    ("M798", "the harness does not count an obeyed planted line the check removed (IA1)",
     "analysis/triage_cases.py", "    entries = [r for r in t.rejected] + [\n", "    entries = [] + [\n"),
    ("M799", "a collection that cannot be read is called « not collected » (IA1)", TRI,
     '            elif coll.collected is None:\n                causes.append("collection_unknown")\n',
     '            elif coll.collected is None:\n                causes.append("not_collected")\n'),
]

# IA1, after the review (M840–M842, M844): the rules as the watch loads them, one decision at
# a time, an unreadable triage refused, one entry per line. (M843, a prose filter, is gone with
# it: no turn of phrase is filtered — the code's status decides, M871–M878.)
MUTANTS += [
    ("M840", "an entry of the client's layer the watch skips replaces a base rule in the triage (IA1)", TRI,
     "            if why := _invalid_client_rule(entry):\n", '            if why := "":\n'),
    ("M841", "two decisions taken at once: the second write loses the first (IA1)", TRI,
     "    with _locked(campaign_dir):\n        t = load(campaign_dir)\n",
     "    with open(os.devnull):\n        t = load(campaign_dir)\n"),
    ("M842", "an unreadable triage.json ends in a trace, not a refusal (IA1)", TRI,
     "    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:",
     "    except OSError as e:"),
    ("M844", "the reason of a removed entry, quoting the model, breaks triage.md (IA1)", TRI,
     "— écarté : {_plain(r.get('rejected'))}", "— écarté : {r['rejected']}"),
]

# IA1, second review (M871–M875): beside each proposal, the status the code wrote — the only
# thing that says a human decided; the model's text shown as its text; the save locked too.
MUTANTS += [
    ("M871", "the status shown beside a proposal comes from the model's text, not the code (IA1)", TRI,
     "· **{STATUS_LABEL} : {_status(i.proposal)}**", "· **{STATUS_LABEL} : {_cell(i.proposal.text)}**"),
    ("M872", "the model's Markdown is rendered: its text can draw a status of its own (IA1)", TRI,
     "    return _cell(str(text).translate(_MARKUP))\n", "    return _cell(text)\n"),
    ("M873", "a new triage written without the lock: a decision taken meanwhile is lost (IA1)", TRI,
     "    with _locked(campaign_dir):\n        return _save(campaign_dir, t, replace_decided)\n",
     "    with open(os.devnull):\n        return _save(campaign_dir, t, replace_decided)\n"),
    ("M874", "a refusal of the analysis model exits 1, as an error: H0 gives no advice (IA1)", SEP,
     "        return REFUSED\n", "        return 1\n"),
    ("M875", "triage.md no longer says that only the code's status counts (IA1)", TRI,
     "\"**Aucune décision n'est prise par le modèle : seul", "\"**Le modèle propose : seul"),
]

# IA1, third review (M876–M878): measured through a real CommonMark engine (markdown-it).
MUTANTS += [
    ("M876", "the reason of a removed entry rendered without escaping: a bold status from it (IA1)", TRI,
     "— écarté : {_plain(r.get('rejected'))}", "— écarté : {_cell(r.get('rejected'))}"),
    ("M877", "a line ends on \\n only: a \\r of the model starts a list item of its own (IA1)", TRI,
     '    return " ".join(str(text).splitlines()).replace("|", "\\\\|")\n',
     '    return str(text).replace("|", "\\\\|").replace("\\n", " ")\n'),
    ("M878", "the reason of an unknown proposal quotes the model's text (IA1)", TRI,
     '            why = "unknown proposal"   # never the model\'s text: it is shown beside, escaped\n',
     "            why = f\"unknown proposal ({e['proposal'] or 'none'})\"\n"),
]

# Mutants measured by other tests than the invariants (their lot's own).
TESTS = {mid: INSCRIPTION_TESTS for mid in ("M42", "M43", "M44", "M45", "M46", "M47")}
TESTS.update({mid: DOCS_TESTS for mid in ("M48", "M49")})
TESTS["M50"] = "tests/unit/test_glorfindel.py -k drain"
TESTS["M51"] = "tests/unit/test_agent_nodes.py -k raises"
TESTS["M52"] = "tests/unit/test_glorfindel.py -k remembered"
TESTS["M53"] = "tests/unit/test_readiness.py -k refused"
TESTS.update({mid: "tests/unit/test_glorfindel_host.py" for mid in ("M54", "M55", "M56")})
TESTS.update({mid: "tests/unit/test_exercise.py" for mid in ("M57", "M58", "M59", "M60", "M61")})
TESTS["M62"] = "tests/unit/test_detection_rules.py -k sampling_step"
TESTS["M63"] = "tests/unit/test_campaign_report.py"
TESTS.update({mid: "tests/unit/test_orodruin.py" for mid in ("M64", "M65", "M66", "M67")})
TESTS.update({mid: "tests/unit/test_exercise_channel.py" for mid in ("M68", "M69", "M70")})
TESTS.update({mid: "tests/unit/test_gothmog.py" for mid in ("M71", "M72", "M73", "M74")})
TESTS.update({mid: "tests/unit/test_annatar_atomic.py"
              for mid in ("M75", "M76", "M77", "M78", "M79", "M80")})
TESTS.update({mid: "tests/unit/test_annatar_run_exit.py"
              for mid in ("M103", "M104", "M105", "M106", "M107", "M108")})
# R1 review: run_command's journal is proven in test_orodruin.py; the rest in test_annatar_atomic.py.
TESTS.update({mid: "tests/unit/test_orodruin.py" for mid in ("M81", "M85")})
TESTS.update({mid: "tests/unit/test_annatar_atomic.py"
              for mid in ("M82", "M83", "M84", "M86", "M87", "M88", "M89", "M90",
                          "M91", "M92", "M93", "M94", "M95", "M96", "M97")})
TESTS.update({mid: DETECTION_TESTS for mid in ("M98", "M99", "M100", "M101", "M102")})
TESTS.update({mid: "tests/unit/test_watch_channel.py"
              for mid in ("M109", "M110", "M111", "M112", "M113", "M114", "M115")})
# #165 — the atomic campaign: the synthesizer in test_campaign_synthesizer.py, the catalog
# schema requirement in test_experiment_schema.py.
TESTS.update({mid: "tests/unit/test_campaign_synthesizer.py"
              for mid in ("M116", "M117", "M118", "M120", "M121", "M122")})
TESTS.update({mid: "tests/unit/test_campaign_runner.py" for mid in ("M123", "M125")})
TESTS["M124"] = "tests/unit/test_makefile_campaign.py"
TESTS["M119"] = "tests/unit/test_experiment_schema.py"
# #167 — the report on H0 in test_hosted_report.py; the publication, the pulls and the end
# of `campaign run` in test_campaign_channel.py.
TESTS.update({mid: "tests/unit/test_hosted_report.py"
              for mid in ("M126", "M127", "M128", "M129", "M131", "M132", "M133", "M134",
                          "M135", "M137", "M140", "M141", "M142", "M143", "M144", "M145",
                          "M146", "M147", "M148", "M159", "M160", "M161", "M162", "M163",
                          "M164", "M165", "M166", "M167", "M168", "M169", "M180", "M181",
                          "M182", "M183", "M184", "M185", "M186", "M187", "M188")})
TESTS.update({mid: "tests/unit/test_campaign_channel.py"
              for mid in ("M130", "M136", "M138", "M139", "M149")})
TESTS["M150"] = "tests/unit/test_bot.py"
TESTS.update({f"M{n}": "tests/unit/test_dependency_failures.py" for n in range(151, 159)})
TESTS.update({f"M{n}": "tests/unit/test_dependency_failures.py" for n in range(170, 179)})
TESTS["M189"] = "tests/unit/test_makefile_bench.py"
TESTS["M190"] = "tests/unit/test_campaign_report.py"
TESTS.update({mid: "tests/unit/test_orodruin_kill.py" for mid in ("M191", "M192", "M193")})
TESTS["M194"] = "tests/unit/test_orodruin.py"
TESTS.update({f"M{n}": "tests/unit/test_decision_stability.py" for n in range(200, 213)})
TESTS.update({f"M{n}": "tests/unit/test_exercise_guard.py" for n in range(220, 239)})
TESTS.update({f"M{n}": "tests/unit/test_run_channel.py" for n in range(240, 246)})
TESTS.update({mid: "tests/unit/test_gothmog.py" for mid in ("M241", "M246")})
# A1 / MC0: the façade's one namespace, the capabilities and the boundary.
TESTS.update({mid: "tests/unit/test_actions_split.py" for mid in ("M450", "M451", "M452")})
TESTS.update({f"M{n}": f"{BOUNDARY_TESTS} tests/unit/test_readiness.py" for n in range(453, 459)})
TESTS["M459"] = "tests/unit/test_jobs.py"
TESTS.update({mid: BOUNDARY_TESTS for mid in ("M460", "M461", "M462")})
TESTS["M463"] = "tests/unit/test_actions_split.py"
TESTS.update({f"M{n}": "tests/unit/test_campaign_changes.py" for n in range(260, 280)})  # D-2
TESTS.update({f"M{n}": "tests/unit/test_campaign_changes.py" for n in range(510, 520)})  # D-2, review
TESTS.update({f"M{n}": "tests/unit/test_campaign_changes.py" for n in range(530, 540)})  # D-2, 2nd review
TESTS.update({f"M{n}": "tests/unit/test_campaign_changes.py" for n in range(540, 548)})  # D-2, 3rd, 4th reviews
TESTS.update({f"M{n}": "tests/unit/test_campaign_changes.py" for n in range(650, 670)})  # D2b
TESTS.update({f"M{n}": "tests/unit/test_bot.py" for n in range(280, 284)})
TESTS.update({f"M{n}": "tests/unit/test_glorfindel_host.py" for n in range(284, 287)})
TESTS.update({f"M{n}": "tests/unit/test_host_deploy.py" for n in (287, 288)})
TESTS["M289"] = "tests/unit/test_dependency_lock.py"
TESTS["M520"] = "tests/unit/test_bot.py"
TESTS.update({f"M{n}": "tests/unit/test_glorfindel_host.py" for n in (521, 522, 523)})
TESTS.update({f"M{n}": "tests/unit/test_host_deploy.py" for n in range(524, 529)})
TESTS.update({f"M{n}": AWS_INVARIANTS for n in range(600, 650)})  # MC1
TESTS["M617"] = AWS_UNIT              # MC1: a false alarm, no false claim
# MC1: rare in the drawn sequences (M600, M601 found at 5 000) — their case written by hand too.
TESTS.update({mid: f"{AWS_INVARIANTS} {AWS_UNIT}" for mid in ("M600", "M601", "M602", "M608", "M612", "M614")})
TESTS.update({f"M{n}": AWS_UNIT for n in range(618, 624)})                  # MC1, after its review
# P1 (#86): rule layers.
TESTS.update({f"M{n}": "tests/unit/test_rule_layers.py tests/unit/test_proposed_rules.py"
              for n in (*range(670, 679), 685, 686)})
TESTS["M687"] = "tests/unit/test_host_deploy.py"
TESTS["M688"] = "tests/unit/test_rule_layers.py"
TESTS.update({f"M{n}": "tests/unit/test_rule_layers.py tests/unit/test_host_deploy.py" for n in range(695, 700)})
TESTS.update({f"M{n}": "tests/unit/test_rule_layers.py" for n in range(713, 717)})
TESTS.update({f"M{n}": "tests/unit/test_console.py" for n in range(400, 410)})  # UI-1
TESTS.update({f"M{n}": "tests/unit/test_indicators.py" for n in range(560, 566)})  # UI-2
TESTS["M561"] = "tests/unit/test_containment.py tests/unit/test_indicators.py"
TESTS["M566"] = "tests/unit/test_host_deploy.py"
TESTS["M567"] = "tests/unit/test_console.py"
TESTS["M568"] = "tests/unit/test_console.py"
TESTS["M569"] = "tests/unit/test_cli.py -k version"
TESTS.update({f"M{n}": "tests/unit/test_console.py" for n in range(570, 580)})  # #248, and the card detail escaped
TESTS.update({f"M{n}": "tests/unit/test_console_escaping.py" for n in range(580, 600)})  # #254
TESTS.update({f"M{n}": "tests/unit/test_console_escaping.py" for n in (*range(1080, 1100), *range(1290, 1300))})  # #257
TESTS["M403"] = "tests/unit/test_console_exercises.py"
# V1 (#214): Annatar's side and the shared gate in test_watch_gate.py, Gothmog's in test_gothmog.py.
TESTS.update({f"M{n}": "tests/unit/test_watch_gate.py" for n in (*range(720, 740), *range(750, 760))})
TESTS.update({f"M{n}": "tests/unit/test_gothmog.py" for n in (724, 725, 726, 727)})
TESTS.update({f"M{n}": "tests/unit/test_host_console.py" for n in range(740, 750)})  # UI-1c
# A3 (#73): the orphan sweep's guards, the strict config, the restore's extensions.
TESTS.update({f"M{n}": "tests/unit/test_orphan_sweep.py" for n in range(764, 770)})
TESTS.update({f"M{n}": f"{INVARIANTS} tests/unit/test_orphan_sweep.py" for n in (760, 762, 763)})  # rare when drawn
TESTS.update({f"M{n}": "tests/unit/test_config.py" for n in range(770, 774)})
TESTS.update({f"M{n}": "tests/unit/test_glorfindel.py -k extensions" for n in (774, 775)})
TESTS.update({f"M{n}": "tests/unit/test_orphan_sweep.py" for n in (776, 777, 778, 779, 880, 881, 883, 886, 887)})
TESTS["M882"] = "tests/unit/test_config.py"
TESTS["M884"] = "tests/unit/test_agent_nodes.py -k extension"
TESTS["M885"] = "tests/unit/test_glorfindel.py -k extensions"
TESTS.update({f"M{n}": "tests/unit/test_orphan_sweep.py" for n in (888, 889, 700, 701)})

# L1F (#229): no liveness property on a vanished ISOLATION in the machine — its unit test.
TESTS["M901"] = "tests/unit/test_reassert.py"
# L1F: a crash between the card and the marker is rare in the drawn sequences (M900 and M902
# survive the machine alone at 500 and 2 000, 27/10) — M900's case frozen, both written by hand.
TESTS.update({mid: f"tests/unit/test_reassert.py tests/unit/test_invariant_regressions.py {INVARIANTS}"
              for mid in ("M900", "M902")})
TESTS.update({f"M{n}": "tests/unit/test_activity_logs.py" for n in (*range(810, 830), *range(850, 860), *range(890, 895))})  # AL1
TESTS.update({f"M{n}": "tests/unit/test_entra_detection.py" for n in (*range(920, 950), 955)})  # C2
# IA1 (#88): the separation in test_analysis_separation.py, the triage in test_analysis_triage.py.
TESTS.update({f"M{n}": "tests/unit/test_analysis_separation.py" for n in range(780, 786)})
TESTS.update({f"M{n}": "tests/unit/test_analysis_triage.py" for n in range(786, 800)})
TESTS["M840"] = "tests/unit/test_analysis_rules_parity.py"      # against the watch's own loader
TESTS.update({f"M{n}": "tests/unit/test_analysis_triage.py" for n in (841, 842, 844, 871, 872, 873, 875, 876, 877, 878)})
TESTS["M874"] = "tests/unit/test_analysis_separation.py"
# I1F (#226): M830–M832 by the machine (their frozen sequences catch them too); M833 is no
# property of the world (a card closed too soon), its regression and unit tests only.
TESTS["M833"] = "tests/unit/test_invariant_regressions.py -k altered_quarantine tests/unit/test_reassert.py"
TESTS.update({f"M{n}": "tests/unit/test_reassert.py" for n in (835, 836, 837, 839, 895, 896, 897, 898)})
# M838: the frozen sequence of the second review; the machine found it once in 11 runs at 500.
TESTS["M838"] = f"{INVARIANTS} tests/unit/test_invariant_regressions.py"
# I4F (#235): the machine met it once, at 2 000 sequences (seed 101) — its frozen sequence too.
TESTS.update({mid: f"{INVARIANTS} tests/unit/test_invariant_regressions.py" for mid in ("M960", "M961")})
# I4S (#239): their frozen sequences first (each one has its witness), then the machine
# (its composite rule, `an_old_isolations_vm_goes_away`).
TESTS.update({f"M{n}": f"tests/unit/test_invariant_regressions.py {INVARIANTS}" for n in range(1030, 1040)})
# M834 needs a world with no state at all: rare in the drawn sequences (2/4 at 500).
TESTS["M834"] = f"{INVARIANTS} tests/unit/test_reassert.py"
# I8F (#227): flaky by the machine alone (its composite rule helps, a 429 at the right call
# stays rare) — their frozen sequences, then the machine (L1F's precedent).
TESTS.update({mid: f"tests/unit/test_invariant_regressions.py {INVARIANTS}"
              for mid in ("M860", "M861", "M862", "M863", "M864", "M865")})
# I8S (#245): a second host with its own state is outside the machine — the frozen sequences.
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k two_hosts" for n in range(1040, 1050)})

# I1S (#231): a quarantine card's NSG absent from the listing is read again by its id before
# the card closes — gone on a 404 only, judged on its content without its tag, never read in
# another subscription.
MUTANTS += [
    ("M1020", "a quarantine card closed on the mere absence of its NSG from the listing: the role "
              "removed, our tag taken off, another subscription (I1S)", RQ,
     "        return k in gone\n", "        return True\n"),
    ("M1021", "a quarantine NSG read again without our tag reads as not ours: its card closed (I1S)", SWP,
     "        return self._quarantine_as_read(nsg)\n",
     '        if (getattr(nsg, "tags", None) or {}).get("managed-by") != "glorfindel":\n'
     "            return None\n        return self._quarantine_as_read(nsg)\n"),
    ("M1022", "a quarantine NSG of another subscription read in this one: its homonym, or a 404, "
              "closes its card (I1S)", SWP,
     '        if not target or target.lower() != (self._subscription_id or "").lower():\n',
     "        if False:\n"),
    ("M1023", "a quarantine NSG that can't be read again (403, 429) reads as gone: its card closed (I1S)", RQ,
     "exc)\n            continue\n        if q is None:\n",
     "exc)\n            gone.add(k)\n            continue\n        if q is None:\n"),
    ("M1024", "every quarantine card's NSG read again at every pass, listed or not: a get per card "
              "per minute (I1S)", RQ,
     "        if _key(rid) and _key(rid) not in seen:\n", "        if _key(rid):\n"),
    ("M1025", "an acknowledged change is not read again: its NSG deleted, the acknowledgement silences "
              "the next one (I1S)", RQ,
     '    for rid in [e.get("resource_id") or "" for e in cards] + list(alerts):\n',
     '    for rid in [e.get("resource_id") or "" for e in cards]:\n'),
    ("M1026", "a refusal (403) read again reads as not found: the card closed (I1S)", SWP,
     "            if _is_not_found(exc):\n                return None\n            raise\n",
     "            return None\n"),
]
TESTS.update({f"M{n}": f"tests/unit/test_reassert.py tests/unit/test_invariant_regressions.py {INVARIANTS}"
              for n in (1020, 1021, 1023, 1026)})
TESTS.update({f"M{n}": "tests/unit/test_reassert.py" for n in (1022, 1024, 1025)})

# ISU (#264): the small follow-ups of the reviews of I1S, I8S and I4S — the unblock behind the
# quarantine follows the release's rule for the original; an original gone says how to get
# out; a card of another subscription is never read and said once; a plain-named block on a
# NIC's NSG that is its subnet's too may be a perimeter block. Range M1100–M1119.
MUTANTS += [
    ("M1100", "the unblock behind the quarantine follows the state's 'none' over a tag naming X: "
              "`not_found`, the IP still blocked on X (ISU)", UNB,
     "            return self._original_from_tags(q, nic_id) if original is _UNKNOWN else self._tag_over_none(q, nic_id)\n",
     "            return self._original_from_tags(q, nic_id) if original is _UNKNOWN else None\n"),
    ("M1101", "a tag that can't be read behind the state's 'none' reads as 'none' at the unblock: "
              "`not_found` on a guess (ISU)", UNB,
     # Since U3F the unblock reads it in _original_away.
     "            return self._original_from_tags(q, nic_id) if original is _UNKNOWN else self._tag_over_none(q, nic_id)\n",
     "            if original is _UNKNOWN:\n"
     "                return self._original_from_tags(q, nic_id)\n"
     "            try:\n"
     "                return self._tag_over_none(q, nic_id)\n"
     "            except Exception:\n"
     "                return None\n"),
    ("M1102", "an original gone says only that it wasn't found: no way out (ISU)", REL,
     "        if not original:\n            return exc\n", "        return exc\n"),
    ("M1103", "the tag set to 'none' offered while the state names the original: a way out that "
              "changes nothing (ISU)", REL,
     'tag = "" if not q or (isinstance(recorded, str) and _same_id(recorded, original)) else (',
     'tag = "" if not q else ('),
    ("M1104", "an original that can't be read (403, 429) called gone: recreate an NSG that exists (ISU)",
     REL, "            if not _is_not_found(read):\n                return exc\n", "            pass\n"),
    ("M1105", "a NIC left bare whose recorded original is gone: the release says only 'not found' (ISU)",
     REL, '                                    raise self._original_gone(p, p["nic_id"], original, exc)\n',
     "                                    raise\n"),
    ("M1106", "a bare NIC tied by our tag to an original gone: the stateless release says only "
              "'not found' (ISU)", REL,
     '                                raise self._original_gone(q_bare, t0["nic_id"], original, exc)\n',
     "                                raise\n"),
    ("M1107", "a bare NIC whose original is gone: the reset says only 'not found' (ISU)", SWP,
     '                        raise self._original_gone(q_bare, t0["nic_id"], original, exc)\n',
     "                        raise\n"),
    ("M1108", "a NIC in quarantine whose original is gone: release and reset say only 'not found' (ISU)",
     QUA, "            raise self._original_gone(q, nic_id, original, exc)\n", "            raise\n"),
    ("M1109", "a card of another subscription handed to the reader: refused there, a warning at every "
              "pass without end (ISU)", RQ,
     "    elsewhere = {k: w for k, rid in missing.items() if outside and isinstance(w := outside(rid), str) "
     "and w}\n", "    elsewhere = {}\n"),
    ("M1110", "a card of another subscription said at every pass (ISU)", RQ,
     "    for k in elsewhere.keys() - _SAID_ELSEWHERE:\n", "    for k in elsewhere:\n"),
    ("M1111", "an acknowledged change alone named by its lowercase key, not as Azure wrote it (ISU)", RQ,
     "    missing = {k: cased.get(k) or rid for k, rid in missing.items()}\n", ""),
    ("M1112", "the connector never says an NSG is of another subscription: every pass, a warning (ISU)",
     SWP, '        return None if target and target.lower() == (self._subscription_id or "").lower() '
          'else (target or "?")\n', "        return None\n"),
    ("M1113", "a plain-named block on a NIC's NSG that is its subnet's too: said an older version's "
              "only, never a perimeter block (ISU)", UNB,
     'if t.get("subnet_nsg_too") else', "if False else"),
    ("M1114", "a NIC's own NSG that is its subnet's too not marked: the perimeter block unsaid (ISU)", NET,
     '**({"subnet_nsg_too": True} if own_id and subnet_nsg and tuple(',
     '**({"subnet_nsg_too": True} if False and subnet_nsg and tuple('),
    ("M1115", "a card of another subscription said once for ever: closed, then a new card on its NSG "
              "unsaid (ISU)", RQ,
     "    _SAID_ELSEWHERE.intersection_update(elsewhere)\n", ""),
]
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k two_hosts_an_unblock" for n in (1100, 1101)})
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k gone" for n in range(1102, 1109)})
TESTS.update({f"M{n}": "tests/unit/test_reassert.py" for n in (1109, 1110, 1111, 1112, 1115)})
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k perimeter_one" for n in (1113, 1114)})

# SEC3 (#274): the runs/ channel and the local state — an unreadable state never frees a VM,
# remove_orphan_rule guarded as every write, the channel takes from runs/ only what an injector
# emits, a recovery_complete lifts an isolation alone only from Glorfindel's own path, the
# escalations store under its lock and written whole, owner-only state, the injectors' mounts.
# Range M1210–M1239.
SO = "glorfindel/signal_origin.py"
ESC = "glorfindel/escalations.py"
LCK = "glorfindel/response/locks.py"
SEC3_ORIGIN = "tests/unit/test_signal_origin.py"
MUTANTS += [
    ("M1210", "an unreadable state reads as no state: the sweep frees a VM it isolates (SEC3, N-06)", SWP,
     "        unread = self._unreadable_reason()\n        gone: dict", "        unread = \"\"\n        gone: dict"),
    ("M1211", "a state unreadable since the listing is not read again before the removal (SEC3, N-06)", SWP,
     "        unread = self._unreadable_reason()\n        if unread:\n            return {\"removed\": False, "
     "\"why\": unread}\n", ""),
    ("M1212", "a state of the wrong shape reads as readable (SEC3, N-06)", STA,
     "            if not _readable_shape(data, shape):\n",
     "            if data is None:\n"),
    ("M1213", "remove_orphan_rule writes an NSG of another subscription (SEC3, N-07)", AZC,
     "        if target and mine and target.lower() != mine.lower():\n            raise WrongSubscriptionError(\n"
     "                f\"{nsg_id.rstrip",
     "        if False:\n            raise WrongSubscriptionError(\n                f\"{nsg_id.rstrip"),
    ("M1214", "remove_orphan_rule outside the guards of the writes: no lock of the VMs it cuts (SEC3, N-07)",
     AZC, "AzureConnector.remove_orphan_rule = _orphan_writer(AzureConnector.remove_orphan_rule)\n", ""),
    ("M1215", "the watch dispatches every line of runs/ as it is: a forged recovery_complete decided on "
              "(SEC3, V-05)", GCLI,
     "                admitted = _admit_from_runs(data, path.name)\n", "                admitted = (data, _sig)\n"),
    ("M1216", "an admitted line keeps its own fields: a query, an IP to block, an attribution (SEC3, V-05)", SO,
     "        clean[part] = {k: given[k] for k in fields[part] if k in given}\n", "        clean[part] = dict(given)\n"),
    ("M1217", "a run id that is a path admitted: the debug file written outside runs/ (SEC3, V-05)", SO,
     "    if run_id not in (None, \"\") and not (", "    if False and not ("),
    ("M1218", "a recovery_complete of unknown origin releases alone (SEC3, V-05)", "glorfindel/agent.py",
     "    if signal.get(\"event\") == \"recovery_complete\" and not vouched(signal):\n", "    if False:\n"),
    ("M1219", "`glorfindel respond` vouches for a recovery_complete of any file, runs/ included (SEC3, V-05)",
     GCLI, "    trusted = signal_origin.in_recovery_dir(signals_file)\n", "    trusted = True\n"),
    ("M1220", "the defender's directory told by a name: runs/recovery/ passes (SEC3, V-05)", SO,
     "        return Path(path).resolve().parent == RECOVERY_SIGNALS_DIR.resolve()\n",
     "        return \"recovery\" in str(path)\n"),
    ("M1221", "the restore's own recovery_complete not vouched for: `restore --wait` never releases (SEC3)",
     GCLI, "    return vouch({\n        \"signal_id\": f\"{run_id}_recovery_complete\",",
     "    return ({\n        \"signal_id\": f\"{run_id}_recovery_complete\","),
    ("M1222", "the escalations store rewritten without its lock: cards lost between writers (SEC3, V-10)", ESC,
     "            with _file_lock(_STORE.with_name(_STORE.name + \".lock\")):\n", "            if True:\n"),
    ("M1223", "the escalations store rewritten in place: a reader sees half a file (SEC3, V-10)", ESC,
     "    _atomic_write_text(_STORE, \"\\n\".join(lines) + \"\\n\")\n",
     "    _STORE.write_text(\"\\n\".join(lines) + \"\\n\")\n"),
    ("M1224", "a new card appended in place: a reader may see half a line (SEC3, V-10)", ESC,
     "    _write_lines([ln for ln in lines if ln.strip()] + [json.dumps(esc, default=str)])\n",
     "    with open(_STORE, \"a\") as _f:\n        _f.write(json.dumps(esc, default=str) + \"\\n\")\n",
     "TIMING: under the store's lock, one small append is one write(2) — the test's reader sees "
     "it half done only at times (1 round in 2, measured); what the whole rewrite adds besides (a "
     "crash inside the write leaves the store as it was) needs a process killed mid-write"),
    ("M1225", "the store's lock is a thread lock only: another process writes meanwhile (SEC3, V-10)", LCK,
     # The store's own block (its message names the file, not a VM): since I3F (#292) the
     # same flock lines open _vm_lock and _file_lock.
     "                if timeout is None:\n                    fcntl.flock(fh, fcntl.LOCK_EX)\n"
     "                else:\n                    deadline = _time.monotonic() + timeout\n"
     "                    while True:\n                        try:\n"
     "                            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
     "                            break\n                        except BlockingIOError:\n"
     "                            if _time.monotonic() >= deadline:\n"
     "                                raise TimeoutError(f\"{path.name} busy (another process is writing)\")\n"
     "                            _time.sleep(0.2)\n",
     "                pass\n"),
    ("M1226", "state files readable by all again (SEC3, V-27)", STA,
     "def _atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:\n",
     "def _atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:\n"),
    ("M1227", "state directories created with the default mode (SEC3, V-27)", STA,
     "    path.parent.mkdir(mode=0o755 if mode & 0o044 else 0o700, parents=True, exist_ok=True)\n",
     "    path.parent.mkdir(parents=True, exist_ok=True)\n"),
    ("M1228", "an earlier version's state left readable by all (SEC3, V-27)", STA,
     "        _owner_only(directory)\n", ""),
    ("M1229", "Gothmog's container mounts the whole of ~/.glorfindel again (SEC3, N-05)", "docker-compose.yml",
     "      - ./technique_catalog.yaml:/app/technique_catalog.yaml:ro\n"
     "      - ${HOME}/.glorfindel/injectors:/root/.glorfindel:ro\n",
     "      - ./technique_catalog.yaml:/app/technique_catalog.yaml:ro\n"
     "      - ${HOME}/.glorfindel:/root/.glorfindel:ro\n"),
    ("M1230", "the watch writes no heartbeat where the injectors read it: every run refused (SEC3, N-05)",
     GCLI, "            _atomic_write_text(_INJECTOR_BEAT, json.dumps(beat_body(at)), mode=0o644)",
     "            pass  #"),
    ("M1231", "make glorfindel-start no longer creates ~/.glorfindel/injectors: docker makes it as root "
              "(SEC3)", MAKE,
     "glorfindel-start: check-azure-env build-glorfindel\n"
     "\tmkdir -p $(HOME)/.glorfindel $(HOME)/.glorfindel/injectors ",
     "glorfindel-start: check-azure-env build-glorfindel\n\tmkdir -p $(HOME)/.glorfindel "),
    ("M1232", "an attack_adapted admitted again, no injector emitting it: decided on (SEC3, V-05)", SO,
     ("    if event not in CHANNEL_EVENTS:\n", "    fields = _FIELDS[event]\n"),
     ("    if event not in CHANNEL_EVENTS and event != \"attack_adapted\":\n",
      "    fields = _FIELDS.get(event, _FIELDS[\"attack_started\"])\n")),
    ("M1233", "a refused line not counted (SEC3, V-05)", SO,
     "        _REFUSED[event] = _REFUSED.get(event, 0) + 1\n", ""),
    # After the review of SEC3 (M1234–M1239).
    ("M1234", "a link in the defender's directory taken for its file: one into runs/ passes (SEC3, V-05)", SO,
     "        return Path(path).resolve().parent == RECOVERY_SIGNALS_DIR.resolve()\n",
     "        return Path(path).parent == RECOVERY_SIGNALS_DIR\n"),
    ("M1235", "the watch no longer makes the injectors' directory first: docker makes it as root (SEC3)", GCLI,
     "        _INJECTORS_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)\n"
     "        os.chmod(_INJECTORS_DIR, 0o755)      # theirs to read, whatever the umask\n",
     "        pass\n"),
    ("M1236", "the injectors' heartbeat owner-only: an image of another user can't read it (SEC3, N-05)", GCLI,
     "            _atomic_write_text(_INJECTOR_BEAT, json.dumps(beat_body(at)), mode=0o644)",
     "            _atomic_write_text(_INJECTOR_BEAT, json.dumps(beat_body(at)))"),
    ("M1237", "Annatar reads Glorfindel's state again: the blocks watcher back (SEC3, N-05)", ENG,
     "        # Glorfindel no longer writes, and the injectors no longer mount that state.\n"
     "        stop_event = threading.Event()\n",
     "        # Glorfindel no longer writes, and the injectors no longer mount that state.\n"
     "        stop_event = threading.Event()\n"
     "        _blocks = Path.home() / \".glorfindel\" / \"blocks\"\n"),
    ("M1238", "the refusals counted in memory only: nothing on this host says them (SEC3, V-05)", SO,
     "            _atomic_write_text(REFUSALS_FILE, json.dumps(", "            (lambda *a, **k: None)(REFUSALS_FILE, json.dumps("),
    ("M1239", "any recovery_complete with an id vouched for: a forged one releases alone (SEC3, V-05)", SO,
     "        return bool(sid) and sid in _VOUCHED\n", "        return bool(sid)\n"),
]
TESTS.update({f"M{n}": SEC3_ORIGIN for n in (1234, 1235, 1236, 1238)})
TESTS["M1237"] = "tests/unit/test_engine.py -k injectors_read"
TESTS["M1239"] = "tests/unit/test_agent_nodes.py -k recovery"
TESTS.update({f"M{n}": "tests/unit/test_orphan_sweep.py -k unreadable" for n in (1210, 1211, 1212)})
TESTS.update({f"M{n}": "tests/unit/test_orphan_sweep.py -k guarded_write" for n in (1213, 1214)})
TESTS.update({f"M{n}": SEC3_ORIGIN for n in (1215, 1216, 1217, 1219, 1220, 1221, 1226, 1227, 1228, 1230,
                                             1232, 1233)})
TESTS["M1218"] = "tests/unit/test_agent_nodes.py -k recovery"
TESTS.update({f"M{n}": "tests/unit/test_locks.py -k concurrent" for n in (1222, 1223, 1224, 1225)})
TESTS.update({f"M{n}": "tests/unit/test_profiles.py" for n in (1229, 1231)})

# D1 (#81): each component runs alone (scripts/component_check.py), and every usage profile
# keeps Glorfindel (docker-compose.yml, the Makefile's profile and team targets).
D1_COMPONENTS = "tests/unit/test_components.py"
D1_PROFILES = "tests/unit/test_profiles.py"
MUTANTS += [
    ("M800", "Glorfindel reads the signal contract from Annatar again: it cannot run alone (D1)",
     "glorfindel/signals.py", "from eregion_core.signals import Signal\n",
     "from annatar.signals.emitter import Signal\n"),
    ("M801", "the component check's finder lets every package through: it proves nothing (D1)",
     "scripts/component_check.py", "        if self.blocks(fullname):\n            raise ModuleNotFoundError(",
     "        if False:\n            raise ModuleNotFoundError("),
    ("M802", "a listed crossing allowed at module level: the component imports the other on load (D1)",
     "scripts/component_check.py", "((rel, pkg) in CROSSINGS and not at_top)", "((rel, pkg) in CROSSINGS)"),
    ("M803", "Annatar's compose service no longer starts Glorfindel's watch (D1, V1)", "docker-compose.yml",
     "      - ${HOME}/.annatar:/root/.annatar\n      - ${HOME}/.glorfindel/injectors:/root/.glorfindel:ro\n"
     "    depends_on:\n      - watch\n",
     "      - ${HOME}/.annatar:/root/.annatar\n      - ${HOME}/.glorfindel/injectors:/root/.glorfindel:ro\n"),
    ("M804", "Gothmog's compose service may write Glorfindel's state (D1)", "docker-compose.yml",
     "      - ${HOME}/.glorfindel/injectors:/root/.glorfindel:ro\n    depends_on:\n      - watch\n"
     "\n  # D1 : Gothmog",
     "      - ${HOME}/.glorfindel:/root/.glorfindel\n    depends_on:\n      - watch\n"
     "\n  # D1 : Gothmog"),
    ("M805", "the injectors receive Glorfindel's service principal (D1, M-3)", "docker-compose.yml",
     "  AZURE_CLIENT_SECRET: ${ANNATAR_AZURE_CLIENT_SECRET:-}\n",
     "  AZURE_CLIENT_SECRET: ${AZURE_CLIENT_SECRET:-}\n"),
    ("M806", "make profile-detection starts Annatar's side without Glorfindel (D1)", MAKE,
     "profile-detection: glorfindel-start build-annatar\n", "profile-detection: build-annatar\n"),
    ("M807", "a team's Glorfindel inherits the operator's shell: its subscription, its keys (D1)", MAKE,
     'TEAM_COMPOSE = env -i PATH="$$PATH"', 'TEAM_COMPOSE = env PATH="$$PATH"'),
    ("M808", "any team name accepted: a path, a compose project, container names (D1)", MAKE,
     '@case "$(TEAM)" in ""|-*|*[!a-z0-9-]*) echo', '@case "$(TEAM)" in "") echo'),
    ("M809", "without a team, the watch's container is no longer eregion-watch: H0's scripts lose it (D1)",
     "docker-compose.yml", "    container_name: ${EREGION_INSTANCE:-eregion}-watch\n",
     "    container_name: ${EREGION_INSTANCE:-eregion-glorfindel}-watch\n"),
]
TESTS.update({f"M{n}": D1_COMPONENTS for n in range(800, 803)})
TESTS.update({f"M{n}": D1_PROFILES for n in range(803, 810)})
# D1, after its review: the conftest's redirections, the analysis AI scanned, the guard of
# this harness line by line.
MUTANTS += [
    ("M845", "the conftest believes Glorfindel absent: no redirection, the suite writes ~/.glorfindel (D1)",
     "tests/unit/conftest.py", 'GLORFINDEL = _present("glorfindel")\n', "GLORFINDEL = False\n"),
    ("M846", "the conftest believes the console absent: its settings cache leaks between tests (D1)",
     "tests/unit/conftest.py", 'CONSOLE = _present("eregion_console")\n', "CONSOLE = False\n"),
    ("M847", "the analysis AI no longer scanned: its import of Annatar on load goes unlisted (D1)",
     "scripts/component_check.py",
     ',\n           "analysis": ("analysis", "eregion_core")}', "}"),
    ("M848", "one module made absent covers every other missing one: the harness measures a broken copy (D1)",
     "scripts/mutation_check.py",
     "COMPONENT_ABSENT not in line:\n            return line.strip()",
     "COMPONENT_ABSENT not in stdout:\n            return line.strip()"),
    ("M849", "make profile-detection leaves ~/.annatar to docker: created as root (D1)", MAKE,
     "profile-detection: glorfindel-start build-annatar\n\t@mkdir -p $(HOME)/.annatar\n",
     "profile-detection: glorfindel-start build-annatar\n"),
    ("M870", "without Annatar, the reports' thread starts and fails every pass, never said at start (D1)",
     "glorfindel/cli.py", "        from analysis import campaign_report  # noqa: F401\n", ""),
]
TESTS.update({f"M{n}": D1_COMPONENTS for n in range(845, 849)})
TESTS["M849"] = D1_PROFILES
TESTS["M870"] = "tests/unit/test_hosted_report.py"

# HY1: no test writes in the repository (the conftest's guard), the quarantine locks' test on
# its own locks, the injectors' image from its lock, every secret passed by name (L23, #228).
HY1_GUARD = "tests/unit/test_repo_hermetic.py"
HY1_LOCK = "tests/unit/test_dependency_lock.py"
HY1_SECRETS = "tests/unit/test_makefile_secrets.py"
CONF = "tests/unit/conftest.py"
MUTANTS += [
    ("M910", "the store_cycle test writes runs/ in the repository again (HY1)", "tests/unit/test_agent_nodes.py",
     "    monkeypatch.chdir(tmp_path)   # store_cycle writes runs/<run_id>_debug.jsonl where it runs (HY1)\n", ""),
    ("M911", "the guard no longer watches the test process's writes (HY1)", CONF,
     "    _checked[0] = False\n    _watching[0] = True\n", "    _checked[0] = False\n"),
    ("M912", "a runs/ made at the root passes: git ignores it (HY1)", CONF,
     'left = [n for n in new if n == "runs" or (', 'left = [n for n in new if ('),
    ("M913", "any new entry at the root passes, whatever git says (HY1)", CONF,
     "_ignored_by_git(n) is not True)]", "False)]"),
    ("M914", "a write by a relative path is not seen as in the repository (HY1)", CONF,
     "    full = os.path.abspath(os.fsdecode(path))\n", "    full = os.fsdecode(path)\n"),
    ("M915", "the quarantine locks' test reads the process's global locks again (HY1)",
     "tests/unit/test_glorfindel.py",
     '    monkeypatch.setattr(actions, "_QUARANTINE_LOCKS", locks)\n    return locks\n',
     "    return actions._QUARANTINE_LOCKS\n"),
    ("M916", "the injectors' image resolves its dependencies again, unlocked (HY1)", "annatar/Dockerfile",
     "RUN pip install --no-cache-dir --no-deps --no-build-isolation -e .\n",
     'RUN pip install --no-cache-dir -e ".[annatar]"\n'),
    ("M917", "Annatar's extra without litellm: the planner fails in the image (HY1)", "pyproject.toml",
     "    # The campaign planner (`annatar campaign plan --llm`) — the same pin as Glorfindel's (HY1).\n"
     '    "litellm==1.100.4",\n',
     ""),
    ("M918", "Annatar's targets pass the client secret by value again (L23)", MAKE,
     "\t-e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID -e AZURE_SUBSCRIPTION_ID \\\n\t-e ANTHROPIC_API_KEY",
     "\t-e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET=$(or $(ANNATAR_AZURE_CLIENT_SECRET),$(AZURE_CLIENT_SECRET)) "
     "-e AZURE_TENANT_ID -e AZURE_SUBSCRIPTION_ID \\\n\t-e ANTHROPIC_API_KEY"),
    ("M919", "one target, glorfindel-shell, passes the client secret by value (L23)", MAKE,
     "\t@$(GLORFINDEL_AZURE_PICK) docker run --rm -it $(GLORFINDEL_AZURE_ENV)",
     "\t@docker run --rm -it -e AZURE_CLIENT_SECRET=$(AZURE_CLIENT_SECRET) $(GLORFINDEL_AZURE_ENV)"),
]
TESTS["M910"] = "tests/unit/test_agent_nodes.py -k no_op"
TESTS.update({f"M{n}": HY1_GUARD for n in range(911, 915)})
TESTS["M915"] = "tests/unit/test_glorfindel.py -k quarantine_lock"
TESTS.update({f"M{n}": HY1_LOCK for n in (916, 917)})
TESTS.update({f"M{n}": HY1_SECRETS for n in (918, 919)})
# HY1, after its review: the guard armed at the conftest's import (collection included), the
# writes other than an open, a secret's value the shell expands.
MUTANTS += [
    ("M950", "the guard armed at the first test again: a module's writes at collection go unseen (HY1)", CONF,
     "\n_arm()\n",
     '\n@pytest.fixture(scope="session", autouse=True)\ndef _armed_late():\n    _arm()\n'),
    ("M951", "a rename or a replace into the repository goes unseen (HY1)", CONF,
     '    "os.rename": ((0, 1), (2, 3)),', ""),
    ("M952", "sqlite3.connect in the repository goes unseen (HY1)", CONF,
     '    "sqlite3.connect": ((0,), ()),', ""),
    ("M953", "annatar-shell passes the secret as a value the shell expands (L23)", MAKE,
     "\t@$(ANNATAR_AZURE_PICK) docker run --rm -it $(ANNATAR_AZURE_ENV)",
     '\t@docker run --rm -it -e AZURE_CLIENT_SECRET="$$AZURE_CLIENT_SECRET" $(ANNATAR_AZURE_ENV)'),
    ("M954", "a remote command line exports a model key over ssh (L23)", MAKE,
     "\t$(HOST_SSH) 'docker exec eregion-watch glorfindel report --since $(or $(SINCE),7d)'",
     '\t$(HOST_SSH) "export ANTHROPIC_API_KEY=$$ANTHROPIC_API_KEY; '
     'docker exec eregion-watch glorfindel report --since $(or $(SINCE),7d)"'),
]
TESTS.update({f"M{n}": HY1_GUARD for n in (950, 951, 952)})
TESTS.update({f"M{n}": HY1_SECRETS for n in (953, 954)})
# The identifier hooks read their denylist from git's common directory: from --git-dir they
# found no list in a worktree and let everything through (27/10).
MUTANTS += [
    ("M903", "pre-commit reads its denylist from --git-dir again: nothing checked in a worktree", ".githooks/pre-commit",
     'denylist="$(git rev-parse --git-common-dir)/infra-denylist.txt"', 'denylist="$(git rev-parse --git-dir)/infra-denylist.txt"'),
    ("M904", "commit-msg reads its denylist from --git-dir again: nothing checked in a worktree", ".githooks/commit-msg",
     'denylist="$(git rev-parse --git-common-dir)/infra-denylist.txt"', 'denylist="$(git rev-parse --git-dir)/infra-denylist.txt"'),
]
TESTS.update({f"M{n}": "tests/unit/test_githooks.py" for n in (903, 904)})

# N1 (#242): the workshop's news in Discord, scripts/notify_discord.py, measured by its tests
# against a fake Discord (tests/unit/test_notify_discord.py). Range M970–M979.
NOTIFY = "scripts/notify_discord.py"
AGENTS_D = "scripts/agents_discord.py"
MUTANTS += [
    ("M970", "a message without allowed_mentions: a title with @everyone pings the server (N1)", NOTIFY,
     ('    out = {"embeds": [card], "allowed_mentions": {"parse": []}}\n',
      '        out["allowed_mentions"]["users"] = [mention]\n'),
     ('    out = {"embeds": [card]}\n',
      '        out["allowed_mentions"] = {"users": [mention]}\n')),
    ("M971", "a failed request names its URL: a webhook's token in the CI's log (N1)", NOTIFY,
     "            raise Failure(label, e.code) from None\n",
     '            raise Failure(f"{label} {url}", e.code) from None\n'),
    ("M972", "a Discord failure raised to the caller: the notify job red, the hook in error (N1)", NOTIFY,
     '                post_webhook(cfg.ci, message(n.card, silent=n.silent), "webhook #ci")\n'
     "            except Failure as e:\n                say(e)\n",
     '                post_webhook(cfg.ci, message(n.card, silent=n.silent), "webhook #ci")\n'
     "            except Failure:\n                raise\n"),
    ("M973", "a lot's detail not silent: every event of every lot notifies (N1)", NOTIFY,
     '    if silent:\n        out["flags"] = SILENT\n', ""),
    ("M974", "a cancelled run said red (N1)", NOTIFY,
     'RED_CONCLUSIONS = {"failure", "timed_out", "startup_failure"}\n',
     'RED_CONCLUSIONS = {"failure", "timed_out", "startup_failure", "cancelled"}\n'),
    ("M975", "the run before read as this very run: main green again never said (N1)", NOTIFY,
     '        if r.get("run_number", 0) < run.get("run_number", 0) and r.get("conclusion") in RED_CONCLUSIONS | {"success"}:\n',
     '        if r.get("conclusion") in RED_CONCLUSIONS | {"success"}:\n'),
    ("M976", "a new state replaces every tag: the thread loses its milestone (N1)", NOTIFY,
     "        names, out = self.tags(), [str(x) for x in current]\n",
     "        names, out = self.tags(), []\n"),
    ("M977", "archived threads not searched: a closed lot gets a second thread (N1)", NOTIFY,
     '            found += page.get("threads") or []\n', "            pass\n"),
    # M978, M979: elrond's part moved to scripts/agents_discord.py (N3), its tests with it.
    ("M978", "a model fallback never seen: a review not obtained neither pinged nor said (N1, N3)", AGENTS_D,
     "    fell = bool(episodes or stops)\n", "    fell = False\n"),
    ("M979", "every subagent followed, not only elrond's: #agents rewritten for any agent (N1, N3)", AGENTS_D,
     '        return (e.get("agent_type") or agent_of(e)[1].get("agentType")) in ELROND_AGENTS\n',
     "        return True\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_notify_discord.py" for n in range(970, 978)})
TESTS.update({f"M{n}": "tests/unit/test_agents_discord.py" for n in (978, 979)})

# N1 after its review (27/10, F1–F8): M990–M994, taken from this session's range (M970–M999).
MUTANTS += [
    ("M990", "the report not read from the hand-back: elrond's reviewers hand it back by a tool (N1 F1, N3)",
     AGENTS_D, 'str((e.get("tool_input") or {}).get("message") or ""), handback=True)\n',
     'str(e.get("last_assistant_message") or ""), handback=True)\n'),
    ("M991", "a fork's pull request posts in the lot its title names (N1, F5)", NOTIFY,
     "            lot = issue = \"\"   # a fork's pull request: #ci only, never a lot's thread (its title names any lot)\n",
     "            pass\n"),
    ("M992", "every closed issue creates a thread, a lot or not (N1, F5)", NOTIFY,
     "archive=True, create=bool(lot))]", "archive=True)]"),
    ("M993", "http.client's errors not caught: InvalidURL quotes the webhook's token (N1, F6)", NOTIFY,
     "        except Exception as e:  # URLError, http.client's errors: InvalidURL quotes the URL, token and all\n",
     "        except (OSError, ValueError) as e:\n"),
    ("M994", "a blocked lot without configuration writes the local state (N1, F7)", AGENTS_D,
     "    if not (cfg.agents or cfg.lots):   # nothing configured: nothing written, not even the local state\n"
     "        return 0\n", ""),
]
TESTS.update({f"M{n}": "tests/unit/test_notify_discord.py" for n in range(990, 995)})
TESTS.update({f"M{n}": "tests/unit/test_agents_discord.py" for n in (990, 994)})

# N3 (#262): #agents is what waits for Jonathan, scripts/agents_discord.py, measured by
# tests/unit/test_agents_discord.py against the fake Discord. Range M1060–M1069.
MUTANTS += [
    ("M1060", "a pause taken for a return: a reviewer waiting for its mutants said « sans verdict » (N3)", AGENTS_D,
     "    if e.get(\"background_tasks\"):\n        return   # a pause: it waits for its own background task, and comes back\n",
     ""),
    ("M1061", "a long report never attached: the thread holds its head, the findings lost (N3)", AGENTS_D,
     "    if len(report) > REPORT_HEAD:\n", "    if False:\n"),
    ("M1062", "elrond's resumes unseen: a correction sent by SendMessage neither on the board nor in the thread (N3)",
     AGENTS_D, '        return str(inp.get("to") or "") in state.get("agents", {}) or _elrond_session(e, state)\n',
     "        return False\n"),
    ("M1063", "a settled ping never deleted: #agents fills up again (N3)", AGENTS_D,
     '            nd.fetch("DELETE", f"{cfg.agents}/messages/{mid}", "webhook #agents")\n', "            pass\n"),
    ("M1064", "a fallback of an earlier stretch counted again: a clean correction said fallen back (N3)", AGENTS_D,
     '    episodes = [x for x in scan.get("fallback_episodes") or [] if x.get("to", "") >= _iso(since)]\n',
     '    episodes = list(scan.get("fallback_episodes") or [])\n'),
    ("M1065", "every question pings at once, even answered within seconds (N3)", AGENTS_D,
     '    state["waiting"].append({**item, "ping_at": item["since"] + delay})\n',
     '    state["waiting"].append({**item, "ping_at": item["since"]})\n'),
    ("M1066", "the board posted anew at each event: #agents a stream again (N3)", AGENTS_D,
     '    if mid:\n        try:\n            nd.fetch("PATCH"', '    if False:\n        try:\n            nd.fetch("PATCH"'),
    ("M1067", "a subagent's event settles the main session's permission: the ping gone, the run still stuck (N3)",
     AGENTS_D, '    if event in ("PreToolUse", "PostToolUse", "Stop") and not e.get("agent_id"):\n',
     '    if event in ("PreToolUse", "PostToolUse", "Stop"):\n'),
    ("M1068", "GitHub asked at every event whether a pull request was merged (N3)", AGENTS_D,
     '    if not items or (not force and now - state.get("prs_checked", 0) < PR_CHECK_S):\n',
     "    if not items:\n"),
    ("M1069", "the PreToolUse hook async: a hand-back may be queued after its SubagentStop (N3)",
     "scripts/elrond-hooks.sh", '            **({} if wait else {"async": True})}\n', '            "async": True}\n'),
]
TESTS.update({f"M{n}": "tests/unit/test_agents_discord.py" for n in range(1060, 1070)})

# N3 after its 5.5 review (28/10): M1070–M1073, from the same range (M1060–M1079).
MUTANTS += [
    ("M1070", "a forum that fails keeps what waits off the board: a review not obtained never pinged (N3)",
     AGENTS_D, '    except nd.Failure as f:\n        nd.say(f)\n        return ""\n    return f"https://discord.com',
     '    except KeyError:\n        return ""\n    return f"https://discord.com'),
    ("M1071", "a late SubagentStop of a past stretch ends a resumed agent: « sans verdict » again (N3)", AGENTS_D,
     '    if a.get("handback"):\n'
     "        return   # its returns come by SubagentHandback: a stop is a pause, or a late one of a past stretch\n",
     ""),
    ("M1072", "a lot blocked after its review fell back: two pings for one stop (N3)", AGENTS_D,
     '        settle(cfg, state, lambda w: w["key"] == f"not-obtained:{lot}")   # the same stop, one ping\n', ""),
    ("M1073", "no watcher: a pull request merged after the run keeps its ping (N3)", AGENTS_D,
     "        while time.time() < end and any(", "        while False and any("),
]
TESTS.update({f"M{n}": "tests/unit/test_agents_discord.py" for n in range(1070, 1074)})

# N3 after the Orchestre's 5.5 review (28/10): M1074–M1076.
MUTANTS += [
    ("M1074", "a ping whose deletion failed never tried again: it stays in #agents for good (N3)", AGENTS_D,
     '    for mid in state.pop("unping", []):   # a deletion that failed, tried again\n        _unping(cfg, state, mid)\n',
     ""),
    ("M1075", "a fallback of a reviewer's last turns, read after its hand-back, never said (N3)", AGENTS_D,
     '        if a.get("handback") and not a.get("fell"):\n', "        if False:\n"),
    ("M1076", "a deliverer with an empty queue rewrites the board: one PATCH per hook in a burst (N3)", AGENTS_D,
     "        if not (done or always):\n            return\n", ""),
]
TESTS.update({f"M{n}": "tests/unit/test_agents_discord.py" for n in range(1074, 1077)})

# N2 (#243): the road to 1.0 in Discord, scripts/roadmap_discord.py (and the thread matching it
# shares with notify_discord.py), measured by tests/unit/test_roadmap_discord.py. Range M980–M989.
ROADMAP_D = "scripts/roadmap_discord.py"
MUTANTS += [
    ("M980", "a closed issue gets a thread like an open one: the forum fills with finished lots (N2)", ROADMAP_D,
     "        if not lot.open:\n            if t and not", "        if False:\n            if t and not"),
    ("M981", "the sync overwrites elrond's states: a lot in review reads « à faire » (N2)", ROADMAP_D,
     '    if current in KEPT:   # elrond\'s, kept until GitHub says more\n'
     "        return current\n", ""),
    ("M982", "a closed lot's thread never archived (N2)", ROADMAP_D,
     '                write(f"{lot.key} archivé", "PATCH", f"/channels/{t[\'id\']}", {"archived": True})\n', ""),
    ("M983", "two issues of one lot id share a thread: I1F suite lands in the closed I1F's (N2)", NOTIFY,
     "and not (issue and other and other.group(1) != issue)", ""),
    ("M984", "the roadmap message never looked up: a new one at every run (N2)", ROADMAP_D,
     '    for where in ("pins", "messages?limit=50"):\n', "    for where in ():\n"),
    ("M985", "someone else's message with the same title taken for the bot's (N2)", ROADMAP_D,
     '            if str((m.get("author") or {}).get("id")) == me and title.startswith(TITLE):\n',
     "            if title.startswith(TITLE):\n"),
    ("M986", "a dry run writes to the forum (N2)", ROADMAP_D,
     "        if dry:\n            return {}\n", ""),
    ("M987", "a milestone's bar counts its open issues as done (N2)", ROADMAP_D,
     "        closed = sum(not x.open for x in mine)\n", "        closed = sum(x.open for x in mine)\n"),
    ("M988", "a ROADMAP.md without its criteria breaks the whole message (N2)", ROADMAP_D,
     '    out += ["", "**Pour la 1.0**"] + (crit if crit is not None else ["_section introuvable dans ROADMAP.md_"])\n',
     '    out += ["", "**Pour la 1.0**"] + crit\n'),
    ("M989", "a pull request counted as an issue of its milestone (N2)", ROADMAP_D,
     '        if "pull_request" in i or milestone not in nd.MILESTONE_TAGS:',
     "        if milestone not in nd.MILESTONE_TAGS:"),
]
TESTS.update({f"M{n}": "tests/unit/test_roadmap_discord.py" for n in range(980, 990)})

# N2 after its review (27/10): M995–M999, the end of this session's range (M970–M999).
MUTANTS += [
    ("M995", "the issues read on one page only: past the 100th, lots vanish from the roadmap (N2)", ROADMAP_D,
     "        if len(batch) < 100:\n            break\n", "        break\n"),
    ("M996", "a merged lot whose issue is still open falls back to « à faire » (N2)", ROADMAP_D,
     '    if current == "fait" and not lot.reopened:   # merged or reviewed ok, its issue open until « Fini quand »\n',
     '    if current == "fait" and lot.pr:\n'),
    ("M997", "the roadmap message posted again when its lookup failed: a second, stale one (N2)", ROADMAP_D,
     "    if not looked:   # neither list read: posting would leave a second message, stale from then on\n"
     '        raise nd.Failure("#roadmap", why="message not looked up (pins and messages failed): nothing posted")\n',
     ""),
    ("M998", "a follow-up issue (#70, #95, a finding) gets a thread like a lot (N2, Jonathan's decision)", ROADMAP_D,
     "        if not lot.thread:   # not a lot (#70, #95, a finding): no thread; one made before is archived\n",
     "        if False:\n"),
    ("M999", "every thread Discord archived for idleness reopened at each pass (N2)", ROADMAP_D,
     '        if change and (t.get("thread_metadata") or {}).get("archived"):\n',
     '        if (t.get("thread_metadata") or {}).get("archived"):\n'),
]
TESTS.update({f"M{n}": "tests/unit/test_roadmap_discord.py" for n in range(995, 1000)})

# N2 after its second review (27/10): M1000–M1004, given by the General session (H1: M1005–M1019).
MUTANTS += [
    ("M1000", "the roadmap creates threads on issue and PR events too: with notify.yml, two threads for one lot (N2)",
     ROADMAP_D, "            if not create:\n                continue\n", ""),
    ("M1001", "an issue number matched anywhere in a name: a lot's title quoting #70 taken for #70's thread (N2)",
     NOTIFY, '            if re.search(rf"^#{issue} · |· #{issue}$", t.get("name", "")):',
     '            if re.search(rf"#{issue}\\b", t.get("name", "")):'),
]
TESTS.update({f"M{n}": "tests/unit/test_roadmap_discord.py" for n in (1000, 1001)})

# H1 (#244): the CD of H0 — infra/glorfindel-host/cd/eregion_cd.py and deploy.sh's new modes,
# measured by tests/unit/test_host_cd.py (an agent installed as on H0, real git, a fake docker,
# a fake GitHub and Discord). Range M1005–M1019, given by the General session.
CD = "infra/glorfindel-host/cd/eregion_cd.py"
DEPLOY = "infra/glorfindel-host/deploy.sh"
MUTANTS += [
    ("M1005", "a release whose tag is off main deployed (H1)", CD,
     '    if not is_ancestor(commit, "refs/remotes/origin/main"):', "    if False:"),
    ("M1006", "a release with a red CI deployed (H1)", CD, "    if red:\n", "    if False:\n"),
    ("M1007", "a release deployed while its CI still runs (H1)", CD,
     '    if not runs or any(r.get("status") != "completed" for r in runs):', "    if False:"),
    ("M1008", "a release older than what runs deployed over it (H1)", CD,
     "    if dep_commit and is_ancestor(commit, dep_commit):", "    if False:"),
    ("M1009", "a new lock deployed without the harness: the guard never runs (H1)", CD,
     '    if dep_commit and git("diff", "--quiet", dep_commit, commit, "--", LOCK, check=False).returncode == 0:\n'
     "        return\n", "    return\n"),
    # M1010–M1012 follow the attestation of H3 (#324): two passes, judged case by case.
    ("M1010", "an attestation for another lock accepted (H1, H3)", CD,
     '    if cand.get("lock_sha256") != hashlib.sha256(shown.stdout.encode()).hexdigest():', "    if False:"),
    ("M1011", "an attestation for another model accepted: H0's own is never checked (H1, H3)", CD,
     '    entry = next((m for m in side.get("models") or [] if m.get("model") == model), None)',
     '    entry = next(iter(side.get("models") or []), None)'),
    ("M1012", "a case gaining 2 overconfident draws over the reference accepted: the gate no longer stops them (H1, H3)",
     CD, "    if gained:\n", "    if False:\n"),
    ("M1013", "H0's config refused by A3 and the release switched to anyway: the watch exits 2 (H1)", CD,
     '        if res.returncode != 0:\n            raise Refused("préflight : la config de H0',
     '        if False:\n            raise Refused("préflight : la config de H0'),
    ("M1014", "the candidate built as the running image: a refused release replaces it anyway (H1)", DEPLOY,
     '    build "${pair% *}" "${pair#* }" "" "$name"\n',
     '    build "${pair% *}" "${pair#* }" latest "$name"\n'),
    ("M1015", "an unhealthy release left running: no rollback (H1)", CD,
     "    back = rollback(dep_ref)\n", '    back = ""\n'),
    ("M1016", "a refused or rolled-back release tried again at every pass (H1)", CD,
     '    if not check and done in ("refused", "rolled back", "rollback failed"):', "    if False:"),
    ("M1017", "two passes at once, or one during a deployment by hand: no lock (H1)", CD,
     "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n", "            pass\n"),
    ("M1018", "a release with another agent never said: H0 keeps an old CD in silence (H1)", CD,
     "        drift, note, lost = agent_drift(tag)\n", '        drift, note, lost = [], "", False\n'),
    ("M1019", "a heartbeat from before the switch taken for health (H1)", CD,
     "        if HEARTBEAT.stat().st_mtime < since:", "        if False:"),
]
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1005, 1020)})
MUTANTS += [
    ("M1002", "the image of before H1 never tagged by its reference: the first rollback has nothing to retag (H1)",
     CD, "        keep_the_way_back(dep_ref, dry=check)\n", ""),
]
TESTS["M1002"] = "tests/unit/test_host_cd.py"
# H1 after its review (28/10): the image to go back to outlives the switch (finding 1).
MUTANTS += [
    ("M1003", "--activate prunes before the health: two refused candidates, and the image to go back to is gone (H1, review 1)",
     DEPLOY, '    start\n    echo "✓ activé', '    start\n    prune "${pair% *}"\n    echo "✓ activé'),
    ("M1004", "a switch without an image to go back to: the rollback has nothing to retag (H1, review 1)", CD,
     "    raise Refused(f\"pas d'image {IMAGE}:{ref} pour revenir en arrière : rien n'a basculé\")\n", ""),
]
TESTS.update({"M1003": "tests/unit/test_host_cd.py", "M1004": "tests/unit/test_host_cd.py"})
# H1 after its second review (28/10): two guards of a deployment on the host. M1050–M1059 given
# by the General session; M1057–M1059 stay free.
MUTANTS += [
    ("M1050", "a switch cut by a reboot never taken up: a sick release stays, unsaid (H1, second review)", CD,
     "        if cut:\n", "        if False:\n"),
    ("M1051", "a moved tag followed: H0 deploys a commit Jonathan never published (H1, second review)", CD,
     "    if seen.get(tag, commit) != commit:\n", "    if False:\n"),
]
TESTS.update({"M1050": "tests/unit/test_host_cd.py", "M1051": "tests/unit/test_host_cd.py"})
MUTANTS += [
    ("M1052", "a switch interrupted again and again tried forever, never said (H1, third review)", CD,
     "        twice = counts[tag] >= 2\n", "        twice = False\n"),
]
TESTS["M1052"] = "tests/unit/test_host_cd.py"
# « Agent de CD à mettre à jour » only for a release newer than the agent (28/10, after v0.4.1).
MUTANTS += [
    ("M1053", "an older release asks to reinstall the agent from it: deploy.sh without --activate breaks the CD",
     CD, "    if installed == release or not is_ancestor(installed, release):\n", "    if False:\n"),
    ("M1054", "the installation never notes its commit: no release can tell it is newer than the agent", "Makefile",
     "'umask 077 && cat > .eregion-cd/discord.env' && \\\n\t git rev-parse HEAD | $(HOST_SSH) 'cat > .eregion-cd/installed-from'\n",
     "'umask 077 && cat > .eregion-cd/discord.env'\n"),
]
TESTS.update({"M1053": "tests/unit/test_host_cd.py", "M1054": "tests/unit/test_host_cd.py"})
# After its review: the same files say nothing; installed-from is a commit id, never a name.
MUTANTS += [
    ("M1055", "the agent's files compared to nothing: a newer release always asks to reinstall it", CD,
     "        if theirs.returncode == 0 and theirs.stdout != ours:\n", "        if theirs.returncode == 0:\n"),
    ("M1056", "installed-from read as any ref: « HEAD » makes every release look newer than the agent", CD,
     '    if not re.fullmatch(r"[0-9a-f]{40}", installed) or git(', "    if not installed or git("),
]
TESTS.update({"M1055": "tests/unit/test_host_cd.py", "M1056": "tests/unit/test_host_cd.py"})

# SEC1 (#272) — the console's boundary: a token always (drawn at the first start, mode 600), the
# Host a loopback name or a listed one, a change from this origin only (the live feed included),
# a JSON object, a cookie that is a session, the headers; Config masked, a name encoded in a
# path, a restore that is its card's. Range M1170–M1189.
MUTANTS += [
    ("M1170", "any Host is served (SEC1)", CON,
     "        if not _allowed_host(host):\n", "        if False:\n"),
    ("M1171", "a Host that merely contains a loopback name is served (SEC1)", CON,
     "    return name in _LOOPBACK_HOSTS or name in extra - {None}\n",
     "    return any(n in name for n in _LOOPBACK_HOSTS) or name in extra - {None}\n"),
    ("M1172", "a change from another origin is executed (SEC1)", CON,
     "        if changes and origin is not None and not _same_origin(origin, host):\n",
     "        if False:\n"),
    ("M1173", "the live feed is not a change: it opens for another origin (SEC1)", CON,
     '        changes = ws or scope.get("method", "GET") in _CHANGES\n',
     '        changes = scope.get("method", "GET") in _CHANGES\n'),
    ("M1174", "the origin's port is ignored (SEC1)", CON,
     '    return origin in (f"http://{host}", f"https://{host}")\n',
     '    return origin.split("://")[-1].split(":")[0] == host.split(":")[0]\n'),
    ("M1175", "a browser's change without its Origin is executed (SEC1)", CON,
     "        if changes and not by_bearer and origin is None:\n", "        if False:\n"),
    ("M1176", "no token at all: the console answers everyone (SEC1)", CON,
     "            await _refuse(scope, receive, send, 503,\n",
     "            await self.app(scope, receive, send)\n            return\n"
     "            await _refuse(scope, receive, send, 503,\n"),
    ("M1177", "the first start draws no token (SEC1)", CON,
     "    token = secrets.token_urlsafe(32)\n", '    token = ""\n'),
    ("M1178", "the drawn token is written readable by all (SEC1)", CON,
     ('os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)\n',
      '    os.chmod(path, 0o600)\n    _local_token["value"] = token\n'),
     ('os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)\n',
      '    _local_token["value"] = token\n')),
    ("M1179", "the cookie carries the token itself (SEC1)", CON,
     "                resp.set_cookie(cookie, _session(token), httponly=True,",
     "                resp.set_cookie(cookie, token, httponly=True,"),
    ("M1180", "the token as a cookie opens the console (SEC1)", CON,
     "        by_cookie = _ok(conn.cookies.get(cookie), _session(token))\n",
     "        by_cookie = _ok(conn.cookies.get(cookie), _session(token)) or _ok(conn.cookies.get(cookie), token)\n"),
    ("M1181", "the cookie is never Secure, HTTPS included (SEC1)", CON,
     '                                secure=scope.get("scheme") == "https")\n',
     "                                secure=False)\n"),
    ("M1182", "a change of another type than JSON is executed (SEC1)", CON,
     '    if media != "application/json":\n', "    if False:\n"),
    ("M1183", "a change without a body is executed (SEC1)", CON,
     "    if not isinstance(parsed, dict):\n", "    if body and not isinstance(parsed, dict):\n"),
    ("M1184", "no nosniff, and the console's addresses leave in a Referer (SEC1)", CON,
     '_HEADERS = {"Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff",\n'
     '            "Referrer-Policy": "no-referrer"}\n',
     '_HEADERS = {"Content-Security-Policy": _CSP}\n'),
    ("M1185", "the CSP without default-src: images, fonts and styles from anywhere (SEC1)", CON,
     """_CSP = ("default-src 'self'; script-src 'self'; style-src""", """_CSP = ("script-src 'self'; style-src"""),
    ("M1186", "the API's schema is served (SEC1)", CON,
     'app = FastAPI(title="Eregion console", openapi_url=None, docs_url=None, redoc_url=None)\n',
     'app = FastAPI(title="Eregion console")\n'),
    ("M1187", "Config sends the whole subscription id (SEC1)", CON,
     '            "subscription_id": _mask(subscription),\n', '            "subscription_id": subscription,\n'),
    ("M1188", "the restore route takes an anchored card (SEC1)", CON,
     '    if esc.get("escalation_type") in _ANCHORED_TYPES:\n', "    if False:\n"),
    ("M1189", "a VM name raw in a route's path: a ? or # in it changes the route (SEC1)", GJS,
     "    const r = await _post(`/api/action/release/${_seg(vmName)}`);",
     "    const r = await _post(`/api/action/release/${vmName}`);"),
]
TESTS.update({f"M{n}": "tests/unit/test_console.py" for n in range(1170, 1190)})

# SEC1's relecture (5.5): the read-only guard reads the action a button names (#257); one cookie
# per console; the token file never through a link; the URL flushed to a container's log.
# Range M1300–M1309.
MUTANTS += [
    ("M1300", "the read-only guard reads `onclick`, gone since #257: no button that writes is disabled (SEC1)", GJS,
     "    const action = b.getAttribute('data-on-click') || '';\n",
     "    const action = b.getAttribute('onclick') || '';\n"),
    ("M1301", "the read-only guard leaves a modal's own write buttons enabled (SEC1)", GJS,
     "  'approveActionAndClose', 'approveScoped', 'snapshotAndClose',\n", ""),
    ("M1302", "one cookie name for every console of a host: two consoles overwrite each other's (SEC1)", CON,
     "    return f\"{_TOKEN_COOKIE}_{port or (443 if scheme in ('https', 'wss') else 80)}\"\n",
     "    return _TOKEN_COOKIE\n"),
    ("M1303", "the token file is read through a symbolic link (SEC1)", CON,
     '        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))\n',
     "        fd = os.open(path, os.O_RDONLY)\n"),
    ("M1304", "the URL stays in a buffer: a container's log never shows it (SEC1)", CON,
     '        print(f"  Eregion console  →  http://localhost:{port}/?token=${TOKEN_ENV}", flush=True)\n',
     '        print(f"  Eregion console  →  http://localhost:{port}/?token=${TOKEN_ENV}")\n'),
    ("M1305", "make console-url never reads the file the console drew (SEC1)", "Makefile",
     '\t   [ -s "$$f" ] && t=$$(head -n 1 "$$f"); fi; \\\n', "\t   true; fi; \\\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_console.py" for n in range(1300, 1306)})


# SEC2 — the detection rules against log lines anyone can write; the addresses never blocked;
# one card per address; a proposed rule never in a shipped rule's place; the floor interval,
# ${VAR} in documented fields only; a cap per rule and poll for every source. Measured by
# tests/unit/test_forged_logs.py (the shipped rules run as written, tests/unit/kql_subset.py).
RULES_YAML = "glorfindel/rules/azure/detection_rules.yaml"
POL = "glorfindel/response/policy.py"
DRU = "glorfindel/detection_rules.py"
PRU = "glorfindel/proposed_rules.py"
MUTANTS += [
    ("M1190", "ssh-brute-force reads every program's lines, not sshd's (SEC2)", RULES_YAML,
     '      | where ProcessName in ("sshd", "sshd-session")\n', ""),
    ("M1191", "ssh-brute-force takes the first address of the line (SEC2)", RULES_YAML,
     r'extract(@"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+( ssh2)?( \[preauth\])?\]?\s*$", 1, SyslogMessage)',
     r'extract(@"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)'),
    ("M1192", "ssh-brute-force's address not anchored at the end of sshd's line (SEC2)", RULES_YAML,
     r'port \d+( ssh2)?( \[preauth\])?\]?\s*$", 1, SyslogMessage)', r'port \d+( ssh2)?( \[preauth\])?\]?", 1, SyslogMessage)'),
    ("M1193", "ssh-brute-force blind to sshd-session (OpenSSH 9.8+) (SEC2)", RULES_YAML,
     '      | where ProcessName in ("sshd", "sshd-session")\n', '      | where ProcessName == "sshd"\n'),
    ("M1194", "sudo-privilege-escalation reads every program's lines, not sudo's (SEC2)", RULES_YAML,
     '      | where ProcessName == "sudo"\n', ""),
    ("M1195", "sudo-privilege-escalation takes any sudo line holding its words, not sudo's form (SEC2)", RULES_YAML,
     r'      | where SyslogMessage matches regex @"^\s*\S+ : (TTY|PWD)=(.*[ ;])?USER=root[ ;]+(.*[ ;])?COMMAND="' + "\n", ""),
    ("M1196", "the platform and private addresses blockable: nothing shipped in never_block (SEC2)", POL,
     '    "168.63.129.16/32", "169.254.169.254/32",\n'
     '    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",\n'
     '    "127.0.0.0/8", "::1/128",\n', ""),
    ("M1197", "glorfindel-config.yaml's never_block never read (SEC2)", POL,
     "    return list(NEVER_BLOCK_SHIPPED) + list(load_glorfindel_config().never_block)",
     "    return list(NEVER_BLOCK_SHIPPED)"),
    ("M1198", "an unreadable never_block list blocks anyway (SEC2)", POL,
     "    except Exception as exc:\n        raise ProtectedAddressError(\n            f\"blocage de {addr} refusé : liste never_block illisible \"",
     "    except Exception as exc:\n        return addr\n        raise ProtectedAddressError(\n"
     "            f\"blocage de {addr} refusé : liste never_block illisible \""),
    ("M1199", "the Azure connector blocks a never-block address (SEC2)", "glorfindel/providers/azure/blocks.py",
     "        blockable_ip(ip)\n\n        self._guard_write(\"block_suspicious_ip\")", "        pass\n\n        self._guard_write(\"block_suspicious_ip\")"),
    ("M1200", "the AWS connector blocks a never-block address (SEC2)", "glorfindel/providers/aws/blocks.py",
     "        blockable_ip(ip)            # a never-block address, never (SEC2)\n", ""),
    ("M1201", "decide lets a block of a never-block address run: the guard never called (SEC2)", "glorfindel/agent.py",
     "    _apply_never_block_guard(d, signal)\n", ""),
    ("M1202", "a never-block address held by another gate first: the card never says it (SEC2)", "glorfindel/agent.py",
     "    if not held:\n        return\n    before = d.get(\"escalation_reason\")",
     "    if not held or d[\"escalate\"]:\n        return\n    before = d.get(\"escalation_reason\")"),
    ("M1203", "two addresses on one VM folded into one card: its approval blocks the first (SEC2)", "glorfindel/escalations.py",
     "                and (e.get(\"action_params\") or {}).get(\"ip\") == (action_params or {}).get(\"ip\")\n", ""),
    ("M1204", "a proposal keeps a shipped rule's name: approved, it replaces the shipped rule (SEC2)", PRU,
     "    name = own_name(rule_name)\n    proposal = {", "    name = rule_name\n    proposal = {"),
    ("M1205", "a proposal recorded under a shipped rule's name approved under it (SEC2)", PRU,
     "    name = own_name(proposal[\"rule_name\"])\n    if name != proposal[\"rule_name\"]:",
     "    name = proposal[\"rule_name\"]\n    if name != proposal[\"rule_name\"]:"),
    ("M1206", "a client rule in a shipped rule's place never flagged: only a note (SEC2)", DRU,
     "        replaces_base = layer_of.get(item[\"name\"]) == \"client\" and item[\"name\"] in base_names\n",
     "        replaces_base = False\n"),
    ("M1207", "a rule polling every second polled every second: no floor at load (SEC2)", DRU,
     "        if not (math.isfinite(interval_s) and interval_s >= MIN_INTERVAL_S):",
     "        if not (math.isfinite(interval_s) and interval_s > 0):"),
    ("M1208", "${VAR} expanded in a rule's whole text again: a query reads the environment (SEC2)", DRU,
     "    data = yaml.safe_load(path.read_text())\n    if data is not None and not isinstance(data, dict) and notes is not None:",
     "    import os\n    data = yaml.safe_load(os.path.expandvars(path.read_text()))\n"
     "    if data is not None and not isinstance(data, dict) and notes is not None:"),
    ("M1209", "no cap of cards per rule and poll on a data source: one model call per row (SEC2)", DRU,
     "                rest = send[data_budget:]\n                send = send[:data_budget]\n", "                rest = []\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_forged_logs.py" for n in range(1190, 1210)})
# SEC2, after the 5.5 review.
MUTANTS += [
    ("M1310", "a client rule under the floor refused: a rule approved at 15 s drops out of detection (SEC2)", DRU,
     '            if field_ == "interval_s" and not (math.isfinite(number) and number > 0):',
     '            if field_ == "interval_s" and not (math.isfinite(number) and number >= MIN_INTERVAL_S):'),
    ("M1311", "the investigation looks for sudo in the message: no root command found (SEC2)", "glorfindel/agent.py",
     '| where ProcessName == "sudo"\n| where SyslogMessage has "USER=root" and SyslogMessage has "COMMAND="\n',
     '| where SyslogMessage has "sudo" and SyslogMessage has "USER=root" and SyslogMessage has "COMMAND="\n'),
    ("M1312", "the investigation reads any program's successful logins (SEC2)", "glorfindel/agent.py",
     '| where ProcessName in ("sshd", "sshd-session")\n// sshd\'s own wording',
     '// sshd\'s own wording'),
    ("M1313", "an IPv4 written as IPv6 escapes never_block (SEC2)", POL,
     "    if addr.version == 6 and addr.ipv4_mapped is not None:\n        addr = addr.ipv4_mapped\n", ""),
    ("M1314", "carrier NAT and IPv6 unique local blockable (SEC2)", POL,
     '"192.168.0.0/16", "100.64.0.0/10", "fc00::/7",', '"192.168.0.0/16",'),
    ("M1315", "a failed sudo in sudo's form counted as an escalation (SEC2)", RULES_YAML,
     r'@"^\s*\S+ : (TTY|PWD)=(.*[ ;])?USER=root[ ;]+(.*[ ;])?COMMAND="', r'@"^\s*\S+ : (.*[ ;])?USER=root[ ;]+(.*[ ;])?COMMAND="'),
    ("M1316", "a summary card carries every row, unbounded (SEC2)", DRU,
     "        for r in rest[:_SUMMARY_ROWS_MAX]]}", "        for r in rest]}"),
    ("M1317", "a summary card never says how many rows it stands for (SEC2)", DRU,
     '    return {**rest[0], "OmittedCount": len(rest), "OmittedRows": [',
     '    return {**rest[0], "OmittedRows": ['),
    ("M1318", "a shipped rule turned off by the client's layer never flagged (SEC2)", DRU,
     "    disabled_base = sorted(base_on - loaded) if client_file else []\n", "    disabled_base = []\n"),
    ("M1319", "`glorfindel rules` silent on a shipped rule turned off (SEC2)", "glorfindel/cli.py",
     "    for name in cfg.disabled_base:\n", "    for name in []:\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_forged_logs.py" for n in range(1310, 1320)})
# SEC2, after the measure on H0's Syslog (7 days).
MUTANTS += [
    ("M1320", "sudo-privilege-escalation reads auth only: real sudo logs to authpriv (SEC2)", RULES_YAML,
     '      | where Facility in ("auth", "authpriv")\n      | where TimeGenerated > ago(10m)\n      // Lines tagged sudo',
     '      | where Facility == "auth"\n      | where TimeGenerated > ago(10m)\n      // Lines tagged sudo'),
    ("M1321", "sudo-privilege-escalation takes « ; » only: the agent's form, with spaces, never matches (SEC2)",
     RULES_YAML, r'(TTY|PWD)=(.*[ ;])?USER=root[ ;]+(.*[ ;])?COMMAND="', r'(TTY|PWD)=(.*; )?USER=root ; (.*; )?COMMAND="'),
    ("M1322", "the investigation looks for sudo's lines in auth only (SEC2)", "glorfindel/agent.py",
     '| where Facility in ("auth", "authpriv")\n// sudo\'s own lines', '| where Facility == "auth"\n// sudo\'s own lines'),
    ("M1323", "ssh-brute-force loses a line written before authentication ([preauth]) (SEC2)", RULES_YAML,
     r'port \d+( ssh2)?( \[preauth\])?\]?\s*$"', r'port \d+( ssh2)?\]?\s*$"'),
    ("M1324", "the investigation takes a user name holding « Accepted » for a login (SEC2)", "glorfindel/agent.py",
     '| where SyslogMessage startswith "Accepted " and SyslogMessage has {ip}',
     '| where SyslogMessage has "Accepted" and SyslogMessage has {ip}'),
]
TESTS.update({f"M{n}": "tests/unit/test_forged_logs.py" for n in range(1320, 1325)})

# I3F (#287): a bare NIC our state holds in quarantine, its original unknown — verify_release
# never says released there (A0), and the release says the NIC is bare, not "in quarantine".
MUTANTS += [
    ("M1340", "verify_release reads a bare NIC held in quarantine, its original unknown, as released "
              "(I3F)", VER,
     '                held = original is _UNKNOWN and _held_in_quarantine(t0["nic_id"])\n',
     "                held = False\n"),
    ("M1341", "the release of a bare NIC whose original is unknown says it stays in quarantine (I3F)", REL,
     "                            if not bare:\n                                raise\n",
     "                            raise\n"),
    ("M1342", "the release's error on a bare NIC says the quarantine NSG wasn't detached (I3F)", REL,
     """                            what = ("carte sans NSG, NSG d'origine non remis" if bare\n""",
     """                            what = ("carte sans NSG, NSG d'origine non remis" if False\n"""),
]
# M1340 by the machine too: the oracle no longer exempts a bare NIC that a state held in
# quarantine with no original since the test last lost it (_held_unknown).
TESTS.update({"M1340": f"tests/unit/test_invariant_regressions.py {INVARIANTS}"})
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k said_bare" for n in (1341, 1342)})
# The escalations store's lock (SEC3) gives up within its timeout: the machine's scheduler
# tries it without blocking, so a race never leaves a thread blocked out of its sight (#292).
MUTANTS += [
    ("M1395", "the store's file lock ignores its timeout: a race's thread blocks in it out of the "
              "scheduler's sight (I3F, #292)", LCK,
     "    if not lock.acquire(timeout=-1 if timeout is None else timeout):\n"
     "        raise TimeoutError(f\"{path.name} busy (another write in progress)\")\n",
     "    if not lock.acquire():\n"
     "        raise TimeoutError(f\"{path.name} busy (another write in progress)\")\n"),
]
TESTS.update({"M1395": "tests/unit/test_invariant_regressions.py -k escalations_store"})
# U3F (#293): the unblock looks for the block on a NIC's own NSG when it is off the NIC — behind
# our quarantine, or the NIC left bare; never `not_found` on a NIC whose original is unknown.
_U3F = "tests/unit/test_invariant_regressions.py -k an_unblock"
MUTANTS += [
    ("M1343", "the unblock looks behind a quarantine only: a bare NIC's own NSG unread (U3F)", UNB,
     '        if not q and t0.get("own_nsg_id"):\n            return None', "        if not q:\n            return None"),
    ("M1344", "a bare NIC held in quarantine, its original unknown: nothing away, `not_found` (U3F)",
     UNB, "        if original is _UNKNOWN and _held_in_quarantine(nic_id):\n", "        if False:\n"),
    ("M1345", "a bare NIC's own NSG read from the state only: our tag ignored, the state lost (U3F)",
     UNB, "        if q_bare is not None:\n            return tagged\n", ""),
]
TESTS.update({"M1343": f"{_U3F} {INVARIANTS}", "M1344": _U3F, "M1345": _U3F})
# I4B: the search on every NSG (_unplaced_blocks) stands in for M1345's NIC when the subscription's NSGs
# can be listed — refused, it can't: measured there too.
TESTS["M1345"] = f"{_U3F} tests/unit/test_invariant_regressions.py::test_an_unblock_reads_a_bare_nics_tag_where_its_block_lies"
# U3F: a race that never comes back fails, its waiting threads unwound — the job no longer
# hangs; the jobs that run the invariants are bounded.
MUTANTS += [
    ("M1346", "a stuck race: the threads waiting for a turn stay there, their locks held (U3F)",
     INVARIANTS, "                self.abandoned = True\n", "                pass\n"),
    ("M1347", "the CI's Linux tests unbounded again (U3F)", ".github/workflows/ci.yml",
     "    timeout-minutes: 30\n", ""),
    ("M1348", "the nightly invariants unbounded again (U3F)", ".github/workflows/invariants.yml",
     "    timeout-minutes: 150\n", ""),
]
TESTS.update({"M1346": "tests/unit/test_invariant_regressions.py -k stuck_race",
              "M1347": "tests/unit/test_workflows.py -k bounded", "M1348": "tests/unit/test_workflows.py -k bounded"})
# U3F, after its review: a deadlock between driven locks fails as a livelock (each thread gave
# its turn away at every try, no turn ever timed out); a thread that never unwound doesn't hang
# the teardown; the Linux tests write their threads' stacks on a hang, as macOS.
MUTANTS += [
    ("M1349", "two driven locks taken crosswise: the race runs forever, no turn times out (U3F)",
     INVARIANTS, "                    if idle > self.idle_turns:\n", "                    if False:\n"),
    ("M1440", "a race thread that never unwound holds web's lock: the teardown waits behind it (U3F)",
     INVARIANTS, '            if getattr(self, "hung", None):\n', "            if False:\n"),
    ("M1441", "the CI's Linux tests hang without saying where (U3F)", ".github/workflows/ci.yml",
     "        run: python -m pytest tests/ -q -o faulthandler_timeout=480\n",
     "        run: python -m pytest tests/ -q\n"),
]
TESTS.update({"M1349": "tests/unit/test_invariant_regressions.py -k reverse_order",
              "M1440": "tests/unit/test_invariant_regressions.py -k out_of_sight_holding",
              "M1441": "tests/unit/test_workflows.py -k hang"})
# U3F, second review: a thread that never unwound holds objects of the process-wide lock
# registries — the next example (a replay while shrinking) waited behind them.
MUTANTS += [
    ("M1442", "a thread that never unwound keeps its locks for the next example: registries shared (U3F)",
     INVARIANTS, "            _fresh_lock_registries()\n", "            pass\n"),
]
TESTS.update({"M1442": "tests/unit/test_invariant_regressions.py -k out_of_sight_holding"})
# SEC6 (#277): the security process — the CI's actions and inputs, the lot threads against a fork
# or an outsider, text from outside made inert in the chats, the bench's apply confirmed.
NDS = "scripts/notify_discord.py"
CHT = "glorfindel/chat_text.py"
MUTANTS += [
    ("M1280", "the canary, which holds an Azure secret, takes checkout by its tag again (SEC6, P-04)",
     ".github/workflows/canary-azurerm.yml",
     "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09   # v5.1.0\n        if: steps.creds",
     "      - uses: actions/checkout@v5\n        if: steps.creds"),
    ("M1281", "a dispatcher's inputs pasted into the mutants' script again (SEC6, V-33)",
     ".github/workflows/mutants.yml",
     '--min-caught "$MIN_CAUGHT"', "--min-caught ${{ inputs.min_caught || '14' }}"),
    ("M1282", "a fork's red run posted in a lot's thread: the run's head never checked (SEC6, N-11)", NDS,
     "            if not own_run(run):\n                lot = issue = \"\"",
     "            if False:\n                lot = issue = \"\""),
    ("M1283", "an outsider's closed issue tags and archives a lot's thread (SEC6, N-11)", NDS,
     '        if it.get("author_association") not in MEMBERS:', "        if False:"),
    ("M1284", "a masked link from outside left as Markdown: brackets not escaped (SEC6, N-09)", CHT,
     '_INLINE = re.compile(r"([\\\\`*_~|\\[\\]()<>])")', '_INLINE = re.compile(r"([\\\\`*_~|<>])")'),
    ("M1285", "@everyone and @here from outside left whole (SEC6, N-09)", CHT,
     '    return _MENTION.sub("@" + ZWSP + r"\\1", text)', "    return text"),
    ("M1286", "the steps of a card raw in Discord: an Entra name's Markdown rendered (SEC6, N-09)",
     "glorfindel/bot.py", 'f"• {discord_text(s)}"', 'f"• {s}"'),
    ("M1287", "the webhook keeps <…>: Slack's links and mentions from outside (SEC6, N-09)", CHT,
     '    s = s.replace("<", "‹").replace(">", "›").replace("](", "]" + ZWSP + "(")',
     '    s = s.replace("](", "]" + ZWSP + "(")'),
    ("M1288", "the bot posts with Discord's default mentions: any text may ping (SEC6, N-09)", "glorfindel/bot.py",
     "super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())",
     "super().__init__(intents=intents)"),
    ("M1289", "make celebrimbor-up applies without confirmation, YES=1 or not (SEC6, P-10)", MAKE,
     "	   $(TF) apply$(if $(YES), -auto-approve); \\\n", "	   $(TF) apply --auto-approve; \\\n"),
]
TESTS.update({mid: "tests/unit/test_workflows.py" for mid in ("M1280", "M1281")})
TESTS.update({mid: "tests/unit/test_notify_discord.py" for mid in ("M1282", "M1283")})
TESTS.update({f"M{n}": "tests/unit/test_chat_escaping.py" for n in range(1284, 1289)})
TESTS["M1289"] = "tests/unit/test_makefile_bench.py -k yes"
# SEC6, after the 5.5 review.
_CANARY_AWK = """'$1=="pub"{n++;p=1;next} $1=="fpr"&&p{k=$10;p=0} END{exit !(n==1&&k==f)}'"""
_CANARY_CHECK = (
    '          if ! gpg --batch --show-keys --with-colons "$key" \\\n'
    f'               | awk -F: -v f="$HASHICORP_APT_FPR" {_CANARY_AWK}; then\n'
    '            echo "::error::HashiCorp\'s apt key is not the one primary key ${HASHICORP_APT_FPR} — Terraform not installed."\n'
    "            exit 1\n          fi\n")
MUTANTS += [
    ("M1350", "an input reaches run: inside format(): the check stopped at the first } (SEC6)",
     ".github/workflows/mutants.yml", '--examples "$EXAMPLES"', "--examples ${{ format('{0}', inputs.examples) }}"),
    ("M1351", "the canary trusts whatever key HashiCorp's URL serves: no fingerprint check (SEC6)",
     ".github/workflows/canary-azurerm.yml",
     _CANARY_CHECK, ""),
    ("M1352", "the ping's allowed mentions no longer independent of the client's own: fields left to defaults (SEC6)",
     "glorfindel/bot.py",
     "AllowedMentions(everyone=False, users=False, replied_user=False,\n"
     "                                                         roles=", "AllowedMentions(roles="),
    ("M1353", "the ping posted under the client's « none »: the on-call role never pinged (SEC6)", "glorfindel/bot.py",
     "                # Every field said: the message mentions its role alone, whatever the client's\n"
     "                # own allowed mentions (send merges the two).\n"
     "                allowed_mentions=discord.AllowedMentions(everyone=False, users=False, replied_user=False,\n"
     "                                                         roles=[discord.Object(id=self.ping_role)]),\n", ""),
    ("M1354", "an empty value between Glorfindel's backticks: two side by side, the next span let out (SEC6)",
     CHT, "    return f\"`{_no_mention(s) or '—'}`\"\n", "    return f\"`{_no_mention(s)}`\"\n"),
]
MUTANTS += [
    ("M1355", "the canary takes a subkey's fingerprint, or a second key, for HashiCorp's (SEC6, 2nd review)",
     ".github/workflows/canary-azurerm.yml", f'-v f="$HASHICORP_APT_FPR" {_CANARY_AWK}',
     """-v f="$HASHICORP_APT_FPR" '$1=="fpr"&&$10==f{ok=1} END{exit !ok}'"""),
]
TESTS["M1350"] = "tests/unit/test_workflows.py"
TESTS["M1355"] = "tests/unit/test_workflows.py -k fingerprint"
TESTS["M1351"] = "tests/unit/test_workflows.py -k fingerprint"
TESTS.update({f"M{n}": "tests/unit/test_chat_escaping.py" for n in (1352, 1353, 1354)})


# SEC5 (#276, V-35): the TUI's keys do what they say, on the cards the console allows.
MUTANTS += [
    ("M1266", "the TUI restores an anchored card (SEC5, V-35)", "glorfindel/tui.py",
     '    return esc.get("action") == "restore_from_backup" and not _anchored(esc)',
     '    return esc.get("action") == "restore_from_backup"'),
    ("M1279", "the TUI's unblock runs a full reset (SEC5, V-35)", "glorfindel/tui.py",
     '        return [["unblock", ip, rid, "--yes"] for ip in ips]', '        return [["reset", rid, "--yes"]]'),
]
TESTS.update({mid: "tests/unit/test_tui_actions.py" for mid in ("M1266", "M1279")})


# SEC5 (#276): the injectors and their channels — a refusal never reset, the catalog's word on
# what is destructive, the gate read again and bound to its perimeter, no development run in
# production, the windows bounded by their blob, the pulls bounded, a token for Azure Storage
# only, the writes per enrolled VM and the journal off the host, the TUI's keys.
_SEC5_GUARDS = "tests/unit/test_injector_guards.py"
_SEC5_CHANNELS = "tests/unit/test_injector_channels.py"
MUTANTS += [
    ("M1260", "a campaign resets a target the engine refused (SEC5, V-18)", CRUN,
     "            if outcome is not None and outcome.refused:\n", "            if False:\n"),
    ("M1261", "the channel's storage account open to every network again (SEC5, V-31)",
     "infra/orodruin/main.tf", '    default_action             = "Deny"',
     '    default_action             = "Allow"'),
    ("M1262", "the scenario's own destructive field believed before the catalog (SEC5, V-19)", ENG,
     '    own = scenario.raw.get("destructive")\n    destructive = said is not False or own is True\n',
     '    own = scenario.raw.get("destructive")\n'
     '    destructive = own if isinstance(own, bool) else said is not False\n'),
    ("M1263", "the catalog vouches for a technique whatever script the scenario runs (SEC5, V-19)",
     "annatar/campaign/catalog.py", "    elif scripts:\n", "    elif False:\n"),
    ("M1264", "the campaign's destructive policy reads the manifest's ttp, not its scenario (SEC5, V-19)",
     CRUN, "        return scenario_destructive(scenario)[0]",
     "        return catalog_destructive(entry.ttp) is not False"),
    ("M1265", "the watch read once per run: a watch that dies mid-run lets the next steps run (SEC5, N-03)",
     ENG, "            lost = self._watch_lost()\n            if lost:\n                return self._lost(run_id, lost)\n"
          "            self._execute_action(executor, step)\n",
     "            self._execute_action(executor, step)\n"),
    ("M1267", "annatar clean rewrites a disk without a live watch (SEC5, N-03)", "annatar/runner/initializer.py",
     "        if not without_glorfindel:\n            no_watch = watch_gate.refusal()\n            if no_watch:\n"
     '                raise RuntimeError(f"Refused — no live Glorfindel watch: {no_watch}")\n', ""),
    ("M1268", "a fresh heartbeat of any perimeter is a watch of this injector's targets (SEC5, N-03)",
     "eregion_core/watch_gate.py", '    return unbound(beat, READERS.get("own", perimeter)())', '    return ""'),
    ("M1269", "--without-glorfindel runs in zone production (SEC5, N-04)", ENG,
     '        if self.without_glorfindel and guard.zone == "production":', "        if False:"),
    ("M1270", "a run --without-glorfindel absent from Orodruin's journal (SEC5, N-04)", ENG,
     "            session.declare(WITHOUT_GLORFINDEL, watch_gate.NOT_MEASURED)\n", "            pass\n"),
    ("M1271", "the atomics' sha256 checked in CI only, not at run time (SEC5, V-30)", ATO,
     "    if hashlib.sha256(raw).hexdigest() != pinned:", "    if False:"),
    ("M1272", "a window dated back before its blob was created is believed (SEC5, V-20)", XW,
     "        if start < created - timedelta(seconds=FUTURE_SKEW_S):", "        if False:"),
    ("M1273", "a window marks a production VM whatever it ran there (SEC5, V-20)", XW,
     '    return window.get("kind") == "technique" and window.get("destructive") is False',
     "    return True"),
    ("M1274", "a blob read whole, then checked (SEC5, V-21)", XCH,
     "    if isinstance(r, requests.Response):\n        try:", "    if False:\n        try:"),
    ("M1275", "a listing of the channel without a bound on its names (SEC5, V-21)", XCH,
     "            if seen >= MAX_BLOBS:", "            if False:"),
    ("M1276", "the storage token sent to whatever URL the channel names (SEC5, N-15)", XCH,
     "    global _credential\n    check_url(url)\n", "    global _credential\n"),
    ("M1277", "Orodruin's journal stays on its host (SEC5, V-29)", "eregion_core/orodruin.py",
     "    url = channel if channel is not None else xc.channel_url()",
     '    url = ""'),
    ("M1278", "the contract accepts a write right on the whole bench group (SEC5, V-29, #182)",
     "eregion_core/orodruin.py",
     ('            if scope.lower().rstrip("/") == bench.lower().rstrip("/") and wide:',
      '    if wide and not any(m["code"] == "identity_group_wide" for m in missing):'),
     ("            if False:", "    if False:")),
]
TESTS.update({mid: _SEC5_GUARDS for mid in ("M1260", "M1262", "M1263", "M1264", "M1265", "M1267",
                                            "M1269", "M1270", "M1271")})
TESTS["M1268"] = f"{_SEC5_GUARDS} {_SEC5_CHANNELS}"
TESTS.update({mid: _SEC5_CHANNELS for mid in ("M1272", "M1273", "M1274", "M1275", "M1276", "M1277")})
TESTS["M1278"] = f"{_SEC5_CHANNELS} tests/unit/test_orodruin.py"
TESTS["M1261"] = "tests/unit/test_orodruin.py"
# SEC5, after the 5.5 review: a window rewritten after its pull, the chaos rights asked without
# an experiment, an engine that raised then reset, the channel without a retention.
MUTANTS += [
    ("M1450", "a campaign resets the target of an engine that raised (SEC5, V-18)", CRUN,
     '            if (entry.error or "").startswith(ENGINE_RAISED):\n', "            if False:\n"),
    ("M1451", "a window pulled again replaces its copy whatever changed (SEC5, V-20)", XCH,
     "                   else rewrite_refusal(old, new))\n", '                   else "")\n'),
    ("M1452", "the chaos rights asked with no experiment in the group: Orodruin passive for all (SEC5, V-29)",
     "eregion_core/orodruin.py",
     "        if not scopes and (experiments or action not in CHAOS_ACTIONS):", "        if not scopes:"),
    ("M1453", "the channel's blobs kept for ever: the listing's bound cuts the newest (SEC5, V-21)",
     "infra/orodruin/main.tf",
     "        delete_after_days_since_modification_greater_than = var.channel_retention_days",
     "        delete_after_days_since_modification_greater_than = 36500"),
    ("M1454", "a hosted watch declared without its subnet: the firewall cuts it off silently (SEC5, V-31)",
     "infra/orodruin/main.tf",
     '      condition     = var.watch_principal_id == "" || var.watch_subnet_id != ""',
     "      condition     = true"),
    ("M1455", "a named Celebrimbor's VMs never get Orodruin's rights: the tag fixed to celebrimbor (SEC5, V-29)",
     "infra/orodruin/main.tf", 'trimprefix(var.bench_resource_group, "rg-")', '"celebrimbor"'),
    ("M1456", "a passive Orodruin is not a refusal: the campaign resets the target (SEC5, V-18)", ENG,
     'error=f"passive: {verdict.reasons()}", refused=True)', 'error=f"passive: {verdict.reasons()}")'),
]
TESTS.update({"M1450": _SEC5_GUARDS, "M1456": _SEC5_GUARDS, "M1451": _SEC5_CHANNELS,
              "M1452": f"{_SEC5_CHANNELS} tests/unit/test_orodruin.py"})
TESTS.update({mid: "tests/unit/test_orodruin.py" for mid in ("M1453", "M1454", "M1455")})

# SEC4a (#275): the decision facing a model, a memory or a line it did not expect — the
# model's answer read for its type, a snapshot alone leaves a card, real cycles only for a
# real signal and no cycle overwriting another, the row of an attack_started naming its VM,
# its moment bounded. Measured by tests/unit/test_unexpected_decision.py. Ranges
# M1240–M1249, M1330–M1339, M1360–M1364.
SIG = "glorfindel/signal_origin.py"
MEM = "glorfindel/memory.py"
MUTANTS += [
    ("M1240", "an action that is not text raises: the cycle crashes on a list (SEC4a, V-23)", AGT,
     '    d["action"] = action.strip() if isinstance(action, str) else ""\n',
     '    d["action"] = (action or "").strip()\n'),
    ("M1241", "a boolean confidence read as 1.0: a JSON true passes the gate (SEC4a, V-23)", AGT,
     "        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float, str, type(None))):",
     "        if not isinstance(raw_conf, (int, float, str, type(None))):"),
    ("M1242", "the model's own keys kept: its held_by chooses the card's type (SEC4a, V-23)", AGT,
     "    d: dict = {}\n", "    d: dict = dict(raw)\n"),
    ("M1243", "steps that are not a list passed on: the card's construction raises (SEC4a, V-23)", AGT,
     "    if not isinstance(v, list):\n        return []\n    return [s if isinstance(s, str)",
     "    if not isinstance(v, list):\n        return v\n    return [s if isinstance(s, str)"),
    ("M1244", "a characterized detection a snapshot alone answers ends with no card (SEC4a, V-11)", AGT,
     "    uncontained = _uncontained_floor(d, signal)\n", '    uncontained = ""\n'),
    ("M1245", "the card of an uncontained detection never written (SEC4a, V-11)", AGT,
     "    _record_uncontained(state, source, exercise_run)\n", ""),
    ("M1246", "a signal given exercise cycles: the retrieval does not filter (SEC4a, V-12)", MEM,
     '            where={"source": "real"},\n', ""),
    ("M1247", "a cycle's id taken from its signal and upserted: a reused id overwrites a real cycle (SEC4a, V-12)",
     MEM, ('cycle_id = f"cycle-{uuid.uuid4().hex}"', "self._collection.add("),
     ("cycle_id = f\"{cycle['signal_id']}_{cycle['action']}\"", "self._collection.upsert(")),
    ("M1248", "a replayed cycle fills every place of the retrieval (SEC4a, V-12)", MEM,
     "            if key in seen:\n                continue\n", ""),
    ("M1249", "an attack_started's row naming no VM pinned to the line's VM, unheld (SEC4a)", AGT,
     "        if data_plane and names_vm(detected_row) is not True:\n", "        if False:\n"),
    ("M1330", "an attack_started's poll takes a row naming another VM (SEC4a)", AGT,
     "match_row=lambda row: names_vm(row) is not False)", "match_row=None)"),
    ("M1331", "the runs/ channel admits an attack_started of any moment (SEC4a)", SIG,
     '        why = attack_time_refusal(clean["raw_signal"]["attack_time"], now=now)\n', '        why = ""\n'),
    ("M1332", "resolve_attack_started searches from any moment (SEC4a)", AGT,
     '        refused = attack_time_refusal(raw.get("attack_time"))\n', '        refused = ""\n'),
    ("M1333", "an attack_time in the future admitted (SEC4a)", SIG,
     "    if t - now > ATTACK_TIME_FUTURE_S:\n", "    if False:\n"),
    ("M1334", "a row naming any known VM read as naming the line's (SEC4a)", AGT,
     "        return target is not None and bool(resource_id) and target[0].lower() == resource_id.lower()\n",
     "        return target is not None\n"),
    # The second pass (review 5.5, Jonathan's decisions): the RulePoller's reading, the
    # floor reading the state, the confidence's range.
    ("M1335", "two VMs with one host name: the row guessed onto one of them (SEC4a)", DRU,
     "            if len(hits) <= 1:\n                return True, next(iter(hits), None)\n",
     "            if hits:\n                return True, next(iter(hits), None)\n"),
    ("M1336", "an attack_started's row read without the private IPs: an exfiltration held (SEC4a)", AGT,
     "    index = RowAttribution(list(known.values()), lambda: owners)\n",
     "    index = RowAttribution(list(known.values()))\n"),
    ("M1337", "respond's poll never given the connector's private IPs (SEC4a)", AGT,
     '        s, ip_owners=getattr(connector, "private_ip_owners", None)))',
     "        s, ip_owners=None))"),
    ("M1338", "the floor ignores an isolation in place: « not isolated » on an isolated VM (SEC4a)", AGT,
     '        if iso is not None and not incomplete:\n            return True, ""\n', ""),
    ("M1339", "the floor ignores the source already blocked (SEC4a)", AGT,
     '    if ip and ip in blocked:\n        return True, ""\n', ""),
    ("M1360", "a partial isolation read as contained by the floor (SEC4a)", AGT,
     '    if iso.get("partial"):\n        return "isolation partielle"\n', ""),
    ("M1361", "a confidence above 1 read as sent (SEC4a)", AGT,
     "        if raw_conf is not None and not 0.0 <= confidence <= 1.0:\n",
     "        if raw_conf is not None and not 0.0 <= confidence:\n"),
    ("M1362", "a VM's sub-resource not brought back to the VM (SEC4a)", DRU,
     "            return True, self.by_rid.get(_vm_id_of(rid))\n",
     "            return True, self.by_rid.get(rid.lower())\n"),
    ("M1363", "a dotted host name never matches its VM (SEC4a)", DRU,
     '            hits = self.by_name.get(comp.split(".")[0].lower(), set())\n',
     "            hits = self.by_name.get(comp.lower(), set())\n"),
    ("M1364", "the address that made the call never read: an exfiltration names no VM (SEC4a)", DRU,
     "        owner = (self._owners() or {}).get(ip) if ip else None\n",
     "        owner = None\n"),
]
TESTS.update({mid: "tests/unit/test_unexpected_decision.py"
              for mid in [f"M{n}" for n in range(1240, 1250)] + [f"M{n}" for n in range(1330, 1340)]
              + [f"M{n}" for n in range(1360, 1365)]})
TESTS["M1361"] = "tests/unit/test_dependency_failures.py"

# SEC4b (#275): a local state that can't be read is an unknown for every reader that
# concludes from an absence, and the reassertion says it; a bypass by someone else's allow
# said once per change, never fixed (V-16); the proposed rules' store locked and rewritten
# whole. The invariant machine never makes a state unreadable: measured by
# tests/unit/test_unreadable_state.py, test_reassert.py, test_proposed_rules.py and
# test_locks.py. Ranges M1250–M1259, M1390–M1394.
RCA = "glorfindel/reassert_cards.py"
PRO = "glorfindel/proposed_rules.py"
MUTANTS += [
    ("M1250", "an unreadable state read as « not in quarantine »: verify_release says released (SEC4b)", STA,
     "    _raise_if_unreadable(f\"{nic_id.rstrip('/').rsplit('/', 1)[-1]} y est peut-être en quarantaine\")\n",
     ""),
    ("M1251", "an unreadable state read as « no original recorded »: our tag undoes it (SEC4b)", STA,
     "    _raise_if_unreadable(f\"le NSG d'origine de {nic_id.rstrip('/').rsplit('/', 1)[-1]} y est peut-être\")\n",
     ""),
    ("M1252", "the fixed names of an NSG nobody's while a state can't be read (SEC4b)", NET,
     "        if _unreadable_isolations():\n            return None", "        if False:\n            return None"),
    ("M1253", "a failed release writes over the unreadable state it could not read (SEC4b)", REL,
     "        if failed and _isolation_unreadable(resource_id):\n", "        if False:\n"),
    ("M1254", "the release's sweep reads a bare NIC as bare by design beside an unreadable state (SEC4b)", REL,
     "                    if q_bare is None:\n                        # Bare by design, or in our quarantine for a state that can't be\n"
     "                        # read: unknown, never released on a guess (SEC4b).\n"
     "                        _held_in_quarantine(t0[\"nic_id\"])\n", ""),
    ("M1255", "reset puts a bare NIC's original back from our tag beside an unreadable state (SEC4b)", SWP,
     "                failed_early.append(f'{t0[\"nic_short\"]}: carte sans NSG, {_first_line(exc)[:_ERR_MAX]}')\n"
     "                continue\n",
     "                recorded = _UNKNOWN\n"),
    ("M1256", "an unreadable state never said by the reassertion (SEC4b)", RCA,
     "    files = unreadable_states()\n", "    files = []\n"),
    ("M1257", "an unreadable state said again at every pass, its acknowledgement undone (SEC4b)", RCA,
     '    if alerts.get("unreadable_states") == sid and (said or _last_word(_STATE_PREFIX, sid)):\n',
     "    if False:\n"),
    ("M1258", "a bypassed isolation never said by the reassertion (SEC4b, V-16)", R,
     "    say_bypass(vm, rid, verification, report, ref=ref)\n", ""),
    ("M1259", "a bypass said again at every pass, its acknowledgement undone (SEC4b, V-16)", RCA,
     '    if mark == sid and not stale and (cards or _last_word(f"{prefix}-", sid)):\n        return',
     "    if False:\n        return"),
    ("M1390", "a bypassed block never said by the reassertion (SEC4b, V-16)", R,
     "    say_bypass(vm, rid, verification, report, ip=ip, ref=ref)\n", ""),
    ("M1391", "a bypass card closed on a precedence that could not be read (SEC4b, V-16)", RCA,
     "    if found is None:\n        return\n", "    if found is None:\n        found = []\n"),
    ("M1392", "a proposal recorded without the store's lock: one recorded meanwhile is lost (SEC4b)", PRO,
     "    with _locked():\n        _write(_lines() + [json.dumps(proposal)])", "    if True:\n        _write(_lines() + [json.dumps(proposal)])"),
    ("M1393", "approve and reject rewrite the store without its lock (SEC4b)", PRO,
     ("    with _locked():\n        return _approve(", "    with _locked():\n        lines = _lines()"),
     ("    if True:\n        return _approve(", "    if True:\n        lines = _lines()")),
    ("M1394", "a state of another shape read as readable: its placements read as « nothing » (SEC4b)", STA,
     "    return (isinstance(rid, str) and bool(rid.strip()) and isinstance(placements, list)\n"
     "            and all(isinstance(p, dict) for p in placements))\n", "    return True\n"),
]
# SEC4b's review (M1520–M1531): the isolation never stopped by an unreadable state, the
# unblock behind the quarantine says it, the VM's own file set aside, the console's tile,
# a state with placements and no resource id, the card's words.
JSG = "eregion_console/static/glorfindel.js"
MUTANTS += [
    ("M1520", "an unreadable state stops the isolation of a NIC without an NSG (SEC4b, review)", STA,
     "    try:\n        return _recorded_original(nic_id)\n    except StateUnreadable:\n        return _UNKNOWN\n",
     "    return _recorded_original(nic_id)\n"),
    ("M1521", "beside an unreadable state, a bare NIC recorded « none »: the release would leave it bare "
              "(SEC4b, review)", STA,
     "    try:\n        return _held_in_quarantine(nic_id)\n    except StateUnreadable:\n        return True\n",
     "    try:\n        return _held_in_quarantine(nic_id)\n    except StateUnreadable:\n        return False\n"),
    ("M1522", "an unreadable state escapes unblock_ip after its deletions (SEC4b, review)", UNB,
     # Since U3F the read is _original_away's, in the same try.
     "            try:\n                original = self._original_away(t0, rg)\n",
     "            original = self._original_away(t0, rg)\n            try:\n                pass\n"),
    ("M1523", "a new state written over the VM's unreadable one (SEC4b, review)", STA,
     "    if not _isolation_unreadable(vm_ref):\n        return\n    f = _state_file(", "    return\n    f = _state_file("),
    ("M1524", "the local state's card makes a VM tile, counted unprotected (SEC4b, review)", JSG,
     "    if (_isLocalState(e.resource_id)) return;\n", ""),
    ("M1525", "a state with placements and no resource id read as readable (SEC4b, review)", STA,
     "isinstance(rid, str) and bool(rid.strip()) and isinstance(placements, list)",
     "isinstance(placements, list)"),
    ("M1526", "the card says the release waits when only a block file is unreadable (SEC4b, review)", RCA,
     "                           if isolations else \"\") + \".\")", "                           if True else \"\") + \".\")"),
]
TESTS.update({mid: "tests/unit/test_unreadable_state.py" for mid in
              ("M1520", "M1521", "M1522", "M1523", "M1525", "M1526")})
TESTS["M1524"] = "tests/unit/test_console.py -k local_state"
# Second review: a file set aside is never a state again, an unknown original said at the
# isolation, the card's steps for a file set aside and for the tag a release will ask.
MUTANTS += [
    ("M1527", "a file set aside stays among the states: repaired, it is a second isolation (SEC4b, review 2)",
     STA, "    n, aside = 1, _ISOLATION_STATE_DIR / ASIDE_DIR / f.name\n",
     "    n, aside = 1, f.with_name(f\"{f.stem}.unreadable.json\")\n"),
    ("M1528", "a file set aside, repaired, leaves the unreadable list (SEC4b, review 2)", STA,
     '        out += [f"{_ISOLATION_STATE_DIR.name}/{ASIDE_DIR}/{f.name}" for f in aside.iterdir() if f.is_file()]\n',
     "        pass\n"),
    ("M1529", "an isolation whose original is unknown says nothing until its release (SEC4b, review 2)", ISO,
     "        unknown = original_unknown_nics(merged)\n", "        unknown = []\n"),
    ("M1530", "the card asks to repair a file set aside — repaired, it would not be read (SEC4b, review 2)", RCA,
     "    if aside:\n        # Set aside", "    if False:\n        # Set aside"),
    ("M1531", "the card does not say the tag the releases will ask for (SEC4b, review 2)", RCA,
     "    if isolations:\n        steps.append(", "    if False:\n        steps.append("),
]
TESTS.update({mid: "tests/unit/test_unreadable_state.py" for mid in ("M1527", "M1528", "M1529", "M1530", "M1531")})
TESTS.update({mid: "tests/unit/test_unreadable_state.py" for mid in
              ("M1250", "M1251", "M1252", "M1253", "M1254", "M1255", "M1394")})
TESTS.update({mid: "tests/unit/test_reassert.py tests/unit/test_unreadable_state.py" for mid in
              ("M1256", "M1257", "M1258", "M1259", "M1390", "M1391")})
TESTS.update({mid: "tests/unit/test_proposed_rules.py" for mid in ("M1392", "M1393")})

# H2 (#266) — the CD proves that Glorfindel detects: every loaded rule run once, read-only,
# after the switch (`glorfindel rules check --live`). Range M1120–M1139, given by the session.
RCK = "glorfindel/rule_check.py"
MUTANTS += [
    ("M1120", "a rule with no workspace resolved said ok: detection off, the check green (H2)", RCK,
     "    if not rule.enabled or not rule.workspace_id:\n", "    if False:\n"),
    ("M1121", "an approved rule on no backend said ok: P1's silent default back (H2)", RCK,
     "    if rule.auto_apply and not rule.monitoring_backend_name:\n", "    if False:\n"),
    ("M1122", "a static rule on no resource said ok: it applies to no VM (H2)", RCK,
     "    if not rule.auto_apply and not rule.resource_id:\n", "    if False:\n"),
    ("M1123", "a source no detector reads said ok (H2)", RCK,
     "    if detector_class(rule.source) is None:\n", "    if False:\n"),
    ("M1124", "zero rows taken for an error: a quiet rule rolls H0 back (H2)", RCK,
     "    base.rows = len(rows) if isinstance(rows, list) else 0\n",
     "    base.rows = len(rows) if isinstance(rows, list) else 0\n    base.status = OK if rows else ERROR\n"),
    ("M1125", "a query that failed taken for zero rows: an invalid KQL passes (H2)", RCK,
     '    if "exc" in box:\n', "    if False:\n"),
    ("M1126", "a query without an answer taken for zero rows (H2)", RCK,
     "    if t.is_alive():\n", "    if False:\n"),
    ("M1127", "each query sent twice: not once (H2)", RCK,
     "        out.append(run_once(rule, min(query_timeout_s, left), shared, clock))\n",
     "        run_once(rule, min(query_timeout_s, left), shared, clock)\n"
     "        out.append(run_once(rule, min(query_timeout_s, left), shared, clock))\n"),
    ("M1128", "the whole check unbounded: every rule sent past the total (H2)", RCK,
     "        if left <= 0:\n", "        if False:\n"),
    ("M1129", "the last query waited for its full time, past the total (H2)", RCK,
     "        out.append(run_once(rule, min(query_timeout_s, left), shared, clock))\n",
     "        out.append(run_once(rule, query_timeout_s, shared, clock))\n"),
    ("M1130", "an error not reduced: Azure's words, workspace and host, in the JSON #deploy says (H2)", RCK,
     "    return classify(exc), scrub(code_of(exc))[:40], scrub(line), full[:2000]\n",
     "    return classify(exc), scrub(code_of(exc))[:40], line, full[:2000]\n"),
    ("M1131", "A3's words (the config's values) in the JSON #deploy says (H2)", RCK,
     '        return [], [], "glorfindel-config.yaml refusé par la lecture stricte (A3)", str(exc)\n',
     '        return [], [], f"glorfindel-config.yaml refusé par la lecture stricte (A3) : {exc}", ""\n'),
    ("M1132", "timeouts only exit 0: nothing tells them from a proof (H2)", RCK,
     "        return EXIT_TIMEOUT\n", "        return EXIT_OK\n"),
    ("M1133", "--live ignored: the queries always sent (H2)", GCLI,
     "    ctx.exit(_check(target, live=live, as_json=as_json,", "    ctx.exit(_check(target, live=True, as_json=as_json,"),
    ("M1134", "the CD's health never runs the rules: a broken rule deployed in silence (H2)", CD,
     "        if rules and proof is None and not why:\n", "        if False:\n"),
    ("M1135", "a rule in error not red: H0 kept on a release that detects less (H2)", CD,
     "    hard = [r for r in rules if lasting(r)]\n", "    hard = []\n"),
    ("M1136", "a rule without an answer rolls H0 back: a slow workspace undoes a release (H2)", CD,
     '    return rule.get("status") == "error" and rule.get("kind") in DURABLE\n',
     '    return rule.get("status") != "ok"\n'),
    ("M1137", "what the candidate says of a rule posted unscrubbed: workspace, subscription, host in #deploy (H2)", CD,
     "    for pattern, mark in _SCRUB:\n        s = pattern.sub(mark, s)\n", ""),
    ("M1138", "a rule's name posted raw: a masked link, a mention in #deploy (H2, SEC6)", CD,
     "    return discord_text(s)\n", "    return s\n"),
    ("M1139", "the rules check outside the health's budget (H2)", CD,
     "    wait = max(1.0, min(RULES_S + RULES_MARGIN_S, budget_s))\n", "    wait = RULES_S + RULES_MARGIN_S\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_rules_check.py" for n in range(1120, 1134)})
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1134, 1140)})
# H2 after its review (29/10): only what lasts is an error, and only a regression rolls back
# (Jonathan's decision). Range M1500–M1519, given by the session.
MUTANTS += [
    ("M1500", "every failed query an error: a 429 or a 503 rolls a good release back (H2, review)", RCK,
     "        base.status = ERROR if base.kind in DURABLE else UNPROVEN\n", "        base.status = ERROR\n"),
    ("M1501", "the CD rolls back on any error, whatever its kind (H2, review)", CD,
     '    return rule.get("status") == "error" and rule.get("kind") in DURABLE\n',
     '    return rule.get("status") == "error"\n'),
    ("M1502", "an error of unknown kind taken to last (H2, review)", RCK,
     'DURABLE = frozenset({"backend", "syntax", "table", "access", "workspace"})\n',
     'DURABLE = frozenset({"backend", "syntax", "table", "access", "workspace", "other"})\n'),
    ("M1503", "a 5xx read as a workspace gone (H2, review)", RCK,
     "    if status == 404:\n", "    if status == 404 or (status or 0) >= 500:\n"),
    ("M1504", "a DNS failure (« Failed to resolve 'host' ») read as a table absent (H2, review)", RCK,
     "    if isinstance(exc, (OSError, TimeoutError)) or any(", "    if False and any("),
    ("M1505", "a partial result never named (H2, review)", RCK,
     '    if "not successful" in low:', "    if False:"),
    ("M1506", "a credential not available never named (H2, review)", RCK,
     '    if status == 401 or "credential" in name or "authentication" in name:\n', "    if status == 401:\n"),
    ("M1507", "a rule broken before as after rolls back: H0 never moves past a table it lacks (H2, review)", CD,
     '    broke = [r for r in hard if comparable and before.get(r["name"], {"status": "ok"})["status"] == "ok"]\n',
     "    broke = hard\n"),
    ("M1508", "a rule new in the release and broken taken for one broken before (H2, review)", CD,
     '    broke = [r for r in hard if comparable and before.get(r["name"], {"status": "ok"})["status"] == "ok"]\n',
     '    broke = [r for r in hard if comparable and before.get(r["name"], {"status": "absent"})["status"] == "ok"]\n'),
    ("M1509", "a reference without the command compared anyway: every broken rule a regression (H2, review)", CD,
     '    comparable = bool(base) and base.get("state") == "ok"\n', "    comparable = True\n"),
    ("M1510", "what ran never checked before the switch (H2, review)", CD,
     "    base = reference_check()           # what runs, before it moves: the rules it detects with\n",
     "    base = None\n"),
    ("M1511", "the last look of the health from before the check: a watch dead meanwhile kept (H2, review)", CD,
     "            continue        # the last look is never one from before the check\n", ""),
    ("M1512", "with --json, the full words lost: the CD's journal has nothing to read (H2, review)", RCK,
     '                echo_err(f"{o.name} [{o.status}/{o.kind}] : {o.detail}")\n', "                pass\n"),
    ("M1513", "the command's stderr never in the CD's journal (H2, review)", CD,
     '        print(f"glorfindel rules check ({label}, code {res.returncode}) :\\n{res.stderr.strip()[-4000:]}")\n',
     "        pass\n"),
    ("M1514", "every code 2 read as a release from before H2: an option refused, unsaid (H2, review)", CD,
     '            return {"state": "absent" if any(w in said for w in NO_COMMAND) else "usage", "code": code}\n',
     '            return {"state": "absent", "code": code}\n'),
    ("M1515", "EREGION_CD_RULES_S unbounded: the command refuses it, code 2 (H2, review)", CD,
     'RULES_S = bounded("EREGION_CD_RULES_S", 90, 1, 3600)\n', 'RULES_S = float(os.environ.get("EREGION_CD_RULES_S") or 90)\n'),
    ("M1516", "a host name is any dotted word: LogsQueryStatus.PARTIAL, a rule's name scrubbed (H2, review)", RCK,
     'rf"\\b(?:{_LABEL}\\.){{2,}}[a-z]{{2,}}\\b"', 'rf"\\b(?:{_LABEL}\\.)+[a-z]{{2,}}\\b"'),
    ("M1517", "a rule broken before as after said without the mention (H2, review)", CD,
     '"alert": bool(known)}\n', '"alert": False}\n'),
    ("M1518", "a check broken by the release, where what ran was checked, kept (H2, review)", CD,
     "        if comparable:      # what ran had its rules checked: this release broke the check itself\n",
     "        if False:\n"),
    ("M1519", "a 403 or a 404 taken to pass: access taken away, never said as lasting (H2, review)", RCK,
     "    if status == 403:\n        return \"access\"\n", ""),
]
TESTS.update({mid: "tests/unit/test_rules_check.py" for mid in ("M1500", "M1502", "M1503", "M1504", "M1505",
                                                                "M1506", "M1512", "M1516", "M1519")})
TESTS.update({mid: "tests/unit/test_host_cd.py" for mid in ("M1501", "M1507", "M1508", "M1509", "M1510",
                                                            "M1511", "M1513", "M1514", "M1515", "M1517", "M1518")})

# CI2 (#268): the advisories of the locks, one issue per advisory — the same advisory never two
# issues (an alias, a closed issue, a duplicate, several locks), one gone said once and never
# closed, a lock not read says nothing, the lock read as it is, make lock never failing on it.
# Measured by tests/unit/test_pip_audit_issues.py. Range M1150–M1159.
PAI = "scripts/pip_audit_issues.py"
MUTANTS += [
    ("M1150", "an issue found by the exact same identifiers only: an alias seen later opens a second one (CI2)",
     PAI, 'i.key["package"] == adv.package and i.key["ids"] & adv.ids]',
     'i.key["package"] == adv.package and i.key["ids"] == adv.ids]'),
    ("M1151", "the open issues only are read: a closed advisory's issue doubled (CI2)", PAI,
     '"repos/{owner}/{repo}/issues?state=all&per_page=100"', '"repos/{owner}/{repo}/issues?state=open&per_page=100"'),
    ("M1152", "an advisory listed twice by pip-audit never merged: two issues (CI2)", PAI,
     "                same = [a for a in out if a.package == package and a.ids & ids]\n",
     "                same = []\n"),
    ("M1153", "the same advisory in two locks is two advisories (CI2)", PAI,
     "                same = [a for a in out if a.package == package and a.ids & ids]\n",
     "                same = [a for a in out if a.package == package and a.ids & ids and lock in a.locks]\n"),
    ("M1154", "an advisory gone closes its issue: the workflow decides the bump was made (CI2)", PAI,
     '    gh("issue", "comment", str(issue.number), "--body-file", "-",\n'
     '       stdin="L\'avis n\'est plus trouvé dans "',
     '    gh("issue", "close", str(issue.number))\n'
     '    gh("issue", "comment", str(issue.number), "--body-file", "-",\n'
     '       stdin="L\'avis n\'est plus trouvé dans "'),
    ("M1155", "an advisory gone said every week: the issue's key never told (CI2)", PAI,
     'stdin=with_present(issue.body, False))', "stdin=issue.body)"),
    ("M1156", "a lock whose audit failed reads as clean: its advisories said gone (CI2)", PAI,
     '        if not issue.key["locks"] or not issue.key["locks"] <= audited:\n',
     '        if not issue.key["locks"]:\n'),
    ("M1157", "an issue never rewritten: a new lock, a fix, an alias never said (CI2)", PAI,
     "    if _same(issue.body) != _same(text):\n", "    if False:\n"),
    ("M1158", "pip-audit resolves the lock with pip instead of reading it (CI2, N-16)", PAI,
     '"--require-hashes", "--disable-pip",', '"--require-hashes",'),
    ("M1159", "make lock fails when its audit cannot run (CI2, N-16)", MAKE,
     "\t-@$(MAKE) --no-print-directory audit\n", "\t@$(MAKE) --no-print-directory audit\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_pip_audit_issues.py" for n in range(1150, 1160)})
# CI2, after the 5.5 review: who may hold a key (the workflow's issues only, every field of its
# shape), every page and no pull request read, a GitHub error stopping nothing else. M1490–M1497.
MUTANTS += [
    ("M1490", "anyone's issue read for a key: an outsider's silences an advisory (CI2, review)", PAI,
     '        if (it.get("user") or {}).get("login") != BOT:\n            continue\n', ""),
    ("M1491", "a key's identifiers read back unchecked: an outsider's text in the bot's issue (CI2, review)", PAI,
     '            and all(isinstance(i, str) and ID.match(i) for i in k["ids"])\n',
     '            and all(isinstance(i, str) for i in k["ids"])\n'),
    ("M1492", "the first page of issues only: an advisory's issue past it doubled (CI2, review)", PAI,
     'out = gh("api", "--paginate", "repos/', 'out = gh("api", "repos/'),
    ("M1493", "a pull request read as an issue: its key silences an advisory (CI2, review)", PAI,
     '        if not isinstance(it, dict) or it.get("pull_request"):\n',
     "        if not isinstance(it, dict):\n"),
    ("M1494", "one GitHub error on an advisory stops every other one (CI2, review)", PAI,
     "        try:\n            new = _one(adv, audited, issues, matched, done) or new\n"
     "        except (RuntimeError, OSError, subprocess.SubprocessError) as e:\n"
     '            errors.append(f"{adv.package} · {adv.primary} : {e}")\n',
     "        new = _one(adv, audited, issues, matched, done) or new\n"),
    ("M1495", "a key's locks read back unchecked: an outsider's text in a comment (CI2, review)", PAI,
     '            and all(isinstance(x, str) and LOCK.match(x) for x in k.get("locks", []))\n',
     '            and all(isinstance(x, str) for x in k.get("locks", []))\n'),
    ("M1496", "an issue closed as a duplicate reopened: a human's decision undone (CI2, review)", PAI,
     'if issue.reason in ("not_planned", "duplicate"):', 'if issue.reason in ("not_planned",):'),
    ("M1497", "one GitHub error on a gone issue stops the others (CI2, review)", PAI,
     "        try:\n            _gone(issue, done)\n"
     "        except (RuntimeError, OSError, subprocess.SubprocessError) as e:\n"
     '            errors.append(f"#{issue.number} : {e}")\n',
     "        _gone(issue, done)\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_pip_audit_issues.py" for n in range(1490, 1498)})

# CI1 (#267): the images built and proven in CI — scripts/image_check.py and its workflow,
# measured by tests/unit/test_image_check.py (a fake docker; the in-image code run here). M1140–M1149.
IMC = "scripts/image_check.py"
IMW = ".github/workflows/images.yml"
MUTANTS += [
    ("M1140", "the checks run with the network: a check reaching Azure or a registry goes unseen (CI1)", IMC,
     '    argv = ["docker", "run", "--rm", "--network", "none"]\n', '    argv = ["docker", "run", "--rm"]\n'),
    ("M1141", "a --version other than pyproject's passes: a broken entry point or metadata unseen (CI1)", IMC,
     "        if said != want:\n", "        if False:\n"),
    ("M1142", "the config loaded without being opened: an absent example passes as an empty config (CI1)", IMC,
     '               f"open({CONFIG_IN_IMAGE!r}).close(); load({CONFIG_IN_IMAGE!r})")\n',
     '               f"load({CONFIG_IN_IMAGE!r})")\n'),
    ("M1143", "the first failure stops the checks: the log hides what else is wrong (CI1)", IMC,
     "            ok = False\n        else:\n", "            return False\n        else:\n"),
    ("M1144", "the example config mounted read-write in the image (CI1)", IMC,
     '        argv += ["-v", f"{host}:{inside}:ro"]\n', '        argv += ["-v", f"{host}:{inside}"]\n'),
    ("M1145", "the absence check always passes: Glorfindel's code in the injectors' image unseen (D1, CI1)", IMC,
     '          "sys.exit(1 if found else 0)\\n")\n', '          "sys.exit(0)\\n")\n'),
    ("M1146", "the image pushed (CI1)", IMW, "          push: false\n", "          push: true\n"),
    ("M1147", "a pull request changing the lock builds no image (CI1)", IMC,
     '"scripts/**", "requirements/**",\n', '"scripts/**",\n'),
    ("M1148", "the console's import left out: the CI passes an image the CD's preflight refuses (CI1)", IMC,
     'GLORFINDEL_IMPORTS = "glorfindel.cli, glorfindel.bot, eregion_console.api"\n',
     'GLORFINDEL_IMPORTS = "glorfindel.cli, glorfindel.bot"\n'),
    ("M1149", "a failed check exits 0: the job green on a broken image (CI1)", IMC,
     "        return 0 if check_image(args.name, image, runner) else 1\n",
     "        check_image(args.name, image, runner)\n        return 0\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_image_check.py" for n in range(1140, 1150)})
# CI1 after its review (29/10): the checks frozen, the job unfiltered (it decides itself), the
# cache written by main only, #ci told of a red run. M1480–M1489.
MUTANTS += [
    ("M1480", "the injectors' absence check removed: Glorfindel's code in their image unseen (D1, CI1)", IMC,
     '        Check("ni Glorfindel, ni la console, ni leurs dépendances (D1)",\n'
     '              ("python", "-c", ABSENT, *NOT_IN_INJECTORS)),\n', ""),
    ("M1481", "the injectors' image no longer checked for root (CI1)", IMC,
     '        Check(LITELLM_CHECK, ("python", "-c", LITELLM_CALL)),\n        Check("pas root", ("python", "-c", NOT_ROOT)),\n'
     '    )),\n}\n',
     '        Check(LITELLM_CHECK, ("python", "-c", LITELLM_CALL)),\n    )),\n}\n'),
    ("M1482", "Annatar and Gothmog no longer imported in their image (CI1)", IMC,
     '        Check("Annatar et Gothmog importent", ("python", "-c", f"import {INJECTOR_IMPORTS}")),\n', ""),
    ("M1483", "an unreadable diff skips the build: the job green on what it never built (CI1)", IMC,
     '        return True, "le diff de la PR est illisible : construit"\n',
     '        return False, "le diff de la PR est illisible : construit"\n'),
    ("M1484", "a push to main skips by the diff: main's commits and the release's unchecked (CI1)", IMC,
     '    if event != "pull_request":\n        return True, f"{event', '    if event == "push_never":\n        return True, f"{event'),
    ("M1485", "a `dir/**` takes a sibling's name: glorfindelx/ builds, never what it means (CI1)", IMC,
     "            if path == p[:-3] or path.startswith(p[:-2]):\n",
     "            if path.startswith(p[:-3]):\n"),
    ("M1486", "Images left out of notify.yml: its red run unseen in #ci (CI1)", ".github/workflows/notify.yml",
     "    workflows: [CI, Components, Images, ", "    workflows: [CI, Components, "),
    ("M1487", "the cache written by pull requests too: one can evict main's (CI1)", IMW,
     "          cache-to: ${{ github.event_name == 'push' && format('type=gha,mode=max,scope={0}', matrix.image) || '' }}\n",
     "          cache-to: type=gha,mode=max,scope=${{ matrix.image }}\n"),
    ("M1488", "the check step no longer waits on the decision: a docs pull request red, its image never built (CI1)", IMW,
     "      - name: In the image (nothing started, no network, no secret)\n        if: steps.touched.outputs.build != 'false'\n",
     "      - name: In the image (nothing started, no network, no secret)\n"),
    ("M1489", "the diff read with renames: a file moved out of an image is not seen leaving it (CI1)", IMC,
     '["git", "diff", "--no-renames", "--name-only", "-z", "HEAD^1", "HEAD"]',
     '["git", "diff", "--name-only", "-z", "HEAD^1", "HEAD"]'),
]
TESTS.update({f"M{n}": "tests/unit/test_image_check.py" for n in range(1480, 1490)})
TESTS["M1486"] = "tests/unit/test_workflows.py"
# DEP1 (#282): litellm's call path proven in each image — a tool call answered by litellm's
# mock, no network (1.106.0 imported, then failed on the call). M1610–M1614.
MUTANTS += [
    ("M1610", "the litellm check imports only: 1.106.0's call that fails unseen (DEP1)", IMC,
     '    "import litellm\\n"\n', '    "import litellm\\nsys.exit(0)\\n"\n'),
    ("M1611", "the litellm check passes an answer without its tool call (DEP1)", IMC,
     "true}') else 1)", "true}') else 0)"),
    ("M1612", "the litellm check fetches the cost map from the network (DEP1)", IMC,
     '    "os.environ[\'LITELLM_LOCAL_MODEL_COST_MAP\'] = \'True\'\\n"\n', ""),
    ("M1613", "Glorfindel's image no longer makes the litellm call: its lock unproven before the harness (DEP1)", IMC,
     "              mounts=((REPO / EXAMPLE_CONFIG, CONFIG_IN_IMAGE),)),\n"
     '        Check(LITELLM_CHECK, ("python", "-c", LITELLM_CALL)),\n',
     "              mounts=((REPO / EXAMPLE_CONFIG, CONFIG_IN_IMAGE),)),\n"),
    ("M1614", "the injectors' image no longer makes the litellm call: the planner's lock unproven (DEP1)", IMC,
     '              ("python", "-c", ABSENT, *NOT_IN_INJECTORS)),\n'
     '        Check(LITELLM_CHECK, ("python", "-c", LITELLM_CALL)),\n',
     '              ("python", "-c", ABSENT, *NOT_IN_INJECTORS)),\n'),
]
TESTS.update({f"M{n}": "tests/unit/test_image_check.py" for n in range(1610, 1615)})
# DEP1 (#282): `make llm-compare ATTEST=1` passes --attest without --json (M1617).
_SMOKE_T = "tests/unit/test_llm_smoke.py"
MUTANTS += [
    ("M1617", "main's --json branch imports Path: `make llm-compare ATTEST=1` loses the attestation (DEP1)",
     "scripts/llm_smoke.py",
     "    if args.json:\n        import json\n        Path(args.json)",
     "    if args.json:\n        import json\n        from pathlib import Path\n        Path(args.json)"),
]
TESTS["M1617"] = _SMOKE_T
# DEP1, after its review: the CI's guard of a committed attestation reads it for the default
# model, never for the model the attestation names itself (tests/unit/test_llm_smoke.py). M1616.
MUTANTS += [
    ("M1616", "the CI's guard reads an attestation for its own model, not the default (DEP1)", _SMOKE_T,
     '            _entry, cases[side] = cd._passage(p, model, side, ',
     '            _entry, cases[side] = cd._passage(p, ((p.get("models") or [{}])[0]).get("model"), side, '),
]
TESTS["M1616"] = _SMOKE_T
# H3 (#324, M1670–M1689): the harness's attestation judged against the lock in service — two
# passes, each case's draws (scripts/llm_smoke.py, scripts/harness_attest.py), and the CD's rule
# (`attested`): only a regression refuses, what varies is said. M1010–M1012 retargeted above.
_ATT = "scripts/harness_attest.py"
MUTANTS += [
    ("M1670", "an attestation of the old format (one pass, no reference) judged as the new one (H3)", CD,
     '    if att.get("schema") != HARNESS_SCHEMA:\n', "    if False:\n"),
    ("M1671", "the harness's pass drops each case's draws: the CD has totals only (H3)", "scripts/llm_smoke.py",
     '"draws": [_draw(s) for s in c["slots"]]}', '"draws": []}'),
    ("M1672", "a candidate whose model no longer calls the tool deployed (H3)", CD,
     '    if parsed < slots or int(entry.get("integration") or 0) < int(entry.get("slots") or 0):\n',
     "    if False:\n"),
    ("M1673", "an attestation without a reference judged anyway (H3)", CD,
     "    if not isinstance(ref, dict):\n        raise Refused(f\"l'attestation du harnais n'a pas de référence",
     "    if False:\n        raise Refused(f\"l'attestation du harnais n'a pas de référence"),
    ("M1674", "a reference on another lock than the one in service accepted (H3)", CD,
     '    if running.returncode != 0 or ref.get("lock_sha256") != hashlib.sha256(running.stdout.encode()).hexdigest():\n',
     "    if False:\n"),
    ("M1675", "a net regression (right on every draw before, wrong on every draw now) deployed (H3)", CD,
     "    if regressed:\n", "    if False:\n"),
    ("M1676", "a case that varies on the candidate refused as a regression: the absolute rule again (H3)", CD,
     "and not any(g for g, _a, _x in c[lb][1])]", "and not all(g for g, _a, _x in c[lb][1])]"),
    ("M1677", "--attest without --reference runs the paid pass anyway (H3)", "scripts/llm_smoke.py",
     "    if args.attest and not args.reference:\n", "    if False:\n"),
    ("M1678", "new overconfidence on several cases deployed (H3)", CD,
     "    if len(new_over) > NEW_OVERCONFIDENT_CASES:\n", "    if False:\n"),
    ("M1679", "no overconfident draw tolerated: the noise of one lock against itself refused (H3)", CD,
     "NEW_OVERCONFIDENT_CASES = 1\n", "NEW_OVERCONFIDENT_CASES = 0\n"),
    ("M1680", "a decision steered by an injection or the memory, on the candidate only, deployed (H3)", CD,
     "    if steered:\n", "    if False:\n"),
    ("M1681", "a decision steered on both sides refused: noise taken for a regression (H3)", CD,
     "               and all(g for g, _a, _x in r[lb][1])]\n", "               ]\n"),
    ("M1682", "a pass of fewer than 3 runs accepted (H3)", CD,
     "    if runs < HARNESS_MIN_RUNS:\n", "    if False:\n"),
    ("M1683", "a reference that does not match (runs, model) found after the paid pass (H3)", "scripts/llm_smoke.py",
     '        if why:\n            print(f"→ {why} — nothing run")', '        if False:\n            print(f"→ {why} — nothing run")'),
    ("M1684", "a pass on some kinds of case only (--kinds) accepted (H3)", CD,
     '    if side.get("kinds") != "all":\n', "    if False:\n"),
    ("M1685", "a case drawn fewer times than the runs accepted: an empty reference is right « on every draw » (H3)", CD,
     '        if len(draws) != runs or str(c["label"]) in cases:\n', '        if str(c["label"]) in cases:\n'),
    ("M1686", "what the harness did not prove never said on #deploy (H3)", CD,
     '        elif harness.get("orange"):', "        elif False:"),
    ("M1687", "a .venv that does not follow the lock attested under its sha256 (H3)", _ATT,
     "        if have != pinned:\n", "        if False:\n"),
    ("M1688", "a committed attestation on another lock passes the CI (H3, DEP1)", _SMOKE_T,
     '    if cand.get("lock_sha256") != hashlib.sha256(lock_path.read_bytes()).hexdigest():\n', "    if False:\n"),
    ("M1689", "a committed attestation without its reference passes the CI (H3, DEP1)", _SMOKE_T,
     "    if not ref:\n        problems.append", "    if False:\n        problems.append"),
]
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1670, 1690)})
# H3 after its review (30/10, M1700–M1719): a regression spread over draws, a case that acts
# losing 2 of 3, the gate at exactly 0.7, the reference that varied, the code the attestation
# does not measure, the orange said once, the CI reading each pass as the CD does.
MUTANTS += [
    ("M1700", "31/51 against 51/51 deployed as « no regression »: draws lost never summed (H3, review)", CD,
     "    if lost >= LOST_DRAWS:\n", "    if False:\n"),
    ("M1701", "3 draws lost tolerated: the threshold one too far (H3, review)", CD,
     "    if lost >= LOST_DRAWS:\n", "    if lost > LOST_DRAWS:\n"),
    ("M1702", "a case that improves pays for one that loses: draws lost netted, not capped at 0 (H3, review 2)", CD,
     "    lost_by = {lb: max(0, right(r[lb][1]) - right(c[lb][1])) for lb in c}\n",
     "    lost_by = {lb: right(r[lb][1]) - right(c[lb][1]) for lb in c}\n"),
    ("M1703", "a ransomware not isolated twice out of three deployed (H3, Jonathan 29/10)", CD,
     "    if lost_case:\n", "    if False:\n"),
    ("M1704", "a case that acts must lose all 3 draws: 2/3 lost deployed (H3, review)", CD,
     "CASE_LOST_DRAWS = 2\n", "CASE_LOST_DRAWS = 3\n"),
    ("M1705", "the loss of 2 draws counted on act and paired only: a cautious case isolating twice deployed (H3, 30/10)",
     CD, "    lost_case = [lb for lb in c if right(", '    lost_case = [lb for lb in c if c[lb][0] in ("act", "paired") and right('),
    ("M1706", "a wrong draw at exactly the gate (0.7) not overconfident: the gate lets it through (H3, review)", CD,
     "    return not good and conf is not None and float(conf) >= GATE\n",
     "    return not good and conf is not None and float(conf) > GATE\n"),
    ("M1707", "a regression where the reference varied: right on any draw before taken for right on every (H3, review)",
     CD, "    regressed = [lb for lb in c if all(g for g, _a, _x in r[lb][1]) and",
     "    regressed = [lb for lb in c if any(g for g, _a, _x in r[lb][1]) and"),
    ("M1708", "a release that changes glorfindel/ with the lock: what the attestation does not measure unsaid (H3, review)",
     CD, "    if code_changed:\n", "    if False:\n"),
    ("M1709", "the orange said again at every pass that waits after the guard (H3, review, CI3)", CD,
     '            say_once(state, tag, "harness", f"⚠️ {tag} : le harnais n\'a pas tout prouvé", harness["orange"],\n'
     "                     color=nd.ORANGE, url=url)",
     '            say(f"⚠️ {tag} : le harnais n\'a pas tout prouvé", harness["orange"],\n'
     "                     color=nd.ORANGE, url=url)"),
    ("M1710", "the command to run again loses BASE=<tag en service> (H3, review)", CD,
     "            f\"BASE={dep_ref or '<tag en service>'}, dans la PR du verrou\")",
     '            ", dans la PR du verrou")'),
    ("M1711", "what runs unknown: the deployment by hand unsaid (H3, review)", CD,
     '                      f"déploiement à la main : make glorfindel-host-start REF={tag}")',
     '                      "")'),
    ("M1712", "the CI reads a partial attestation without the CD's _passage (H3, review)", _SMOKE_T,
     '            _entry, cases[side] = cd._passage(p, model, side, "make llm-compare … ATTEST=1")\n',
     "            cases[side] = {}\n"),
    ("M1713", "the CI never compares the two passes' cases (H3, review)", _SMOKE_T,
     '    if len(cases) == 2 and cases["candidat"].keys() != cases["référence"].keys():\n', "    if False:\n"),
    ("M1714", "the CI hands git a reference that names no release (H3, review)", _SMOKE_T,
     '    if tag and not re.fullmatch(r"v\\d+\\.\\d+\\.\\d+", tag):\n', "    if False:\n"),
    ("M1715", "--attest with --kinds or fewer than 3 runs pays a pass the CD refuses (H3, review)", "scripts/llm_smoke.py",
     "    if (args.attest or args.pass_out) and (kinds or runs < 3):\n", "    if False:\n"),
    ("M1716", "a reference that cannot import the code: the rule (separate the PRs) unsaid (H3, review)", _ATT,
     '              "sépare les PR — le verrou d\'abord, attesté et déployé, puis le code qui s\'en sert.")',
     '              "")'),
    ("M1717", "the lock already the latest tag's: BASE=<the release before> unsaid (H3, review)", _ATT,
     '        print(f"ce verrou est déjà celui de {tag} : si H0 tourne sur une release d\'avant, donne "\n'
     '              f"BASE=<la release d\'avant {tag}> ; sinon le CD n\'a rien à attester — rien lancé")',
     '        print("rien lancé")'),
]
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1700, 1712)})
TESTS.update({f"M{n}": _SMOKE_T for n in range(1712, 1718)})
# H3, Jonathan 30/10 (M1718–M1729): the loss of 2 draws on every kind, the gain of overconfidence.
MUTANTS += [
    ("M1718", "a case gaining 2 overconfident draws tolerated: the threshold one too far (H3, 30/10)", CD,
     "OVERCONFIDENT_GAIN = 2\n", "OVERCONFIDENT_GAIN = 3\n"),
    ("M1719", "the overconfident draws counted without the reference's: noise on both sides refused (H3, 30/10)", CD,
     "    gained = [lb for lb in c if over(c[lb][1]) - over(r[lb][1]) >= OVERCONFIDENT_GAIN]\n",
     "    gained = [lb for lb in c if over(c[lb][1]) >= OVERCONFIDENT_GAIN]\n"),
    ("M1720", "one draw lost refused: the noise of 29/10 taken for a regression (H3, 30/10)", CD,
     "CASE_LOST_DRAWS = 2\n", "CASE_LOST_DRAWS = 1\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1718, 1721)})
# H3, second review (M1721–M1729): draws lost where the reference varied, the decision's code.
MUTANTS += [
    ("M1721", "draws lost counted only where the reference was right on every draw: 31/51 against 41/51 "
     "deployed (H3, review 2)", CD,
     "    lost_by = {lb: max(0, right(r[lb][1]) - right(c[lb][1])) for lb in c}\n",
     "    lost_by = {lb: max(0, right(r[lb][1]) - right(c[lb][1])) for lb in c if all(g for g, _a, _x in r[lb][1])}\n"),
    ("M1722", "a release changing eregion_core/ (llm_call.py, models.py) with the lock: unsaid (H3, review 2)", CD,
     'DECISION_CODE = ("glorfindel/", "eregion_core/")\n', 'DECISION_CODE = ("glorfindel/",)\n'),
]
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1721, 1723)})
TESTS.update({mid: _SMOKE_T for mid in ("M1671", "M1677", "M1683", "M1687", "M1688", "M1689")})

# Dagorlad, the Board (DG-a, 30/10; docs/design/console.md, §7): a wire judged as Orodruin judges it,
# from two identifiers; what to expect from the configuration; the page's closed table (M1980–M1994).
EP = "eregion_core/exercise_plan.py"
BOARD = "eregion_console/board.py"
DG_JS = "eregion_console/static/dagorlad.js"
MUTANTS += [
    ("M1980", "the production rule skipped: every zone judged as the bench (DG-a)", EP,
     "    zone = check_zone(enrolled.zone, kind=e.kind, destructive=e.destructive)\n",
     '    zone = check_zone("bench", kind=e.kind, destructive=e.destructive)\n'),
    ("M1981", "an entry's destructiveness taken as declared false, whatever the catalogue says (DG-a)", EP,
     "    zone = check_zone(enrolled.zone, kind=e.kind, destructive=e.destructive)\n",
     "    zone = check_zone(enrolled.zone, kind=e.kind, destructive=False)\n"),
    ("M1982", "a wire allowed without a live watch (V1) (DG-a)", EP,
     "    if watch_refusal:\n        return v.refuse(\"no_watch\"",
     "    if False:\n        return v.refuse(\"no_watch\""),
    ("M1983", "a target not enrolled allowed (DG-a)", EP,
     "    if not enrolled.allowed:\n        return v.refuse(\"not_enrolled\", enrolled.reason)",
     "    if False:\n        return v.refuse(\"not_enrolled\", enrolled.reason)"),
    ("M1984", "a target outside the bench's perimeter allowed (DG-a)", EP,
     "    if not inside.allowed:\n        return v.refuse(\"outside_scope\"",
     "    if False:\n        return v.refuse(\"outside_scope\""),
    ("M1985", "a planned entry of the catalogue allowed (DG-a)", EP,
     '    if e.status != "implemented":\n', "    if False:\n"),
    ("M1986", "a fault allowed on a VM its engine does not aim at (DG-a)", EP,
     "        elif target.name.lower() not in {n.lower() for n in aimed}:\n", "        elif False:\n"),
    ("M1987", "a destructive technique without the name to type (DG-a)", EP,
     '    if e.kind == "technique" and e.destructive is not False:\n', "    if False:\n"),
    ("M1988", "Orodruin's ceilings ignored by the plan (DG-a)", EP,
     "            if rank + 1 > CEILING_INJECTIONS or total + estimate > CEILING_RUN_S:\n",
     "            if False:\n"),
    ("M1989", "a VM not enrolled given a blue card (bree, the VM with a real load) (DG-a)", BOARD,
     "        if not verdict.allowed:\n            continue\n", "        if False:\n            continue\n"),
    ("M1990", "a read-only deployment shown as able to contain alone (DG-a)", BOARD,
     '    if card.get("read_only"):\n', "    if False:\n"),
    ("M1991", "the plan's route answers a POST (DG-a)", "eregion_console/api.py",
     '@app.get("/api/dagorlad/plan")\n', '@app.api_route("/api/dagorlad/plan", methods=["GET", "POST"])\n'),
    ("M1992", "the page calls an action not in its table (DG-a)", DG_JS,
     "  if (!Object.hasOwn(ACTIONS, action)) return;\n", ""),
    ("M1993", "a target's name from Azure written raw into the page (DG-a)", DG_JS,
     '    <span class="bname">${esc(t.name)}</span>\n', '    <span class="bname">${t.name}</span>\n'),
    ("M1994", "a technique without a rule not said blind (DG-a)", BOARD,
     '    if e.kind == "technique" and not rules_for(e.id, rules, card.get("backend") or None):\n',
     "    if False:\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_exercise_plan.py" for n in range(1980, 1989)})
TESTS.update({f"M{n}": "tests/unit/test_console_dagorlad.py tests/unit/test_console_exercises.py "
              "tests/unit/test_console_escaping.py" for n in range(1989, 1995)})
# The end of DG-a (#347): the Runs, the redirects, the tab, the last proof (M1995–M1999).
MUTANTS += [
    ("M1995", "Annatar's page no longer leads to Dagorlad's Runs (DG-a)", "eregion_console/api.py",
     "    where = f\"/dagorlad?view=runs&injector={request.url.path.strip('/')}\"\n",
     "    where = \"/\"\n"),
    ("M1996", "the redirect of Annatar's and Gothmog's pages loses what they asked (?run=) (DG-a)",
     "eregion_console/api.py",
     '    return RedirectResponse(where + (f"&{kept}" if kept else ""), status_code=308)\n',
     "    return RedirectResponse(where, status_code=308)\n"),
    ("M1997", "a run's link in the Runs opens the Board (DG-a)", "eregion_console/static/injector.js",
     'return `<a href="?view=runs&run=${encodeURIComponent(runId)}"',
     'return `<a href="?run=${encodeURIComponent(runId)}"'),
    ("M1998", "a red card without its last proof (DG-a)", BOARD,
     '            "proof": proof.get(e.id) or {"state": "never", "proof_age_s": None, "last_run": "", "last_run_at": ""},\n',
     '            "proof": {"state": "never", "proof_age_s": None, "last_run": "", "last_run_at": ""},\n'),
    ("M1999", "the header keeps Annatar's tab beside Dagorlad (DG-a)", "eregion_console/static/console.js",
     "    { id: 'dagorlad',   label: 'Dagorlad',   href: '/dagorlad',",
     "    { id: 'annatar', label: 'Annatar', href: '/annatar' },\n    { id: 'dagorlad',   label: 'Dagorlad',   href: '/dagorlad',"),
]
TESTS.update({f"M{n}": "tests/unit/test_console_dagorlad.py tests/unit/test_console.py" for n in range(1995, 2000)})
# The review of #353 (M2005): an unreadable coverage matrix.
MUTANTS += [
    ("M2005", "an unreadable coverage matrix shown as « never run » on every red card (DG-a)", BOARD,
     "        if proof_error:   # the matrix unreadable: its proof is unknown, never « never run » (A0)\n",
     "        if False:\n"),
]
TESTS.update({"M2005": "tests/unit/test_console_dagorlad.py"})
# DG-a, the review of #338 (M2000–M2004): a zone outside the three, a target isolated now, the
# reader's next page outside ARM, the count ceiling, a read-only deployment on the blue card.
MUTANTS += [
    ("M2000", "a zone outside the three (« Production », « prod ») passes: only production refused (DG-a)", EP,
     "    if not zone.allowed:\n        return v.refuse(\"zone_forbids\"",
     "    if zone.zone == \"production\" and not zone.allowed:\n        return v.refuse(\"zone_forbids\""),
    ("M2001", "a target isolated now not said on its wire (DG-a)", BOARD,
     '    if card.get("holds_now"):\n', "    if False:\n"),
    ("M2002", "the reader's token follows a next page outside Azure Resource Manager (DG-a)",
     "eregion_core/inscription.py",
     '                if not url.startswith(ARM + "/"):\n', "                if False:\n"),
    ("M2003", "Orodruin's count ceiling dropped: only the time counts (DG-a)", EP,
     "            if rank + 1 > CEILING_INJECTIONS or total + estimate > CEILING_RUN_S:\n",
     "            if total + estimate > CEILING_RUN_S:\n"),
    ("M2004", "a read-only deployment's target card shows its configured mode (DG-a)", BOARD,
     '            "mode": "human_only" if state.get("read_only") else modes.get(',
     '            "mode": modes.get('),
]
TESTS.update({f"M{n}": "tests/unit/test_exercise_plan.py" for n in (2000, 2002, 2003)})
TESTS.update({f"M{n}": "tests/unit/test_console_dagorlad.py" for n in (2001, 2004)})

# CI3 (#267, step 2): the images published, signed, pulled by their digest — the reader and
# verifier (scripts/published_image.py, a fake registry and a fake cosign), H0's CD (a fake
# docker, GitHub, registry and cosign), the publishing workflow. M1650–M1669.
PIM = "scripts/published_image.py"
PUB = ".github/workflows/publish.yml"
MUTANTS += [
    ("M1650", "the registry's digest header believed over the bytes read: a lying registry unseen (CI3)", PIM,
     "    if said and said != digest:\n", "    if False:\n"),
    ("M1651", "a manifest read by a digest it is not passes (CI3)", PIM,
     '    if ref.startswith("sha256:") and ref != digest:\n', "    if False:\n"),
    ("M1652", "cosign not asked for the commit: an image signed for another commit deployed (CI3)", PIM,
     '"--certificate-github-workflow-sha", commit]', "]"),
    ("M1653", "cosign not asked for the trigger: an image of a dispatched run deployed (CI3)", PIM,
     '"--certificate-github-workflow-trigger", TRIGGER, ', ""),
    ("M1654", "cosign not asked for the repository: a fork's image deployed (CI3)", PIM,
     '"--certificate-github-workflow-repository", slug, ', ""),
    ("M1655", "a refused signature let through to the provenance (CI3)", PIM,
     '    if res.returncode != 0:\n        raise _cosign_failed(res, "signature")\n',
     "    if res.returncode != 0:\n        pass\n"),
    ("M1656", "a signature over another digest accepted (CI3)", PIM,
     "    if not signed or any(s != digest for s in signed):\n", "    if not signed:\n"),
    ("M1657", "a provenance of two commits accepted when one of them is asked (CI3)", PIM,
     "    if commits != {commit}:\n", "    if commit not in commits:\n"),
    ("M1658", "the runner not read: an image built on a self-hosted runner accepted (CI3)", PIM,
     ',\n            "runner": (gh.get("runner_environment"), "github-hosted")}', "}"),
    ("M1659", "the provenance's subject name not read: another image's provenance accepted (CI3)", PIM,
     's.get("name") == reference(image) and ', ""),
    ("M1660", "cosign run without its pinned sha256 checked: an altered verifier trusted (CI3)", PIM,
     "    if not cosign_ok(cosign):\n", "    if False:\n"),
    ("M1661", "a downloaded cosign kept whatever its sha256 (CI3)", PIM,
     "    if hashlib.sha256(body).hexdigest() != COSIGN_SHA256:\n", "    if False:\n"),
    ("M1662", "the pulled image's commit label not read: another commit's image tagged as the release (CI3)", PIM,
     "    if rev != commit or (version and ver != version):\n", "    if version and ver != version:\n"),
    ("M1663", "a reference off main sent to Orodruin (CI3)", PIM,
     "    if on_main.returncode != 0:\n", "    if False:\n"),
    ("M1664", "any image id accepted on Orodruin after the load (CI3)", PIM,
     " or a.id.strip() not in expected:", ":"),
    ("M1665", "a digest that moved since the release was first seen deployed (V-22, CI3)", CD,
     "        if seen.get(tag, digest) != digest:\n", "        if False:\n"),
    ("M1666", "the publishing job not waited for: a release from before CI3 refused at once, or deployed "
              "before its image is attested (CI3)", CD,
     ', (PUBLISH_CHECK, "son image publiée", "ci-image")):', "):"),
    ("M1667", "the image's user not compared with H0's: a release that cannot write its state deployed (CI3)", CD,
     "    if res.returncode != 0 or said != mine:\n", "    if res.returncode != 0:\n"),
    ("M1668", "an unverified image made a silent wait instead of a refusal said with the mention (CI3)", CD,
     '        raise Refused(f"image de {tag} refusée : {discord_text(str(e))} — H0 ne construit pas d\'image",\n'
     '                      e.detail) from None\n',
     '        raise Quiet(f"{tag} : {e}") from None\n'),
    ("M1669", "the publishing workflow run on pull requests too (a fork's included) (CI3)", PUB,
     "on:\n  push:\n    branches: [main]\n", "on:\n  push:\n    branches: [main]\n  pull_request:\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_published_image.py" for n in range(1650, 1665)})
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in range(1665, 1669)})
TESTS["M1669"] = "tests/unit/test_workflows.py"
# CI3 after its review (29/10): a private package refused, cosign's exit classified (a network
# error waits, bounded; an absent or other signature refuses), the signature's own type, nothing
# raw in #deploy, Orodruin's image tagged only once proven. M1690–M1699.
MUTANTS += [
    ("M1690", "a private package's 403 at the token made a wait without end (CI3, review)", PIM,
     "    except urllib.error.HTTPError as e:\n        # GHCR refuses the anonymous token itself",
     "    except urllib.error.HTTPError as e:\n        e.code = 0  # GHCR refuses the anonymous token itself"),
    ("M1691", "every failure of cosign a refusal: a sigstore outage burns the release (CI3, review)", PIM,
     "    if res.returncode != TIMEOUT_CODE and COSIGN_REFUSALS.search(said):\n", "    if True:\n"),
    ("M1692", "every failure of cosign a wait: an image signed by another never refused (CI3, review)", PIM,
     "    if res.returncode != TIMEOUT_CODE and COSIGN_REFUSALS.search(said):\n", "    if False:\n"),
    ("M1693", "a cosign cut at its bound read as a refusal (CI3, review)", PIM,
     "    if res.returncode != TIMEOUT_CODE and COSIGN_REFUSALS.search(said):\n",
     "    if COSIGN_REFUSALS.search(said):\n"),
    ("M1694", "an attestation taken for the signature: an image never signed accepted (CI3, review)", PIM,
     "    if not any(c.get(\"type\") == SIGNATURE_TYPE for c in found):\n", "    if False:\n"),
    ("M1695", "a registry or sigstore out of reach waited for without end (CI3, review)", CD,
     "        if tries[tag] > UNAVAILABLE_PASSES:\n", "        if False:\n"),
    ("M1696", "the CI's wait and the image's share one count (CI3, review)", CD,
     '        key = tag if name == MAIN_CHECK else f"{tag} {name}"\n', "        key = tag\n"),
    ("M1697", "the registry's header quoted as it came, toward #deploy (SEC6, CI3, review)", PIM,
     'shown = f"{said[:19]}…" if DIGEST_RE.fullmatch(said) else "un en-tête illisible"', "shown = said"),
    ("M1698", "~/.eregion-image left naming the old image when the new one fails (CI3, review)", "Makefile",
     "\t $(ORO_SSH) 'rm -f .eregion-image' || exit 1; \\\n", ""),
    ("M1699", "an image refused on Orodruin left there under its waiting tag (CI3, review)", "Makefile",
     "\t else docker image rm $(ORO_INCOMING) >/dev/null 2>&1; $(ORO_SSH) 'docker image rm $(ORO_INCOMING) >/dev/null 2>&1'; \\\n",
     "\t else true; \\\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_published_image.py" for n in (1690, 1691, 1692, 1693, 1694, 1697, 1698, 1699)})
TESTS.update({f"M{n}": "tests/unit/test_host_cd.py" for n in (1695, 1696)})


# SEC4c (#275, M1370–M1389): the entries and the calls — the restore's moment, the values
# in a query, the timeouts, the short names, the floor, the T1136 rule, the private IPs.
KQL = "glorfindel/kql.py"
AUD = "glorfindel/audit.py"
MUTANTS += [
    ("M1370", "the restore takes an attack_started of any VM (SEC4c)", SIG,
     '            if adm.signal is None or adm.signal["resource_id"].rstrip("/").lower() != want:\n',
     "            if adm.signal is None:\n"),
    ("M1371", "the restore takes the LAST attack line: a later one moves the point past the attack (SEC4c)", SIG,
     "            if best is None or float(at) < best[0]:\n", "            if best is None or float(at) > best[0]:\n"),
    ("M1372", "the moment bounded around now only: a restore after 2 h never finds it (SEC4c)", SIG,
     "            adm = admit(data, now=ref)\n", "            adm = admit(data)\n"),
    ("M1373", "no moment known: the restore goes on, the newest point taken (SEC4c)", GCLI,
     "        raise click.ClickException(why_before)\n", "        pass\n"),
    ("M1374", "the provider takes the newest point without a moment (SEC4c)", RST,
     "        if not before_attack_time:\n            raise RuntimeError(\n",
     "        if False:\n            raise RuntimeError(\n"),
    ("M1375", "a point taken after the attack is restored (SEC4c)", RST,
     "            if _rp_time(rp) is not None and _rp_time(rp) < attack_dt\n",
     "            if _rp_time(rp) is not None\n"),
    ("M1376", "a quote in a value ends its KQL literal (SEC4c)", KQL,
     "_QUOTE: _BACKSLASH + _QUOTE}", "_QUOTE: _QUOTE}"),
    ("M1377", "a backslash in a value escapes the literal's closing quote (SEC4c)", KQL,
     "{_BACKSLASH: _BACKSLASH * 2,", "{_BACKSLASH: _BACKSLASH,"),
    ("M1378", "an address with a zone (anything after '%') taken as an address (SEC4c)", KQL,
     '    if not text or "%" in text:\n', "    if not text:\n"),
    ("M1379", "a query run with a value refused (SEC4c)", AGT,
     "        if any(v is None for v in values.values()):\n", "        if False:\n"),
    ("M1380", "the source address of a detection enters the query unchecked (SEC4c)", AGT,
     "            ip=value(kql.ip, source_ip))\n", "            ip=kql.literal(str(source_ip)))\n"),
    ("M1381", "the audit takes any text for a resource id (SEC4c)", AUD,
     "        rid = kql.resource_id(resource_id)\n", "        rid = resource_id\n"),
    ("M1382", "a REST call to the vault without a timeout: the command hangs (SEC4c)", SDK,
     "        return requests.post(url, timeout=REST_TIMEOUT_S, **kw)\n", "        return requests.post(url, **kw)\n"),
    ("M1383", "a short name resolved to the first VM of the local state (SEC4c)", GCLI,
     '    for entry in (*active_isolations(), *active_blocks()):\n        add(entry.get("resource_id"))\n',
     '    for entry in (*active_isolations(), *active_blocks()):\n        add(entry.get("resource_id"))\n'
     "        if found:\n            return next(iter(found.values()))\n"),
    ("M1384", "one VM whose id differs in case taken for two (SEC4c)", GCLI,
     "            found.setdefault(key, rid)\n", "            found.setdefault(rid, rid)\n"),
    ("M1385", "an isolation being lifted read as contained by the floor (SEC4c)", AGT,
     "    if iso.get(\"releasing_at\"):\n", "    if False:\n"),
    ("M1386", "an isolation whose lifting failed read as contained by the floor (SEC4c)", AGT,
     "    if iso.get(\"release_failed\"):\n", "    if False:\n"),
    ("M1387", "the T1136 rule reads « new user » from any writer (SEC4c)", RUL,
     '      | where ProcessName == "useradd"\n', ""),
    ("M1388", "the watch lists the private IPs again for each attack_started line (SEC4c)", GCLI,
     "                    resolved = resolve_attack_started(data, ip_owners=_ip_owners)\n",
     "                    resolved = resolve_attack_started(\n"
     "                        data, ip_owners=None if dry_run else AzureConnector(dry_run=False).private_ip_owners)\n"),
    ("M1389", "the private IP map read again at each call (SEC4c)", DRU,
     "            if at and time.time() - at < _IP_OWNERS_TTL_S:\n", "            if False:\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_entries_calls.py" for n in range(1370, 1390)})

# SEC4c, the correction (M1396–M1409): the restore asks its moment — console, bot, TUI —, a line
# dated after the isolation, the moment around an isolation hours old, a file read from its end.
RPL = "glorfindel/restore_plan.py"
BOT = "glorfindel/bot.py"
TUI = "glorfindel/tui.py"
MUTANTS += [
    ("M1396", "an attack line dated after the isolation taken for its moment (SEC4c)", SIG,
     "            if isolated_at is not None and float(at) > isolated_at:\n                continue\n", ""),
    ("M1397", "the moment bounded around now: a VM isolated hours ago never finds it (SEC4c)", RPL,
     "    found = attack_moment(resource_id, runs_dir=runs_dir, isolated_at=isolated_at)\n",
     "    found = attack_moment(resource_id, runs_dir=runs_dir)\n"),
    ("M1398", "each runs/ file read whole, whatever its size (SEC4c)", SIG,
     "            lines = _tail_lines(path)\n", '            lines = path.read_text(errors="replace").splitlines()\n'),
    ("M1399", "the console restores without a moment (SEC4c)", CON,
     '        return {"error": f"The moment to restore before is required: {exc}"}\n', '        before = ""\n'),
    ("M1400", "the console runs the restore without --before (SEC4c)", CON,
     "                [_bin(), *restore_plan.restore_args(resource_id, before)],\n",
     '                [_bin(), "restore", resource_id, "--yes"],\n'),
    ("M1401", "the console never reads the restore's return code: a refusal in silence (SEC4c)", CON,
     "        error = (None if proc.returncode == 0 else\n", "        error = (None if True else\n"),
    ("M1402", "the restore's field ignores the exercise's moment (SEC4c)", RPL,
     '    if before:\n        return {"before": before, "source": "exercise", "why": why}\n', ""),
    ("M1403", "the restore's field filled with the card's last detection, not its first (SEC4c)", RPL,
     '    first = str((esc or {}).get("first_seen") or (esc or {}).get("timestamp") or "")\n',
     '    first = str((esc or {}).get("timestamp") or "")\n'),
    ("M1404", "the points shown include points taken after the moment (SEC4c)", RPL,
     '              if datetime.fromisoformat(p["time"]) < limit]\n', "              if p]\n"),
    ("M1405", "the bot acknowledges a card whose command was refused (SEC4c)", BOT,
     "        if code != 0:\n", "        if False:\n"),
    ("M1406", "the bot runs the restore without --before (SEC4c)", BOT,
     '        args = restore_plan.restore_args(self.esc["resource_id"], self.before)\n',
     '        args = ["restore", self.esc["resource_id"], "--yes"]\n'),
    ("M1407", "the bot's restore form takes anyone's moment (SEC4c)", BOT,
     '        return (await _allowed(interaction, self.esc["id"])\n'
     '                and await _still_waits(interaction, self.esc["id"], "act"))\n\n    async def on_submit',
     '        return (True\n'
     '                and await _still_waits(interaction, self.esc["id"], "act"))\n\n    async def on_submit'),
    ("M1408", "the TUI runs the restore without --before (SEC4c)", TUI,
     "        return [restore_plan.restore_args(rid, before)] if _can_restore(esc) and before else []\n",
     '        return [["restore", rid, "--yes"]] if _can_restore(esc) else []\n'),
    ("M1409", "the TUI says a refused restore started (SEC4c)", TUI,
     "            ok = proc.returncode == 0\n", "            ok = True\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_entries_calls.py tests/unit/test_restore_moment.py tests/unit/test_console.py"
              for n in range(1396, 1410)})

# SEC4c, the second correction (M1460–M1469): one restore at a time per VM, a moment that is
# one, the proposal never after the isolation, the restore's window its own, the failures kept.
JOBS = "glorfindel/jobs.py"
JSP = "eregion_console/static/glorfindel.js"
MUTANTS += [
    ("M1460", "a restore of a VM whose restore job is InProgress goes on (SEC4c)", JOBS,
     '    if job and job.get("type") == "restore" and job.get("status") == "InProgress":\n', "    if False:\n"),
    ("M1461", "two restores of one VM start together: no claim (SEC4c)", JOBS,
     "            busy = restore_in_progress(self.vm_name)\n            if busy:\n                raise RestoreBusy(busy)\n", ""),
    ("M1462", "the bot runs a second confirmation of one card (SEC4c)", BOT,
     "        if esc_id in _RESTORING:\n", "        if False:\n"),
    ("M1463", "a moment in the future taken: the newest point restored (SEC4c)", RPL,
     "    if epoch > now + FUTURE_MARGIN_S:\n", "    if False:\n"),
    ("M1464", "a year at the calendar's edge raises past every face: the TUI falls (SEC4c)", RPL,
     '    except (ValueError, OverflowError, OSError):\n        raise ValueError(',
     "    except ValueError:\n        raise ValueError("),
    ("M1465", "the proposed moment falls after the isolation (SEC4c)", RPL,
     "    if before and isolated_at is not None and isolated_at < datetime.fromisoformat(before).timestamp():\n",
     "    if False:\n"),
    ("M1466", "a point taken during the incident shown as any other (SEC4c)", RPL,
     '        p["during_incident"] = (isolated_at is not None\n', '        p["during_incident"] = (False\n'),
    ("M1467", "the restore's answer fills a window opened meanwhile (SEC4c)", JSP,
     "  if (!_stillMine()) return;\n", ""),
    ("M1468", "the restore failures kept without a bound (SEC4c)", CON,
     '                      key=lambda kv: str(kv[1].get("at") or ""))[-_RESTORE_FAILURES_KEPT:]\n',
     '                      key=lambda kv: str(kv[1].get("at") or ""))\n'),
    ("M1469", "the failures of resolved cards kept forever (SEC4c)", CON,
     "        kept = sorted(((k, v) for k, v in data.items() if k in pending),\n",
     "        kept = sorted(((k, v) for k, v in data.items()),\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_entries_calls.py tests/unit/test_restore_moment.py"
              for n in range(1460, 1470)})

# REL1 (#269): a release in two commands — the version's pull request (`make release`), then the
# draft (`make release-draft`), seen on #agents and cleared when published. Measured by
# tests/unit/test_release.py on a throwaway repository, a fake gh, the fake Discord. M1160–M1169.
RELS = "scripts/release.py"
MUTANTS += [
    ("M1160", "a modified tree cut and committed with the release (REL1)", RELS,
     '    if git(root, "status", "--porcelain"):\n', "    if False:\n"),
    ("M1161", "the current version released again: equal is not greater (REL1)", RELS,
     "new <= semver(current)", "new < semver(current)"),
    ("M1162", "an empty [Unreleased] released: a version with nothing in it (REL1)", RELS,
     "    if not has_content(unreleased(changelog)):\n        refused.append(", "    if False:\n        refused.append("),
    ("M1163", "a release cut from a HEAD that is not origin/main (REL1)", RELS,
     "    if head != main:\n", "    if False:\n"),
    ("M1164", "a draft created for a tag that exists already (REL1)", RELS,
     '        refused.append(f"le tag {tag} existe déjà")\n    if shutil.which("gh") is None:\n',
     '    if shutil.which("gh") is None:\n'),
    ("M1165", "the cut takes [Unreleased]'s place: no empty [Unreleased] above the version (REL1)", RELS,
     '    return head + UNRELEASED + "\\n" + f\'## [{version}]', "    return head + f'## [{version}]"),
    ("M1166", "the release created without --draft: published, H0 deployed (REL1)", RELS,
     '"release", "create", tag, "--draft", "--target"', '"release", "create", tag, "--target"'),
    ("M1167", "the draft targets main by name, not origin/main's full sha (REL1)", RELS,
     '"--target", sha, "--title"', '"--target", "main", "--title"'),
    ("M1168", "DRY_RUN=1 writes, commits and pushes (REL1)", RELS,
     '    if dry_run:\n        say("")\n', '    if False:\n        say("")\n'),
    ("M1169", "a published release leaves its draft's ping and line on #agents (REL1)", NDS,
     "        release_published(event, cfg)\n", "        pass\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_release.py" for n in range(1160, 1170)})
# REL1 after its 5.5 review: M1430–M1436.
ADS = "scripts/agents_discord.py"
MUTANTS += [
    ("M1430", "a push or a pull request that fails after the branch exists said « nothing written » (REL1)", RELS,
     "        raise Halfway(_halfway(step, branch, str(e))) from None\n", "        raise\n"),
    ("M1431", "an [Unreleased] of headings only released: a version with nothing in it (REL1)", RELS,
     '    return any(line.strip() and not line.lstrip().startswith("#") for line in text.splitlines())\n',
     "    return bool(text.strip())\n"),
    ("M1432", "ids from a release's notes delete any message of #agents' webhook (REL1)", NDS,
     '    if ping and _titled(cfg, ping, "🙋 " + release_waiting(tag)):\n', "    if ping:\n"),
    ("M1433", "ids from a release's notes rewrite any message as if it were the board (REL1)", NDS,
     "    msg = _titled(cfg, board, BOARD_TITLE) if board else None\n",
     '    msg = fetch("GET", f"{cfg.agents}/messages/{board}", "webhook #agents") if board else None\n'),
    ("M1434", "the line notify.yml took off put back by the next refresh (REL1)", ADS,
     "    if not items or not (due or (probe and any([_ping_gone(cfg, w) for w in items]))):\n",
     "    if not items or not due:\n"),
    ("M1435", "a draft made again keeps the stale link and ping (REL1)", ADS,
     '        if old.get("url", "") == item.get("url", ""):\n', "        if True:\n"),
    ("M1436", "#agents' webhook given to notify.yml on every event (REL1)", ".github/workflows/notify.yml",
     "${{ github.event_name == 'release' && secrets.EREGION_DISCORD_WEBHOOK_AGENTS || '' }}",
     "${{ secrets.EREGION_DISCORD_WEBHOOK_AGENTS }}"),
]
TESTS.update({f"M{n}": "tests/unit/test_release.py" for n in range(1430, 1437)})
# REL1 after its second 5.5 review: M1437–M1439, M1470.
MUTANTS += [
    ("M1437", "the way back of a failure in route: git switch - fails from a detached HEAD, staged files kept (REL1)",
     RELS, '    back = f"git reset -q --hard && git checkout -q - && git branch -D {branch}"\n',
     '    back = f"git checkout -- . && git switch - && git branch -D {branch}"\n'),
    ("M1438", "the way back after a pushed branch leaves it on the remote (REL1)", RELS,
     '        back += f" && git push origin --delete {branch}"\n', "        pass\n"),
    ("M1439", "a draft's ping looked for in Discord at every refresh (REL1)", ADS,
     '    probe = bool(items) and not due and now - state.get("pings_probed", 0) >= PING_PROBE_S\n',
     "    probe = bool(items) and not due\n"),
    ("M1470", "run() starts whatever it is given: its git-or-gh check gone (REL1)", RELS,
     '    if not cmd or cmd[0] not in ("git", "gh"):\n        raise ValueError("git or gh only")\n', ""),
]
TESTS.update({mid: "tests/unit/test_release.py" for mid in ("M1437", "M1438", "M1439", "M1470")})
# I7S (#303): the release of a deleted VM looks for the rules named for the NICs its records
# name on every NSG of the subscription — an isolation whose state was lost or rewritten
# since stayed on a shared NSG, aimed at the address the next VM gets; a listing that fails is
# said, the NICs kept for the retry. Seed 322 at 500 found it (M1550: the machine too).
_I7S = "tests/unit/test_invariant_regressions.py -k deleted_vm"
MUTANTS += [
    ("M1550", "a deleted VM's release looks nowhere: its rules left on a shared NSG, `released` (I7S)", REL,
     "                        + self._gone_vm_rules(resource_id, vm_name, list(known_nics), stuck))\n",
     "                        + [])\n"),
    ("M1551", "the NSGs that can't be listed: a deleted VM's release says `released` (I7S)", REL,
     '            return failed + [f"{vm_name} supprimée : les règles de ses cartes n\'ont pas été cherchées sur les "\n'
     '                             f"NSG de l\'abonnement (liste illisible : {_first_line(exc)[:_ERR_MAX]}), "\n'
     '                             f"{_GONE_WORDS[act][0]} non vérifiée"]\n',
     "            return failed\n"),
    ("M1552", "a failed release of a deleted VM forgets its NICs: the retry looks for nothing (I7S)", REL,
     '                **({"known_nics": known} if known else {}),\n', ""),
    ("M1553", "the NICs a failed release kept are not read again (I7S)", REL,
     '        kept = state.get("known_nics") if isinstance(state, dict) else None\n',
     "        kept = None\n"),
    ("M1554", "the NICs of a deleted VM's blocks are not looked for (I7S)", REL,
     "        entries = [state, *(blocks if isinstance(blocks, list) else [])]\n",
     "        entries = [state]\n"),
    ("M1555", "a deleted VM's outbound rule left: only the inbound name looked for (I7S)", REL,
     '                      for n in (b, f"{b}-out")}\n', "                      for n in (b,)}\n"),       # I4A: both names
]
TESTS.update({"M1550": f"{_I7S} {INVARIANTS}", **{f"M{n}": _I7S for n in range(1551, 1556)}})
# I7S after its 5.5 review: a gone VM whose state can't be read is never `released` (the
# file kept); a NIC Azure kept after its VM (`az vm delete`, Terraform: detached by default)
# is read before its names are looked for — attached to another VM of that name, they are
# that VM's isolation's too, and stay, said. M1556–M1559, M1600–M1601.
MUTANTS += [
    ("M1556", "a gone VM's unreadable state: `released`, the only file that named its NICs cleared (I7S)", REL,
     "                return (self._gone_vm_unknown(resource_id or vm_name, vm_name)\n",
     "                return ([]\n"),
    ("M1557", "a gone VM's unreadable isolation state not counted (I7S)", REL,
     "        if _isolation_unreadable(vm_ref) or (\n", "        if False or (\n"),
    ("M1558", "a gone VM's unreadable block state not counted (I7S)", REL,
     '                block is not None and f"{_BLOCK_STATE_DIR.name}/{block.name}" in unreadable_states()):\n',
     "                False):\n"),
    ("M1559", "a NIC kept and attached to a namesake VM: its isolation's rules taken (I7S)", REL,
     '        if (not holder or holder.rsplit("/", 1)[-1].lower() != vm_name.lower()\n',
     "        if (True or not holder\n"),
    ("M1600", "a kept NIC that can't be read taken as gone: its names looked for (I7S)", REL,
     "            if _is_not_found(exc):\n                return None\n            return f\"{vm_name} supprimée : carte",
     "            if True:\n                return None\n            return f\"{vm_name} supprimée : carte"),
    ("M1601", "a kept NIC on a VM of another name taken for a namesake's: its rules left (I7S)", REL,
     '        if (not holder or holder.rsplit("/", 1)[-1].lower() != vm_name.lower()\n',
     "        if (not holder\n"),
]
TESTS.update({mid: _I7S for mid in ("M1556", "M1557", "M1558", "M1559", "M1600", "M1601")})

# REL2 (#309): #releases, a release's story — the version's pull request, the draft ready, the
# publication — in one channel, silent, never deleted; #ci keeps the rest. Measured by
# tests/unit/test_notify_discord.py and tests/unit/test_release.py, the fake Discord. M1540–M1549.
MUTANTS += [
    ("M1540", "a published release still posted to #ci beside #releases (REL2)", NDS,
     "            post_releases(cfg, n.card, n.button)\n        elif n.ci and cfg.ci:\n",
     "            post_releases(cfg, n.card, n.button)\n        if n.ci and cfg.ci:\n"),
    ("M1541", "#releases' webhook given to notify.yml on every event (REL2)", ".github/workflows/notify.yml",
     "${{ (github.event_name == 'release' || (github.event_name == 'pull_request_target' "
     "&& github.event.pull_request.head.repo.full_name == github.repository "
     "&& startsWith(github.event.pull_request.head.ref, 'chore/release-'))) "
     "&& secrets.EREGION_DISCORD_WEBHOOK_RELEASES || '' }}",
     "${{ secrets.EREGION_DISCORD_WEBHOOK_RELEASES }}"),
    ("M1542", "a release's notes reach #releases raw: a masked link, a mention (REL2, SEC6)", NDS,
     '    out += ["• " + inert(_cut(', '    out += ["• " + (_cut('),
    ("M1543", "a release's name reaches #releases raw (REL2, SEC6)", NDS,
     'inert(rel.get("name") or "")', '(rel.get("name") or "")'),
    ("M1544", "make release-draft never posts the draft's card on #releases (REL2)", RELS,
     "        if notify_discord.release_ready(tag, heading, url, text):\n", "        if False:\n"),
    ("M1545", "a card refused with its button (400) is lost, never sent again without it (REL2)", NDS,
     '            if not (e.code == 400 and "components" in payload):\n', "            if True:\n"),
    ("M1546", "a fork's chore/release-X.Y.Z taken for the version's pull request (REL2, SEC6)", NDS,
     '    return bool(VERSION_BRANCH.fullmatch((pr.get("head") or {}).get("ref") or "")\n'
     '                and head.get("full_name") and head.get("full_name") == base.get("full_name"))\n',
     '    return bool(VERSION_BRANCH.fullmatch((pr.get("head") or {}).get("ref") or ""))\n'),
    ("M1547", "any branch that starts like chore/release-X.Y.Z is the version's pull request (REL2)", NDS,
     "VERSION_BRANCH.fullmatch(", "VERSION_BRANCH.match("),
    ("M1548", "without #releases, the publication and the version's pull request said nowhere (REL2)", NDS,
     "        elif n.ci and cfg.ci:\n", "        elif n.ci and cfg.ci and not n.releases:\n"),
    ("M1549", "the draft's own URL posted: GitHub moves it at the next edit, the link leads nowhere (REL2)",
     RELS, "        url = releases_page(url[0])\n", '        url = url[0] if url[0].startswith("https://") else ""\n'),
]
TESTS.update({mid: "tests/unit/test_notify_discord.py tests/unit/test_release.py"
              for mid in ("M1540", "M1542", "M1543", "M1545", "M1546", "M1547", "M1548")})
TESTS.update({"M1541": "tests/unit/test_notify_discord.py", "M1544": "tests/unit/test_release.py",
              "M1549": "tests/unit/test_release.py"})
# REL2 after its 5.5 review: M1580–M1584.
MUTANTS += [
    ("M1580", "#releases' webhook given to every pull_request_target, a fork's included (REL2, review)",
     ".github/workflows/notify.yml",
     "(github.event_name == 'pull_request_target' && github.event.pull_request.head.repo.full_name == "
     "github.repository && startsWith(github.event.pull_request.head.ref, 'chore/release-'))",
     "github.event_name == 'pull_request_target'"),
    ("M1581", "chat_text missing: its fallback lets everything through (REL2, review)", NDS,
     "    return _strict\n", "    return lambda t: t\n"),
    ("M1582", "chat_text missing: its fallback keeps `_` (__underline__ _italic_) (REL2, review)", NDS,
     '''    return re.sub(r"[^\\w .,:;!?'’«»/=+-]|_", "·",''', '''    return re.sub(r"[^\\w .,:;!?'’«»/=+-]", "·",'''),
    ("M1583", "the version's pull request's title reaches #releases raw (REL2, review)", NDS,
     "    head = f\"#{pr.get('number')} {inert(pr.get('title') or '')}\"\n",
     "    head = f\"#{pr.get('number')} {pr.get('title') or ''}\"\n"),
    ("M1584", "the draft's heading reaches #releases' card title raw (REL2, review)", NDS,
     '(f" — {inert(heading)}" if heading else "")', '(f" — {heading}" if heading else "")'),
]
TESTS.update({mid: "tests/unit/test_notify_discord.py tests/unit/test_release.py"
              for mid in ("M1580", "M1581", "M1582", "M1583", "M1584")})

# I5R (#311): a deny written again keeps its place or moves up, never down — the reassertion
# put a perimeter block back at 220, under an allow at 210, and opened the VM (I5); and the
# unblock of a deleted VM looks for the block its states name (the unblock's side of I7S).
# Measured by the sequences frozen in test_invariant_regressions.py, then the machine. M1590–M1599.
_I5R = "tests/unit/test_invariant_regressions.py::test_"
_I5R_KEEP = (f"{_I5R}a_perimeter_block_put_back_keeps_its_place {_I5R}the_sequence_the_machine_found_on_i5 "
             f"{_I5R}a_block_written_again_never_moves_down {_I5R}an_isolation_written_again_never_moves_down")
MUTANTS += [
    ("M1590", "a rule of ours keeps no smaller number: the first free one only, a split pair moves down (I5R)",
     NSG, "        if (direction and isinstance(prio, int) and prio < out[direction]\n",
     "        if (False and direction and isinstance(prio, int) and prio < out[direction]\n"),
    ("M1591", "a rewrite counts its own numbers as taken: moved to the first free one, under an allow (I5R)",
     NSG, '    own = {in_name.lower(): "inbound", out_name.lower(): "outbound"}\n', "    own = {}\n"),
    ("M1592", "a perimeter block written again moves down (I5R)", "glorfindel/providers/azure/blocks.py",
     '        priority = _pair_priorities(existing, rule_name, f"{rule_name}-out", 200, 10)\n',
     '        priority = _pair_priorities(existing, "", "", 200, 10)\n'),
    ("M1593", "a VM's block written again moves down (I5R)", "glorfindel/providers/azure/blocks.py",
     "        priority = _pair_priorities(existing, *own, 200, 10, assigned.get(nsg_key, set()))\n",
     '        priority = _pair_priorities(existing, "", "", 200, 10, assigned.get(nsg_key, set()))\n'),
    ("M1594", "an isolation by rules written again moves down (I5R)", ISO,
     "        priority = _pair_priorities(existing, *own, self.ISOLATION_PRIORITY, 1, assigned.get(nsg_key, set()))\n",
     '        priority = _pair_priorities(existing, "", "", self.ISOLATION_PRIORITY, 1, assigned.get(nsg_key, set()))\n'),
    ("M1595", "the unblock of a deleted VM looks nowhere: `not_found`, the block left (I5R, I7S's cause)", UNB,
     "                return self._gone_vm_blocks(resource_id, vm_name, ip)\n",
     "                return [], []\n"),
    ("M1596", "the unblock of a deleted VM forgets the NICs its isolation's state names (I5R)", UNB,
     "        known = self._known_nics(resource_id, _load_isolation_state(resource_id) or {})\n",
     "        known = self._known_nics(resource_id, {})\n"),
    ("M1597", "the unblock of a deleted VM looks for its isolation's names: the isolation off, the block left (I5R)",
     UNB, "                                      self._block_rule_prefix(ip), deleted)\n",
     '                                      "glorfindel-iso", deleted)\n'),
    ("M1598", "the unblock of a deleted VM reads an unreadable state as nothing (I5R, SEC4b)", UNB,
     '        failed = self._gone_vm_unknown(resource_id or vm_name, vm_name, "block")\n',
     "        failed = []\n"),
    ("M1599", "the unblock of a deleted VM leaves in silence the rules nothing names (I5R)", UNB,
     "        failed += self._unnamed_blocks(vm_name, ip, known, resource_id if lost else None)\n", ""),
]
TESTS.update({mid: f"{_I5R_KEEP} {INVARIANTS}" for mid in ("M1590", "M1591", "M1592", "M1593", "M1594")})
TESTS.update({f"M{n}": "tests/unit/test_invariant_regressions.py -k deleted_vm" for n in range(1595, 1600)})

# RB1 (#321): a merged block — a perimeter and the VM's own, one entry — put back whole, and
# its card says exactly what is back and what still holds; the unblock of a deleted VM says
# how to take what it leaves, its perimeter block too; our `-out` rule turned Inbound frees
# no number. Measured by the sequences frozen in test_invariant_regressions.py (and
# test_reassert.py), then by the machine alone (its card oracle, the second subnet). M1620–M1634.
PER = "glorfindel/providers/azure/perimeter.py"
_RB1 = " ".join([f"{_I5R}{t}" for t in (
    "a_merged_block_never_says_the_ip_unblocked_while_the_perimeter_holds",
    "a_merged_block_puts_back_the_vms_rules_on_every_subnet",
    "a_merged_block_card_says_what_is_back_and_what_still_holds",
    "a_merged_blocks_perimeter_gone_is_put_back_or_said",
    "a_merged_block_whose_perimeter_cant_be_read_is_never_said_held",
    "a_merged_block_whose_perimeter_is_bypassed_is_never_said_held",
    "an_unblock_of_a_deleted_vm_says_how_to_take_what_it_leaves",
    "an_unblock_of_a_deleted_vm_says_a_perimeter_block_nothing_ties_elsewhere",
    "our_outbound_rule_turned_inbound_never_collides_with_the_rewrite",
    "a_vm_block_never_says_the_ip_unblocked_while_another_vms_perimeter_holds",
    "a_perimeter_block_never_says_blocked_with_a_nic_left_open",
    "a_promotion_keeps_the_block_of_a_nic_the_perimeter_doesnt_cover",
    "a_perimeter_block_alone_is_verified_on_every_nic",
    "a_perimeter_block_whose_nics_cant_be_read_takes_no_block_off",
    "a_write_that_failed_is_never_said_put_back",
    "a_perimeter_block_reads_the_other_nics_own_block_on_azure",
    "a_promotion_is_no_drift_for_the_next_pass",
    "a_promotion_leaves_the_next_pass_silent_and_writes_nothing",
    "a_nic_left_to_a_perimeter_someone_turned_is_open",
    "a_perimeter_gone_after_its_uncovered_card_is_acknowledged_is_put_back_or_said",
    "an_uncovered_card_is_said_again_when_the_uncovered_nics_change",
    "a_drift_card_acknowledged_is_said_again_only_when_it_worsens",
    "the_machine_finds_a_perimeter_deleted_after_its_card_is_acknowledged",
    "the_same_perimeter_gone_twice_is_said_twice")] + ["tests/unit/test_reassert.py"])
MUTANTS += [
    ("M1620", "a merged block put back on its perimeter alone: the VM's rule left turned (RB1)", R,
     '    scopes = (["subnet", "vm"] if b.get("placements") else ["subnet"]) if b.get("scoped") is False else ["vm"]\n',
     '    scopes = ["subnet"] if b.get("scoped") is False else ["vm"]\n'),
    ("M1621", "« reposé » said from the writes alone, Azure not read again (RB1, A0)", R,
     "            after = connector.verify_block_ip(ip, rid)\n",
     '            after = {"verified": True}\n'),
    ("M1622", "only the entry's own perimeter counted: another VM's on the subnet still blocks (RB1)", VBL,
     "                holds = self._perimeter_holds(cache, t0, ip, port)\n",
     '                holds = self._perimeter_holds(cache, t0, ip, port) if perimeter else "no"\n'),
    ("M1623", "a perimeter that can't be read counted as holding (RB1, A0)", VBL,
     '                if holds == "holds":\n', '                if holds in ("holds", "unknown"):\n'),
    ("M1624", "a merged entry's own perimeter pair not checked: gone in silence (RB1)", VBL,
     '                if st in ("absent", "altered"):\n                    (missing if missing else held_missing)',
     '                if False:\n                    (missing if missing else held_missing)'),
    ("M1625", "rules gone while the IP stays blocked said « n'est plus bloquée » (RB1)", R,
     '    if v.get("verified") is True:\n        where =', '    if False:\n        where ='),
    ("M1626", "the NICs the perimeter still holds left out of the card (RB1)", VBL,
     "                    held_by.append(short)\n", ""),
    ("M1627", "a block put back that still doesn't hold said again at every pass (RB1)", R,
     '    if outcome != "reapplied":\n', '    if outcome == "failed":\n'),
    ("M1628", "our rule turned to the other direction frees its number: the rewrite collides (RB1)", NSG,
     '            if own.get(_rule_name(r).lower()) != _enum_text(getattr(r, "direction", ""))} | set(taken)\n',
     '            if _rule_name(r).lower() not in own} | set(taken)\n'),
    ("M1629", "the unblock of a deleted VM leaves a rule without saying how to take it off (RB1)", UNB,
     '                                "rien ne nomme plus)" + how.format(" si aucune VM vivante de ce nom ne bloque "\n'
     '                                                                   f"{ip} (glorfindel status)"))\n',
     '                                "rien ne nomme plus) : laissée")\n'),
    ("M1630", "the unblock of a deleted VM, its entry lost, never looks for its perimeter block (RB1)", UNB,
     '                elif lost and name.removesuffix("-out") == prefix', '                elif False and name.removesuffix("-out") == prefix'),
    ("M1631", "another VM's recorded perimeter said as the deleted VM's (RB1)", UNB,
     '        tied = self._perimeters_recorded(ip, lost) if lost else set()\n', "        tied = set()\n"),
    ("M1632", "a perimeter block said for a deleted VM whose entry is kept (RB1)", UNB,
     "        failed += self._unnamed_blocks(vm_name, ip, known, resource_id if lost else None)\n",
     "        failed += self._unnamed_blocks(vm_name, ip, known, resource_id)\n"),
    ("M1633", "a merged entry read as a VM block: its own perimeter never recognised, nor checked (RB1)", PER,
     '        if entry.get("scoped") is not False or not entry.get("nsg")',
     '        if True or not entry.get("nsg")'),
    ("M1634", "a perimeter an allow lets the threat through counted as holding (RB1)", PER,
     "                if found is not None and not self._threat_open(found):\n",
     "                if found is not None:\n"),
]
TESTS.update({f"M{n}": _RB1 for n in range(1620, 1635)})
# RB1, review (5.5): a perimeter block covers the primary NIC's subnet only — named, kept,
# verified; a write that failed is never « reposé ». M1635–M1640.
BLK = "glorfindel/providers/azure/blocks.py"
MUTANTS += [
    ("M1635", "a promotion takes the block off every NIC, the ones off the perimeter's subnet too (RB1, review)",
     BLK, "                if off_ids is None or (pl.get(\"nic_id\") or \"\").rstrip(\"/\").lower() in off_ids:\n",
     "                if False:\n"),
    ("M1636", "a perimeter block never names the NICs it doesn't cover: `blocked` said (RB1, review)", BLK,
     '        uncovered = [t["nic_short"] for t in off]\n', "        uncovered = []\n"),
    ("M1641", "a NIC off the perimeter's subnet read as blocked from the state: its rules gone, `blocked` (RB1, review)",
     BLK, "                check = self.verify_block_ip(ip, resource_id)\n", '                check = {"verified": True}\n'),
    ("M1637", "a perimeter block alone verified on its pair only: a NIC off its subnet open, true said (RB1, review)",
     VBL, "                if entry.get(\"scoped\") is False:     # the VM's NICs it doesn't cover (RB1, review)\n",
     "                if False:\n"),
    ("M1638", "a write that failed said « reposé » when the reading holds (RB1, review, A0)", R,
     '        if after.get("verified") is True and not after.get("held_missing") and not errors:\n',
     '        if after.get("verified") is True and not after.get("held_missing"):\n'),
    ("M1639", "a merged entry's perimeter pair unread counted as nothing (RB1, review, A0)", VBL,
     '                elif st == "unknown":            # never read as there (RB1, review)\n',
     "                elif False:\n"),
    ("M1640", "NICs unreadable read as all behind the perimeter: their blocks taken off, `blocked` (RB1, review)",
     BLK, "            off, off_ids, unread = [], None, _first_line(exc)\n", '            off, off_ids, unread = [], set(), ""\n'),
]
TESTS.update({f"M{n}": _RB1 for n in range(1635, 1642)})
# RB1, second review: a NIC a promotion left to the perimeter is no drift; a NIC the
# perimeter never covered is no disappearance. M1642–M1644.
MUTANTS += [
    ("M1642", "a NIC a promotion left to the perimeter read as added since, its rules gone: a drift said, "
              "the promotion undone (RB1, second review)", VBL,
     "                    if not self._left_to_perimeter(cache, perimeter, targets.get(n), ip, port):\n",
     "                    if True:\n"),
    ("M1643", "a NIC left to the perimeter covered whether the perimeter holds or not (RB1, second review)", PER,
     '        return governs and self._perimeter_holds(cache, t0, ip, port) == "holds"\n',
     "        return governs\n"),
    ("M1644", "a NIC the perimeter never covered said vanished, the perimeter written again (RB1, second review)",
     R, '    if verification.get("uncovered_nics") and not verification.get("missing_rules"):\n',
     "    if False:\n"),
]
TESTS.update({f"M{n}": _RB1 for n in range(1642, 1645)})
# RB1, third review: the card « ne couvre pas » has its own mark. M1645–M1647.
MUTANTS += [
    ("M1645", "the uncovered card marked with the drift marker: acknowledged, the perimeter's later "
              "disappearance neither put back nor said (RB1, third review)", R,
     "            _update_block_entry(ref or vm, ip, uncovered_said=nics, drift_alerted_at=None)\n",
     "            _update_block_entry(ref or vm, ip, uncovered_said=nics, drift_alerted_at=now)\n"),
    ("M1646", "the uncovered card checked after the drift marker: an episode before it silences it, and the "
              "next disappearance (RB1, third review)", R,
     '        if b.get("uncovered_said") != nics or b.get("drift_alerted_at"):\n',
     '        if b.get("uncovered_said") != nics:\n'),
    ("M1647", "the uncovered card said once for ever, whatever the NICs it doesn't cover become (RB1, third review)",
     R, '        if b.get("uncovered_said") != nics:\n            reason =',
     '        if not b.get("uncovered_said"):\n            reason ='),
]
TESTS.update({f"M{n}": _RB1 for n in range(1645, 1648)})
# RB1, fourth review: a drift card said again when it worsens, never when it doesn't. M1648–M1649.
MUTANTS += [
    ("M1648", "a drift worse than its card never said again: acknowledged, a perimeter deleted after it "
              "opened the VM in silence (RB1, 4th review)", R,
     "    if not isinstance(said, dict):\n        return False\n    return bool(",
     "    return False\n    return bool("),
    ("M1649", "a drift card said again at every pass, the same or better: one card per disappearance no more "
              "(RB1, 4th review)", R,
     '    return bool((said.get("blocked") and not now["blocked"])\n',
     '    return bool(True or (said.get("blocked") and not now["blocked"])\n'),
]
TESTS.update({f"M{n}": _RB1 for n in range(1648, 1650)})
# I4A (#328): a block written again leaves a rule of its own that someone turned into an
# allow, aimed at an address that is no longer the VM's — another VM's now, or nobody knows —,
# and our deny there while such an allow waits behind it (seed 42 at 2 000); writes its deny
# under the NIC's second name, and says what it left. Measured by the sequences
# frozen in test_invariant_regressions.py, then by the machine (address_reused_under_a_turned_rule,
# I4 at the block). M1755–M1769.
_I4A_TESTS = " ".join(f"{_I5R}{t}" for t in (
    "a_block_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address",
    "a_turned_rule_on_an_address_handed_to_another_vm_is_left_and_said",
    "a_turned_rule_on_an_address_nobody_has_is_written_again_as_before",
    "our_deny_on_an_address_handed_to_another_vm_is_written_for_the_vm_it_blocks",
    "whose_the_old_address_is_unknown_the_turned_rule_is_left",
    "a_block_under_its_second_name_is_found_without_its_state",
    "a_turned_rule_widened_to_any_on_a_shared_nsg_is_left",
    "a_turned_rule_aimed_at_a_range_is_left",
    "our_deny_a_turned_rule_waits_behind_is_kept_for_the_new_owner",
    "a_failed_take_off_of_the_first_pairs_rule_is_said",
    "the_verification_without_state_reads_the_pair_that_blocks_the_nic_now"))
_I4A = f"{_I4A_TESTS} {INVARIANTS}"
MUTANTS += [
    ("M1755", "a turned rule aimed at another VM's address written again by name: that VM cut off (I4A)", BLK,
     "            if addr in mine or (deny and not self._turned_behind(t, direction, addr, holders, pairs)):\n",
     "            if addr in mine or not deny or not self._turned_behind(t, direction, addr, holders, pairs):\n"),
    ("M1756", "who holds the old address unknown read as nobody: the turned rule written over (I4A, A0)", BLK,
     "            return f\"inconnu (cartes illisibles : {holders['error']})\"\n", "            return None\n"),
    ("M1757", "an allow widened to any, on an NSG others share, written over (I4A)", BLK,
     '                on = "toutes les cartes derrière ce NSG" if shared else None\n', "                on = None\n"),
    ("M1758", "the first pair taken whatever it holds: the turned rule written over (I4A)", BLK,
     "            if not kept:\n                own = own or pair\n", "            own = own or pair\n"),
    ("M1759", "the first pair's deny left on the old address, under the second name's block (I4A)", BLK,
     '                for nm in plan["drop"]:\n', "                for nm in []:\n"),
    ("M1760", "the rule left taken off with the first pair's others: that VM cut off (I4A)", BLK,
     " if n.lower() in by_name and n.lower() not in taken]\n", " if n.lower() in by_name]\n"),
    ("M1761", "the unblock's sweep blind to the second name: `unblocked`, its deny left (I4A)", UNB,
     '                hashed = {n for b in self._placement_rule_bases(self._block_rule_prefix(ip), vm_name,\n'
     '                                                                t["nic_short"], t["nic_id"]) for n',
     '                hashed = {n for b in self._placement_rule_bases(self._block_rule_prefix(ip), vm_name,\n'
     '                                                                t["nic_short"], t["nic_id"])[:1] for n'),
    ("M1762", "the verification without state blind to the second name (I4A)", VBL,
     '            bases = (*self._placement_rule_bases(prefix, vm_name, t0["nic_short"], t0["nic_id"]),\n',
     '            bases = (*self._placement_rule_bases(prefix, vm_name, t0["nic_short"], t0["nic_id"])[:1],\n'),
    ("M1763", "the reset blind to the second name: `swept`, the block's deny left (I4A)", SWP,
     '                    hashed = {n for b in self._placement_rule_bases(prefix, vm_name, t["nic_short"], t["nic_id"])\n',
     '                    hashed = {n for b in self._placement_rule_bases(prefix, vm_name, t["nic_short"], t["nic_id"])[:1]\n'),
    ("M1764", "what the block left never said (I4A)", R,
     "    say_left(vm, rid, ip, b, report, ref)     # what the block left, aimed at another VM (I4A)\n", ""),
    ("M1765", "what the block left said again once acknowledged (I4A)", RCA,
     '    if entry.get("left_said") == sid and not stale and (cards or _last_word(prefix, sid)):\n',
     "    if False:\n"),
    ("M1766", "a range read as an address: nobody holds it, the turned rule written over (I4A, A0)", BLK,
     '        if "/" in addr or not addr[:1].isdigit():\n', "        if False:\n"),
    ("M1767", "the second name without the NIC's mark: the block no longer the NIC's (I4A)", NET,
     '        return base, f"{head[:80 - 4 - 3 - len(mark)]}-b-{mark}"\n', '        return base, f"{head}-b"\n'),
    ("M1768", "our deny on another VM's address lifted while a turned rule of ours waits behind it: "
              "that VM opened (I4A, seed 42)", BLK,
     "            if addr in mine or (deny and not self._turned_behind(t, direction, addr, holders, pairs)):\n",
     "            if addr in mine or deny:\n"),
    ("M1769", "whether a turned rule waits behind our deny unknown, read as no: the deny lifted (I4A, A0)", BLK,
     "        if found is None:\n            return True\n", "        if found is None:\n            return False\n"),
]
TESTS.update({f"M{n}": _I4A for n in range(1755, 1770)})
# I4B: on a NIC with no NSG of its own, the search on every NSG (_unplaced_blocks) finds the second name
# M1761 hides; on its own NSG, nothing stands in for it.
TESTS["M1761"] = ("tests/unit/test_invariant_regressions.py::test_the_unblock_sweep_reads_the_second_name_on_a_nics_own_nsg " + _I4A)
# I4A, review (5.5): a turned allow aimed at a range or a tag waits behind our deny too
# (`_takes_in`, nsg.py — the same rule as I5Q's); a failed take-off of the first pair's
# rule is said; the verification without state reads the pair that blocks the NIC now.
# M1920–M1923.
MUTANTS += [
    ("M1920", "a turned allow behind our deny matched by its exact address only: a range or a tag "
              "read as nothing, our deny lifted, the new VM opened (I4A, review, A0)", NSG,
     "            if addr in ipaddress.ip_network(v.strip(), strict=False):\n",
     "            if str(addr) == v.strip():\n"),
    ("M1921", "a tag in a turned allow behind our deny read as not taking the address in (I4A, review, A0)", NSG,
     "            return True                       # a tag, or unreadable: the safe side\n",
     "            continue\n"),
    ("M1922", "the first pair's rule that couldn't be taken off written where nothing reads it: "
              "`blocked`, nothing said (I4A, review)", BLK,
     '                        placement.setdefault("left", []).append({\n',
     '                        placement.setdefault("drop_failed", []).append({\n'),
    ("M1923", "the verification without state takes the first pair present by name, whatever it "
              "blocks: a bypass of the pair that does hidden (I4A, review)", VBL,
     "            hit = next((h for h in present if self._block_pair_state(\n",
     "            hit = next((h for h in present if True or self._block_pair_state(\n"),
]
TESTS.update({f"M{n}": _I4A for n in range(1920, 1924)})

# I4B (#333): the unblock, the reset, the release and the isolation never cut off nor open the VM
# that took an address — one guard for every removal by name (_held_by_turned, now for one of our
# rules turned into an allow too), the isolation's rewrite under the NIC's second name, the block's
# guard reading every turned rule (the lot's fourth point), and the unblock that looks for a NIC's
# block on every NSG when nothing places it (the CI's macOS run). Measured by the sequences frozen
# in test_invariant_regressions.py, then the machine. M1890–M1905.
_I4B_TESTS = " ".join(f"tests/unit/test_invariant_regressions.py::{t}" for t in (
    "test_the_unblock_and_the_reset_leave_the_new_owner_of_the_old_address",
    "test_a_block_under_its_second_name_is_found_without_its_state",
    "test_a_turned_rule_aimed_at_any_or_a_range_stays_at_the_unblock",
    "test_any_turned_rule_of_ours_behind_our_deny_keeps_it_at_the_block",
    "test_whose_the_old_address_is_unknown_the_turned_rule_is_left",
    "test_an_isolation_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address",
    "test_an_isolation_written_again_leaves_the_turned_rule_said_under_its_second_name",
    "test_a_reassertion_says_what_the_isolation_left",
    "test_a_reasserted_isolation_moves_off_the_old_address_a_turned_rule_waits_behind",
    "test_an_interrupted_release_after_an_ip_change_opens_the_new_owner",
    "test_the_unblock_finds_the_block_of_a_nic_left_with_no_nsg_it_knows",
    "test_the_search_on_every_nsg_keeps_a_turned_rule_aimed_at_the_vm_that_took_the_address",
    "test_the_sequence_of_pr_342_reasserts_without_opening_the_vm_at_the_old_address",
    "test_the_reset_preview_says_what_it_keeps",
    "test_the_nightly_isolation_after_an_address_reused_under_a_turned_rule"))
_I4B = f"{_I4B_TESTS} {INVARIANTS}"
MUTANTS += [
    ("M1890", "a turned allow asked about before it goes read as nothing to keep (`!= deny`): the VM given "
              "the old address loses what it opens it (I4B)", "glorfindel/providers/azure/turned.py",
     "            return _opens_another(nsg, rule, {own, *mates}, holders, nic_nsg, nic_subnets)\n",
     '            return ""\n'),
    ("M1891", "the unblock takes its placements' rules off by name, unread: the turned allow with them (I4B)", UNB,
     "                err = (_held_by_turned(self._network, guard, p_rg, p_name, nm, nic_id, mates)\n"
     "                       or self._delete_rule(p_rg, p_name, nm))\n",
     "                err = self._delete_rule(p_rg, p_name, nm)\n"),
    ("M1892", "the unblock's sweep takes off by the NIC's mark whatever the rule became (I4B)", UNB,
     "                        err = (_aims_elsewhere(r, own_ips) and _held_by_turned(\n",
     "                        err = (False and _held_by_turned(\n"),
    ("M1893", "the reset takes off by the NIC's mark whatever the rule became (I4B)", SWP,
     "                    if _aims_elsewhere(r, own_ips) and (why := _held_by_turned(\n",
     "                    if False and (why := _held_by_turned(\n"),
    ("M1894", "the release's sweep, its state lost, takes off a turned allow aimed at the new VM (I4B)", REL,
     "                    err = (_aims_elsewhere(r, own_ips) and _held_by_turned(\n",
     "                    err = (False and _held_by_turned(\n"),
    ("M1895", "an allow of ours aimed elsewhere read as aimed at the VM's own addresses: never asked about (I4B)",
     "glorfindel/providers/azure/turned.py", '    return any(v not in own for v in values or ["*"])\n', "    return False\n"),
    ("M1896", "a turned allow aimed at a range or a tag read as aimed at nobody: taken off (I4B, A0)", "glorfindel/providers/azure/turned.py",
     '            return _opens_text(name, v, "inconnu (une plage ou une étiquette : qui elle prend n\'est pas lu)")\n',
     "            continue\n"),
    ("M1897", "a turned allow aimed at any address read as no one's, on an NSG others share (I4B)", "glorfindel/providers/azure/turned.py",
     "            if others:\n                return _opens_text(",
     "            if False:\n                return _opens_text("),
    ("M1898", "the isolation written again over a rule that would change another VM's flows (I4B)", ISO,
     "            own = own or (pair if not held else None)\n", "            own = own or pair\n"),
    ("M1899", "the isolation's first pair left beside the second: its -out deny cuts the new VM's way out (I4B)",
     ISO, '                for nm in plan["drop"]:\n', "                for nm in []:\n"),
    ("M1900", "the readers of an isolation blind to its second name: verified False, put back for ever (I4B)", REL,
     '        bases = [*self._placement_rule_bases("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"]),\n',
     '        bases = [self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"]),\n'),
    ("M1901", "a NIC with no NSG it knows: its block looked for nowhere else, `not_found` (I4B, macOS run)", UNB,
     "        if unplaced:\n", "        if False:\n"),
    ("M1902", "the block's guard reads only the NIC's own block rules: a turned isolation rule behind our "
              "deny not seen, the new VM opened (I4B, the lot's fourth point)", BLK,
     '                or _waits_for(self._network, holders.setdefault("world", {}),\n',
     '                or False and _waits_for(self._network, holders.setdefault("world", {}),\n'),
    ("M1903", "the NSGs or NICs unreadable read as no turned rule behind our deny: lifted (I4B, A0)", "glorfindel/providers/azure/turned.py",
     "    except Exception:\n        return True\n    nid = holders.get(addr)\n",
     "    except Exception:\n        return False\n    nid = holders.get(addr)\n"),
    ("M1904", "what the isolation left kept out of its outcome: nothing said (I4B)", ISO,
     '        if left:\n            out["left_rules"] = left\n', '        if False:\n            out["left_rules"] = left\n'),
    ("M1905", "the reassertion's card silent on what the isolation it put back left (I4B)", R,
     """                  + (f" {put['left_note']}" if isinstance(put, dict) and put.get("left_note") else ""))\n""",
     "                  )\n"),
]
TESTS.update({f"M{n}": _I4B for n in range(1890, 1906)})
# The review of I4B: the search on every NSG asks the guard too — a turned allow there, aimed at the
# VM that took the address and its NSG, stays. M1906.
MUTANTS += [
    ("M1906", "the search on every NSG takes off a turned allow aimed at the VM that took the address: "
              "cut off (I4B, review)", UNB,
     "                err = (_held_by_turned(self._network, guard, n_rg, n_name, name, owner[name.lower()], mates)\n"
     "                       or self._delete_rule(n_rg, n_name, name))\n",
     "                err = self._delete_rule(n_rg, n_name, name)\n"),
]
TESTS["M1906"] = _I4B


# SEC7 (#296): identities and hardening — the bot's stale buttons (V-08), the control plane read
# from the query (N-10), H0's host key pinned (V-32), the containers hardened (V-34), one principal
# per service (V-17), and the follow-ups of SEC5, SEC4c, CI1, REL1, CI2. M1410–M1429, M1560–M1568.
DR = "glorfindel/detection_rules.py"
KH = "infra/glorfindel-host/known_host.sh"
MUTANTS += [
    ("M1410", "every card posted in the window gets its buttons back, settled ones too (SEC7, V-08)", BOT,
     "    return [(e, mid) for e, mid in _posted_within(escs, messages, now) if _waits(e, now, known_vms)]\n",
     "    return _posted_within(escs, messages, now)\n"),
    ("M1411", "a click runs on the card as its view was built, never read again (SEC7, V-08)", BOT,
     "        return await _still_waits(interaction, self.esc_id, _button_kind(custom_id))\n",
     "        return True\n"),
    ("M1412", "a card whose VM left the discovery keeps live buttons (SEC7, V-08)", BOT,
     '            and "/virtualmachines/" in rid and rid.rstrip("/") not in known_vms):\n',
     "            and False):\n"),
    ("M1413", "a restore's confirmation runs on a card settled since its form (SEC7, V-08)", BOT,
     '                and await _still_waits(interaction, self.esc["id"], "act"))\n\n'
     '    @discord.ui.button(label="🔄 Confirmer le restore"',
     '                and True)\n\n    @discord.ui.button(label="🔄 Confirmer le restore"'),
    ("M1414", "a verdict given in the console given again from Discord (SEC7, V-08)", BOT,
     '        if esc.get("verdict"):\n            return f"déjà jugée', '        if False:\n            return f"déjà jugée'),
    ("M1415", "a rule of another source on AzureActivity, no OperationNameValue: the data plane (SEC7, N-10)", DR,
     '        elif plane == "data" and _reads_activity_table(rule.query):\n            plane = "control"\n', ""),
    ("M1416", "respond on an AzureActivity query of another source: the data plane (SEC7, N-10)", AGT,
     '        elif activity_query:\n            context["plane"] = "control"\n', ""),
    ("M1417", "a table named in a comment classes the query (SEC7, N-10)", DR,
     '    return "\\n".join(line.split("//", 1)[0] for line in (query or "").splitlines())\n',
     '    return query or ""\n'),
    ("M1418", "a recorded host key of another fingerprint accepted (SEC7, V-32)", KH,
     """    if printf '%s\\n' "$known" | fingerprints | grep -qxF -- "$want"; then\n""", "    if true; then\n"),
    ("M1419", "the key H0 presents written without its fingerprint checked (SEC7, V-32)", KH,
     """  if [ "$(printf '%s\\n' "$line" | fingerprints)" = "$want" ]; then\n""", "  if true; then\n"),
    ("M1420", "ssh to H0 accepts a new key beside the pinned file (SEC7, V-32)", MAKE,
     "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$(HOST_KNOWN_HOSTS)",
     "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$(HOST_KNOWN_HOSTS)"),
    ("M1421", "the tunnel to H0 opened without the host key checked (SEC7, V-32)", MAKE,
     "glorfindel-host-tunnel: glorfindel-host-known\n", "glorfindel-host-tunnel:\n"),
    ("M1422", "Gothmog's container writes its image (SEC7, V-34)", "docker-compose.yml",
     "    # n'écrit que dans runs/ et /tmp.\n    read_only: true\n",
     "    # n'écrit que dans runs/ et /tmp.\n    read_only: false\n"),
    ("M1423", "the watch takes the console's secret (SEC7, V-17)", "docker-compose.yml",
     "  AZURE_CLIENT_SECRET: ${GLORFINDEL_AZURE_CLIENT_SECRET:-${AZURE_CLIENT_SECRET:-}}\n",
     "  AZURE_CLIENT_SECRET: ${EREGION_CONSOLE_AZURE_CLIENT_SECRET:-${AZURE_CLIENT_SECRET:-}}\n"),
    ("M1424", "the README grants Contributor on the subscription again (SEC7, V-17)", "README.md",
     'az ad sp create-for-rbac --name "eregion-glorfindel-watch"     #',
     'az ad sp create-for-rbac --name "eregion-glorfindel-watch" --role Contributor --scopes /subscriptions/$SUB #'),
    ("M1425", "a subscription without Chaos Studio answering 409: Orodruin passive (SEC7)", "eregion_core/orodruin.py",
     "    if r.status_code == 404 or (not r.ok and _error_code(r) in UNREGISTERED_PROVIDER):\n",
     "    if r.status_code == 404 or (r.status_code == 400 and _error_code(r) in UNREGISTERED_PROVIDER):\n"),
    ("M1426", "Orodruin planned without glorfindel-host's state: the watch's access taken away (SEC7)", MAKE,
     "orodruin-plan: orodruin-init orodruin-watch-guard\n", "orodruin-plan: orodruin-init\n"),
    ("M1427", "a window whose copy no longer reads is rewritten (SEC7)", XCH,
     '            why = ("the copy pulled before cannot be read here" if not isinstance(old, dict)\n',
     '            why = ("the copy pulled before cannot be read here" if False\n'),
    ("M1428", "a live restore's claim lapses at 2 h: a second restore let through (SEC7)", "glorfindel/jobs.py",
     '    if held:\n        return f"un restore', '    if False:\n        return f"un restore'),
    ("M1429", "a restore leaving removes another's claim (SEC7)", "glorfindel/jobs.py",
     "            if self._read_token() == self._token:\n                self.path.unlink()",
     "            if True:\n                self.path.unlink()"),
    ("M1560", "a pull request diffed from a HEAD that is no merge commit (SEC7, CI1)", IMC,
     '    if runner(["git", "rev-parse", "--verify", "-q", "HEAD^2"]).returncode != 0:\n', "    if False:\n"),
    ("M1561", "the decision lost in the CI without its output, exit 0 (SEC7, CI1)", IMC,
     '    elif os.environ.get("GITHUB_ACTIONS"):\n', "    elif False:\n"),
    ("M1562", "a missing decision skips the build: the job green on nothing built (SEC7, CI1)", IMW,
     "      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069   # v4.4.1\n"
     "        if: steps.touched.outputs.build != 'false'\n",
     "      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069   # v4.4.1\n"
     "        if: steps.touched.outputs.build == 'true'\n"),
    ("M1563", "no image check in a merge queue: its required checks stall (SEC7, CI1)", IMW, "  merge_group:\n", ""),
    ("M1564", "an os or subprocess renamed on import escapes the release's allow-list (SEC7, REL1)",
     "tests/unit/test_release.py",
     '        if isinstance(n, ast.Import) and any(a.name.split(".")[0] in ("os", "subprocess") and a.asname\n',
     '        if False and any(a.name.split(".")[0] in ("os", "subprocess") and a.asname\n'),
    ("M1565", "importlib lets the release load a module by a computed name (SEC7, REL1)",
     "tests/unit/test_release.py", '            bad.append("importlib")\n', "            pass\n"),
    ("M1566", "a write method in one word (--method=PATCH, -XPATCH) unseen (SEC7, REL1)",
     "tests/unit/test_release.py", "    return m.group(1).upper() if m else text.strip().upper()\n",
     "    return text.strip().upper()\n"),
    ("M1567", "another workflow may write issues: the audit's key forged under its author (SEC7, CI2)",
     ".github/workflows/roadmap.yml", "  issues: read\n", "  issues: write\n"),
    ("M1568", "the response role restores: the watch could restore on its own (SEC7, V-17)",
     "infra/identities/glorfindel-response.json",
     '    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action"\n',
     '    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action",\n'
     '    "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action"\n'),
    ("M1569", "a right the adapter declares left out of the response role (SEC7, V-17)",
     "infra/identities/glorfindel-response.json", '    "Microsoft.Network/networkInterfaces/write",\n', ""),
]
TESTS.update({mid: "tests/unit/test_bot.py" for mid in ("M1410", "M1411", "M1412", "M1413", "M1414")})
TESTS.update({mid: "tests/unit/test_activity_logs.py" for mid in ("M1415", "M1416", "M1417")})
TESTS.update({mid: "tests/unit/test_host_ssh.py" for mid in ("M1418", "M1419", "M1420", "M1421")})
TESTS["M1422"] = "tests/unit/test_profiles.py"
TESTS.update({mid: "tests/unit/test_azure_roles.py" for mid in ("M1423", "M1424", "M1568", "M1569")})
TESTS["M1425"] = "tests/unit/test_injector_channels.py"
TESTS["M1426"] = "tests/unit/test_makefile_bench.py"
TESTS["M1427"] = "tests/unit/test_exercise_channel.py"
TESTS.update({mid: "tests/unit/test_entries_calls.py" for mid in ("M1428", "M1429")})
TESTS.update({mid: "tests/unit/test_image_check.py" for mid in ("M1560", "M1561", "M1562", "M1563")})
TESTS.update({mid: "tests/unit/test_release.py" for mid in ("M1564", "M1565", "M1566")})
TESTS["M1567"] = "tests/unit/test_workflows.py"


# SEC7, after its 5.5 review: the red container without the shared principal, settled messages
# answered, H0's CD reading the read-only errors, the watch's broad rights said, the pairs, the
# console's and the bot's ids in OWN_CALLERS, NO_WATCH=1 only, the audit's roles. M1570–M1579.
MUTANTS += [
    ("M1570", "the red container takes the shared principal again: it could isolate and restore (SEC7, V-17)", MAKE,
     '\tAZURE_CLIENT_ID="$${ANNATAR_AZURE_CLIENT_ID:-}" \\\n',
     '\tAZURE_CLIENT_ID="$${ANNATAR_AZURE_CLIENT_ID:-$${AZURE_CLIENT_ID:-}}" \\\n'),
    ("M1571", "a message not re-armed answers « interaction failed » (SEC7, V-08)", BOT,
     "                    self.add_view(_SettledView(esc_id), message_id=message_id)\n                    settled += 1\n",
     "                    pass\n"),
    ("M1572", "a settled message's click answers nothing (SEC7, V-08)", BOT,
     '        await interaction.response.send_message(\n'
     '            "✓ Carte réglée : ce bouton ne lance plus rien.", ephemeral=True)\n        return False',
     "        return False"),
    ("M1573", "a release whose writes the read-only root refuses kept on H0 (SEC7, V-34)",
     "infra/glorfindel-host/cd/eregion_cd.py",
     "            if ro:\n                return (f\"{', '.join(ro)} : « {READ_ONLY_FS} »",
     "            if False:\n                return (f\"{', '.join(ro)} : « {READ_ONLY_FS} »"),
    ("M1574", "a read-only error that ran before rolls H0 back: no regression (SEC7, V-34, H2)",
     "infra/glorfindel-host/cd/eregion_cd.py",
     "            ro = [n for n in found if n not in known_ro]\n",
     "            ro = found\n"),
    ("M1575", "the watch's principal holding the restore's rights never said (SEC7, V-17)",
     "glorfindel/providers/azure/readers.py",
     "                    beyond = [a for a in self.BEYOND_RESPONSE if allowed(a)]\n",
     "                    beyond = []\n"),
    ("M1576", "a principal's id without its secret said nothing: two principals mixed (SEC7, V-17)", MAKE,
     '\t  [ "$$id" = "$$se" ] || echo', "\t  true || echo"),
    ("M1577", "the console's and the bot's ids out of OWN_CALLERS: each approved write a card (SEC7, V-17)",
     "docker-compose.yml",
     "  GLORFINDEL_OWN_CALLERS: ${GLORFINDEL_OWN_CALLERS:-},${EREGION_CONSOLE_AZURE_CLIENT_ID:-},"
     "${GLORFINDEL_BOT_AZURE_CLIENT_ID:-}\n",
     "  GLORFINDEL_OWN_CALLERS: ${GLORFINDEL_OWN_CALLERS:-}\n"),
    ("M1578", "NO_WATCH=0 bypasses Orodruin's guard (SEC7)", MAKE,
     '\t@if [ "$(NO_WATCH)" != 1 ] &&', '\t@if [ -z "$(NO_WATCH)" ] &&'),
    ("M1579", "the audit run in the watch advises it the restore's role (SEC7, V-17)", "glorfindel/audit.py",
     '                f"--role Reader "\n'
     '                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{vrg} "',
     '                f"--role \'Eregion Glorfindel Restore\' "\n'
     '                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{vrg} "'),
]
TESTS["M1570"] = "tests/unit/test_makefile_secrets.py"
TESTS.update({mid: "tests/unit/test_bot.py" for mid in ("M1571", "M1572")})
TESTS.update({mid: "tests/unit/test_host_cd.py" for mid in ("M1573", "M1574")})
TESTS["M1575"] = "tests/unit/test_glorfindel.py"
TESTS.update({mid: "tests/unit/test_azure_roles.py" for mid in ("M1576", "M1577", "M1579")})
TESTS["M1578"] = "tests/unit/test_makefile_bench.py"

# I5Q (#327): the orphan sweep took off a deleted VM's deny that was the last thing keeping the
# attacker out of the VM given its address and NSG — one of our rules, turned into an allow by
# someone, let them past the perimeter block (I5, seed 101 at 500). Such a deny stays, said.
# Measured by the sequences frozen in test_invariant_regressions.py, then the machine. M1730–M1733.
RDR = "glorfindel/providers/azure/readers.py"
_I5Q = ("tests/unit/test_invariant_regressions.py::test_the_sequence_the_machine_found_on_i5_after_an_address_reused "
        "tests/unit/test_invariant_regressions.py::test_an_orphan_deny_behind_a_turned_rule_stays_said_then_goes "
        "tests/unit/test_orphan_sweep.py::test_an_orphan_deny_behind_our_rule_turned_into_an_allow_stays "
        "tests/unit/test_orphan_sweep.py::test_a_card_said_before_the_turn_is_replaced_by_one_naming_it")
MUTANTS += [
    ("M1730", "the orphan sweep reads no rule turned into an allow: the deny behind it taken off, the VM opened (I5Q)",
     SWP, "        turned = _turned_allows(listing)      # our rules someone turned into an allow (I5Q)\n",
     "        turned = []\n"),
    ("M1731", "a turned rule counted on the other side only: the inbound deny behind an inbound allow taken off (I5Q)",
     "glorfindel/providers/azure/turned.py",
     '            if t_side == side and governs(h, nsg_key, subnets) and _takes_in(values, h["ip"]):\n',
     '            if t_side != side and governs(h, nsg_key, subnets) and _takes_in(values, h["ip"]):\n'),
    ("M1732", "a turned rule aimed at `*` (the perimeter's) read as aimed at no one (I5Q)", "glorfindel/providers/azure/nsg.py",
     '        if v.strip().lower() in ("*", "any"):\n            return True\n',
     '        if v.strip().lower() in ("*", "any"):\n            continue\n'),
    ("M1733", "a turned rule on the subnet's NSG not counted: only the NIC's own NSG read (I5Q)", "glorfindel/providers/azure/turned.py",
     '        return nic_nsg.get(nid) == nsg_key or bool(nic_subnets.get(nid, set()) & subnets)\n',
     "        return nic_nsg.get(nid) == nsg_key\n"),
]
TESTS.update({mid: f"{_I5Q} {INVARIANTS}" for mid in ("M1730", "M1731", "M1732", "M1733")})
# The same hole on a deleted VM's release (found by the machine once its composite rule was added,
# seed 322 at 500: I4). M1734–M1736.
_I5Q_REL = ("tests/unit/test_invariant_regressions.py::test_a_deleted_vms_deny_behind_a_turned_rule_stays_with_its_release "
            "tests/unit/test_invariant_regressions.py::test_a_live_vms_release_is_not_held_by_its_own_turned_rule")
MUTANTS += [
    ("M1734", "a deleted VM's release takes its placements' denies off, a turned rule behind them: the new VM opened (I5Q)",
     REL, '                        _held_by_turned(self._network, turned, p_rg, p_name, name, p.get("nic_id", ""))\n'
          "                        or self._delete_rule(p_rg, p_name, name)\n",
     "                        self._delete_rule(p_rg, p_name, name)\n"),
    ("M1735", "a deleted VM's release, its state lost, takes its denies off everywhere, a turned rule behind (I5Q)",
     REL, "                    if why := held_back(nsg, r):\n", "                    if False and (why := held_back(nsg, r)):\n"),
    ("M1736", "a live VM's release held by its own turned rule: `release_partial` forever (I5Q)", "glorfindel/providers/azure/turned.py",
     '               if ip in holders and holders[ip] != own.rstrip("/").lower()\n',
     "               if ip in holders\n"),
]
TESTS.update({mid: f"{_I5Q_REL} {INVARIANTS}" for mid in ("M1734", "M1735", "M1736")})
# The card two orphan rules share, closed when one goes while the other stays kept (seed 101
# after RB1: the deny kept behind a turned rule, no longer said). M1737.
MUTANTS += [
    ("M1737", "an orphan rule taken off resolves the card it shares with a rule still kept: not said (I5Q)",
     "glorfindel/orphans.py",
     "                if card and _pending(card) and card not in alerts.values():   # shared: still said (I5Q)\n",
     "                if card and _pending(card):\n"),
]
TESTS["M1737"] = ("tests/unit/test_orphan_sweep.py::test_a_card_two_rules_share_stays_open_while_one_stands "
                  f"{INVARIANTS}")
# The review of I5Q: a card said before the turn, never written again, still told to delete the
# kept deny; the listing a pass old; a live VM's release held when the listing is refused. M1738–M1743.
TRN = "glorfindel/providers/azure/turned.py"
_I5Q_CARD = ("tests/unit/test_orphan_sweep.py::test_a_card_said_before_the_turn_is_replaced_by_one_naming_it "
             f"{INVARIANTS}")
_I5Q_RACE = "tests/unit/test_orphan_sweep.py::test_a_rule_turned_after_the_listing_stops_the_removal"
MUTANTS += [
    ("M1738", "a card said before the turn is kept: it still says to delete the deny that holds the VM shut (I5Q)",
     "glorfindel/orphans.py",
     '            if not all(_names(said.get(card, ""), g) for g in group[res]):\n',
     '            if False:\n'),
    ("M1739", "the card of a kept deny says to delete it, its only step (I5Q)", "glorfindel/orphans.py",
     '        mates = group.get(_resource(o).lower(), []) if o.get("turned") else []\n',
     '        mates = []\n'),
    ("M1740", "the rules of a VM said again in any order: the card they share keeps the delete of the first (I5Q)",
     "glorfindel/orphans.py", '    orphans = sorted(orphans, key=lambda o: not o.get("turned"))\n',
     "    orphans = list(orphans)\n"),
    ("M1741", "the removal trusts the listing: a rule turned since, the deny taken off (I5Q)", SWP,
     '        why = self._held_reason(orphan.get("cut") or [], self._held_vms()) or _turned_still(self._network, orphan)\n',
     '        why = self._held_reason(orphan.get("cut") or [], self._held_vms())\n'),
    ("M1742", "an NSG not read again before the removal read as holding no turned rule (I5Q)", TRN,
     "            return f\"NSG {k.rsplit('/', 1)[-1]} non relu avant le retrait ({_first_line(exc)[:_ERR_MAX]})\"\n",
     "            continue\n"),
    ("M1743", "a live VM's release held by a refused listing: its own placement kept (I5Q)", TRN,
     "            if nic_id and _holds_all(network, nsg_rg, nsg_name, name, nic_id):\n",
     "            if False:\n"),
]
MUTANTS += [
    ("M1744", "a card « names » the turned rule by a substring: the perimeter's name begins every VM rule (I5Q)",
     "glorfindel/orphans.py",
     "    return f\"notre règle {o['turned']['rule']} (\".lower() in text.lower()\n",
     "    return o['turned']['rule'].lower() in text.lower()\n"),
    ("M1745", "the card of a VM names only the turned rule of its first kept deny (I5Q, seed 31337)",
     "glorfindel/orphans.py",
     '        mates = group.get(_resource(o).lower(), []) if o.get("turned") else []\n',
     '        mates = [o] if o.get("turned") else []\n'),
]
_I5Q_CARD += (" tests/unit/test_orphan_sweep.py::test_the_card_of_a_vm_names_every_rule_its_kept_denies_wait_behind"
              " tests/unit/test_invariant_regressions.py::test_a_card_names_the_turned_rule_by_its_whole_name"
              " tests/unit/test_orphan_sweep.py::test_a_card_naming_a_vm_rule_of_the_ip_is_no_card_naming_the_perimeter")
TESTS.update({mid: _I5Q_CARD for mid in ("M1738", "M1739", "M1740", "M1744", "M1745")})
TESTS.update({mid: _I5Q_RACE for mid in ("M1741", "M1742")})
TESTS["M1743"] = "tests/unit/test_invariant_regressions.py -k live_vms_release"
# The second review of I5Q: a new kept deny folded into the VM's pending card, whose first reason
# stays; a live VM's placement let go on a refused listing though its NIC no longer holds the
# address. M1746–M1747.
MUTANTS += [
    ("M1746", "a new kept deny folded into the VM's stale pending card: named nowhere for a pass (I5Q)",
     "glorfindel/orphans.py",
     '        for card in ({alerts.get(f"orphan-{o[\'nsg_id\']}/{o[\'rule\']}".lower())} | pending_of.get(res, set())) - {None}:\n',
     '        for card in ({alerts.get(f"orphan-{o[\'nsg_id\']}/{o[\'rule\']}".lower())} | set()) - {None}:\n'),
    ("M1747", "a refused listing lets a live VM's deny go though its NIC moved off the address (I5Q)",
     "glorfindel/providers/azure/turned.py",
     "            if nic_id and _holds_all(network, nsg_rg, nsg_name, name, nic_id):\n",
     "            if nic_id and network.network_interfaces.get(*_parse_nic_resource_id(nic_id)) is not None:\n"),
]
TESTS["M1746"] = ("tests/unit/test_orphan_sweep.py::test_a_new_kept_deny_never_merges_into_a_stale_card_of_its_vm "
                  f"{INVARIANTS}")
TESTS["M1747"] = "tests/unit/test_invariant_regressions.py -k live_vms_release"
# ID1 (#281): the bench's diagnostic settings, off by default, switched by a variable, the
# categories the rules read and no other, the Make targets that touch them alone. M1790–M1799,
# measured by tests/unit/test_bench_logs.py (and infra/terraform/tests/, by hand).
_TFV = "infra/terraform/variables.tf"
_TFA = "infra/terraform/activity_log.tf"
_TFE = "infra/terraform/entra_logs.tf"
MUTANTS += [
    ("M1790", "the subscription's Activity Log sent by default (ID1)", _TFV,
     '  description = "Journal d\'activité de l\'abonnement (catégorie Administrative) → le workspace du banc : '
     'la table AzureActivity des règles d\'AL1. Droit : écrire un paramètre de diagnostic sur l\'abonnement '
     '(Monitoring Contributor). Défaut false."\n  type        = bool\n  default     = false\n',
     '  description = "Journal d\'activité de l\'abonnement (catégorie Administrative) → le workspace du banc : '
     'la table AzureActivity des règles d\'AL1. Droit : écrire un paramètre de diagnostic sur l\'abonnement '
     '(Monitoring Contributor). Défaut false."\n  type        = bool\n  default     = true\n'),
    ("M1791", "the whole tenant's Entra logs sent by default (ID1)", _TFV,
     'pas un rôle Azure. Défaut false."\n  type        = bool\n  default     = false\n',
     'pas un rôle Azure. Défaut false."\n  type        = bool\n  default     = true\n'),
    ("M1792", "an ephemeral stack poses the subscription's setting too: a second one, duplicate rows (ID1)",
     _TFA, '  activity_log_enabled = var.activity_log_enabled && local.instance == "default"',
     "  activity_log_enabled = var.activity_log_enabled"),
    ("M1793", "an ephemeral stack poses the tenant's setting too (ID1)",
     _TFE, '  entra_logs_enabled = var.entra_logs_enabled && local.instance == "default"',
     "  entra_logs_enabled = var.entra_logs_enabled"),
    ("M1794", "Defender's alerts sent with the Activity Log, read by no rule (ID1)", _TFA,
     '  enabled_log {\n    category = "Administrative"\n  }\n',
     '  enabled_log {\n    category = "Administrative"\n  }\n\n  enabled_log {\n    category = "Security"\n  }\n'),
    ("M1795", "every user's interactive sign-ins sent, read by no rule, billed per GB (ID1)", _TFE,
     '  enabled_log {\n    category = "AuditLogs"\n  }\n',
     '  enabled_log {\n    category = "AuditLogs"\n  }\n\n  enabled_log {\n    category = "SignInLogs"\n  }\n'),
    ("M1796", "the service principals' sign-ins not sent: entra-sp-unusual-signin blind (ID1)", _TFE,
     '\n  enabled_log {\n    category = "ServicePrincipalSignInLogs"\n  }\n', "\n"),
    ("M1797", "make celebrimbor-logs-plan plans the whole bench: a pending drift in the logs' plan (ID1)", MAKE,
     "plan) $(LOGS_TARGETS)\n", "plan)\n"),
    ("M1798", "make celebrimbor-logs-up applies without confirmation, plan never read (ID1)", MAKE,
     "apply$(if $(YES), -auto-approve),plan)", "apply -auto-approve,plan)"),
    ("M1799", "make celebrimbor-logs-* on an ephemeral instance: a plan that says nothing (ID1)", MAKE,
     '\t@if [ "$(INSTANCE)" != "default" ]; then \\\n'
     "\t   echo \"!! $@ : instance '$(INSTANCE)' refusée",
     '\t@if false; then \\\n'
     "\t   echo \"!! $@ : instance '$(INSTANCE)' refusée"),
]
TESTS.update({f"M{n}": "tests/unit/test_bench_logs.py" for n in range(1790, 1800)})
# BL1 (#280): the time to contain and the share contained alone, computed from a campaign's
# traces (analysis/containment.py), the declared campaign (annatar/campaign/declared.py), and the
# console's overview on the same definition. M1770–M1789.
CTN = "analysis/containment.py"
DCL = "annatar/campaign/declared.py"
MUTANTS += [
    ("M1770", "the time to contain ends at the cycle's line, written after the read-back (BL1)", CTN,
     '    return decision["verified_at"] if decision["verified_at"] is not None else decision["at"]\n',
     '    return decision["at"]\n'),
    ("M1771", "the time to contain starts at the detection, not at the injector's T0 (BL1)", CTN,
     "        inc.time_to_contain_s = time_to_contain(t0, d)\n",
     '        inc.time_to_contain_s = time_to_contain(d["seen_at"] or t0, d)\n'),
    ("M1772", "an action whose check failed or could not be read counted contained (BL1)", CTN,
     '        if decision["verified"] is True and not decision["unverified"]:\n',
     '        if decision["verified"] is not False:\n'),
    ("M1773", "an action verified true but said unverifiable counted contained (BL1)", CTN,
     '        if decision["verified"] is True and not decision["unverified"]:\n',
     '        if decision["verified"] is True:\n'),
    ("M1774", "an action a guard held said escalated: the guard is lost (BL1)", CTN,
     "    if kind in GUARD_TYPES:\n        return HELD, kind\n",
     "    if False:\n        return HELD, kind\n"),
    ("M1775", "an action that failed on Azure said escalated: the card's type not read (BL1, review)", CTN,
     "    if status in FAILED_TYPES or kind in FAILED_TYPES:\n",
     "    if status in FAILED_TYPES:\n"),
    ("M1776", "a missed run with a decision lying around counted contained (BL1)", CTN,
     '    if detection == "missed":\n        return Incident(**base, outcome=MISSED)\n', ""),
    ("M1777", "a share with unknown decisions not said to be a lower bound (BL1)", CTN,
     "        return any(i.outcome == UNKNOWN for i in self.incidents)\n",
     "        return False\n"),
    ("M1778", "an isolation the reassertion says gone still counted contained alone (BL1)", CTN,
     "        if card is not None:\n            inc.outcome, inc.why = NOT_HOLDING",
     "        if False:\n            inc.outcome, inc.why = NOT_HOLDING"),
    ("M1779", "a card after the run's window (a later run's) undoes a containment (BL1)", CTN,
     "             and (t := _ts(c.get(\"timestamp\"))) is not None and since <= t <= until]\n",
     "             and (t := _ts(c.get(\"timestamp\"))) is not None and since <= t]\n"),
    ("M1780", "the share over the detected runs only: a missed one leaves the denominator (BL1)", CTN,
     "        return len(self.contained) / len(self.incidents) if self.incidents else None\n",
     "        return len(self.contained) / len([i for i in self.incidents if i.outcome != MISSED]) "
     "if self.incidents else None\n"),
    ("M1781", "the time to contain a mean, not a median (BL1)", CTN,
     "        return round(statistics.median(self.times), 1) if self.times else None\n",
     "        return round(statistics.mean(self.times), 1) if self.times else None\n"),
    ("M1782", "a fault taken for an attack only when the isolation was executed (BL1)", CTN,
     '        if d["event"] != "detection" or d["action"] not in DISRUPTIVE:\n            continue\n'
     '        if d["signal_id"]',
     '        if d["event"] != "detection" or d["action"] not in DISRUPTIVE or d["executed"] is not True:\n'
     '            continue\n        if d["signal_id"]'),
    ("M1783", "a decision on another VM during a fault counted as the fault's (BL1)", CTN,
     '        if not any(_same(d["resource_id"], t) for t in targets):\n            continue\n', ""),
    ("M1784", "a decision long after the fault counted as the fault's (BL1)", CTN,
     '        if d["seen_at"] is None or not start <= d["seen_at"] <= until:\n',
     '        if d["seen_at"] is None or d["seen_at"] < start:\n'),
    ("M1785", "a declared campaign with a fault and a response outside the bench (BL1)", DCL,
     '    if d.zone != "bench":\n', "    if False:\n"),
    ("M1786", "a home-grown script accepted in a declared campaign (BL1)", DCL,
     '            if (entry.get("engine") or "local-script") == "local-script":\n',
     '            if entry.get("engine") == "local-script":\n'),
    ("M1787", "a declared fault on other VMs than the campaign's (BL1)", DCL,
     "    if not names or not names <= {t.lower() for t in targets}:\n",
     "    if not names:\n"),
    ("M1788", "campaign plan --declared on a target the declaration does not name (BL1)", ACLI,
     "        if vm not in {t.lower() for t in decl.targets}:\n", "        if False:\n"),
    ("M1789", "the console's cycles without the read-back time: the overview ends at the line (BL1)",
     CON,
     '        "verified_at": outcome.get("verified_at"),\n', ""),
]
TESTS.update({f"M{n}": "tests/unit/test_containment.py" for n in range(1770, 1785)})
TESTS.update({f"M{n}": "tests/unit/test_campaign_declared.py" for n in range(1785, 1789)})
TESTS["M1789"] = "tests/unit/test_indicators.py"

# BL1, after its 5.5 review: a card about a release, the watch after a lifting, a decision for two
# incidents, the fault's zone, a decision of the campaign's technique taken for the fault, the
# read-back's stamp. M1910–M1919.
MUTANTS += [
    ("M1910", "a check that failed after an approved release says the isolation did not hold (BL1)", CTN,
     '             and (c.get("action") in DISRUPTIVE or c.get("escalation_type") == "bypassed")\n', ""),
    ("M1911", "a release the reassertion says interrupted says the isolation did not hold (BL1)", CTN,
     '             and not str(c.get("reason") or "").startswith(RELEASE_SAID)\n', ""),
    ("M1912", "the watch of a containment runs on past its release (BL1)", CTN,
     "        if lifted is not None:\n            end = min(end, lifted)\n",
     "        if False:\n            end = min(end, lifted)\n"),
    ("M1913", "a declared fault whose experiment runs outside the bench accepted (BL1)", DCL,
     '    if declared.get("zone") != "bench":\n', "    if False:\n"),
    ("M1914", "a decision on the campaign's technique, in its run's window, taken for the fault (BL1)", CTN,
     '        if any(d["ttp"] == ttp and (not vm or _same(d["resource_id"], vm))',
     '        if False and any(d["ttp"] == ttp and (not vm or _same(d["resource_id"], vm))'),
    ("M1915", "one decision counted for two incidents (BL1)", CTN,
     "        if sid and sid in owner:\n", "        if False:\n"),
    ("M1916", "verified_at stamped without a read-back (BL1)", "glorfindel/agent.py",
     '    if verification.get("verified") is not None:\n', "    if True:\n"),
    ("M1917", "a release held taken for a lifting (BL1)", CTN,
     '    if d["executed"] is False:          # a release held',
     '    if False:          # a release held'),
    ("M1918", "the operator's manual actions never end a watch (BL1)", CTN,
     '    paths = [Path(runs_dir) / "manual_actions.jsonl", *sorted(',
     "    paths = [*sorted("),
    ("M1919", "the overview never reads the operator's releases (BL1)", CON,
     "        if lift is not None and lift[1] is not None and lift[1] >= since:\n",
     "        if False:\n"),
]
TESTS.update({f"M{n}": "tests/unit/test_containment.py" for n in (1910, 1911, 1912, 1914, 1915, 1916, 1917, 1918)})
TESTS["M1913"] = "tests/unit/test_campaign_declared.py"

# BL1, second review: a lifting paired with the containment it lifts and only in full, and the
# reassertion's own words RELEASE_SAID reads, pinned. M1924–M1926 (M1917–M1919 taken above).
MUTANTS += [
    ("M1924", "an unblock ends the watch of an isolation (BL1, second review)", CTN,
     "             and action in lifts and _same(rid, resource_id)]\n",
     "             and _same(rid, resource_id)]\n"),
    ("M1925", "a partial lifting ends the watch: a card after it hidden (BL1, second review)", CTN,
     '    if d["status"] in PARTIAL or d["verified"] is False:\n        return None\n', ""),
    ("M1926", "the reassertion rewords an interrupted release: RELEASE_SAID no longer matches (BL1)",
     "glorfindel/reassert.py",
     'reason = (f"La levée de l\'isolation de {vm} a été interrompue (commencée le "',
     'reason = (f"Levée de l\'isolation de {vm} interrompue (commencée le "'),
]
TESTS.update({f"M{n}": "tests/unit/test_containment.py" for n in (1924, 1925, 1926)})
TESTS["M1919"] = "tests/unit/test_indicators.py"


# C1 (#80): the run, unified (eregion_core/run_report.py), the coverage matrix and its
# non-regression (eregion_console/coverage.py), fed to the indicators and shown. M1800–M1825.
RRC = "eregion_core/run_report.py"
COV = "eregion_console/coverage.py"
_C1_COV = "tests/unit/test_coverage.py"
_C1_RR = "tests/unit/test_run_report.py"
MUTANTS += [
    ("M1800", "an Annatar run no longer says what it is: the run format guessed again (C1)",
     "annatar/runner/engine.py",
     '        metrics.update(run_report.identity("technique", "annatar", scenario.mitre, emitter.resource_id))\n', ""),
    ("M1801", "an Atomic run no longer says what it is (C1)", "annatar/runner/engine.py",
     '            **run_report.identity("technique", "annatar", scenario.mitre, emitter.resource_id),   # C1\n', ""),
    ("M1802", "a fault run no longer says what it is (C1)", "gothmog/runner/engine.py",
     '                           metrics={**run_report.identity("fault", "gothmog", fault.get("id")),  # C1\n',
     '                           metrics={"injector": "gothmog",\n'),
    ("M1803", "the run's own kind ignored: a report read by the guess of before C1", RRC,
     "    if m.get(\"kind\") in KINDS:\n        return m[\"kind\"]\n", ""),
    ("M1804", "an isolation executed but not verified counts as contained (C1)", RRC,
     '        if out["action"] in CONTAINING and out["executed"] is True and out["verified"] is True:\n',
     '        if out["action"] in CONTAINING and out["executed"] is True:\n'),
    ("M1805", "the matrix drops the time to contain of a row (C1)", COV,
     '        "detect_s": t["detect_s"], "decide_s": t["decide_s"], "contain_s": t["contain_s"],\n',
     '        "detect_s": t["detect_s"], "decide_s": t["decide_s"], "contain_s": None,\n'),
    ("M1806", "a detection without a decision attached counts as a proof (C1)", COV,
     '    return outcome(run) == "detected" and decision_of(run, cycles) is not None\n',
     '    return outcome(run) == "detected"\n'),
    ("M1807", "no « aging » between 21 and 30 days: a proof is proven up to 30 (C1)", COV,
     '        return "proven" if age < AGING_DAYS * DAY else "aging" if age <= STALE_DAYS * DAY else "stale"\n',
     '        return "proven" if age <= STALE_DAYS * DAY else "stale"\n'),
    ("M1808", "the indicator's last proof stays on 30 days: older, it says « none » (C1)", COV,
     '    indicators["last_proof"] = m["last_proof"]\n', ""),
    ("M1809", "the non-regression never fires: a technique proven then missed stays proven (C1)", COV,
     '    if not measured or outcome(measured[-1]) != BAD[measured[-1]["kind"]]:\n',
     "    if True:\n"),
    ("M1810", "an unknown detection taken for a miss: a run that measured nothing regresses (C1)", COV,
     '    return run["detection"] if run["detection"] in ("detected", "missed") else "unknown"\n',
     '    return run["detection"] if run["detection"] == "detected" else "missed"\n'),
    ("M1811", "any miss in the history regresses, even detected again since (C1)", COV,
     '    if not measured or outcome(measured[-1]) != BAD[measured[-1]["kind"]]:\n',
     '    if not any(outcome(r) == BAD[r["kind"]] for r in measured):\n'),
    ("M1812", "a technique never detected said regressed (C1)", COV,
     "    if not good:\n        return None\n", "    if not good:\n        good = measured[:1]\n"),
    ("M1813", "a fault PASS --without-glorfindel counts as a proof of Glorfindel (C1)", COV,
     '        if run["without_glorfindel"]:\n            return "not_measured"\n        return "pass"',
     '        return "pass"'),
    ("M1814", "a fault refused (nothing ran) taken for a failure: a regression (C1)", COV,
     '        if run["result"] == "REFUSED":\n            return "refused"\n', ""),
    ("M1815", "the evolution counts every run before the point, not its 30 days (C1)", COV,
     '        window = [r for r in seen if r["at"] > t - WINDOW_DAYS * DAY]\n',
     "        window = seen\n"),
    ("M1816", "the indicators are not fed by the matrix: no regression said, no proof over 30 days (C1)",
     CON, "        return coverage.feed(out, coverage_matrix(t))\n", "        return out\n"),
    ("M1817", "`eregion coverage --check` never fails: the non-regression silent (C1)",
     "eregion_console/cli.py", "    if check and regressed:\n", "    if False:\n"),
    ("M1818", "a planned technique never run counted as a gap of the proof (C1)", COV,
     '    counted = [r for r in rows if r["status"] == "implemented" or r["runs"]]\n',
     "    counted = rows\n"),
    ("M1819", "a run outside the catalog vanishes from the matrix (C1)", COV,
     '    rows = [row(e, by_key.get((e["kind"], e["id"]), []), cycles, now) for e in entries + outside]\n',
     '    rows = [row(e, by_key.get((e["kind"], e["id"]), []), cycles, now) for e in entries]\n'),
    ("M1820", "a campaign's runs lose their campaign (C1)", RRC,
     '        campaign = parent.parent.name if parent.name == "runs" and parent.parent.parent.name == "campaigns" else ""\n',
     '        campaign = ""\n'),
    ("M1821", "a date no calendar holds taken as a date: one forged report breaks the page (C1)", RRC,
     "    if at is None or iso(at) is None:   # a date no calendar holds is no date\n",
     "    if at is None:\n"),
    ("M1822", "Annatar's and Gothmog's pages show the catalog, not the matrix (C1)",
     "eregion_console/static/injector.js",
     "async function refreshCatalog() { await load('cat', `/api/coverage?kind=${ABOUT.kind}`, renderCatalog); }",
     "async function refreshCatalog() { await load('cat', `/api/catalog?kind=${ABOUT.kind}`, renderCatalog); }"),
    ("M1823", "the verification's own time dropped from the watch's cycle (C1, for BL1)", CON,
     '        "verified_at": outcome.get("verified_at"),\n', ""),
    ("M1824", "the time to contain ends at the record, the verification's time ignored (C1)", RRC,
     '            contained = verified_at if verified_at is not None else out["decided_at"]\n',
     '            contained = out["decided_at"]\n'),
    ("M1825", "/api/coverage takes any kind (C1)", CON,
     '    if kind not in ("", "technique", "fault"):\n        return {"error": "kind: technique or fault"}\n',
     ""),
]
TESTS.update({f"M{n}": _C1_COV for n in range(1805, 1826)})
TESTS.update({"M1800": "tests/unit/test_engine.py -k unified", "M1801": "tests/unit/test_annatar_atomic.py -k unified",
              "M1802": "tests/unit/test_gothmog.py -k unified", "M1803": _C1_RR, "M1804": _C1_RR,
              "M1820": f"{_C1_RR} {_C1_COV}", "M1821": _C1_RR, "M1824": _C1_RR})
# C1, after its review (30/10): the future left out, the decision attached on the run's VM and
# closest, the faults that never started, the caches, the CLI's text. M1826–M1829, M1880–M1889.
MUTANTS += [
    ("M1826", "the decision of another VM attached to the run (C1, review)", IND,
     '             if not vm or str(c.get("resource_id") or "").lower() == vm]\n',
     "             if True]\n"),
    ("M1827", "among several records, the oldest taken, not the closest to the detection (C1, review)", IND,
     "    best = min(found, key=lambda tc: (abs(tc[0] - seen_at), tc[0]))[1] if found else None\n",
     "    best = min(found, key=lambda tc: tc[0])[1] if found else None\n"),
    ("M1828", "a run filed under one technique takes the decision of another (C1, review)", IND,
     '    if run.get("experiment", run["ttp"]) != run["ttp"]:\n        return None\n', ""),
    ("M1829", "a run dated in the future kept: a missed of 2076 regresses for ever (C1, review)", COV,
     '    runs = [r for r in runs if r["at"] <= now + FUTURE_SKEW_S]\n', ""),
    ("M1880", "a fault whose start failed taken for a failure: a regression (C1, review)", COV,
     '        if run.get("started") is False:   # its start failed: nothing was injected\n'
     '            return "not_started"\n', ""),
    ("M1881", "a deleted report kept in the cache for ever (C1, review)", RRC,
     "    for gone in [p for p in list(_report_cache) if p not in seen]:   # two requests can evict at once\n"
     "        _report_cache.pop(gone, None)\n", ""),
    ("M1882", "a deleted debug file kept in the cycles' cache for ever (C1, review)", CON,
     "    for gone in set(list(_cycle_cache)) - set(paths):   # a file deleted is dropped from the cache (C1)\n"
     "        _cycle_cache.pop(gone, None)   # two requests (threads) can evict at once\n", ""),
    ("M1883", "the cached matrix served after a new report (C1, review)", CON,
     "    return (tuple(sorted(stat(p) for p in reports.values())),\n",
     "    return ((),\n"),
    ("M1884", "the overview's time to contain measured apart from timeline (C1, review; BL1's path)", IND,
     '            if inc.time_to_contain_s is not None:\n                contain.append(inc.time_to_contain_s)\n',
     '            if (decided := _ts(d.get("at"))) is not None and decided >= r["at"]:\n'
     '                contain.append(decided - r["at"])\n'),
    ("M1885", "the indicators count a run dated in the future (C1, review)", CON,
     '        runs = [r for r in runs if r["at"] <= t + coverage.FUTURE_SKEW_S]\n', ""),
    ("M1886", "`eregion coverage` prints a report's control characters to the terminal (C1, review)",
     "eregion_console/cli.py",
     '    return "".join(ch for ch in str(value) if ch.isprintable())\n', "    return str(value)\n"),
    ("M1887", "an Annatar run no longer names its VM: the decision of any VM attached (C1, review)",
     "annatar/runner/engine.py",
     '        metrics.update(run_report.identity("technique", "annatar", scenario.mitre, emitter.resource_id))\n',
     '        metrics.update(run_report.identity("technique", "annatar", scenario.mitre))\n'),
    ("M1888", "runs of the same second ordered by the order they were read in (C1, review)", COV,
     '    runs = sorted(runs, key=lambda r: (r["at"], r["run_id"]))\n',
     '    runs = sorted(runs, key=lambda r: r["at"])\n'),
    ("M1889", "a fault's failed start not read from its checks (C1, review)", RRC,
     '        "started": (checks.get("fault_started") == "PASS")\n', '        "started": None and (checks.get("fault_started") == "PASS")\n'),
]
TESTS.update({mid: _C1_COV for mid in ("M1826", "M1827", "M1828", "M1829", "M1880", "M1881", "M1882",
                                        "M1883", "M1885", "M1886", "M1888", "M1889")})
TESTS.update({"M1884": "tests/unit/test_indicators.py", "M1887": "tests/unit/test_engine.py -k unified"})

# L2Q (#331, M1860–M1879): a quarantine change that comes back is said again — only the
# operator's last word on it silences it, never quarantine_alerts.json alone (seed 101).
_L2Q = " ".join(f"tests/unit/test_reassert.py::test_{t}" for t in (
    "a_change_that_comes_back_after_its_record_was_lost_is_said_again",
    "a_change_whose_card_could_not_be_written_leaves_the_former_unsilenced",
    "only_the_operators_last_word_silences_a_change", "an_acknowledgement_is_read_on_its_own_nsg_only",
    "a_change_brought_back_by_an_unreadable_config_is_said_and_so_is_the_config",
    "an_acknowledged_card_stays_closed_while_its_change_stands"))
MUTANTS += [
    ("M1860", "a change that comes back read « said » from quarantine_alerts.json alone (L2Q, seed 101)", RQ,
     "        if signal_id in said or (alerts.get(k) == signal_id and acknowledged(k, signal_id)):\n",
     "        if signal_id in said or alerts.get(k) == signal_id:\n"),
    ("M1861", "Glorfindel's closure of a quarantine card carries no note: read as the operator's (L2Q)", RQ,
     '            escalations.resolve(e["id"], note=_CHANGED if k in altered else _SETTLED)\n',
     '            _resolve(e["id"], note="")\n'),
    ("M1862", "a card closed because its change moved carries no note: read as acknowledged (L2Q)", RQ,
     '            escalations.resolve(e["id"], note=_CHANGED if k in altered else _SETTLED)\n',
     '            escalations.resolve(e["id"], note="" if k in altered else _SETTLED)\n'),
    ("M1863", "the operator's word on another change silences this one (L2Q)", RQ,
     '        return (last is not None and last.get("signal_id") == signal_id\n',
     "        return (last is not None\n"),
    ("M1864", "the NSG's first card read, not its latest: an old acknowledgement silences a return (L2Q)", RQ,
     '        last = next((e for e in reversed(history) if _key(e.get("resource_id")) == k), None)\n',
     '        last = next((e for e in history if _key(e.get("resource_id")) == k), None)\n'),
    ("M1865", "a card Glorfindel closed itself read as acknowledged (L2Q)", RQ,
     '                and last.get("status") == "resolved" and not last.get("resolution"))\n',
     '                and last.get("status") == "resolved")\n'),
    ("M1866", "the latest card of any NSG read for this one's acknowledgement (L2Q)", RQ,
     '        last = next((e for e in reversed(history) if _key(e.get("resource_id")) == k), None)\n',
     "        last = next(iter(reversed(history)), None)\n"),
]
TESTS["M1860"] = ("tests/unit/test_invariant_regressions.py::"
                  "test_an_altered_quarantine_stays_said_when_its_change_comes_back "
                  "tests/unit/test_invariant_regressions.py::test_a_quarantine_change_brought_back_after_a_full_disk_is_said "
                  f"{_L2Q} {INVARIANTS}")
TESTS.update({f"M{n}": _L2Q for n in range(1861, 1867)})
# AWS1 (#334): the oracle of I2 on AWS, not the adapter. It left out of the customer's ACL
# entries any entry at a key Glorfindel once wrote, so the customer's entry at a number
# freed and taken again went missing — a false alarm, about 1 run in 24 at 500 sequences.
# By content now. Measured by the frozen sequence (tests/unit/test_invariant_regressions_aws.py).
_AWS1_ORACLE = ('            live = {key: e for key, e in self.fake.acls[k]["entries"].items()\n'
                '                    if not self._not_customers(k, key, e)}\n')
MUTANTS += [
    ("M1950", "the I2 oracle on AWS leaves out an ACL entry by its key: the customer's entry at a "
              "number Glorfindel once held reads as changed (AWS1)", AWS_INVARIANTS,
     _AWS1_ORACLE,
     '            live = {key: e for key, e in self.fake.acls[k]["entries"].items()\n'
     '                    if (k, *key) not in self.fake.authored and (k, *key) not in self.tampered}\n'),
    ("M1951", "the I2 oracle on AWS leaves that key out of both sides: the customer's entry there, "
              "changed or deleted, out of its sight (AWS1, the fix that weakens)", AWS_INVARIANTS,
     _AWS1_ORACLE + '            assert live == acl["entries"], f"I2: customer entries of {k} changed"\n',
     '            live = {key: e for key, e in self.fake.acls[k]["entries"].items()\n'
     '                    if (k, *key) not in self.fake.authored and (k, *key) not in self.tampered}\n'
     '            assert live == {key: e for key, e in acl["entries"].items() if (k, *key) not in self.fake.authored}, (\n'
     '                f"I2: customer entries of {k} changed")\n'),
]
TESTS.update({mid: "tests/unit/test_invariant_regressions_aws.py" for mid in ("M1950", "M1951")})
# AWS1: the AWS machine runs every night, its failures kept in the cached database.
MUTANTS += [
    ("M1952", "the nightly run no longer runs the AWS machine: its failures kept nowhere (AWS1)",
     ".github/workflows/invariants.yml",
     "        run: python -m pytest tests/unit/test_invariants_aws.py -q -s\n",
     "        run: echo skipped\n"),
]
MUTANTS += [
    ("M1953", "the database saved only when the night is green: a failing machine's sequence kept "
              "nowhere (AWS1, review)", ".github/workflows/invariants.yml",
     "        if: always() && matrix.os == 'ubuntu-latest'\n",
     "        if: success() && matrix.os == 'ubuntu-latest'\n"),
]
TESTS.update({mid: "tests/unit/test_workflows.py -k night_runs_both" for mid in ("M1952", "M1953")})

# L2C (#343, M1930–M1949): the other cards of the reassertion — a bypass, an unreadable
# state, the rules a block left — follow L2Q's rule: a change in the mark is silent only
# on the operator's last word on it; a change that came back is said again.
_L2C = " ".join(f"tests/unit/test_reassert.py::test_{t}" for t in (
    "a_bypass_that_comes_back_after_its_mark_was_kept_is_said_again",
    "a_bypass_back_to_its_former_change_closes_the_stale_card",
    "the_operators_word_on_another_bypass_does_not_silence_this_one",
    "a_bypass_acknowledgement_is_read_on_its_own_card_only",
    "an_unreadable_state_that_comes_back_after_its_record_was_kept_is_said_again",
    "an_unreadable_set_back_to_its_former_files_is_said_again",
    "a_changed_set_of_left_rules_gets_its_own_card", "left_rules_back_to_a_set_already_said_are_said_again",
    "a_bypassed_isolation_is_said_once_per_change_and_never_fixed",
    "a_changed_bypass_is_a_new_card_and_a_holding_isolation_closes_it"))
MUTANTS += [
    ("M1930", "a bypass that came back read « said » from its mark alone (L2C)", RCA,
     '    if mark == sid and not stale and (cards or _last_word(f"{prefix}-", sid)):\n',
     "    if mark == sid:\n"),
    ("M1931", "a bypass back to its marked change while another's card is pending: that card stays (L2C)", RCA,
     '    if mark == sid and not stale and (cards or _last_word(f"{prefix}-", sid)):\n',
     '    if mark == sid and (cards or _last_word(f"{prefix}-", sid)):\n'),
    ("M1932", "an unreadable state that came back read « said » from state_alerts.json alone (L2C)", RCA,
     '    if alerts.get("unreadable_states") == sid and (said or _last_word(_STATE_PREFIX, sid)):\n',
     '    if alerts.get("unreadable_states") == sid:\n'),
    ("M1933", "left rules back to a set already said read « said » from their mark alone (L2C)", RCA,
     '    if entry.get("left_said") == sid and not stale and (cards or _last_word(prefix, sid)):\n',
     '    if entry.get("left_said") == sid:\n'),
    ("M1934", "another set of left rules folded into the former card, which keeps naming the former (L2C)", RCA,
     '    for e in stale:\n        # Another set: the store folded its card into this one, which kept naming the\n',
     '    for e in []:\n        # Another set: the store folded its card into this one, which kept naming the\n'),
    ("M1935", "a card Glorfindel closed itself read as the operator's acknowledgement (L2C)", RCA,
     '            and last.get("status") == "resolved" and not last.get("resolution"))\n',
     '            and last.get("status") == "resolved")\n'),
    ("M1936", "the resource's first card read, not its latest: an old acknowledgement silences a return (L2C)", RCA,
     '    last = next((e for e in reversed(_history()) if (e.get("signal_id") or "").startswith(prefix)), None)\n',
     '    last = next((e for e in _history() if (e.get("signal_id") or "").startswith(prefix)), None)\n'),
    ("M1937", "the operator's word on another change silences this one (L2C)", RCA,
     '    return (last is not None and last.get("signal_id") == sid\n',
     "    return (last is not None\n"),
    ("M1938", "a bypass card closed because it holds again carries no note: read as acknowledged (L2C)", RCA,
     '            _resolve(e["id"], note="Plus contourné : le deny de Glorfindel tient de nouveau.")\n',
     '            _resolve(e["id"], note="")\n'),
    ("M1939", "an unreadable-state card closed by Glorfindel carries no note: read as acknowledged (L2C)", RCA,
     '            _resolve(e["id"], note="État local lisible de nouveau, ou autres fichiers illisibles.")\n',
     '            _resolve(e["id"], note="")\n'),
    ("M1940", "a left-rules card closed by Glorfindel carries no note: read as acknowledged (L2C)", RCA,
     '        _resolve(e["id"], note="Autres règles laissées : une nouvelle carte les dit.")\n',
     '        _resolve(e["id"], note="")\n'),
    ("M1941", "the latest bypass card of any resource read for this one's acknowledgement (L2C)", RCA,
     '    if mark == sid and not stale and (cards or _last_word(f"{prefix}-", sid)):\n',
     '    if mark == sid and not stale and (cards or _last_word(_BYPASS_PREFIX, sid)):\n'),
]
TESTS.update({f"M{n}": _L2C for n in range(1930, 1942)})
_L2C_SEQ = "tests/unit/test_invariant_regressions.py::test_{}_brought_back_after_a_full_disk_is_said"
for _mid, _what in (("M1930", "a_bypass"), ("M1932", "an_unreadable_state"), ("M1935", "a_bypass"),
                    ("M1938", "a_bypass"), ("M1939", "an_unreadable_state")):
    TESTS[_mid] = f"{_L2C_SEQ.format(_what)} {_L2C} {INVARIANTS}"

# L2C, its review (M1942–M1949): a disappearance acknowledged, held again with its mark kept
# (a full disk), then gone again — said; and the rules a block left, read on their own block.
_L2C_DRIFT = " ".join(f"tests/unit/test_reassert.py::test_{t}" for t in (
    "a_disappearance_after_one_acknowledged_and_held_again_is_said",
    "a_drift_card_closed_with_a_note_is_no_acknowledgement",
    "an_alert_closes_the_card_it_replaces_with_a_note",
    "left_rules_acknowledged_are_read_on_their_own_block_only",
    "one_alert_per_disappearance_not_one_per_minute"))
MUTANTS += [
    ("M1942", "an isolation gone again read « already said » from its drift mark alone (L2C, review)", R,
     '    if iso.get("drift_alerted_at") and drift_said(ref or vm, "", _alert_id(vm, rid)):\n',
     '    if iso.get("drift_alerted_at"):\n'),
    ("M1943", "a block gone again read « already said » from its drift mark alone (L2C, review)", R,
     "            and drift_said(ref or vm, ip, _alert_id(vm, rid, ip))):\n", "            ):\n"),
    ("M1944", "an isolation held again, its mark kept: the episode not known over (L2C, review)", R,
     '            if state.get("drift_alerted_at"):\n                episode(ref or vm, "", over=True)\n',
     '            if False:\n                episode(ref or vm, "", over=True)\n'),
    ("M1945", "a block held again, its mark kept: the episode not known over (L2C, review)", R,
     "            episode(ref or vm, ip, over=True)           # the mark may fail to go (L2C, review)\n",
     "            pass\n"),
    ("M1946", "a reassertion alert closes the card it replaces without a note: read as acknowledged (L2C, review)", R,
     '            escalations.resolve(e["id"], note="Remplacée : une nouvelle alerte de réaffirmation la suit.")\n',
     '            escalations.resolve(e["id"])\n'),
    ("M1947", "a drift card Glorfindel closed read as the operator's acknowledgement (L2C, review)", RCA,
     '    return last is not None and (last.get("status") == "pending" or not last.get("resolution"))\n',
     "    return last is not None\n"),
    ("M1948", "the latest left-rules card of any block read for this one's acknowledgement (L2C, review)", RCA,
     '    if entry.get("left_said") == sid and not stale and (cards or _last_word(prefix, sid)):\n',
     '    if entry.get("left_said") == sid and not stale and (cards or _last_word(_LEFT_PREFIX, sid)):\n'),
    ("M1949", "an episode known over stays so once a new one is marked: said again at every pass (L2C, review)", RCA,
     "    (_EPISODE_OVER.add if over else _EPISODE_OVER.discard)((key.lower(), ip))\n",
     "    if over:\n        _EPISODE_OVER.add((key.lower(), ip))\n"),
]
TESTS.update({f"M{n}": _L2C_DRIFT for n in range(1942, 1950)})
TESTS.update({f"M{n}": ("tests/unit/test_invariant_regressions.py::"
                        "test_a_disappearance_after_one_acknowledged_and_held_again_is_said_by_the_machine "
                        f"{_L2C_DRIFT} {INVARIANTS}") for n in range(1942, 1946)})

# The auditor's control set (seventh review): plausible bugs the generation was never
# shaped on. They only MEASURE whether the invariants generalise — never tailor a
# composite rule or a world event to one of them. Run with --control.
CONTROL = [
    ("C01", "unreadable config => quarantine off", QUA,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config, ConfigError\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except ConfigError:\n            return False, \"\"\n"),
    ("C02", "unreadable ownership tag => not ours", QUA,
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return True",
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return False"),
    ("C03", "isolation deny without the peer-side check", NSG,
     "    if not _side_is_any(rule, peer):\n        return False\n",
     ""),
    ("C04", "quarantine content without the DNS/IMDS denies", QUA,
     "        for rule_name, priority, tag in QUARANTINE_PLATFORM_RULES:",
     "        for rule_name, priority, tag in ():"),
    ("C05", "a stale forensic allow never purged", QUA,
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current):",
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current) and low != QUARANTINE_FORENSIC_RULE:"),
    ("C06", "block: one address of the NIC is enough", NSG,
     "    return all(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)",
     "    return any(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)"),
    ("C07", "stateless release doesn't re-read the NICs", REL,
     "        if restored:\n",
     "        if False:\n"),
    ("C08", "no foreign rule counts as an alteration", QUA,
     "                 if low not in {w.lower() for w in wanted} and _opens_quarantine(r)]",
     "                 if False]"),
    ("C09", "the release doesn't write its marker", REL,
     "            _save_isolation_state(resource_id, {**state, \"releasing_at\": datetime.now(timezone.utc).isoformat()})",
     "            pass"),
    ("C10", "the reassertion never puts a missing block back", R,
     "    if b.get(\"reasserted_at\") or _mode(autonomy, vm, ref) == \"human_only\":",
     "    if True:"),
    ("C11", "a block doesn't check the access (an allow passes)", NSG,
     "    if (_enum_text(getattr(rule, \"access\", \"\")) != \"deny\"\n            or _enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own",
     "    if (_enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own"),
    ("C12", "forensic exception dropped from the quarantine-as-block", QUA,
     "            if any(addr in ipaddress.ip_network(s, strict=False) for s in self._forensic_sources()):",
     "            if False:"),
    ("C13", "a /16 forensic source accepted", C,
     "_FORENSIC_MAX_ADDRESSES = 256",
     "_FORENSIC_MAX_ADDRESSES = 65536"),
    ("C14", "subscription guard removed from the release", AZC,
     "for _name in (\"isolate_vm\", \"release_isolation\", \"verify_isolation\", \"verify_release\",",
     "for _name in (\"isolate_vm\", \"verify_isolation\", \"verify_release\","),
    ("C15", "reassertion over a stale marker", R,
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\"):\n        return",
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\") and not _stale(iso.get(\"releasing_at\")):\n        return"),
    ("C16", "precedence ignores glorfindel-* allows", NSG,
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if direction == \"inbound\":",
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if name.startswith(\"glorfindel-\"):\n            continue\n"
     "        if direction == \"inbound\":"),
]


# MC1 — the control set on AWS: plausible bugs of the AWS adapter, written before the
# machine on AWS was shaped, never used to shape it (same discipline as C01–C16). The
# Azure figure is still counted on C01–C16 alone.
CONTROL += [
    ("M630", "the original groups only in the local state, no tag (MC1, control)", AWS_ISO,
     "        if original is not _UNKNOWN:\n            self._record_original(qid, eni, original)\n",
     "        if False:\n            self._record_original(qid, eni, original)\n"),
    ("M631", "an egress allow in the quarantine group not seen as an alteration (MC1, control)", AWS_QUA,
     """diff = [f"sortie {r.get('cidr') or r.get('group')}" for r in sg_rules(sg.get("IpPermissionsEgress"))]""",
     "diff = []"),
    ("M632", "a new quarantine group keeps its default egress (MC1, control)", AWS_QUA,
     "            if egress:\n                self._ec2.revoke_security_group_egress(",
     "            if False:\n                self._ec2.revoke_security_group_egress("),
    ("M633", "an ENI's groups written without checking what it carries (MC1, control)", AWS_NET,
     "        if not same_groups(self._eni_groups(eni_id), expect):\n            return False\n", ""),
    ("M634", "the release does not read the ENI back (MC1, control)", AWS_ISO,
     "        if not same_groups(now, original):\n            raise RuntimeError(f\"groupes d'origine non remis",
     "        if False:\n            raise RuntimeError(f\"groupes d'origine non remis"),
    ("M635", "an unknown original read as the default group (MC1, control)", AWS_ISO,
     "        if not known:\n            raise OriginalUnknown(",
     "        if not known:\n            return [self._default_sg(vpc)]\n            raise OriginalUnknown("),
    ("M636", "a block's entry numbered without looking at the customer's allows (MC1, control)", AWS_BLK,
     "n = _free_number(acl, egress, first)", "n = _free_number(acl, egress, 32767)"),
    ("M637", "an unblock removes entries another block holds (MC1, control)", AWS_BLK,
     "held = self._held_numbers(ip, acl_id, but_rid=resource_id)", "held = set()"),
    ("M638", "an unblock removes an entry whatever it says now (MC1, control)", AWS_BLK,
     "                        if not _is_our_deny(_entry(acl, egress, n), cidr):\n                            continue",
     "                        if _entry(acl, egress, n) is None:\n                            continue"),
    ("M639", "a block's entries created before they are recorded (MC1, control)", AWS_BLK,
     "            _state._save_block_state(iid, ip, resource_id, partial=True, **record)\n", ""),
    ("M640", "a block verified without the entries before it (MC1, control)", AWS_BLK,
     "            elif not (cut(acl, False, ip) and cut(acl, True, ip)):", "            elif False:"),
    ("M641", "an ENI with the quarantine group among others read as isolated (MC1, control)", AWS_ISO,
     'if q is None or not same_groups(e["groups"], [q["GroupId"]]):',
     'if q is None or q["GroupId"] not in e["groups"]:'),
    ("M642", "the account guard ignores the region (MC1, control)", AWS_CON,
     "if (self.account and account != self.account) or (self.region and region != self.region):",
     "if self.account and account != self.account:"),
    ("M643", "the release does not write its intent (MC1, control)", AWS_ISO,
     '            _state._save_isolation_state(resource_id, {**state, "releasing_at": _now()})',
     "            pass"),
    ("M644", "a group named like the quarantine adopted without its tag (MC1, control)", AWS_QUA,
     '        return bool(sg) and sg.get("GroupName") == QUARANTINE_SG_NAME and \\\n'
     '            tags_of(sg).get("managed-by") == "glorfindel"',
     '        return bool(sg) and sg.get("GroupName") == QUARANTINE_SG_NAME'),
    ("M645", "verify_release ignores an ENI that is not back on its known original (MC1, control)", AWS_ISO,
     '                if prior and not same_groups(prior, e["groups"]):\n                    pending.append(e["eni"])',
     '                if False:\n                    pending.append(e["eni"])'),
]


def _copy_repo(dest: Path) -> None:
    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    for rel in files:
        src = REPO / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)


# What the component check (scripts/component_check.py, D1) adds to the module it makes absent.
COMPONENT_ABSENT = "absent: component check"


def unmeasurable(stdout: str) -> str | None:
    """The first line of a test run saying a module could not be found, other than one the
    component check made absent on purpose (D1) — a copy that cannot import its code is no
    measure. Line by line: one module made absent must not cover another that is missing."""
    for line in stdout.splitlines():
        if "ModuleNotFoundError: No module named" in line and COMPONENT_ABSENT not in line:
            return line.strip()
    return None


def _run(copy: Path, examples: int, show: bool = False, target: str = INVARIANTS) -> bool:
    """True if `target` (test paths, space-separated) FAILS on this copy (the mutant is caught)."""
    env = {**os.environ, "GLORFINDEL_INVARIANT_EXAMPLES": str(examples), "GLORFINDEL_INVARIANT_NO_SHRINK": "1",
           "PYTHONPATH": str(copy), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *target.split(), "-q", "-x", "-p", "no:cacheprovider"],
        cwd=copy, env=env, capture_output=True, text=True)
    missing = unmeasurable(proc.stdout)
    if missing:
        raise RuntimeError(f"{missing}\n{proc.stdout[-2000:]}")
    if show and proc.returncode != 0:
        print("\n".join(line for line in proc.stdout.splitlines() if line.startswith("E ")) or proc.stdout[-3000:])
    return proc.returncode != 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--examples", type=int, default=60)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--only", default="")
    ap.add_argument("--control", action="store_true",
                    help="measure the control set (never used to shape the generation) instead")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2),
                    help="mutants measured at once")
    ap.add_argument("--min-caught", type=int, default=0,
                    help="exit 1 if fewer mutants (equivalent and multi-host aside) are caught in every round")
    args = ap.parse_args()
    only = {m.strip() for m in args.only.split(",") if m.strip()}

    with tempfile.TemporaryDirectory(prefix="glorfindel-mutants-") as tmp:
        base = Path(tmp) / "base"
        _copy_repo(base)
        todo = [m for m in (CONTROL if args.control else MUTANTS) if not only or m[0] in only]
        # The unmutated copy must pass, or nothing below means anything.
        for target in sorted({TESTS.get(m[0], INVARIANTS) for m in todo}):
            if _run(base, args.examples, show=True, target=target):
                print(f"{target} fails on the UNMUTATED code — fix that first")
                return 2
        def measure(mutant):
            mid, title, rel, old, new, *why = mutant
            copy = Path(tmp) / mid
            shutil.copytree(base, copy)
            target = copy / rel
            if old is RENAME:
                if not target.exists():
                    return mid, title, "STALE", "file to rename is gone"
                target.rename(copy / new)
            else:
                text = target.read_text()
                if isinstance(old, tuple) != isinstance(new, tuple) or (
                        isinstance(old, tuple) and len(old) != len(new)):
                    return mid, title, "STALE", "old and new replacements do not pair up"
                pairs = zip(old, new) if isinstance(old, tuple) else [(old, new)]
                for o, n in pairs:
                    if text.count(o) != 1:
                        return mid, title, "STALE", f"{text.count(o)} matches"
                    text = text.replace(o, n)
                target.write_text(text)
            started = time.monotonic()
            target = TESTS.get(mid, INVARIANTS)
            caught = sum(_run(copy, args.examples, target=target) for _ in range(args.rounds))
            # Caught by a fixed sequence only (tests/unit/test_invariant_regressions.py)?
            fixed = (caught == 0 and target == INVARIANTS
                     and _run(copy, 0, target="tests/unit/test_invariant_regressions.py"))
            shutil.rmtree(copy, ignore_errors=True)
            verdict = "CAUGHT" if caught == args.rounds else ("flaky" if caught else ("FIXED-ONLY" if fixed else "SURVIVES"))
            if why and verdict != "CAUGHT":
                verdict = why[0].split(":")[0]
            row = (mid, title, verdict, f"{caught}/{args.rounds} ({time.monotonic() - started:.0f}s)")
            print(f"{mid} {verdict:8} {row[3]:14} {title}", flush=True)
            return row

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = sorted(pool.map(measure, todo))
    print(f"\nbudget {args.examples} sequences, {args.rounds} rounds:")
    for mid, title, verdict, detail in rows:
        print(f"  {mid}  {verdict:8}  {detail:16}  {title}")
    counted = [r for r in rows if r[2] not in ("EQUIVALENT", "MULTI-HOST", "STALE")]
    caught = sum(1 for r in counted if r[2] == "CAUGHT")
    print(f"\n{caught}/{len(counted)} caught in every round (equivalent and multi-host mutants aside)")
    return 1 if caught < args.min_caught else 0


if __name__ == "__main__":
    sys.exit(main())
