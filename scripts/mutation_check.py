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
SWP = "glorfindel/providers/azure/sweep.py"
SDK = "glorfindel/providers/azure/sdk.py"
FAC = "glorfindel/actions.py"                 # the façade (A1)
PIF = "glorfindel/providers/interface.py"
R = "glorfindel/reassert.py"
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
GHTML = "eregion_console/static/glorfindel.html"
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
    '                return RunOutcome(run_id, "unknown", error=f"glorfindel: {no_watch}")\n')
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
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)',
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips[:1])'),
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
     "        failed += self._sweep_isolation(rg, vm_name, remaining)",
     "        failed += [] if state.get(\"placements\") else self._sweep_isolation(rg, vm_name, remaining)"),
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
    ("M16", "blocks verified by rule name, not content (S2)", UNB,
     "        altered = [n for n, r, d in zip(names, found, (\"inbound\", \"outbound\")) if not _deny_blocks(r, d, ip, ips)]",
     "        altered = []"),
    ("M17", "per-VM lock inoperative", AZC,
     "        with _vm_lock(rid.rstrip(\"/\").rsplit(\"/\", 1)[-1]):\n            return method(self, *args, **kwargs)",
     "        return method(self, *args, **kwargs)"),
    # Found by L26 itself (the world moving): kept so they stay found.
    ("M18", "a NIC's old-IP rule recognised by content only (L26)", NSG,
     "    if name in hashed:\n        # Only Glorfindel names a rule with a NIC's hash",
     "    if name in hashed and _deny_applies(rule, ips):\n        # Only Glorfindel names a rule with a NIC's hash"),
    ("M19", "a block verified against the IPs recorded at block time (L26)", UNB,
     "                now = current.get(nic) if current is not None and isinstance(nic, str) else None",
     "                now = None"),
    ("M20", "release asks for the original of a NIC no longer in quarantine (L26)", REL,
     "                        if now and not _same_id(now, p[\"nsg_id\"]):",
     "                        if False:"),
    ("M21", "a block counted on an NSG that no longer governs the NIC (L26)", UNB,
     '                    off = [p for p in ps if (p["nsg_rg"].lower(), p["nsg_name"].lower()) not in governing]',
     "                    off = []"),
    ("M22", "a partial release's flat fields read as a legacy state (L26)", REL,
     '        elif "placements" not in state and state.get("nsg_name") and not _is_quarantine_nsg(state["nsg_name"]):',
     '        elif state.get("nsg_name"):'),
    ("M23", "an unblock doesn't look behind the quarantine (L27)", UNB,
     "            views = self._nic_nsg_views(t0)\n            if t0.get(\"quarantine\"):",
     "            views = self._nic_nsg_views(t0)\n            if False:"),
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
    ("M38", "a block gone behind the quarantine not reported (A0, L1)", UNB,
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
     'return RunOutcome(run_id, "unknown", error=f"passive: {verdict.reasons()}")',
     'return RunOutcome(run_id, "unknown")'),
    ("M105", "a target not enrolled exits 0 (#158)", ENG,
     'return RunOutcome(run_id, "unknown", error=f"safety: {guard.reason}")',
     'return RunOutcome(run_id, "unknown")'),
    ("M106", "a dirty start (atomic) exits 0 (#158)", ENG,
     'run_id, "unknown", error="initial state not clean before the atomic"',
     'run_id, "unknown"'),
    ("M107", "an atomic the adapter refuses exits 0 (#158)", ENG,
     'return RunOutcome(run_id, "unknown", error=f"atomic: {e}")',
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
     '\t@echo "annatar campaign plan (Orodruin, max $(CAMPAIGN_MAX))" && $(ORO_SSH) ',
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
    ("M173", "the model: a confidence outside [0, 1] is kept as sent — 500 % on the card (G2 review)",
     "glorfindel/agent.py",
     "    if not math.isnan(confidence):\n        confidence = min(max(confidence, 0.0), 1.0)\n", ""),
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
     "    return _targets(window, resource_id) and live(window, when) and enrolled(resource_id)\n",
     "    return _targets(window, resource_id) and live(window, when)\n"),
    ("M223", "the run_id shortcut marks a VM its window does not name (H-1)", XW,
     '            w.get("run_id") == run_id and _targets(w, resource_id) for w in ws) \\\n',
     '            w.get("run_id") == run_id for w in ws) \\\n'),
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
     "        if isinstance(policy, ButtonPolicy) and policy.allows(interaction.user):\n",
     "        if True:\n"),
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
     "      <<: [*env, *azure, *webhook]\n", "      <<: [*env, *azure, *models, *webhook]\n"),
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
     "        await _refuse(interaction, self.esc_id, policy)\n        return False\n",
     "        await _refuse(interaction, self.esc_id, policy)\n        return True\n"),
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
     'in -*|*[!A-Za-z0-9._-]*) echo "REF invalide', 'in *[!A-Za-z0-9._-]*) echo "REF invalide'),
    ("M525", "a REF exported in the environment is deployed in silence (M-3, review)", MAKE,
     '@case "$(origin REF)" in environment*)', '@case "$(origin REF)" in nowhere*)'),
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
     '    _STORE.write_text("\\n".join(json.dumps(p) for p in updated) + "\\n")\n',
     '    proposal["status"] = "approved"\n'
     '    proposal["approved_at"] = datetime.now(timezone.utc).isoformat()\n'
     '    _STORE.write_text("\\n".join(json.dumps(p) for p in updated) + "\\n")\n'
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
     '        if not token or scope["type"] not in ("http", "websocket"):\n',
     '        if not token or scope["type"] not in ("http", "websocket") or scope.get("path") == "/annatar":\n'),
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
    ("M560", "a run takes any decision of its technique, not the one at its detection (UI-2)", IND,
     "             and (t := _ts(c.get(\"signal_at\"))) is not None and abs(t - seen_at) <= MATCH_SLACK_S]\n",
     "             and (t := _ts(c.get(\"signal_at\"))) is not None and t >= run[\"at\"]]\n"),
    ("M561", "a recommendation counts as contained alone in human-only (UI-2)", IND,
     '        if disruptive and d.get("executed") is True and d.get("verified") is True:\n',
     "        if disruptive:\n"),
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
     '    response.headers["Content-Security-Policy"] = _CSP\n', ""),
    ("M569", "glorfindel --version written by hand again: it drifts from the package (#222)", GCLI,
     '@click.version_option(package_name="eregion", prog_name="glorfindel")',
     '@click.version_option(version="0.2.0", prog_name="glorfindel")'),
    ("M570", "a new card type shows under its raw name: quarantine_altered unlabelled (#248)", GHTML,
     "  quarantine_altered:  'quarantine NSG altered',\n", ""),
    ("M571", "a control-plane card gets the anchor VM's Restore and restore command back (#248)", GHTML,
     "const _ANCHORED_TYPES = new Set(['control_plane_change', 'identity_change', 'unattributed_signal']);",
     "const _ANCHORED_TYPES = new Set(['identity_change', 'unattributed_signal']);"),
    ("M572", "a card on a quarantine NSG asks for a verdict, as if a decision (#248)", GHTML,
     "const _NOT_DECISIONS = new Set(['posture_gap', 'orphan_rule', 'quarantine_altered', 'proposed_rule',",
     "const _NOT_DECISIONS = new Set(['posture_gap', 'orphan_rule', 'proposed_rule',"),
    ("M573", "the feed loses what held a decision without action: an empty « escalate → » (#248)", CON,
     '        "held_by": data.get("held_by", ""),\n', ""),
    ("M574", "what Glorfindel closed itself stays on its tile forever (#248)", CON,
     "if (now - at).total_seconds() <= _HANDLED_FOR_H * 3600:", "if True:"),
    ("M575", "a card a human acknowledged shows as done by Glorfindel (#248)", CON,
     'if e.get("status") != "resolved" or not e.get("resolution"):', 'if e.get("status") != "resolved":'),
    ("M576", "a card's reason written raw into the page: an Entra app's name runs in the console (XSS)", GHTML,
     "line-height:1.6\">${_attr(e.reason || '')}</div>", "line-height:1.6\">${e.reason || ''}</div>"),
    ("M577", "a card's suggested steps written raw into the page (XSS)", GHTML,
     "• ${_attr(s)}</div>", "• ${s}</div>"),
    ("M578", "a card's proposed query written raw into the page (XSS)", GHTML,
     "${_attr(e.proposed_query.trim())}</pre>", "${e.proposed_query.trim()}</pre>"),
    ("M579", "an anchored card offers Restore on its anchor VM again (#248)", GHTML,
     "const isRestore = e.action === 'restore_from_backup' && !_isAnchored(e);",
     "const isRestore = e.action === 'restore_from_backup';"),
    # #254: what comes from the outside is escaped where it lands — the page's text, an on…
    # attribute (_js), a URL — and the reader (scripts/console_escaping.py) finds it raw.
    ("M580", "a feed signal's event written raw: a run's report runs in the console (#254)", GHTML,
     "${icon} ${_attr(entry.event)}</span>", "${icon} ${entry.event}</span>"),
    ("M581", "a feed action written raw: the model's invented action name runs in the console (#254)", GHTML,
     '<span class="feed-event ${cls}">${icon} ${_attr(label)}</span>', '<span class="feed-event ${cls}">${icon} ${label}</span>'),
    ("M582", "a feed entry's technique and VM written raw (#254)", GHTML,
     """      <span class="feed-meta">${_attr(entry.ttp || '')} ${_attr(entry.vm || '')}</span>\n      <span class="feed-pct">""",
     """      <span class="feed-meta">${entry.ttp || ''} ${entry.vm || ''}</span>\n      <span class="feed-pct">"""),
    ("M583", "a rule's query written raw in its window: a rule the model wrote runs in the console (#254)", GHTML,
     "${_attr((rule.query || '').trim())}", "${(rule.query || '').trim()}"),
    ("M584", "a rule's description written raw in its window (#254)", GHTML,
     "${_attr(rule.description || '—')}", "${rule.description || '—'}"),
    ("M585", "a rule's name written raw in its row (#254)", GHTML,
     '<span style="color:${dc};font-size:9px">●</span>\n      <span style="flex:1;min-width:0;overflow:hidden;'
     'text-overflow:ellipsis;white-space:nowrap" title="${_attr(r.name)}">${_attr(r.name)}</span>',
     '<span style="color:${dc};font-size:9px">●</span>\n      <span style="flex:1;min-width:0;overflow:hidden;'
     'text-overflow:ellipsis;white-space:nowrap" title="${_attr(r.name)}">${r.name}</span>'),
    ("M586", "a decision's technique written raw on the VM card (#254)", GHTML,
     '<span class="dec-ttp">${_attr(a.ttp)}</span>', '<span class="dec-ttp">${a.ttp}</span>'),
    ("M587", "a card's title written raw: the `|| e.action` fallback runs the model's text (#254)", GHTML,
     '<span class="esc-action-label">${_attr(label)}</span>', '<span class="esc-action-label">${label}</span>'),
    ("M588", "a card's title written raw in its detail (#254)", GHTML,
     'font-size:12px">${_attr(label)}</span>', 'font-size:12px">${label}</span>'),
    ("M589", "the configuration's error written raw (#254)", GHTML,
     "Failed to load config: ${_attr(e.message)}</div>", "Failed to load config: ${e.message}</div>"),
    ("M590", "a handler's argument between quotes again: a VM name with a quote runs on click (#254)", GHTML,
     'onclick="showEscModal(${_js(vmName)})"', "onclick=\"showEscModal('${vmName}')\""),
    ("M591", "the IP to block written into the handler raw (#254)", GHTML,
     "  const ipArg = ip ? `,ip:${_js(ip)}` : '';", "  const ipArg = ip ? `,ip:'${ip}'` : '';"),
    ("M592", "_attr raises on what is not a string: the card's window no longer opens (#254)", GHTML,
     "  return String(s ?? '').replace(/&/g, '&amp;')", "  return (s || '').replace(/&/g, '&amp;')"),
    ("M593", "_attr lets a tag through (#254)", GHTML, ".replace(/</g, '&lt;')", ""),
    ("M594", "_js only escapes for HTML: a quote ends the handler's string (#254)", GHTML,
     "  return _attr(JSON.stringify(String(s ?? '')));", "  return _attr(String(s ?? ''));"),
    ("M595", "the overview writes a section's label raw (#254)", "eregion_console/static/overview.html",
     "no ${esc(s.label)} window in the last 7 days", "no ${s.label} window in the last 7 days"),
    ("M596", "the reader takes `x || field` for the page's: the labels' fallback goes unseen (#254)", CESC,
     '            if node.text in ("||", "??", "+"):', '            if node.text in ("??", "+"):'),
    ("M597", "the reader takes an on… attribute for text: HTML escaping passes there (#254)", CESC,
     '        if name.startswith("on"):\n            return "js"', '        if name.startswith("on"):\n            return "html"'),
    ("M598", "the reader misses what goes into a Map: the cards' buttons go unseen (#254)", CESC,
     "                if method not in _PURE:", "                if False:"),
    ("M599", "the reader takes a promise's callback argument as the page's (#254)", CESC,
     "                if fn.escapes or not (fn.named or fn.feeds):", "                if fn.escapes:"),
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
    ("M833", "the altered quarantine's card is closed at the next pass, its change standing (I1F)", R,
     "        if k in altered and altered[k][0] == sid:\n            said.add(sid)\n"
     "        elif k in altered or settled(k):\n",
     "        if k in altered or settled(k):\n"),
    # After the review (5.5): the watch's pass, an acknowledgement, an unknown.
    ("M834", "nothing recorded: the pass reads no quarantine NSG (I1F, review)", R,
     "    report: list[dict] = []\n    _whatever_the_state(connector, autonomy, report)\n    return report\n",
     "    return []\n"),
    ("M836", "an acknowledged quarantine card comes back at every pass (I1F, review)", R,
     "        if signal_id in said or alerts.get(k) == signal_id:\n",
     "        if signal_id in said:\n"),
    ("M837", "a quarantine card closed on an NSG read as unknown (I1F, review)", R,
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
    ("M897", "a listing that fails reads as empty: every quarantine card closed (I1F, second review)", R,
     '        log.warning("reassert: quarantine NSGs not checked (%s)", exc)\n        return\n',
     '        log.warning("reassert: quarantine NSGs not checked (%s)", exc)\n        listing = []\n'),
    ("M898", "an unreadable configuration said at every pass (I1F, second review)", GCLI,
     '        if seen.get("config_error") != str(exc):\n', "        if True:\n"),
]

# I8F (#227): a bare NIC our state holds in quarantine, its original unknown — never "none".
MUTANTS += [
    ("M860", "a bare NIC isolated again records 'none' over an unknown original: released bare, an old "
             "isolation left without state (I8F, I8)", QUA,
     '                elif recorded is _UNKNOWN and prior is _UNKNOWN and _held_in_quarantine(t["nic_id"]):',
     "                elif False:"),
    ("M861", "reset skips a bare NIC whose original is unknown: swept, an old isolation left without "
             "state (I8F, I8)", SWP,
     '                if recorded is _UNKNOWN and _held_in_quarantine(t0["nic_id"]):\n'
     "                    # In quarantine for our state",
     "                if False:\n                    # In quarantine for our state"),
    ("M862", "a release drops the placement whose original is unknown: the next says released, "
             "an old isolation left without state (I8F, relecture)", REL,
     '                                          f"non détaché : {_first_line(exc)[:_ERR_MAX]}")\n'
     "                            remaining.append(p)\n",
     '                                          f"non détaché : {_first_line(exc)[:_ERR_MAX]}")\n'
     '                            if type(exc).__name__ != "OriginalUnknown":\n'
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
     "                    original, q_bare = self._bare_nic_original(t0, rg)\n"
     "                    if q_bare is not None:\n",
     "                    original, q_bare = self._bare_nic_original(t0, rg)\n"
     "                    if False:\n"),
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
     SWP, "        why = self._held_reason(orphan.get(\"cut\") or [], self._held_vms())\n",
     "        why = \"\"\n"),
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
      "        # silence (L1F, invariant machine).\n        _update_block_entry(ref or vm, ip, drift_alerted_at=now)\n"),
     ('        outcome = "failed"\n        _update_block_entry(ref or vm, ip, drift_alerted_at=now)\n'
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
      "        _update_block_entry(ref or vm, ip, drift_alerted_at=now)\n        report.append(",),
     ("        _update_block_entry(ref or vm, ip, drift_alerted_at=now)\n"
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
     "                named, tgt = True, by_rid.get(_vm_id_of(rid))",
     "                named, tgt = True, by_rid.get(rid.lower())"),
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
     "    return (any(isinstance(r, dict) and r.get(\"OperationNameValue\") for r in rows)\n"
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
     "        entra_query = _reads_entra_table(query) and not is_control_plane_source(source)",
     "        entra_query = False"),
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
TESTS["M566"] = "tests/unit/test_host_deploy.py"
TESTS["M567"] = "tests/unit/test_console.py"
TESTS["M568"] = "tests/unit/test_console.py"
TESTS["M569"] = "tests/unit/test_cli.py -k version"
TESTS.update({f"M{n}": "tests/unit/test_console.py" for n in range(570, 580)})  # #248, and the card detail escaped
TESTS.update({f"M{n}": "tests/unit/test_console_escaping.py" for n in range(580, 600)})  # #254
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
              "removed, our tag taken off, another subscription (I1S)", R,
     "        return k in gone\n", "        return True\n"),
    ("M1021", "a quarantine NSG read again without our tag reads as not ours: its card closed (I1S)", SWP,
     "        return self._quarantine_as_read(nsg)\n",
     '        if (getattr(nsg, "tags", None) or {}).get("managed-by") != "glorfindel":\n'
     "            return None\n        return self._quarantine_as_read(nsg)\n"),
    ("M1022", "a quarantine NSG of another subscription read in this one: its homonym, or a 404, "
              "closes its card (I1S)", SWP,
     '        if not target or target.lower() != (self._subscription_id or "").lower():\n',
     "        if False:\n"),
    ("M1023", "a quarantine NSG that can't be read again (403, 429) reads as gone: its card closed (I1S)", R,
     "exc)\n            continue\n        if q is None:\n",
     "exc)\n            gone.add(k)\n            continue\n        if q is None:\n"),
    ("M1024", "every quarantine card's NSG read again at every pass, listed or not: a get per card "
              "per minute (I1S)", R,
     "        if _key(rid) and _key(rid) not in seen:\n", "        if _key(rid):\n"),
    ("M1025", "an acknowledged change is not read again: its NSG deleted, the acknowledgement silences "
              "the next one (I1S)", R,
     '    for rid in [e.get("resource_id") or "" for e in cards] + list(alerts):\n',
     '    for rid in [e.get("resource_id") or "" for e in cards]:\n'),
    ("M1026", "a refusal (403) read again reads as not found: the card closed (I1S)", SWP,
     "            if _is_not_found(exc):\n                return None\n            raise\n",
     "            return None\n"),
]
TESTS.update({f"M{n}": f"tests/unit/test_reassert.py tests/unit/test_invariant_regressions.py {INVARIANTS}"
              for n in (1020, 1021, 1023, 1026)})
TESTS.update({f"M{n}": "tests/unit/test_reassert.py" for n in (1022, 1024, 1025)})

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
     "      - ${HOME}/.annatar:/root/.annatar\n      - ${HOME}/.glorfindel:/root/.glorfindel:ro\n"
     "    depends_on:\n      - watch\n",
     "      - ${HOME}/.annatar:/root/.annatar\n      - ${HOME}/.glorfindel:/root/.glorfindel:ro\n"),
    ("M804", "Gothmog's compose service may write Glorfindel's state (D1)", "docker-compose.yml",
     "      - ${HOME}/.glorfindel:/root/.glorfindel:ro\n    depends_on:\n      - watch\n"
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
     '    "litellm==1.86.1",\n',
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
    ("M978", "palantir's verdict misread: a model fallback neither alerted nor reviewed (N1)", NOTIFY,
     '    fell = scan.get("verdict") == "review-needed"\n',
     '    fell = scan.get("verdict") == "review_needed"\n'),
    ("M979", "every subagent's stop followed, not only elrond's: #agents rewritten for any agent (N1)", NOTIFY,
     '    return data.get("hook_event_name") == "SubagentStop" and data.get("agent_type") in ELROND_AGENTS\n',
     '    return data.get("hook_event_name") == "SubagentStop"\n'),
]
TESTS.update({f"M{n}": "tests/unit/test_notify_discord.py" for n in range(970, 980)})

# N1 after its review (27/10, F1–F8): M990–M994, taken from this session's range (M970–M999).
MUTANTS += [
    ("M990", "the verdict read only in last_assistant_message: elrond's reviewers hand it back by a tool (N1, F1)",
     NOTIFY, "        verdict = verdict_of(final_report(transcript, data))\n",
     '        verdict = verdict_of(data.get("last_assistant_message", ""))\n'),
    ("M991", "a fork's pull request posts in the lot its title names (N1, F5)", NOTIFY,
     "            lot = issue = \"\"   # a fork's pull request: #ci only, never a lot's thread (its title names any lot)\n",
     "            pass\n"),
    ("M992", "every closed issue creates a thread, a lot or not (N1, F5)", NOTIFY,
     "archive=True, create=bool(lot))]", "archive=True)]"),
    ("M993", "http.client's errors not caught: InvalidURL quotes the webhook's token (N1, F6)", NOTIFY,
     "        except Exception as e:  # URLError, http.client's errors: InvalidURL quotes the URL, token and all\n",
     "        except (OSError, ValueError) as e:\n"),
    ("M994", "a blocked lot without configuration writes the local state (N1, F7)", NOTIFY,
     "    if not (cfg.agents or cfg.lots):   # nothing configured: nothing written, not even the local state\n"
     "        return 0\n", ""),
]
TESTS.update({f"M{n}": "tests/unit/test_notify_discord.py" for n in range(990, 995)})

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
