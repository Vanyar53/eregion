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
A = "glorfindel/actions.py"
R = "glorfindel/reassert.py"
C = "glorfindel/config.py"
INS = "eregion_core/inscription.py"
ENG = "annatar/runner/engine.py"
EXE = "annatar/executors/azure_vm.py"
ATO = "annatar/engines/atomic.py"
SYN = "annatar/campaign/synthesizer.py"
CATSCHEMA = "schemas/technique_catalog.schema.json"
WCH = "eregion_core/watch_channel.py"
GOTH = "gothmog/runner/engine.py"
DET = "annatar/runner/detection.py"
INVARIANTS = "tests/unit/test_invariants.py"
INSCRIPTION_TESTS = "tests/unit/test_inscription.py tests/unit/test_engine.py"
DOCS_TESTS = "tests/unit/test_docs_budget.py"
DETECTION_TESTS = "tests/unit/test_annatar_detection.py tests/unit/test_engine.py"
# A mutant whose "old" text is RENAME renames its file to "new" instead of editing it.
RENAME = object()

# (id, bug class, file, text in the code today, text that re-introduces the bug[, why
# the invariants can't see it])
MUTANTS = [
    ("M01", "rule name without the NIC hash (homonyms share a name)", A,
     'base = f"{prefix}-{vm_name}-{nic_short}-{_nic_hash(nic_id, 6)}"',
     'base = f"{prefix}-{vm_name}-{nic_short}"'),
    ("M02", "deny any/any on a shared NIC NSG", A,
     "        return len(nics) > 1 or len(subnets) > 0",
     "        return False"),
    ("M03", "deny scoped to the NIC's first IP only", A,
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)',
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips[:1])'),
    ("M04", "outbound allows ignored by the precedence check", A,
     '        elif direction == "outbound":\n            src, dst = outbound_src, outbound_dst',
     '        elif direction == "outbound":\n            continue'),
    ("M05", "verify_release ignores a quarantine NSG still attached", A,
     "                  for t0 in targets if t0.get(\"quarantine\")]",
     "                  for t0 in targets if False]"),
    ("M06", "state deleted right after it is written (C1's effect)", A,
     "    _atomic_write_text(target, json.dumps(payload))\n",
     "    _atomic_write_text(target, json.dumps(payload))\n    if name != name.lower():\n        target.unlink()\n"),
    ("M07", "release sweeps the NICs only when there is no state", A,
     "        failed += self._sweep_isolation(rg, vm_name, remaining)",
     "        failed += [] if state.get(\"placements\") else self._sweep_isolation(rg, vm_name, remaining)"),
    ("M08", "fallback deny any/any on an NSG that only looks dedicated", A,
     '    return bool(target.get("private_ips")) or _ip_scoped(target)',
     "    return _ip_scoped(target)"),
    ("M09", "a missing original tag read as 'no NSG' (Q7)", A,
     "        if not value:\n            raise OriginalUnknown(",
     "        if not value:\n            return None\n            raise OriginalUnknown("),
    ("M10", "an unreadable subnet read as 'no subnet NSG'", A,
     "                subnet_nsg, subnet_unreadable = None, True",
     "                subnet_nsg, subnet_unreadable = None, False"),
    ("M11", "_is_not_found by substring", A,
     "    # No substring guess:",
     "    if \"not found\" in str(exc).lower():\n        return True\n    # No substring guess:",
     "EQUIVALENT: no call site sees a non-404 'not found' since the release re-reads the NIC"),
    ("M12", "isolation verified by rule name, not content", A,
     '                    and _deny_isolates(r_in, "inbound", ips) and _deny_isolates(r_out, "outbound", ips)):',
     "                    ):"),
    ("M13", "reassertion ignores a release that has started", "glorfindel/reassert.py",
     "    return bool(state.get(\"partial\") or state.get(failed_key) or state.get(running_key))",
     "    return bool(state.get(\"partial\") or state.get(failed_key))"),
    ("M14", "release does not read the NIC back", A,
     "            if not _same_id(now or \"\", original or \"\"):",
     "            if False:"),
    ("M15", "an unreadable config falls back to the defaults (S1)", A,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except Exception:\n            return True, \"\"\n"),
    ("M16", "blocks verified by rule name, not content (S2)", A,
     "        altered = [n for n, r, d in zip(names, found, (\"inbound\", \"outbound\")) if not _deny_blocks(r, d, ip, ips)]",
     "        altered = []"),
    ("M17", "per-VM lock inoperative", A,
     "        with _vm_lock(rid.rstrip(\"/\").rsplit(\"/\", 1)[-1]):\n            return method(self, *args, **kwargs)",
     "        return method(self, *args, **kwargs)"),
    # Found by L26 itself (the world moving): kept so they stay found.
    ("M18", "a NIC's old-IP rule recognised by content only (L26)", A,
     "    if name in hashed:\n        # Only Glorfindel names a rule with a NIC's hash",
     "    if name in hashed and _deny_applies(rule, ips):\n        # Only Glorfindel names a rule with a NIC's hash"),
    ("M19", "a block verified against the IPs recorded at block time (L26)", A,
     "                now = current.get(nic) if current is not None and isinstance(nic, str) else None",
     "                now = None"),
    ("M20", "release asks for the original of a NIC no longer in quarantine (L26)", A,
     "                        if now and not _same_id(now, p[\"nsg_id\"]):",
     "                        if False:"),
    ("M21", "a block counted on an NSG that no longer governs the NIC (L26)", A,
     '                    off = [p for p in ps if (p["nsg_rg"].lower(), p["nsg_name"].lower()) not in governing]',
     "                    off = []"),
    ("M22", "a partial release's flat fields read as a legacy state (L26)", A,
     '        elif "placements" not in state and state.get("nsg_name") and not _is_quarantine_nsg(state["nsg_name"]):',
     '        elif state.get("nsg_name"):'),
    ("M23", "an unblock doesn't look behind the quarantine (L27)", A,
     "            views = self._nic_nsg_views(t0)\n            if t0.get(\"quarantine\"):",
     "            views = self._nic_nsg_views(t0)\n            if False:"),
    ("M24", "reset --from-azure reads the original from the tag only (L27)", A,
     "                original = _recorded_original(t0[\"nic_id\"])\n                if original is _UNKNOWN:\n"
     "                    original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])\n"
     "                originals[t0[\"nic_id\"]] = original",
     "                originals[t0[\"nic_id\"]] = original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])"),
    ("M25", "a partial reset leaves the state unmarked (L27)", A,
     "        elif not dry_run:\n            # Part of it is gone from Azure",
     "        elif False:\n            # Part of it is gone from Azure",
     "EQUIVALENT: since A0 the reset records its intent (releasing_at / unblocking_at) before "
     "touching Azure — a partial reset's state is held by that marker either way; the failure "
     "mark only changes the operator's wording"),
    ("M26", "a NIC left without an NSG: the release moves on (L28, U2)", A,
     "                        if now is None:\n                            # Detached from our NSG",
     "                        if False:\n                            # Detached from our NSG"),
    ("M27", "an unreadable config hides an emptied quarantine NSG (L28, U4)", A,
     "            wanted = self._quarantine_wanted(with_forensic=False)\n            forensic_known = False",
     "            raise\n            forensic_known = False"),
    ("M28", "orphan rules not reported (L28, U1)", A,
     "                if len(mark) not in (6, 8) or any(c not in \"0123456789abcdef\" for c in mark) or mark in marks:",
     "                if True:"),
    ("M29", "a bare NIC isolated again records 'none' over its original (L28, U2)", A,
     "            if original is None:\n                # A bare NIC may have been in our quarantine before",
     "            if False:\n                # A bare NIC may have been in our quarantine before"),
    ("M30", "the quarantine swap is not read back (A0)", A,
     '            if not _same_id(now or "", q["nsg_id"]):',
     "            if False:"),
    ("M31", "one deny's priority used for both directions (A0)", A,
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": out if isinstance(out, int) else prio},',
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": prio},'),
    ("M32", "an outbound allow before a block counted as exposure (A0)", A,
     '                    port is None or direction == "outbound" or _rule_covers_port(r, port)),',
     '                    port is None or (direction == "inbound" and _rule_covers_port(r, port))),'),
    ("M33", "an unowned old fixed-name rule on a non-dedicated NSG ignored (A0)", A,
     '        if not (t.get("sharing_unknown") or _ip_scoped(t)):\n            return []',
     '        if True:\n            return []'),
    ("M34", "verify_release ignores the old single-NSG state (A0)", A,
     "            rules = self._list_rules(cache, l_rg, l_name)\n            names =",
     "            rules = []\n            names ="),
    ("M35", "reset --from-azure records no intent (A0)", A,
     '            if state:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})',
     '            if False:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})'),
    ("M36", "the old state file removed after the new one is written (A0)", A,
     "    if olds and not target.exists():",
     "    if False:"),
    ("M37", "reassertion alerts keyed by the VM's name (A0, L1)", "glorfindel/reassert.py",
     '    return f"reassert-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")',
     '    return f"reassert-{vm}" + (f"-{ip}" if ip else "")'),
    ("M38", "a block gone behind the quarantine not reported (A0, L1)", A,
     "                                    held_missing += names",
     "                                    pass"),
    ("M39", "reset reads a bare NIC's original from the tag only (A0)", A,
     "            if recorded is not _UNKNOWN:\n                original = recorded\n            elif q_bare is None:",
     "            if False:\n                original = recorded\n            elif q_bare is None:"),
    ("M40", "a deleted NSG's listing read as unreadable (A0, L1)", A,
     "                cache[key] = [] if _is_not_found(exc) else None",
     "                cache[key] = None"),
    ("M41", "reset doesn't sweep the original it puts back on a bare NIC (A0)", A,
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
    ("M50", "the drain spares any session with a forensic source (S8)", A,
     'flt = flt[:-1] + f"and not ( dst {cidr} and ( {local} ) ) )"',
     'flt = flt[:-1] + f"and not dst {cidr} )"'),
    # Sixth review, S9: a verification that raised left the graph (cycle_failed, no Revert).
    ("M51", "a verification that raises leaves the graph (S9)", "glorfindel/agent.py",
     "    except Exception as exc:\n        first = str(exc).strip().splitlines()[0]",
     "    except Exception as exc:\n        raise\n        first = str(exc).strip().splitlines()[0]"),
    # Sixth review, S7: a quarantine refused at execution, unknown to the readiness gate.
    ("M52", "a quarantine refused at execution is not remembered (S7)", A,
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
     "    if resource_id.lower() not in (window.get(\"targets\") or []):\n        return False\n", ""),
    ("M58", "a window never closed never lapses (B2)", "eregion_core/exercise.py",
     "    end = _parse(window.get(\"end\")) or expires\n    # A window closed late still lapses at its expiry.\n"
     "    last = min(end, expires) + timedelta(seconds=GRACE_AFTER_S)\n",
     "    end = _parse(window.get(\"end\")) or when\n    last = end + timedelta(seconds=GRACE_AFTER_S)\n"),
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
     '    for name, step in (("revoke", revoke), ("stop", stop)):',
     '    for name, step in (("stop", stop),):'),
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
     '    if engine == "atomic":\n', "    if False:\n"),
    ("M117", "the synthesizer writes an atomic without its steady-state probes (#165)", SYN,
     '        "steady_state": {"probes": [dict(p) for p in probes]},\n', ""),
    ("M118", "the synthesizer accepts an engine_ref the adapter cannot resolve (#165)", SYN,
     '    try:\n        resolve_ref(engine_ref)\n    except AtomicError as e:\n'
     '        return SynthesisResult(False, f"{ttp}: engine_ref unresolved — {e}")\n',
     "    pass\n"),
    ("M119", "the catalog schema accepts an implemented atomic without steady_state (#165)", CATSCHEMA,
     '                  "const": "atomic"\n', '                  "const": "atomic-never"\n'),
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
              for mid in ("M116", "M117", "M118")})
TESTS["M119"] = "tests/unit/test_experiment_schema.py"


# The auditor's control set (seventh review): plausible bugs the generation was never
# shaped on. They only MEASURE whether the invariants generalise — never tailor a
# composite rule or a world event to one of them. Run with --control.
CONTROL = [
    ("C01", "unreadable config => quarantine off", A,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config, ConfigError\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except ConfigError:\n            return False, \"\"\n"),
    ("C02", "unreadable ownership tag => not ours", A,
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return True",
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return False"),
    ("C03", "isolation deny without the peer-side check", A,
     "    if not _side_is_any(rule, peer):\n        return False\n",
     ""),
    ("C04", "quarantine content without the DNS/IMDS denies", A,
     "        for rule_name, priority, tag in QUARANTINE_PLATFORM_RULES:",
     "        for rule_name, priority, tag in ():"),
    ("C05", "a stale forensic allow never purged", A,
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current):",
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current) and low != QUARANTINE_FORENSIC_RULE:"),
    ("C06", "block: one address of the NIC is enough", A,
     "    return all(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)",
     "    return any(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)"),
    ("C07", "stateless release doesn't re-read the NICs", A,
     "        if restored:\n",
     "        if False:\n"),
    ("C08", "no foreign rule counts as an alteration", A,
     "                 if low not in {w.lower() for w in wanted} and _opens_quarantine(r)]",
     "                 if False]"),
    ("C09", "the release doesn't write its marker", A,
     "            _save_isolation_state(resource_id, {**state, \"releasing_at\": datetime.now(timezone.utc).isoformat()})",
     "            pass"),
    ("C10", "the reassertion never puts a missing block back", R,
     "    if b.get(\"reasserted_at\") or _mode(autonomy, vm, ref) == \"human_only\":",
     "    if True:"),
    ("C11", "a block doesn't check the access (an allow passes)", A,
     "    if (_enum_text(getattr(rule, \"access\", \"\")) != \"deny\"\n            or _enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own",
     "    if (_enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own"),
    ("C12", "forensic exception dropped from the quarantine-as-block", A,
     "            if any(addr in ipaddress.ip_network(s, strict=False) for s in self._forensic_sources()):",
     "            if False:"),
    ("C13", "a /16 forensic source accepted", C,
     "_FORENSIC_MAX_ADDRESSES = 256",
     "_FORENSIC_MAX_ADDRESSES = 65536"),
    ("C14", "subscription guard removed from the release", A,
     "for _name in (\"isolate_vm\", \"release_isolation\", \"verify_isolation\", \"verify_release\",",
     "for _name in (\"isolate_vm\", \"verify_isolation\", \"verify_release\","),
    ("C15", "reassertion over a stale marker", R,
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\"):\n        return",
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\") and not _stale(iso.get(\"releasing_at\")):\n        return"),
    ("C16", "precedence ignores glorfindel-* allows", A,
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if direction == \"inbound\":",
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if name.startswith(\"glorfindel-\"):\n            continue\n"
     "        if direction == \"inbound\":"),
]


def _copy_repo(dest: Path) -> None:
    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    for rel in files:
        src = REPO / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)


def _run(copy: Path, examples: int, show: bool = False, target: str = INVARIANTS) -> bool:
    """True if `target` (test paths, space-separated) FAILS on this copy (the mutant is caught)."""
    env = {**os.environ, "GLORFINDEL_INVARIANT_EXAMPLES": str(examples), "GLORFINDEL_INVARIANT_NO_SHRINK": "1",
           "PYTHONPATH": str(copy), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *target.split(), "-q", "-x", "-p", "no:cacheprovider"],
        cwd=copy, env=env, capture_output=True, text=True)
    if "glorfindel" in proc.stdout and "ModuleNotFoundError" in proc.stdout:
        raise RuntimeError(proc.stdout[-2000:])
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
                if text.count(old) != 1:
                    return mid, title, "STALE", f"{text.count(old)} matches"
                target.write_text(text.replace(old, new))
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
