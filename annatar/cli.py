import os

import click
from rich.console import Console

console = Console()


class _AnnatarCli(click.Group):
    """Render operational failures as a clean one-liner, not a raw traceback.

    Missing creds, an azure-mgmt import mismatch, a campaign in a terminal state —
    these are operator conditions, not bugs. Dumping a 20-line stack helps no one.
    Print the cause + a targeted hint and exit non-zero. ANNATAR_DEBUG=1 restores
    the full traceback for real debugging. Mirrors glorfindel's _GlorfindelCli.
    """

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (click.ClickException, click.exceptions.Abort, click.exceptions.Exit,
                SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:  # noqa: BLE001 — deliberate CLI boundary
            if os.environ.get("ANNATAR_DEBUG"):
                raise
            console.print(f"[red]✗ {type(e).__name__}: {e}[/red]")
            msg = str(e)
            if "AZURE_SUBSCRIPTION_ID" in msg or "credential" in msg.lower():
                console.print(
                    "[dim]  → environnement non chargé : `direnv allow` ou "
                    "`source .envrc` avant de relancer.[/dim]"
                )
            console.print("[dim]  (ANNATAR_DEBUG=1 pour la stack complète)[/dim]")
            ctx.exit(1)


@click.group(cls=_AnnatarCli)
@click.version_option()
def cli():
    """Annatar — simulate attacks, measure real RTO/RPO."""


@cli.command()
@click.argument("scenario")
@click.option(
    "--dry-run", is_flag=True, help="Show what would happen without executing."
)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option(
    "--skip-preflight",
    is_flag=True,
    help="Skip VM state checks (power + isolation).",
)
@click.option(
    "--without-glorfindel",
    is_flag=True,
    help="Development run: no live Glorfindel watch required. The report says the "
         "detection was not measured, by choice.",
)
def run(scenario: str, dry_run: bool, yes: bool, skip_preflight: bool,
        without_glorfindel: bool):
    """Run a chaos scenario (path or scenario name).

    SCENARIO can be a file path or the scenario name from 'annatar list'.

    Examples:
        annatar run azure-ransomware-vm
        annatar run annatar/scenarios/azure/ransomware-vm.yaml
    """
    import os
    from annatar.runner.engine import Engine
    from annatar.runner.parser import find_scenario_by_name

    path = scenario
    if not os.path.exists(path):
        resolved = find_scenario_by_name(scenario)
        if resolved:
            path = resolved
        else:
            console.print(
                f"[red]Scenario not found:[/red] '{scenario}'\n"
                "  Pass a file path or a scenario name from 'annatar list'."
            )
            raise SystemExit(1)

    # With EREGION_EXERCISE_CHANNEL, the run's report goes to H0 at its end (#193).
    engine = Engine(dry_run=dry_run, skip_preflight=skip_preflight, publish_report=True,
                    without_glorfindel=without_glorfindel)
    outcome = engine.run(path, skip_confirm=yes)
    code = run_exit_code(outcome)
    if code:
        _print_run_failure(outcome)
        raise SystemExit(code)


# `annatar run` exit codes (#158). A script or a CI chaining runs reads the code, not the
# console: every refusal (Orodruin passive, target not enrolled, dirty start, an atomic the
# adapter will not run faithfully, cap, preflight, invalid scenario) and every error after
# the target was touched (no observable effect, initial state not restored or not verified)
# exits non-zero. A run that raises goes through _AnnatarCli (exit 1, one line). The campaign
# runner calls Engine.run itself and reads RunOutcome.error: it marks that scenario in error
# and goes on — this code is the single-run CLI's only.
EXIT_OK = 0
EXIT_RUN_FAILED = 1

# One hint per refusal, by the prefix Engine.run gives RunOutcome.error.
_RUN_HINTS = (
    ("glorfindel:", "aucune watch de Glorfindel vivante : lancer `glorfindel watch` (ou la watch "
                    "hébergée, vue par EREGION_WATCH_CHANNEL) ; rien n'a été touché. Run de "
                    "développement : --without-glorfindel (le rapport le dit)."),
    ("passive:", "contrat d'Orodruin passif : lancer depuis un Orodruin armé "
                 "(ailleurs, un injecteur reste passif)."),
    ("safety:", "cible hors banc ou non inscrite : tags eregion-target et eregion-zone "
                "sur la VM et son groupe."),
    ("atomic:", "test atomic refusé (annatar/engines/atomic.py) ou sondes steady_state "
                "incomplètes : rien n'a été joué."),
    ("cap:", "plafond d'appels du contrat d'Orodruin (EREGION_MAX_INJECTIONS) atteint."),
    ("scenario:", "scénario invalide : `annatar validate <scénario>`."),
    ("engine:", "moteur que le runner ne sait pas jouer."),
    ("preflight", "VM arrêtée ou isolée : corriger, ou --skip-preflight."),
    ("integrity", "disque de test pas propre après le setup."),
    ("initial state not clean", "départ sale : remettre la VM dans son état initial, "
                                "rien n'a été joué."),
    ("initial state not", "la VM peut être sale : jouer la commande de rattrapage "
                          "affichée plus haut avant tout autre run."),
    ("atomic ran", "aucun effet observé : pas d'attack_started, rien à détecter."),
)


def run_exit_code(outcome) -> int:
    """The exit code of `annatar run` for an Engine.run result: 0 only for a run that went
    through (or a dry run / an operator's « no », which return no outcome); any refusal or
    error carried by ``RunOutcome.error`` is non-zero."""
    if outcome is not None and getattr(outcome, "error", None):
        return EXIT_RUN_FAILED
    return EXIT_OK


def _print_run_failure(outcome) -> None:
    """One line, plus a hint when the refusal is a known one (like _AnnatarCli)."""
    console.print(f"[red]✗ run {outcome.run_id}: {outcome.error}[/red]")
    hint = next((h for prefix, h in _RUN_HINTS if outcome.error.startswith(prefix)), None)
    if hint:
        console.print(f"[dim]  → {hint}[/dim]")


@cli.command()
@click.argument("technique")
@click.argument("target")
@click.option("--request", required=True, help="The Dagorlad request this wire belongs to (its id).")
@click.option("--typed-name", default="", help="The target's name, as the operator typed it on their "
              "machine — a destructive technique runs only on the VM of that name.")
def wire(technique: str, target: str, request: str, typed_name: str):
    """One wire of a Dagorlad request (DG-b), run by Orodruin: TECHNIQUE (an id of the catalogue)
    on TARGET (a VM's resource id), as one run — its scenario made from the catalogue, the
    request's id written in its window, its journal and its report. Every guard of `annatar run`
    holds (the watch, the contract, the inscription and the zone, the cap); a destructive
    technique also needs the name typed, compared to the VM's.

        annatar wire T1110.001 /subscriptions/…/virtualMachines/vm-x --request r-…
    """
    import tempfile
    from pathlib import Path

    from annatar.campaign.catalog import load_catalog
    from annatar.campaign.scope import Scope
    from annatar.campaign.synthesizer import synthesize
    from annatar.runner.engine import Engine
    from eregion_core.exercise_request import valid_id
    from eregion_core.inscription import rg_from_id, subscription_from_id

    if not valid_id(request):
        raise click.UsageError("--request takes a request id (r-<YYYYMMDDTHHMMSSZ>-<6 hex>)")
    entry = load_catalog().get(technique)
    if not entry:
        console.print(f"[red]✗ {technique}: not a technique of the catalogue — nothing run[/red]")
        raise SystemExit(EXIT_RUN_FAILED)
    rg = rg_from_id(target)
    scope = Scope(subscription_id=subscription_from_id(target),
                  allowed_resource_groups=[rg] if rg else [], allowed_resource_ids=[target])
    # The scenario lives only for the run: never in runs/, where a local watch reads.
    with tempfile.TemporaryDirectory(prefix="annatar-wire-") as tmp:
        made = synthesize(entry=entry, target_resource_id=target, scope=scope, out_dir=Path(tmp),
                          seq=1, allow_destructive=bool(typed_name))
        if not made.ok:
            console.print(f"[red]✗ wire refused: {made.reason}[/red]")
            raise SystemExit(EXIT_RUN_FAILED)
        engine = Engine(publish_report=True, request=request, typed_name=typed_name)
        outcome = engine.run(str(made.path), skip_confirm=True)
    code = run_exit_code(outcome)
    if code:
        _print_run_failure(outcome)
        raise SystemExit(code)


@cli.command(name="list")
def list_scenarios():
    """List available scenarios."""
    from annatar.runner.parser import list_available
    list_available()


@cli.command()
@click.argument("scenario", required=False)
@click.option(
    "--all", "validate_all", is_flag=True, help="Validate all available scenarios."
)
def validate(scenario: str | None, validate_all: bool):
    """Validate one scenario YAML or all available scenarios.

    Examples:
        annatar validate annatar/scenarios/azure/ransomware-vm.yaml
        annatar validate azure-ransomware-vm
        annatar validate --all
    """
    import glob
    import os
    from annatar.runner.parser import (
        ScenarioParser,
        scenarios_root,
        find_scenario_by_name,
    )

    parser = ScenarioParser()

    if validate_all or not scenario:
        root = scenarios_root()
        files = sorted(glob.glob(str(root / "**" / "*.yaml"), recursive=True))
        if not files:
            console.print("[yellow]No scenarios found.[/yellow]")
            return
        project_root = root.parent.parent
        failed = 0
        for f in files:
            result = parser.validate(f)
            rel = os.path.relpath(f, project_root)
            if result.valid:
                console.print(f"[green]OK[/green]   {rel}")
            else:
                failed += 1
                console.print(f"[red]FAIL[/red] {rel}")
                for err in result.errors:
                    console.print(f"     [dim]{err}[/dim]")
        summary = f"{len(files)} scenario(s)"
        if failed:
            console.print(f"\n[red]{failed} failed[/red] / {summary}")
        else:
            console.print(f"\n[green]All {summary} valid[/green]")
        return

    # Single scenario — resolve by name if needed
    path = scenario
    if not __import__("os").path.exists(path):
        resolved = find_scenario_by_name(scenario)
        if resolved:
            path = resolved
        else:
            console.print(f"[red]Not found:[/red] '{scenario}'")
            raise SystemExit(1)

    result = parser.validate(path)
    if result.valid:
        console.print(f"[green]OK[/green] {path} is valid")
    else:
        for err in result.errors:
            console.print(f"[red]FAIL[/red] {err}")


@cli.command()
@click.argument("run_id")
def report(run_id: str):
    """Display or export a run report."""
    from annatar.runner.report import RunReport
    RunReport.display(run_id)


@cli.command()
@click.option(
    "--yes", is_flag=True, help="Pass -auto-approve to terraform apply."
)
@click.argument("scenario", type=click.Path(exists=True), required=False)
def init(yes: bool, scenario: str | None):
    """Provision Azure test environment.

    Optionally pass a SCENARIO path to also prepare the VM disk in one step:

        annatar init --yes scenarios/azure/ransomware-vm.yaml
    """
    from annatar.runner.initializer import InitRunner
    InitRunner().run(auto_approve=yes, scenario_path=scenario)


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--without-glorfindel", is_flag=True,
              help="Development clean: no live Glorfindel watch required (written to "
                   "Orodruin's journal).")
def clean(scenario: str, without_glorfindel: bool):
    """Reset the VM disk to a clean state before re-running a scenario.

    Like `run`, never without a live Glorfindel watch (V1, SEC5).
    After this, run 'glorfindel snapshot <resource_id> --yes' to capture
    a clean recovery point.
    """
    from annatar.runner.initializer import InitRunner
    InitRunner().clean(scenario, without_glorfindel=without_glorfindel)


# ── Generative campaigns ─────────────────────────────────────────────────────
@cli.group()
def campaign():
    """Plan, run and inspect generative attack campaigns (kill-chains)."""


@campaign.command(name="plan")
@click.option("--target", required=True, help="Target resource_id (must be in the Celebrimbor sandbox).")
@click.option("--objective", default="", help="One-line campaign intent (steers the LLM planner).")
@click.option("--max-scenarios", default=5, show_default=True, help="Budget ceiling.")
@click.option("--allow-destructive", is_flag=True, help="Permit destructive (testdata-only) techniques.")
@click.option("--llm/--no-llm", "use_llm", default=False, help="Use the LLM planner (default: deterministic).")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
@click.option("--declared", "declared_path", default=None, type=click.Path(dir_okay=False),
              help="A declared campaign (BL1): exactly its techniques, in its order — no planner. "
                   "Checked against the catalog first (annatar/campaign/declared.py).")
def campaign_plan(target, objective, max_scenarios, allow_destructive, use_llm, runs_dir, declared_path):
    """Plan a kill-chain and materialize its scenarios (state: planned)."""
    from annatar.campaign.catalog import load_catalog
    from annatar.campaign.manifest import (
        Budget,
        CampaignManifest,
        ScenarioEntry,
        Scope,
        campaign_dir,
        new_campaign_id,
    )
    from annatar.campaign.planner import plan_campaign
    from annatar.campaign.synthesizer import synthesize
    from eregion_core.inscription import rg_from_id, subscription_from_id

    rg = rg_from_id(target)
    sub = subscription_from_id(target)
    guard = Scope(
        subscription_id=sub,
        allowed_resource_groups=[rg] if rg else [],
        allowed_resource_ids=[target],
    )
    res = guard.check(target, rg)
    if not res.allowed:
        console.print(f"[red]Target rejected:[/red] {res.reason}")
        raise SystemExit(1)

    catalog = load_catalog()
    if declared_path:
        # BL1: the techniques a human declared, checked against the catalog — never the planner's.
        from annatar.campaign import declared
        from annatar.campaign.planner import CampaignPlan, PlannedTechnique
        try:
            decl = declared.load(declared_path)
        except ValueError as e:
            console.print(f"[red]Declared campaign refused:[/red] {e}")
            raise SystemExit(1)
        problems = declared.problems(decl, catalog)
        vm = target.rstrip("/").rsplit("/", 1)[-1].lower()
        if vm not in {t.lower() for t in decl.targets}:
            problems.append(f"target {vm} is not one of the declaration's ({', '.join(decl.targets)})")
        if problems:
            console.print(f"[red]Declared campaign {decl.id or declared_path} refused:[/red]")
            for p in problems:
                console.print(f"  • {p}")
            raise SystemExit(1)
        plan = CampaignPlan(objective=objective or f"declared: {decl.id}", techniques=[
            PlannedTechnique(ttp=ttp, tactic=catalog[ttp].get("tactic", ""), name=catalog[ttp].get("name", ""))
            for ttp in decl.techniques])
        max_scenarios = max(max_scenarios, len(plan.techniques))
    else:
        plan = plan_campaign(objective=objective, max_scenarios=max_scenarios, use_llm=use_llm)

    cid = new_campaign_id()
    cdir = campaign_dir(cid, runs_dir=runs_dir)
    scen_dir = cdir / "scenarios"

    entries: list[ScenarioEntry] = []
    for i, tech in enumerate(plan.techniques, 1):
        entry = catalog.get(tech.ttp)
        if not entry:
            continue
        s = synthesize(
            entry=entry, target_resource_id=target, scope=guard,
            out_dir=scen_dir, seq=i, allow_destructive=allow_destructive,
        )
        if not s.ok:
            console.print(f"[yellow]skip {tech.ttp}: {s.reason}[/yellow]")
            continue
        entries.append(
            ScenarioEntry(
                seq=i, ttp=tech.ttp, tactic=tech.tactic, name=tech.name,
                scenario_file=f"scenarios/{s.path.name}",
                target_resource_id=target,
                destructive=bool(entry.get("destructive")),
                safe_target=entry.get("safe_target", "") or "",
            )
        )

    if not entries:
        console.print("[red]No scenario could be synthesized — nothing planned.[/red]")
        raise SystemExit(1)

    manifest = CampaignManifest(
        campaign_id=cid,
        objective=objective or plan.objective,
        scope=Scope(
            subscription_id=sub,
            allowed_resource_groups=[rg] if rg else [],
            allowed_resource_ids=[target],
        ),
        budget=Budget(max_scenarios=max_scenarios, allow_destructive=allow_destructive),
        scenarios=entries,
    )
    manifest.save(cdir)
    console.print(f"[green]Planned campaign {cid}[/green] — {len(entries)} scenario(s):")
    for e in entries:
        console.print(f"  [{e.seq}] {e.tactic:22} {e.ttp}  {e.scenario_file}")
    console.print(
        f"\n[dim]Review {cdir}/manifest.json, then:[/dim] "
        f"annatar campaign run {cid} --yes"
    )
    if declared_path and decl.faults:
        console.print(f"[dim]Its fault(s), played by Gothmog on the same target(s): "
                      f"{', '.join(decl.faults)} (gothmog run <id>, docs/banc-bl1.md).[/dim]")


@campaign.command(name="run")
@click.argument("campaign_id")
@click.option("--yes", is_flag=True, help="Ratify the budget/scope and execute.")
@click.option("--dry-run", is_flag=True, help="Preview the sequence without executing.")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
@click.option("--without-glorfindel", is_flag=True,
              help="Development campaign: no live Glorfindel watch required. Each run's "
                   "report says the detection was not measured, by choice.")
@click.option("--report/--no-report", default=True,
              help="Write the campaign report at the end (IA0, analysis/campaign_report.py); "
                   "with EREGION_EXERCISE_CHANNEL, publish the campaign to H0, whose watch "
                   "writes it (#167). --no-report: neither written nor published.")
def campaign_run(campaign_id, yes, dry_run, runs_dir, without_glorfindel, report):
    """Execute a planned campaign sequentially within its budget/scope."""
    from annatar.campaign.manifest import CampaignManifest, campaign_dir
    from annatar.campaign.runner import CampaignRefused, CampaignRunner
    from eregion_core import watch_gate

    cdir = campaign_dir(campaign_id, runs_dir=runs_dir)
    if not (cdir / "manifest.json").exists():
        console.print(f"[red]Campaign not found:[/red] {campaign_id}")
        raise SystemExit(1)

    m = CampaignManifest.load(cdir)
    if m.state == "planned":
        if not (yes or dry_run):
            console.print(
                "[yellow]Campaign is 'planned' — ratify budget/scope with --yes "
                "(or preview with --dry-run).[/yellow]"
            )
            raise SystemExit(1)
        if yes and not dry_run:
            m.set_state("ratified")
            m.save(cdir)

    try:
        result = CampaignRunner(cdir, dry_run=dry_run, without_glorfindel=without_glorfindel).run()
    except CampaignRefused as e:  # V1: nothing ran, the manifest is as it was
        console.print(f"[red]✗ {e}[/red]")
        console.print(f"[dim]  → {_CAMPAIGN_HINT}[/dim]")
        raise SystemExit(EXIT_RUN_FAILED)
    if not dry_run:
        r = result.results
        console.print(
            f"\n[bold]Campaign {result.campaign_id} → {result.state}[/bold]  "
            f"executed={r['executed']} detected={r['detected']} "
            f"missed={r['missed']} skipped={r['skipped']} errors={r['errors']}"
        )
        # From Orodruin (an exercise channel set), the campaign goes to H0, whose watch
        # writes its report (#167); else, or if it could not go, written here if possible.
        # Without Glorfindel (V1) no report is written, here nor on H0 — and that is said.
        without = result.without_glorfindel
        if report and not _publish_campaign(cdir, runs_dir, result.state, without) \
                and not without:
            _write_campaign_report(cdir)
        if without:
            console.print(f"[yellow]{watch_gate.NO_CAMPAIGN_REPORT}.[/yellow]")
        # A campaign stopped on its way (kill switch, the watch gone mid-campaign) did not
        # complete: a script, or `make orodruin-campaign-run`, must see it.
        if result.state == "aborted":
            raise SystemExit(EXIT_RUN_FAILED)


_CAMPAIGN_HINT = ("lancer la watch de Glorfindel (ou la watch hébergée, vue par "
                  "EREGION_WATCH_CHANNEL), ou --without-glorfindel pour une campagne de "
                  "développement ; une campagne reprise garde son réglage de départ.")


def _publish_campaign(cdir, runs_dir, state, without_glorfindel=False) -> bool:
    """#167: carry the finished campaign to H0 over the exercise channel — its manifest and
    its runs' reports, nothing else (eregion_core/exercise_channel.py) — and say where its
    report will be written: on H0 for a ``done`` campaign only (the hosted watch writes no
    other) whose executed runs all had their report to publish, by hand otherwise (and an
    executed run without a report is said). False without a channel (nothing sent) or when the
    publication failed: reported, never raised (the campaign has run)."""
    from pathlib import Path

    from eregion_core import exercise_channel

    if not exercise_channel.channel_url():
        return False
    try:
        cid, names = exercise_channel.publish_campaign(cdir, Path(runs_dir))
    except Exception as exc:
        console.print(f"[yellow]Campaign not published to H0 ({type(exc).__name__}: "
                      f"{str(exc)[:120]})[/yellow]")
        return False
    try:
        missing = exercise_channel.unpublished_runs(cdir, Path(runs_dir))
    except Exception:  # the manifest was just published from this very file
        missing = []
    if without_glorfindel:  # V1: H0 writes no report for it (analysis/hosted_report.py)
        console.print(f"[yellow]Campaign published to H0[/yellow] ({len(names)} file(s)) — "
                      "no report will be written for it there")
    elif missing:
        # H0 waits for the report of every executed run: without them, it never writes the
        # campaign's (`--runs-dir` other than runs/: the runs' reports stay in runs/).
        console.print(f"[yellow]Campaign published to H0[/yellow] ({len(names)} file(s)) — "
                      f"{len(missing)} executed run(s) without a report under {runs_dir}/ "
                      f"(not published): H0 will not write its report on its own. By hand, "
                      f"where the campaign, its runs and the watch's files are: "
                      f"make campaign-report CAMPAIGN={cid}")
    elif state == "done":
        console.print(f"[green]Campaign published to H0[/green] ({len(names)} file(s)) — the "
                      f"hosted watch writes its report: runs/campaigns/{cid}/report.md on H0 "
                      f"(make glorfindel-host-campaign-report CAMPAIGN={cid})")
    else:
        console.print(f"[yellow]Campaign published to H0[/yellow] ({len(names)} file(s)) — "
                      f"'{state}': no report is written on its own; by hand, where the "
                      f"campaign and the watch's files are: make campaign-report CAMPAIGN={cid}")
    return True


def _write_campaign_report(cdir) -> None:
    """IA0: the report writes itself at the end of a campaign. Never fails the campaign —
    without the analysis package or a model key, it says so and how to write it later."""
    try:
        from analysis import campaign_report as cr
        rep = cr.build(cdir)
        out = cdir / "report.md"
        out.write_text(cr.render(rep), encoding="utf-8")
        console.print(f"[green]Campaign report → {out}[/green]  "
                      f"{len(rep.kept)} claim(s) kept, {len(rep.rejected)} rejected by the check")
    except Exception as exc:  # the campaign ran; its report can be written later
        console.print(f"[yellow]Campaign report not written ({type(exc).__name__}: {str(exc)[:120]}) — "
                      f"later: make campaign-report CAMPAIGN={cdir.name}[/yellow]")


@campaign.command(name="list")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_list(runs_dir):
    """List campaigns and their state."""
    from annatar.campaign.manifest import CampaignManifest, campaigns_root

    root = campaigns_root(runs_dir)
    if not root.exists():
        console.print("[dim]No campaigns yet.[/dim]")
        return
    for d in sorted(root.iterdir()):
        if not (d / "manifest.json").exists():
            continue
        m = CampaignManifest.load(d)
        r = m.results
        console.print(
            f"{m.campaign_id}  [{m.state}]  {len(m.scenarios)} scenario(s)  "
            f"detected={r['detected']}/{r['executed']}"
        )


@campaign.command(name="show")
@click.argument("campaign_id")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_show(campaign_id, runs_dir):
    """Show a campaign manifest summary."""
    from annatar.campaign.manifest import CampaignManifest, campaign_dir

    cdir = campaign_dir(campaign_id, runs_dir=runs_dir)
    if not (cdir / "manifest.json").exists():
        console.print(f"[red]Campaign not found:[/red] {campaign_id}")
        raise SystemExit(1)
    m = CampaignManifest.load(cdir)
    console.print(f"[bold]{m.campaign_id}[/bold]  state={m.state}  objective={m.objective!r}")
    console.print(f"scope: {m.scope.allowed_resource_ids}")
    for e in m.scenarios:
        det = e.detection or "-"
        console.print(
            f"  [{e.seq}] {e.ttp:12} {e.status:9} detection={det:9} "
            f"run_id={e.run_id or '-'}"
        )


