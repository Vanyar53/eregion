"""`eregion` — the command of Eregion as a whole: today, its console."""
import os

import click

from eregion_console import sections


@click.group()
def cli():
    """Eregion — Glorfindel defends, Annatar and Gothmog prove it."""
    # The console reads Azure with the host's identity. Compose passes `${AZURE_CLIENT_ID:-}`:
    # empty, it stops azure-identity before the VM's managed identity — the glorfindel
    # command drops it, this one must too (H0, 26/10: every read of the console failed).
    from glorfindel.cli import _drop_empty_service_principal_env
    _drop_empty_service_principal_env()


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Listen address. Loopback by default: the console triggers real Azure "
                   "actions. It answers under a loopback name, or one EREGION_CONSOLE_HOSTS lists.")
@click.option("--port", default=7007, show_default=True)
@click.option("--sections", "chosen", default=None, metavar="annatar,gothmog",
              help="The injectors to show, whatever this host holds (else detected from "
                   "runs/). Glorfindel is always shown.")
def console(host: str, port: int, chosen: str | None):
    """Start the web console (http://localhost:7007): Overview, Glorfindel, Annatar,
    Gothmog, Config.

    Requires: pip install -e '.[console]', from the clone

    Every page and API call requires the token: EREGION_CONSOLE_TOKEN (or
    GLORFINDEL_WARROOM_TOKEN, its former name), else the one drawn at the first start and kept in
    ~/.glorfindel/console_token (mode 600), printed with the URL. Open
    http://localhost:7007/?token=<token> once (a session cookie is then kept), or send
    `Authorization: Bearer <token>` from scripts.
    """
    if chosen is not None:
        os.environ[sections.ENV] = chosen
    try:
        sections.override()
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--sections") from exc
    from eregion_console.api import serve
    serve(host=host, port=port)


_MARK = {"detected": "✓", "pass": "✓", "missed": "✗", "fail": "✗", "unknown": "?",
         "not_measured": "·", "refused": "·"}


def _age(seconds) -> str:
    if seconds is None:
        return "—"
    s = max(0, int(seconds))
    return f"{s // 86400}d" if s >= 86400 else f"{s // 3600}h" if s >= 3600 else f"{s // 60}m"


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="The matrix as GET /api/coverage gives it.")
@click.option("--check", is_flag=True,
              help="Exit 1 when a technique or a fault regressed: proven before, failed since.")
def coverage(as_json: bool, check: bool):
    """The coverage matrix (C1), from runs/ in this directory: each technique of the catalog and
    each declared fault, its last run, its last proof and its state — proven, aging (21 days),
    stale (over 30), regressed, unproven, never.

    Reads the run reports, the watch's cycles and the catalog only: no cloud, no model. After a
    replay of the catalog on the bench (from Orodruin), `eregion coverage --check` is the
    non-regression: it fails on a technique detected before and missed since.
    """
    import json
    import time

    from eregion_console.api import coverage_matrix
    from eregion_core.run_report import epoch
    now = time.time()
    m = coverage_matrix(now)
    regressed = m["summary"]["techniques"]["regressed"] + m["summary"]["faults"]["regressed"]
    if as_json:
        click.echo(json.dumps(m, indent=2))
    else:
        if m.get("error"):
            click.echo(f"! {m['error']}")
        for half in ("techniques", "faults"):
            click.echo(f"{half.upper():<14}{'state':<11}{'last run':<26}{'last proof':<12}history")
            for r in m[half]:
                last, proof = r["last_run"], r["last_proof"]
                run = f"{_age(now - (epoch(last['at']) or now))} ago {last['outcome']}" if last else "—"
                shown = f"{_age(proof['age_s'])} ago" if proof else "—"
                click.echo(f"{str(r['id'])[:13]:<14}{r['state']:<11}{run[:25]:<26}{shown:<12}"
                           f"{''.join(_MARK.get(h['outcome'], '?') for h in r['history'])}"
                           f"{'' if r['in_catalog'] else '  (outside the catalog)'}")
            click.echo("")
        s = m["summary"]["techniques"]
        point = m["evolution"][-1] if m["evolution"] else {}
        click.echo(f"coverage: {point.get('implemented_detected', 0)} / {s['implemented']} implemented "
                   f"techniques detected in {m['window_days']} d · stale {s['stale']} · "
                   f"never proven {s['never'] + s['unproven']}")
        click.echo("regressed: " + (", ".join(regressed) if regressed else "none"))
    if check and regressed:
        raise SystemExit(1)
