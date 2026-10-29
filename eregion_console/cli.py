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
