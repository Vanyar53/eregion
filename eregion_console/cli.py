"""`eregion` — the command of Eregion as a whole: today, its console."""
import os

import click

from eregion_console import sections


@click.group()
def cli():
    """Eregion — Glorfindel defends, Annatar and Gothmog prove it."""


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Listen address. Loopback by default: the console triggers real Azure "
                   "actions. To expose it, set EREGION_CONSOLE_TOKEN first.")
@click.option("--port", default=7007, show_default=True)
@click.option("--sections", "chosen", default=None, metavar="annatar,gothmog",
              help="The injectors to show, whatever this host holds (else detected from "
                   "runs/). Glorfindel is always shown.")
def console(host: str, port: int, chosen: str | None):
    """Start the web console (http://localhost:7007): Overview, Glorfindel, Annatar,
    Gothmog, Config.

    Requires: pip install eregion[console]

    With EREGION_CONSOLE_TOKEN set (or GLORFINDEL_WARROOM_TOKEN, its former name), every
    page and API call requires the token: open http://<host>:7007/?token=<token> once (it is
    then kept in a cookie), or send `Authorization: Bearer <token>` from scripts.
    """
    if chosen is not None:
        os.environ[sections.ENV] = chosen
    try:
        sections.override()
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--sections") from exc
    from eregion_console.api import serve
    serve(host=host, port=port)
