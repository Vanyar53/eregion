"""Write host.env — the hosted Glorfindel's environment (H0) — from the operator's own.

    python infra/glorfindel-host/host_env.py infra/glorfindel-host/host.env   # .envrc loaded
    python infra/glorfindel-host/host_env.py --check infra/glorfindel-host/host.env

Only what the VM needs: the subscription, the model's key, the Discord bot (the VM runs
it: `docker compose --profile bot`), who may press its buttons, and the webhook. One file,
read by docker compose to fill docker-compose.yml: each container then receives only the
variables its own list names (M-3, #183) — the model's key the watch, the bot's token the
bot, the console's token the console. Never an Azure secret — the VM
authenticates by its managed identity, and AZURE_CLIENT_ID alone would make
DefaultAzureCredential look for a user-assigned identity that doesn't exist. Always
GLORFINDEL_READ_ONLY=1, and a console token drawn here, under its name, EREGION_CONSOLE_TOKEN.
Refuses to overwrite an existing file (the token would change).
Prints the keys it wrote, never a value.

A host.env written before UI-1 carries the token under its former name,
GLORFINDEL_WARROOM_TOKEN: it stays valid, nothing to rename. `--check` (run by
`make glorfindel-host-push`) says which name carries it — the console's rule: the new name
when it is not empty, else the former — and refuses a host.env with neither: pushed, it would
leave the console on the VM without a token. Never prints the token.

The model's key is the one its provider reads (OL1, #525; the rule: eregion_core/models.py,
`required_env`): ANTHROPIC_API_KEY for anthropic/… or the default, OPENAI_API_KEY for
openai/…, AZURE_API_KEY and AZURE_API_BASE (or GLORFINDEL_LLM_BASE_URL in its place) for
azure/…, MISTRAL_API_KEY for mistral/…; no key for a local model (ollama/…), but
GLORFINDEL_LLM_BASE_URL — in the watch's container, LiteLLM's default address is the container
itself; nothing for an OpenAI-compatible model served at GLORFINDEL_LLM_BASE_URL (self-hosted).
An unknown provider is refused, with the list. The message names what is missing, never a
value. host.env carries only the keys of the configured models' providers, never another
provider's. `--check` (and `make glorfindel-host-model`, before it writes anything) holds a
host.env to the same rule, its model's variables read as the watch receives them. The analysis
model (EREGION_ANALYSIS_MODEL) writes the campaign reports, never a decision: its missing key,
or a local analysis model (it does not read GLORFINDEL_LLM_BASE_URL), is said, not refused.

The never_target list (NT1, #583; eregion_core/never_target.py), which the watch reads to write
an identity card's plan (IR1a): ids, no secret, copied from the operator's environment like the
rest — each one's source a Terraform output, named in NEVER_TARGET, never read here. One empty,
or an entry that is no object id, is said, by the writing and by `--check`, never refused: an
unreadable list refuses every identity — each verb of a plan a human's step, closed, not a
breakdown. What is said names the variable and its source, never a value; the executor's client
id empty is said as information (ℹ): it stays empty as long as the executor is not enabled.

The azurerm canary's appid (CAN2, #605), EREGION_RULE_CANARY_APPID: the bench's copy of
nsg-change-outside-glorfindel takes it from the watch's environment to set the canary's runs aside.
An id, no secret, copied like the rest; empty or no GUID, it is said (`canary_warning`), never
refused — the shipped rule runs, and the canary makes its cards.

A value written, any of COPIED, never holds a line break, a carriage return, a quote, a `$` or a
backslash (one pair of quotes around it is unwrapped, as compose reads it): refused, the
variable named, never the value — a line break would add a variable of its own to host.env, a
quote left open would make compose refuse the whole file, a `$` would be interpolated by compose
(`'a$HOME'` written `a$HOME`: the watch would receive a path), a backslash read as an escape.
`--check` refuses a line whose value opens a quote it never closes, or holds a backslash inside
quotes (`"abc\\"`: compose takes the next line into the value, or refuses the file).
"""
from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eregion_core.models import (  # noqa: E402
    BASE_URL, DEFAULT_ANALYSIS_MODEL, LOCAL_PROVIDERS, PROVIDER_ENV, UnknownProvider, missing_env,
    model_provider,
)
from eregion_core.never_target import ids  # noqa: E402

# OL1: every provider's variables — docker-compose.yml (x-models) passes them all to the watch.
# host.env carries only those of the configured models' providers (carried_keys), never another
# provider's key: an operator's .envrc may hold several.
MODEL_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MISTRAL_API_KEY", "AZURE_API_KEY",
              "AZURE_API_BASE", "AZURE_API_VERSION")
# NT1 (#583): the never_target list, to the watch alone (docker-compose.yml) — each variable, its
# source (a Terraform output, read by the operator into .envrc), and what its absence leaves.
_ORODRUIN_OUT = "terraform -chdir=infra/orodruin output -raw"
_HOST_OUT = "terraform -chdir=infra/glorfindel-host output -raw"
NEVER_TARGET = {
    "EREGION_OPERATOR_OBJECT_ID": (
        f"{_ORODRUIN_OUT} operator_object_id",
        "la liste never_target de la watch est illisible : chaque verbe d'un plan d'identité (IR1a) "
        "devient une étape de l'humain — fermé, pas une panne"),
    "EREGION_PROTECTED_IDENTITIES": (
        f"{_ORODRUIN_OUT} protected_identities, et l'object id de l'exécuteur ({_HOST_OUT} "
        "identity_executor_object_id), séparés par des virgules",
        "Orodruin et les watches ne sont pas dans la liste never_target de la watch : un plan "
        "d'identité pourrait les viser"),
    "EREGION_IDENTITY_EXECUTOR_CLIENT_ID": (
        f"{_HOST_OUT} identity_executor_client_id",
        "l'exécuteur d'identité n'est pas dans la liste never_target de la watch (vide tant qu'il "
        "n'est pas activé, identity_executor_enabled : rien à faire alors)"),
}
# Its client id is empty as long as the executor is not enabled: said, never as a warning.
EXECUTOR = "EREGION_IDENTITY_EXECUTOR_CLIENT_ID"
# What a value written into host.env never holds (NT1 review, measured with `docker compose
# config`): a line break adds a line — a variable of its own, which compose reads (the signed
# queue switched on, its keys); a quote compose opens and never closes refuses the whole file, and
# no service starts on H0; compose interpolates a `$` (second review: `'a$HOME'`, unwrapped, gave
# the watch a path) and reads a backslash as an escape. Every value copied, not only the list's.
UNSAFE = {"\n": "a line break", "\r": "a carriage return", "$": "a dollar sign", "\\": "a backslash",
          '"': "a quote", "'": "a quote"}
COPIED = ("AZURE_SUBSCRIPTION_ID", "AZURE_WORKSPACE_ID",
          "GLORFINDEL_LLM_MODEL", "GLORFINDEL_LLM_BASE_URL", *MODEL_KEYS,
          "GLORFINDEL_WEBHOOK_URL", "GLORFINDEL_BACKUP_VAULT",
          "DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID", "DISCORD_PING_ROLE",
          "DISCORD_ALLOWED_USERS", "DISCORD_ALLOWED_ROLES",
          "EREGION_EXERCISE_CHANNEL", "EREGION_WATCH_CHANNEL",
          # IA1: the analysis AI's model, never Glorfindel's — the hosted watch writes the
          # campaign reports with it (analysis/hosted_report.py).
          "EREGION_ANALYSIS_MODEL",
          # CAN2: the azurerm canary's appid, which the bench's copy of nsg-change-outside-glorfindel
          # takes from the watch's environment (`env_guids`) — an id, no secret.
          "EREGION_RULE_CANARY_APPID",
          # NT1: who is never a target, read by the watch (eregion_core/never_target.py).
          *NEVER_TARGET)
CANARY = "EREGION_RULE_CANARY_APPID"
# The model's key is required by its provider (model_missing), never here.
REQUIRED = ("AZURE_SUBSCRIPTION_ID",)
MODEL = "GLORFINDEL_LLM_MODEL"
ANALYSIS = "EREGION_ANALYSIS_MODEL"
# The console's token, and its former name (eregion_console/api.py, console_token).
TOKEN = "EREGION_CONSOLE_TOKEN"
LEGACY_TOKEN = "GLORFINDEL_WARROOM_TOKEN"
# FS1c: the signed action queue — never copied from the operator's environment: its keys are this
# workstation's, H0's are its own (`make glorfindel-host-queue-keys`). Written in host.env by hand,
# keys and flag in one push; --check holds them together.
QUEUE_FLAG = "EREGION_ACTION_QUEUE"
QUEUE_KEYS = "EREGION_QUEUE_KEYS"
QUEUE_GESTURE = ("make glorfindel-host-queue-keys, then its line and EREGION_ACTION_QUEUE=1 in host.env, "
                 "then make glorfindel-host-push (docs/operations.md, « La file d'actions signée »)")


def queue_problems(env: dict) -> list[str]:
    """FS1c: what keeps H0's queue from taking a gesture, said before the push — a flag the queue
    does not read (« 1 » only), or the flag set without the console's key pinned at the watch, or
    without the bot's while the bot runs (DISCORD_BOT_TOKEN): pushed, the console of H0 would grey
    every write and the watch refuse them all (no_key_pinned). Empty: nothing to say."""
    from eregion_core.action_queue import parse_pins, pin_problems
    flag = env.get(QUEUE_FLAG, "")
    if flag not in ("", "1"):
        return [f"{QUEUE_FLAG}={flag[:20]!r}: the queue reads « 1 » only — anything else leaves it off"]
    if flag != "1":
        return []
    pins, wrong = parse_pins(env.get(QUEUE_KEYS, ""))
    services = ("console", "bot") if env.get("DISCORD_BOT_TOKEN") else ("console",)
    return pin_problems(pins, wrong, services)


def model_missing(environ: dict) -> tuple[str, list[str]]:
    """(the provider of the decision model, the variables it needs that `environ` leaves
    empty). An unknown provider: SystemExit, with the list — never the value."""
    model = environ.get(MODEL, "")
    try:
        return model_provider(model), missing_env(model, environ)
    except UnknownProvider as exc:
        raise SystemExit(f"{MODEL}: {exc}") from None


def _analysis_provider(environ: dict) -> str:
    """The analysis model's provider, "" when it names none known."""
    try:
        return model_provider(environ.get(ANALYSIS, "") or DEFAULT_ANALYSIS_MODEL)
    except UnknownProvider:
        return ""


def analysis_warning(environ: dict) -> str:
    """What the analysis model lacks, said: it writes the campaign reports (IA1), never a
    decision — a report that fails is given up after 3 attempts. "" when nothing. A local
    analysis model is said too: the analysis never passes GLORFINDEL_LLM_BASE_URL
    (analysis/campaign_report.py, analysis/triage.py), so it would call the watch's container."""
    provider = _analysis_provider(environ)
    if not provider:
        return (f"⚠ {ANALYSIS} ne nomme aucun fournisseur connu ({', '.join(PROVIDER_ENV)}) : "
                "les rapports de campagne échoueront.")
    if provider in LOCAL_PROVIDERS:
        return (f"⚠ l'IA d'analyse ({ANALYSIS}) est un modèle local, mais elle ne lit pas "
                f"{BASE_URL} : dans le conteneur de la watch, elle viserait le conteneur lui-même, "
                "et les rapports de campagne échoueront. Garde un modèle d'analyse d'un fournisseur, "
                "avec sa clé.")
    lacking = [k for k in PROVIDER_ENV[provider] if not environ.get(k)]
    if not lacking:
        return ""
    return (f"⚠ l'IA d'analyse ({ANALYSIS}, vide : {DEFAULT_ANALYSIS_MODEL}) lit "
            f"{', '.join(lacking)}, vide : les rapports de campagne échoueront. Pose la clé, ou "
            f"un autre modèle dans {ANALYSIS}.")


def never_target_warnings(environ: dict) -> list[str]:
    """What the watch's never_target list lacks, said — one line a variable, its source named,
    never its value: an empty one, or one with an entry that is no object id (read strictly, as
    eregion_core/never_target.py reads it: the whole list then refuses every identity). Never a
    refusal: the absence leaves every verb of a plan a human's step, closed."""
    said = []
    for name, (source, left) in NEVER_TARGET.items():
        got, bad = ids(environ.get(name, ""))
        if bad:
            said.append(f"⚠ {name} porte {len(bad)} entrée(s) qui ne sont pas des object ids : la liste "
                        "never_target de la watch est illisible, chaque verbe d'un plan d'identité "
                        f"devient une étape de l'humain. Sa source : {source}.")
        elif not got:
            mark = "ℹ" if name == EXECUTOR else "⚠"
            said.append(f"{mark} {name} vide : {left}. Sa source : {source}.")
    return said


_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def canary_warning(value: str) -> str:
    """CAN2: the azurerm canary's appid, as the watch reads it — said when it is set but no GUID
    (the watch ignores it: the canary's runs make their cards, the shipped rule running). Empty is
    not said here (a deployment without the bench's layer has no use of it): the watch says it, when
    a rule of its layer needs it. Never the value; never a refusal. "" otherwise."""
    value = value.strip()
    if not value or _GUID.fullmatch(value):
        return ""
    return (f"⚠ {CANARY} n'est pas un GUID : la watch l'ignore, et les runs du canari azurerm font leurs "
            "cartes nsg-change-outside-glorfindel (la règle livrée tourne). Sa source : l'appid du "
            "principal du canari (docs/operations.md, « Le canari azurerm, sans secret »).")


def never_target_read(env: dict) -> dict:
    """The list's variables as the watch receives them (model_value: a pair of quotes removed, a
    comment alone empty) — `terraform output` without `-raw` gives a quoted value."""
    return {k: model_value(env.get(k, "")) for k in NEVER_TARGET}


def unquoted(value: str) -> str:
    """A value with one pair of quotes around it, unwrapped — what compose reads of `KEY="…"`;
    any other value as it is."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def unsafe(out: dict) -> None:
    """SystemExit if a value to write holds what UNSAFE names: the variable said, never the value."""
    for k, v in out.items():
        held = sorted({what for c, what in UNSAFE.items() if c in v})
        if held:
            raise SystemExit(f"{k} holds {' and '.join(held)}: written into host.env, it would add a "
                             "variable that docker compose reads, or make compose refuse the whole file "
                             "(no service would start on H0). Its value is not printed — set it again, "
                             "on one line, without quotes.")


def carried_keys(environ: dict) -> set[str]:
    """The model variables host.env carries: those of the decision model's provider (its own
    key, even when a self-hosted endpoint does not require it) and of the analysis model's;
    AZURE_API_VERSION with an azure/… model only. Never another provider's key."""
    providers = {model_provider(environ.get(MODEL, "")), _analysis_provider(environ)} - {""}
    keys = {k for p in providers for k in PROVIDER_ENV[p]}
    if "azure" in providers:
        keys.add("AZURE_API_VERSION")
    return keys


def host_env(environ: dict) -> dict:
    missing = [k for k in REQUIRED if not environ.get(k)]
    provider, lacking = model_missing(environ)
    if missing or lacking:
        said = missing + ([f"{', '.join(lacking)} (the model's provider, {provider}, {MODEL})"]
                          if lacking else [])
        raise SystemExit(f"missing in the environment (load .envrc): {'; '.join(said)}")
    carried = carried_keys(environ)
    out = {k: unquoted(environ[k]) for k in COPIED if environ.get(k) and (k not in MODEL_KEYS or k in carried)}
    out["GLORFINDEL_READ_ONLY"] = "1"
    # A powered-off VM stays on the map a week (default 8 h): gondolin, off between
    # exercises, kept vanishing from the observed fleet.
    out.setdefault("GLORFINDEL_DISCOVERY_RETENTION_H", environ.get("GLORFINDEL_DISCOVERY_RETENTION_H") or "168")
    unsafe(out)                         # NT1 review: no line nor quote injected into host.env
    out[TOKEN] = secrets.token_urlsafe(24)
    return out


def read_env(path: Path) -> dict:
    """KEY=value lines of a host.env, as docker compose reads them (`docker compose config`,
    measured 27/10): the last line of a key wins; comment lines and blank lines are skipped;
    the value is trimmed, then a « # … » after a blank is a comment — but `KEY=   # note`
    gives « # note », not an empty value. The Makefile and status.sh read the console's token
    the same way."""
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = re.sub(r"\s+#.*$", "", value.strip()).strip()
    return out


def model_value(value: str) -> str:
    """A model's variable of a host.env read by read_env, as the watch receives it: a pair of
    quotes around it removed, as compose removes them (`KEY=""` is empty); a value that is only
    a comment (`KEY=   # note`, which compose keeps as « # note ») is no key nor model: empty.
    The console's token keeps read_env's reading — the Makefile and status.sh share it."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return "" if v.startswith("#") else v


def token_name(env: dict) -> str:
    """The variable that carries the console's token: TOKEN when it is not empty, else
    LEGACY_TOKEN when it is not, else "". Not empty, not merely present: compose passes both,
    empty when unset."""
    for name in (TOKEN, LEGACY_TOKEN):
        if env.get(name, ""):
            return name
    return ""


def _quoted(path: Path):
    """(variable, value) of each line of a host.env whose value starts with a quote, trimmed — read
    on the raw line, before read_env cuts a « # » inside quotes."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            v = value.strip()
            if v[:1] in ("\"", "'"):
                yield key.strip(), v


def unclosed(path: Path) -> list[str]:
    """The variables whose value opens a quote it never closes on its line: docker compose refuses
    the whole file (« unterminated quoted value », measured)."""
    return [k for k, v in _quoted(path) if v.find(v[0], 1) == -1]


def escaped(path: Path) -> list[str]:
    """The variables with a backslash inside a quoted value: compose reads `\\"` as an escaped
    quote — `"abc\\"` never closes, it takes the next line into the value or refuses the file
    (second review, measured); `'a\\'` the same."""
    return [k for k, v in _quoted(path) if "\\" in v]


def check(dst: str) -> int:
    if names := unclosed(Path(dst)):
        raise SystemExit(f"{dst}: {', '.join(names)} opens a quote it never closes — docker compose "
                         "would refuse the whole file, and no service would start on H0. Close it, or "
                         "write the value without quotes.")
    if names := escaped(Path(dst)):
        raise SystemExit(f"{dst}: {', '.join(names)} holds a backslash inside quotes — docker compose "
                         "reads it as an escape: the value may take the next line, or the whole file be "
                         "refused. Write the value without quotes nor backslash.")
    env = read_env(Path(dst))
    name = token_name(env)
    if name and env[name].startswith("#"):
        # `KEY=   # note`: compose takes « # note » as the value (measured, 27/10).
        raise SystemExit(f"{dst}: {name} holds a comment, which docker compose would take as the "
                         "token — write the value alone on its line.")
    if not name:
        raise SystemExit(f"{dst}: no console token ({TOKEN}, or its former name {LEGACY_TOKEN}) — "
                         f"pushed, the console on the VM would run without one. Set {TOKEN} "
                         "(python -c 'import secrets; print(secrets.token_urlsafe(24))').")
    # OL1: the key the model's provider reads — pushed without it, the watch could not decide.
    provider, lacking = model_missing({k: model_value(env.get(k, "")) for k in (MODEL, BASE_URL, *MODEL_KEYS)})
    if lacking:
        raise SystemExit(f"{dst}: {', '.join(lacking)} empty — the model's provider, {provider} "
                         f"({MODEL}), needs it: pushed, the watch could not decide.")
    # FS1c: the queue's flag and its keys together, as the watch reads them.
    lacking = queue_problems({k: model_value(env.get(k, "")) for k in (QUEUE_FLAG, QUEUE_KEYS, "DISCORD_BOT_TOKEN")})
    if lacking:
        raise SystemExit(f"{dst}: the signed action queue would refuse every gesture — " + "; ".join(lacking)
                         + f". The gesture: {QUEUE_GESTURE}.")
    # NT1: the never_target list, as the watch receives it — said, never refused.
    for warning in never_target_warnings(never_target_read(env)):
        print(f"{dst}: {warning}", file=sys.stderr)
    if canary := canary_warning(model_value(env.get(CANARY, ""))):      # CAN2: said, never refused
        print(f"{dst}: {canary}", file=sys.stderr)
    if name == LEGACY_TOKEN:
        print(f"{dst}: console token under its former name, {LEGACY_TOKEN} — valid, nothing to rename")
    else:
        print(f"{dst}: console token under {TOKEN} (a reference before UI-1, v0.3.0 or earlier, "
              f"reads only {LEGACY_TOKEN}: its War Room would start without a token)")
    return 0


def main(dst: str) -> int:
    path = Path(dst)
    if path.exists():
        raise SystemExit(f"{dst} exists — remove it first to draw a new console token")
    env = host_env(dict(os.environ))
    if env.get("DISCORD_BOT_TOKEN") and not (env.get("DISCORD_ALLOWED_USERS") or env.get("DISCORD_ALLOWED_ROLES")):
        print("⚠ DISCORD_ALLOWED_USERS / DISCORD_ALLOWED_ROLES vides : les boutons du bot refuseront "
              "tout clic (fermé par défaut). Ajoute ton id Discord à host.env.", file=sys.stderr)
    if warning := analysis_warning(env):
        print(warning, file=sys.stderr)
    if os.environ.get(QUEUE_FLAG) or os.environ.get(QUEUE_KEYS):
        print(f"ℹ {QUEUE_FLAG} / {QUEUE_KEYS} de ton environnement ne vont pas dans host.env : ce sont "
              f"les clés de ce poste, H0 a les siennes — {QUEUE_GESTURE}.", file=sys.stderr)
    for warning in never_target_warnings(never_target_read(env)):
        print(warning, file=sys.stderr)
    if warning := canary_warning(env.get(CANARY, "")):
        print(warning, file=sys.stderr)
    path.touch(mode=0o600)
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    print(f"{dst}: " + ", ".join(env))
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        sys.exit(check(sys.argv[2]))
    sys.exit(main(sys.argv[1]))
