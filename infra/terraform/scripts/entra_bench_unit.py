#!/usr/bin/env python3
"""IDI1b (#573) — what the azuread provider (3.10.0) cannot declare, by Microsoft Graph, under the
operator's az login (never a principal): Eregion's attribute set and its two definitions, the bench's
RESTRICTED administrative unit, and the enrollment attribute on a test user.

    prepare            read only: what exists, what would be created (the requests, in full)
    prepare --yes      creates what is missing: the set « Eregion », its definitions eregionTarget and
                       eregionZone, and — when no unit is pinned (EREGION_BENCH_ADMIN_UNIT_ID) — the
                       restricted unit, whose id it prints: pin it in terraform.tfvars
                       (entra_bench_unit_id); a pinned unit is read again, restricted or refused
    assign             the attribute on one user (EREGION_USER_OBJECT_ID, EREGION_ATTR_TARGET,
                       EREGION_ATTR_ZONE), then read back — Terraform's terraform_data calls it
                       (entra_bench_unit.tf), before the user enters the unit

Why here and not in Terraform: azuread_administrative_unit has no isMemberManagementRestricted (the
restriction is fixed at creation, never changed after), and no resource of azuread defines an
attribute set, a definition, or a user's attribute (docs/design/reponse-identite.md, hypothesis 13).
An attribute set and a definition cannot be deleted (only deactivated): they live in the tenant, not
in the disposable stack.

Every call is ``az rest`` with an argument list (no shell); the az login must be on the bench's
subscription (AZURE_SUBSCRIPTION_ID or ARM_SUBSCRIPTION_ID), as a user. Standard library only: run
from the repository, by make (celebrimbor-unit-prepare) or by Terraform. Tests:
tests/unit/test_bench_users.py, against a fake az. The names are the guard's
(eregion_core/inscription.py: ATTRIBUTE_SET, ATTRIBUTE_NAMES), checked equal there.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

GRAPH = "https://graph.microsoft.com/v1.0"
ATTRIBUTE_SET = "Eregion"
ATTRIBUTES = {
    "eregionTarget": "Le banc qui inscrit cet utilisateur (eregion-target : un nom d'attribut n'admet pas le tiret).",
    "eregionZone": "La zone de l'utilisateur inscrit (eregion-zone) : bench, twin ou production.",
}
ZONES = ("bench", "twin", "production")
UNIT_NAME = "au-celebrimbor-bench"
UNIT_DESCRIPTION = ("Eregion (IDI1b) : l'unité restreinte du banc. Seuls ses utilisateurs de test, sans rôle ; "
                    "jamais un opérateur, un compte de secours ni un groupe.")
UNIT_ENV = "EREGION_BENCH_ADMIN_UNIT_ID"
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
BENCH = re.compile(r"celebrimbor(-[a-z0-9-]{1,40})?")
CSA_TYPE = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
# az rest says a 404 on its standard error (ERROR: Not Found(…Request_ResourceNotFound…)): to measure.
_NOT_FOUND = re.compile(r"Not Found|NotFound|Request_ResourceNotFound")
UNIT_SELECT = "id,displayName,isMemberManagementRestricted,membershipType"
# A unit just created may not be readable yet (replication): read again, a few times, spaced.
READ_TRIES = 4
DELAY_ENV = "EREGION_GRAPH_RETRY_S"


class Refused(Exception):
    """A state this script does not build on: said, nothing written."""


def _az(*args: str) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["az", *args], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise Refused(f"az {' '.join(args[:3])} n'a pas répondu en 120 s : rien n'est tenu pour fait, relancer")
    except OSError as e:
        raise Refused(f"az introuvable ou illisible : {e}")
    return r.returncode, r.stdout, r.stderr


def _json(out: str, what: str) -> dict:
    try:
        got = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        raise Refused(f"{what} : une réponse qui n'est pas du JSON ({out.strip()[:120]!r})")
    if not isinstance(got, dict):
        raise Refused(f"{what} : une réponse qui n'est pas un objet JSON")
    return got


def rest(method: str, path: str, body: dict | None = None) -> dict | None:
    """One request to Microsoft Graph. A GET answered 404 is None; any other error raises."""
    args = ["rest", "--method", method, "--url", f"{GRAPH}{path}"]
    if body is not None:
        args += ["--headers", "Content-Type=application/json", "--body", json.dumps(body)]
    code, out, err = _az(*args)
    if code != 0:
        if method == "GET" and _NOT_FOUND.search(err or ""):
            return None
        raise Refused(f"az rest {method} {path} : {(err or out).strip()[:300]}")
    return _json(out, f"az rest {method} {path}")


def check_login() -> None:
    """The az login: a user, on the bench's subscription — its token is the bench's tenant's."""
    want = (os.environ.get("AZURE_SUBSCRIPTION_ID") or os.environ.get("ARM_SUBSCRIPTION_ID") or "").strip().lower()
    if not GUID.fullmatch(want):
        raise Refused("AZURE_SUBSCRIPTION_ID absent : l'abonnement du banc n'est pas nommé (source .envrc)")
    code, out, err = _az("account", "show", "--query", "{id:id, type:user.type}", "-o", "json")
    if code != 0:
        raise Refused(f"az account show : {(err or out).strip()[:200]} (az login d'abord)")
    acct = _json(out, "az account show")
    if str(acct.get("id") or "").lower() != want:
        raise Refused("l'abonnement courant d'az n'est pas celui du banc : az account set --subscription "
                      "\"$AZURE_SUBSCRIPTION_ID\"")
    if acct.get("type") != "user":
        raise Refused("az est connecté sous un principal : appliquer sous ton az login, jamais un principal")


def _definition(name: str) -> dict:
    return {"attributeSet": ATTRIBUTE_SET, "name": name, "description": ATTRIBUTES[name], "type": "String",
            "status": "Available", "isCollection": False, "isSearchable": True, "usePreDefinedValuesOnly": False}


def _unit_body() -> dict:
    return {"displayName": UNIT_NAME, "description": UNIT_DESCRIPTION, "isMemberManagementRestricted": True}


def _unit_refusal(got: dict) -> str:
    """Why this unit is not the bench's as Eregion builds it, or "": restricted, never dynamic."""
    if got.get("isMemberManagementRestricted") is not True:
        return "n'est pas restreinte — la restriction se fixe à la création, jamais après"
    if str(got.get("membershipType") or "").lower() == "dynamic":
        return "est dynamique — une règle, pas Celebrimbor, choisirait ses membres"
    return ""


def _delay() -> float:
    try:
        return max(0.0, float(os.environ.get(DELAY_ENV) or 5))
    except ValueError:
        return 5.0


def prepare(yes: bool, unit: str, say=print) -> str:
    """The set, its definitions, the unit. Returns the unit's id ("" when none is pinned nor made)."""
    check_login()
    if rest("GET", f"/directory/attributeSets/{ATTRIBUTE_SET}") is None:
        body = {"id": ATTRIBUTE_SET, "description": "Eregion : l'inscription des identités du banc (IDI1b).",
                "maxAttributesPerSet": 10}
        say(f"+ POST {GRAPH}/directory/attributeSets {json.dumps(body, ensure_ascii=False)}")
        if yes:
            rest("POST", "/directory/attributeSets", body)
    else:
        say(f"= l'ensemble d'attributs {ATTRIBUTE_SET} existe")
    for name in ATTRIBUTES:
        found = rest("GET", f"/directory/customSecurityAttributeDefinitions/{ATTRIBUTE_SET}_{name}")
        if found is None:
            body = _definition(name)
            say(f"+ POST {GRAPH}/directory/customSecurityAttributeDefinitions {json.dumps(body, ensure_ascii=False)}")
            if yes:
                rest("POST", "/directory/customSecurityAttributeDefinitions", body)
            continue
        if (found.get("type") != "String" or found.get("isCollection") is not False
                or found.get("status") != "Available"):
            raise Refused(f"{ATTRIBUTE_SET}.{name} existe, mais pas comme Eregion le définit (String, une "
                          f"valeur, Available) : {json.dumps(found)[:200]}")
        say(f"= la définition {ATTRIBUTE_SET}.{name} existe")

    if unit:
        if not GUID.fullmatch(unit):
            raise Refused(f"{UNIT_ENV} : un object id (GUID, en minuscules)")
        got = rest("GET", f"/directory/administrativeUnits/{unit}?$select={UNIT_SELECT}")
        if got is None:
            raise Refused(f"l'unité épinglée {unit} n'existe pas, ou n'est pas encore lisible, dans ce tenant")
        why = _unit_refusal(got)
        if why:
            raise Refused(f"l'unité épinglée {unit} {why} : ne pas s'en servir")
        say(f"= l'unité restreinte {unit} ({got.get('displayName')}) : entra_bench_unit_id = \"{unit}\"")
        return unit
    # No unit pinned. A unit of that name already: never a second one. A guard against a duplicate,
    # not an enrollment by the name — the guard and the executor pin the id, never this lookup.
    same = rest("GET", f"/directory/administrativeUnits?$filter=displayName%20eq%20'{UNIT_NAME}'&$select={UNIT_SELECT}")
    existing = [str(u.get("id") or "") for u in (same or {}).get("value") or [] if isinstance(u, dict)]
    if existing:
        raise Refused(f"une unité nommée {UNIT_NAME} existe déjà ({', '.join(existing)}) : la relire avec "
                      f"UNIT={existing[0]}, jamais en créer une seconde")
    body = _unit_body()
    say(f"+ POST {GRAPH}/directory/administrativeUnits {json.dumps(body, ensure_ascii=False)}")
    if not yes:
        say("  (aucune unité épinglée : YES=1 la crée, et dit son id à épingler)")
        return ""
    made = rest("POST", "/directory/administrativeUnits", body) or {}
    new = str(made.get("id") or "").lower()
    if not GUID.fullmatch(new):
        raise Refused(f"Graph n'a pas dit l'id de l'unité créée : {json.dumps(made)[:200]}")
    # What Graph answered to the creation itself: restricted, or not to pin.
    if made.get("isMemberManagementRestricted") is not True:
        raise Refused(f"l'unité {new} est créée, mais Graph la dit non restreinte : ne pas l'épingler "
                      f"(UNIT={new} la relit)")
    got = None
    for attempt in range(READ_TRIES):
        got = rest("GET", f"/directory/administrativeUnits/{new}?$select={UNIT_SELECT}")
        if got is not None:
            break
        if attempt < READ_TRIES - 1:
            time.sleep(_delay())
    if got is None:
        raise Refused(f"l'unité restreinte {new} est créée, mais pas encore lisible : la relire dans une minute "
                      f"avec UNIT={new} — ne pas en créer une autre")
    why = _unit_refusal(got)
    if why:
        raise Refused(f"l'unité {new}, relue, {why} : ne pas l'épingler")
    say(f"✓ l'unité restreinte {new} — à épingler dans infra/terraform/terraform.tfvars :\n"
        f"    entra_bench_unit_id = \"{new}\"\n  puis, pour relancer ce script : UNIT={new}")
    return new


def assign(user: str, bench: str, zone: str, say=print) -> None:
    """The enrollment attribute on one test user, then read back."""
    if not GUID.fullmatch(user or ""):
        raise Refused("EREGION_USER_OBJECT_ID : un object id (GUID, en minuscules)")
    if not BENCH.fullmatch(bench or ""):
        raise Refused(f"EREGION_ATTR_TARGET : un banc de Celebrimbor, pas {bench!r}")
    if zone not in ZONES:
        raise Refused(f"EREGION_ATTR_ZONE : une de {', '.join(ZONES)}, pas {zone!r}")
    check_login()
    value = {"@odata.type": CSA_TYPE, "eregionTarget": bench, "eregionZone": zone}
    rest("PATCH", f"/users/{user}", {"customSecurityAttributes": {ATTRIBUTE_SET: value}})
    got = rest("GET", f"/users/{user}?$select=id,customSecurityAttributes") or {}
    have = (got.get("customSecurityAttributes") or {}).get(ATTRIBUTE_SET) or {}
    if have.get("eregionTarget") != bench or have.get("eregionZone") != zone:
        raise Refused(f"l'attribut relu sur {user} n'est pas celui posé : {json.dumps(have)[:200]}")
    say(f"✓ {user} : {ATTRIBUTE_SET}.eregionTarget={bench}, {ATTRIBUTE_SET}.eregionZone={zone}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["prepare"] or args == ["prepare", "--yes"]:
            prepare("--yes" in args, (os.environ.get(UNIT_ENV) or "").strip())
            return 0
        if args == ["assign"]:
            assign((os.environ.get("EREGION_USER_OBJECT_ID") or "").strip(),
                   os.environ.get("EREGION_ATTR_TARGET") or "", os.environ.get("EREGION_ATTR_ZONE") or "")
            return 0
    except Refused as e:
        print(f"!! {e}", file=sys.stderr)
        return 1
    print("usage: entra_bench_unit.py prepare [--yes] | assign", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
