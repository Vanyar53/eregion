"""Values that enter a KQL query (SEC4c, #275).

A query built with a value read from a log line or a VM's state — a host name, an address —
holds that value inside a string literal, and nowhere else. Each value is checked for what
it is first (`ip`, `name`, `resource_id`): a value that is not one is refused, and the query
is not run (the caller says so). Then `literal` writes it as a KQL string literal whose
every character that could end or bend it is escaped — the literal ends where it should,
whatever the value.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata


class UnsafeValue(ValueError):
    """A value that is not what its query expects: the query is not run."""


# A host name or an Azure resource name: letters, digits, '.', '_', '-' — what a VM, its
# OS host name (Computer) and a resource group are named with (parentheses aside, below).
# Never a quote, a space, a backslash or a pipe.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
# A resource group may also hold parentheses (Azure's naming rules); at most 90 characters.
_GROUP = re.compile(r"[A-Za-z0-9_().-]{1,90}")
_PROVIDER = re.compile(r"[A-Za-z][A-Za-z0-9.]{0,63}")
_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")

_BACKSLASH, _QUOTE = "\\", '"'
# Inside a double-quoted KQL literal, a backslash starts an escape and a quote ends it.
_ESCAPES = {_BACKSLASH: _BACKSLASH * 2, _QUOTE: _BACKSLASH + _QUOTE}


def literal(value: str) -> str:
    """`value` as a KQL double-quoted string literal: a backslash and a quote escaped, a
    control or format character (a line break, a NUL, a direction mark) refused — the
    literal holds the value, and ends where it should."""
    if not isinstance(value, str):
        raise UnsafeValue(f"pas une chaîne ({type(value).__name__})")
    for ch in value:
        if unicodedata.category(ch)[0] in ("C", "Z") and ch != " ":
            raise UnsafeValue(f"caractère de contrôle U+{ord(ch):04X}")
    return '"' + "".join(_ESCAPES.get(ch, ch) for ch in value) + '"'


def ip(value) -> str:
    """An IPv4 or IPv6 address, as written (`ipaddress` reads it), never a zone (`%eth0`:
    anything may follow the '%')."""
    text = value if isinstance(value, str) else ""
    if not text or "%" in text:
        raise UnsafeValue(f"pas une adresse IP ({str(value)[:60]!r})")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise UnsafeValue(f"pas une adresse IP ({text[:60]!r})") from None
    return text


def name(value) -> str:
    """A VM's name or a host name (Computer), as Azure and a host name allow it."""
    text = value if isinstance(value, str) else ""
    if not _NAME.fullmatch(text):
        raise UnsafeValue(f"pas un nom de VM ou d'hôte ({str(value)[:60]!r})")
    return text


def resource_id(value) -> str:
    """An Azure resource id: /subscriptions/<id>/resourceGroups/<group>/providers/
    <namespace>/<type>/<name> (a child type and name may follow)."""
    text = value if isinstance(value, str) else ""
    parts = text.rstrip("/").split("/")
    ok = (len(parts) >= 9 and len(parts) % 2 == 1 and parts[0] == ""
          and parts[1].lower() == "subscriptions" and _NAME.fullmatch(parts[2])
          and parts[3].lower() == "resourcegroups" and _GROUP.fullmatch(parts[4])
          and not parts[4].endswith(".")
          and parts[5].lower() == "providers" and _PROVIDER.fullmatch(parts[6])
          and all(_TYPE.fullmatch(t) for t in parts[7::2])
          and all(_NAME.fullmatch(n) for n in parts[8::2]))
    if not ok:
        raise UnsafeValue(f"pas un identifiant de ressource Azure ({str(value)[:80]!r})")
    return text
