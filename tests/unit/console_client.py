"""The console as the tests reach it (SEC1): there is no console without a token, nor under a
host name it does not know. The conftest sets ``TOKEN`` as the console's token in every test;
``console()`` opens the app under a loopback name, with that token as a script sends it
(``Authorization: Bearer``). A browser's requests (cookie, Origin) are built by the tests of
the boundary themselves (test_console.py).

FastAPI is imported only when a client is asked for: the conftest imports this module in the
components' runs too, where the console's extra is not installed.
"""
from __future__ import annotations

TOKEN = "test-console-token"
ORIGIN = "http://localhost:7007"
# The live feed under the same name: the TestClient names a WebSocket's host "testserver" otherwise.
WS = "ws://localhost:7007/api/feed"


def console(token: str | None = TOKEN, **kwargs):
    """A TestClient of the console: under ORIGIN, with ``token`` as its bearer (None: none)."""
    from fastapi.testclient import TestClient

    import eregion_console.api as api
    headers = dict(kwargs.pop("headers", {}) or {})
    if token is not None:
        headers.setdefault("Authorization", f"Bearer {token}")
    return TestClient(api.app, base_url=kwargs.pop("base_url", ORIGIN), headers=headers, **kwargs)
