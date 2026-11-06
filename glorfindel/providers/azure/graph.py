"""Microsoft Graph, read only (IR1a, docs/design/reponse-identite.md §3.4) — the one place Eregion
reads Entra ID's objects: the parameters of an identity card's plan (the object's id, a keyId, a
grant's or an assignment's id) and its check after a human's gesture.

Read only by construction: this module has a GET and nothing else — no POST, PATCH, PUT or DELETE
is written here, and tests/unit/test_identity_plan.py keeps it so. The watch's identity reads
Graph with `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`RoleManagement.Read.Directory` and `User.Read.All` (docs/operations.md, « Identités Azure »; the
exact rights are hypothesis 10, to measure). Without them — H0 today —, every read is
`Unreadable`, and says why: the plan keeps what the log gives, each parameter not read marked
so, and a check is never « held ».

What a read answers:
  - the object, a dict;
  - None: Graph says it does not exist (404) — an absence is an answer (a grant removed);
  - `Unreadable`: a right missing (401, 403), an error (429, 5xx, an answer that is no JSON,
    a token that cannot be had), a delay (no connection, no answer in time), or a list
    longer than `MAX_PAGES` (an absence in it could not be told).
    When Graph answered, it says its status and its error code (`error.code`, filtered by
    `eregion_core.inscription.graph_error_code`: letters and `_` only, never copied raw), and the page of
    a list that answered so — a caller may read one exact answer of the first page as « none »
    (IDI1p: a tenant without PIM, `no_pim_license`), never another.

Only Graph's own host is ever called: a path is a path (`/applications/<id>`), a next page is
followed only on that host, and a redirection never (`allow_redirects=False`: a 3xx is an error).
The time: 5 s to connect and 15 s for each wait on the socket (not for the whole answer); the
token's own fetch has no bound here; a plan's reads have one budget in all (`deadline`).
"""
from __future__ import annotations

from eregion_core.inscription import graph_error_code

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"
# Connection in 5 s, an answer in 15 s: a button the operator waits on, and a card being written.
# The 15 s bound each wait on the socket (requests' read timeout), not the whole answer; getting
# the token (azure.identity) has no bound of its own. A caller's `deadline` bounds its reads in all.
TIMEOUT_S = (5, 15)
MAX_PAGES = 5


class Unreadable(Exception):
    """Graph could not be read. `kind`: `right` (401, 403), `error`, `delay`, `off` (no reader:
    a dry run, the tests). Never read as « held ». When Graph answered: its `status`, its error
    `code` (filtered: `graph_error_code`), and the `page` of a list it answered so (0 the first)."""

    def __init__(self, why: str, kind: str = "error", *, status: int = 0, code: str = "", page: int = 0):
        super().__init__(why)
        self.kind = kind
        self.status, self.code, self.page = status, code, page


class NoGraph:
    """A reader that reads nothing, and says why: a dry run, the tests."""

    def __init__(self, why: str):
        self.why = why

    def get(self, path: str, params: dict | None = None, deadline: float | None = None):
        raise Unreadable(self.why, "off")

    def list(self, path: str, params: dict | None = None, deadline: float | None = None):
        raise Unreadable(self.why, "off")


class GraphReader:
    """GET on Microsoft Graph, with the process's identity (DefaultAzureCredential: the managed
    identity on H0, a service principal or `az login` elsewhere)."""

    def __init__(self, credential=None, session=None, timeout=TIMEOUT_S):
        self._credential = credential
        self._session = session
        self._timeout = timeout

    def _token(self) -> str:
        try:
            if self._credential is None:
                from azure.identity import DefaultAzureCredential
                self._credential = DefaultAzureCredential()
            return self._credential.get_token(SCOPE).token
        except Exception as exc:
            raise Unreadable(f"jeton de Graph indisponible ({type(exc).__name__})", "right") from None

    def _get(self, url: str, params: dict | None, deadline: float | None = None, page: int = 0):
        if not url.startswith(GRAPH + "/"):
            raise Unreadable("adresse hors de Graph refusée", "error")
        import time

        import requests
        session = self._session or requests
        timeout = self._timeout
        if deadline is not None:        # the caller's budget in all (a plan: entra_items.PLAN_BUDGET_S)
            left = deadline - time.monotonic()
            if left <= 0:
                raise Unreadable("budget de lecture de Graph dépassé", "delay")
            timeout = (min(timeout[0], left), min(timeout[1], left))
        try:
            r = session.get(url, headers={"Authorization": f"Bearer {self._token()}"},
                            params=params, timeout=timeout, allow_redirects=False)
        except requests.Timeout:
            raise Unreadable(f"Graph n'a pas répondu à temps ({self._timeout[1]} s)", "delay") from None
        except requests.ConnectionError:
            raise Unreadable(f"Graph injoignable en {self._timeout[0]} s", "delay") from None
        except requests.RequestException as exc:
            raise Unreadable(f"Graph : {type(exc).__name__}", "error") from None
        status = getattr(r, "status_code", 0)
        if status == 404:
            return None
        code = graph_error_code(r) if status != 200 else ""
        said = f"{status}{' ' + code if code else ''}"
        if status in (401, 403):
            raise Unreadable(f"droit absent sur Graph ({said})", "right", status=status, code=code, page=page)
        if 300 <= status < 400:         # never followed: Graph's answer is on Graph's host, or none
            raise Unreadable(f"Graph a répondu une redirection ({said}) : non suivie", "error",
                             status=status, code=code, page=page)
        if status != 200:
            raise Unreadable(f"Graph a répondu {said}", "error", status=status, code=code, page=page)
        try:
            body = r.json()
        except Exception:
            raise Unreadable("réponse de Graph illisible (pas du JSON)", "error") from None
        if not isinstance(body, dict):
            raise Unreadable("réponse de Graph illisible (pas un objet)", "error")
        return body

    def get(self, path: str, params: dict | None = None, deadline: float | None = None):
        """The object at `path`, None if Graph says it does not exist, else `Unreadable`.
        `deadline` (time.monotonic): no read past it, each socket wait bounded by what is left."""
        if not path.startswith("/") or "://" in path:
            raise Unreadable("chemin de Graph refusé", "error")
        return self._get(GRAPH + path, params, deadline)

    def list(self, path: str, params: dict | None = None, deadline: float | None = None) -> list[dict] | None:
        """Every item of a collection (its pages followed, at most `MAX_PAGES`), None if the
        collection's owner does not exist."""
        body = self.get(path, params, deadline)
        if body is None:
            return None
        items = list(body.get("value") or [])
        for page in range(1, MAX_PAGES):
            nxt = body.get("@odata.nextLink")
            if not nxt:
                return [i for i in items if isinstance(i, dict)]
            body = self._get(str(nxt), None, deadline, page)
            if body is None:
                return None
            items += list(body.get("value") or [])
        if body.get("@odata.nextLink"):
            raise Unreadable(f"liste de Graph au-delà de {MAX_PAGES} pages : une absence n'y serait pas sûre",
                             "error")
        return [i for i in items if isinstance(i, dict)]


def default_reader():
    """The watch's reader (tests/unit/conftest.py replaces it: no test ever reads Graph)."""
    return GraphReader()
