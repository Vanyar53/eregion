"""The exercise container in memory (#167): what Azure Blob Storage answers to the calls of
eregion_core/exercise_channel.py — put a blob, list the container (prefix, pages with a
``NextMarker``), get a blob — without the network. Each write moves the container's clock
by one second: a blob's ``Last-Modified`` is that clock, years before the tests' files, so a
local copy reads as up to date until a test makes it older (``os.utime``)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace
from xml.sax.saxutils import escape

URL = "https://exampleaccount.blob.core.windows.net/exercises"
CRED = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="tok"))


def _answer(status: int, content: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(ok=200 <= status < 300, status_code=status, content=content)


class FakeContainer:
    def __init__(self, url: str = URL, page_size: int = 1000):
        self.url = url
        self.page_size = page_size
        self.blobs: dict[str, tuple[bytes, datetime]] = {}
        self.clock = datetime(2020, 1, 1, tzinfo=timezone.utc)
        self.puts: list[str] = []          # blob names written, in order
        self.gets: list[str] = []          # blob names downloaded, in order
        self.listings: list[dict] = []     # the parameters of each listing call
        self.tokens: list[str] = []        # the bearer tokens the calls carried
        self.refused: set[str] = set()     # names a put or a get is refused on (403)

    def _name(self, url: str) -> str:
        assert url.startswith(self.url + "/"), f"outside the container: {url}"
        return url[len(self.url) + 1:]

    def put(self, url, headers=None, data=b"", timeout=None):
        self.tokens.append((headers or {}).get("Authorization", ""))
        name = self._name(url)
        if name in self.refused:
            return _answer(403)
        self.clock += timedelta(seconds=1)
        self.blobs[name] = (bytes(data), self.clock)
        self.puts.append(name)
        return _answer(201)

    def get(self, url, headers=None, params=None, timeout=None):
        self.tokens.append((headers or {}).get("Authorization", ""))
        if params and params.get("comp") == "list":
            assert url == self.url and params.get("restype") == "container"
            self.listings.append(dict(params))
            return _answer(200, self._listing(params.get("prefix", ""), params.get("marker", "")))
        name = self._name(url)
        self.gets.append(name)
        if name in self.refused:
            return _answer(403)
        if name not in self.blobs:
            return _answer(404)
        return _answer(200, self.blobs[name][0])

    def _listing(self, prefix: str, marker: str) -> bytes:
        names = sorted(n for n in self.blobs if n.startswith(prefix))
        start = names.index(marker) if marker else 0  # the marker: the next page's first name
        page, rest = names[start:start + self.page_size], names[start + self.page_size:]
        items = "".join(
            f"<Blob><Name>{escape(n)}</Name><Properties><Last-Modified>"
            f"{format_datetime(self.blobs[n][1], usegmt=True)}</Last-Modified></Properties></Blob>"
            for n in page)
        nxt = f"<NextMarker>{escape(rest[0])}</NextMarker>" if rest else "<NextMarker />"
        return (f'<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="exercises">'
                f"<Prefix>{escape(prefix)}</Prefix><Blobs>{items}</Blobs>{nxt}</EnumerationResults>"
                ).encode()

    def body(self, name: str) -> bytes:
        return self.blobs[name][0]
