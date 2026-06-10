"""Source interface.

A ``Source`` enriches a single IOC and returns a :class:`SourceVerdict`.

All HTTP traffic goes through :meth:`Source._http_get` / ``_http_post``, which
require an injected ``session`` (a ``requests.Session``-like object). Tests
pass a mock session, so the suite runs fully OFFLINE — there is no implicit
network client.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import IOC, IOCType, SourceVerdict


class SourceError(Exception):
    """Raised when a source cannot produce a verdict for transport reasons."""


class Source(ABC):
    """Base class for an enrichment source.

    Subclasses set :attr:`name`, declare which :attr:`supported_types` they can
    answer for, and implement :meth:`enrich`. Network calls must go through the
    injected session; if no session is configured the source raises
    :class:`SourceError` rather than reaching the network on its own.
    """

    #: Stable source identifier (used in cache keys and STIX provenance).
    name: str = "base"
    #: IOC types this source can meaningfully enrich.
    supported_types: tuple[IOCType, ...] = ()
    #: Default per-source trust weight when fusing scores.
    weight: float = 1.0

    def __init__(
        self,
        api_key: str = "",
        session: Any | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.api_key = api_key
        self.session = session
        self.timeout = timeout

    # ── capability check ────────────────────────────────────────────────
    def supports(self, ioc: IOC) -> bool:
        return ioc.type in self.supported_types

    # ── enrichment ──────────────────────────────────────────────────────
    @abstractmethod
    def enrich(self, ioc: IOC) -> SourceVerdict:
        """Return this source's verdict for ``ioc``.

        Implementations should return a :class:`SourceVerdict` with ``error``
        set rather than raising for "not found" / "no data" cases.
        """
        raise NotImplementedError

    # ── transport (guarded; never auto-creates a network client) ─────────
    def _http_get(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("GET", url, **kwargs)

    def _http_post(self, url: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        if self.session is None:
            raise SourceError(
                f"{self.name}: no HTTP session configured (offline). "
                "Inject a session to make live requests."
            )
        kwargs.setdefault("timeout", self.timeout)
        resp = self.session.request(method, url, **kwargs)
        status = getattr(resp, "status_code", 200)
        if status >= 400:
            raise SourceError(f"{self.name}: HTTP {status} for {url}")
        return resp.json()
