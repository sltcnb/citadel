"""Enrichment orchestrator.

Runs each registered :class:`Source` over each IOC (respecting the source's
declared type support), caches verdicts with a TTL, and fuses them into a
cross-source confidence score.
"""

from __future__ import annotations

from collections.abc import Iterable

from .cache import TTLCache
from .models import IOC, EnrichedIOC, SourceVerdict
from .scoring import score_enriched
from .sources.base import Source, SourceError


class Enricher:
    def __init__(
        self,
        sources: Iterable[Source],
        cache: TTLCache | None = None,
    ) -> None:
        self.sources: list[Source] = list(sources)
        self.cache = cache if cache is not None else TTLCache()
        self.weights = {s.name: s.weight for s in self.sources}

    def enrich_one(self, ioc: IOC) -> EnrichedIOC:
        verdicts: list[SourceVerdict] = []
        for src in self.sources:
            if not src.supports(ioc):
                continue
            key = TTLCache.key(src.name, ioc)
            cached = self.cache.get(key)
            if cached is not None:
                verdicts.append(cached)
                continue
            try:
                verdict = src.enrich(ioc)
            except SourceError as exc:
                verdict = SourceVerdict(
                    source=src.name, malicious=0.0, confidence=0.0, error=str(exc)
                )
            self.cache.set(key, verdict)
            verdicts.append(verdict)

        enriched = EnrichedIOC(ioc=ioc, verdicts=verdicts)
        return score_enriched(enriched, self.weights)

    def enrich_all(self, iocs: Iterable[IOC]) -> list[EnrichedIOC]:
        return [self.enrich_one(ioc) for ioc in iocs]
