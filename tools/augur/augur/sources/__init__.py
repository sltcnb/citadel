"""Pluggable enrichment sources for Augur."""

from __future__ import annotations

from .abuseipdb import AbuseIPDBSource
from .base import Source, SourceError
from .greynoise import GreyNoiseSource
from .otx import OTXSource
from .shodan import ShodanSource
from .urlhaus import URLhausSource

BUILTIN_SOURCES: dict[str, type[Source]] = {
    URLhausSource.name: URLhausSource,
    AbuseIPDBSource.name: AbuseIPDBSource,
    OTXSource.name: OTXSource,
    ShodanSource.name: ShodanSource,
    GreyNoiseSource.name: GreyNoiseSource,
}

__all__ = [
    "Source",
    "SourceError",
    "URLhausSource",
    "AbuseIPDBSource",
    "OTXSource",
    "ShodanSource",
    "GreyNoiseSource",
    "BUILTIN_SOURCES",
]
