"""Augur — Citadel intel enrichment.

Turn raw indicators into scored, sourced, shareable intelligence:
enrich IOCs across pluggable sources, compute a cross-source confidence
score, and export a STIX 2.1 bundle of indicators.
"""

from __future__ import annotations

__version__ = "0.5.0"

from .models import IOC, EnrichedIOC, IOCType, SourceVerdict

__all__ = ["IOC", "IOCType", "SourceVerdict", "EnrichedIOC", "__version__"]
