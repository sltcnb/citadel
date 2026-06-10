"""Rosetta — Citadel canonicalizer.

Reads ForensicEvent JSONL (see contracts/forensic_event.schema.json) and emits
ECS v8 documents (see contracts/ecs_extension.md). The artifact_type -> ECS
event.category/type mapping is config-driven (see fieldmaps/default.yaml).
"""

__version__ = "0.1.0"

from .normalize import Normalizer, load_fieldmap, normalize_event  # noqa: F401

__all__ = ["Normalizer", "load_fieldmap", "normalize_event", "__version__"]
