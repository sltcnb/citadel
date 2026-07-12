"""SQLAlchemy models for the Citadel API.

Importing this package registers every model on ``db.Base.metadata`` so that
``db.init_db()`` (``create_all``) and Alembic autogenerate see the full schema.
Add new models here as they are introduced.
"""

from __future__ import annotations

from models.evidence_seal_anchor import EvidenceSealAnchor

__all__ = ["EvidenceSealAnchor"]
