"""DB-backed evidence seal chain-of-custody anchor.

This table is the **authoritative, out-of-band anchor** for each per-case evidence
seal chain. The chain itself (and a mirror anchor) live in Redis; persisting a
second copy of ``{head_hash, length}`` in the relational DB puts the anchor in an
*independent trust domain*. An attacker who can rewrite the Redis chain list can
no longer silently rewrite the anchor too, because the DB anchor is compared
during full verification (see ``services/evidence_seal.py``).

One row per case: ``case_id`` is the primary key.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


def _now() -> datetime:
    return datetime.now(UTC)


class EvidenceSealAnchor(Base):
    """Authoritative per-case anchor: the chain head hash and its length."""

    __tablename__ = "evidence_seal_anchor"

    case_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"EvidenceSealAnchor(case_id={self.case_id!r}, "
            f"head_hash={self.head_hash!r}, length={self.length})"
        )
