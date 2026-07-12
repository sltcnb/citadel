"""Relational database access (SQLAlchemy) for the Citadel API.

The platform is predominantly Redis-backed. This module provides a small,
lazily-initialised SQLAlchemy layer for the handful of records that need to live
in a **second, independent trust domain** from Redis — most notably the evidence
seal chain-of-custody anchor (see ``services/evidence_seal.py`` /
``models/evidence_seal_anchor.py``).

Design notes
------------
* The engine + sessionmaker are created lazily on first use so that merely
  importing a service module never requires a live database. Tests may inject
  their own sqlite-backed sessionmaker via :func:`set_sessionmaker`.
* ``DATABASE_URL`` selects the backend (default: a local sqlite file). The schema
  is created with :func:`init_db` (``create_all``); an Alembic migration is also
  provided for deployments that manage schema out-of-band.
* :func:`session_scope` is a transactional context manager: it commits on clean
  exit and rolls back on error.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Default to a local sqlite file so first run works with zero configuration.
_DEFAULT_URL = "sqlite:///./citadel.db"


class Base(DeclarativeBase):
    """Declarative base shared by every SQLAlchemy model under ``models/``."""


_engine = None
_Session: sessionmaker | None = None


def _database_url() -> str:
    return os.getenv("DATABASE_URL", _DEFAULT_URL)


def get_engine():
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        url = _database_url()
        # check_same_thread is a sqlite-only knob; harmless to pass only for sqlite.
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, future=True, connect_args=connect_args)
    return _engine


def get_sessionmaker() -> sessionmaker:
    """Return the process-wide sessionmaker, creating it on first use."""
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _Session


def set_sessionmaker(maker: sessionmaker | None) -> None:
    """Override (or reset, with ``None``) the sessionmaker — primarily for tests."""
    global _Session
    _Session = maker


def init_db() -> None:
    """Create all model tables if they do not yet exist (``create_all``).

    Importing the models package registers every model on :data:`Base.metadata`,
    so this creates the full schema. Safe to call repeatedly.
    """
    import models  # noqa: F401  (registers models on Base.metadata)

    Base.metadata.create_all(bind=get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session context: commit on success, rollback on error."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
