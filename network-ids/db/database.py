"""
SQLAlchemy engine, declarative Base, and session factory.

All other modules import these symbols and never construct their own engine.
SQLite is opened with check_same_thread=False because the sniffer thread and
the Flask request threads write concurrently; SQLAlchemy serializes the writes
via its connection pool.
"""

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine  # pyright: ignore[reportMissingImports]
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker  # pyright: ignore[reportMissingImports]

import config


_db_path = Path(config.DB_PATH)
_db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{_db_path}",
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


@contextmanager
def session_scope() -> Iterator[Session]:
    """Yield a session, commit on success, roll back on error, always close."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()