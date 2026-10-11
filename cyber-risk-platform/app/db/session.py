"""
CyberRisk-Guidewire-Connector (CRGC)
Database Session & Engine Management
"""

from collections.abc import Generator
from typing import Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from config.settings import get_settings


def create_db_engine(db_url: str | None = None, echo: bool | None = None):
    settings = get_settings()
    url = db_url or settings.database_url
    should_echo = echo if echo is not None else settings.db_echo

    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(
        url,
        echo=should_echo,
        connect_args=connect_args,
    )


engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a thread-safe database session.
    Guarantees session cleanup on request completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
