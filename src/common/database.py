"""Accès base de données partagé (SQLAlchemy 2.x).

Modèle ORM minimal pour persister les alertes produites par le bloc 4 et
consommées par le bloc 5. PostgreSQL en production, repli SQLite en dev.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    String,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from src.common.config import settings


class Base(DeclarativeBase):
    pass


class AlertORM(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String, default="INFO")
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    vulnerability_ids: Mapped[list] = mapped_column(JSON, default=list)
    phishing_sample_ids: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(String, default="")
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="NEW")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


_db_url = settings.effective_database_url
# SQLite : autoriser l'usage multi-thread (FastAPI) et lisser la concurrence.
_connect_args = {"check_same_thread": False} if _db_url.startswith("sqlite") else {}
engine = create_engine(_db_url, future=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Crée les tables si elles n'existent pas."""
    Base.metadata.create_all(engine)


def get_session():
    """Générateur de session (utilisable comme dépendance FastAPI)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
