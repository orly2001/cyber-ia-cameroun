"""Persistance des alertes (Bloc 4 -> base partagée).

Upsert idempotent des :class:`Alert` dans ``AlertORM`` via ``SessionLocal``.
La base peut être indisponible (sandbox, BDD non démarrée) : dans ce cas la
fonction journalise l'erreur et renvoie 0 sans propager d'exception.
"""

from __future__ import annotations

from typing import List

from src.common.logging_conf import get_logger
from src.common.schemas import Alert

logger = get_logger(__name__)


def _to_orm_kwargs(alert: Alert) -> dict:
    """Mappe une ``Alert`` Pydantic vers les colonnes d'``AlertORM``."""
    return {
        "id": alert.id,
        "title": alert.title,
        "risk_score": alert.risk_score,
        "severity": alert.severity.value,
        "rule_id": alert.rule_id,
        "vulnerability_ids": list(alert.vulnerability_ids),
        "phishing_sample_ids": list(alert.phishing_sample_ids),
        "rationale": alert.rationale,
        "recommended_actions": list(alert.recommended_actions),
        "status": alert.status.value,
        "created_at": alert.created_at,
    }


def persist_alerts(alerts: List[Alert]) -> int:
    """Persiste (upsert) les alertes en base.

    Args:
        alerts: alertes produites par :func:`correlate`.

    Returns:
        Nombre d'alertes effectivement persistées (0 si BDD indisponible ou
        liste vide).
    """
    if not alerts:
        return 0

    # Imports différés : permet d'importer le package sans connexion BDD.
    try:
        from src.common.database import AlertORM, SessionLocal, init_db
    except Exception as exc:  # pragma: no cover - environnement sans BDD
        logger.error("Couche base de données indisponible : %s", exc)
        return 0

    try:
        init_db()
    except Exception as exc:
        logger.error("Échec d'initialisation de la base : %s", exc)
        return 0

    count = 0
    session = SessionLocal()
    try:
        for alert in alerts:
            kwargs = _to_orm_kwargs(alert)
            existing = session.get(AlertORM, alert.id)
            if existing is None:
                session.add(AlertORM(**kwargs))
            else:
                # Upsert : on met à jour les champs susceptibles d'évoluer,
                # sans réécraser created_at d'origine.
                for field_name, value in kwargs.items():
                    if field_name == "created_at":
                        continue
                    setattr(existing, field_name, value)
            count += 1
        session.commit()
        logger.info("%d alerte(s) persistée(s).", count)
        return count
    except Exception as exc:
        session.rollback()
        logger.error("Échec de persistance des alertes : %s", exc)
        return 0
    finally:
        session.close()


__all__ = ["persist_alerts"]
