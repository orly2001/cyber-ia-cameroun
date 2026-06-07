"""Sécurité de l'API du bloc 5 — authentification par clé d'API.

Fournit la dépendance FastAPI :func:`require_api_key`, à appliquer aux endpoints
qui MODIFIENT l'état du système (``PATCH /api/alerts/{id}``, ``POST /api/run-demo``).
Les endpoints de lecture restent publics.

Règle de compatibilité (mode dev permissif) :

* si ``settings.api_key`` est VIDE (non configurée), l'authentification est
  DÉSACTIVÉE — la requête passe et un avertissement est journalisé. Cela évite
  de casser la démo et les tests qui ne configurent pas de clé ;
* si ``settings.api_key`` est DÉFINIE, l'en-tête ``X-API-Key`` doit correspondre
  exactement (comparaison en temps constant via :func:`secrets.compare_digest`),
  sinon une erreur HTTP 401 est levée.
"""

from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Header, HTTPException, status

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

#: Nom de l'en-tête HTTP transportant la clé d'API.
API_KEY_HEADER = "X-API-Key"


def require_api_key(
    x_api_key: Optional[str] = Header(
        default=None,
        alias=API_KEY_HEADER,
        description="Clé d'API requise sur les endpoints sensibles.",
    ),
) -> None:
    """Vérifie la clé d'API présentée pour un endpoint sensible.

    Args:
        x_api_key: valeur de l'en-tête ``X-API-Key`` (injectée par FastAPI).

    Raises:
        HTTPException: 401 si une clé est configurée et que la clé fournie est
            absente ou incorrecte.
    """
    expected = settings.api_key

    # Mode dev permissif : aucune clé configurée => authentification désactivée.
    if not expected:
        logger.warning(
            "API_KEY non configurée : authentification DÉSACTIVÉE pour les "
            "endpoints sensibles (mode dev permissif). Définissez API_KEY en "
            "production."
        )
        return

    # Clé configurée : exiger une correspondance exacte (temps constant).
    if x_api_key is None or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Clé d'API invalide ou manquante.",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )


def enforce_production_security() -> None:
    """Refuse le demarrage en production sans cle d'API (audit cyber M1).

    En environnement ``production``, une ``API_KEY`` vide signifierait que les
    endpoints sensibles (upload, run-demo, patch) sont ouverts a tous : on
    bloque donc explicitement le demarrage. En dev, on se contente d'un
    avertissement (mode permissif conserve pour la demo et les tests).

    Raises:
        RuntimeError: si environment == "production" et api_key est vide.
    """
    if settings.environment.lower() == "production" and not settings.api_key:
        raise RuntimeError(
            "Demarrage refuse : API_KEY est vide en environnement 'production'. "
            "Definissez une cle forte (env API_KEY) pour proteger les endpoints "
            "sensibles, ou repassez ENVIRONMENT=development."
        )


__all__ = ["require_api_key", "API_KEY_HEADER", "enforce_production_security"]
