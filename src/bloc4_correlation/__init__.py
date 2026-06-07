"""Bloc 4 — Moteur de corrélation & génération d'alertes.

Consomme les sorties des blocs 1 à 3 (vulnérabilités, scores, samples et
prédictions de phishing) et produit des :class:`~src.common.schemas.Alert`
persistables.

API publique :
    - :func:`correlate`     : applique les règles et produit les alertes.
    - :func:`persist_alerts`: upsert idempotent des alertes en base.
"""

from __future__ import annotations

from src.bloc4_correlation.correlator import correlate
from src.bloc4_correlation.persistence import persist_alerts

__all__ = ["correlate", "persist_alerts"]
