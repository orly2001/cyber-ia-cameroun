"""Intégration Bloc 1 -> Bloc 4/5 : injecter les vulnérabilités scannées.

Ce module fait le pont entre le scan (Bloc 1) et le moteur de corrélation /
les alertes persistées (Bloc 4) consommées par le dashboard (Bloc 5).

Conception : tous les imports lourds (scoring ML, corrélation, persistance) sont
PARESSEUX et toute défaillance est journalisée sans propager d'exception, afin
de ne casser aucun contrat existant ni la démo hors-ligne.
"""

from __future__ import annotations

from typing import List

from src.common.logging_conf import get_logger
from src.common.schemas import Alert, Vulnerability

logger = get_logger(__name__)


def inject_vulnerabilities(
    vulnerabilities: List[Vulnerability],
    *,
    persist: bool = True,
) -> List[Alert]:
    """Injecte des vulnérabilités dans le moteur de corrélation/alertes.

    Étapes :
        1. Scoring ML/heuristique des vulnérabilités (Bloc 3).
        2. Corrélation -> alertes (Bloc 4), même sans phishing associé.
        3. Persistance optionnelle des alertes (consommées par le dashboard).

    Args:
        vulnerabilities: vulnérabilités issues d'un scan (réel ou démo).
        persist: si ``True``, persiste les alertes générées en base.

    Returns:
        Liste des :class:`Alert` produites (vide si aucune règle ne se déclenche
        ou en cas d'indisponibilité d'un composant — jamais d'exception).
    """
    vulnerabilities = vulnerabilities or []
    if not vulnerabilities:
        return []

    # 1. Scoring (import paresseux ; repli silencieux si indisponible).
    vuln_scores = []
    try:
        from src.bloc3_ia.vuln_scorer import VulnScorer

        vuln_scores = VulnScorer().score(vulnerabilities)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Scoring des vulnérabilités indisponible (%s).", exc)

    # 2. Corrélation -> alertes.
    try:
        from src.bloc4_correlation.correlator import correlate

        alerts = correlate(
            vulnerabilities=vulnerabilities,
            vuln_scores=vuln_scores,
            phishing_samples=[],
            phishing_predictions=[],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Corrélation indisponible (%s) ; aucune alerte.", exc)
        return []

    # 3. Persistance optionnelle (tolérante à l'absence de BDD).
    if persist and alerts:
        try:
            from src.bloc4_correlation.persistence import persist_alerts

            n = persist_alerts(alerts)
            logger.info("%d alerte(s) issue(s) du scan persistée(s).", n)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Persistance des alertes de scan échouée (%s).", exc)

    return alerts


__all__ = ["inject_vulnerabilities"]
