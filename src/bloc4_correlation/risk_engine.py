"""Moteur de score de risque composite (Bloc 4).

Combine deux dimensions pour produire un score borné [0, 100] :

    1. **Gravité des vulnérabilités** — moyenne, sur les vulnérabilités
       impliquées, d'un score unitaire mêlant la sévérité CVSS (normalisée 0..1)
       et la priorité ML du :class:`VulnScore` (``ml_score`` 0..1) :

           vuln_unit = 0.6 * (cvss / 10) + 0.4 * ml_score

    2. **Pression de phishing** — combinaison de la *proportion* de samples
       prédits phishing et du *score moyen* de ces prédictions :

           phish_pressure = 0.5 * (n_phishing / n_total) + 0.5 * mean(score_phishing)

Le score final pondère ces deux dimensions :

           base = 100 * (0.6 * vuln_severity + 0.4 * phish_pressure)

borné dans [0, 100]. Les listes vides sont gérées (contribution nulle) sans
jamais lever d'exception ni produire de division par zéro.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from src.common.logging_conf import get_logger
from src.common.schemas import (
    PhishingPrediction,
    PhishingSample,
    VulnScore,
    Vulnerability,
)

logger = get_logger(__name__)

# Pondérations globales entre dimensions (somme = 1.0).
_W_VULN = 0.6
_W_PHISH = 0.4

# Pondérations internes à la gravité vulnérabilité (somme = 1.0).
_W_CVSS = 0.6
_W_ML = 0.4


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Borne ``value`` dans [low, high]."""
    return max(low, min(high, value))


def _vuln_severity(
    vulns: Sequence[Vulnerability],
    vuln_scores: Dict[str, VulnScore],
) -> float:
    """Gravité moyenne normalisée [0..1] des vulnérabilités fournies."""
    if not vulns:
        return 0.0
    total = 0.0
    for v in vulns:
        cvss_norm = (v.cvss_score or 0.0) / 10.0
        score = vuln_scores.get(v.id)
        ml = score.ml_score if score is not None else 0.0
        total += _W_CVSS * cvss_norm + _W_ML * ml
    return total / len(vulns)


def _phishing_pressure(
    samples: Sequence[PhishingSample],
    predictions: Sequence[PhishingPrediction],
) -> float:
    """Pression de phishing normalisée [0..1]."""
    if not predictions:
        return 0.0
    phishing = [p for p in predictions if p.is_phishing]
    if not phishing:
        return 0.0
    proportion = len(phishing) / len(predictions)
    mean_score = sum(p.score for p in phishing) / len(phishing)
    return 0.5 * proportion + 0.5 * mean_score


def compute_risk(
    vuln_scores: Dict[str, VulnScore],
    phishing_preds: List[PhishingPrediction],
    vulns: List[Vulnerability],
    samples: List[PhishingSample],
) -> float:
    """Calcule le score de risque composite borné [0, 100].

    Args:
        vuln_scores: mapping ``vulnerability_id -> VulnScore`` (priorités ML).
        phishing_preds: prédictions de phishing à prendre en compte.
        vulns: vulnérabilités à prendre en compte.
        samples: échantillons de phishing associés aux prédictions.

    Returns:
        Score composite dans l'intervalle [0.0, 100.0].
    """
    vuln_sev = _vuln_severity(vulns, vuln_scores)
    phish = _phishing_pressure(samples, phishing_preds)
    base = 100.0 * (_W_VULN * vuln_sev + _W_PHISH * phish)
    risk = round(_clamp(base), 2)
    logger.debug(
        "compute_risk: vuln_sev=%.3f phish=%.3f -> risk=%.2f",
        vuln_sev,
        phish,
        risk,
    )
    return risk


__all__ = ["compute_risk"]
