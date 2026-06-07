"""Corrélateur principal (Bloc 4) : règles -> alertes.

Applique les règles déclaratives de :mod:`rules`, calcule un score de risque
composite via :mod:`risk_engine`, dérive une :class:`Severity`, rédige une
explication (``rationale``) en français et propose des actions concrètes.

Chaque règle déclenchée produit une :class:`Alert` dont l'``id`` est stable
(dérivé de la règle et des entités impliquées) pour permettre un upsert
idempotent en base.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List

from src.common.logging_conf import get_logger
from src.common.schemas import (
    Alert,
    AlertStatus,
    PhishingPrediction,
    PhishingSample,
    Severity,
    VulnScore,
    Vulnerability,
)

from src.bloc4_correlation.risk_engine import compute_risk
from src.bloc4_correlation.rules import (
    RULES,
    MatchContext,
    RuleMatch,
)

logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Sévérité dérivée du score de risque [0..100]
# --------------------------------------------------------------------------- #
def _severity_from_risk(risk: float) -> Severity:
    """Convertit un risk_score [0..100] en sévérité qualitative."""
    if risk >= 80.0:
        return Severity.CRITICAL
    if risk >= 60.0:
        return Severity.HIGH
    if risk >= 35.0:
        return Severity.MEDIUM
    if risk > 0.0:
        return Severity.LOW
    return Severity.INFO


# --------------------------------------------------------------------------- #
# Identifiant d'alerte stable
# --------------------------------------------------------------------------- #
def _stable_alert_id(match: RuleMatch) -> str:
    """Génère un id déterministe à partir de la règle et des entités visées."""
    payload = "|".join(
        [
            match.rule_id,
            ",".join(sorted(match.vulnerability_ids)),
            ",".join(sorted(match.phishing_sample_ids)),
        ]
    )
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
    return f"alert-{match.rule_id.lower()}-{digest}"


# --------------------------------------------------------------------------- #
# Actions recommandées par règle
# --------------------------------------------------------------------------- #
def _recommended_actions(
    match: RuleMatch,
    vulns_by_id: Dict[str, Vulnerability],
    samples_by_id: Dict[str, PhishingSample],
) -> List[str]:
    """Construit des actions concrètes adaptées à la règle déclenchée."""
    actions: List[str] = []

    # Actions liées aux vulnérabilités impliquées.
    for vid in match.vulnerability_ids:
        v = vulns_by_id.get(vid)
        if v is None:
            continue
        if v.cve_id:
            actions.append(f"Appliquer le correctif pour {v.cve_id} sur {v.host}")
        else:
            actions.append(f"Corriger '{v.name}' sur {v.host}")
        if v.port in {21, 22, 23, 3306, 3389, 445, 1433, 5432, 6379, 27017}:
            actions.append(
                f"Restreindre l'accès au port {v.port} ({v.service or 'service'}) "
                f"de {v.host} via pare-feu/VPN"
            )

    # Actions spécifiques à la nature de la règle.
    if match.rule_id == "R2":
        actions.append("Sensibiliser les clients Mobile Money au phishing par SMS")
        actions.append("Signaler les numéros émetteurs aux opérateurs (MTN/Orange)")
    if match.rule_id in {"R1", "R3"}:
        domains = _extract_domains(match.phishing_sample_ids, samples_by_id)
        for dom in domains:
            actions.append(f"Bloquer le domaine {dom}")
        actions.append("Activer le MFA et surveiller les connexions suspectes")

    if not actions:
        actions.append("Investiguer l'alerte et qualifier le risque")

    # Déduplication en conservant l'ordre.
    seen: set[str] = set()
    unique: List[str] = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return unique


def _extract_domains(
    sample_ids: List[str],
    samples_by_id: Dict[str, PhishingSample],
) -> List[str]:
    """Extrait quelques domaines plausibles des textes de phishing."""
    import re

    pattern = re.compile(r"https?://([^/\s]+)|\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b", re.I)
    domains: List[str] = []
    seen: set[str] = set()
    for sid in sample_ids:
        s = samples_by_id.get(sid)
        if s is None:
            continue
        text = s.clean_text or s.raw_text or ""
        for m in pattern.finditer(text):
            dom = (m.group(1) or m.group(2) or "").lower()
            if dom and dom not in seen:
                seen.add(dom)
                domains.append(dom)
    return domains[:5]


# --------------------------------------------------------------------------- #
# Corrélateur principal
# --------------------------------------------------------------------------- #
def correlate(
    vulnerabilities: List[Vulnerability],
    vuln_scores: List[VulnScore],
    phishing_samples: List[PhishingSample],
    phishing_predictions: List[PhishingPrediction],
) -> List[Alert]:
    """Applique les règles de corrélation et produit la liste des alertes.

    Args:
        vulnerabilities: vulnérabilités issues du bloc 1.
        vuln_scores: priorités ML issues du bloc 3.
        phishing_samples: échantillons de phishing issus du bloc 2.
        phishing_predictions: prédictions de phishing issues du bloc 3.

    Returns:
        Liste d'``Alert`` (vide si aucune règle ne se déclenche). Robuste aux
        listes vides.
    """
    vulnerabilities = vulnerabilities or []
    vuln_scores = vuln_scores or []
    phishing_samples = phishing_samples or []
    phishing_predictions = phishing_predictions or []

    vulns_by_id: Dict[str, Vulnerability] = {v.id: v for v in vulnerabilities}
    scores_by_id: Dict[str, VulnScore] = {s.vulnerability_id: s for s in vuln_scores}
    samples_by_id: Dict[str, PhishingSample] = {s.id: s for s in phishing_samples}

    ctx = MatchContext(
        vulnerabilities=vulnerabilities,
        vuln_scores=scores_by_id,
        phishing_samples=samples_by_id,
        phishing_predictions=phishing_predictions,
    )

    alerts: List[Alert] = []
    for rule in RULES:
        try:
            match = rule.match(ctx)
        except Exception as exc:  # une règle défaillante ne casse pas le moteur
            logger.warning("Règle %s en échec : %s", rule.id, exc)
            continue
        if match is None:
            continue

        # Sous-ensembles d'entités impliquées par la règle.
        sub_vulns = [vulns_by_id[i] for i in match.vulnerability_ids if i in vulns_by_id]
        sub_preds = [
            p for p in phishing_predictions if p.sample_id in set(match.phishing_sample_ids)
        ]
        sub_samples = [
            samples_by_id[i] for i in match.phishing_sample_ids if i in samples_by_id
        ]

        raw_risk = compute_risk(scores_by_id, sub_preds, sub_vulns, sub_samples)
        # Le poids de la règle module le risque final.
        risk = round(min(100.0, raw_risk * rule.weight), 2)
        severity = _severity_from_risk(risk)

        rationale = (
            f"[{rule.id} — {rule.name}] {match.explanation} "
            f"Score de risque composite : {risk}/100 ({severity.value})."
        )
        actions = _recommended_actions(match, vulns_by_id, samples_by_id)

        alert = Alert(
            id=_stable_alert_id(match),
            title=f"{rule.name}",
            risk_score=risk,
            severity=severity,
            rule_id=rule.id,
            vulnerability_ids=match.vulnerability_ids,
            phishing_sample_ids=match.phishing_sample_ids,
            rationale=rationale,
            recommended_actions=actions,
            status=AlertStatus.NEW,
        )
        alerts.append(alert)
        logger.info("Alerte générée : %s (%s, risk=%.2f)", alert.id, severity.value, risk)

    # Tri décroissant par risque pour faciliter la consommation côté dashboard.
    alerts.sort(key=lambda a: a.risk_score, reverse=True)
    return alerts


__all__ = ["correlate"]
