"""Bloc 3 — Moteur IA (détection de phishing & scoring de vulnérabilités).

Ce paquet expose les modèles mappant vers les contrats partagés :

* :class:`PhishingDetector`     -> TF-IDF + RandomForest (+ repli heuristique)
* :class:`BertPhishingDetector` -> transformer multilingue fine-tuné
* :class:`VulnScorer`           -> :class:`src.common.schemas.VulnScore`

Tous les imports lourds (scikit-learn, xgboost, transformers, torch) sont
PARESSEUX (effectues dans les methodes). ``import src.bloc3_ia`` reussit donc
sans ces dependances, et chaque modele dispose d'un REPLI permettant au pipeline
de produire des predictions SANS aucun entrainement prealable.

Points d'entree publics :
    >>> from src.bloc3_ia import get_detector, evaluate_predictions
    >>> detector = get_detector()
    >>> predictions = detector.predict(samples)
"""

from __future__ import annotations

from typing import Union  # noqa: F401

from src.bloc3_ia.bert_detector import BertPhishingDetector
from src.bloc3_ia.evaluation import evaluate_predictions, print_report
from src.bloc3_ia.phishing_detector import PhishingDetector
from src.bloc3_ia.vuln_scorer import VulnScorer
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

Detector = Union[BertPhishingDetector, PhishingDetector]


def get_detector(kind: str = "auto") -> Detector:
    """Selectionne et retourne un detecteur de phishing pret a l'emploi.

    Args:
        kind: strategie de selection :

            * ``"auto"`` (defaut) : renvoie un :class:`BertPhishingDetector` si
              ``transformers``/``torch`` sont disponibles ET qu'un modele
              fine-tune existe sur disque ; sinon un :class:`PhishingDetector`
              (TF-IDF charge si present, sinon repli heuristique).
            * ``"bert"`` : force le :class:`BertPhishingDetector` (predictions
              neutres si indisponible).
            * ``"tfidf"`` : force le :class:`PhishingDetector` (charge le modele
              persistant si present).

    Returns:
        Une instance de detecteur exposant ``predict(samples)``.
    """
    if kind == "bert":
        detector = BertPhishingDetector()
        detector.load()
        return detector

    if kind == "tfidf":
        return PhishingDetector().load()

    if kind != "auto":
        logger.warning("kind='%s' inconnu ; repli sur 'auto'.", kind)

    bert = BertPhishingDetector()
    if bert.is_available() and bert.model_dir.exists():
        logger.info("get_detector(auto) : modele BERT detecte, selection de BERT.")
        bert.load()
        if bert.is_loaded:
            return bert
        logger.warning("Chargement BERT echoue ; repli sur TF-IDF/heuristique.")

    logger.info("get_detector(auto) : selection du detecteur TF-IDF/heuristique.")
    return PhishingDetector().load()


__all__ = [
    "PhishingDetector",
    "BertPhishingDetector",
    "VulnScorer",
    "get_detector",
    "evaluate_predictions",
    "print_report",
]
