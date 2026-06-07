"""Évaluation des prédictions de phishing (métriques de classification).

Calcule accuracy, precision, recall, F1 et matrice de confusion à partir des
``PhishingSample`` labellisés et des :class:`PhishingPrediction` correspondantes.

L'implémentation est manuelle (bibliothèque standard) afin de rester sans
dépendance lourde ; ``scikit-learn`` n'est utilisé qu'en repli paresseux si
présent. Le module reste donc importable et exécutable sans sklearn/torch.
"""

from __future__ import annotations

from typing import Dict, List

from src.common.logging_conf import get_logger
from src.common.schemas import PhishingPrediction, PhishingSample

logger = get_logger(__name__)


def _metrics_from_counts(tp: int, fp: int, tn: int, fn: int) -> Dict[str, object]:
    """Calcule les métriques de classification à partir des effectifs bruts.

    Args:
        tp: vrais positifs.
        fp: faux positifs.
        tn: vrais négatifs.
        fn: faux négatifs.

    Returns:
        Dictionnaire ``n_evaluated``, ``accuracy``, ``precision``, ``recall``,
        ``f1`` et ``confusion_matrix``. Métriques nulles si aucun effectif.
    """
    n_evaluated = tp + fp + tn + fn
    if n_evaluated == 0:
        return {
            "n_evaluated": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        }

    accuracy = (tp + tn) / n_evaluated
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return {
        "n_evaluated": n_evaluated,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def evaluate_predictions(
    samples: List[PhishingSample],
    predictions: List[PhishingPrediction],
) -> Dict[str, object]:
    """Calcule les métriques de classification binaire phishing.

    Seuls les échantillons dont le ``label`` n'est pas ``None`` sont pris en
    compte. La classe positive est ``1`` (phishing). La correspondance entre
    échantillons et prédictions se fait par ``sample_id``.

    Args:
        samples: échantillons (labellisés ou non).
        predictions: prédictions associées (un par échantillon idéalement).

    Returns:
        Dictionnaire contenant ``n_evaluated``, ``accuracy``, ``precision``,
        ``recall``, ``f1`` et ``confusion_matrix`` (clés ``tp``, ``fp``, ``tn``,
        ``fn``). Toutes les métriques valent ``0.0`` si aucun échantillon
        labellisé n'est disponible.
    """
    pred_by_id: Dict[str, PhishingPrediction] = {p.sample_id: p for p in predictions}

    tp = fp = tn = fn = 0
    n_evaluated = 0
    for sample in samples:
        if sample.label is None:
            continue
        pred = pred_by_id.get(sample.id)
        if pred is None:
            logger.warning("Aucune prédiction pour l'échantillon %s.", sample.id)
            continue
        n_evaluated += 1
        y_true = int(sample.label)
        y_pred = 1 if pred.is_phishing else 0
        if y_true == 1 and y_pred == 1:
            tp += 1
        elif y_true == 0 and y_pred == 1:
            fp += 1
        elif y_true == 0 and y_pred == 0:
            tn += 1
        else:  # y_true == 1 and y_pred == 0
            fn += 1

    if n_evaluated == 0:
        logger.warning("Aucun échantillon labellisé : métriques nulles.")
    return _metrics_from_counts(tp, fp, tn, fn)


def evaluate_by_source(
    samples: List[PhishingSample],
    predictions: List[PhishingPrediction],
) -> Dict[str, Dict[str, object]]:
    """Ventile precision/recall/F1 par ``source`` des échantillons.

    Permet d'objectiver la généralisation réelle du modèle : un score global
    élevé peut masquer de gros écarts entre données réelles (ex.
    ``uci_sms_spam``) et données synthétiques (``synthetic``). On calcule donc un
    jeu de métriques par valeur de ``sample.source``.

    Seuls les échantillons labellisés et appariés à une prédiction (par
    ``sample_id``) sont comptés. La classe positive est ``1`` (phishing).

    Args:
        samples: échantillons (labellisés ou non), porteurs du champ ``source``.
        predictions: prédictions associées (appariées par ``sample_id``).

    Returns:
        Dictionnaire ``{source: metrics}`` où ``metrics`` a la même structure
        que :func:`evaluate_predictions`. Dictionnaire vide si aucun échantillon
        labellisé n'est exploitable.
    """
    pred_by_id: Dict[str, PhishingPrediction] = {p.sample_id: p for p in predictions}

    # Effectifs (tp, fp, tn, fn) par source.
    counts: Dict[str, List[int]] = {}
    for sample in samples:
        if sample.label is None:
            continue
        pred = pred_by_id.get(sample.id)
        if pred is None:
            continue
        src = sample.source or "inconnu"
        slot = counts.setdefault(src, [0, 0, 0, 0])  # [tp, fp, tn, fn]
        y_true = int(sample.label)
        y_pred = 1 if pred.is_phishing else 0
        if y_true == 1 and y_pred == 1:
            slot[0] += 1
        elif y_true == 0 and y_pred == 1:
            slot[1] += 1
        elif y_true == 0 and y_pred == 0:
            slot[2] += 1
        else:  # y_true == 1 and y_pred == 0
            slot[3] += 1

    return {
        src: _metrics_from_counts(tp, fp, tn, fn)
        for src, (tp, fp, tn, fn) in sorted(counts.items())
    }


def print_report(metrics: Dict[str, object]) -> None:
    """Affiche un rapport lisible des métriques d'évaluation.

    Args:
        metrics: dictionnaire retourné par :func:`evaluate_predictions`.
    """
    cm = metrics.get("confusion_matrix", {})
    lines = [
        "=" * 48,
        " RAPPORT D'ÉVALUATION — DÉTECTION DE PHISHING",
        "=" * 48,
        f" Échantillons évalués : {metrics.get('n_evaluated', 0)}",
        f" Accuracy             : {metrics.get('accuracy', 0.0):.4f}",
        f" Precision            : {metrics.get('precision', 0.0):.4f}",
        f" Recall               : {metrics.get('recall', 0.0):.4f}",
        f" F1-score             : {metrics.get('f1', 0.0):.4f}",
        "-" * 48,
        " Matrice de confusion :",
        f"   Vrais positifs (TP)  : {cm.get('tp', 0)}",
        f"   Faux positifs (FP)   : {cm.get('fp', 0)}",
        f"   Vrais négatifs (TN)  : {cm.get('tn', 0)}",
        f"   Faux négatifs (FN)   : {cm.get('fn', 0)}",
        "=" * 48,
    ]
    report = "\n".join(lines)
    print(report)
    logger.info("Rapport d'évaluation généré (n=%s).", metrics.get("n_evaluated", 0))


def print_by_source_report(by_source: Dict[str, Dict[str, object]]) -> None:
    """Affiche un tableau des métriques ventilées par source.

    Args:
        by_source: dictionnaire retourné par :func:`evaluate_by_source`.
    """
    lines = [
        "=" * 64,
        " MÉTRIQUES PAR SOURCE (généralisation réelle)",
        "=" * 64,
        f" {'source':<18}{'n':>5}{'prec':>9}{'recall':>9}{'f1':>9}",
        "-" * 64,
    ]
    if not by_source:
        lines.append(" (aucune source labellisée exploitable)")
    for src, m in by_source.items():
        lines.append(
            f" {src:<18}{m.get('n_evaluated', 0):>5}"
            f"{m.get('precision', 0.0):>9.4f}"
            f"{m.get('recall', 0.0):>9.4f}"
            f"{m.get('f1', 0.0):>9.4f}"
        )
    lines.append("=" * 64)
    print("\n".join(lines))
    logger.info("Rapport par source généré (%d source(s)).", len(by_source))


__all__ = [
    "evaluate_predictions",
    "evaluate_by_source",
    "print_report",
    "print_by_source_report",
]
