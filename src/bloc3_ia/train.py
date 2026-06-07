"""Script d'entrainement HONNETE et VERSIONNE du detecteur de phishing (bloc 3).

Corrige les defauts de l'ancien flux :

* **Donnees reelles en priorite** : l'ordre de chargement privilegie un dataset
  consolide, puis les datasets externes reels, et ne retombe sur le synthetique
  qu'en dernier recours.
* **Pas de fuite de donnees** : split stratifie train/val/test ; le calibrage du
  seuil se fait sur la VALIDATION et l'evaluation finale sur le TEST tenu a
  l'ecart (jamais vu a l'entrainement ni au calibrage).
* **Seuil calibre** : apres entrainement, on balaye les seuils sur la VAL et on
  retient celui qui maximise le F1 (ou le rappel sous contrainte precision >=
  0.95). Le seuil retenu (``chosen_threshold``) est persiste dans le meta.json.
* **Transparence par source** : metriques precision/recall/F1 ventilees par
  ``source`` (reel ``uci_sms_spam`` vs ``synthetic``...) pour objectiver la
  generalisation reelle.
* **Versionnage des artefacts** : sauvegarde versionnee (modele + metrics.json +
  meta.json) via :mod:`src.bloc3_ia.model_registry`.

Ordre de priorite du chargement du dataset :

1. ``data/processed/training_dataset.csv`` (corpus consolide) s'il existe ;
2. SINON, concatenation de tous les ``data/external/*.csv`` ;
3. SINON, le corpus synthetique (``corpus_generator.generate_corpus``) ;
4. SINON, ``data/samples/phishing_samples_cm.csv``.

Deux modeles via ``--model`` :

* ``tfidf`` (defaut) : baseline TF-IDF + RandomForest (scikit-learn).
* ``bert``           : fine-tuning d'un transformer multilingue (sortie propre
  si ``transformers``/``torch`` absents).

Usage :
    python -m src.bloc3_ia.train                       # tfidf (defaut)
    python -m src.bloc3_ia.train --model tfidf --test-size 0.2 --val-size 0.1
    python -m src.bloc3_ia.train --model bert --seed 42
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.bloc2_phishing import generate_corpus, load_samples, preprocess
from src.bloc3_ia.bert_detector import BertPhishingDetector
from src.bloc3_ia.evaluation import (
    evaluate_by_source,
    evaluate_predictions,
    print_by_source_report,
    print_report,
)
from src.bloc3_ia.phishing_detector import PhishingDetector
from src.common.config import DATA_DIR, SAMPLES_DIR, settings
from src.common.logging_conf import get_logger
from src.common.schemas import PhishingPrediction, PhishingSample

logger = get_logger(__name__)

# Chemins de reference pour l'ordre de priorite du chargement.
PROCESSED_DATASET = DATA_DIR / "processed" / "training_dataset.csv"
EXTERNAL_DIR = DATA_DIR / "external"
SAMPLES_CSV = SAMPLES_DIR / "phishing_samples_cm.csv"

# Seuil en deca duquel on considere le jeu de donnees comme tres petit.
_SMALL_DATASET_THRESHOLD = 30

# Contrainte de precision minimale pour la strategie "rappel sous contrainte".
_MIN_PRECISION = 0.95
# Grille de seuils balayee sur la validation (de 0.05 a 0.95 par pas de 0.01).
_THRESHOLD_GRID = [round(0.05 + 0.01 * i, 2) for i in range(0, 91)]


# --------------------------------------------------------------------------- #
# Chargement du dataset (donnees reelles en priorite)
# --------------------------------------------------------------------------- #
def load_dataset() -> Tuple[List[PhishingSample], str]:
    """Charge le dataset selon l'ordre de priorite (reel d'abord).

    Returns:
        Un couple ``(samples, source)`` ou ``source`` decrit l'origine retenue
        (``"processed"``, ``"external"``, ``"synthetic"`` ou ``"samples"``).
        ``samples`` est vide si aucune source n'a abouti.
    """
    # 1) Corpus consolide produit par un autre module.
    if PROCESSED_DATASET.exists():
        logger.info("Dataset consolide detecte : %s", PROCESSED_DATASET)
        samples = load_samples(PROCESSED_DATASET)
        if samples:
            return samples, "processed"
        logger.warning("Dataset consolide vide/illisible ; passage au suivant.")

    # 2) Concatenation de tous les CSV reels de data/external/.
    if EXTERNAL_DIR.exists():
        external_csvs = sorted(EXTERNAL_DIR.glob("*.csv"))
        if external_csvs:
            logger.info(
                "%d CSV externe(s) detecte(s) dans %s.",
                len(external_csvs),
                EXTERNAL_DIR,
            )
            merged: List[PhishingSample] = []
            for csv_path in external_csvs:
                merged.extend(load_samples(csv_path))
            if merged:
                logger.info(
                    "%d echantillon(s) reel(s) concatene(s) depuis data/external/.",
                    len(merged),
                )
                return merged, "external"
            logger.warning("CSV externes vides/illisibles ; passage au suivant.")

    # 3) Corpus synthetique (filet de securite).
    logger.info("Aucune donnee reelle exploitable : generation synthetique.")
    synth = generate_corpus()
    if synth:
        return synth, "synthetic"

    # 4) Dernier repli : echantillons CM livres avec le projet.
    if SAMPLES_CSV.exists():
        logger.info("Repli ultime sur %s.", SAMPLES_CSV)
        samples = load_samples(SAMPLES_CSV)
        if samples:
            return samples, "samples"

    return [], "none"


# --------------------------------------------------------------------------- #
# Split stratifie train/val/test
# --------------------------------------------------------------------------- #
def _stratified_split(
    samples: List[PhishingSample],
    test_size: float,
    val_size: float,
    seed: int,
) -> Tuple[List[PhishingSample], List[PhishingSample], List[PhishingSample]]:
    """Decoupe les echantillons labellises en train/val/test (stratifie).

    Args:
        samples: echantillons labellises (``label`` in {0, 1}).
        test_size: proportion du test (0..1).
        val_size: proportion de la validation (0..1, par rapport au total).
        seed: graine de reproductibilite.

    Returns:
        Triplet ``(train, val, test)``. Si la stratification est impossible
        (effectifs trop faibles), retombe sur un split non stratifie.
    """
    from sklearn.model_selection import train_test_split

    labels = [int(s.label) for s in samples]
    stratify = labels if len(set(labels)) >= 2 else None

    # 1) On isole d'abord le TEST.
    try:
        train_val, test = train_test_split(
            samples,
            test_size=test_size,
            random_state=seed,
            stratify=stratify,
        )
    except ValueError:
        logger.warning("Stratification du test impossible ; split simple.")
        train_val, test = train_test_split(
            samples, test_size=test_size, random_state=seed
        )

    # 2) On isole ensuite la VAL depuis le reste (proportion relative ajustee).
    if val_size <= 0.0 or len(train_val) < 4:
        return train_val, [], test

    rel_val = val_size / max(1e-9, (1.0 - test_size))
    rel_val = min(max(rel_val, 0.0), 0.9)
    tv_labels = [int(s.label) for s in train_val]
    tv_stratify = tv_labels if len(set(tv_labels)) >= 2 else None
    try:
        train, val = train_test_split(
            train_val,
            test_size=rel_val,
            random_state=seed,
            stratify=tv_stratify,
        )
    except ValueError:
        logger.warning("Stratification de la val impossible ; split simple.")
        train, val = train_test_split(
            train_val, test_size=rel_val, random_state=seed
        )
    return train, val, test


def _class_support(samples: List[PhishingSample]) -> Dict[int, int]:
    """Compte le support par classe (0/1) sur les echantillons labellises."""
    support: Dict[int, int] = {0: 0, 1: 0}
    for s in samples:
        if s.label is not None:
            support[int(s.label)] = support.get(int(s.label), 0) + 1
    return support


# --------------------------------------------------------------------------- #
# Calibrage du seuil (sur la VALIDATION uniquement, ANTI-FUITE)
# --------------------------------------------------------------------------- #
def _predictions_at_threshold(
    samples: List[PhishingSample],
    scores: List[float],
    threshold: float,
    model: str = "tfidf_rf",
) -> List[PhishingPrediction]:
    """Construit des predictions a partir de scores bruts et d'un seuil donne.

    Args:
        samples: echantillons alignes sur ``scores``.
        scores: scores de phishing ∈ [0, 1] (sortie de ``predict_scores``).
        threshold: seuil de decision a appliquer.
        model: nom du modele a renseigner dans la prediction.

    Returns:
        Liste de :class:`PhishingPrediction` (un par echantillon).
    """
    return [
        PhishingPrediction(
            sample_id=s.id,
            is_phishing=score >= threshold,
            score=round(float(score), 4),
            model=model,
        )
        for s, score in zip(samples, scores)
    ]


def calibrate_threshold(
    val_samples: List[PhishingSample],
    val_scores: List[float],
    min_precision: float = _MIN_PRECISION,
) -> Tuple[float, Dict[str, object]]:
    """Choisit le meilleur seuil sur la VALIDATION (anti-fuite).

    Strategie :

    1. Parmi les seuils dont la precision >= ``min_precision``, retenir celui qui
       maximise le RAPPEL (puis le F1 en cas d'egalite) ; cela exploite la marge
       d'une precision elevee pour AUGMENTER le rappel sans s'effondrer.
    2. Si AUCUN seuil n'atteint ``min_precision`` sur la val, retomber sur le
       seuil qui maximise le F1 global.

    Args:
        val_samples: echantillons de validation labellises.
        val_scores: scores de phishing ∈ [0, 1] du modele sur la validation.
        min_precision: contrainte de precision minimale (defaut 0.95).

    Returns:
        Couple ``(chosen_threshold, info)`` ou ``info`` documente la strategie
        retenue et les metriques de validation au seuil choisi.
    """
    best_f1_thr = settings.phishing_threshold
    best_f1_val = -1.0
    best_f1_metrics: Dict[str, object] = {}

    best_constrained_thr: Optional[float] = None
    best_constrained_recall = -1.0
    best_constrained_f1 = -1.0
    best_constrained_metrics: Dict[str, object] = {}

    for thr in _THRESHOLD_GRID:
        preds = _predictions_at_threshold(val_samples, val_scores, thr)
        m = evaluate_predictions(val_samples, preds)
        f1 = float(m.get("f1", 0.0))
        prec = float(m.get("precision", 0.0))
        rec = float(m.get("recall", 0.0))

        # Suivi du meilleur F1 global (repli).
        if f1 > best_f1_val:
            best_f1_val = f1
            best_f1_thr = thr
            best_f1_metrics = m

        # Suivi du meilleur rappel sous contrainte de precision.
        if prec >= min_precision:
            if rec > best_constrained_recall or (
                rec == best_constrained_recall and f1 > best_constrained_f1
            ):
                best_constrained_recall = rec
                best_constrained_f1 = f1
                best_constrained_thr = thr
                best_constrained_metrics = m

    if best_constrained_thr is not None:
        info = {
            "strategy": f"max_recall@precision>={min_precision}",
            "min_precision": min_precision,
            "val_metrics": best_constrained_metrics,
        }
        return best_constrained_thr, info

    info = {
        "strategy": "max_f1 (contrainte de precision inatteignable sur val)",
        "min_precision": min_precision,
        "val_metrics": best_f1_metrics,
    }
    return best_f1_thr, info


# --------------------------------------------------------------------------- #
# Entrainement TF-IDF
# --------------------------------------------------------------------------- #
def _train_tfidf(
    samples: List[PhishingSample],
    source: str,
    test_size: float,
    val_size: float,
    seed: int,
) -> int:
    """Entraine, calibre le seuil (val), evalue sur le TEST, et versionne.

    Returns:
        Code de sortie (0 = succes, 1 = echec).
    """
    try:
        from sklearn.model_selection import train_test_split  # noqa: F401
    except ImportError:
        logger.error(
            "scikit-learn absent : entrainement TF-IDF impossible. "
            "Le pipeline reste en repli heuristique."
        )
        return 1

    labeled = [s for s in samples if s.label is not None]
    n_total = len(samples)
    n_labeled = len(labeled)
    logger.info(
        "Source=%s : %d echantillon(s), dont %d labellise(s).",
        source,
        n_total,
        n_labeled,
    )

    if len({s.label for s in labeled}) < 2:
        logger.error(
            "Moins de 2 classes labellisees : entrainement impossible. "
            "Le pipeline restera en repli heuristique."
        )
        return 1

    if n_labeled < _SMALL_DATASET_THRESHOLD:
        logger.warning(
            "Jeu de donnees tres petit (%d labellise(s) < %d) : "
            "metriques peu fiables, poursuite quand meme.",
            n_labeled,
            _SMALL_DATASET_THRESHOLD,
        )

    # Split stratifie : le TEST n'est JAMAIS vu (ni a l'entrainement ni au
    # calibrage) ; la VAL sert uniquement au calibrage du seuil.
    train, val, test = _stratified_split(labeled, test_size, val_size, seed)
    logger.info(
        "Split : train=%d, val=%d, test=%d.", len(train), len(val), len(test)
    )

    # ANTI-FUITE : on entraine sur le TRAIN seul (la VAL doit rester non vue par
    # le modele pour calibrer le seuil honnetement). Si la VAL est vide, on
    # retombe sur train (calibrage degrade, signale).
    detector = PhishingDetector()
    detector.train(train)
    if not detector.is_trained:
        logger.error("L'entrainement TF-IDF n'a pas abouti (dependances ?). Arret.")
        return 1

    # --- Calibrage du seuil sur la VALIDATION ---
    default_threshold = float(settings.phishing_threshold)
    chosen_threshold = default_threshold
    calib_info: Dict[str, object] = {"strategy": "defaut (pas de validation)"}
    if val:
        val_scores = detector.predict_scores(val)
        chosen_threshold, calib_info = calibrate_threshold(val, val_scores)
        logger.info(
            "Seuil calibre sur la validation : %.3f (strategie=%s).",
            chosen_threshold,
            calib_info.get("strategy"),
        )
    else:
        logger.warning(
            "Validation vide : pas de calibrage, seuil par defaut %.3f conserve.",
            default_threshold,
        )
    detector.set_threshold(chosen_threshold, calibrated=bool(val))

    # --- Evaluation HONNETE sur le test tenu a l'ecart ---
    if not test:
        logger.warning(
            "Test vide (donnees insuffisantes) : evaluation sur train (indicative)."
        )
        eval_set = train
    else:
        eval_set = test

    test_scores = detector.predict_scores(eval_set)

    # Metriques AVANT calibrage (seuil par defaut) pour la transparence.
    preds_default = _predictions_at_threshold(eval_set, test_scores, default_threshold)
    metrics_default = evaluate_predictions(eval_set, preds_default)

    # Metriques APRES calibrage (seuil retenu) = metriques officielles.
    preds_chosen = _predictions_at_threshold(eval_set, test_scores, chosen_threshold)
    metrics = evaluate_predictions(eval_set, preds_chosen)

    print(f"\n>>> Seuil par defaut (config) : {default_threshold:.3f}")
    print(f">>> Seuil CALIBRE retenu      : {chosen_threshold:.3f} "
          f"(strategie : {calib_info.get('strategy')})")
    print("\n--- TEST @ seuil par defaut (avant calibrage) ---")
    print_report(metrics_default)
    print("\n--- TEST @ seuil CALIBRE (apres calibrage) ---")
    print_report(metrics)

    # Metriques ventilees par source (transparence sur la generalisation).
    by_source = evaluate_by_source(eval_set, preds_chosen)
    print()
    print_by_source_report(by_source)

    support = _class_support(eval_set)
    logger.info(
        "Support par classe sur le set d'evaluation : legitime(0)=%d, phishing(1)=%d.",
        support.get(0, 0),
        support.get(1, 0),
    )
    print(f"\n Support set d'eval  legitime (0) : {support.get(0, 0)}")
    print(f" Support set d'eval  phishing (1) : {support.get(1, 0)}")

    # Compatibilite : conserve aussi l'alias joblib historique.
    legacy_path = detector.save()

    # Sauvegarde versionnee (modele + metrics.json + meta.json + alias courant).
    meta = {
        "model": "tfidf_rf",
        "date": datetime.now().isoformat(timespec="seconds"),
        "seed": seed,
        "dataset_source": source,
        "dataset_size_total": n_total,
        "dataset_size_labeled": n_labeled,
        "split": {
            "test_size": test_size,
            "val_size": val_size,
            "n_train": len(train),
            "n_val": len(val),
            "n_test": len(test),
        },
        "eval_set": "test" if test else "train_fallback",
        "support_eval": support,
        # --- Seuil calibre + transparence ---
        "default_threshold": default_threshold,
        "chosen_threshold": chosen_threshold,
        "calibration": calib_info,
        "metrics_default_threshold": metrics_default,
        "metrics_chosen_threshold": metrics,
        "metrics_by_source": by_source,
        "legacy_alias": str(legacy_path) if legacy_path else None,
    }
    try:
        from src.bloc3_ia.model_registry import save_model

        version_dir = save_model(detector, metrics, meta, kind="tfidf_rf")
        logger.info("Entrainement termine. Artefact versionne : %s", version_dir)
        return 0
    except Exception as exc:
        logger.error("Echec du versionnage de l'artefact : %s", exc)
        return 1


# --------------------------------------------------------------------------- #
# Entrainement BERT
# --------------------------------------------------------------------------- #
def _train_bert(
    samples: List[PhishingSample],
    source: str,
    test_size: float,
    val_size: float,
    seed: int,
) -> int:
    """Fine-tune BERT avec split honnete et versionnage, si deps presentes.

    Returns:
        Code de sortie : 0 meme si BERT est indisponible (sortie propre).
    """
    if not BertPhishingDetector.is_available():
        logger.warning(
            "transformers/torch absent : fine-tuning BERT impossible. "
            "Installez-les avec : pip install 'transformers>=4.30' 'torch>=2.0'. "
            "Aucun modele entraine - le pipeline reste en TF-IDF/heuristique."
        )
        return 0

    labeled = [s for s in samples if s.label is not None]
    if len({s.label for s in labeled}) < 2:
        logger.error("Moins de 2 classes labellisees : entrainement BERT impossible.")
        return 1

    train, val, test = _stratified_split(labeled, test_size, val_size, seed)
    logger.info(
        "Split BERT : train=%d, val=%d, test=%d.", len(train), len(val), len(test)
    )

    detector = BertPhishingDetector()
    try:
        detector.train(train + val)
    except (RuntimeError, TypeError) as exc:
        logger.error("Fine-tuning BERT impossible : %s", exc)
        return 1

    eval_set = test if test else (train + val)
    predictions = detector.predict(eval_set)
    metrics = evaluate_predictions(eval_set, predictions)
    print_report(metrics)
    by_source = evaluate_by_source(eval_set, predictions)
    print()
    print_by_source_report(by_source)
    support = _class_support(eval_set)
    print(f" Support set d'eval  legitime (0) : {support.get(0, 0)}")
    print(f" Support set d'eval  phishing (1) : {support.get(1, 0)}")

    meta = {
        "model": "bert_multilingual",
        "date": datetime.now().isoformat(timespec="seconds"),
        "seed": seed,
        "dataset_source": source,
        "dataset_size_labeled": len(labeled),
        "split": {
            "test_size": test_size,
            "val_size": val_size,
            "n_train": len(train),
            "n_val": len(val),
            "n_test": len(test),
        },
        "support_eval": support,
        "metrics_by_source": by_source,
    }
    try:
        from src.bloc3_ia.model_registry import save_model

        version_dir = save_model(detector, metrics, meta, kind="bert")
        logger.info("Fine-tuning BERT termine. Artefact versionne : %s", version_dir)
    except Exception as exc:
        logger.warning("Versionnage BERT non effectue (%s).", exc)
    logger.info("Modele BERT disponible : %s", getattr(detector, "model_dir", "?"))
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Analyse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Entrainement honnete et versionne du detecteur de phishing."
    )
    parser.add_argument(
        "--model",
        choices=["tfidf", "bert"],
        default="tfidf",
        help="Modele a entrainer (defaut : tfidf).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion du jeu de TEST tenu a l'ecart (defaut : 0.2).",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.1,
        help="Proportion du jeu de VALIDATION (defaut : 0.1).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Graine de reproductibilite (defaut : 42).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Pipeline : charge -> nettoie -> split -> entraine -> calibre -> evalue.

    Returns:
        Code de sortie du processus (0 = succes / sortie propre).
    """
    args = _parse_args(argv)
    logger.info(
        "Demarrage entrainement (modele=%s, test_size=%.2f, val_size=%.2f, seed=%d).",
        args.model,
        args.test_size,
        args.val_size,
        args.seed,
    )

    samples, source = load_dataset()
    if not samples:
        logger.error("Aucun echantillon charge. Arret.")
        return 1
    samples = preprocess(samples)

    # Anti-fuite (audit IA MAJEUR-1) : deux messages dont le texte NETTOYE est
    # identique (ex. templates synthetiques ne differant que par un montant ou
    # un numero, effaces en <MONEY>/<PHONE>) creent une fuite train->test. On
    # deduplique donc sur clean_text AVANT le split (on garde la 1re occurrence).
    seen = set()
    deduped: List[PhishingSample] = []
    for smp in samples:
        key = (smp.clean_text or smp.raw_text or "").strip().lower()
        if key and key in seen:
            continue
        seen.add(key)
        deduped.append(smp)
    removed = len(samples) - len(deduped)
    if removed:
        logger.info(
            "Anti-fuite : %d doublon(s) de texte nettoye supprime(s) avant split "
            "(%d -> %d echantillons uniques).", removed, len(samples), len(deduped)
        )
    samples = deduped

    if args.model == "bert":
        return _train_bert(samples, source, args.test_size, args.val_size, args.seed)
    return _train_tfidf(samples, source, args.test_size, args.val_size, args.seed)


if __name__ == "__main__":
    sys.exit(main())
