"""Script d'entrainement HONNETE et VERSIONNE du detecteur de phishing (bloc 3).

Corrige les defauts de l'ancien flux :

* **Donnees reelles en priorite** : l'ordre de chargement privilegie un dataset
  consolide, puis les datasets externes reels, et ne retombe sur le synthetique
  qu'en dernier recours.
* **Pas de fuite de donnees** : split stratifie train/val/test ; l'evaluation se
  fait sur le TEST tenu a l'ecart (jamais vu a l'entrainement).
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
from src.bloc3_ia.evaluation import evaluate_predictions, print_report
from src.bloc3_ia.phishing_detector import PhishingDetector
from src.common.config import DATA_DIR, SAMPLES_DIR
from src.common.logging_conf import get_logger
from src.common.schemas import PhishingSample

logger = get_logger(__name__)

# Chemins de reference pour l'ordre de priorite du chargement.
PROCESSED_DATASET = DATA_DIR / "processed" / "training_dataset.csv"
EXTERNAL_DIR = DATA_DIR / "external"
SAMPLES_CSV = SAMPLES_DIR / "phishing_samples_cm.csv"

# Seuil en deca duquel on considere le jeu de donnees comme tres petit.
_SMALL_DATASET_THRESHOLD = 30


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
# Entrainement TF-IDF
# --------------------------------------------------------------------------- #
def _train_tfidf(
    samples: List[PhishingSample],
    source: str,
    test_size: float,
    val_size: float,
    seed: int,
) -> int:
    """Entraine, evalue sur le TEST tenu a l'ecart, et versionne le modele.

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

    # Split stratifie : le TEST n'est JAMAIS vu a l'entrainement.
    train, val, test = _stratified_split(labeled, test_size, val_size, seed)
    logger.info(
        "Split : train=%d, val=%d, test=%d.", len(train), len(val), len(test)
    )

    # Entrainement sur train (+ val, simple agregation pour stabiliser le baseline).
    fit_samples = train + val
    detector = PhishingDetector()
    detector.train(fit_samples)
    if not detector.is_trained:
        logger.error("L'entrainement TF-IDF n'a pas abouti (dependances ?). Arret.")
        return 1

    # Evaluation HONNETE sur le test tenu a l'ecart.
    if not test:
        logger.warning(
            "Test vide (donnees insuffisantes) : evaluation sur train (indicative)."
        )
        eval_set = fit_samples
    else:
        eval_set = test
    metrics = evaluate_predictions(eval_set, detector.predict(eval_set))
    print_report(metrics)

    support = _class_support(eval_set)
    logger.info(
        "Support par classe sur le set d'evaluation : legitime(0)=%d, phishing(1)=%d.",
        support.get(0, 0),
        support.get(1, 0),
    )
    print(f" Support set d'eval  legitime (0) : {support.get(0, 0)}")
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
    metrics = evaluate_predictions(eval_set, detector.predict(eval_set))
    print_report(metrics)
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
    """Pipeline : charge -> nettoie -> split -> entraine -> evalue (test) -> versionne.

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
