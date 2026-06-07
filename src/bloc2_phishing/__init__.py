"""Bloc 2 - Collecte & pretraitement des messages de phishing.

Ce paquet charge les echantillons de phishing (SMS Mobile Money, e-mails
bancaires, URLs) vers le contrat partage :class:`src.common.schemas.PhishingSample`
puis nettoie leur texte pour alimenter le moteur IA (bloc 3).

Contexte camerounais : SMS MTN MoMo / Orange Money, banques (Afriland, UBA,
Ecobank), operateurs (CAMTEL, ENEO).

Points d'entree publics :
    >>> from src.bloc2_phishing import load_samples, preprocess
    >>> samples = preprocess(load_samples())

Generation d'un corpus synthetique (recherche defensive) :
    >>> from src.bloc2_phishing import generate_corpus
    >>> corpus = generate_corpus(n_per_class=120, seed=42)

Acquisition / assemblage du dataset d'entrainement reel :
    >>> from src.bloc2_phishing import build_training_dataset, load_external
    >>> path = build_training_dataset()
"""

from __future__ import annotations

from src.bloc2_phishing.corpus_generator import export_csv, generate_corpus
from src.bloc2_phishing.dataset_downloader import (
    build_training_dataset,
    dataset_stats,
    download_source,
    load_external,
)
from src.bloc2_phishing.loader import load_samples
from src.bloc2_phishing.preprocessing import preprocess

__all__ = [
    "load_samples",
    "preprocess",
    "generate_corpus",
    "export_csv",
    "build_training_dataset",
    "load_external",
    "download_source",
    "dataset_stats",
]
