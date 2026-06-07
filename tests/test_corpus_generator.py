"""Tests du générateur synthétique de corpus de phishing (bloc 2).

Vérifie que :func:`generate_corpus` produit un corpus équilibré, conforme au
contrat :class:`src.common.schemas.PhishingSample`, avec des identifiants
uniques et des labels binaires valides. Le générateur n'utilise que la
bibliothèque standard : aucun import lourd n'est requis.
"""

from __future__ import annotations

from src.bloc2_phishing.corpus_generator import generate_corpus
from src.common.schemas import PhishingSample


def test_generate_corpus_balanced() -> None:
    """``n_per_class=20`` renvoie 40 échantillons équilibrés et valides."""
    samples = generate_corpus(n_per_class=20)

    # Taille totale = 2 * n_per_class.
    assert len(samples) == 40

    # Tous des PhishingSample.
    assert all(isinstance(s, PhishingSample) for s in samples)

    # Labels binaires valides et équilibrés (20 / 20).
    labels = [s.label for s in samples]
    assert set(labels) == {0, 1}
    assert labels.count(1) == 20
    assert labels.count(0) == 20

    # Identifiants uniques.
    ids = [s.id for s in samples]
    assert len(set(ids)) == len(ids)

    # Texte brut non vide et source synthétique.
    assert all(s.raw_text.strip() for s in samples)
    assert all(s.source == "synthetic" for s in samples)


def test_generate_corpus_reproducible() -> None:
    """Une même graine produit un corpus identique (reproductibilité)."""
    a = generate_corpus(n_per_class=20, seed=7)
    b = generate_corpus(n_per_class=20, seed=7)
    assert [s.raw_text for s in a] == [s.raw_text for s in b]
