"""Génère le corpus synthétique de phishing camerounais et l'exporte en CSV.

Usage (depuis la racine du projet) :

    python -m scripts.generate_corpus

Écrit ``data/samples/phishing_corpus_synth.csv`` (≈ 240 lignes, équilibré
phishing/légitime) et affiche un résumé par classe, canal et langue.

⚠️ Données ENTIÈREMENT SYNTHÉTIQUES destinées à la recherche défensive
(entraînement/évaluation de détecteurs). Aucune donnée personnelle réelle.
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from src.bloc2_phishing.corpus_generator import export_csv, generate_corpus
from src.common.config import SAMPLES_DIR
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

DEFAULT_OUTPUT = SAMPLES_DIR / "phishing_corpus_synth.csv"


def _print_summary(samples, out_path: Path) -> None:
    by_label = Counter(s.label for s in samples)
    by_channel = Counter(s.channel.value for s in samples)
    by_language = Counter(s.language for s in samples)

    print("=" * 60)
    print("Corpus synthétique de phishing camerounais — résumé")
    print("=" * 60)
    print(f"Fichier      : {out_path}")
    print(f"Total        : {len(samples)} échantillons")
    print("-" * 60)
    print("Par classe   :")
    print(f"  phishing (label=1) : {by_label.get(1, 0)}")
    print(f"  légitime (label=0) : {by_label.get(0, 0)}")
    print("Par canal    :")
    for chan, cnt in sorted(by_channel.items()):
        print(f"  {chan:<6} : {cnt}")
    print("Par langue   :")
    for lang, cnt in sorted(by_language.items()):
        print(f"  {lang:<6} : {cnt}")
    print("-" * 60)
    print("Exemples :")
    for s in samples[:3]:
        snippet = s.raw_text[:70] + ("…" if len(s.raw_text) > 70 else "")
        print(f"  [{s.id}|{s.channel.value}|{s.language}|label={s.label}] {snippet}")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--n-per-class",
        type=int,
        default=120,
        help="Nombre d'échantillons par classe (défaut : 120 -> ~240 lignes).",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Graine de reproductibilité (défaut : 42)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Chemin du CSV de sortie (défaut : {DEFAULT_OUTPUT}).",
    )
    args = parser.parse_args()

    samples = generate_corpus(n_per_class=args.n_per_class, seed=args.seed)
    out_path = export_csv(samples, args.output)
    _print_summary(samples, out_path)


if __name__ == "__main__":
    main()
