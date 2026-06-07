"""Télécharge les datasets publics réels puis assemble le dataset d'entraînement.

Usage (depuis la racine du projet) :

    python -m scripts.download_datasets [--no-download] [--max-synthetic-ratio R]

Comportement :
    1. Tente de télécharger TOUTES les sources du registre (best effort). En
       sandbox / réseau bloqué, les échecs sont logués mais NE plantent PAS.
    2. Assemble ``data/processed/training_dataset.csv`` à partir des fichiers
       présents dans ``data/external/`` (réel d'abord), complété par le corpus
       synthétique camerounais plafonné.
    3. Affiche la composition (réel vs synthétique, classes, canaux, langues).

⚠️ Aucune donnée personnelle réelle n'est collectée. Usage défensif.
"""

from __future__ import annotations

import argparse
from collections import Counter

from src.bloc2_phishing.dataset_downloader import (
    SOURCES,
    build_training_dataset,
    dataset_stats,
    download_all,
)
from src.bloc2_phishing.loader import load_samples
from src.common.config import EXTERNAL_DIR, PROCESSED_DIR
from src.common.logging_conf import get_logger

logger = get_logger(__name__)


def _print_stats(out_path, stats) -> None:
    print("=" * 64)
    print("Dataset d'entraînement — composition")
    print("=" * 64)
    print(f"Fichier        : {out_path}")
    print(f"Total          : {stats['total']} échantillons")
    print(f"Réel           : {stats['real']}")
    print(f"Synthétique    : {stats['synthetic']} "
          f"(ratio {stats['synthetic_ratio']:.1%})")
    print("-" * 64)
    print("Par classe     :")
    for k, v in sorted(stats["by_label"].items()):
        print(f"  {k:<10} : {v}")
    print("Par canal      :")
    for k, v in sorted(stats["by_channel"].items()):
        print(f"  {k:<10} : {v}")
    print("Par langue     :")
    for k, v in sorted(stats["by_language"].items()):
        print(f"  {k:<10} : {v}")
    print("Par source     :")
    for k, v in sorted(stats["by_source"].items()):
        print(f"  {k:<22} : {v}")
    print("=" * 64)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-download", action="store_true",
        help="Ne pas tenter de télécharger ; utiliser uniquement data/external/.")
    parser.add_argument(
        "--max-synthetic-ratio", type=float, default=0.25,
        help="Part maximale de synthétique dans le dataset final (défaut 0.25).")
    parser.add_argument(
        "--seed", type=int, default=42, help="Graine de reproductibilité.")
    parser.add_argument(
        "--timeout", type=int, default=20, help="Timeout réseau (s).")
    args = parser.parse_args()

    if args.no_download:
        logger.info("Mode --no-download : aucun téléchargement tenté.")
    else:
        print(f"Tentative de téléchargement de {len(SOURCES)} source(s) "
              f"vers {EXTERNAL_DIR} (best effort)...")
        results = download_all(dest_dir=EXTERNAL_DIR, timeout=args.timeout)
        for name, path in results.items():
            status = f"OK -> {path.name}" if path else "échec (réseau/sandbox)"
            print(f"  - {name:<24} : {status}")

    out_path = build_training_dataset(
        prefer_real=True,
        max_synthetic_ratio=args.max_synthetic_ratio,
        seed=args.seed,
        out=PROCESSED_DIR / "training_dataset.csv",
        external_dir=EXTERNAL_DIR,
    )

    samples = load_samples(out_path)
    stats = dataset_stats(samples)
    _print_stats(out_path, stats)

    # Garde-fou visible : doublons + plafond synthétique.
    keys = Counter()
    for s in samples:
        import re
        keys[re.sub(r"\s+", " ", (s.raw_text or "").strip().lower())] += 1
    n_dups = sum(c - 1 for c in keys.values() if c > 1)
    print(f"Doublons (raw_text normalisé) : {n_dups}")
    print(f"IDs uniques : {len({s.id for s in samples}) == len(samples)}")
    print(f"Plafond synthétique respecté (<= {args.max_synthetic_ratio:.0%}) : "
          f"{stats['synthetic_ratio'] <= args.max_synthetic_ratio + 1e-9}")


if __name__ == "__main__":
    main()
