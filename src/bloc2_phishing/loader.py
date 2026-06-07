"""Chargement des échantillons de phishing depuis un CSV vers PhishingSample.

Le CSV par défaut est ``data/samples/phishing_samples_cm.csv`` (colonnes :
``id, channel, raw_text, language, label, source``). ``pandas`` est importé de
manière paresseuse afin que le module reste importable sans la dépendance.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

from src.common.config import SAMPLES_DIR
from src.common.logging_conf import get_logger
from src.common.schemas import Channel, PhishingSample

logger = get_logger(__name__)

# CSV d'exemple livré avec le projet.
DEFAULT_CSV = SAMPLES_DIR / "phishing_samples_cm.csv"


def _parse_label(value) -> Optional[int]:
    """Convertit une cellule de label en ``int`` (1/0) ou ``None`` si vide."""
    import math

    if value is None:
        return None
    # pandas représente les cellules manquantes par NaN (float).
    if isinstance(value, float) and math.isnan(value):
        return None
    text = str(value).strip()
    if text == "" or text.lower() in {"nan", "none", "null"}:
        return None
    try:
        return int(float(text))
    except (TypeError, ValueError):
        logger.warning("Label illisible '%s' ignoré (None).", value)
        return None


def _parse_channel(value) -> Channel:
    """Mappe une chaîne vers :class:`Channel`, repli sur SMS si inconnu."""
    text = str(value).strip().upper()
    try:
        return Channel(text)
    except ValueError:
        logger.warning("Canal inconnu '%s' ; repli sur SMS.", value)
        return Channel.SMS


def load_samples(path: Optional[Union[str, Path]] = None) -> List[PhishingSample]:
    """Charge un CSV de messages et le mappe vers ``list[PhishingSample]``.

    Args:
        path: chemin du CSV. Si ``None``, utilise le CSV d'exemple camerounais
            (``data/samples/phishing_samples_cm.csv``).

    Returns:
        Liste de :class:`PhishingSample` (``clean_text`` vide, à remplir par le
        prétraitement). Liste vide si pandas est absent ou le fichier illisible.
    """
    try:
        import pandas as pd  # import paresseux : dépendance optionnelle
    except ImportError:
        logger.error("pandas n'est pas installé ; impossible de charger le CSV.")
        return []

    csv_path = Path(path) if path is not None else DEFAULT_CSV
    if not csv_path.exists():
        logger.error("Fichier d'échantillons introuvable : %s", csv_path)
        return []

    try:
        # skipinitialspace gère les espaces de remplissage après les virgules
        # (CSV aligné/relu par un linter) ; on nettoie aussi les en-têtes.
        df = pd.read_csv(csv_path, skipinitialspace=True)
        df.columns = [str(c).strip() for c in df.columns]
    except Exception as exc:  # CSV malformé, encodage, etc.
        logger.error("Échec de lecture du CSV %s : %s", csv_path, exc)
        return []

    samples: List[PhishingSample] = []
    for _, row in df.iterrows():
        try:
            sample = PhishingSample(
                id=str(row["id"]).strip(),
                channel=_parse_channel(row.get("channel")),
                raw_text=str(row.get("raw_text", "") or ""),
                clean_text=None,
                language=str(row.get("language", "fr") or "fr").strip().lower(),
                label=_parse_label(row.get("label")),
                source=str(row.get("source", "manual") or "manual").strip(),
            )
        except Exception as exc:  # ligne incomplète / invalide
            logger.warning("Ligne ignorée (%s) : %s", row.to_dict(), exc)
            continue
        samples.append(sample)

    logger.info("%d échantillon(s) chargé(s) depuis %s.", len(samples), csv_path)
    return samples
