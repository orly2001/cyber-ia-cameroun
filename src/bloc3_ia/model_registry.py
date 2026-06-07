"""Versionnage des artefacts de modèle (registre local daté).

Ce module gère un registre simple et portable d'artefacts de modèle sous
``models/registry/<kind>/<YYYYmmdd-HHMMSS>/`` :

* ``model.joblib``  : le pipeline sérialisé (via le ``save`` du détecteur ou
  ``joblib.dump`` direct du pipeline) ;
* ``metrics.json``  : les métriques d'évaluation (test tenu à l'écart) ;
* ``meta.json``     : les métadonnées (taille du dataset, composition, split,
  date, graine, etc.).

L'alias « courant » n'utilise PAS de lien symbolique (compatibilité Windows) :
il est matérialisé par un fichier ``CURRENT.txt`` dans ``models/registry/<kind>/``
qui porte le chemin (relatif au projet) du dossier de version courante.

Les imports lourds (``joblib``) sont PARESSEUX (effectués dans les méthodes).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from src.common.config import MODELS_DIR
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

# Racine du registre des artefacts versionnés.
REGISTRY_DIR = MODELS_DIR / "registry"
# Nom du fichier pointeur tenant lieu d'alias « courant » (pas de symlink).
CURRENT_FILE = "CURRENT.txt"


def _kind_dir(kind: str) -> Path:
    """Renvoie le dossier racine d'un type de modèle (``models/registry/<kind>``)."""
    return REGISTRY_DIR / kind


def _timestamp() -> str:
    """Horodatage de version au format ``YYYYmmdd-HHMMSS`` (tri lexicographique)."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def save_model(
    detector,
    metrics: Dict[str, object],
    meta: Dict[str, object],
    kind: str = "tfidf_rf",
) -> Path:
    """Sauvegarde un artefact de modèle versionné et met à jour l'alias courant.

    Crée ``models/registry/<kind>/<YYYYmmdd-HHMMSS>/`` contenant :
    ``model.joblib`` (via ``detector.save(...)`` si disponible, sinon
    ``joblib.dump`` direct du pipeline ``detector._pipeline``), ``metrics.json``
    et ``meta.json``. Met ensuite à jour ``models/registry/<kind>/CURRENT.txt``.

    Args:
        detector: détecteur entraîné (expose idéalement ``save(path)`` et/ou un
            attribut ``_pipeline``).
        metrics: dictionnaire de métriques d'évaluation (test tenu à l'écart).
        meta: métadonnées (taille dataset, composition, split, date, graine…).
        kind: type de modèle (sous-dossier du registre, défaut ``"tfidf_rf"``).

    Returns:
        Le chemin du dossier de version créé.
    """
    version = _timestamp()
    version_dir = _kind_dir(kind) / version
    version_dir.mkdir(parents=True, exist_ok=True)
    model_path = version_dir / "model.joblib"

    # 1) Sérialisation du modèle : on privilégie le save() du détecteur (qui
    #    sait quoi persister), avec repli sur joblib.dump du pipeline brut.
    saved = False
    save_fn = getattr(detector, "save", None)
    if callable(save_fn):
        try:
            result = save_fn(model_path)
            saved = result is not None
        except Exception as exc:  # détecteur sans pipeline / incompatible
            logger.warning("detector.save() a échoué (%s) ; repli joblib.dump.", exc)

    if not saved:
        pipeline = getattr(detector, "_pipeline", None)
        if pipeline is None:
            logger.warning(
                "Aucun pipeline à sérialiser : artefact model.joblib non écrit."
            )
        else:
            try:
                import joblib  # import paresseux

                joblib.dump(pipeline, model_path)
                saved = True
            except ImportError:
                logger.error("joblib absent : impossible de sérialiser le modèle.")

    # 2) Écriture des métriques et métadonnées (toujours, même sans modèle).
    enriched_meta = dict(meta)
    enriched_meta.setdefault("kind", kind)
    enriched_meta.setdefault("version", version)
    enriched_meta.setdefault("saved_at", datetime.now().isoformat(timespec="seconds"))

    (version_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (version_dir / "meta.json").write_text(
        json.dumps(enriched_meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 3) Mise à jour de l'alias « courant » (fichier pointeur, pas de symlink).
    _set_current(kind, version_dir)

    logger.info("Artefact de modèle versionné sauvegardé : %s", version_dir)
    return version_dir


def _set_current(kind: str, version_dir: Path) -> None:
    """Écrit le pointeur d'alias courant (``CURRENT.txt``) pour un type donné."""
    kind_dir = _kind_dir(kind)
    kind_dir.mkdir(parents=True, exist_ok=True)
    # On stocke un chemin POSIX relatif à la racine projet quand c'est possible
    # (portable Git/Windows), avec repli sur le chemin absolu.
    try:
        rel = version_dir.resolve().relative_to(MODELS_DIR.parent.resolve())
        pointer = rel.as_posix()
    except ValueError:
        pointer = version_dir.resolve().as_posix()
    (kind_dir / CURRENT_FILE).write_text(pointer + "\n", encoding="utf-8")


def load_current(kind: str = "tfidf_rf") -> Optional[Path]:
    """Renvoie le chemin du ``model.joblib`` courant, ou ``None``.

    Lit ``models/registry/<kind>/CURRENT.txt`` et renvoie le chemin du fichier
    ``model.joblib`` du dossier pointé s'il existe réellement.

    Args:
        kind: type de modèle (défaut ``"tfidf_rf"``).

    Returns:
        Le ``Path`` du ``model.joblib`` courant, ou ``None`` si absent/invalide.
    """
    pointer_file = _kind_dir(kind) / CURRENT_FILE
    if not pointer_file.exists():
        return None
    try:
        pointer = pointer_file.read_text(encoding="utf-8").strip()
    except Exception as exc:
        logger.warning("Lecture du pointeur courant impossible (%s).", exc)
        return None
    if not pointer:
        return None

    version_dir = Path(pointer)
    if not version_dir.is_absolute():
        version_dir = MODELS_DIR.parent / version_dir
    model_path = version_dir / "model.joblib"
    if not model_path.exists():
        logger.warning("model.joblib introuvable pour la version courante : %s", model_path)
        return None
    return model_path


def list_versions(kind: str = "tfidf_rf") -> List[Path]:
    """Liste les dossiers de versions d'un type, triés chronologiquement.

    Args:
        kind: type de modèle (défaut ``"tfidf_rf"``).

    Returns:
        Liste de ``Path`` (dossiers de version), du plus ancien au plus récent.
        Liste vide si aucun.
    """
    kind_dir = _kind_dir(kind)
    if not kind_dir.exists():
        return []
    versions = [
        p for p in kind_dir.iterdir() if p.is_dir() and (p / "meta.json").exists()
    ]
    return sorted(versions, key=lambda p: p.name)


def latest_metrics(kind: str = "tfidf_rf") -> Dict[str, object]:
    """Renvoie les métriques de la version courante (ou la plus récente).

    Tente d'abord la version pointée par l'alias courant ; à défaut, la version
    la plus récente listée. Renvoie un dictionnaire vide si rien n'est trouvé.

    Args:
        kind: type de modèle (défaut ``"tfidf_rf"``).

    Returns:
        Le contenu de ``metrics.json``, ou ``{}`` si indisponible.
    """
    # 1) Tenter la version courante (via le model.joblib pointé).
    current_model = load_current(kind)
    candidate_dir: Optional[Path] = None
    if current_model is not None:
        candidate_dir = current_model.parent
    else:
        versions = list_versions(kind)
        if versions:
            candidate_dir = versions[-1]

    if candidate_dir is None:
        return {}

    metrics_file = candidate_dir / "metrics.json"
    if not metrics_file.exists():
        return {}
    try:
        return json.loads(metrics_file.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Lecture de metrics.json impossible (%s).", exc)
        return {}


__all__ = [
    "REGISTRY_DIR",
    "save_model",
    "load_current",
    "list_versions",
    "latest_metrics",
]
