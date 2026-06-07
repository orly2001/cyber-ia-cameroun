"""Service d'inférence & upload de fichiers — analyse de phishing à la demande.

Ce module expose un :class:`APIRouter` (préfixe ``/api``) permettant à une
entreprise ou un usager d'analyser des messages (SMS / e-mail / URL) avec le
modèle de détection courant (bloc 3), soit :

* à l'unité (``POST /api/analyze``) ;
* en lot via un corps JSON (``POST /api/analyze/batch``) ;
* en lot via l'upload d'un fichier CSV ou TXT (``POST /api/upload``).

Chaque verdict expose ``is_phishing``, un ``score`` ∈ [0, 1], le ``model``
utilisé, le canal, une liste d'``indicators`` (motifs à risque repérés) et le
``clean_text`` normalisé (bloc 2).

Le routeur s'importe SANS modèle entraîné : :func:`src.bloc3_ia.get_detector`
bascule automatiquement sur le repli heuristique. Les imports lourds (détecteur,
pandas) sont PARESSEUX pour garder l'import du module rapide et robuste.

Intégration : le mainteneur inclut ce routeur dans ``main.py`` (voir la fin du
fichier pour les deux lignes exactes). Aucun chemin n'entre en collision avec
les endpoints existants (``/api/alerts``, ``/api/stats``, ``/api/run-demo``,
``/health``).
"""

from __future__ import annotations

import re
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from src.bloc2_phishing.preprocessing import clean_text, preprocess
from src.common.logging_conf import get_logger
from src.common.schemas import Channel, PhishingSample
from src.bloc5_dashboard.api.security import require_api_key

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Limites de sécurité pour l'upload et le batch.
# --------------------------------------------------------------------------- #
#: Taille maximale d'un fichier uploadé (octets) — 2 Mo.
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
#: Nombre maximal de lignes/messages traitées par upload.
MAX_UPLOAD_ROWS = 5000
#: Nombre maximal d'items dans un batch JSON.
MAX_BATCH_ITEMS = 1000

# --------------------------------------------------------------------------- #
# Détection d'indicateurs à risque (heuristique, indépendante du modèle).
# --------------------------------------------------------------------------- #
# URL raccourcie (services courants).
_SHORTENER_RE = re.compile(
    r"\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|cutt\.ly|rb\.gy)\b",
    re.IGNORECASE,
)
# URL générique (http/https/www).
_URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
# Montant en FCFA / XAF.
_MONEY_RE = re.compile(r"\b\d[\d\s.,]*\s*(?:fcfa|f\s*cfa|xaf)\b", re.IGNORECASE)
# TLD / motifs de domaine suspects fréquents dans le phishing local.
_SUSPICIOUS_DOMAIN_RE = re.compile(
    r"(?:\.ml\b|\.tk\b|\.ga\b|\.cf\b|secure-login|account-verify|cm-secure)",
    re.IGNORECASE,
)

# Mots-clés à risque -> libellé lisible de l'indicateur.
_RISK_KEYWORDS = {
    "code pin": "mot-clé:code PIN",
    "pin": "mot-clé:PIN",
    "urgent": "mot-clé:urgent",
    "suspendu": "mot-clé:compte suspendu",
    "suspended": "mot-clé:account suspended",
    "gagne": "mot-clé:gain/loterie",
    "gagnez": "mot-clé:gain/loterie",
    "gagné": "mot-clé:gain/loterie",
    "felicitations": "mot-clé:félicitations",
    "félicitations": "mot-clé:félicitations",
    "verify": "mot-clé:verify",
    "verifier": "mot-clé:vérifier",
    "vérifier": "mot-clé:vérifier",
    "login": "mot-clé:login",
    "connexion": "mot-clé:connexion",
    "confirmez": "mot-clé:confirmez",
    "cliquez": "mot-clé:cliquez",
}


def extract_indicators(text: str) -> List[str]:
    """Détecte les motifs à risque présents dans un texte brut.

    Heuristique purement lexicale (indépendante du modèle) destinée à expliquer
    un verdict : mots-clés sensibles, montants FCFA, URLs raccourcies, domaines
    suspects, présence d'URL.

    Args:
        text: texte brut du message (SMS, e-mail, URL).

    Returns:
        Liste dédoublonnée et ordonnée de libellés d'indicateurs détectés
        (vide si aucun motif n'est repéré).
    """
    if not text:
        return []

    indicators: List[str] = []
    lowered = text.lower()

    for keyword, label in _RISK_KEYWORDS.items():
        if keyword in lowered and label not in indicators:
            indicators.append(label)

    if _MONEY_RE.search(text):
        indicators.append("montant FCFA")
    if _SHORTENER_RE.search(text):
        indicators.append("URL raccourcie")
    if _SUSPICIOUS_DOMAIN_RE.search(text):
        indicators.append("domaine suspect")
    if _URL_RE.search(text):
        indicators.append("URL présente")

    return indicators


# --------------------------------------------------------------------------- #
# Schémas Pydantic de requête / réponse (propres à l'inférence).
# --------------------------------------------------------------------------- #
class AnalyzeRequest(BaseModel):
    """Corps de requête pour l'analyse d'un message unitaire."""

    text: str = Field(..., description="Contenu brut du message à analyser")
    channel: Channel = Field(Channel.SMS, description="Canal : SMS | EMAIL | URL")
    language: str = Field("fr", description="Code langue ISO 639-1 (fr, en)")


class AnalyzeResult(BaseModel):
    """Verdict d'analyse d'un message."""

    is_phishing: bool = Field(..., description="Verdict : True si phishing")
    score: float = Field(..., ge=0.0, le=1.0, description="Probabilité de phishing")
    model: str = Field(..., description="Modèle utilisé (heuristic | tfidf_rf | …)")
    channel: Channel = Field(..., description="Canal analysé")
    indicators: List[str] = Field(
        default_factory=list, description="Motifs à risque détectés"
    )
    clean_text: str = Field("", description="Texte normalisé (bloc 2)")


class BatchItem(BaseModel):
    """Un message d'un lot JSON."""

    text: str = Field(..., description="Contenu brut du message")
    channel: Channel = Field(Channel.SMS, description="Canal : SMS | EMAIL | URL")
    language: str = Field("fr", description="Code langue ISO 639-1")


class BatchRequest(BaseModel):
    """Corps de requête pour l'analyse d'un lot de messages (max 1000)."""

    items: List[BatchItem] = Field(..., description="Messages à analyser")


class BatchSummary(BaseModel):
    """Résumé agrégé d'une analyse en lot."""

    n: int = Field(0, description="Nombre de messages analysés")
    n_phishing: int = Field(0, description="Nombre de verdicts phishing")
    rate: float = Field(0.0, ge=0.0, le=1.0, description="Taux de phishing (0-1)")


class BatchResponse(BaseModel):
    """Réponse d'une analyse en lot (résultats + résumé)."""

    summary: BatchSummary = Field(..., description="Résumé agrégé")
    results: List[AnalyzeResult] = Field(
        default_factory=list, description="Verdict par message"
    )


class UploadResponse(BaseModel):
    """Réponse d'un upload de fichier analysé en lot."""

    filename: str = Field(..., description="Nom du fichier reçu")
    count: int = Field(0, description="Nombre de messages analysés")
    summary: BatchSummary = Field(..., description="Résumé agrégé")
    results: List[AnalyzeResult] = Field(
        default_factory=list, description="Verdict par message"
    )


class ModelInfo(BaseModel):
    """Informations sur le modèle de détection courant."""

    type: str = Field(..., description="Type effectif (heuristic | tfidf_rf | bert)")
    trained: bool = Field(False, description="True si un modèle ML est chargé")
    threshold: float = Field(0.5, description="Seuil de décision phishing")
    metrics: dict = Field(
        default_factory=dict, description="Métriques du registre si disponibles"
    )


# --------------------------------------------------------------------------- #
# Détecteur partagé (chargé paresseusement, mis en cache).
# --------------------------------------------------------------------------- #
_DETECTOR = None  # cache du détecteur courant (import lourd différé)


def _get_detector():
    """Retourne le détecteur courant (chargé une seule fois, import paresseux).

    Returns:
        Une instance exposant ``predict(samples)`` (BERT, TF-IDF ou repli
        heuristique selon ce qui est disponible).
    """
    global _DETECTOR
    if _DETECTOR is None:
        from src.bloc3_ia import get_detector  # import paresseux

        _DETECTOR = get_detector()
        logger.info("Détecteur de phishing initialisé (%s).", type(_DETECTOR).__name__)
    return _DETECTOR


def _analyze_samples(samples: List[PhishingSample]) -> List[AnalyzeResult]:
    """Prétraite, prédit et assemble les verdicts d'une liste d'échantillons.

    Args:
        samples: échantillons à analyser (``clean_text`` est rempli ici).

    Returns:
        Liste de :class:`AnalyzeResult`, alignée sur ``samples``.
    """
    if not samples:
        return []

    preprocess(samples)  # remplit clean_text
    detector = _get_detector()
    predictions = detector.predict(samples)

    # Indexer les prédictions par sample_id pour un appariement robuste.
    by_id = {p.sample_id: p for p in predictions}

    results: List[AnalyzeResult] = []
    for sample in samples:
        pred = by_id.get(sample.id)
        if pred is None:
            # Sécurité : ne devrait pas arriver, repli neutre.
            logger.warning("Prédiction manquante pour l'échantillon %s.", sample.id)
            continue
        results.append(
            AnalyzeResult(
                is_phishing=pred.is_phishing,
                score=pred.score,
                model=pred.model,
                channel=sample.channel,
                indicators=extract_indicators(sample.raw_text),
                clean_text=sample.clean_text or "",
            )
        )
    return results


def _summarize(results: List[AnalyzeResult]) -> BatchSummary:
    """Calcule le résumé agrégé d'une liste de verdicts.

    Args:
        results: verdicts d'analyse.

    Returns:
        Un :class:`BatchSummary` (n, n_phishing, taux).
    """
    n = len(results)
    n_phishing = sum(1 for r in results if r.is_phishing)
    rate = round(n_phishing / n, 4) if n else 0.0
    return BatchSummary(n=n, n_phishing=n_phishing, rate=rate)


# --------------------------------------------------------------------------- #
# Routeur.
# --------------------------------------------------------------------------- #
router = APIRouter(prefix="/api", tags=["inference"])


@router.post("/analyze", response_model=AnalyzeResult)
def analyze(payload: AnalyzeRequest) -> AnalyzeResult:
    """Analyse un message unitaire et renvoie un verdict de phishing.

    Construit un :class:`PhishingSample`, applique le prétraitement (bloc 2),
    prédit via le détecteur courant (bloc 3) et enrichit le verdict d'une liste
    d'indicateurs à risque détectés dans le texte brut.
    """
    text = (payload.text or "").strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le champ 'text' ne doit pas être vide.",
        )

    sample = PhishingSample(
        id="analyze-1",
        channel=payload.channel,
        raw_text=payload.text,
        language=(payload.language or "fr").strip().lower(),
    )
    results = _analyze_samples([sample])
    if not results:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Échec de l'analyse du message.",
        )
    return results[0]


@router.post("/analyze/batch", response_model=BatchResponse)
def analyze_batch(payload: BatchRequest) -> BatchResponse:
    """Analyse un lot de messages fournis en JSON (limite 1000).

    Renvoie un verdict par message ainsi qu'un résumé agrégé (n, n_phishing,
    taux). Renvoie 400 si le lot est vide ou dépasse la limite.
    """
    items = payload.items or []
    if not items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le lot 'items' ne doit pas être vide.",
        )
    if len(items) > MAX_BATCH_ITEMS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Lot trop volumineux ({len(items)} > {MAX_BATCH_ITEMS}).",
        )

    samples = [
        PhishingSample(
            id=f"batch-{i}",
            channel=item.channel,
            raw_text=item.text,
            language=(item.language or "fr").strip().lower(),
        )
        for i, item in enumerate(items)
    ]
    results = _analyze_samples(samples)
    return BatchResponse(summary=_summarize(results), results=results)


@router.post(
    "/upload",
    response_model=UploadResponse,
    dependencies=[Depends(require_api_key)],
)
async def upload(file: UploadFile = File(...)) -> UploadResponse:
    """Analyse en lot un fichier uploadé (.csv ou .txt).

    Deux formats acceptés :

    * **.csv** au format standard ``id,channel,raw_text,language,label,source``
      (seul ``raw_text`` est obligatoire ; les autres colonnes sont optionnelles) ;
    * **.txt** : un message par ligne, canal ``SMS`` par défaut.

    Contrôles : taille max 2 Mo (413 sinon) et 5000 lignes max (400 sinon).
    Renvoie 400 pour un fichier vide, mal formé ou d'extension non gérée.

    Endpoint coûteux : protégé par clé d'API (voir :func:`require_api_key`).
    """
    filename = file.filename or "upload"
    lower_name = filename.lower()
    if not (lower_name.endswith(".csv") or lower_name.endswith(".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Extension non gérée : utilisez un fichier .csv ou .txt.",
        )

    # Lecture BORNEE en flux (audit cyber M3) : on s'arrete des que la limite
    # est depassee, sans jamais charger un fichier geant entierement en RAM.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Fichier trop volumineux (> {MAX_UPLOAD_BYTES} octets).",
            )
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fichier vide.",
        )

    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            content = raw.decode("latin-1")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Encodage de fichier illisible : {exc}",
            )

    if lower_name.endswith(".txt"):
        samples = _samples_from_txt(content)
    else:
        samples = _samples_from_csv(content)

    if not samples:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Aucun message exploitable dans le fichier (vide ou mal formé).",
        )
    if len(samples) > MAX_UPLOAD_ROWS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Trop de lignes ({len(samples)} > {MAX_UPLOAD_ROWS}).",
        )

    results = _analyze_samples(samples)
    return UploadResponse(
        filename=filename,
        count=len(results),
        summary=_summarize(results),
        results=results,
    )


def _samples_from_txt(content: str) -> List[PhishingSample]:
    """Construit des échantillons depuis un .txt (un message par ligne).

    Args:
        content: contenu textuel décodé du fichier.

    Returns:
        Liste de :class:`PhishingSample` (canal SMS par défaut). Les lignes
        vides sont ignorées.
    """
    samples: List[PhishingSample] = []
    idx = 0
    for line in content.splitlines():
        text = line.strip()
        if not text:
            continue
        samples.append(
            PhishingSample(
                id=f"txt-{idx}",
                channel=Channel.SMS,
                raw_text=text,
                language="fr",
            )
        )
        idx += 1
    return samples


def _samples_from_csv(content: str) -> List[PhishingSample]:
    """Construit des échantillons depuis un CSV standard.

    Format attendu : en-têtes incluant au moins ``raw_text``. Les colonnes
    ``id``, ``channel``, ``language``, ``label``, ``source`` sont optionnelles.

    Args:
        content: contenu textuel décodé du fichier CSV.

    Returns:
        Liste de :class:`PhishingSample`. Lève si la colonne ``raw_text`` est
        absente (CSV mal formé).
    """
    import csv
    import io

    reader = csv.DictReader(io.StringIO(content), skipinitialspace=True)
    if reader.fieldnames is None:
        return []
    fields = {(f or "").strip().lower(): f for f in reader.fieldnames}
    if "raw_text" not in fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV mal formé : colonne 'raw_text' obligatoire absente.",
        )

    def _channel(value: Optional[str]) -> Channel:
        try:
            return Channel((value or "SMS").strip().upper())
        except ValueError:
            return Channel.SMS

    samples: List[PhishingSample] = []
    for i, row in enumerate(reader):
        raw_text = (row.get(fields["raw_text"]) or "").strip()
        if not raw_text:
            continue  # ligne sans message exploitable
        sid = (row.get(fields["id"]).strip() if "id" in fields and row.get(fields["id"]) else f"csv-{i}")
        lang = (row.get(fields["language"]) if "language" in fields else None) or "fr"
        samples.append(
            PhishingSample(
                id=sid,
                channel=_channel(row.get(fields["channel"]) if "channel" in fields else None),
                raw_text=raw_text,
                language=str(lang).strip().lower(),
            )
        )
    return samples


@router.get("/model", response_model=ModelInfo)
def model_info() -> ModelInfo:
    """Renvoie les informations sur le modèle de détection courant.

    Indique le type effectif (BERT, TF-IDF ou repli heuristique), s'il est
    entraîné, le seuil de décision et les métriques du registre si disponibles.
    """
    detector = _get_detector()
    trained = bool(getattr(detector, "is_trained", False))

    if type(detector).__name__ == "BertPhishingDetector":
        kind = "bert"
    elif trained:
        kind = "tfidf_rf"
    else:
        kind = "heuristic"

    threshold = float(getattr(detector, "threshold", 0.5))

    metrics: dict = {}
    try:
        from src.bloc3_ia.model_registry import latest_metrics  # import paresseux

        metrics = latest_metrics("tfidf_rf") or {}
    except Exception as exc:  # noqa: BLE001 — registre optionnel
        logger.debug("Métriques du registre indisponibles (%s).", exc)

    return ModelInfo(type=kind, trained=trained, threshold=threshold, metrics=metrics)


__all__ = [
    "router",
    "extract_indicators",
    "AnalyzeRequest",
    "AnalyzeResult",
    "BatchItem",
    "BatchRequest",
    "BatchSummary",
    "BatchResponse",
    "UploadResponse",
    "ModelInfo",
]
