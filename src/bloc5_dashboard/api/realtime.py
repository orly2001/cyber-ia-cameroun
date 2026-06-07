"""Router FastAPI — flux d'événements analysés en TEMPS RÉEL (bloc 5).

Expose un :class:`fastapi.APIRouter` (préfixe ``/api``) consommable par le
dashboard pour afficher les verdicts de phishing en direct :

* ``GET /api/stream``        : flux Server-Sent Events (SSE) d'événements analysés ;
* ``GET /api/live/recent``   : buffer mémoire des N derniers événements analysés ;
* ``GET /api/live/stats``    : agrégats temps réel calculés sur le buffer.

Garanties de robustesse :

* l'import du module n'a AUCUN effet de bord (pas de thread, pas de modèle
  chargé) — le router s'importe sans dépendance lourde ;
* le détecteur est chargé paresseusement et partagé entre requêtes ;
* le buffer est un anneau borné, protégé par un verrou simple (thread-safe) ;
* aucune collision de route avec les endpoints existants de ``main.py``
  (``/api/alerts``, ``/api/stats``, ``/api/run-demo``…) ni avec un éventuel
  router d'inférence (``/api/analyze``, ``/api/upload``, ``/api/model``).
"""

from __future__ import annotations

import json
import threading
from collections import deque
from typing import Any, Deque, Dict, Iterator, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from src.common.logging_conf import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["realtime"])

# --------------------------------------------------------------------------- #
# État partagé (buffer en anneau + détecteur paresseux)
# --------------------------------------------------------------------------- #
_BUFFER_MAXLEN = 500
_buffer: Deque[Dict[str, Any]] = deque(maxlen=_BUFFER_MAXLEN)
_buffer_lock = threading.Lock()

_detector_cache: Dict[str, Any] = {}  # cache mono-entrée du détecteur


def _get_detector() -> Any:
    """Retourne un détecteur partagé (chargé paresseusement, une seule fois)."""
    det = _detector_cache.get("detector")
    if det is None:
        from src.bloc3_ia import get_detector

        det = get_detector()
        _detector_cache["detector"] = det
        logger.info("Détecteur temps réel chargé et mis en cache.")
    return det


def _push(event: Dict[str, Any]) -> None:
    """Ajoute un événement analysé au buffer en anneau (thread-safe)."""
    with _buffer_lock:
        _buffer.append(event)


def _snapshot() -> List[Dict[str, Any]]:
    """Retourne une copie immuable du contenu courant du buffer."""
    with _buffer_lock:
        return list(_buffer)


# --------------------------------------------------------------------------- #
# Alimentation du buffer (utilisable par les tests, SANS thread)
# --------------------------------------------------------------------------- #
def prime_buffer(n: int = 5, phishing_rate: float = 0.25, seed: int = 42) -> int:
    """Génère et analyse ``n`` événements pour remplir le buffer (synchrone).

    Aucun thread n'est lancé : la fonction est entièrement synchrone et sert de
    point d'amorçage pour les tests et les démos.

    Args:
        n: nombre d'événements à produire et analyser.
        phishing_rate: taux de phishing du générateur.
        seed: graine de reproductibilité.

    Returns:
        Le nombre d'événements effectivement ajoutés au buffer.
    """
    from src.bloc5_dashboard.log_simulator import EventGenerator, analyze_event

    detector = _get_detector()
    gen = EventGenerator(phishing_rate=phishing_rate, seed=seed)
    added = 0
    for event in gen.stream(n=n, delay=0.0):
        _push(analyze_event(event, detector=detector))
        added += 1
    return added


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
def _sse_iterator(count: int, delay: float, phishing_rate: float, seed: Optional[int]) -> Iterator[bytes]:
    """Générateur SSE : produit, analyse et émet ``count`` événements.

    Chaque message respecte le protocole SSE : ``data: <json>\\n\\n``. Les
    événements sont aussi poussés dans le buffer pour les endpoints de repli.
    """
    from src.bloc5_dashboard.log_simulator import EventGenerator, analyze_event

    detector = _get_detector()
    gen = EventGenerator(phishing_rate=phishing_rate, seed=seed)
    for event in gen.stream(n=count, delay=delay):
        analysed = analyze_event(event, detector=detector)
        _push(analysed)
        payload = json.dumps(analysed, ensure_ascii=False, default=str)
        yield f"data: {payload}\n\n".encode("utf-8")


@router.get("/stream")
def stream(
    count: int = Query(20, ge=1, le=200, description="Nombre d'événements à émettre."),
    delay: float = Query(0.5, ge=0.0, le=5.0, description="Délai (s) entre événements."),
    phishing_rate: float = Query(
        0.25, ge=0.0, le=1.0, description="Taux de phishing simulé."
    ),
    seed: Optional[int] = Query(None, description="Graine de reproductibilité."),
) -> StreamingResponse:
    """Flux Server-Sent Events d'événements analysés en continu.

    Le flux est BORNÉ par ``count`` (max 200) afin d'éviter tout flux infini en
    contexte de test/démo. Chaque ligne ``data:`` contient un événement enrichi
    (``is_phishing``, ``score``, ``model``, ``indicators``).
    """
    generator = _sse_iterator(count=count, delay=delay, phishing_rate=phishing_rate, seed=seed)
    return StreamingResponse(generator, media_type="text/event-stream")


@router.get("/live/recent")
def live_recent(
    limit: int = Query(20, ge=1, le=_BUFFER_MAXLEN, description="Nombre d'événements."),
) -> List[Dict[str, Any]]:
    """Renvoie les ``limit`` derniers événements analysés (repli sans SSE).

    Si le buffer est vide (aucun ``/stream`` ni amorçage), il est amorcé une
    fois de manière synchrone pour fournir une réponse exploitable.
    """
    snapshot = _snapshot()
    if not snapshot:
        prime_buffer(n=min(limit, 10))
        snapshot = _snapshot()
    return snapshot[-limit:]


@router.get("/live/stats")
def live_stats() -> Dict[str, Any]:
    """Agrégats temps réel calculés sur le buffer en mémoire.

    Returns:
        Dictionnaire : ``total`` analysés, ``n_phishing``, ``phishing_rate``
        (taux observé), ``recent_scores`` (10 derniers scores) et
        ``buffer_capacity``.
    """
    snapshot = _snapshot()
    total = len(snapshot)
    n_phishing = sum(1 for e in snapshot if e.get("is_phishing"))
    rate = round(n_phishing / total, 4) if total else 0.0
    recent_scores = [float(e.get("score", 0.0)) for e in snapshot[-10:]]
    return {
        "total": total,
        "n_phishing": n_phishing,
        "phishing_rate": rate,
        "recent_scores": recent_scores,
        "buffer_capacity": _BUFFER_MAXLEN,
    }


__all__ = ["router", "prime_buffer"]
