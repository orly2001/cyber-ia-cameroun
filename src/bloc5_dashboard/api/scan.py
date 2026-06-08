"""Endpoint de scan reseau/vulnerabilites (bloc 1) declenchable depuis le dashboard.

Expose ``POST /api/scan`` avec un parametre ``engine`` :
    - ``auto`` (defaut) : route selon la cible (URL http -> ZAP, IP/hote -> nmap) ;
    - ``nmap`` : force le scan reseau ;
    - ``zap``  : force le scan web ;
    - ``demo`` : aucun appel reseau, renvoie des vulnerabilites d'exemple reelles.

Securite : protege par :func:`require_api_key`. Les erreurs de scan renvoient
un HTTP 400 propre. Les imports lourds (bloc 1) restent paresseux.
"""

from __future__ import annotations

import time
from typing import List, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.bloc5_dashboard.api.security import require_api_key
from src.common.logging_conf import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api", tags=["scan"])

#: Moteurs de scan acceptes par l'endpoint.
Engine = Literal["auto", "nmap", "zap", "demo"]


class ScanRequest(BaseModel):
    """Parametres d'une requete de scan."""

    target: str = Field(..., description="IP / hote / URL a scanner", min_length=1)
    engine: Engine = Field(
        "auto",
        description="Moteur : auto | nmap | zap | demo (defaut auto).",
    )
    inject: bool = Field(
        False,
        description="Injecter les vulnerabilites dans le moteur d'alertes (dashboard).",
    )
    # Compatibilite ascendante : ancien champ booleen ``demo``.
    demo: bool = Field(False, description="Alias herite : equivaut a engine='demo'.")


class ScanResponse(BaseModel):
    """Resultat d'un scan."""

    target: str
    engine: str
    count: int
    duration_sec: float
    vulnerabilities: List[dict]


def _resolve_engine(req: ScanRequest) -> str:
    """Determine le moteur effectif a partir de la requete.

    Args:
        req: requete de scan.

    Returns:
        Le moteur effectif : ``demo``, ``nmap`` ou ``zap``. ``auto`` est resolu
        selon la cible (URL -> zap, sinon nmap).
    """
    engine = req.engine
    # L'alias herite ``demo=True`` prime pour ne pas casser les anciens appels.
    if req.demo:
        engine = "demo"

    if engine == "demo":
        return "demo"
    if engine in ("nmap", "zap"):
        return engine

    # engine == "auto" : route selon la nature de la cible.
    if req.target.lower().startswith(("http://", "https://")):
        return "zap"
    return "nmap"


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
def scan(req: ScanRequest) -> ScanResponse:
    """Lance un scan (Nmap/ZAP/demo via bloc 1) et renvoie les vulnerabilites.

    Args:
        req: cible, moteur (``auto``/``nmap``/``zap``/``demo``) et option
            d'injection dans le dashboard.

    Returns:
        :class:`ScanResponse` avec ``target``, ``engine`` effectif, ``count``,
        ``duration_sec`` et la liste des vulnerabilites (JSON).

    Raises:
        HTTPException: 400 si le scan echoue ou si la cible est invalide.
    """
    target = (req.target or "").strip()
    if not target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cible vide.")

    engine = _resolve_engine(req)
    started = time.monotonic()

    try:
        if engine == "demo":
            # Import paresseux : aucune infra requise pour la demo live.
            from src.bloc1_scan.sample_data import demo_vulnerabilities

            vulns = demo_vulnerabilities()
        else:
            from src.bloc1_scan import run_scan

            # ``run_scan`` route lui-meme URL->ZAP / hote->nmap ; la cible est
            # deja validee plus haut.
            vulns = run_scan([target], demo=False)
    except Exception as exc:  # noqa: BLE001
        logger.error("Echec scan %s (engine=%s) : %s", target, engine, exc)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Scan impossible : {exc}",
        )

    duration = round(time.monotonic() - started, 3)

    # Injection optionnelle dans le moteur d'alertes (tolerante aux pannes).
    if req.inject and vulns:
        try:
            from src.bloc1_scan.integration import inject_vulnerabilities

            alerts = inject_vulnerabilities(vulns, persist=True)
            logger.info("Scan %s : %d alerte(s) injectee(s).", target, len(alerts))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Injection des vulnerabilites echouee : %s", exc)

    logger.info(
        "Scan %s termine (engine=%s) : %d vuln(s) en %.3fs.",
        target,
        engine,
        len(vulns),
        duration,
    )
    return ScanResponse(
        target=target,
        engine=engine,
        count=len(vulns),
        duration_sec=duration,
        vulnerabilities=[v.model_dump(mode="json") for v in vulns],
    )


__all__ = ["router"]
