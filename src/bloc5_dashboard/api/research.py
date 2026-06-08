"""Registre de recherches : enregistre les analyses des usagers.

Idee produit : quand un usager analyse un message/URL inconnu, on l'ENREGISTRE
comme « recherche ». Elle devient consultable dans « recherches recentes »,
exportable (CSV / JSON) et partageable.

Ce module reutilise la VRAIE logique d'analyse du bloc 5
(:func:`src.bloc5_dashboard.api.inference._analyze_samples`) afin de produire un
verdict coherent (``is_phishing``, ``score``, ``indicators``, ``model``), puis
persiste le tout via :class:`src.common.database.ResearchORM`.

Robustesse : tout acces base est encapsule ; en cas d'indisponibilite de la
BDD, on journalise et on renvoie une reponse degradee (jamais de 500 brut).
Les imports lourds (detecteur, assistant Gemini) sont PARESSEUX.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from src.bloc5_dashboard.api.security import require_api_key
from src.common.database import ResearchORM, SessionLocal, init_db
from src.common.logging_conf import get_logger
from src.common.schemas import Channel, Research

logger = get_logger(__name__)
router = APIRouter(prefix="/api/research", tags=["research"])


# --------------------------------------------------------------------------- #
# Schemas d'entree propres au registre de recherches.
# --------------------------------------------------------------------------- #
class ResearchCreate(BaseModel):
    """Corps de requete pour enregistrer une recherche usager."""

    query: str = Field(..., min_length=1, description="Texte/URL a analyser")
    channel: Channel = Field(Channel.SMS, description="Canal : SMS | EMAIL | URL")


# --------------------------------------------------------------------------- #
# Helpers internes.
# --------------------------------------------------------------------------- #
def _normalize(query: str) -> str:
    """Normalise une requete pour la deduplication (espaces + casse)."""
    return " ".join((query or "").strip().lower().split())


def _stable_id(query: str, channel: str) -> str:
    """Calcule un identifiant stable (hash) a partir de la requete normalisee.

    Deux requetes identiques (apres normalisation) et de meme canal partagent le
    meme id : c'est la cle de deduplication.
    """
    digest = hashlib.sha1(f"{_normalize(query)}|{channel}".encode("utf-8")).hexdigest()
    return f"rs-{digest[:16]}"


def _orm_to_model(row: ResearchORM) -> Research:
    """Convertit une ligne ``ResearchORM`` en modele Pydantic ``Research``."""
    return Research(
        id=row.id,
        query=row.query,
        channel=Channel(row.channel) if row.channel else Channel.SMS,
        is_phishing=row.is_phishing,
        score=row.score,
        indicators=row.indicators or [],
        summary=row.summary or "",
        model=row.model or "tfidf_rf",
        source=row.source or "user",
        shared=bool(row.shared),
        created_at=row.created_at,
    )


def _analyze_query(query: str, channel: Channel) -> dict:
    """Analyse une requete en reutilisant la VRAIE logique d'inference.

    Construit un :class:`PhishingSample` et appelle ``_analyze_samples`` (import
    paresseux). En cas d'echec (modele indisponible, etc.), renvoie un repli
    neutre afin de ne jamais bloquer l'enregistrement de la recherche.

    Returns:
        Dictionnaire ``{is_phishing, score, indicators, model}``.
    """
    try:
        from src.bloc5_dashboard.api.inference import _analyze_samples
        from src.common.schemas import PhishingSample

        sample = PhishingSample(
            id="research-1",
            channel=channel,
            raw_text=query,
            language="fr",
        )
        results = _analyze_samples([sample])
        if results:
            r = results[0]
            return {
                "is_phishing": bool(r.is_phishing),
                "score": float(r.score),
                "indicators": list(r.indicators),
                "model": r.model,
            }
    except Exception as exc:  # noqa: BLE001 — analyse best-effort
        logger.warning("Analyse de la recherche impossible (%s) : repli neutre.", exc)
    return {"is_phishing": None, "score": None, "indicators": [], "model": "tfidf_rf"}


def _build_summary(query: str, analysis: dict) -> str:
    """Produit un resume en langage naturel (assistant IA si dispo, sinon regle).

    Tente d'appeler ``src.bloc3_ia.gemini_assistant.summarize`` via un import
    paresseux protege. En cas d'absence/echec, on construit un resume de repli
    base sur le verdict heuristique.
    """
    try:
        from src.bloc3_ia.gemini_assistant import summarize  # import paresseux

        text = summarize(query)
        if text:
            return str(text).strip()
    except Exception as exc:  # noqa: BLE001 — assistant optionnel
        logger.debug("Resume Gemini indisponible (%s) : repli regle.", exc)

    is_ph = analysis.get("is_phishing")
    indicators = analysis.get("indicators") or []
    if is_ph is True:
        base = "Verdict : message a RISQUE (phishing probable)."
    elif is_ph is False:
        base = "Verdict : message a priori legitime."
    else:
        base = "Verdict indisponible (analyse non concluante)."
    if indicators:
        base += " Indicateurs detectes : " + ", ".join(indicators) + "."
    return base


def _ensure_tables() -> None:
    """Garantit l'existence des tables (idempotent, tolerant a l'echec)."""
    try:
        init_db()
    except Exception as exc:  # noqa: BLE001
        logger.debug("init_db a echoue (%s).", exc)


# --------------------------------------------------------------------------- #
# Endpoints.
# --------------------------------------------------------------------------- #
@router.get("", response_model=List[Research])
def list_research(
    limit: int = Query(50, ge=1, le=500, description="Nombre max de recherches"),
    shared: Optional[bool] = Query(
        None, description="Si true, ne renvoie que les recherches partagees"
    ),
):
    """Liste paginee des recherches recentes (created_at decroissant).

    Filtre optionnel ``shared=true`` pour ne renvoyer que les recherches
    partagees. En cas d'indisponibilite de la BDD : liste vide (jamais 500).
    """
    _ensure_tables()
    try:
        with SessionLocal() as db:
            stmt = select(ResearchORM).order_by(ResearchORM.created_at.desc())
            if shared is True:
                stmt = stmt.where(ResearchORM.shared.is_(True))
            stmt = stmt.limit(limit)
            rows = db.execute(stmt).scalars().all()
            return [_orm_to_model(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.error("Lecture des recherches impossible (%s).", exc)
        return []


@router.post("", response_model=Research, dependencies=[Depends(require_api_key)])
def create_research(req: ResearchCreate) -> Research:
    """Analyse une requete usager et l'enregistre comme recherche recente.

    Etapes : analyse (logique reelle d'inference) -> DEDUPLICATION (si une
    recherche avec la meme query normalisee + canal existe, on renvoie
    l'existante) -> sinon creation (id stable), resume (Gemini ou repli),
    persistance via ``ResearchORM``.
    """
    _ensure_tables()
    rid = _stable_id(req.query, req.channel.value)

    # Deduplication : si la recherche existe deja, on la renvoie telle quelle.
    try:
        with SessionLocal() as db:
            existing = db.get(ResearchORM, rid)
            if existing is not None:
                return _orm_to_model(existing)
    except Exception as exc:  # noqa: BLE001
        logger.error("Acces BDD impossible (deduplication) (%s).", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base de donnees indisponible, reessayez plus tard.",
        )

    analysis = _analyze_query(req.query, req.channel)
    summary = _build_summary(req.query, analysis)

    try:
        with SessionLocal() as db:
            # Re-verifier l'existence (concurrence) avant insertion.
            existing = db.get(ResearchORM, rid)
            if existing is not None:
                return _orm_to_model(existing)
            row = ResearchORM(
                id=rid,
                query=req.query,
                channel=req.channel.value,
                is_phishing=analysis["is_phishing"],
                score=analysis["score"],
                indicators=analysis["indicators"],
                summary=summary,
                model=analysis["model"],
                source="user",
                shared=False,
                created_at=datetime.now(timezone.utc),
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            return _orm_to_model(row)
    except Exception as exc:  # noqa: BLE001
        logger.error("Persistance de la recherche impossible (%s).", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enregistrement impossible, base de donnees indisponible.",
        )


@router.get("/export")
def export_research(
    fmt: str = Query("json", pattern="^(json|csv)$", description="json | csv"),
    shared: Optional[bool] = Query(
        None, description="Si true, n'exporte que les recherches partagees"
    ),
):
    """Exporte les recherches en CSV ou JSON (telechargement).

    En-tetes ``Content-Type`` et ``Content-Disposition`` adaptes au format pour
    declencher un telechargement cote navigateur. ``shared=true`` restreint
    l'export aux recherches partagees.
    """
    _ensure_tables()
    try:
        with SessionLocal() as db:
            stmt = select(ResearchORM).order_by(ResearchORM.created_at.desc())
            if shared is True:
                stmt = stmt.where(ResearchORM.shared.is_(True))
            rows = db.execute(stmt).scalars().all()
            data = [_orm_to_model(r).model_dump(mode="json") for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.error("Export impossible (BDD indisponible) (%s).", exc)
        data = []

    if fmt == "json":
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        return StreamingResponse(
            iter([payload]),
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=recherches.json"
            },
        )

    # CSV : en-tete toujours present (au moins une ligne d'en-tetes).
    cols = [
        "id", "query", "channel", "is_phishing", "score",
        "indicators", "summary", "model", "source", "shared", "created_at",
    ]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for item in data:
        record = dict(item)
        # Aplatir la liste d'indicateurs pour le CSV.
        record["indicators"] = "; ".join(record.get("indicators") or [])
        writer.writerow(record)
    return StreamingResponse(
        iter([out.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=recherches.csv"},
    )



@router.get("/stats")
def research_stats():
    """Agregats du registre de recherches pour les graphes du dashboard.

    Retourne le total, le nombre/taux de phishing, la repartition par canal et
    par verdict, le nombre de recherches partagees, et une serie temporelle
    (recherches par jour, 14 derniers jours). Jamais 500 : renvoie des zeros si
    la BDD est indisponible.
    """
    _ensure_tables()
    empty = {
        "total": 0, "n_phishing": 0, "n_legit": 0, "n_unknown": 0,
        "phishing_rate": 0.0, "shared": 0,
        "by_channel": {}, "by_verdict": {}, "by_day": [],
    }
    try:
        with SessionLocal() as db:
            rows = db.execute(select(ResearchORM)).scalars().all()
    except Exception as exc:  # noqa: BLE001
        logger.error("Stats recherches impossibles (%s).", exc)
        return JSONResponse(empty)

    total = len(rows)
    n_ph = sum(1 for r in rows if r.is_phishing is True)
    n_leg = sum(1 for r in rows if r.is_phishing is False)
    n_unk = total - n_ph - n_leg
    by_channel: dict = {}
    by_day: dict = {}
    shared = 0
    for r in rows:
        ch = r.channel or "SMS"
        by_channel[ch] = by_channel.get(ch, 0) + 1
        if r.shared:
            shared += 1
        day = (r.created_at.isoformat()[:10] if r.created_at else "")
        if day:
            by_day[day] = by_day.get(day, 0) + 1
    series = [{"date": d, "count": c} for d, c in sorted(by_day.items())][-14:]
    return JSONResponse({
        "total": total, "n_phishing": n_ph, "n_legit": n_leg, "n_unknown": n_unk,
        "phishing_rate": round(n_ph / total, 4) if total else 0.0,
        "shared": shared,
        "by_channel": by_channel,
        "by_verdict": {"phishing": n_ph, "legitime": n_leg, "inconnu": n_unk},
        "by_day": series,
    })


@router.get("/{rid}", response_model=Research)
def get_research(rid: str) -> Research:
    """Detail d'une recherche (404 si absente)."""
    _ensure_tables()
    try:
        with SessionLocal() as db:
            row = db.get(ResearchORM, rid)
    except Exception as exc:  # noqa: BLE001
        logger.error("Lecture de la recherche %s impossible (%s).", rid, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base de donnees indisponible.",
        )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Recherche introuvable."
        )
    return _orm_to_model(row)


@router.post(
    "/{rid}/share", response_model=Research, dependencies=[Depends(require_api_key)]
)
def share_research(rid: str) -> Research:
    """Marque une recherche comme partagee (``shared=true``).

    Permet de « partager une recherche » : elle apparaitra ensuite dans la liste
    filtree ``GET /api/research?shared=true`` et dans l'export partage.
    """
    _ensure_tables()
    try:
        with SessionLocal() as db:
            row = db.get(ResearchORM, rid)
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Recherche introuvable.",
                )
            row.shared = True
            db.commit()
            db.refresh(row)
            return _orm_to_model(row)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Partage de la recherche %s impossible (%s).", rid, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base de donnees indisponible.",
        )


__all__ = ["router"]
