"""Application FastAPI du bloc 5 — API de lecture/gestion des alertes SOC.

Expose les alertes corrélées (bloc 4) persistées via ``AlertORM`` et fournit
des agrégats pour le dashboard. L'import de ce module ne doit jamais échouer
hors contexte serveur : les dépendances lourdes (pipeline démo) sont importées
paresseusement.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.common.config import settings
from src.common.database import AlertORM, get_session, init_db
from src.common.schemas import Alert, AlertStatus, Severity

from .schemas_api import AlertUpdate, RunDemoResponse, StatsResponse
from .security import require_api_key, enforce_production_security
from .ratelimit import rate_limit_middleware
from .inference import router as inference_router
from .realtime import router as realtime_router


# --------------------------------------------------------------------------- #
# Application & CORS
# --------------------------------------------------------------------------- #
app = FastAPI(
    title="SOC API — IA & Cybersécurité Cameroun",
    description="API de lecture et de gestion des alertes de sécurité (bloc 5).",
    version="1.0.0",
)

_cors_origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
# Securite (audit cyber M4) : jamais de wildcard "*" combine aux credentials.
# Sans origine configuree -> "*" SANS credentials ; sinon liste blanche + creds.
if _cors_origins:
    _allow_origins, _allow_credentials = _cors_origins, True
else:
    _allow_origins, _allow_credentials = ["*"], False
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


app.middleware("http")(rate_limit_middleware)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Ajoute des en-têtes de sécurité basiques à chaque réponse.

    N'interfère pas avec le CORS (géré par ``CORSMiddleware``) : on se contente
    d'enrichir la réponse déjà construite avec des protections standard.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.on_event("startup")
def _on_startup() -> None:
    """Verifie la securite de prod puis initialise la base au demarrage."""
    enforce_production_security()
    init_db()


# Routers métier : inférence (analyse/upload/modèle) et temps réel (logs live).
app.include_router(inference_router)
app.include_router(realtime_router)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _orm_to_alert(row: AlertORM) -> Alert:
    """Convertit une ligne ORM en modèle Pydantic ``Alert``."""
    return Alert(
        id=row.id,
        title=row.title,
        risk_score=row.risk_score,
        severity=Severity(row.severity) if row.severity else Severity.INFO,
        rule_id=row.rule_id,
        vulnerability_ids=row.vulnerability_ids or [],
        phishing_sample_ids=row.phishing_sample_ids or [],
        rationale=row.rationale or "",
        recommended_actions=row.recommended_actions or [],
        status=AlertStatus(row.status) if row.status else AlertStatus.NEW,
        created_at=row.created_at,
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.get("/health", tags=["système"])
def health() -> dict:
    """Sonde de disponibilité."""
    return {"status": "ok"}


@app.get("/api/alerts", response_model=List[Alert], tags=["alertes"])
def list_alerts(
    severity: Optional[Severity] = Query(None, description="Filtrer par sévérité"),
    status: Optional[AlertStatus] = Query(None, description="Filtrer par statut"),
    min_risk: Optional[float] = Query(
        None, ge=0.0, le=100.0, description="Risque minimum (>=)"
    ),
    db: Session = Depends(get_session),
) -> List[Alert]:
    """Retourne la liste des alertes, avec filtres optionnels."""
    stmt = select(AlertORM)
    if severity is not None:
        stmt = stmt.where(AlertORM.severity == severity.value)
    if status is not None:
        stmt = stmt.where(AlertORM.status == status.value)
    if min_risk is not None:
        stmt = stmt.where(AlertORM.risk_score >= min_risk)
    stmt = stmt.order_by(AlertORM.risk_score.desc())
    rows = db.execute(stmt).scalars().all()
    return [_orm_to_alert(r) for r in rows]


@app.get("/api/alerts/{alert_id}", response_model=Alert, tags=["alertes"])
def get_alert(alert_id: str, db: Session = Depends(get_session)) -> Alert:
    """Retourne le détail d'une alerte (404 si absente)."""
    row = db.get(AlertORM, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return _orm_to_alert(row)


@app.patch(
    "/api/alerts/{alert_id}",
    response_model=Alert,
    tags=["alertes"],
    dependencies=[Depends(require_api_key)],
)
def update_alert(
    alert_id: str, payload: AlertUpdate, db: Session = Depends(get_session)
) -> Alert:
    """Met à jour le statut d'une alerte (acquittement, résolution…).

    Endpoint sensible : protégé par clé d'API (voir :func:`require_api_key`).
    """
    row = db.get(AlertORM, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    row.status = payload.status.value
    db.commit()
    db.refresh(row)
    return _orm_to_alert(row)


@app.get("/api/stats", response_model=StatsResponse, tags=["alertes"])
def stats(db: Session = Depends(get_session)) -> StatsResponse:
    """Calcule les agrégats du dashboard (KPI, répartitions, top 5)."""
    total = db.execute(select(func.count(AlertORM.id))).scalar_one() or 0

    by_severity: dict[str, int] = {}
    for sev, count in db.execute(
        select(AlertORM.severity, func.count(AlertORM.id)).group_by(AlertORM.severity)
    ).all():
        by_severity[sev or "INFO"] = count

    by_status: dict[str, int] = {}
    for st, count in db.execute(
        select(AlertORM.status, func.count(AlertORM.id)).group_by(AlertORM.status)
    ).all():
        by_status[st or "NEW"] = count

    average_risk = float(
        db.execute(select(func.avg(AlertORM.risk_score))).scalar() or 0.0
    )

    top_rows = (
        db.execute(select(AlertORM).order_by(AlertORM.risk_score.desc()).limit(5))
        .scalars()
        .all()
    )
    top_alerts = [_orm_to_alert(r) for r in top_rows]

    return StatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        average_risk=round(average_risk, 2),
        top_alerts=top_alerts,
    )


@app.post(
    "/api/run-demo",
    response_model=RunDemoResponse,
    tags=["système"],
    dependencies=[Depends(require_api_key)],
)
def run_demo() -> RunDemoResponse:
    """Lance le pipeline de démonstration (import paresseux).

    Endpoint sensible : protégé par clé d'API (voir :func:`require_api_key`).
    Gère proprement l'absence du module ``src.pipeline`` : l'API reste
    fonctionnelle même si le pipeline n'est pas encore disponible.
    """
    try:
        from src.pipeline import run_demo as _run_demo  # import paresseux
    except ImportError:
        return RunDemoResponse(
            success=False,
            alerts_generated=0,
            message="Pipeline de démonstration indisponible (module src.pipeline absent).",
        )

    try:
        result = _run_demo()
    except Exception as exc:  # noqa: BLE001 — on veut une réponse propre côté API
        return RunDemoResponse(
            success=False,
            alerts_generated=0,
            message=f"Échec du pipeline : {exc}",
        )

    # Le pipeline peut renvoyer un int, une liste d'alertes, ou rien.
    if isinstance(result, int):
        generated = result
    elif hasattr(result, "__len__"):
        generated = len(result)
    else:
        generated = 0

    return RunDemoResponse(
        success=True,
        alerts_generated=generated,
        message=f"Pipeline exécuté : {generated} alerte(s) générée(s).",
    )
