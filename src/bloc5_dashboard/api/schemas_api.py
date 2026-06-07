"""Modèles Pydantic propres à l'API du bloc 5.

Ces schémas complètent les contrats partagés (``src.common.schemas``) avec
les structures de requête/réponse spécifiques au dashboard SOC.
"""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field

from src.common.schemas import Alert, AlertStatus


class AlertUpdate(BaseModel):
    """Corps de requête pour mettre à jour le statut d'une alerte (PATCH)."""

    status: AlertStatus = Field(
        ..., description="Nouveau statut : ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE"
    )


class StatsResponse(BaseModel):
    """Agrégats destinés aux cartes KPI et graphiques du dashboard."""

    total: int = Field(0, description="Nombre total d'alertes")
    by_severity: Dict[str, int] = Field(
        default_factory=dict, description="Répartition par sévérité"
    )
    by_status: Dict[str, int] = Field(
        default_factory=dict, description="Répartition par statut"
    )
    average_risk: float = Field(0.0, description="Risque moyen (0-100)")
    top_alerts: List[Alert] = Field(
        default_factory=list, description="Top 5 alertes par risk_score décroissant"
    )


class RunDemoResponse(BaseModel):
    """Réponse du déclenchement du pipeline de démonstration."""

    success: bool = Field(..., description="True si le pipeline a pu s'exécuter")
    alerts_generated: int = Field(0, description="Nombre d'alertes générées")
    message: str = Field("", description="Détail lisible (erreur ou confirmation)")


__all__ = ["AlertUpdate", "StatsResponse", "RunDemoResponse"]
