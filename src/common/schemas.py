"""Contrats de données partagés (Pydantic v2).

⚠️ Ces modèles constituent l'INTERFACE entre les blocs. Ne pas modifier un champ
existant sans accord de l'équipe : tout le pipeline en dépend.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Mapping CVSS v3.1 -> sévérité qualitative."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Channel(str, Enum):
    SMS = "SMS"
    EMAIL = "EMAIL"
    URL = "URL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Vulnerability(BaseModel):
    id: str = Field(..., description="Identifiant unique (uuid ou hash stable)")
    host: str = Field(..., description="IP ou nom d'hôte scanné")
    port: Optional[int] = Field(None, ge=0, le=65535)
    service: Optional[str] = Field(None, description="Service détecté (http, ssh)")
    name: str = Field(..., description="Intitulé de la vulnérabilité")
    description: str = ""
    cve_id: Optional[str] = Field(None, description="Ex. CVE-2024-1234")
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    severity: Severity = Severity.INFO
    source: str = Field("zap", description="zap | nmap | nvd | manual")
    scanned_at: datetime = Field(default_factory=_now)

    @model_validator(mode="after")
    def _derive_severity(self):
        if self.severity == Severity.INFO and (self.cvss_score or 0.0) > 0.0:
            self.severity = Severity.from_cvss(float(self.cvss_score))
        return self


class PhishingSample(BaseModel):
    id: str
    channel: Channel
    raw_text: str = Field(..., description="Contenu brut du message/URL")
    clean_text: Optional[str] = Field(None, description="Texte nettoyé (bloc 2)")
    language: str = Field("fr", description="Code ISO 639-1 (fr, en)")
    label: Optional[int] = Field(
        None, description="Annotation : 1=phishing, 0=légitime, None=non labellisé"
    )
    source: str = Field("manual", description="phishtank | openphish | kaggle | terrain")
    collected_at: datetime = Field(default_factory=_now)


class PhishingPrediction(BaseModel):
    sample_id: str
    is_phishing: bool
    score: float = Field(..., ge=0.0, le=1.0, description="Probabilité de phishing")
    model: str = Field("tfidf_rf", description="tfidf_rf | bert_multilingual")
    predicted_at: datetime = Field(default_factory=_now)


class VulnScore(BaseModel):
    vulnerability_id: str
    ml_score: float = Field(..., ge=0.0, le=1.0, description="Priorité ML normalisée")
    priority: Severity = Severity.MEDIUM
    model: str = Field("rf_vuln", description="rf_vuln | xgboost_vuln")
    scored_at: datetime = Field(default_factory=_now)


class Alert(BaseModel):
    id: str
    title: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Score composite 0-100")
    severity: Severity
    rule_id: Optional[str] = Field(None, description="Règle de corrélation déclenchée")
    vulnerability_ids: List[str] = Field(default_factory=list)
    phishing_sample_ids: List[str] = Field(default_factory=list)
    rationale: str = Field("", description="Explication lisible de l'alerte")
    recommended_actions: List[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = Field(default_factory=_now)


__all__ = [
    "Severity",
    "Channel",
    "AlertStatus",
    "Vulnerability",
    "PhishingSample",
    "PhishingPrediction",
    "VulnScore",
    "Alert",
]
