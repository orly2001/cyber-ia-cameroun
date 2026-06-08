"""Assistant IA (Google Gemini) : explications en langage naturel.

Degrade proprement : si le module Gemini ou la cle est absent, renvoie une
explication basee sur des regles (jamais d'erreur 500).
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.common.logging_conf import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/assistant", tags=["assistant"])


class ExplainRequest(BaseModel):
    text: str = Field(..., description="Message/alerte a expliquer")
    is_phishing: Optional[bool] = None
    score: Optional[float] = None
    indicators: List[str] = Field(default_factory=list)


class ExplainResponse(BaseModel):
    explanation: str
    advice: List[str]
    powered_by: str


def _fallback(req: ExplainRequest) -> ExplainResponse:
    verdict = "probablement frauduleux" if req.is_phishing else "probablement legitime"
    adv = [
        "Ne cliquez sur aucun lien et ne communiquez jamais votre code PIN.",
        "Verifiez l'expediteur via un canal officiel (agence, *126#...).",
    ] if req.is_phishing else ["Aucune action requise ; restez vigilant."]
    expl = f"Ce message est {verdict}. Indices : {', '.join(req.indicators) or 'aucun indice fort'}."
    return ExplainResponse(explanation=expl, advice=adv, powered_by="regles")


@router.post("/explain", response_model=ExplainResponse)
def explain(req: ExplainRequest) -> ExplainResponse:
    """Explique un verdict. Utilise Gemini si configure, sinon repli regles."""
    try:
        from src.bloc3_ia.gemini_assistant import explain_with_gemini
        out = explain_with_gemini(req.text, req.is_phishing, req.score, req.indicators)
        if out:
            return ExplainResponse(**out, powered_by="gemini")
    except Exception as exc:  # noqa: BLE001
        logger.info("Assistant Gemini indisponible (%s) — repli regles.", exc)
    return _fallback(req)


class SummaryRequest(BaseModel):
    text: str = Field(..., description="Texte/recherche a resumer")
    max_words: int = Field(60, ge=10, le=300, description="Longueur cible (mots)")


class SummaryResponse(BaseModel):
    summary: str
    powered_by: str


def _summary_fallback(req: SummaryRequest) -> SummaryResponse:
    """Resume de repli (troncature simple) si Gemini est indisponible."""
    words = req.text.split()
    if len(words) <= req.max_words:
        summary = req.text.strip()
    else:
        summary = " ".join(words[: req.max_words]).rstrip(".,;") + "..."
    return SummaryResponse(summary=summary, powered_by="regles")


@router.post("/summary", response_model=SummaryResponse)
def summary(req: SummaryRequest) -> SummaryResponse:
    """Resume un texte. Utilise Gemini si configure, sinon repli regles."""
    try:
        from src.bloc3_ia.gemini_assistant import summarize
        out = summarize(req.text, req.max_words)
        if out:
            return SummaryResponse(summary=out, powered_by="gemini")
    except Exception as exc:  # noqa: BLE001
        logger.info("Resume Gemini indisponible (%s) — repli regles.", exc)
    return _summary_fallback(req)


__all__ = ["router"]
