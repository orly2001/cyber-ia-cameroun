"""Assistant IA reel base sur Google Gemini (API REST).

Ce module encapsule les appels a l'API Gemini (``generateContent``) pour
fournir des explications en langage naturel et des resumes adaptes au
contexte camerounais (phishing, Mobile Money, cybersecurite).

Principes de robustesse :
    * ``requests`` est importe PARESSEUSEMENT (l'absence de la lib ne casse
      jamais l'import du module ni l'API).
    * Aucune exception n'est propagee vers l'appelant : en cas d'erreur
      (cle absente, panne reseau, timeout, reponse malformee), les fonctions
      renvoient ``None`` et l'API peut alors degrader proprement vers le repli
      base sur des regles.
    * Aucune cle d'API n'est ecrite en dur ; la cle provient de la config
      (variable d'environnement ``GEMINI_API_KEY``).
"""
from __future__ import annotations

from typing import List, Optional

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

def _redact(msg: object) -> str:
    """Masque la cle d'API Gemini dans un message (ex. exception contenant l'URL)."""
    text = str(msg)
    key = (settings.gemini_api_key or "").strip()
    if key:
        text = text.replace(key, "***")
    import re as _re
    return _re.sub(r"(key=)[^&\s]+", r"\1***", text)


# Timeout court : l'assistant ne doit jamais bloquer la requete HTTP entrante.
_TIMEOUT_SECONDS = 8.0


def is_available() -> bool:
    """Indique si l'assistant Gemini est configure (cle presente).

    Returns:
        ``True`` si une cle d'API non vide est configuree, ``False`` sinon.
        Ne teste PAS la connectivite reseau (verification a froid, sans I/O).
    """
    return bool(settings.gemini_api_key and settings.gemini_api_key.strip())


def generate(prompt: str) -> Optional[str]:
    """Appelle l'API Gemini ``generateContent`` et renvoie le texte genere.

    Helper generique reutilise par :func:`explain_with_gemini` et
    :func:`summarize`. Effectue un appel REST POST vers
    ``{gemini_base_url}/models/{gemini_model}:generateContent``.

    Args:
        prompt: invite (prompt) textuelle envoyee au modele.

    Returns:
        Le texte de la premiere reponse candidate, ou ``None`` si l'assistant
        est indisponible (cle absente, lib manquante, erreur reseau/HTTP,
        reponse vide ou malformee). Aucune exception n'est propagee.
    """
    if not is_available():
        logger.debug("Gemini indisponible : aucune cle d'API configuree.")
        return None

    if not prompt or not prompt.strip():
        logger.debug("Gemini : prompt vide, appel ignore.")
        return None

    # Import paresseux : evite une dependance dure a 'requests' a l'import.
    try:
        import requests  # noqa: PLC0415  (lazy import volontaire)
    except ImportError:
        logger.warning("Gemini : la librairie 'requests' est absente — repli.")
        return None

    url = (
        f"{settings.gemini_base_url.rstrip('/')}"
        f"/models/{settings.gemini_model}:generateContent"
    )
    params = {"key": settings.gemini_api_key}
    body = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        resp = requests.post(
            url, params=params, json=body, timeout=_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001  (panne reseau/timeout/DNS...)
        logger.warning("Gemini : echec de l'appel reseau (%s) — repli.", _redact(exc))
        return None

    # Code HTTP non 2xx => on degrade sans lever d'exception.
    try:
        if resp.status_code != 200:
            logger.warning(
                "Gemini : reponse HTTP %s — repli.", resp.status_code
            )
            return None
        data = resp.json()
    except Exception as exc:  # noqa: BLE001  (JSON invalide...)
        logger.warning("Gemini : reponse illisible (%s) — repli.", _redact(exc))
        return None

    # Parsing defensif : candidates[0].content.parts[0].text
    try:
        candidates = data.get("candidates") or []
        if not candidates:
            logger.info("Gemini : aucune candidate dans la reponse — repli.")
            return None
        parts = (candidates[0].get("content") or {}).get("parts") or []
        if not parts:
            logger.info("Gemini : reponse sans 'parts' — repli.")
            return None
        text = parts[0].get("text")
        if not text or not text.strip():
            logger.info("Gemini : texte vide — repli.")
            return None
        return text.strip()
    except Exception as exc:  # noqa: BLE001  (structure inattendue)
        logger.warning("Gemini : parsing impossible (%s) — repli.", _redact(exc))
        return None


def _split_advice(raw: str) -> List[str]:
    """Decoupe un bloc texte en une liste de conseils nettoyes.

    Args:
        raw: texte brut pouvant contenir des conseils sur plusieurs lignes
            (puces ``-``/``*``/``•`` ou numerotation ``1.``).

    Returns:
        Liste de conseils non vides (au plus 3).
    """
    advice: List[str] = []
    for line in raw.splitlines():
        cleaned = line.strip().lstrip("-*•0123456789.) ").strip()
        if cleaned:
            advice.append(cleaned)
    return advice[:3]


def explain_with_gemini(
    text: str,
    is_phishing: Optional[bool],
    score: Optional[float],
    indicators: List[str],
) -> Optional[dict]:
    """Genere une explication en langage naturel d'un verdict de detection.

    Construit un prompt FR adapte au contexte (detection de phishing /
    cybersecurite au Cameroun, Mobile Money) demandant une explication courte
    suivie de 2 a 3 conseils pratiques.

    Args:
        text: message ou alerte a expliquer.
        is_phishing: verdict booleen du detecteur (peut etre ``None``).
        score: score de confiance (0..1), facultatif.
        indicators: liste d'indices ayant motive le verdict.

    Returns:
        Dictionnaire ``{"explanation": str, "advice": [str, ...]}`` ou ``None``
        si Gemini est indisponible / en erreur (repli gere par l'appelant).
    """
    if not is_available():
        return None

    verdict = (
        "probablement frauduleux (phishing)"
        if is_phishing
        else "probablement legitime"
    )
    score_txt = (
        f"{score:.0%}" if isinstance(score, (int, float)) else "non communique"
    )
    indices_txt = ", ".join(indicators) if indicators else "aucun indice fort"

    prompt = (
        "Tu es un assistant de cybersecurite pour le Cameroun, specialise dans "
        "la detection d'arnaques par SMS/email et de fraudes au Mobile Money "
        "(MTN MoMo, Orange Money).\n"
        f"Message analyse : \"{text}\"\n"
        f"Verdict du detecteur : {verdict}.\n"
        f"Niveau de confiance : {score_txt}.\n"
        f"Indices detectes : {indices_txt}.\n\n"
        "Reponds en francais simple. D'abord une explication courte (1 a 2 "
        "phrases) de pourquoi ce message est juge ainsi. Ensuite, sur une ligne "
        "par conseil, donne 2 a 3 conseils concrets prefixes par un tiret '-'. "
        "Sois bref et concret."
    )

    out = generate(prompt)
    if out is None:
        return None

    # Separation explication / conseils : la 1re ligne(s) non-puce = explication,
    # les lignes en puces = conseils.
    explanation_lines: List[str] = []
    advice_lines: List[str] = []
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        is_bullet = stripped[0] in "-*•" or stripped[:2].rstrip(".)").isdigit()
        if is_bullet:
            advice_lines.append(stripped)
        elif advice_lines:
            # Texte apres le debut des conseils => rattache au dernier conseil.
            advice_lines.append(stripped)
        else:
            explanation_lines.append(stripped)

    explanation = " ".join(explanation_lines).strip()
    advice = _split_advice("\n".join(advice_lines)) if advice_lines else []

    # Garde-fous : on garantit un contenu exploitable.
    if not explanation:
        explanation = out.strip()
    if not advice:
        advice = ["Restez vigilant et verifiez via un canal officiel."]

    return {"explanation": explanation, "advice": advice}


def summarize(text: str, max_words: int = 60) -> Optional[str]:
    """Resume / explique brievement un texte en langage naturel.

    Reutilisable par le registre de recherches (resume d'une recherche, d'une
    vulnerabilite, etc.).

    Args:
        text: texte a resumer.
        max_words: longueur cible maximale du resume (en mots).

    Returns:
        Le resume genere par Gemini, ou ``None`` si indisponible / en erreur.
    """
    if not is_available():
        return None
    if not text or not text.strip():
        return None

    prompt = (
        "Resume le texte suivant en francais simple, en au plus "
        f"{max_words} mots, dans le contexte de la cybersecurite au Cameroun. "
        "Va a l'essentiel, sans introduction.\n\n"
        f"Texte : {text}"
    )
    return generate(prompt)


__all__ = ["is_available", "generate", "explain_with_gemini", "summarize"]
