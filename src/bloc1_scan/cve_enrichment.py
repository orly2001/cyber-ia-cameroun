"""Enrichissement CVE via l'API NVD (NIST National Vulnerability Database).

⚠️ ÉTHIQUE : l'enrichissement n'attaque aucune cible ; il interroge seulement
la base publique NVD. Respectez toutefois les quotas de l'API.

Fonctionnalités :
    - Recherche par CPE ou mot-clé.
    - Respect du rate-limit NVD (délai adapté à la présence d'une clé API).
    - Extraction du score/vecteur CVSS (v3.1, repli v3.0 puis v2) + sévérité.
    - Extraction des CWE et des références (avec tags ``exploit``/``patch``).
    - Cache mémoire simple (évite les requêtes répétées).
    - Mode HORS-LIGNE TOLÉRANT : en l'absence de réseau (ou de ``requests``),
      la fonction journalise et renvoie une liste vide — JAMAIS d'exception.
    - Enrichissement direct d'un objet :class:`Vulnerability`.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from src.common.config import settings
from src.common.logging_conf import get_logger
from src.common.schemas import Vulnerability

logger = get_logger(__name__)

# Cache mémoire : clé de recherche -> résultats déjà calculés.
_CACHE: Dict[str, List[Dict[str, Any]]] = {}

# Verrou + horodatage pour faire respecter le rate-limit NVD entre appels.
_RATE_LOCK = threading.Lock()
_LAST_CALL_AT: float = 0.0

# Délais recommandés par le NVD (en secondes) entre deux requêtes :
#   - avec clé API : ~50 requêtes / 30 s  -> ~0.6 s
#   - sans clé API : ~5 requêtes / 30 s   -> ~6.0 s
_DELAY_WITH_KEY = 0.6
_DELAY_WITHOUT_KEY = 6.0


def _respect_rate_limit() -> None:
    """Patiente si nécessaire pour respecter le rate-limit du NVD.

    Le délai dépend de la présence d'une ``nvd_api_key`` (cf. config). L'appel
    est thread-safe : un seul appelant traverse à la fois.
    """
    global _LAST_CALL_AT
    delay = _DELAY_WITH_KEY if settings.nvd_api_key else _DELAY_WITHOUT_KEY
    with _RATE_LOCK:
        now = time.monotonic()
        wait = (_LAST_CALL_AT + delay) - now
        if wait > 0:
            logger.debug("NVD rate-limit : attente de %.2fs.", wait)
            time.sleep(wait)
        _LAST_CALL_AT = time.monotonic()


def enrich_with_nvd(
    cpe_or_keyword: str,
    *,
    max_results: int = 5,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    """Interroge l'API NVD pour récupérer des CVE liées à un CPE/mot-clé.

    Args:
        cpe_or_keyword: chaîne CPE (``cpe:2.3:...``), identifiant CVE
            (``CVE-2021-41773``) ou mot-clé libre (ex. ``"apache 2.4.49"``).
        max_results: nombre maximal de CVE retournées.
        timeout: délai max (s) de la requête HTTP.

    Returns:
        Liste de dicts ``{cve_id, description, cvss_score, cvss_vector,
        cvss_severity, cwe, references, has_exploit, has_patch}``.
        Liste VIDE en mode hors-ligne ou en cas d'erreur (jamais d'exception).
    """
    key = (cpe_or_keyword or "").strip().lower()
    if not key:
        return []
    if key in _CACHE:
        logger.debug("NVD : cache touché pour '%s'.", key)
        return _CACHE[key]

    try:
        import requests  # import paresseux : dépendance optionnelle / lourde
    except ImportError:
        logger.warning("'requests' indisponible ; enrichissement NVD ignoré.")
        return []

    params = _build_params(cpe_or_keyword, max_results)

    headers: Dict[str, str] = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        _respect_rate_limit()
        response = requests.get(
            settings.nvd_base_url,
            params=params,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # pas de réseau, timeout, quota dépassé, etc.
        logger.warning("NVD injoignable pour '%s' (%s) ; retour vide.", key, exc)
        return []

    try:
        results = _parse_nvd_payload(payload)
    except Exception as exc:  # payload inattendu : on protège l'appelant
        logger.warning("NVD : payload illisible pour '%s' (%s).", key, exc)
        return []

    _CACHE[key] = results
    logger.info("NVD : %d CVE récupérée(s) pour '%s'.", len(results), key)
    return results


def _build_params(cpe_or_keyword: str, max_results: int) -> Dict[str, Any]:
    """Construit les paramètres de requête selon le type d'entrée.

    Args:
        cpe_or_keyword: CPE, identifiant CVE ou mot-clé.
        max_results: nombre maximal de résultats.

    Returns:
        Dictionnaire de paramètres prêt pour l'API NVD 2.0.
    """
    low = cpe_or_keyword.lower().strip()
    if low.startswith("cpe:"):
        return {"cpeName": cpe_or_keyword, "resultsPerPage": max_results}
    if low.startswith("cve-"):
        # Recherche directe d'une CVE précise par son identifiant.
        return {"cveId": cpe_or_keyword.upper(), "resultsPerPage": max_results}
    return {"keywordSearch": cpe_or_keyword, "resultsPerPage": max_results}


def enrich_vulnerability(
    vuln: Vulnerability,
    *,
    timeout: float = 10.0,
) -> Vulnerability:
    """Complète une :class:`Vulnerability` avec les données NVD si possible.

    Renseigne ``cve_id``, ``cvss_score`` et ``cvss_vector`` lorsqu'ils sont
    absents et qu'une CVE correspondante est trouvable (par ``cve_id`` existant
    ou par le ``name`` comme mot-clé). En mode hors-ligne, l'objet est renvoyé
    INCHANGÉ — jamais d'exception.

    Args:
        vuln: vulnérabilité à enrichir (non mutée ; une copie est renvoyée).
        timeout: délai max (s) de la requête HTTP.

    Returns:
        Une nouvelle :class:`Vulnerability` enrichie (ou identique si rien à
        ajouter / mode hors-ligne).
    """
    # Terme de recherche : la CVE déjà connue prime, sinon le libellé.
    query = vuln.cve_id or vuln.name
    if not query:
        return vuln

    cves = enrich_with_nvd(query, max_results=1, timeout=timeout)
    if not cves:
        return vuln

    top = cves[0]
    data = vuln.model_dump()

    if not data.get("cve_id") and top.get("cve_id"):
        data["cve_id"] = top["cve_id"]

    new_score = top.get("cvss_score")
    if (not data.get("cvss_score")) and new_score:
        data["cvss_score"] = float(new_score)

    if (not data.get("cvss_vector")) and top.get("cvss_vector"):
        data["cvss_vector"] = top["cvss_vector"]

    if not data.get("description") and top.get("description"):
        data["description"] = top["description"]

    try:
        return Vulnerability(**data)
    except Exception as exc:  # validation Pydantic : on ne casse jamais l'appelant
        logger.warning("Enrichissement Vulnerability ignoré (%s).", exc)
        return vuln


def _parse_nvd_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extrait les CVE et leurs métriques d'une réponse NVD API 2.0."""
    results: List[Dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score, vector, severity = _extract_cvss(cve.get("metrics", {}) or {})
        references = _extract_references(cve.get("references", []) or [])
        results.append(
            {
                "cve_id": cve_id,
                "description": _extract_description(cve),
                "cvss_score": score,
                "cvss_vector": vector,
                "cvss_severity": severity,
                "cwe": _extract_cwes(cve.get("weaknesses", []) or []),
                "references": references,
                "has_exploit": any(r.get("exploit") for r in references),
                "has_patch": any(r.get("patch") for r in references),
            }
        )
    return results


def _extract_description(cve: Dict[str, Any]) -> str:
    """Renvoie la description anglaise (repli : première disponible)."""
    descriptions = cve.get("descriptions", []) or []
    fallback = ""
    for desc in descriptions:
        text = desc.get("value", "")
        if desc.get("lang") == "en":
            return text
        fallback = fallback or text
    return fallback


def _extract_cvss(
    metrics: Dict[str, Any],
) -> tuple[float, Optional[str], Optional[str]]:
    """Récupère (score, vecteur, sévérité) en privilégiant CVSS v3.1 > v3.0 > v2."""
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {}) or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        # La sévérité figure dans cvssData (v3) ou au niveau de l'entrée (v2).
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if score is not None:
            return float(score), vector, severity
    return 0.0, None, None


def _extract_cwes(weaknesses: List[Dict[str, Any]]) -> List[str]:
    """Extrait la liste des identifiants CWE (ex. ``CWE-79``)."""
    cwes: List[str] = []
    seen: set[str] = set()
    for weakness in weaknesses:
        for desc in weakness.get("description", []) or []:
            value = (desc.get("value") or "").strip()
            if value and value.upper().startswith("CWE-") and value not in seen:
                seen.add(value)
                cwes.append(value)
    return cwes


# Mots-clés signalant respectivement un exploit ou un correctif dans une réf.
_EXPLOIT_TAGS = {"exploit", "third party advisory"}
_PATCH_TAGS = {"patch", "vendor advisory", "release notes", "mitigation"}


def _extract_references(references: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalise les références NVD en taggant exploit/patch.

    Args:
        references: liste brute ``references`` de l'objet CVE NVD.

    Returns:
        Liste de dicts ``{url, tags, exploit, patch}``.
    """
    out: List[Dict[str, Any]] = []
    for ref in references:
        url = ref.get("url")
        if not url:
            continue
        tags = [str(t).lower() for t in (ref.get("tags") or [])]
        tagset = set(tags)
        out.append(
            {
                "url": url,
                "tags": tags,
                "exploit": bool(tagset & _EXPLOIT_TAGS),
                "patch": bool(tagset & _PATCH_TAGS),
            }
        )
    return out


def clear_cache() -> None:
    """Vide le cache mémoire (utile pour les tests)."""
    _CACHE.clear()


__all__ = [
    "enrich_with_nvd",
    "enrich_vulnerability",
    "clear_cache",
]
