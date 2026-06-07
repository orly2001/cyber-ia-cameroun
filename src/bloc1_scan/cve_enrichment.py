"""Enrichissement CVE via l'API NVD (NIST National Vulnerability Database).

⚠️ ÉTHIQUE : l'enrichissement n'attaque aucune cible ; il interroge seulement
la base publique NVD. Respectez toutefois les quotas de l'API.

Fonctionnalités :
    - Recherche par CPE ou mot-clé.
    - Extraction du score/vecteur CVSS (v3.1, repli v3.0 puis v2).
    - Cache mémoire simple (évite les requêtes répétées).
    - Mode hors-ligne tolérant : en l'absence de réseau (ou de ``requests``),
      la fonction journalise et renvoie une liste vide.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.common.config import settings
from src.common.logging_conf import get_logger

logger = get_logger(__name__)

# Cache mémoire : clé de recherche -> résultats déjà calculés.
_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def enrich_with_nvd(
    cpe_or_keyword: str,
    *,
    max_results: int = 5,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    """Interroge l'API NVD pour récupérer des CVE liées à un CPE/mot-clé.

    Args:
        cpe_or_keyword: chaîne CPE (``cpe:2.3:...``) ou mot-clé libre
            (ex. ``"apache 2.4.49"``).
        max_results: nombre maximal de CVE retournées.
        timeout: délai max (s) de la requête HTTP.

    Returns:
        Liste de dicts ``{cve_id, description, cvss_score, cvss_vector,
        cvss_severity}``. Liste vide en mode hors-ligne ou en cas d'erreur.
    """
    key = cpe_or_keyword.strip().lower()
    if not key:
        return []
    if key in _CACHE:
        logger.debug("NVD : cache touché pour '%s'.", key)
        return _CACHE[key]

    try:
        import requests  # import paresseux : dépendance optionnelle
    except ImportError:
        logger.warning("'requests' indisponible ; enrichissement NVD ignoré.")
        return []

    # Choix du paramètre : CPE exact vs mot-clé.
    if cpe_or_keyword.lower().startswith("cpe:"):
        params: Dict[str, Any] = {
            "cpeName": cpe_or_keyword,
            "resultsPerPage": max_results,
        }
    else:
        params = {
            "keywordSearch": cpe_or_keyword,
            "resultsPerPage": max_results,
        }

    headers: Dict[str, str] = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
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

    results = _parse_nvd_payload(payload)
    _CACHE[key] = results
    logger.info("NVD : %d CVE récupérée(s) pour '%s'.", len(results), key)
    return results


def _parse_nvd_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extrait les CVE et leur métrique CVSS d'une réponse NVD API 2.0."""
    results: List[Dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score, vector, severity = _extract_cvss(cve.get("metrics", {}) or {})
        results.append(
            {
                "cve_id": cve_id,
                "description": _extract_description(cve),
                "cvss_score": score,
                "cvss_vector": vector,
                "cvss_severity": severity,
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
