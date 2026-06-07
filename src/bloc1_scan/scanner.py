"""Orchestrateur du Bloc 1 — Scan de vulnérabilités.

Combine la découverte réseau (nmap), le scan web (OWASP ZAP) et
l'enrichissement CVE (NVD), puis mappe le tout vers le contrat partagé
:class:`src.common.schemas.Vulnerability`.

⚠️ AVERTISSEMENT ÉTHIQUE & LÉGAL
    Les scans actifs (nmap, ZAP) ne doivent viser QUE des cibles pour lesquelles
    vous disposez d'une autorisation écrite. En l'absence d'autorisation,
    utilisez exclusivement ``demo=True``.

Mode démo (``demo=True``) :
    Aucun appel réseau ni outil externe ; renvoie un échantillon réaliste afin
    que le pipeline complet (blocs 2 à 5) puisse être testé hors-ligne.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from src.bloc1_scan.cve_enrichment import enrich_with_nvd
from src.bloc1_scan.nmap_scanner import NmapScanner
from src.bloc1_scan.sample_data import demo_vulnerabilities
from src.bloc1_scan.zap_scanner import ZapScanner
from src.common.logging_conf import get_logger
from src.common.schemas import Vulnerability

logger = get_logger(__name__)

# Mapping qualitatif ZAP -> score CVSS approximatif (faute de métrique exacte).
_ZAP_RISK_TO_SCORE: Dict[str, float] = {
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "informational": 0.0,
    "info": 0.0,
}


def run_scan(targets: List[str], demo: bool = False) -> List[Vulnerability]:
    """Lance le scan de vulnérabilités sur une liste de cibles.

    Args:
        targets: liste d'IP/hôtes (nmap) ou d'URL (ZAP). Une URL (``http(s)://``)
            déclenche un scan web ; sinon un scan réseau.
        demo: si ``True``, n'effectue AUCUN appel réseau et renvoie un
            échantillon codé en dur.

    Returns:
        Liste d'objets :class:`Vulnerability` conformes au schéma partagé.
    """
    if demo:
        logger.info("Mode DÉMO actif : aucun appel réseau, données simulées.")
        return demo_vulnerabilities()

    if not targets:
        logger.warning("Aucune cible fournie ; rien à scanner.")
        return []

    nmap_scanner = NmapScanner()
    zap_scanner = ZapScanner()
    vulnerabilities: List[Vulnerability] = []

    for target in targets:
        if _is_url(target):
            logger.info("Scan web (ZAP) de %s.", target)
            for alert in zap_scanner.scan(target):
                vulnerabilities.append(_zap_alert_to_vuln(alert))
        else:
            logger.info("Scan réseau (nmap) de %s.", target)
            for svc in nmap_scanner.scan(target):
                vulnerabilities.append(_nmap_service_to_vuln(svc))

    logger.info("Scan terminé : %d vulnérabilité(s) au total.", len(vulnerabilities))
    return vulnerabilities


# --------------------------------------------------------------------------- #
# Helpers de mapping
# --------------------------------------------------------------------------- #
def _stable_id(host: str, port: Optional[int], name: str) -> str:
    """Génère un identifiant stable (hash) à partir de host+port+name."""
    raw = f"{host}|{port if port is not None else ''}|{name}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def _is_url(target: str) -> bool:
    """Indique si la cible est une URL web (à confier à ZAP)."""
    return target.lower().startswith(("http://", "https://"))


def _nmap_service_to_vuln(svc: Dict[str, Any]) -> Vulnerability:
    """Convertit un service nmap en :class:`Vulnerability`, enrichi via NVD."""
    host = svc.get("host", "")
    port = svc.get("port")
    service = svc.get("service")
    product = (svc.get("product") or "").strip()
    version = (svc.get("version") or "").strip()

    # Construit un libellé lisible du service détecté.
    descriptor = " ".join(p for p in (product, version) if p).strip()
    name = f"Service exposé : {service or 'inconnu'}"
    if descriptor:
        name = f"{name} ({descriptor})"

    cve_id: Optional[str] = None
    cvss_score = 0.0
    cvss_vector: Optional[str] = None
    description = f"Port {port}/{svc.get('protocol', 'tcp')} ouvert."

    # Enrichissement CVE seulement si l'on dispose d'un produit identifiable.
    if descriptor:
        cves = enrich_with_nvd(descriptor)
        if cves:
            top = cves[0]
            cve_id = top.get("cve_id")
            cvss_score = float(top.get("cvss_score") or 0.0)
            cvss_vector = top.get("cvss_vector")
            description = top.get("description") or description

    return Vulnerability(
        id=_stable_id(host, port, name),
        host=host,
        port=port,
        service=service,
        name=name,
        description=description,
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        source="nmap",
    )


def _zap_alert_to_vuln(alert: Dict[str, Any]) -> Vulnerability:
    """Convertit une alerte ZAP en :class:`Vulnerability`."""
    host = alert.get("host") or ""
    name = alert.get("name") or "Alerte ZAP"
    risk = (alert.get("risk") or "").strip().lower()
    cvss_score = _ZAP_RISK_TO_SCORE.get(risk, 0.0)

    cve_id = alert.get("cveid")
    cvss_vector: Optional[str] = None

    # Si l'alerte référence une CVE, tente d'en récupérer le score réel.
    if cve_id:
        cves = enrich_with_nvd(cve_id)
        if cves:
            top = cves[0]
            cvss_score = float(top.get("cvss_score") or cvss_score)
            cvss_vector = top.get("cvss_vector")

    description = alert.get("description", "")
    if alert.get("solution"):
        description = f"{description}\n\nRemédiation : {alert['solution']}".strip()

    return Vulnerability(
        id=_stable_id(host, None, name),
        host=host,
        port=None,
        service="http",
        name=name,
        description=description,
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        source="zap",
    )
