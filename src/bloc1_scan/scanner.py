"""Orchestrateur du Bloc 1 — Scan de vulnérabilités.

Combine la découverte réseau (nmap), le scan web (OWASP ZAP) et
l'enrichissement CVE (NVD), puis mappe le tout vers le contrat partagé
:class:`src.common.schemas.Vulnerability`.

⚠️ AVERTISSEMENT ÉTHIQUE & LÉGAL
    Les scans actifs (nmap, ZAP) ne doivent viser QUE des cibles autorisées par
    écrit. Sans autorisation, utilisez exclusivement ``demo=True``.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from src.bloc1_scan.cve_enrichment import enrich_with_nvd
from src.bloc1_scan.nmap_scanner import NmapScanner, is_sensitive_port
from src.bloc1_scan.sample_data import demo_vulnerabilities
from src.bloc1_scan.zap_scanner import ZapScanner
from src.common.logging_conf import get_logger
from src.common.schemas import Severity, Vulnerability

logger = get_logger(__name__)

_ZAP_RISK_TO_SCORE: Dict[str, float] = {
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "informational": 0.0,
    "info": 0.0,
}

_ZAP_RISK_TO_SEVERITY: Dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def run_scan(targets: List[str], demo: bool = False) -> List[Vulnerability]:
    """Lance le scan de vulnérabilités sur une liste de cibles.

    Args:
        targets: IP/hôtes (nmap) ou URL http(s):// (ZAP).
        demo: si ``True``, aucun appel réseau ; échantillon codé en dur.

    Returns:
        Liste de :class:`Vulnerability` conformes au schéma partagé.
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


def _stable_id(host: str, port: Optional[int], name: str) -> str:
    """Génère un identifiant stable (hash) à partir de host+port+name."""
    raw = f"{host}|{port if port is not None else ''}|{name}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def _is_url(target: str) -> bool:
    """Indique si la cible est une URL web (à confier à ZAP)."""
    return target.lower().startswith(("http://", "https://"))


def _nmap_service_to_vuln(svc: Dict[str, Any]) -> Vulnerability:
    """Convertit un service nmap (port ouvert) en :class:`Vulnerability`.

    La sévérité par défaut est INFO ; un port sensible la passe à MEDIUM, et un
    enrichissement NVD peut la relever via le ``cvss_score`` (schéma).
    """
    host = svc.get("host", "")
    port = svc.get("port")
    protocol = svc.get("protocol", "tcp")
    service = svc.get("service")
    product = (svc.get("product") or "").strip()
    version = (svc.get("version") or "").strip()

    descriptor = " ".join(p for p in (service or "", product, version) if p).strip()
    name = f"Port {port}/{protocol} ouvert"
    if descriptor:
        name = f"{name} ({descriptor})"

    severity = Severity.INFO
    sensitive = is_sensitive_port(port)
    if sensitive:
        severity = Severity.MEDIUM
        description = (
            f"Port {port}/{protocol} ouvert — service sensible : {sensitive}. "
            "Vérifiez l'exposition, l'authentification et restreignez l'accès."
        )
    else:
        description = f"Port {port}/{protocol} ouvert."

    cve_id: Optional[str] = None
    cvss_score = 0.0
    cvss_vector: Optional[str] = None

    product_descriptor = " ".join(p for p in (product, version) if p).strip()
    if product_descriptor:
        cves = enrich_with_nvd(product_descriptor)
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
        severity=severity,
        source="nmap",
    )


def _zap_alert_to_vuln(alert: Dict[str, Any]) -> Vulnerability:
    """Convertit une alerte ZAP normalisée en :class:`Vulnerability`.

    - ``host`` extrait de l'URL ; ``service`` = https si URL HTTPS sinon http.
    - ``cvss_score`` via enrichissement CVE si CVE citée, sinon approximé du risque.
    - ``severity`` dérivée du risque ZAP (raffinée par le schéma si cvss > 0).
    - ``source`` = "zap" ; ``id`` = hash stable host+name.
    """
    host = alert.get("host") or ""
    name = alert.get("name") or "Alerte ZAP"
    risk = (alert.get("risk") or "").strip().lower()
    cvss_score = _ZAP_RISK_TO_SCORE.get(risk, 0.0)
    severity = _ZAP_RISK_TO_SEVERITY.get(risk, Severity.INFO)

    cve_id = alert.get("cveid")
    cvss_vector: Optional[str] = None

    if cve_id:
        cves = enrich_with_nvd(cve_id)
        if cves:
            top = cves[0]
            cvss_score = float(top.get("cvss_score") or cvss_score)
            cvss_vector = top.get("cvss_vector")

    service = _service_from_url(alert.get("url") or "")

    parts: List[str] = [alert.get("description") or ""]
    if alert.get("param"):
        parts.append(f"Paramètre concerné : {alert['param']}.")
    if alert.get("method"):
        parts.append(f"Méthode HTTP : {alert['method']}.")
    if alert.get("cweid"):
        parts.append(f"CWE : {alert['cweid']}.")
    if alert.get("solution"):
        parts.append(f"Remédiation : {alert['solution']}")
    if alert.get("reference"):
        parts.append(f"Références : {alert['reference']}")
    description = "\n\n".join(p.strip() for p in parts if p and p.strip())

    return Vulnerability(
        id=_stable_id(host, None, name),
        host=host,
        port=None,
        service=service,
        name=name,
        description=description,
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        source="zap",
    )


def _service_from_url(url: str) -> str:
    """Déduit le service (http / https) à partir d'une URL."""
    return "https" if url.lower().startswith("https://") else "http"


def _build_arg_parser() -> "argparse.ArgumentParser":
    """Construit le parseur d'arguments du scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m src.bloc1_scan.scanner",
        description=(
            "Scanner de vulnérabilités (Bloc 1). Cible http(s):// -> OWASP ZAP ; "
            "sinon nmap. N'utilisez le mode réel que sur des cibles AUTORISÉES."
        ),
    )
    parser.add_argument("--target", required=True,
                        help="IP / hôte / URL à scanner (ex. http://localhost:8080).")
    parser.add_argument("--demo", action="store_true",
                        help="Mode démo : aucun appel réseau, données simulées.")
    parser.add_argument("--output", "-o", default=None,
                        help="Chemin d'un fichier JSON où écrire les vulnérabilités.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Point d'entrée CLI : scanne ``--target`` et affiche/écrit le résultat."""
    import json

    args = _build_arg_parser().parse_args(argv)
    vulns = run_scan([args.target], demo=args.demo)
    payload = [v.model_dump(mode="json") for v in vulns]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        logger.info("%d vulnérabilité(s) écrite(s) dans %s.", len(payload), args.output)
        print(f"{len(payload)} vulnérabilité(s) écrite(s) dans {args.output}")
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main())
