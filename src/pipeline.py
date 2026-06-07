"""Orchestration end-to-end du système IA & Cybersécurité Cameroun.

Enchaîne les 5 blocs :

    Bloc 1 (scan)      -> Vulnerability[]
    Bloc 3 (scoring)   -> VulnScore[]
    Bloc 2 (phishing)  -> PhishingSample[]  (chargement + prétraitement)
    Bloc 3 (détection) -> PhishingPrediction[]
    Bloc 4 (corrél.)   -> Alert[]  (+ persistance pour le Bloc 5)

Usage :
    python -m src.pipeline --demo      # données d'exemple, sans outils externes
    python -m src.pipeline --targets 127.0.0.1 scanme.nmap.org
"""

from __future__ import annotations

import argparse
from typing import List, Optional

from src.common.logging_conf import get_logger
from src.common.schemas import Alert

logger = get_logger(__name__)


def run_pipeline(
    targets: Optional[List[str]] = None,
    demo: bool = True,
    persist: bool = True,
) -> List[Alert]:
    """Exécute le pipeline complet et retourne les alertes générées.

    Args:
        targets: cibles de scan (ignorées si demo=True).
        demo: mode démonstration (aucun appel réseau, repli heuristique IA).
        persist: si True, persiste les alertes en base pour le dashboard.
    """
    # --- Imports paresseux : permet d'utiliser le module sans toutes les deps ---
    from src.bloc1_scan import run_scan
    from src.bloc2_phishing import load_samples, preprocess
    from src.bloc3_ia import PhishingDetector, VulnScorer
    from src.bloc4_correlation import correlate, persist_alerts

    targets = targets or []

    # 1) Scan de vulnérabilités (Bloc 1)
    logger.info("Bloc 1 — scan de vulnérabilités (demo=%s)…", demo)
    vulnerabilities = run_scan(targets, demo=demo)
    logger.info("  -> %d vulnérabilité(s)", len(vulnerabilities))

    # 2) Scoring ML des vulnérabilités (Bloc 3)
    logger.info("Bloc 3 — scoring des vulnérabilités…")
    vuln_scores = VulnScorer().score(vulnerabilities)
    logger.info("  -> %d score(s)", len(vuln_scores))

    # 3) Chargement + prétraitement du corpus phishing (Bloc 2)
    logger.info("Bloc 2 — collecte & prétraitement phishing…")
    samples = preprocess(load_samples())
    logger.info("  -> %d échantillon(s)", len(samples))

    # 4) Détection phishing (Bloc 3)
    logger.info("Bloc 3 — détection phishing…")
    detector = PhishingDetector()
    try:
        detector.load()  # réutilise un modèle entraîné si disponible
    except Exception:
        logger.info("  (pas de modèle entraîné — repli heuristique)")
    predictions = detector.predict(samples)
    logger.info("  -> %d prédiction(s)", len(predictions))

    # 5) Corrélation & génération d'alertes (Bloc 4)
    logger.info("Bloc 4 — corrélation & alertes…")
    alerts = correlate(vulnerabilities, vuln_scores, samples, predictions)
    logger.info("  -> %d alerte(s)", len(alerts))

    if persist:
        n = persist_alerts(alerts)
        logger.info("Persistance : %d alerte(s) enregistrée(s).", n)

    return alerts


def run_demo() -> List[Alert]:
    """Raccourci appelé par l'API (POST /api/run-demo)."""
    return run_pipeline(demo=True, persist=True)


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pipeline IA & Cybersécurité Cameroun")
    parser.add_argument("--demo", action="store_true", help="Mode démonstration (hors-ligne)")
    parser.add_argument("--targets", nargs="*", default=[], help="Cibles de scan")
    parser.add_argument("--no-persist", action="store_true", help="Ne pas enregistrer en base")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = _parse_args(argv)
    demo = args.demo or not args.targets
    alerts = run_pipeline(targets=args.targets, demo=demo, persist=not args.no_persist)

    print("\n=== ALERTES GÉNÉRÉES ===")
    for a in alerts:
        print(f"[{a.severity.value:8}] {a.risk_score:5.1f} | {a.title}")
        if a.rationale:
            print(f"           {a.rationale}")
    if not alerts:
        print("(aucune alerte)")


if __name__ == "__main__":
    main()
