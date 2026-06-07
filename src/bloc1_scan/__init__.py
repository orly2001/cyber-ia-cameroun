"""Bloc 1 — Scan de vulnérabilités.

Ce paquet orchestre la découverte de vulnérabilités (nmap + OWASP ZAP) et
l'enrichissement CVE via l'API NVD, puis mappe les résultats vers le contrat
partagé :class:`src.common.schemas.Vulnerability`.

⚠️ AVERTISSEMENT ÉTHIQUE & LÉGAL
    N'utilisez ces scanners QUE sur des systèmes dont vous possédez l'autorisation
    écrite explicite. Scanner un hôte tiers sans accord est illégal au Cameroun
    (loi n°2010/012 sur la cybersécurité) comme dans la plupart des juridictions.

Point d'entrée public :
    >>> from src.bloc1_scan import run_scan
    >>> vulns = run_scan(["192.168.1.10"], demo=True)
"""

from __future__ import annotations

from src.bloc1_scan.scanner import run_scan

__all__ = ["run_scan"]
