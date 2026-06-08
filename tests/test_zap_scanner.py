"""Tests du scanner OWASP ZAP (Bloc 1) avec un client ZAP MOCKÉ.

Aucun démon ZAP ni réseau n'est requis : on injecte un faux client ``zapv2``
dans ``sys.modules`` pour piloter le flux spider → scan actif → alertes, puis on
vérifie le mapping vers le contrat partagé :class:`Vulnerability`.
"""

from __future__ import annotations

import sys
import types
from unittest import mock

import pytest

from src.bloc1_scan.scanner import _zap_alert_to_vuln, run_scan
from src.bloc1_scan.zap_scanner import ZapScanner
from src.common.schemas import Severity, Vulnerability


# --------------------------------------------------------------------------- #
# Fabrique de faux client ZAP
# --------------------------------------------------------------------------- #
def _make_fake_zap(alerts):
    """Construit un faux client ``ZAPv2`` enregistrant les appels du flux.

    Le spider et le scan actif renvoient successivement « 0 » puis « 100 » pour
    exercer la boucle de polling sans réellement attendre.
    """
    zap = mock.MagicMock(name="ZAPv2")

    zap.urlopen = mock.MagicMock(return_value="OK")

    zap.spider.scan = mock.MagicMock(return_value="1")
    zap.spider.status = mock.MagicMock(side_effect=["0", "100"])

    zap.ascan.scan = mock.MagicMock(return_value="2")
    zap.ascan.status = mock.MagicMock(side_effect=["0", "100"])

    zap.core.alerts = mock.MagicMock(return_value=alerts)
    return zap


def _install_fake_zapv2(monkeypatch, zap):
    """Injecte un module ``zapv2`` factice dont ``ZAPv2`` renvoie ``zap``."""
    fake_module = types.ModuleType("zapv2")
    fake_module.ZAPv2 = mock.MagicMock(return_value=zap)
    monkeypatch.setitem(sys.modules, "zapv2", fake_module)
    return fake_module


SAMPLE_ALERTS = [
    {
        "alert": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://localhost:8080/vulnerabilities/xss_r/?name=test",
        "param": "name",
        "method": "GET",
        "cweid": "79",
        "cveid": "",
        "description": "Un paramètre est renvoyé sans échappement.",
        "solution": "Échapper les sorties.",
        "reference": "https://owasp.org/xss",
    },
    {
        "name": "X-Content-Type-Options Header Missing",
        "risk": "Low",
        "confidence": "High",
        "url": "https://localhost:8443/",
        "param": "",
        "method": "GET",
        "description": "En-tête de sécurité manquant.",
    },
]


# --------------------------------------------------------------------------- #
# Flux ZAP (spider / ascan / alerts)
# --------------------------------------------------------------------------- #
def test_scan_runs_full_flow_and_maps_alerts(monkeypatch):
    """Le scan enchaîne urlopen → spider → ascan → alerts et mappe les alertes."""
    zap = _make_fake_zap(SAMPLE_ALERTS)
    fake_module = _install_fake_zapv2(monkeypatch, zap)

    scanner = ZapScanner(poll_interval=0.0, max_wait=5.0)
    # Évite toute attente réelle dans _open_url / _poll.
    monkeypatch.setattr("src.bloc1_scan.zap_scanner.time.sleep", lambda *_: None)

    results = scanner.scan("http://localhost:8080")

    # Le client a été instancié avec la bonne configuration de proxy.
    assert fake_module.ZAPv2.called
    # Flux complet exercé.
    zap.urlopen.assert_called_once_with("http://localhost:8080")
    zap.spider.scan.assert_called_once_with("http://localhost:8080")
    zap.ascan.scan.assert_called_once_with("http://localhost:8080")
    zap.core.alerts.assert_called_once_with(baseurl="http://localhost:8080")

    assert len(results) == 2
    first = results[0]
    assert first["name"] == "Cross Site Scripting (Reflected)"
    assert first["risk"] == "High"
    assert first["host"] == "localhost"
    assert first["param"] == "name"
    assert first["method"] == "GET"
    assert first["cweid"] == "79"


def test_scan_without_active_scan_skips_ascan(monkeypatch):
    """Avec ``active_scan=False``, le scan actif (ascan) n'est pas lancé."""
    zap = _make_fake_zap(SAMPLE_ALERTS)
    _install_fake_zapv2(monkeypatch, zap)
    monkeypatch.setattr("src.bloc1_scan.zap_scanner.time.sleep", lambda *_: None)

    scanner = ZapScanner(poll_interval=0.0, active_scan=False)
    scanner.scan("http://localhost:8080")

    zap.spider.scan.assert_called_once()
    zap.ascan.scan.assert_not_called()


def test_scan_returns_empty_when_daemon_unreachable(monkeypatch):
    """Si le démon est injoignable (exception), le scan renvoie []."""
    zap = _make_fake_zap(SAMPLE_ALERTS)
    zap.spider.scan = mock.MagicMock(side_effect=RuntimeError("connection refused"))
    _install_fake_zapv2(monkeypatch, zap)
    monkeypatch.setattr("src.bloc1_scan.zap_scanner.time.sleep", lambda *_: None)

    scanner = ZapScanner(poll_interval=0.0)
    assert scanner.scan("http://localhost:8080") == []


# --------------------------------------------------------------------------- #
# Robustesse : zapv2 absent
# --------------------------------------------------------------------------- #
def test_scan_returns_empty_when_zapv2_missing(monkeypatch):
    """Si ``zapv2`` n'est pas importable, le scan journalise et renvoie []."""
    # S'assure qu'aucun zapv2 (réel ou factice) n'est présent.
    monkeypatch.setitem(sys.modules, "zapv2", None)
    scanner = ZapScanner(poll_interval=0.0)
    assert scanner.scan("http://localhost:8080") == []


# --------------------------------------------------------------------------- #
# Mapping vers le contrat partagé Vulnerability
# --------------------------------------------------------------------------- #
def test_alert_maps_to_vulnerability_schema():
    """Une alerte ZAP normalisée produit un Vulnerability conforme au schéma."""
    alert = {
        "host": "localhost",
        "url": "http://localhost:8080/x",
        "name": "SQL Injection",
        "risk": "High",
        "param": "id",
        "method": "POST",
        "cweid": "89",
        "cveid": None,
        "description": "Injection SQL possible.",
        "solution": "Requêtes paramétrées.",
        "reference": "https://owasp.org/sqli",
    }
    vuln = _zap_alert_to_vuln(alert)

    assert isinstance(vuln, Vulnerability)
    assert vuln.host == "localhost"
    assert vuln.service == "http"
    assert vuln.name == "SQL Injection"
    assert vuln.source == "zap"
    assert vuln.severity == Severity.HIGH
    # id stable (hash) non vide et déterministe.
    assert vuln.id and _zap_alert_to_vuln(alert).id == vuln.id
    # Les champs riches sont repris dans la description.
    assert "id" in vuln.description
    assert "POST" in vuln.description


def test_severity_derivation_from_risk():
    """La sévérité est dérivée du risque ZAP (High/Medium/Low/Info)."""
    cases = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFO,
    }
    for risk, expected in cases.items():
        vuln = _zap_alert_to_vuln(
            {"host": "h", "url": "http://h/", "name": f"a-{risk}", "risk": risk}
        )
        assert vuln.severity == expected, risk


def test_https_url_yields_https_service():
    """Une URL HTTPS donne service='https'."""
    vuln = _zap_alert_to_vuln(
        {"host": "h", "url": "https://h/", "name": "tls", "risk": "Low"}
    )
    assert vuln.service == "https"


# --------------------------------------------------------------------------- #
# Intégration run_scan (routage URL -> ZAP)
# --------------------------------------------------------------------------- #
def test_run_scan_routes_url_to_zap(monkeypatch):
    """run_scan(demo=False) route une cible http(s):// vers ZapScanner."""
    fake_alerts = [
        {
            "host": "localhost",
            "url": "http://localhost:8080/",
            "name": "Alerte test",
            "risk": "Medium",
        }
    ]
    monkeypatch.setattr(
        "src.bloc1_scan.scanner.ZapScanner.scan",
        lambda self, target: fake_alerts,
    )
    vulns = run_scan(["http://localhost:8080"], demo=False)
    assert len(vulns) == 1
    assert vulns[0].source == "zap"
    assert vulns[0].severity == Severity.MEDIUM


def test_run_scan_demo_mode_is_offline():
    """Le mode démo renvoie des Vulnerability sans aucun appel réseau."""
    vulns = run_scan(["http://localhost:8080"], demo=True)
    assert vulns and all(isinstance(v, Vulnerability) for v in vulns)
