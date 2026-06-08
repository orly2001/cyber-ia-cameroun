"""Tests de l'endpoint /api/scan et de l'enrichissement CVE (mode hors-ligne).

⚠️ Base de données : on force une base SQLite locale (``/tmp``) AVANT tout import
applicatif (l'engine SQLAlchemy est construit à l'import de
``src.common.database``), pour éviter les « disk I/O error » sur montage réseau.
"""

from __future__ import annotations

import os

# --- Forcer une base SQLite locale AVANT les imports applicatifs --------------
os.environ.setdefault("SQLITE_FALLBACK", "sqlite:////tmp/s.db")
os.environ["USE_SQLITE_FALLBACK"] = "true"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.bloc5_dashboard.api.main import app  # noqa: E402
from src.common.database import init_db  # noqa: E402
from src.common.schemas import Severity, Vulnerability  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Client de test partagé ; garantit la création des tables."""
    init_db()
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
# /api/scan — mode démo
# --------------------------------------------------------------------------- #
def test_scan_demo_returns_valid_vulnerabilities(client: TestClient) -> None:
    """Le mode démo renvoie des Vulnerability valides sans aucune infra."""
    resp = client.post(
        "/api/scan",
        json={"target": "http://localhost:8080", "engine": "demo"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["engine"] == "demo"
    assert data["target"] == "http://localhost:8080"
    assert data["count"] > 0
    assert data["count"] == len(data["vulnerabilities"])
    assert isinstance(data["duration_sec"], (int, float))

    # Chaque entrée doit être une Vulnerability valide selon le schéma partagé.
    for raw in data["vulnerabilities"]:
        vuln = Vulnerability(**raw)
        assert vuln.id and vuln.host and vuln.name
        assert 0.0 <= vuln.cvss_score <= 10.0


def test_scan_demo_contains_real_cve(client: TestClient) -> None:
    """L'échantillon démo référence de vraies CVE (ex. Apache CVE-2021-41773)."""
    resp = client.post("/api/scan", json={"target": "10.0.0.1", "engine": "demo"})
    assert resp.status_code == 200
    cves = {v.get("cve_id") for v in resp.json()["vulnerabilities"]}
    assert "CVE-2021-41773" in cves
    # Au moins une vuln critique (CVSS >= 9.0) pour une démo crédible.
    scores = [v["cvss_score"] for v in resp.json()["vulnerabilities"]]
    assert max(scores) >= 9.0


def test_scan_legacy_demo_alias(client: TestClient) -> None:
    """L'ancien champ booléen ``demo`` reste compatible (engine forcé à demo)."""
    resp = client.post("/api/scan", json={"target": "10.0.0.1", "demo": True})
    assert resp.status_code == 200
    assert resp.json()["engine"] == "demo"
    assert resp.json()["count"] > 0


def test_scan_rejects_empty_target(client: TestClient) -> None:
    """Une cible vide est rejetée (422 validation ou 400 métier)."""
    resp = client.post("/api/scan", json={"target": "", "engine": "demo"})
    assert resp.status_code in (400, 422)


# --------------------------------------------------------------------------- #
# Enrichissement CVE — mode hors-ligne
# --------------------------------------------------------------------------- #
def test_enrich_with_nvd_offline_no_exception() -> None:
    """Hors-ligne : ``enrich_with_nvd`` renvoie une liste vide sans exception."""
    from src.bloc1_scan.cve_enrichment import clear_cache, enrich_with_nvd

    clear_cache()
    result = enrich_with_nvd("apache 2.4.49")
    assert isinstance(result, list)  # vide en sandbox sans réseau, mais jamais None


def test_enrich_with_nvd_empty_keyword() -> None:
    """Une clé vide renvoie immédiatement une liste vide."""
    from src.bloc1_scan.cve_enrichment import enrich_with_nvd

    assert enrich_with_nvd("") == []
    assert enrich_with_nvd("   ") == []


def test_enrich_vulnerability_offline_keeps_structure() -> None:
    """Hors-ligne : l'objet Vulnerability est renvoyé INCHANGÉ, structure intacte."""
    from src.bloc1_scan.cve_enrichment import clear_cache, enrich_vulnerability

    clear_cache()
    vuln = Vulnerability(
        id="t1",
        host="10.0.0.9",
        port=80,
        service="http",
        name="Apache HTTP Server 2.4.49 path traversal",
        cve_id="CVE-2021-41773",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    out = enrich_vulnerability(vuln)
    assert isinstance(out, Vulnerability)
    assert out.id == "t1"
    assert out.cve_id == "CVE-2021-41773"
    assert out.cvss_score == 9.8
    assert out.severity == Severity.CRITICAL


def test_parse_nvd_payload_extracts_cvss_and_cwe() -> None:
    """Le parsing d'un payload NVD synthétique extrait CVSS, CWE et références."""
    from src.bloc1_scan.cve_enrichment import _parse_nvd_payload

    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "descriptions": [{"lang": "en", "value": "Path traversal."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-22"}]}
                    ],
                    "references": [
                        {"url": "https://example.com/x", "tags": ["Exploit"]},
                        {"url": "https://vendor/y", "tags": ["Patch"]},
                    ],
                }
            }
        ]
    }
    results = _parse_nvd_payload(payload)
    assert len(results) == 1
    top = results[0]
    assert top["cve_id"] == "CVE-2021-41773"
    assert top["cvss_score"] == 9.8
    assert top["cvss_severity"] == "CRITICAL"
    assert "CWE-22" in top["cwe"]
    assert top["has_exploit"] is True
    assert top["has_patch"] is True
