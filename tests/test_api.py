"""Tests de l'API du bloc 5 (FastAPI TestClient).

Couvre les endpoints publics (santé, lecture, statistiques), le pipeline de
démonstration, la mise à jour de statut et la gestion des 404. Un test dédié
vérifie l'authentification par clé d'API sur un endpoint sensible.

⚠️ Base de données : sur certains montages réseau, SQLite déclenche une erreur
« disk I/O error ». On force donc une base sur disque local (``/tmp``) en
réglant l'environnement AVANT tout import applicatif (l'engine SQLAlchemy est
construit à l'import de ``src.common.database``).
"""

from __future__ import annotations

import os

# --- Forcer une base SQLite locale AVANT les imports applicatifs --------------
os.environ["SQLITE_FALLBACK"] = "sqlite:////tmp/test_soc.db"
os.environ["USE_SQLITE_FALLBACK"] = "true"
_DB_FILE = "/tmp/test_soc.db"
if os.path.exists(_DB_FILE):
    os.remove(_DB_FILE)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.common.config import settings  # noqa: E402
from src.common.database import init_db  # noqa: E402
from src.bloc5_dashboard.api.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Client de test partagé ; garantit la création des tables."""
    init_db()
    with TestClient(app) as c:
        yield c


def _pandas_available() -> bool:
    """Indique si pandas est disponible (requis par le corpus du mode démo)."""
    try:
        import pandas  # noqa: F401
        return True
    except ImportError:
        return False


def test_health(client: TestClient) -> None:
    """La sonde de santé répond 200 avec un statut OK et les en-têtes sécurité."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    # En-têtes de sécurité ajoutés par le middleware.
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_run_demo_without_key_is_ok(client: TestClient) -> None:
    """Sans clé configurée, POST /api/run-demo passe (mode dev permissif)."""
    assert settings.api_key == "", "Le test suppose API_KEY vide par défaut."
    resp = client.post("/api/run-demo")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"success", "alerts_generated", "message"}
    if _pandas_available():
        assert body["success"] is True
        assert body["alerts_generated"] >= 1


@pytest.mark.skipif(
    not _pandas_available(),
    reason="pandas requis pour générer des alertes via le mode démo.",
)
def test_list_alerts_after_demo(client: TestClient) -> None:
    """Après la démo, GET /api/alerts renvoie au moins une alerte valide."""
    client.post("/api/run-demo")
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert isinstance(alerts, list)
    assert len(alerts) > 0
    first = alerts[0]
    assert {"id", "title", "risk_score", "severity", "status"} <= set(first)


def test_stats_structure(client: TestClient) -> None:
    """GET /api/stats renvoie la structure d'agrégats attendue."""
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {
        "total",
        "by_severity",
        "by_status",
        "average_risk",
        "top_alerts",
    }
    assert isinstance(body["total"], int)
    assert isinstance(body["by_severity"], dict)
    assert isinstance(body["by_status"], dict)
    assert isinstance(body["average_risk"], (int, float))
    assert isinstance(body["top_alerts"], list)


@pytest.mark.skipif(
    not _pandas_available(),
    reason="pandas requis pour disposer d'une alerte à mettre à jour.",
)
def test_patch_status(client: TestClient) -> None:
    """PATCH /api/alerts/{id} met à jour le statut d'une alerte existante."""
    client.post("/api/run-demo")
    alert_id = client.get("/api/alerts").json()[0]["id"]
    resp = client.patch(f"/api/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACKNOWLEDGED"


def test_get_alert_404(client: TestClient) -> None:
    """Une alerte inexistante renvoie 404."""
    resp = client.get("/api/alerts/inexistant-xyz")
    assert resp.status_code == 404


def test_patch_alert_404(client: TestClient) -> None:
    """PATCH sur une alerte inexistante renvoie 404 (clé non requise ici)."""
    resp = client.patch("/api/alerts/inexistant-xyz", json={"status": "RESOLVED"})
    assert resp.status_code == 404


def test_api_key_auth(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Avec une clé configurée : 401 sans clé / 200 avec la bonne clé.

    On mute l'attribut ``api_key`` de l'instance ``settings`` partagée : la
    dépendance ``require_api_key`` lit cette même instance, la modification est
    donc effective sans recharger le module.
    """
    monkeypatch.setattr(settings, "api_key", "secret-test-123")

    # Sans clé -> 401
    resp_no_key = client.post("/api/run-demo")
    assert resp_no_key.status_code == 401

    # Mauvaise clé -> 401
    resp_bad = client.post("/api/run-demo", headers={"X-API-Key": "mauvaise"})
    assert resp_bad.status_code == 401

    # Bonne clé -> 200
    resp_ok = client.post(
        "/api/run-demo", headers={"X-API-Key": "secret-test-123"}
    )
    assert resp_ok.status_code == 200
