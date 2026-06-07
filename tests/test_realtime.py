"""Tests du flux temps réel (bloc 5) : SSE, buffer récent et agrégats.

Les imports applicatifs construisent l'engine SQLAlchemy : on force donc une
base SQLite locale AVANT tout import (cf. ``tests/test_api.py``).
"""

from __future__ import annotations

import os

# --- Forcer une base SQLite locale AVANT les imports applicatifs --------------
os.environ["SQLITE_FALLBACK"] = "sqlite:////tmp/rt.db"
os.environ["USE_SQLITE_FALLBACK"] = "true"
_DB_FILE = "/tmp/rt.db"
if os.path.exists(_DB_FILE):
    os.remove(_DB_FILE)

import json  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.bloc5_dashboard.api.realtime import router  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Application de test minimale incluant uniquement le router temps réel."""
    app = FastAPI(title="Realtime test app")
    app.include_router(router)
    with TestClient(app) as c:
        yield c


def _parse_sse_events(body: str) -> list[dict]:
    """Extrait et parse les blocs ``data: <json>`` d'une réponse SSE."""
    events = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload:
                events.append(json.loads(payload))
    return events


def test_stream_returns_event_stream(client: TestClient) -> None:
    """``/api/stream`` renvoie du SSE avec au moins un event JSON exploitable."""
    resp = client.get("/api/stream", params={"count": 3, "delay": 0})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse_events(resp.text)
    assert len(events) >= 1
    first = events[0]
    assert "is_phishing" in first
    assert "score" in first
    assert isinstance(first["is_phishing"], bool)
    assert 0.0 <= float(first["score"]) <= 1.0
    assert "indicators" in first and isinstance(first["indicators"], list)


def test_live_recent_returns_list(client: TestClient) -> None:
    """``/api/live/recent`` renvoie une liste d'événements analysés."""
    resp = client.get("/api/live/recent", params={"limit": 5})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "is_phishing" in data[0]
    assert "score" in data[0]


def test_live_stats_structure(client: TestClient) -> None:
    """``/api/live/stats`` expose la structure d'agrégats attendue."""
    # On amorce d'abord le flux pour garantir un buffer non vide.
    client.get("/api/stream", params={"count": 4, "delay": 0})

    resp = client.get("/api/live/stats")
    assert resp.status_code == 200
    stats = resp.json()
    for key in ("total", "n_phishing", "phishing_rate", "recent_scores", "buffer_capacity"):
        assert key in stats
    assert stats["total"] >= 1
    assert stats["n_phishing"] <= stats["total"]
    assert isinstance(stats["recent_scores"], list)
    assert 0.0 <= float(stats["phishing_rate"]) <= 1.0
