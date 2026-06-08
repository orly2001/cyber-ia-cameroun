"""Tests du registre de recherches (bloc 5) : creation, dedup, partage, export, stats."""
import os
os.environ.setdefault("SQLITE_FALLBACK", "sqlite:////tmp/test_research.db")

import importlib
from fastapi.testclient import TestClient


def _client():
    # BDD locale isolee pour eviter l'erreur disque du montage.
    import src.common.config as cfg
    cfg.get_settings.cache_clear()
    import src.common.database as db
    importlib.reload(db)
    import src.bloc5_dashboard.api.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_research_create_and_dedup():
    c = _client()
    payload = {"query": "MTN MoMo confirmez votre code PIN http://momo.ml", "channel": "SMS"}
    r1 = c.post("/api/research", json=payload)
    assert r1.status_code == 200, r1.text
    d1 = r1.json()
    assert d1["is_phishing"] is True
    assert d1["query"] == payload["query"]
    # Deduplication : meme requete -> meme id, pas de doublon.
    r2 = c.post("/api/research", json=payload)
    assert r2.status_code == 200
    assert r2.json()["id"] == d1["id"]


def test_research_list_share_export_stats():
    c = _client()
    c.post("/api/research", json={"query": "Bonjour reunion demain 10h", "channel": "EMAIL"})
    rid = c.post("/api/research", json={"query": "gagnez 1000000 FCFA loterie bit.ly/z", "channel": "SMS"}).json()["id"]

    # Liste
    lst = c.get("/api/research").json()
    assert isinstance(lst, list) and len(lst) >= 2

    # Partage
    shared = c.post(f"/api/research/{rid}/share")
    assert shared.status_code == 200 and shared.json()["shared"] is True
    assert len(c.get("/api/research?shared=true").json()) >= 1

    # Export
    assert c.get("/api/research/export?fmt=csv").status_code == 200
    assert c.get("/api/research/export?fmt=json").status_code == 200

    # Stats (routage : /stats ne doit pas matcher /{rid})
    st = c.get("/api/research/stats")
    assert st.status_code == 200
    s = st.json()
    assert s["total"] >= 2
    assert set(["n_phishing", "n_legit", "phishing_rate", "by_channel", "by_verdict", "by_day"]).issubset(s)


def test_research_404():
    c = _client()
    assert c.get("/api/research/inexistant-xyz").status_code == 404
