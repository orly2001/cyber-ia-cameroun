"""Tests du service d'inférence & upload (bloc 5 — routeur ``inference``).

On monte une app FastAPI de test minimaliste incluant uniquement le routeur
d'inférence, puis on l'exerce via ``TestClient``. La base SQLite locale est
forcée AVANT tout import applicatif (cohérence avec les autres tests), même si
le routeur n'utilise pas la base.

Le modèle de détection peut varier (BERT / TF-IDF / repli heuristique) : les
tests vérifient donc la STRUCTURE et la COHÉRENCE des réponses, pas une valeur
de label précise.
"""

from __future__ import annotations

import io
import os

# --- Forcer une base SQLite locale AVANT les imports applicatifs --------------
os.environ["SQLITE_FALLBACK"] = "sqlite:////tmp/inf.db"
os.environ["USE_SQLITE_FALLBACK"] = "true"
_DB_FILE = "/tmp/inf.db"
if os.path.exists(_DB_FILE):
    os.remove(_DB_FILE)

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.bloc5_dashboard.api import inference  # noqa: E402

_PHISHING_TEXT = "URGENT confirmez votre code PIN MoMo http://bit.ly/x sinon compte suspendu"
_LEGIT_TEXT = "Bonjour, on se voit demain a 10h pour le cafe."


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Client de test sur une app montant uniquement le routeur d'inférence."""
    app = FastAPI()
    app.include_router(inference.router)
    with TestClient(app) as c:
        yield c


def _assert_result_shape(body: dict) -> None:
    """Vérifie la structure d'un verdict d'analyse."""
    assert set(body) >= {
        "is_phishing",
        "score",
        "model",
        "channel",
        "indicators",
        "clean_text",
    }
    assert isinstance(body["is_phishing"], bool)
    assert isinstance(body["score"], (int, float))
    assert 0.0 <= body["score"] <= 1.0
    assert isinstance(body["model"], str) and body["model"]
    assert isinstance(body["indicators"], list)
    assert isinstance(body["clean_text"], str)


def test_extract_indicators_phishing() -> None:
    """La fonction d'indicateurs repère les motifs d'un texte phishing."""
    indicators = inference.extract_indicators(_PHISHING_TEXT)
    assert indicators, "Des indicateurs devraient être détectés."
    assert any("PIN" in i or "pin" in i.lower() for i in indicators)
    assert "URL raccourcie" in indicators


def test_analyze_phishing(client: TestClient) -> None:
    """Un texte clairement phishing renvoie une structure cohérente + indicateurs."""
    resp = client.post(
        "/api/analyze",
        json={"text": _PHISHING_TEXT, "channel": "SMS", "language": "fr"},
    )
    assert resp.status_code == 200
    body = resp.json()
    _assert_result_shape(body)
    assert body["channel"] == "SMS"
    # Indicateurs lexicaux non vides sur un texte aussi chargé.
    assert len(body["indicators"]) > 0
    # clean_text doit être normalisé (URL -> <URL>).
    assert body["clean_text"] != ""


def test_analyze_legit(client: TestClient) -> None:
    """Un texte légitime renvoie une structure cohérente (label libre)."""
    resp = client.post("/api/analyze", json={"text": _LEGIT_TEXT})
    assert resp.status_code == 200
    _assert_result_shape(resp.json())


def test_analyze_empty_400(client: TestClient) -> None:
    """Un texte vide est rejeté (400)."""
    resp = client.post("/api/analyze", json={"text": "   "})
    assert resp.status_code == 400


def test_analyze_batch(client: TestClient) -> None:
    """Le batch JSON renvoie un résultat par item + un résumé cohérent."""
    resp = client.post(
        "/api/analyze/batch",
        json={
            "items": [
                {"text": _PHISHING_TEXT, "channel": "SMS"},
                {"text": _LEGIT_TEXT, "channel": "EMAIL"},
            ]
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) >= {"summary", "results"}
    assert len(body["results"]) == 2
    for r in body["results"]:
        _assert_result_shape(r)
    summ = body["summary"]
    assert summ["n"] == 2
    assert 0 <= summ["n_phishing"] <= 2
    assert 0.0 <= summ["rate"] <= 1.0


def test_analyze_batch_empty_400(client: TestClient) -> None:
    """Un batch vide est rejeté (400)."""
    resp = client.post("/api/analyze/batch", json={"items": []})
    assert resp.status_code == 400


def test_upload_txt(client: TestClient) -> None:
    """Upload d'un .txt (2 lignes) : count=2, structure et résumé cohérents."""
    payload = (_PHISHING_TEXT + "\n" + _LEGIT_TEXT + "\n").encode("utf-8")
    resp = client.post(
        "/api/upload",
        files={"file": ("messages.txt", io.BytesIO(payload), "text/plain")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "messages.txt"
    assert body["count"] == 2
    assert len(body["results"]) == 2
    for r in body["results"]:
        _assert_result_shape(r)
    assert body["summary"]["n"] == 2


def test_upload_csv(client: TestClient) -> None:
    """Upload d'un petit CSV standard : analyse en lot cohérente."""
    csv_content = (
        "id,channel,raw_text,language,label,source\n"
        f"1,SMS,{_PHISHING_TEXT.replace(',', ' ')},fr,,manual\n"
        f"2,EMAIL,{_LEGIT_TEXT.replace(',', ' ')},fr,,manual\n"
    ).encode("utf-8")
    resp = client.post(
        "/api/upload",
        files={"file": ("samples.csv", io.BytesIO(csv_content), "text/csv")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "samples.csv"
    assert body["count"] == 2
    for r in body["results"]:
        _assert_result_shape(r)


def test_upload_empty_400(client: TestClient) -> None:
    """Upload d'un fichier vide : 400."""
    resp = client.post(
        "/api/upload",
        files={"file": ("vide.txt", io.BytesIO(b""), "text/plain")},
    )
    assert resp.status_code == 400


def test_upload_bad_extension_400(client: TestClient) -> None:
    """Upload d'une extension non gérée : 400."""
    resp = client.post(
        "/api/upload",
        files={"file": ("data.json", io.BytesIO(b"{}"), "application/json")},
    )
    assert resp.status_code == 400


def test_upload_csv_missing_column_400(client: TestClient) -> None:
    """CSV sans colonne raw_text : 400 (mal formé)."""
    bad = b"id,channel,texte\n1,SMS,bonjour\n"
    resp = client.post(
        "/api/upload",
        files={"file": ("bad.csv", io.BytesIO(bad), "text/csv")},
    )
    assert resp.status_code == 400


def test_model_info(client: TestClient) -> None:
    """GET /api/model renvoie la structure d'informations du modèle courant."""
    resp = client.get("/api/model")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) >= {"type", "trained", "threshold", "metrics"}
    assert isinstance(body["type"], str) and body["type"]
    assert isinstance(body["trained"], bool)
    assert isinstance(body["threshold"], (int, float))
    assert isinstance(body["metrics"], dict)
