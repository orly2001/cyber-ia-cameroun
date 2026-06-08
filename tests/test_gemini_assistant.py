"""Tests de l'assistant Gemini : parsing mocké + dégradation sans clé/réseau.

Aucun appel réseau réel : ``requests.post`` est mocké.
"""
import types
from unittest.mock import patch

from src.bloc3_ia import gemini_assistant as ga
from src.common.config import settings


def _fake_response(text):
    r = types.SimpleNamespace()
    r.status_code = 200
    r.json = lambda: {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return r


def test_unavailable_without_key(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "")
    assert ga.is_available() is False
    assert ga.explain_with_gemini("x", True, 0.9, ["bit.ly"]) is None
    assert ga.summarize("un texte") is None


def test_generate_parses_mocked_response(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "FAKE_KEY")
    fake = _fake_response("Ceci est l'explication.\nConseil A\nConseil B")
    with patch("requests.post", return_value=fake):
        out = ga.explain_with_gemini("gagnez 1M FCFA", True, 0.95, ["loterie"])
    assert isinstance(out, dict)
    assert "explanation" in out and out["explanation"]
    assert isinstance(out["advice"], list)


def test_network_failure_returns_none(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "FAKE_KEY")
    def boom(*a, **k):
        raise RuntimeError("réseau coupé key=FAKE_KEY")
    with patch("requests.post", side_effect=boom):
        assert ga.explain_with_gemini("x", False, 0.1, []) is None
        # La cle ne doit pas fuiter : _redact la masque.
        assert ga._redact("erreur key=FAKE_KEY") == "erreur key=***"


def test_summarize_mocked(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "FAKE_KEY")
    with patch("requests.post", return_value=_fake_response("Résumé court.")):
        assert ga.summarize("un long texte à résumer", 30) == "Résumé court."
