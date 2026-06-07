"""Test d'intégration du pipeline en mode démonstration (hors-ligne).

Vérifie que ``run_pipeline(demo=True, persist=False)`` produit une liste non
vide d'``Alert`` valides SANS aucune dépendance externe ni modèle entraîné
(repli heuristique).

Le repli heuristique du bloc 3 n'a besoin d'aucune dépendance lourde, mais le
chargement du corpus phishing (bloc 2) repose sur ``pandas``. Si pandas est
absent de l'environnement, le test est ignoré (skip) plutôt qu'en échec, car le
repli renvoie alors une liste vide d'échantillons.
"""

from __future__ import annotations

import pytest

from src.common.schemas import Alert, Severity


def _pandas_available() -> bool:
    try:
        import pandas  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _pandas_available(),
    reason="pandas requis pour charger le corpus phishing du mode démo.",
)
def test_run_pipeline_demo_produces_alerts():
    from src.pipeline import run_pipeline

    alerts = run_pipeline(demo=True, persist=False)

    assert isinstance(alerts, list)
    assert len(alerts) >= 1, "Le mode démo doit produire au moins une alerte."

    for a in alerts:
        assert isinstance(a, Alert)
        assert 0.0 <= a.risk_score <= 100.0
        assert a.severity in set(Severity)
        assert a.title


@pytest.mark.skipif(
    not _pandas_available(),
    reason="pandas requis pour charger le corpus phishing du mode démo.",
)
def test_run_pipeline_demo_alerts_sorted_desc():
    from src.pipeline import run_pipeline

    alerts = run_pipeline(demo=True, persist=False)
    risks = [a.risk_score for a in alerts]
    assert risks == sorted(risks, reverse=True)


def test_pipeline_module_imports_without_heavy_deps():
    """L'import du module pipeline ne doit tirer aucune dépendance lourde."""
    import src.pipeline as pipeline

    assert hasattr(pipeline, "run_pipeline")
    assert hasattr(pipeline, "run_demo")
