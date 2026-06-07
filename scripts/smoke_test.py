"""Smoke-test end-to-end de l'API SOC (bloc 5) via ``TestClient``.

Exerce TOUS les endpoints clés de l'API en mémoire (sans serveur réseau) et
imprime un récapitulatif PASS/FAIL par endpoint. Le script se termine avec un
code de sortie non nul si au moins un cas échoue, afin d'être utilisable en CI.

Endpoints couverts :

* ``GET  /health``                 — sonde de disponibilité ;
* ``POST /api/run-demo``           — pipeline de démonstration ;
* ``GET  /api/alerts``             — liste des alertes (sans/avec filtre) ;
* ``GET  /api/stats``              — agrégats du dashboard ;
* ``POST /api/analyze``            — analyse d'un message unitaire ;
* ``POST /api/analyze/batch``      — analyse d'un lot de messages ;
* ``POST /api/upload``             — upload d'un CSV en mémoire ;
* ``GET  /api/model``              — informations sur le modèle courant ;
* ``GET  /api/live/recent``        — derniers événements temps réel ;
* ``GET  /api/live/stats``         — agrégats temps réel.

Base de données : sur certains montages réseau, SQLite déclenche une erreur
« disk I/O error ». On force donc une base sur disque local (``/tmp``) AVANT
tout import applicatif (l'engine SQLAlchemy est construit à l'import de
``src.common.database``). La variable ``SQLITE_FALLBACK`` existante est
respectée si elle est déjà définie.
"""

from __future__ import annotations

import io
import os
import sys
from typing import Callable, List, Tuple

# --- Forcer une base SQLite locale AVANT les imports applicatifs --------------
os.environ.setdefault("SQLITE_FALLBACK", "sqlite:////tmp/smoke_soc.db")
os.environ["USE_SQLITE_FALLBACK"] = "true"

_DB_URL = os.environ["SQLITE_FALLBACK"]
if _DB_URL.startswith("sqlite:////"):
    _db_file = "/" + _DB_URL.split("sqlite:////", 1)[1]
    try:
        if os.path.exists(_db_file):
            os.remove(_db_file)
    except OSError:
        pass

from fastapi.testclient import TestClient  # noqa: E402

from src.bloc5_dashboard.api.main import app  # noqa: E402
from src.common.database import init_db  # noqa: E402


def _csv_payload() -> bytes:
    """Construit un petit CSV de phishing/légitime pour l'endpoint upload."""
    lines = [
        "id,channel,raw_text,language",
        "u1,SMS,URGENT votre compte est suspendu cliquez http://bit.ly/x,fr",
        "u2,SMS,Salut on se voit a midi pour le dejeuner,fr",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def run_checks(client: TestClient) -> List[Tuple[str, bool, str]]:
    """Exécute tous les cas de test et renvoie ``(nom, ok, détail)`` par cas.

    Args:
        client: client de test FastAPI déjà initialisé.

    Returns:
        Liste de tuples ``(libellé, succès, détail)`` pour le récapitulatif.
    """
    results: List[Tuple[str, bool, str]] = []

    def check(name: str, fn: Callable[[], Tuple[bool, str]]) -> None:
        """Exécute un cas en capturant toute exception comme un échec propre."""
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 — un crash = un FAIL, pas un arrêt
            ok, detail = False, f"exception: {exc}"
        results.append((name, ok, detail))

    # --- système : health ---------------------------------------------------- #
    def _health() -> Tuple[bool, str]:
        r = client.get("/health")
        ok = r.status_code == 200 and r.json().get("status") == "ok"
        return ok, f"HTTP {r.status_code}"

    check("GET /health", _health)

    # --- système : run-demo -------------------------------------------------- #
    def _run_demo() -> Tuple[bool, str]:
        r = client.post("/api/run-demo")
        ok = r.status_code == 200 and set(r.json()) == {
            "success",
            "alerts_generated",
            "message",
        }
        return ok, f"HTTP {r.status_code} generated={r.json().get('alerts_generated')}"

    check("POST /api/run-demo", _run_demo)

    # --- alertes : liste ----------------------------------------------------- #
    def _alerts_list() -> Tuple[bool, str]:
        r = client.get("/api/alerts")
        ok = r.status_code == 200 and isinstance(r.json(), list)
        return ok, f"HTTP {r.status_code} n={len(r.json()) if ok else '?'}"

    check("GET /api/alerts", _alerts_list)

    # --- alertes : liste filtrée --------------------------------------------- #
    def _alerts_filtered() -> Tuple[bool, str]:
        r = client.get("/api/alerts", params={"min_risk": 0, "status": "NEW"})
        ok = r.status_code == 200 and isinstance(r.json(), list)
        return ok, f"HTTP {r.status_code} n={len(r.json()) if ok else '?'}"

    check("GET /api/alerts (filtre)", _alerts_filtered)

    # --- alertes : stats ----------------------------------------------------- #
    def _stats() -> Tuple[bool, str]:
        r = client.get("/api/stats")
        ok = r.status_code == 200 and set(r.json()) == {
            "total",
            "by_severity",
            "by_status",
            "average_risk",
            "top_alerts",
        }
        return ok, f"HTTP {r.status_code} total={r.json().get('total')}"

    check("GET /api/stats", _stats)

    # --- inférence : analyze unitaire ---------------------------------------- #
    def _analyze() -> Tuple[bool, str]:
        r = client.post(
            "/api/analyze",
            json={
                "text": "URGENT compte suspendu, verifiez via http://bit.ly/x",
                "channel": "SMS",
                "language": "fr",
            },
        )
        body = r.json() if r.status_code == 200 else {}
        ok = r.status_code == 200 and {"is_phishing", "score", "model"} <= set(body)
        return ok, f"HTTP {r.status_code} score={body.get('score')}"

    check("POST /api/analyze", _analyze)

    # --- inférence : analyze batch ------------------------------------------- #
    def _analyze_batch() -> Tuple[bool, str]:
        r = client.post(
            "/api/analyze/batch",
            json={
                "items": [
                    {"text": "Gagnez 1000000 FCFA maintenant", "channel": "SMS"},
                    {"text": "Reunion equipe demain 9h", "channel": "EMAIL"},
                ]
            },
        )
        body = r.json() if r.status_code == 200 else {}
        ok = (
            r.status_code == 200
            and "summary" in body
            and body.get("summary", {}).get("n") == 2
        )
        return ok, f"HTTP {r.status_code} n={body.get('summary', {}).get('n')}"

    check("POST /api/analyze/batch", _analyze_batch)

    # --- inférence : upload CSV en mémoire ----------------------------------- #
    def _upload() -> Tuple[bool, str]:
        files = {"file": ("smoke.csv", io.BytesIO(_csv_payload()), "text/csv")}
        r = client.post("/api/upload", files=files)
        body = r.json() if r.status_code == 200 else {}
        ok = r.status_code == 200 and body.get("count") == 2
        return ok, f"HTTP {r.status_code} count={body.get('count')}"

    check("POST /api/upload (CSV)", _upload)

    # --- inférence : modèle -------------------------------------------------- #
    def _model() -> Tuple[bool, str]:
        r = client.get("/api/model")
        body = r.json() if r.status_code == 200 else {}
        ok = r.status_code == 200 and {"type", "trained", "threshold"} <= set(body)
        return ok, f"HTTP {r.status_code} type={body.get('type')}"

    check("GET /api/model", _model)

    # --- temps réel : live/recent -------------------------------------------- #
    def _live_recent() -> Tuple[bool, str]:
        r = client.get("/api/live/recent", params={"limit": 5})
        ok = r.status_code == 200 and isinstance(r.json(), list)
        return ok, f"HTTP {r.status_code} n={len(r.json()) if ok else '?'}"

    check("GET /api/live/recent", _live_recent)

    # --- temps réel : live/stats --------------------------------------------- #
    def _live_stats() -> Tuple[bool, str]:
        r = client.get("/api/live/stats")
        body = r.json() if r.status_code == 200 else {}
        ok = r.status_code == 200 and {"total", "n_phishing", "phishing_rate"} <= set(
            body
        )
        return ok, f"HTTP {r.status_code} total={body.get('total')}"

    check("GET /api/live/stats", _live_stats)

    return results


def main() -> int:
    """Point d'entrée : exécute le smoke-test et imprime le récapitulatif.

    Returns:
        Code de sortie ``0`` si tous les cas passent, ``1`` sinon.
    """
    init_db()
    with TestClient(app) as client:
        results = run_checks(client)

    print("=" * 60)
    print("SMOKE-TEST API SOC — récapitulatif")
    print("=" * 60)
    failures = 0
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[{status}] {name:<32} {detail}")
    print("-" * 60)
    total = len(results)
    print(f"Résultat : {total - failures}/{total} PASS, {failures} FAIL")
    print("=" * 60)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
