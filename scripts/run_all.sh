#!/usr/bin/env bash
# run_all.sh — Lance TOUS les services pour tester le produit (Linux/Mac/WSL).
#   - prepare l'environnement Python (venv + dependances), sauf SKIP_VENV=1 / SKIP_INSTALL=1
#   - entraine le modele s'il est absent
#   - demarre l'API FastAPI (:8000) et sert le frontend (:5173)
#   - attend /health, peuple la demo, puis garde les services actifs (Ctrl+C pour arreter)
#   Mode auto-test :  SMOKE=1 ./scripts/run_all.sh   (teste les endpoints puis s'arrete)
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-5173}"
PY="python3"

echo "== Projet : $ROOT =="

# 1) venv + dependances (optionnels)
if [ "${SKIP_VENV:-0}" != "1" ]; then
  [ -d venv ] || { echo "Creation du venv..."; python3 -m venv venv; }
  # shellcheck disable=SC1091
  source venv/bin/activate
  PY="python"
fi
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
  echo "Installation des dependances..."
  $PY -m pip install --quiet --upgrade pip
  $PY -m pip install --quiet -r requirements.txt
fi

# 2) Entrainement si modele absent
if [ ! -f models/registry/tfidf_rf/CURRENT.txt ] && [ ! -f models/phishing_tfidf_rf.joblib ]; then
  echo "Aucun modele -> entrainement..."
  $PY -m src.bloc3_ia.train --model tfidf --seed 42 || echo "(entrainement indisponible, repli heuristique)"
else
  echo "Modele existant detecte."
fi

API_PID=""; WEB_PID=""
cleanup() {
  echo; echo "Arret des services..."
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

# 3) API
echo "Demarrage de l'API sur http://localhost:$API_PORT ..."
$PY -m uvicorn src.bloc5_dashboard.api.main:app --host 127.0.0.1 --port "$API_PORT" >/tmp/api_soc.log 2>&1 &
API_PID=$!

# 4) Frontend
echo "Service du frontend sur http://localhost:$WEB_PORT ..."
$PY -m http.server "$WEB_PORT" --directory src/bloc5_dashboard/frontend >/tmp/web_soc.log 2>&1 &
WEB_PID=$!

# 5) Attente /health
echo "Attente de l'API..."
ok=0
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:$API_PORT/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] && echo "API operationnelle." || { echo "API KO (voir /tmp/api_soc.log)"; cat /tmp/api_soc.log; exit 1; }

# 6) Peuplement demo
curl -fsS -X POST "http://localhost:$API_PORT/api/run-demo" >/dev/null 2>&1 || true

echo ""
echo "================ PRET A TESTER ================"
echo " Dashboard SOC : http://localhost:$WEB_PORT/index.html"
echo " Console live  : http://localhost:$WEB_PORT/console.html"
echo " API + docs    : http://localhost:$API_PORT/docs"
echo "=============================================="

# Mode auto-test : verifie quelques endpoints puis s'arrete
if [ "${SMOKE:-0}" = "1" ]; then
  echo "[SMOKE] Verification des endpoints..."
  rc=0
  curl -fsS "http://localhost:$API_PORT/health" >/dev/null && echo "[OK] /health" || { echo "[KO] /health"; rc=1; }
  curl -fsS "http://localhost:$API_PORT/api/model" >/dev/null && echo "[OK] /api/model" || { echo "[KO] /api/model"; rc=1; }
  curl -fsS "http://localhost:$WEB_PORT/index.html" >/dev/null && echo "[OK] frontend index" || { echo "[KO] frontend"; rc=1; }
  curl -fsS -X POST "http://localhost:$API_PORT/api/analyze" -H "Content-Type: application/json" \
       -d '{"text":"MTN MoMo confirmez votre code PIN http://x.ml","channel":"SMS"}' >/dev/null \
       && echo "[OK] /api/analyze" || { echo "[KO] /api/analyze"; rc=1; }
  echo "[SMOKE] termine (rc=$rc)"; exit $rc
fi

# Sinon : garder les services actifs jusqu'a Ctrl+C
echo "(Ctrl+C pour arreter)"
wait
