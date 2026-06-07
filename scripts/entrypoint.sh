#!/bin/sh
# Entrypoint de déploiement : entraîne le modèle s'il est absent, puis sert l'API.
set -e
cd /app

if [ ! -f models/registry/tfidf_rf/CURRENT.txt ] && [ ! -f models/phishing_tfidf_rf.joblib ]; then
  echo "[entrypoint] Aucun modèle courant détecté — acquisition des données + entraînement…"
  python -m scripts.download_datasets || echo "[entrypoint] acquisition partielle (réseau restreint) — on continue"
  python -m src.bloc3_ia.train --model tfidf || echo "[entrypoint] entraînement indisponible — repli heuristique actif"
else
  echo "[entrypoint] Modèle existant détecté — démarrage direct."
fi

exec uvicorn src.bloc5_dashboard.api.main:app --host 0.0.0.0 --port 8000
