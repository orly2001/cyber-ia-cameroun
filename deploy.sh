#!/usr/bin/env bash
# deploy.sh — Deploiement COMPLET et autonome (db + api + frontend) Linux/macOS.
# N'installe/demarre que ce qui manque : Docker (CLI + daemon), images, build.
# Usage : ./deploy.sh [up|down|logs|status]   (defaut: up)
set -u
cd "$(dirname "$0")"
CMD="${1:-up}"

is_mac() { [ "$(uname -s)" = "Darwin" ]; }
docker_engine_ok() { docker info >/dev/null 2>&1; }

ensure_docker() {
  # 1) CLI present ?
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker n'est pas installe."
    if is_mac; then
      if command -v brew >/dev/null 2>&1; then echo "Installation via Homebrew..."; brew install --cask docker || true
      else echo "Installe Docker Desktop : https://www.docker.com/products/docker-desktop/"; exit 1; fi
    elif command -v apt-get >/dev/null 2>&1; then
      echo "Installation de docker.io via apt (sudo requis)..."
      sudo apt-get update -y && sudo apt-get install -y docker.io docker-compose-plugin || { echo "Echec install."; exit 1; }
    else
      echo "Gestionnaire de paquets non reconnu. Installe Docker manuellement."; exit 1
    fi
  fi
  # 2) Moteur en marche ?
  if docker_engine_ok; then return 0; fi
  echo "Le moteur Docker ne tourne pas — tentative de demarrage..."
  if is_mac; then open -a Docker 2>/dev/null || true
  else sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true; fi
  echo "Attente du moteur Docker (jusqu'a 180 s)..."
  for i in $(seq 1 60); do sleep 3; if docker_engine_ok; then echo "Moteur Docker pret."; return 0; fi; done
  echo "Docker ne repond pas. Demarre Docker puis relance ce script."; exit 1
}

get_compose() {
  if docker compose version >/dev/null 2>&1; then echo "docker compose";
  elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose";
  else echo ""; fi
}

# Ports depuis .env si present
[ -f .env ] && set -a && . ./.env && set +a
API_PORT="${API_PORT:-8000}"; WEB_PORT="${WEB_PORT:-5173}"

case "$CMD" in
  down|logs|status)
    ensure_docker; DC="$(get_compose)"; [ -z "$DC" ] && { echo "docker compose introuvable"; exit 1; }
    case "$CMD" in
      down)   $DC down; echo "Stack arretee." ;;
      logs)   exec $DC logs -f ;;
      status) exec $DC ps ;;
    esac; exit 0 ;;
  up) : ;;
  *) echo "Commande inconnue: $CMD (up|down|logs|status)"; exit 2 ;;
esac

# ---- UP ----
ensure_docker
DC="$(get_compose)"; [ -z "$DC" ] && { echo "docker compose introuvable (inclus avec Docker)."; exit 1; }
[ -f .env ] || { cp .env.docker.example .env 2>/dev/null && echo "[.env cree depuis .env.docker.example]"; }

echo "== Build image API + recuperation images db/web (si absentes) =="
$DC up -d --build || { echo "Echec du demarrage. Logs : ./deploy.sh logs"; exit 1; }

echo "== Attente de l'API (entrainement du modele au 1er demarrage) =="
ok=0
for i in $(seq 1 80); do
  if curl -fsS "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
[ "$ok" = "1" ] && echo "API operationnelle sur :${API_PORT}." || { echo "API pas prete. Logs :"; $DC logs --tail=50 api; }

curl -fsS -X POST "http://localhost:${API_PORT}/api/run-demo" >/dev/null 2>&1 || true

URL="http://localhost:${WEB_PORT}/index.html"
( command -v xdg-open >/dev/null && xdg-open "$URL" ) 2>/dev/null \
  || ( command -v open >/dev/null && open "$URL" ) 2>/dev/null || true

cat <<MSG

================ DEPLOIEMENT PRET ================
 Dashboard SOC : http://localhost:${WEB_PORT}/index.html
 Console live  : http://localhost:${WEB_PORT}/console.html
 API + docs    : http://localhost:${API_PORT}/docs
--------------------------------------------------
 Logs : ./deploy.sh logs     Arret : ./deploy.sh down
=================================================
MSG
