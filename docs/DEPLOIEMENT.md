# Guide de déploiement — IA & Cybersécurité Cameroun

Trois façons de lancer le produit, de la plus simple à la production.

## 1. Déploiement Docker COMPLET (recommandé)

Une seule commande démarre toute la stack : **PostgreSQL + API FastAPI + frontend**.

### Windows (PowerShell)
```powershell
.\deploy.ps1            # build + démarre + ouvre le navigateur
.\deploy.ps1 logs       # suivre les logs
.\deploy.ps1 status     # état des services
.\deploy.ps1 down       # tout arrêter
```

### Linux / macOS
```bash
./deploy.sh up          # build + démarre + ouvre le navigateur
./deploy.sh logs
./deploy.sh status
./deploy.sh down
```

Ou via `make` : `make deploy` / `make deploy-down`.

Le script vérifie Docker, construit les images, démarre les 3 services, attend
que l'API réponde (le **modèle s'entraîne au premier démarrage** — soyez patient),
peuple quelques alertes de démo, puis ouvre le dashboard.

### Accès
| Service | URL |
|---|---|
| Dashboard SOC | http://localhost:5173/index.html |
| Console temps réel + upload | http://localhost:5173/console.html |
| API (Swagger) | http://localhost:8000/docs |
| Santé API | http://localhost:8000/health |

### Services (docker-compose.yml)
- **db** — PostgreSQL 16, volume `pgdata` persistant, healthcheck `pg_isready`.
- **api** — image construite via `Dockerfile`, dépend de `db` (healthy), modèle
  persisté dans le volume `models`, healthcheck `/health`.
- **web** — nginx servant le frontend statique (`docker/nginx.conf`).

## 2. Lancement local SANS Docker (test rapide)

Nécessite Python 3.11+. Démarre API (:8000) + frontend (:5173) et ouvre le navigateur.

```bash
# Linux/macOS
./scripts/run_all.sh
# Windows
.\scripts\run_all.ps1
```
La base par défaut est **SQLite** (aucun PostgreSQL requis). `Ctrl+C` pour arrêter.

## 3. Manuel (développement)
```bash
make install          # pip install -r requirements.txt
make train            # entraîne le modèle (modèle calibré)
make run-api          # uvicorn :8000 (--reload)
# servir le frontend :
python -m http.server 5173 --directory src/bloc5_dashboard/frontend
```

## Configuration (.env)

Toutes les variables ont des valeurs par défaut — la stack marche sans `.env`.
Copier `.env.docker.example` en `.env` pour personnaliser :

| Variable | Défaut | Rôle |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` => **API_KEY obligatoire** (sinon l'API refuse de démarrer) |
| `POSTGRES_PASSWORD` | `soc` | mot de passe PostgreSQL (**à changer en prod**) |
| `API_KEY` | _(vide)_ | protège upload / run-demo / patch (en-tête `X-API-Key`) |
| `PHISHING_THRESHOLD` | `0.5` | seuil de décision (le modèle est calibré à ~0.23) |
| `API_PORT` / `WEB_PORT` | `8000` / `5173` | ports publiés |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | origines autorisées |

### Passage en production
1. Dans `.env` : `ENVIRONMENT=production`, un `API_KEY` fort, un `POSTGRES_PASSWORD` fort.
2. `./deploy.sh up`.
3. Dans la console (`console.html`), renseigner le champ **Clé API** pour les actions protégées.

## Notes
- **BERT** n'est pas inclus dans l'image (trop lourd) ; voir le commentaire dans
  le `Dockerfile` pour l'activer (`transformers` + `torch`).
- Le frontend appelle l'API sur `http://localhost:8000` (constante `API_BASE` en
  haut de `index.html` / `console.html`) — l'adapter si l'API est sur un autre hôte.
- Pour un hôte distant : ajouter son origine à `CORS_ORIGINS` et régler `API_BASE`.
