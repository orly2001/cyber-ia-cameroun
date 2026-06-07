# Guide de déploiement — IA & Cybersécurité Cameroun

Ce guide décrit comment lancer la plateforme en local (environnement virtuel)
ou via Docker, comment configurer les variables d'environnement, et comment
basculer entre **SQLite** (dev) et **PostgreSQL** (prod).

---

## 1. Lancement local (venv)

Prérequis : Python 3.11 (3.10+ accepté).

```bash
python -m venv venv
source venv/bin/activate        # Windows : venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # puis adapter
```

Par défaut, `USE_SQLITE_FALLBACK=true` : aucun PostgreSQL requis, la base est
un fichier SQLite local (`data/soc_dev.db`).

Pipeline de démonstration (hors-ligne) :

```bash
python -m src.pipeline --demo
# ou : make demo
```

API + dashboard :

```bash
uvicorn src.bloc5_dashboard.api.main:app --reload
# ou : make run-api
```

Le `Makefile` regroupe les commandes courantes : `make install`, `make test`,
`make run-api`, `make demo`, `make train`, `make lint`, `make docker-up`,
`make docker-down`.

---

## 2. Lancement Docker (PostgreSQL + API)

Prérequis : Docker + Docker Compose v2.

```bash
docker compose up --build
# ou : make docker-up   (lance en arrière-plan)
```

Deux services sont démarrés :

| Service | Image / build      | Rôle                                  | Port |
|---------|--------------------|---------------------------------------|------|
| `db`    | `postgres:16`      | base PostgreSQL persistante (`pgdata`)| —    |
| `api`   | build `Dockerfile` | API FastAPI (bloc 5)                  | 8000 |

L'API attend que `db` soit **healthy** (`depends_on: condition: service_healthy`)
avant de démarrer. Les identifiants PostgreSQL (`soc` / `soc` / base `soc_cm`)
sont alignés avec `src/common/config.py`.

Arrêt :

```bash
docker compose down          # garde le volume de données
docker compose down -v       # supprime aussi le volume pgdata
# ou : make docker-down
```

> **Note BERT** : l'image Docker n'embarque pas `torch` / `transformers`
> (trop lourds). Le détecteur de phishing utilise le repli TF-IDF/RandomForest.
> Pour activer BERT, retirer le filtre `grep -v` sur ces paquets dans le
> `Dockerfile` (étape `pip install`) puis reconstruire l'image.

---

## 3. Variables d'environnement

Définies dans `.env` (local) ou via l'environnement du conteneur (Docker).
Référence : `src/common/config.py`.

| Variable               | Défaut                                               | Description                                   |
|------------------------|------------------------------------------------------|-----------------------------------------------|
| `ENVIRONMENT`          | `development`                                         | Profil applicatif                             |
| `LOG_LEVEL`            | `INFO`                                                | Niveau de log                                 |
| `DATABASE_URL`         | `postgresql+psycopg2://soc:soc@localhost:5432/soc_cm`| URL PostgreSQL (prod)                         |
| `USE_SQLITE_FALLBACK`  | `true`                                               | `true` → SQLite local ; `false` → PostgreSQL  |
| `API_HOST`             | `0.0.0.0`                                             | Adresse d'écoute de l'API                     |
| `API_PORT`             | `8000`                                                | Port de l'API                                 |
| `CORS_ORIGINS`         | `http://localhost:5173,http://localhost:3000`        | Origines autorisées (CSV)                     |
| `NVD_API_KEY`          | *(vide)*                                              | Clé API NVD (enrichissement CVE)              |
| `ZAP_API_URL`          | `http://localhost:8080`                              | URL OWASP ZAP                                 |
| `PHISHING_THRESHOLD`   | `0.5`                                                | Seuil de détection phishing                   |
| `BERT_MODEL_NAME`      | `bert-base-multilingual-cased`                       | Modèle BERT (si activé)                       |

En Docker, le service `api` reçoit :

```
DATABASE_URL=postgresql+psycopg2://soc:soc@db:5432/soc_cm
USE_SQLITE_FALLBACK=false
```

(`db` est le nom d'hôte du service PostgreSQL sur le réseau Compose, pas
`localhost`.)

---

## 4. Bascule SQLite ↔ PostgreSQL

L'URL effectivement utilisée est calculée par `Settings.effective_database_url` :

- `USE_SQLITE_FALLBACK=true`  → SQLite (`data/soc_dev.db`) — aucun serveur requis.
- `USE_SQLITE_FALLBACK=false` → `DATABASE_URL` (PostgreSQL).

**Passer en PostgreSQL en local :**

1. Démarrer PostgreSQL (ex. via `docker compose up db`).
2. Dans `.env` :
   ```
   USE_SQLITE_FALLBACK=false
   DATABASE_URL=postgresql+psycopg2://soc:soc@localhost:5432/soc_cm
   ```
3. Relancer l'API. Les tables sont créées automatiquement au démarrage
   (`init_db()` appelé par l'événement `startup` de FastAPI).

> Le pilote PostgreSQL `psycopg2-binary` est déjà inclus dans
> `requirements.txt` et installé dans l'image Docker.

---

## 5. Accès au dashboard

- **API** : http://localhost:8000
  - Santé : `GET /health`
  - Documentation interactive (Swagger) : http://localhost:8000/docs
  - Alertes : `GET /api/alerts`, agrégats : `GET /api/stats`
- **Frontend** : ouvrir le fichier `src/bloc5_dashboard/frontend/index.html`
  dans un navigateur. Régler la constante `API_BASE` (en haut du fichier /
  de son script) sur `http://localhost:8000` pour qu'il interroge l'API.

Pour peupler la base de démonstration : `POST /api/run-demo` (ou
`python -m src.pipeline --demo`).

## Modèle, analyse temps réel et console (mise à jour)

### Entraînement & déploiement du modèle
- Les données d'entraînement proviennent de **datasets publics réels** téléchargés par
  `python -m scripts.download_datasets` (registre dans `src/bloc2_phishing/dataset_downloader.py`).
  En environnement réseau restreint, le module utilise les fichiers déjà présents dans
  `data/external/` ; en dernier recours seulement, il complète avec un corpus synthétique
  (plafonné à 25 %).
- Entraînement honnête (split train/val/**test** tenu à l'écart) :
  `python -m src.bloc3_ia.train --model tfidf`. Artefacts **versionnés** sous
  `models/registry/tfidf_rf/<horodatage>/` (+ `metrics.json`, `meta.json`, alias `CURRENT.txt`).
- En conteneur, `scripts/entrypoint.sh` entraîne automatiquement le modèle s'il est absent,
  puis lance l'API (déploiement clé en main).

### Nouveaux endpoints (servis par l'API)
- `POST /api/analyze` — analyse d'un message (texte + canal) → verdict, score, indicateurs.
- `POST /api/analyze/batch` — analyse d'un lot de messages.
- `POST /api/upload` — upload d'un fichier `.csv`/`.txt` pour analyse en lot (protégé par clé d'API).
- `GET /api/model` — informations et métriques du modèle déployé.
- `GET /api/stream` — flux **temps réel** (SSE) de logs simulés analysés en direct.
- `GET /api/live/recent`, `GET /api/live/stats` — buffer et agrégats temps réel.

### Interfaces web
- `src/bloc5_dashboard/frontend/index.html` — **Dashboard SOC** (alertes corrélées).
- `src/bloc5_dashboard/frontend/console.html` — **Console d'analyse** : analyser un message,
  uploader un fichier, et visualiser le flux temps réel. Régler `API_BASE` en tête du script.
