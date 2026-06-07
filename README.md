# IA & Cybersécurité Cameroun

Plateforme de détection et de corrélation **vulnérabilités ↔ phishing**, orientée
contexte camerounais (Mobile Money MTN/Orange, banques locales). Projet tutoré
collectif réparti entre une **équipe Cybersécurité** et une **équipe IA**.

## Architecture (5 blocs)

| Bloc | Rôle | Équipe | Module |
|------|------|--------|--------|
| 1 | Scan de vulnérabilités (OWASP ZAP, Nmap) + enrichissement CVE/NVD | Cyber (C1) | `src/bloc1_scan` |
| 2 | Collecte & prétraitement du corpus phishing (SMS/URL/email) | IA (I3) | `src/bloc2_phishing` |
| 3 | Moteur IA : détection phishing (TF-IDF/RF, BERT) + scoring vulnérabilités (RF/XGBoost) | IA (I1/I2) | `src/bloc3_ia` |
| 4 | Moteur de corrélation + score de risque composite + alertes | Commun (C2/I1) | `src/bloc4_correlation` |
| 5 | Dashboard SOC : API FastAPI + React/Chart.js + PostgreSQL | Cyber (C3) | `src/bloc5_dashboard` |

Le flux complet est orchestré par `src/pipeline.py`.

## Contrats de données

Tous les blocs échangent via les modèles Pydantic de `src/common/schemas.py`
(`Vulnerability`, `PhishingSample`, `PhishingPrediction`, `VulnScore`, `Alert`).
**Ne pas modifier ces schémas sans concertation** — ils garantissent que les
blocs s'emboîtent.

## Installation

```bash
python -m venv venv
source venv/bin/activate        # Windows : venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # puis adapter
```

Par défaut, un repli **SQLite** (`USE_SQLITE_FALLBACK=true`) évite d'avoir besoin
de PostgreSQL pour le développement.

## Démarrage rapide

```bash
# Pipeline complet sur les données d'exemple (scan simulé + IA + corrélation)
python -m src.pipeline --demo

# API + dashboard
uvicorn src.bloc5_dashboard.api.main:app --reload
# puis ouvrir src/bloc5_dashboard/frontend/index.html
```

## Tests

```bash
pytest -q
```

## Déploiement

Lancement local (SQLite, sans PostgreSQL) ou conteneurisé (PostgreSQL + API) :

```bash
# Local — voir le Makefile pour les autres cibles
make install && make demo && make run-api

# Docker — PostgreSQL + API FastAPI (port 8000)
make docker-up      # docker compose up --build -d
make docker-down
```

Le `Makefile` regroupe les commandes utiles (`install`, `test`, `run-api`,
`demo`, `train`, `lint`, `docker-up`, `docker-down`). Guide complet (variables
d'environnement, bascule SQLite ↔ PostgreSQL, accès au dashboard) :
[`docs/DEPLOIEMENT.md`](docs/DEPLOIEMENT.md).

## Structure

```
src/
  common/            # contrats partagés (schemas, config, database, logging)
  bloc1_scan/        # scan de vulnérabilités
  bloc2_phishing/    # collecte & prétraitement phishing
  bloc3_ia/          # moteur IA (phishing + scoring vuln)
  bloc4_correlation/ # corrélation & alertes
  bloc5_dashboard/   # API + frontend
  pipeline.py        # orchestration end-to-end
data/samples/        # données d'exemple (contexte CM)
docs/                # mémoire (.docx) + architecture (.drawio)
tests/               # tests unitaires
```

## Avertissement éthique

Les outils de scan ne doivent être utilisés que sur des systèmes pour lesquels
vous disposez d'une **autorisation écrite**. Les données phishing servent
uniquement à la recherche défensive.
