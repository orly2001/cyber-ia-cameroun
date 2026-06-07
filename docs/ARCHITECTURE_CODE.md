# Architecture du code — IA & Cybersécurité Cameroun

Document technique synthétique (≈1 page) destiné à l'équipe de développement.
Il décrit la structure du code, le flux de données entre les 5 blocs et la
manière de lancer chaque partie.

## 1. Structure des paquets

```
cyber-ia-cameroun/
├── src/
│   ├── common/              # Contrats partagés (le « ciment » du système)
│   │   ├── schemas.py       # Modèles Pydantic : Vulnerability, PhishingSample,
│   │   │                    #   PhishingPrediction, VulnScore, Alert + enums
│   │   ├── config.py        # Settings (.env), chemins, URL BDD, seuils
│   │   ├── database.py      # SQLAlchemy : AlertORM, engine, SessionLocal, init_db
│   │   └── logging_conf.py  # get_logger() uniforme
│   ├── bloc1_scan/          # Scan de vulnérabilités  -> Vulnerability[]
│   │   ├── scanner.py       # run_scan(targets, demo=False)  (point d'entrée)
│   │   ├── nmap_scanner.py  # wrapper python-nmap (lazy import)
│   │   ├── zap_scanner.py   # wrapper OWASP ZAP (lazy import)
│   │   ├── cve_enrichment.py# enrichissement NVD (requests, lazy import)
│   │   └── sample_data.py   # demo_vulnerabilities() pour le mode démo
│   ├── bloc2_phishing/      # Collecte & prétraitement -> PhishingSample[]
│   │   ├── loader.py        # load_samples(path=None) (pandas, lazy import)
│   │   └── preprocessing.py # preprocess(samples) (stdlib uniquement)
│   ├── bloc3_ia/            # Moteur IA -> PhishingPrediction[] + VulnScore[]
│   │   ├── phishing_detector.py # PhishingDetector (TF-IDF+RF + repli heuristique)
│   │   ├── bert_detector.py     # BertPhishingDetector (transformers, lazy)
│   │   ├── vuln_scorer.py       # VulnScorer (RF/XGBoost + repli heuristique)
│   │   └── train.py             # script d'entraînement du détecteur
│   ├── bloc4_correlation/   # Corrélation -> Alert[]
│   │   ├── rules.py         # règles déclaratives R1..R4 (logique pure)
│   │   ├── risk_engine.py   # compute_risk() -> score composite [0..100]
│   │   ├── correlator.py    # correlate(...) (point d'entrée)
│   │   └── persistence.py   # persist_alerts(alerts) (upsert idempotent)
│   ├── bloc5_dashboard/api/ # API REST FastAPI (lecture des alertes)
│   │   ├── main.py          # endpoints /api/alerts, /api/stats, /api/run-demo
│   │   └── schemas_api.py   # AlertUpdate, StatsResponse, RunDemoResponse
│   └── pipeline.py          # Orchestration end-to-end (run_pipeline / run_demo)
├── data/samples/            # phishing_samples_cm.csv, scan_targets.txt
├── tests/                   # tests pytest (schemas, corrélation, pipeline démo)
└── pytest.ini               # pythonpath = . pour résoudre "import src..."
```

## 2. Flux de données

```
Bloc 1 (scan)      --run_scan-->            Vulnerability[]
Bloc 3 (scoring)   --VulnScorer.score-->    VulnScore[]
Bloc 2 (phishing)  --load_samples+preprocess--> PhishingSample[]
Bloc 3 (détection) --PhishingDetector.predict--> PhishingPrediction[]
Bloc 4 (corrél.)   --correlate-->           Alert[]   --persist_alerts--> BDD
Bloc 5 (dashboard) <--lecture (AlertORM)--  Alert[]   (API FastAPI)
```

`src/pipeline.py` enchaîne ces étapes. Tous les modèles échangés sont définis
**une seule fois** dans `src/common/schemas.py` : c'est l'interface contractuelle
entre blocs, à ne pas modifier sans accord d'équipe.

### Principes transverses
- **Imports paresseux** : sklearn, xgboost, transformers, torch, nmap, zapv2,
  requests et pandas ne sont jamais importés au niveau module. Chaque module
  reste donc importable sans ces dépendances.
- **Replis heuristiques** : les blocs 1 (données démo) et 3 (heuristiques
  phishing & scoring) fonctionnent sans modèle entraîné ni accès réseau, ce qui
  garantit que `run_pipeline(demo=True)` produit des alertes hors-ligne.
- **Tolérance aux pannes** : scanners, enrichissement NVD et persistance BDD
  journalisent et renvoient un résultat neutre (liste vide / 0) au lieu de lever.

## 3. Comment lancer chaque partie

Prérequis : `python -m venv .venv` puis `pip install -r requirements.txt`
(les paquets BERT — transformers/torch — sont optionnels et lourds).

| Action | Commande |
| --- | --- |
| Pipeline en démo (hors-ligne) | `python -m src.pipeline --demo` |
| Pipeline sur cibles réelles*  | `python -m src.pipeline --targets 127.0.0.1 http://exemple.cm` |
| Pipeline sans persistance     | `python -m src.pipeline --demo --no-persist` |
| Entraîner le détecteur phishing | `python -m src.bloc3_ia.train` |
| Démarrer l'API (bloc 5)        | `uvicorn src.bloc5_dashboard.api.main:app --reload` |
| Lancer les tests               | `pytest` |

\* *Éthique & légal : ne scannez que des cibles pour lesquelles vous disposez
d'une autorisation écrite (loi camerounaise n°2010/012 sur la cybersécurité).*

## 4. Base de données

- Repli **SQLite** activé par défaut (`use_sqlite_fallback=True`) :
  `data/soc_dev.db`. Aucune installation requise pour le dev.
- **PostgreSQL** en production : régler `USE_SQLITE_FALLBACK=false` et
  `DATABASE_URL` dans `.env`. Les tables sont créées par `init_db()` (appelé au
  démarrage de l'API et avant chaque persistance d'alertes).
