# PLAN DE REFONTE — ANALYSTE-PROGRAMMEUR INDÉPENDANT N°2
## Projet « IA & Cybersécurité Cameroun » — vers un outil de production

> Document d'ANALYSE et de PLAN uniquement. Aucune modification de code n'est
> effectuée ici. Rédigé indépendamment du second analyste. Date : 2026-06-07.
> Objectif client révisé : outil CONCRET (entreprise + usagers), modèle entraîné
> sur de VRAIS datasets, déployé/servi, analyse temps réel (logs en direct),
> upload de fichiers pour test/analyse.

---

## 0. Synthèse exécutive (à lire en premier)

Le socle actuel est **propre, testé (42 verts), bien découplé** (contrats Pydantic,
imports paresseux, repli heuristique partout). Mais il a été conçu comme une
**démo pédagogique batch**, pas comme un **service d'inférence**. Les trois piliers
de la nouvelle vision — *modèle servi en ligne*, *temps réel*, *upload* — sont
**absents** côté API et frontend, et la **stratégie données réelles** n'est
qu'amorcée (un seul CSV UCI, 100 % anglais, déséquilibré). La refonte est donc
surtout **additive** (peu de réécriture), à condition de **figer les contrats**
`schemas.py` et de réutiliser `PhishingDetector` tel quel pour l'inférence.

Décision N°2 majeure (divergence assumée d'une approche naïve « tout BERT ») :
**garder TF-IDF + Régression Logistique calibrée comme modèle SERVI par défaut**,
BERT optionnel hors ligne. Raisons : la sandbox bloque le réseau lourd, le corpus
réel est petit (~1 300 lignes), la latence/CPU comptent pour du temps réel, et une
LogReg calibrée donne des **probabilités fiables** indispensables au réglage du
seuil anti-faux-positifs.

---

## 1. Évaluation critique de l'architecture actuelle

### 1.1 Forces (à préserver)
- **Contrats partagés Pydantic v2** (`src/common/schemas.py`) : `PhishingSample`,
  `PhishingPrediction`, `Alert`… colonne vertébrale qui fait tenir les 5 blocs.
  `PhishingPrediction` est **déjà prêt pour l'inférence en ligne** (sample_id,
  is_phishing, score, model).
- **Imports paresseux systématiques** (sklearn, torch, pandas, joblib) : modules
  importables sans deps lourdes → tests rapides, déploiement léger possible.
- **Repli heuristique** (`phishing_detector._predict_heuristic`,
  `vuln_scorer._score_heuristic`) : le pipeline ne casse jamais. À conserver comme
  filet de sécurité de PRODUCTION (modèle absent/corrompu), pas seulement démo.
- **Persistance idempotente** des alertes (`bloc4/persistence.py`, upsert par id
  stable) : base saine pour ajouter d'autres entités.
- **Sécurité API amorcée** : `require_api_key`, en-têtes `X-Content-Type-Options`
  / `X-Frame-Options`, CORS configurable. Comparaison de clé en temps constant.
- **Prétraitement local pertinent** (`bloc2/preprocessing.py`) : tokens
  `<URL>/<PHONE>/<MONEY>`, gestion FCFA et numéros 237. Atout différenciant CM.

### 1.2 Faiblesses / écarts face à « outil de production »
| # | Écart | Impact vision | Gravité |
|---|-------|---------------|---------|
| F1 | **Aucun endpoint d'inférence** : l'API ne sert que des alertes en lecture + `run-demo`. Le modèle entraîné n'est jamais exposé. | Bloque « modèle déployé/servi ». | CRITIQUE |
| F2 | **Pas d'upload de fichiers** (FastAPI `UploadFile` absent). | Bloque « upload pour test/analyse ». | CRITIQUE |
| F3 | **Pas de temps réel** (aucun SSE/WebSocket, frontend en polling manuel `refreshAll()`). | Bloque « analyse temps réel ». | CRITIQUE |
| F4 | **Données réelles minimales** : 1 seul CSV UCI (1064 lignes, **100 % EN**, **15 % spam** → déséquilibré), aucune source FR ni URL/phishing réel. Le `train.py` préfère même le corpus *synthétique* au réel. | Contredit « entraîné sur de vrais datasets ». | HAUTE |
| F5 | **Modèle servi non chargé au démarrage** : aucune init du détecteur dans l'API ; rechargement joblib à chaque requête prévu nulle part. | Latence/temps réel. | HAUTE |
| F6 | **Pas de calibration des probabilités** : RandomForest renvoie des `predict_proba` mal calibrés → un seuil 0.5 fixe et un score peu fiable pour l'UX et l'anti-FP. | Qualité décisionnelle. | HAUTE |
| F7 | **Pas de versionnage/métadonnées de modèle** (date, métriques, n_samples, hash données). Un seul `.joblib` écrasé. | Traçabilité prod / rollback. | MOYENNE |
| F8 | **Pas d'évaluation sur split tenu à l'écart** : `train.py` évalue sur les MÊMES données d'entraînement (`detector.predict(labeled)`) → métriques optimistes, **fuite**. | Crédibilité des chiffres démo. | HAUTE |
| F9 | **Frontend mono-vue** (alertes), pas de zone upload ni flux live. CDN Chart.js externe (offline KO en démo). | UX entreprise. | MOYENNE |
| F10 | **`run-demo` non protégé côté UX** mais `require_api_key` désactivé si clé vide (mode permissif). En prod c'est un trou. | Sécurité. | MOYENNE |
| F11 | **Couplage seuil global** `settings.phishing_threshold` (0.5) partagé par tous les modèles, non réglable par canal. | Anti-FP fin. | MOYENNE |

### 1.3 Dette technique ciblée
- `train.py` : logique de sélection de corpus à inverser (réel d'abord), et
  évaluation à déplacer sur un test split.
- `@app.on_event("startup")` est **déprécié** en FastAPI récent → migrer vers
  `lifespan` (occasion d'y charger le modèle).
- `_URL_RE`/`_PHONE_RE` agressifs : le regex téléphone peut avaler des suites de
  chiffres anodines (faux `<PHONE>`). À surveiller sur données EN réelles.

### 1.4 Sur-/sous-dimensionné
- **Sur-dimensionné** : `bert_detector.py` (170 lignes Trainer + boucle PyTorch)
  pour un corpus de ~1 300 lignes et une sandbox sans torch — c'est du « nice to
  have » qui détourne l'effort. **Le garder mais le déprioriser**.
- **Sur-dimensionné** : `xgboost` dans `vuln_scorer` (faiblement supervisé par
  pseudo-labels heuristiques → n'apprend rien d'utile au-delà de l'heuristique).
- **Sous-dimensionné** : tout le **service d'inférence** (F1–F3), le **catalogue
  de données réelles** (F4) et l'**observabilité modèle** (F7/F8).

---

## 2. Stratégie DONNÉES

### 2.1 Constat chiffré
- Réel disponible : `data/external/sms_spam_collection.csv` = **1064** lignes,
  **904 ham / 160 spam (15,0 %)**, **100 % anglais**, source UCI.
- Synthétique : `phishing_corpus_synth.csv` = 240 lignes, parfaitement équilibré,
  FR-dominant, contexte MoMo CM. Utile mais **ne doit jamais dominer** le réel.
- Problème : un modèle entraîné majoritairement EN/UCI **généralisera mal** aux
  SMS FR camerounais → besoin de sources FR réelles + dataset terrain CM.

### 2.2 Sources réelles recommandées (URLs + licences + mode d'acquisition)
Acquisition via **`web_fetch` sur fichiers bruts** (requests bloqué 403). Toujours
écrire le CSV final via **bash heredoc** (anti-désync sur gros fichiers).

| Source | Contenu | URL brute (raw) | Licence | Note |
|--------|---------|-----------------|---------|------|
| **UCI SMS Spam** (déjà là) | 5574 SMS EN, ham/spam | déjà ingéré | CC BY 4.0 (Almeida & Hidalgo) | Élargir à 5574 (on n'en a que 1064). |
| **PhishTank** (URLs phishing vérifiées) | URLs phishing réelles | `http://data.phishtank.com/data/online-valid.csv` | Usage gratuit, attribution requise | Alimente le canal **URL** (manque total aujourd'hui). |
| **OpenPhish community feed** | URLs phishing live | `https://openphish.com/feed.txt` | Gratuit non-commercial (community) | Texte brut une URL/ligne → label=1, channel=URL. |
| **Kaggle « Phishing Email »** (ex. `subhajournal/phishingemails`) | E-mails phishing/ham EN | via Kaggle API (token) ou export CSV | CC0 / variable selon dataset | Alimente le canal **EMAIL**. Vérifier licence par dataset. |
| **SpamAssassin public corpus** | E-mails ham/spam (mbox) | `https://spamassassin.apache.org/old/publiccorpus/` | Apache-2.0 | Robuste, gros volume EMAIL ; parsing mbox requis. |
| **Mendeley / `Nazario` phishing corpus** | E-mails phishing réels | dépôts académiques (Mendeley Data) | CC BY | Diversité d'attaques EMAIL. |
| **Tranco list** (domaines légitimes) | Top domaines bénins | `https://tranco-list.eu/` | Académique gratuit | Source de NÉGATIFS URL pour équilibrer PhishTank/OpenPhish. |

> Si une source est inaccessible dans la sandbox → **fallback génération**
> (`corpus_generator`) UNIQUEMENT pour combler, jamais comme source primaire.

### 2.3 Schéma canonique & fusion multi-sources
Cible : **`data/processed/phishing_dataset.csv`** au format contractuel existant
`id,channel,raw_text,language,label,source` (déjà respecté par UCI). Un nouveau
module **`src/bloc2_phishing/datasets.py`** centralise :
- `fetch_<source>()` : téléchargement raw (web_fetch) → fichier dans `data/external/`.
- `normalize_<source>()` : mapping vers le schéma canonique + détection de langue
  (heuristique légère FR/EN sans dépendance lourde, ou `langid`/`fasttext-lid`
  optionnel et paresseux).
- `merge_sources([...]) -> data/processed/phishing_dataset.csv`.

### 2.4 Qualité, anti-fuite, split propre
- **Dédoublonnage** : clé = `clean_text` normalisé (réutiliser `preprocessing.clean_text`)
  + hash SHA1. Supprimer doublons EXACTS *inter-sources* (URLs PhishTank vs OpenPhish
  se recoupent). Conserver la première occurrence (source la plus fiable d'abord).
- **Anti-fuite (fuite de split)** : faire le **split AVANT** toute sur-représentation
  ou augmentation ; garantir qu'un même texte/URL/domaine n'apparaît pas à la fois
  en train et en test (split **par domaine** pour les URLs). Split stratifié
  `train/val/test = 70/15/15` sur (label × channel × language). **Graine fixe 42**
  et fichiers `*_train.csv / *_val.csv / *_test.csv` versionnés (ou indices figés).
- **Équilibrage** : UCI est à 15 % de spam. Stratégie : **class_weight='balanced'**
  côté modèle (déjà présent) + éventuel **sous-échantillonnage léger** des négatifs
  EN pour éviter qu'ils écrasent le signal FR/MoMo. NE PAS suréchantillonner
  naïvement le texte (fuite si avant split).
- **Couverture FR/CM** : injecter le corpus synthétique CM **et** viser une collecte
  terrain (cf. 2.5). Cible : ≥ 30 % d'exemples FR dans train.

### 2.5 Dataset camerounais (terrain)
- Créer **`data/external/phishing_cm_terrain.csv`** (même schéma, `source=terrain`)
  alimenté par : contributions anonymisées d'usagers (capture d'écran → texte),
  signalements opérateurs, et le CSV `phishing_samples_cm.csv` existant promu au
  rang de « seed terrain ». **Anonymisation obligatoire** (masquage tel/montant via
  le préprocesseur). Documenter provenance et consentement.

### 2.6 Politique de fallback génération (règle dure)
1. Tenter toutes les sources réelles → fusion.
2. Si une classe/canal/langue est **sous le seuil minimal** (ex. < 50 exemples),
   compléter avec `generate_corpus()` **marqué `source=synthetic`**.
3. **Plafond synthétique : ≤ 25 % du train**. Logguer le ratio réel/synthétique.
4. Le rapport de modèle DOIT afficher ce ratio (transparence client).

---

## 3. Stratégie MODÈLE

### 3.1 Choix et justification (divergence N°2)
**Modèle SERVI par défaut : `TfidfVectorizer(1-2 grammes, sublinear) +
LogisticRegression(class_weight='balanced')` enveloppé d'un `CalibratedClassifierCV`
(sigmoïde) ou `RandomForest` calibré.**

Justification vs « BERT multilingue partout » :
- **Latence temps réel** : LogReg/TF-IDF infère en ~ms sur CPU → adapté au flux
  live et à l'upload de gros fichiers. BERT CPU = centaines de ms/échantillon.
- **Probabilités calibrées** : LogReg + calibration donne des scores interprétables
  (essentiels pour le seuil anti-FP et l'affichage « 87 % phishing »). RF non
  calibré (état actuel) sort des proba tassées → mauvais réglage de seuil.
- **Petit corpus** : ~1 300 lignes réelles → un transformer sur-apprend ou exige
  fine-tuning instable ; TF-IDF est robuste et reproductible.
- **Sandbox sans réseau lourd** : torch/transformers non garantis → BERT reste un
  **chemin optionnel hors ligne** (`bert_detector` conservé tel quel).

> Note d'implémentation : `PhishingDetector` actuel code RandomForest en dur. La
> tâche T7 propose de rendre le classifieur configurable et d'ajouter la
> calibration, **sans casser** la signature `train()/predict()/save()/load()`.

### 3.2 Métriques cibles réalistes (sur TEST tenu à l'écart)
- **F1 (classe phishing) ≥ 0,90** sur SMS EN (UCI est « facile »).
- **F1 ≥ 0,80** sur le sous-ensemble FR/CM (plus dur, peu de données).
- **Precision ≥ 0,92** au seuil opérationnel (priorité anti-FP : un faux positif
  qui bloque un vrai SMS MoMo est coûteux côté usager).
- **Recall phishing ≥ 0,85**.
- **ROC-AUC ≥ 0,95** global. Rapporter aussi **PR-AUC** (corpus déséquilibré).

### 3.3 Calibration & gestion des faux positifs
- **Calibration** : `CalibratedClassifierCV(method='sigmoid', cv=5)` sur le train,
  vérifiée par **courbe de fiabilité** + **Brier score** sur val.
- **Seuil** : ne PAS garder 0.5 en dur. Choisir le seuil **maximisant la précision
  sous contrainte recall ≥ 0,85** sur la val, puis le persister dans les métadonnées
  du modèle. Exposer un **seuil par canal** (SMS plus strict que URL) en remplaçant
  l'usage direct de `settings.phishing_threshold` par un seuil porté par le modèle.
- **Zone grise** : scores dans [seuil-0,1 ; seuil+0,1] → statut « À VÉRIFIER »
  plutôt que binaire dur, surfacé dans l'UI.

### 3.4 Persistance & versionnage
- Conserver `joblib` mais **emballer un artefact riche** :
  `models/phishing/<timestamp>/model.joblib` + `metadata.json`
  (`model_type, threshold_per_channel, metrics_test, n_train, n_synth_ratio,
  data_hash, sklearn_version, trained_at, git_sha?`).
- Pointeur stable **`models/phishing/current`** (copie ou lien) chargé par l'API.
- Permet **rollback** et affichage de la version servie dans le dashboard (`/api/model/info`).

---

## 4. Conception INFÉRENCE & UPLOAD & TEMPS RÉEL

### 4.1 Nouveau sous-module `src/bloc3_ia/inference.py`
- Singleton **`get_detector()`** : charge `models/phishing/current` une fois
  (lazy + cache module), repli heuristique si absent. Réutilise `PhishingDetector`.
- `analyze_text(text, channel, language) -> PhishingPrediction (+ clean_text, reasons)`.
- `analyze_batch(samples) -> list[PhishingPrediction]`.
- `reasons` : top features TF-IDF contributives (explicabilité légère pour l'UI).

### 4.2 Contrats d'API (nouveaux endpoints, bloc 5)
Fichier `schemas_api.py` étendu + routes dans `main.py` (ou `routers/inference.py`).

```
POST /api/analyze                      # texte unitaire
  body: {raw_text, channel?, language?}
  -> {sample_id, is_phishing, score, model, threshold, clean_text, reasons[]}

POST /api/analyze/batch                # liste de messages
  body: {items: [{raw_text, channel?, language?}, ...]}   # max 1000
  -> {results: [PhishingPrediction-like...], summary: {n, n_phishing}}

POST /api/upload                       # fichier CSV/TXT/log
  multipart: file
  -> {job_id?, n_lines, results[...] | streamed}          # voir 4.4

GET  /api/model/info                   # version, métriques, seuils servis
GET  /api/stream/live  (SSE)           # flux temps réel (voir 4.3)

# Endpoints sensibles (analyse de masse, upload) protégés par require_api_key
# dès qu'API_KEY est définie ; rate-limit applicatif simple.
```

### 4.3 Temps réel — choix : **SSE** (Server-Sent Events)
Divergence N°2 : préférer **SSE** à WebSocket. Raisons : unidirectionnel
(serveur→UI) suffit pour un flux de logs analysés, plus simple à servir derrière
FastAPI (`StreamingResponse`), reconnexion native navigateur, pas de handshake WS.
- `GET /api/stream/live` émet un événement par log analysé :
  `{ts, raw_text, channel, score, is_phishing, model}`.
- **Source du flux (simulation demandée)** : un générateur côté serveur rejoue,
  à cadence configurable (ex. 1–3 msg/s), un mélange réel+synthétique du test set
  (jamais de données sensibles), passe chaque ligne dans `analyze_text`, émet le
  résultat, et **persiste les cas phishing** comme `PhishingSample`+`PhishingPrediction`
  (pour alimenter bloc4/alertes — cf. §5).
- Backpressure : file bornée, drop-oldest si client lent.

### 4.4 Upload — contrats & sécurité
- Types autorisés : `.csv`, `.txt`, `.log` (+ `text/csv`, `text/plain`).
- **Taille max** : 5 Mo (config `max_upload_bytes`), refus 413 au-delà ; lecture
  **en streaming** (ne pas charger tout en RAM).
- **Nombre de lignes max** : 5 000 par upload (au-delà → 422 + conseil batch/job).
- **Anti-abus** : `require_api_key` si configurée ; rate-limit (ex. 10 uploads/min/IP,
  simple compteur en mémoire ou slowapi) ; sanitation : on ne stocke jamais le
  fichier brut sur disque sans nettoyage ; encodage forcé UTF-8 avec fallback latin-1.
- **Sécurité contenu** : pas d'exécution, parsing CSV via `csv`/`pandas` en lecture
  seule ; rejet des colonnes inattendues ; troncature des `raw_text` > 5 000 chars.
- Réponse : tableau de prédictions + résumé (n, % phishing, top suspects), option
  **téléchargement du CSV annoté**.

### 4.5 UX Dashboard (refonte `frontend/index.html`)
Trois zones (onglets ou sections) :
1. **Live** : flux SSE défilant (badge score coloré, canal, horodatage), compteur
   temps réel phishing/min, bouton start/stop de la simulation.
2. **Analyse** : zone de saisie texte + sélecteur canal → résultat instantané
   (score, verdict, raisons, seuil servi).
3. **Upload** : drag & drop fichier → barre de progression → tableau résultats +
   export annoté.
4. **Alertes** (existant) + **bandeau version modèle** (`/api/model/info`).
Détails : **héberger Chart.js en local** (offline), conserver le repli démo,
afficher l'état de connexion SSE.

---

## 5. Intégration au reste du système

- **Bloc 4 (corrélation)** : les prédictions issues du live/upload doivent pouvoir
  alimenter `correlate()`. Plan : la simulation live persiste les `PhishingSample`
  + `PhishingPrediction` phishing dans une table (nouvelle `PhishingEventORM`),
  puis un déclencheur périodique (ou bouton) relance `correlate()` avec les
  vulnérabilités courantes → règle **R2 (pic SMS MoMo)** se déclenche naturellement
  sur un afflux live. Aucun changement aux règles nécessaire.
- **Alertes/persistance (bloc 5)** : réutiliser `persist_alerts` tel quel.
  Ajouter `PhishingEventORM` (id, channel, raw_text, score, is_phishing, model,
  created_at) pour historiser le flux et le rendre interrogeable
  (`GET /api/events?is_phishing=true`).
- **Contrats** : NE PAS modifier `schemas.py`. Tout nouvel objet API vit dans
  `schemas_api.py`. C'est la garantie de non-régression des 42 tests.
- **Config** : ajouter à `config.py` : `max_upload_bytes`, `max_upload_lines`,
  `live_rate_per_sec`, `model_dir`, `synthetic_max_ratio` — avec valeurs par défaut.

---

## 6. Découpage en TÂCHES atomiques (1 tâche = 1 agent)

Ordre = dépendances. Chaque tâche a des **critères d'acceptation testables**.
Convention : ne pas casser les 42 tests existants (régression = blocage).

### Lot A — Données (peut démarrer immédiatement)
- **T1. Étendre l'ingestion UCI au corpus complet (5574)** *(dépend: —)*
  - Livrable : `data/external/sms_spam_collection.csv` complété ; loader inchangé.
  - Accept. : ≥ 5000 lignes, schéma intact, `load_samples` charge sans erreur,
    distribution labels logguée.
- **T2. Module `datasets.py` : fetch + normalize PhishTank/OpenPhish (URL)** *(dépend: —)*
  - Livrable : `src/bloc2_phishing/datasets.py` (fetch via web_fetch, normalize
    vers schéma canonique, label=1 channel=URL ; négatifs via Tranco).
  - Accept. : test offline avec **fixture** (pas de réseau) ; `normalize_*` mappe
    correctement ; gestion d'échec réseau → retour vide + log.
- **T3. Fusion + dédoublonnage + split stratifié anti-fuite** *(dépend: T1,T2)*
  - Livrable : `merge_sources()` → `data/processed/phishing_dataset_{train,val,test}.csv`.
  - Accept. : aucun doublon de `clean_text` inter-split ; aucune URL/domaine
    partagé train↔test ; ratios 70/15/15 ; graine 42 reproductible ; ratio
    synthétique ≤ 25 % loggué.

### Lot B — Modèle (dépend de Lot A pour les données réelles)
- **T4. Corriger l'évaluation sur split tenu à l'écart** *(dépend: T3)*
  - Livrable : `train.py` évalue sur `*_test.csv`, plus jamais sur le train.
  - Accept. : métriques calculées sur test ; régression interdite ; rapport imprimé.
- **T5. Classifieur configurable + calibration** *(dépend: T3)*
  - Livrable : `PhishingDetector` accepte `estimator='logreg'|'rf'`,
    enveloppe `CalibratedClassifierCV`, signatures inchangées.
  - Accept. : `predict_proba` calibré (Brier < baseline RF), tests unitaires
    train/predict toujours verts.
- **T6. Sélection de seuil par canal + métadonnées modèle** *(dépend: T5)*
  - Livrable : choix de seuil sur val (precision sous recall≥0.85), `metadata.json`,
    arbo `models/phishing/<ts>/` + pointeur `current`.
  - Accept. : `metadata.json` complet ; seuil persisté et relu ; `/api/model/info`
    expose la version.
- **T7. Entraînement réel & rapport de référence** *(dépend: T4,T5,T6)*
  - Livrable : modèle entraîné sur données réelles, rapport métriques test.
  - Accept. : F1 SMS EN ≥ 0,90 ; ROC-AUC ≥ 0,95 ; PR-AUC rapporté ; ratio
    réel/synthétique documenté.

### Lot C — Inférence & API (dépend de Lot B)
- **T8. `inference.py` (singleton détecteur + analyze_text/batch + reasons)** *(dépend: T6)*
  - Accept. : charge `current`, repli heuristique si absent ; `analyze_text`
    retourne score+reasons ; tests unitaires.
- **T9. Endpoints `/api/analyze` + `/api/analyze/batch` + `/api/model/info`** *(dépend: T8)*
  - Accept. : 200 + schéma respecté ; batch borné à 1000 (422 au-delà) ; tests API.
- **T10. `/api/upload` (sécurité taille/type/lignes + CSV annoté)** *(dépend: T8)*
  - Accept. : refus 413 > 5 Mo, 422 > 5000 lignes, 415 type invalide ; CSV valide
    → résultats ; tests avec petits fichiers fixtures.
- **T11. `/api/stream/live` SSE + simulateur + `PhishingEventORM`** *(dépend: T8)*
  - Accept. : flux émet ≥ N événements ; cadence configurable ; cas phishing
    persistés ; test consommant le stream quelques secondes.
- **T12. Migration `startup` → `lifespan` + préchargement modèle** *(dépend: T8)*
  - Accept. : modèle chargé une fois au boot ; aucun warning de dépréciation.

### Lot D — Intégration & UX (dépend de Lot C)
- **T13. Brancher live/upload sur bloc4 (corrélation déclenchable)** *(dépend: T11)*
  - Accept. : afflux SMS MoMo live → R2 déclenche une alerte persistée.
- **T14. Refonte frontend (Live + Analyse + Upload + version modèle, Chart.js local)** *(dépend: T9,T10,T11)*
  - Accept. : 3 sections fonctionnelles contre l'API locale ; repli démo conservé ;
    aucune dépendance CDN bloquante.
- **T15. Durcissement sécurité prod (rate-limit, API_KEY obligatoire en prod)** *(dépend: T9,T10)*
  - Accept. : endpoints sensibles refusent sans clé si `environment=production` ;
    rate-limit testé.

### Lot E — Qualité
- **T16. Tests d'intégration end-to-end + charge légère** *(dépend: Lot C/D)*
  - Accept. : voir §7.

---

## 7. Plan de TEST & VALIDATION

### 7.1 Unitaires (étendre `tests/`)
- `test_datasets.py` : normalize_* (fixtures), dédoublonnage, split anti-fuite
  (aucun chevauchement train/test), ratio synthétique plafonné.
- `test_inference.py` : singleton, repli heuristique sans modèle, reasons non vides.
- `test_calibration.py` : Brier calibré < Brier non calibré ; seuil persisté relu.

### 7.2 Intégration (FastAPI `TestClient`/`httpx`)
- `test_analyze_api.py` : `/api/analyze` (verdict cohérent sur message MoMo connu),
  `/api/analyze/batch` (borne 1000), `/api/model/info`.
- `test_upload_api.py` : CSV valide ok ; > taille → 413 ; > lignes → 422 ; type
  invalide → 415.
- `test_stream.py` : ouvrir SSE, recevoir ≥ 3 événements, statut 200, fermeture propre.
- `test_e2e_live_to_alert.py` : simuler afflux MoMo → vérifier alerte R2 persistée.

### 7.3 Charge légère
- 1000 messages via `/api/analyze/batch` < 2 s (CPU) ; upload 5 000 lignes < 5 s ;
  SSE stable 60 s sans fuite mémoire (suivi RSS).

### 7.4 Critères « prêt pour démo entreprise »
1. Modèle réel chargé au boot, version visible dans le dashboard.
2. `/api/analyze` renvoie verdict+score calibré+raisons sur saisie libre.
3. Upload CSV → tableau annoté + export, en < 5 s pour 5 000 lignes.
4. Vue **Live** : flux défilant temps réel, compteur phishing/min, start/stop.
5. Afflux live MoMo → alerte corrélée apparaît dans la table d'alertes.
6. Sécurité : clé d'API exigée en prod, limites upload appliquées.
7. Métriques test publiées (F1≥0.90 EN, ROC-AUC≥0.95) + ratio réel/synthétique.
8. Suite de tests verte (42 existants + nouveaux), zéro warning de dépréciation.

---

## 8. Synthèse finale (décisions clés, divergences, ordre)

1. **Refonte additive, pas réécriture** : figer `schemas.py`, réutiliser
   `PhishingDetector`/`correlate`/`persist_alerts` ; tout le neuf passe par
   `schemas_api.py`, `inference.py`, `datasets.py` et de nouvelles routes.
2. **Divergence modèle** : modèle SERVI = **TF-IDF + LogReg calibrée** (proba
   fiables, latence ms, robuste sur petit corpus) ; **BERT reste optionnel
   hors ligne** — contre l'intuition naïve « BERT partout », inadaptée à la
   sandbox et au temps réel CPU.
3. **Divergence temps réel** : **SSE** plutôt que WebSocket (flux unidirectionnel,
   plus simple à servir et reconnexion native).
4. **Données d'abord** : inverser la priorité de `train.py` (réel > synthétique),
   plafonner le synthétique à 25 %, ajouter URL (PhishTank/OpenPhish) et EMAIL
   (SpamAssassin/Kaggle), viser ≥30 % FR, dataset terrain CM anonymisé.
5. **Corriger la fuite d'évaluation** (T4) et **calibrer** (T5/T6) avant d'annoncer
   des chiffres : sinon métriques optimistes non crédibles en démo.
6. **Anti-FP par le seuil** : seuil choisi sous contrainte recall, par canal,
   persisté dans les métadonnées du modèle (fin de `phishing_threshold` en dur).
7. **Ordre d'exécution recommandé** : Lot A (T1→T3) ∥ démarrage rapide →
   Lot B (T4→T7) → Lot C (T8→T12) → Lot D (T13→T15) → Lot E (T16).
   Chemin critique : **T3 → T6 → T8 → {T9,T10,T11} → T14**.
8. **Garde-fou permanent** : 42 tests verts + repli heuristique conservé comme
   filet de PRODUCTION, pas seulement de démo.
