# Plan de refonte — Analyste-Programmeur N°1

Projet : **IA & Cybersécurité Cameroun** — `C:\Users\yvanj\Desktop\cyber-ia-cameroun`
Auteur : Analyste-Programmeur indépendant N°1
Date : 2026-06-07
Statut : document de PLAN (aucune modification de code dans ce livrable)

> Objectif du client (nouvelle vision) : transformer le projet en **outil concret**
> utilisable par une entreprise et ses usagers, avec un modèle **entraîné sur de
> vrais datasets téléchargés**, **déployé et servi**, capable d'**analyse en temps
> réel** (logs entrants simulés) et d'**analyse de fichiers uploadés**.

---

## 0. Contexte technique vérifié (contraintes dures)

- Sandbox Linux, Python 3.10. `requests`/`urllib` DIRECTS sont **bloqués** (proxy 403).
  Seul `mcp__workspace__web_fetch` récupère des fichiers bruts (ex. `raw.githubusercontent.com`).
  → Le code (downloader) DOIT utiliser `requests` (marche en prod réseau ouvert) ET
  prévoir un fallback. Pour l'entraînement **ici/maintenant**, on s'appuie sur des
  datasets déjà récupérés via `web_fetch` et déposés dans `data/external/`.
- Vrai dataset déjà en place : `data/external/sms_spam_collection.csv`
  (1064 SMS réels labellisés ; colonnes `id,channel,raw_text,language,label,source` ;
  source UCI SMS Spam Collection ; déjà au format `PhishingSample`).
- L'outil d'écriture peut désynchroniser le montage sur **gros fichiers** →
  écrire les gros fichiers via **bash heredoc**.
- 42 tests pytest au vert — toute refonte doit **rester verte** (ne pas casser
  `src/common/schemas.py`, contrat inter-blocs).

---

## 1. Diagnostic : écart entre l'existant et la nouvelle vision

### 1.1 Ce qui existe déjà (réutilisable, ne pas réécrire)

| Brique | Fichier | État |
|---|---|---|
| Contrats Pydantic | `src/common/schemas.py` | OK — `PhishingSample` a déjà `source` libre (`phishtank|openphish|kaggle|terrain`), `Channel` = SMS/EMAIL/URL. Suffisant. |
| Chargement CSV → `PhishingSample` | `src/bloc2_phishing/loader.py` | OK, tolérant (labels manquants, canal inconnu). Réutilisable tel quel pour les datasets externes au bon format. |
| Prétraitement FR/EN SMS CM | `src/bloc2_phishing/preprocessing.py` | OK, normalise `<URL>/<PHONE>/<MONEY>`. À conserver. |
| Détecteur TF-IDF + RF + repli heuristique | `src/bloc3_ia/phishing_detector.py` | OK — `train/predict/save/load` + heuristique. Base solide. |
| Détecteur BERT (lazy) | `src/bloc3_ia/bert_detector.py` | OK — option lourde, déjà câblée. |
| Évaluation manuelle | `src/bloc3_ia/evaluation.py` | OK (accuracy/precision/recall/F1/CM). |
| Script d'entraînement | `src/bloc3_ia/train.py` | Partiel — pas de **split train/val/test**, évalue en **train=test** (sur-optimiste), pas de versionnage d'artefacts, ne lit que `data/samples/`. |
| API alertes + stats | `src/bloc5_dashboard/api/main.py` | OK pour les alertes ; **aucun endpoint d'inférence/upload/temps réel**. |
| Frontend dashboard | `src/bloc5_dashboard/frontend/index.html` | Statique, Chart.js, lecture des alertes uniquement. Pas d'écran analyse/upload/live. |
| Générateur synthétique | `src/bloc2_phishing/corpus_generator.py` | OK mais devient **fallback** (plus source principale). |

### 1.2 Ce qui MANQUE vraiment (à construire)

1. **Acquisition de vrais datasets** : aucun module ne télécharge de dataset en ligne.
   Le seul vrai dataset (`sms_spam_collection.csv`) a été déposé manuellement.
   → Manque `src/bloc2_phishing/dataset_downloader.py` (registre de sources, download,
   normalisation vers `PhishingSample`, fallback génération).
2. **Pipeline d'entraînement « propre »** : pas de split, pas de métriques honnêtes
   (val/test), pas d'artefacts versionnés ni de fichier de métriques persisté.
   → Refonte de `train.py` + `evaluation.py` (ajout `train_val_test_split`, rapport JSON).
3. **Service d'inférence** : impossible aujourd'hui d'analyser un message ou un lot
   via l'API. → endpoints `POST /api/analyze`, `POST /api/analyze-batch` (upload).
4. **Analyse temps réel** : aucun simulateur de logs ni streaming.
   → `src/bloc5_dashboard/api/realtime.py` (simulateur + SSE) + écran dashboard.
5. **Upload de fichiers** : aucun endpoint multipart. → `POST /api/upload-analyze`.
6. **UI usager** : le dashboard est SOC-only. Manque un écran « analyse / upload /
   flux temps réel » orienté entreprise.
7. **Chargement du dataset externe par défaut** : `train.py` ne regarde pas
   `data/external/`. → ajouter `data/external/` aux candidats, prioritaire.

### 1.3 Décision d'architecture

- **Ne pas toucher** `src/common/schemas.py` (interface contractuelle, 42 tests).
  `PhishingSample` couvre tous les besoins (texte, canal, label, source, langue).
- Ajouter un **module d'acquisition** dans le bloc 2 (collecte = rôle du bloc 2).
- Ajouter un **service d'inférence** comme nouveau sous-module du bloc 5
  (`src/bloc5_dashboard/api/inference.py`) qui réutilise `bloc3_ia.get_detector()`.
- Le **temps réel** vit dans le bloc 5 (présentation), il consomme le détecteur du bloc 3.

---

## 2. Datasets réels recommandés

> Règle : privilégier les **raw GitHub** (récupérables ici via `web_fetch`), licence
> permissive, format texte simple (CSV/TSV/txt). Les sources « API/portail » (PhishTank,
> OpenPhish) restent référencées pour la **prod** (réseau ouvert via `requests`).

### 2.1 Phishing SMS

| Dataset | URL publique | web_fetch ? | Licence | Notes |
|---|---|---|---|---|
| **UCI SMS Spam Collection** (déjà en place) | `https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv` | ✅ (raw GitHub, TSV `ham/spam\ttexte`) | UCI / usage recherche | **Source de référence SMS.** Déjà normalisé dans `data/external/sms_spam_collection.csv`. Mirror TSV ci-contre pour re-télécharger. |
| SMS Spam (mirror CSV) | `https://raw.githubusercontent.com/mohitgupta-omg/Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv` | ✅ | dérivé UCI | Colonnes `v1`(label),`v2`(texte) ; encodage latin-1 possible → forcer `encoding`. |

### 2.2 Phishing e-mail

| Dataset | URL publique | web_fetch ? | Licence | Notes |
|---|---|---|---|---|
| **Phishing email (curated CSV)** | `https://raw.githubusercontent.com/MariyaSha/phishing_emails/main/phishing_emails.csv` | ✅ (à vérifier au moment du run) | dépôt public GitHub | Petit corpus e-mails phishing labellisés. Vérifier colonnes au download. |
| SpamAssassin public corpus | `https://spamassassin.apache.org/old/publiccorpus/` (archives `.tar.bz2`) | ⚠️ archives binaires — **prod uniquement** (`requests` + extraction), pas idéal via web_fetch | Apache | Ham + spam e-mails réels. Pour la prod / enrichissement. |
| Enron (ham legit) | `https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip` | ⚠️ zip | public | Gros volume e-mails ham/spam ; **prod**. |

> Recommandation : pour l'e-mail, viser un **CSV raw GitHub** au moment du run (vérifier
> l'accessibilité via `web_fetch`) ; si indisponible → **fallback génération** (templates
> e-mails bancaires CM déjà dans `corpus_generator.py`).

### 2.3 URLs malveillantes

| Dataset | URL publique | web_fetch ? | Licence | Notes |
|---|---|---|---|---|
| **Malicious / Phishing URLs (CSV)** | `https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv` | ✅ (à valider) | dépôt public | Features + label ; on n'utilise que l'URL brute + label → mapper en `Channel.URL`. |
| URLhaus (abuse.ch) | `https://urlhaus.abuse.ch/downloads/csv_recent/` | ⚠️ portail (peut bloquer) — **prod** via `requests` | CC0 | URLs malveillantes fraîches, label=1. Référence prod. |
| PhishTank | `https://data.phishtank.com/data/online-valid.csv` | ⚠️ nécessite clé/agent — **prod** | usage selon CGU PhishTank | URLs phishing vérifiées, label=1. |
| OpenPhish (feed gratuit) | `https://openphish.com/feed.txt` | ⚠️ portail — **prod** | usage selon CGU | Liste d'URLs (label=1) sans légitimes → compléter par URLs légitimes (Tranco/Alexa top). |

> Pour les URLs, prévoir aussi une **source de légitimes** (label=0), ex. top domaines
> Tranco (`https://raw.githubusercontent.com/.../top-1m`-like) ou réutiliser
> `_LEGIT_DOMAINS` du générateur. Sinon le modèle URL n'aura qu'une classe.

### 2.4 Synthèse de la stratégie d'acquisition

- **Ici (sandbox)** : registre s'appuyant sur les CSV/TSV **raw GitHub** + dataset déjà
  déposé. Le downloader tente `requests`, échoue (403), et **retombe sur les fichiers
  déjà présents dans `data/external/`** (déposés via `web_fetch` au préalable).
- **En prod (réseau ouvert)** : le même downloader télécharge réellement via `requests`
  (PhishTank, URLhaus, OpenPhish, archives e-mail).
- **Si tout échoue** : `generate_corpus()` (fallback synthétique CM).

---

## 3. Module d'acquisition de données — `src/bloc2_phishing/dataset_downloader.py`

### 3.1 Responsabilités

1. Tenir un **registre de sources** (nom, URL, parseur, canal, licence).
2. **Télécharger** chaque source (via `requests`, lazy import) vers `data/external/`,
   avec **cache** (ne pas re-télécharger si présent), timeout, et **fallback** sur le
   fichier local déjà présent si le réseau échoue.
3. **Normaliser** chaque source brute → `list[PhishingSample]` (au contrat partagé).
4. Offrir un **fallback génération** (`corpus_generator.generate_corpus`) si aucune
   source n'aboutit.
5. **Fusionner / dédupliquer** et exporter un corpus consolidé
   `data/external/phishing_corpus_real.csv` (réutilisable par `train.py`).

### 3.2 Interface de fonctions (signatures cibles)

```python
# src/bloc2_phishing/dataset_downloader.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from src.common.schemas import Channel, PhishingSample

EXTERNAL_DIR = DATA_DIR / "external"        # data/external/
CONSOLIDATED_CSV = EXTERNAL_DIR / "phishing_corpus_real.csv"

@dataclass(frozen=True)
class DatasetSource:
    name: str                  # "uci_sms_spam"
    url: str                   # raw GitHub de préférence
    filename: str              # nom local dans data/external/
    channel: Channel           # canal par défaut si non porté par la ligne
    license: str               # "UCI/recherche", "CC0", ...
    parser: Callable[[Path], List[PhishingSample]]  # parseur dédié -> PhishingSample[]
    enabled: bool = True

# Registre central (extensible)
REGISTRY: List[DatasetSource] = [...]   # SMS / EMAIL / URL

# --- Téléchargement bas niveau ---
def download_file(source: DatasetSource, *, force: bool = False,
                  timeout: int = 30) -> Optional[Path]:
    """Télécharge via requests (lazy). Cache: si le fichier local existe et
    force=False -> renvoie le local. En cas d'échec réseau (403/timeout) ->
    renvoie le fichier local s'il existe, sinon None. NE LÈVE PAS."""

# --- Parseurs (un par format) ---
def _parse_uci_tsv(path: Path) -> List[PhishingSample]: ...        # ham/spam \t texte
def _parse_generic_csv(path: Path, text_col, label_col,
                       channel: Channel, source: str) -> List[PhishingSample]: ...
def _parse_url_list(path: Path, label: int, source: str) -> List[PhishingSample]: ...

# --- Acquisition haut niveau ---
def acquire_source(source: DatasetSource, *, force: bool = False) -> List[PhishingSample]:
    """download_file -> parser. [] si indisponible."""

def acquire_all(*, channels: Optional[List[Channel]] = None,
                force: bool = False,
                allow_fallback: bool = True) -> List[PhishingSample]:
    """Parcourt le REGISTRY, agrège, déduplique (sur raw_text normalisé).
    Si total == 0 et allow_fallback -> generate_corpus() (source='synthetic')."""

def build_real_corpus(out: Path = CONSOLIDATED_CSV, *,
                      force: bool = False) -> Path:
    """acquire_all -> export_csv(...) -> chemin du corpus consolidé."""
```

### 3.3 Normalisation vers `PhishingSample`

- `id` : `f"{source.name}-{i:05d}"` (stable, préfixé par source).
- `channel` : porté par la source (SMS/EMAIL/URL) sauf si la ligne le précise.
- `raw_text` : texte brut (ou l'URL pour `Channel.URL`).
- `language` : `"en"` par défaut pour datasets internationaux ; `detect` léger
  optionnel (heuristique mots FR) — sinon `"en"`.
- `label` : `1` (phishing/spam/malicious) / `0` (legit/ham) ; `None` si absent.
- `source` : `source.name` (traçabilité de provenance).
- **Dédup** : sur `clean_text` (via `preprocessing.clean_text`) pour éviter doublons
  inter-sources.

### 3.4 Registre initial proposé

| name | channel | url (raw de préférence) | parser |
|---|---|---|---|
| `uci_sms_spam` | SMS | `.../pycon-2016-tutorial/.../sms.tsv` | `_parse_uci_tsv` |
| `email_phishing` | EMAIL | CSV raw GitHub (à valider au run) | `_parse_generic_csv` |
| `malicious_urls` | URL | CSV raw GitHub (à valider au run) | `_parse_generic_csv` / `_parse_url_list` |

### 3.5 Critère « marche ici » vs « marche en prod »

- `download_file` essaie `requests` d'abord (prod), puis fallback **fichier local**.
- Pré-requis sandbox : déposer au préalable (via `web_fetch` exécuté par l'agent qui
  implémente) les fichiers bruts dans `data/external/` sous le `filename` attendu.
  Le downloader les retrouvera alors automatiquement.

---

## 4. Plan d'entraînement « modèle très bien entraîné »

### 4.1 Principes

- **Split honnête** train/val/test (stratifié) — fin du `train==test` actuel.
- **Métriques sur le test set** (jamais vues à l'entraînement) + matrice de confusion.
- **Artefacts versionnés** : modèle + métriques + métadonnées (date, datasets, tailles,
  hyperparamètres) dans un dossier daté.
- **Choix du seuil** (`phishing_threshold`) calibré sur le **val set** (max F1).

### 4.2 Fichiers à modifier / ajouter

1. `src/bloc3_ia/evaluation.py` — ajouter :
   ```python
   def train_val_test_split(samples, test_size=0.15, val_size=0.15, seed=42,
                            stratify=True) -> tuple[list, list, list]: ...
   def metrics_at_threshold(y_true, scores, threshold) -> dict: ...
   def best_threshold(y_true, scores) -> float:   # balaye 0.05..0.95, max F1
   ```
2. `src/bloc3_ia/train.py` — refonte du flux :
   - candidats corpus = `["phishing_corpus_real.csv"(external), "phishing_corpus_synth.csv", "phishing_samples_cm.csv"]` (external **prioritaire**) ;
   - option `--build-corpus` → appelle `dataset_downloader.build_real_corpus()` avant ;
   - split → fit sur **train** → calibrer seuil sur **val** → évaluer sur **test** ;
   - persistance versionnée (voir 4.3) + écriture `metrics.json`.
3. `src/bloc3_ia/phishing_detector.py` — petit ajout : `predict_scores(samples)`
   (probas brutes) pour permettre la calibration de seuil sans dupliquer la logique.

### 4.3 Persistance versionnée des artefacts

```
models/
  phishing_tfidf_rf.joblib                 # alias "courant" (compat existant)
  registry/
    tfidf_rf/
      2026-06-07T1200/
        model.joblib
        metrics.json        # accuracy/precision/recall/f1 (test) + CM + threshold
        meta.json           # datasets, n_train/n_val/n_test, hyperparams, git? date
      LATEST -> 2026-06-07T1200   # (fichier pointeur texte)
```

- `phishing_detector.save()` écrit le `.joblib` daté **et** met à jour l'alias courant.
- `metrics.json` est lu par l'API (`GET /api/model-info`) pour afficher la qualité.

### 4.4 Objectif de qualité (critère d'acceptation)

- Sur le **test set** UCI SMS : **F1 ≥ 0.90** attendu (TF-IDF + RF sur 1064 SMS réels
  est réaliste). Documenter la valeur obtenue dans `metrics.json`.
- Option BERT : `--model bert` (déjà câblé) — même split, mêmes métriques persistées
  dans `models/registry/bert/...`. Lourd : optionnel, non bloquant.

### 4.5 Pipeline de bout en bout (commande cible)

```bash
# 1) Construire le corpus réel (download + normalisation + fallback)
python -m src.bloc2_phishing.dataset_downloader            # build_real_corpus()
# 2) Entraîner avec split + métriques + versionnage
python -m src.bloc3_ia.train --model tfidf --build-corpus
# -> models/registry/tfidf_rf/<ts>/{model.joblib,metrics.json,meta.json}
```

---

## 5. Service d'inférence + upload

### 5.1 Nouveau module — `src/bloc5_dashboard/api/inference.py`

Réutilise `from src.bloc3_ia import get_detector` + `bloc2.preprocessing`.

```python
def analyze_text(text: str, channel: Channel = Channel.SMS,
                 language: str = "fr") -> PhishingPrediction
def analyze_samples(samples: list[PhishingSample]) -> list[PhishingPrediction]
def analyze_csv_bytes(data: bytes) -> list[dict]   # parse CSV upload -> samples -> prédictions
def analyze_txt_bytes(data: bytes, channel: Channel) -> list[dict]  # 1 ligne = 1 message
```

- Le détecteur est chargé **une fois** (singleton module-level + `functools.lru_cache`)
  pour éviter de relire le `.joblib` à chaque requête (perf).

### 5.2 Endpoints API (à ajouter dans `main.py`)

| Méthode | Route | Corps / params | Réponse | Auth |
|---|---|---|---|---|
| GET | `/api/model-info` | — | `{model, trained, metrics, threshold, datasets}` | public |
| POST | `/api/analyze` | `{text, channel?, language?}` | `AnalyzeResponse` (score, is_phishing, model, clean_text, reasons[]) | public (rate-limit) |
| POST | `/api/analyze-batch` | `{items:[{text,channel?}...]}` (≤ N) | `{results:[...], summary:{n, n_phishing, avg_score}}` | public |
| POST | `/api/upload-analyze` | `multipart/form-data` fichier `.csv`/`.txt` | `{results:[...], summary, filename}` | public |

### 5.3 Schémas E/S (à ajouter dans `schemas_api.py`)

```python
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    channel: Channel = Channel.SMS
    language: str = "fr"

class AnalyzeResult(BaseModel):
    text: str
    channel: Channel
    is_phishing: bool
    score: float            # 0..1
    model: str              # tfidf_rf | heuristic | bert_multilingual
    reasons: list[str] = [] # mots-clés / signaux déclencheurs (explicabilité)

class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResult]
    summary: dict           # {n, n_phishing, avg_score}

class ModelInfoResponse(BaseModel):
    model: str
    trained: bool
    threshold: float
    metrics: dict           # depuis metrics.json (ou {} si absent)
    datasets: list[str]
```

### 5.4 Garde-fous upload (sécurité/perf)

- Taille max fichier (ex. **2 Mo**), nombre max de lignes (ex. **5000**).
- Types autorisés : `text/csv`, `text/plain` (vérifier extension + content-type).
- Lecture **en mémoire** (pas d'écriture disque) ; encodage `utf-8` avec repli `latin-1`.
- Renvoyer une erreur 413/415 explicite si dépassement/type invalide.

### 5.5 UI (frontend)

Ajouter au `index.html` (ou nouvel onglet) un panneau **« Analyse »** :
- zone de texte + sélecteur canal → bouton « Analyser » → carte résultat (score,
  badge phishing/légitime, raisons) via `POST /api/analyze` ;
- bouton **upload** `.csv/.txt` → tableau de résultats + résumé (n, % phishing) via
  `POST /api/upload-analyze` ;
- bandeau **qualité du modèle** (depuis `GET /api/model-info`).

---

## 6. Analyse temps réel

### 6.1 Simulateur de logs — `src/bloc5_dashboard/api/realtime.py`

```python
def synthetic_log_stream(rate_per_sec: float = 1.0, phishing_ratio: float = 0.3,
                         seed: int | None = None) -> Iterator[PhishingSample]:
    """Génère un flux infini d'événements (messages entrants) en réutilisant
    corpus_generator + un sous-échantillon du corpus réel, à cadence contrôlée."""

def analyze_event(sample: PhishingSample) -> AnalyzeResult:
    """Prétraite + détecte (détecteur singleton)."""
```

Source des événements : mélange du **corpus réel** (rejoué) + génération synthétique,
pour rester réaliste et hors-ligne. Cadence pilotable (`rate_per_sec`).

### 6.2 Streaming : **SSE** (recommandé)

- Endpoint `GET /api/stream/logs` → `text/event-stream` (FastAPI `StreamingResponse`).
- Chaque message SSE = un `AnalyzeResult` JSON (timestamp, texte tronqué, score, verdict).
- Avantages SSE vs WebSocket : simple, unidirectionnel (serveur→UI), compatible
  proxies, pas de dépendance extra.
- **Repli polling** : `GET /api/stream/poll?since=<ts>` (buffer circulaire en mémoire,
  ex. 200 derniers événements) pour environnements sans SSE.
- Paramètres : `?rate=`, `?phishing_ratio=`, `?limit=` (mode démo borné pour les tests).

### 6.3 Intégration dashboard

- Onglet **« Temps réel »** : table live (auto-scroll) des événements analysés, badge
  rouge/vert, compteur d'alertes phishing/min, mini-graphe (Chart.js déjà présent).
- Bouton Start/Stop sur le flux SSE (ouverture/fermeture `EventSource`).
- Option : un événement classé phishing au-dessus d'un score élevé peut créer une
  `Alert` (réutiliser `bloc4_correlation.persist_alerts`) → apparaît dans le SOC.

---

## 7. Découpage en tâches atomiques (1 tâche = 1 agent)

> Ordre = ordre de dépendance. Chaque tâche a un critère **testable**.

### T1 — Préparer/valider les datasets externes (acquisition)
- **Dépend de** : rien.
- **Livrable** : `data/external/sms_spam_collection.csv` (déjà OK) + tentative de
  récupération **e-mail** et **URL** via `web_fetch` (raw GitHub) → déposés en
  `data/external/`. Documenter les URLs réellement accessibles.
- **Acceptation** : au moins 2 canaux disponibles en `data/external/` au format
  `PhishingSample`-compatible ; sinon documenter le fallback.
- **Note** : écrire les gros fichiers via **bash heredoc**.

### T2 — `dataset_downloader.py` (module d'acquisition)
- **Dépend de** : T1.
- **Livrable** : `src/bloc2_phishing/dataset_downloader.py` (cf. §3) + export dans
  `src/bloc2_phishing/__init__.py` (`acquire_all`, `build_real_corpus`).
- **Acceptation** :
  - `build_real_corpus()` produit `data/external/phishing_corpus_real.csv` non vide ;
  - réseau coupé → fallback fichiers locaux ; locaux absents → `generate_corpus` ;
  - `load_samples(corpus_real)` recharge sans erreur ; nouveaux tests pytest verts.

### T3 — Split + métriques honnêtes (`evaluation.py`)
- **Dépend de** : rien (parallélisable avec T2).
- **Livrable** : `train_val_test_split`, `metrics_at_threshold`, `best_threshold`.
- **Acceptation** : split stratifié reproductible (seed) ; somme des tailles = total ;
  `best_threshold` ∈ [0,1] ; tests unitaires sur jeu jouet.

### T4 — Refonte entraînement versionné (`train.py` + `phishing_detector.py`)
- **Dépend de** : T2, T3.
- **Livrable** : `--build-corpus`, split, calibration seuil, persistance
  `models/registry/tfidf_rf/<ts>/` + `metrics.json`/`meta.json` + alias courant ;
  `predict_scores()` ajouté au détecteur.
- **Acceptation** : `python -m src.bloc3_ia.train --model tfidf` génère les 3 artefacts ;
  `metrics.json` contient les métriques **test** ; **F1 test ≥ 0.90** sur UCI SMS ;
  modèle rechargeable par `PhishingDetector().load()`.

### T5 — Service d'inférence (`inference.py` + schémas)
- **Dépend de** : T4 (modèle entraîné disponible) — fonctionne aussi en heuristique.
- **Livrable** : `src/bloc5_dashboard/api/inference.py` + schémas dans `schemas_api.py`.
- **Acceptation** : `analyze_text("...lien suspect...")` renvoie `AnalyzeResult` cohérent ;
  détecteur chargé une seule fois (lru_cache) ; tests unitaires sur texte phishing/légit.

### T6 — Endpoints API analyse + upload (`main.py`)
- **Dépend de** : T5.
- **Livrable** : `GET /api/model-info`, `POST /api/analyze`, `/api/analyze-batch`,
  `/api/upload-analyze` (multipart) avec garde-fous (taille/type/lignes).
- **Acceptation** : tests `httpx`/`TestClient` : analyse unitaire, batch, upload CSV
  (réponse `summary` correcte), rejets 413/415 ; endpoints publics OK.

### T7 — Temps réel (`realtime.py` + endpoints SSE/polling)
- **Dépend de** : T5.
- **Livrable** : `src/bloc5_dashboard/api/realtime.py`, `GET /api/stream/logs` (SSE),
  `GET /api/stream/poll`.
- **Acceptation** : en mode borné (`?limit=N`), le flux renvoie N événements analysés ;
  test : N événements reçus, chacun valide ; buffer polling renvoie les derniers.

### T8 — UI : onglets Analyse + Temps réel (`frontend/index.html`)
- **Dépend de** : T6, T7.
- **Livrable** : panneaux Analyse (texte + upload + model-info) et Temps réel (live SSE).
- **Acceptation** : démo manuelle : saisir un SMS phishing → verdict affiché ; upload
  CSV → tableau + résumé ; flux live défile ; bandeau qualité modèle visible.

### T9 — Docs + Makefile + requirements
- **Dépend de** : T2, T4, T6, T7.
- **Livrable** : MAJ `README.md`, `docs/ARCHITECTURE_CODE.md`, cibles Makefile
  (`build-corpus`, `train`, `serve`), ajout `python-multipart`, `sse-starlette`(opt.).
- **Acceptation** : `make build-corpus && make train && make run-api` documenté ;
  `pip install -r requirements.txt` couvre les nouvelles deps ; 42+ tests verts.

**Graphe de dépendances** :
`T1 → T2`, `T3` (indé), `(T2,T3) → T4 → T5 → {T6, T7} → T8`, `T9` en fin.

---

## 8. Risques et points de vigilance

### Réseau / acquisition
- **Proxy 403 en sandbox** : `requests` direct échoue → le downloader DOIT cacher/fallback
  sur `data/external/`. Toujours pré-déposer les fichiers via `web_fetch`.
- **URLs raw GitHub instables** (renommage/suppression de dépôts) : valider chaque URL
  au moment du run ; encapsuler chaque source dans un try/except (une source KO ne casse
  pas l'acquisition globale).
- **Licences** : ne redistribuer que des datasets à licence permissive (UCI/recherche,
  CC0, Apache). PhishTank/OpenPhish : respecter CGU (prod, pas de redistribution).

### Données / modèle
- **Déséquilibre & langue** : UCI SMS est en **anglais** → le modèle peut sous-performer
  sur le **FR/SMS CM**. Mitigation : conserver une part de corpus CM (synthétique +
  `phishing_samples_cm.csv`) dans le mix d'entraînement ; documenter le périmètre.
- **Fuite de données (data leakage)** : split AVANT tout fit ; dédup inter-split sur
  `clean_text` pour éviter qu'un même message soit en train ET test.
- **URLs à classe unique** : OpenPhish/URLhaus = phishing only → injecter des légitimes,
  sinon le modèle URL est inutilisable.

### Service / sécurité
- **Upload** : limiter taille/lignes/type (DoS, fichiers piégés) ; lecture en mémoire ;
  ne **jamais exécuter** le contenu ; échapper le texte renvoyé à l'UI (XSS).
- **Endpoints publics d'analyse** : prévoir un **rate-limit** simple (par IP) pour éviter
  l'abus ; ne pas logger le contenu sensible uploadé.
- **SSE** : borner le flux (timeout / `limit`) pour ne pas saturer le serveur ; fermer
  proprement les connexions ; le simulateur ne doit utiliser que des données synthétiques
  ou rejouées (pas de PII réelle).

### Performance
- **Chargement modèle par requête** : charger le `.joblib` une seule fois (singleton).
- **Batch volumineux** : vectorisation TF-IDF en lot (déjà le cas) ; borner la taille.
- **BERT** : inférence CPU lente → garder TF-IDF par défaut, BERT optionnel.

### Qualité / faux positifs
- **Faux positifs** sur OTP/notifications légitimes (contiennent « code », montants) :
  conserver les exemples **légitimes** CM dans l'entraînement ; calibrer le seuil sur le
  val set ; exposer les `reasons` pour l'explicabilité et l'ajustement humain.
- **Non-régression** : ne pas modifier `src/common/schemas.py` ; garder les 42 tests
  verts ; ajouter des tests pour chaque nouvelle tâche.

---

## Synthèse des décisions clés et ordre d'exécution

1. **Ne pas toucher `src/common/schemas.py`** : `PhishingSample` couvre déjà texte, canal,
   label, langue et source — les 42 tests et le contrat inter-blocs restent intacts.
2. **Acquisition réelle = nouveau module bloc 2** `dataset_downloader.py` : registre de
   sources, download `requests` + **fallback fichiers `data/external/`** + **fallback
   génération**. La génération synthétique devient un simple filet de sécurité.
3. **Datasets de référence** : UCI SMS (déjà en place) pour SMS ; CSV raw GitHub pour
   e-mail et URL (validés via `web_fetch` au run), avec sources prod (PhishTank, URLhaus,
   OpenPhish, SpamAssassin) pour le réseau ouvert.
4. **Entraînement honnête et versionné** : split stratifié train/val/test, seuil calibré
   sur val, métriques **test** persistées (`metrics.json`), artefacts datés sous
   `models/registry/` + alias courant. Cible **F1 test ≥ 0.90** sur UCI SMS.
5. **Service d'inférence** : `inference.py` (détecteur singleton) + endpoints
   `/api/analyze`, `/api/analyze-batch`, `/api/upload-analyze`, `/api/model-info`.
6. **Temps réel** : `realtime.py` (simulateur de logs) + **SSE** `/api/stream/logs`
   (repli polling), intégré au dashboard (onglet live).
7. **UI** : ajout des écrans Analyse (texte + upload + qualité modèle) et Temps réel.
8. **Sécurité/perf d'abord** : limites d'upload, rate-limit, anti-leakage au split,
   gestion des faux positifs (légitimes CM + seuil calibré + `reasons`).
9. **Ordre recommandé** : **T1** (datasets) → **T2** (downloader) // **T3** (split/metrics)
   → **T4** (train versionné) → **T5** (inférence) → **T6** (API) + **T7** (temps réel)
   → **T8** (UI) → **T9** (docs/Make/requirements).
10. **Règles d'or sandbox** : pré-déposer les datasets via `web_fetch`, écrire les gros
    fichiers via **bash heredoc**, garder tous les imports lourds **paresseux**, et
    conserver la suite de tests **verte** à chaque tâche.
