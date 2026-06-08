# Audit FINAL — Expert indépendant IA / ML & Données

Projet : **IA & Cybersécurité Cameroun**
Date : 2026-06-08
Sandbox : Linux, Python 3.10 (sklearn, pandas, fastapi, httpx ; pas de torch/transformers, pas de réseau Gemini).
Méthode : vérification par exécution réelle (pytest + TestClient + lecture du code). Aucune modification du code applicatif.

---

## VERDICT : VALIDÉ POUR DÉMO

Le périmètre IA/ML/Données est cohérent, robuste et démontrable. Les 97 tests passent. Toutes les nouvelles fonctionnalités (assistant Gemini, registre de recherches) fonctionnent en mode dégradé propre sans réseau ni torch. Une seule réserve de sécurité non bloquante pour la démo est signalée (clé Gemini en clair dans `.env`).

Préparation effectuée : nettoyage `__pycache__`, `SQLITE_FALLBACK=sqlite:////tmp/ai.db`, `/tmp/ai.db` supprimé avant chaque exécution.

---

## Synthèse des points 1 à 5

| # | Domaine | Statut | Preuve |
|---|---------|--------|--------|
| 1 | Assistant Gemini | **OK** | URL/body/parsing conformes ; lazy `requests` ; dégradation `powered_by=regles` sans 500 ; signatures cohérentes |
| 2 | Registre de recherches | **OK** | inférence réelle réutilisée ; dedup id stable ; /export csv ok ; routage /stats & /export AVANT /{rid} |
| 3 | Modèle & inférence | **OK** | seuil calibré 0.23 chargé ; même prétraitement train/serve ; split stratifié sans fuite ; /api/model expose métriques |
| 4 | Dashboard data | **OK** | tous les fetch ciblent des endpoints existants ; champs lus présents ; graphes alimentés par /api/research/stats |
| 5 | Tests | **OK (réserve mineure)** | test_research.py présent (3 cas) ; test_gemini_assistant.py ABSENT |

---

## Point 1 — Assistant Gemini (OK)

Fichiers : `src/bloc3_ia/gemini_assistant.py`, `src/bloc5_dashboard/api/assistant.py`.

- **URL REST conforme** (`gemini_assistant.py:70-75`) :
  `{base}/models/{model}:generateContent` avec `?key=` passé via `params` (et non concaténé) ; body `{"contents":[{"parts":[{"text":prompt}]}]}` ; parsing défensif `candidates[0].content.parts[0].text` (L97-114). Conforme à l'API `generateContent`.
- **`requests` en import paresseux** (`gemini_assistant.py:64-68`) : l'absence de la lib ne casse ni l'import ni l'API (repli `None`).
- **`is_available()`** (L30-37) : test à froid de la clé, sans I/O réseau.
- **Dégradation propre** : `explain()` et `summary()` capturent toute exception et retombent sur `_fallback`/`_summary_fallback` (`assistant.py:44-51`, `74-84`). Vérifié en live : avec clé présente mais réseau bloqué (proxy 403), la réponse reste **200** avec `powered_by=regles`. Jamais de 500.
- **Cohérence des signatures** (vérifiée par grep) :
  - `def summarize(text, max_words=60)` (`gemini_assistant.py:217`) ; appelée `summarize(req.text, req.max_words)` (`assistant.py:79`) et `summarize(query)` (`research.py:129`) — compatibles.
  - `def explain_with_gemini(text, is_phishing, score, indicators)` (`gemini_assistant.py:135`) ; appelée à l'identique (`assistant.py:46`).

## Point 2 — Registre de recherches (OK)

Fichier : `src/bloc5_dashboard/api/research.py`.

- **Réutilise la VRAIE inférence** : `_analyze_query` appelle `inference._analyze_samples` via import paresseux (L96-105). Live : `POST /api/research` renvoie `is_phishing=True` correctement renseigné.
- **Déduplication par id stable** : `_stable_id = sha1(normalize(query)|channel)` (L58-65). Live : 2 POST identiques → **même id** `rs-c1b51b814d8ae9d1`, la 2ᵉ requête renvoie l'existante (pas de doublon). Double-vérification d'existence avant insert (concurrence, L216-218).
- **Enregistrement à la volée** : analyse → résumé (Gemini ou repli règle, L119-145) → persistance `ResearchORM`.
- **/export csv & json** : live `GET /api/research/export?fmt=csv` → **200**, `Content-Type: text/csv`, en-tête CSV présent ; `Content-Disposition: attachment`.
- **/share** : `POST /api/research/{rid}/share` → **200**, passe `shared=True`.
- **/stats** : live **200**, structure complète (`total, n_phishing, n_legit, n_unknown, phishing_rate, shared, by_channel, by_verdict, by_day`).
- **ROUTAGE CORRECT** : `@router.get("/export")` (L244) et `@router.get("/stats")` (L300) déclarés **AVANT** `@router.get("/{rid}")` (L348). Donc `/stats` et `/export` ne sont pas capturés par la route paramétrique. Vérifié en live (stats routé sans 404).
- **Robustesse BDD** : chaque accès est encapsulé ; lecture/stats/export renvoient liste/zéros si BDD KO (jamais 500) ; les écritures renvoient 503 explicite.

## Point 3 — Modèle & inférence (OK)

Fichiers : `src/bloc3_ia/train.py`, `phishing_detector.py`, `src/bloc5_dashboard/api/inference.py`.

- **Seuil calibré chargé** : `chosen_threshold=0.23` persisté dans `meta.json` (registre `tfidf_rf/20260607-223001`), chargé au démarrage du détecteur (log : « Seuil calibré chargé depuis le registre : 0.230 »). Live `/api/model` → `threshold=0.23`, `threshold_calibrated=True`, `type=tfidf_rf`.
- **Cohérence train/serve (même prétraitement)** : `train.py:603` appelle `preprocess(samples)` (bloc 2) ; le détecteur fit/predict sur `clean_text or raw_text` (`phishing_detector.py:120,180`). Le service applique le même `preprocess` (`inference._analyze_samples:244`). Identique des deux côtés.
- **Pas de fuite** : split stratifié train/val/test (`train.py:132-191`) ; calibrage du seuil sur la **validation**, évaluation finale sur le **test** (`train.py:377-406`). Conforme aux bonnes pratiques.
- **/api/model expose les métriques** : `metrics` (accuracy, precision, recall, f1, confusion_matrix) et `metrics_by_source` lus depuis le registre (`inference.py:540-558`). Live **200**.

## Point 4 — Dashboard data (OK)

Fichier réel : `src/bloc5_dashboard/frontend/recherche.html` (et non `frontend/recherche.html`).

- **Tous les fetch ciblent des endpoints existants** : `/api/analyze`, `/api/assistant/explain`, `/api/research`, `/api/research?limit=200`, `/api/research/stats`, `/api/research/{id}`, `/api/research/{id}/share`, `/api/research/export?fmt=`, `/api/scan`. Aucun endpoint fantôme.
- **Champs lus existants** : `is_phishing, score, model, indicators, explanation, advice, powered_by, query, channel, created_at, id, summary, shared, total, n_phishing, phishing_rate, by_verdict, by_channel, by_day` — tous présents dans les réponses des modèles Pydantic correspondants.
- **Graphes alimentés par /api/research/stats** : donut (`by_verdict`/`by_channel`), barre, et ligne temporelle (`by_day`) consomment exactement la structure renvoyée par `/stats`.

## Point 5 — Tests (OK, réserve mineure)

- `tests/test_research.py` présent : `test_research_create_and_dedup`, `test_research_list_share_export_stats`, `test_research_404` — couvre dedup, liste, partage, export, stats et 404.
- **`tests/test_gemini_assistant.py` ABSENT** (MINEUR). La dégradation de l'assistant est néanmoins couverte indirectement par les tests d'API et vérifiée en live (powered_by=regles). Recommandé d'ajouter un test unitaire pour `is_available()`, le parsing `generate()` (mock requests) et le repli `explain()/summary()`.
- **Fiabilité** : `97 passed, 1 warning in ~13s`. Le warning est une dépréciation Starlette/httpx (non bloquant).

---

## Problèmes par gravité

### BLOQUANT
- Aucun.

### MAJEUR
- Aucun.

### MINEUR
1. **Clé Gemini en clair dans `.env`** — `.env:5` contient `GEMINI_API_KEY=AQ.Ab8RN6...`. Le fichier est `chmod 700` et `.gitignore`, mais la clé est exposée dans les logs d'erreur réseau (l'URL complète avec `?key=...` apparaît dans les WARNING). Correctif : (a) masquer le `key` dans le message de log (`gemini_assistant.py:82` — logger l'exception sans l'URL, ou tronquer) ; (b) **révoquer/rotater** cette clé avant toute diffusion du dépôt ou des logs. Non bloquant pour la démo locale.
2. **`test_gemini_assistant.py` absent** — ajouter un test unitaire de l'assistant (mock `requests`, vérif parsing + repli). Voir Point 5.
3. **Permissif en dev** — `API_KEY` vide → endpoints sensibles (POST research, share, upload) ouverts (`security.py:52-58`). Comportement voulu et journalisé ; pensez à définir `API_KEY` + `ENVIRONMENT=production` avant tout déploiement réel (le garde-fou `enforce_production_security` est déjà en place).

---

## Détail des exécutions

```
python3 -m pytest -p no:cacheprovider  ->  97 passed, 1 warning in 13.28s

TestClient (sans réseau Gemini) :
  POST /api/research              -> 200  is_phishing=True  id=rs-c1b51b814d8ae9d1
  POST /api/research (identique)  -> 200  id IDENTIQUE (dedup OK)
  GET  /api/research/stats        -> 200  structure complète, routé (pas 404)
  GET  /api/research/export?fmt=csv -> 200  text/csv, en-tête présent
  POST /api/assistant/explain     -> 200  powered_by=regles
  POST /api/assistant/summary     -> 200  powered_by=regles
  GET  /api/research/{rid}        -> 200 ; GET /api/research/inexistant -> 404
  POST /api/research/{rid}/share  -> 200
  POST /api/analyze               -> 200
  GET  /api/model                 -> 200  threshold=0.23  calibrated=True  type=tfidf_rf

Routage research (grep @router.get) :
  /export (L244), /stats (L300)  AVANT  /{rid} (L348)  -> OK

Signatures :
  def summarize(text, max_words=60)            (gemini_assistant.py:217)
  summarize(req.text, req.max_words)           (assistant.py:79)        -> OK
  summarize(query)                             (research.py:129)        -> OK
  explain_with_gemini(text,is_phishing,score,indicators) déf & appel    -> OK
```

---

## Conclusion

Le système est **VALIDÉ POUR DÉMO**. Architecture IA/ML propre : inférence réelle réutilisée par le registre, prétraitement cohérent train/serve, seuil calibré sans fuite, assistant Gemini robuste et dégradant proprement, dashboard branché sur des endpoints réels. Seules subsistent des recommandations mineures (rotation de la clé Gemini + masquage dans les logs, ajout d'un test unitaire de l'assistant) à traiter avant un déploiement public — sans impact sur la présentation.
