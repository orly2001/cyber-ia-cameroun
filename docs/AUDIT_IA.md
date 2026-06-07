# AUDIT IA / MACHINE LEARNING & DONNÉES — Détection de phishing

**Produit :** IA & Cybersécurité Cameroun
**Périmètre :** Bloc 2 (datasets) + Bloc 3 (entraînement/évaluation) + Bloc 5 (inférence temps réel)
**Auditeur :** Expert indépendant IA/ML & Données
**Date :** 2026-06-07
**Environnement vérifié :** Python 3.10.12, scikit-learn 1.7.2, pandas 2.3.3, fastapi 0.136.3 (pas de torch/transformers — conforme à l'attendu)

---

## DÉCISION : **APPROUVÉ AVEC RÉSERVES**

Le pipeline est techniquement honnête sur les points fondamentaux (split réellement
stratifié, pas de fuite *test→train* sur les données réelles, métriques calculées
sur un test tenu à l'écart, matrice de confusion mathématiquement exacte,
cohérence train/serve parfaite). Les chiffres annoncés (acc 0.95 / prec 1.00 /
recall 0.79 / f1 0.88) sont **reproductibles et exacts**.

**MAIS** deux réserves majeures empêchent une approbation pleine :

1. **Fuite synthétique → test** liée à la pauvreté de templates du générateur :
   après prétraitement, des phishing synthétiques quasi-identiques se retrouvent
   dans train ET test, gonflant artificiellement le rappel.
2. **Généralisation réelle médiocre et masquée par l'agrégat** : sur le **vrai**
   phishing (UCI), le rappel n'est que de **0.56**, contre **1.00** sur le
   synthétique. Le 0.79 global est une moyenne trompeuse.

Aucun de ces points n'est bloquant pour un *prototype défensif*, mais ils doivent
être corrigés et explicitement documentés avant tout déploiement en production.

---

## PROBLÈMES PAR GRAVITÉ

### MAJEUR-1 — Fuite synthétique → test (rappel gonflé)
**Cause racine :** `src/bloc2_phishing/corpus_generator.py` n'utilise que ~26
squelettes de phrases (4-5 variantes par scénario) remplis par des valeurs
aléatoires (montants, numéros, jetons de lien). Le prétraitement
`src/bloc2_phishing/preprocessing.py:82-84` normalise URL/montant/téléphone vers
`<URL>` / `<MONEY>` / `<PHONE>` et supprime les chiffres, ce qui **efface
justement les seules différences** entre deux messages issus du même template.

**Preuve mesurée :**
- 345 lignes synthétiques → **195 squelettes uniques** seulement (≈150 quasi-doublons).
- Les 35 URLs phishing synthétiques se réduisent toutes à `<URL>`.
- Split seed=42, test_size=0.2 : **26 / 277 lignes de test (9,4 %)** ont un
  `clean_text` **identique** à une ligne de train — **toutes synthétiques**, dont
  **16 phishing**.

**Impact :** ~16 des ~66 phishing du test sont des doublons (après nettoyage) du
train ⇒ rappel/précision du phishing optimistes.

**Correctif précis :**
- **Dédoublonner sur le texte NETTOYÉ, pas sur le brut.** Actuellement
  `dataset_downloader.py:477-493` (`_norm_key` / `_dedupe`) déduplique sur
  `raw_text`. Remplacer la clé par `clean_text(raw_text)` (importer depuis
  `bloc2_phishing.preprocessing`) afin que les quasi-doublons synthétiques
  s'effondrent en une seule ligne avant le split.
- **OU** splitter par groupe de template : ajouter un champ « template_id » au
  générateur et utiliser `sklearn.model_selection.GroupShuffleSplit` dans
  `train.py:_stratified_split` pour qu'un même squelette ne soit jamais à la fois
  en train et en test.
- **Enrichir le générateur** : augmenter le nombre de squelettes par scénario
  (objectif ≥ 15-20) pour réduire la redondance intrinsèque.

---

### MAJEUR-2 — Généralisation réelle faible masquée par l'agrégat
**Preuve mesurée** (réentraînement seed=42, ventilation du rappel phishing par source) :

| Source du phishing (test) | n  | Rappel | Faux négatifs |
|---------------------------|----|--------|---------------|
| synthétique               | 34 | **1.000** | 0 |
| uci_sms_spam (réel)       | 32 | **0.562** | 14 |
| **agrégat**               | 66 | 0.788  | 14 |

**Les 14 faux négatifs sont TOUS du phishing réel.** Le modèle « réussit » surtout
parce qu'il revoit du synthétique déjà vu (cf. MAJEUR-1). Sur le terrain (FR/CM),
le détecteur laisserait passer ~4 phishing réels sur 10.

**Honnêteté du reporting :** le chiffre brut (recall 0.79, FN=14) est **correctement
reporté** dans `models/registry/.../metrics.json` et l'évaluation est faite sur le
test. **Ce qui manque, c'est la ventilation par source/langue**, sans laquelle le
0.79 induit en erreur.

**Correctifs précis :**
- **Reporter le rappel ventilé réel/synthétique et FR/EN** dans
  `evaluation.py` (ajouter un calcul groupé) et dans `meta.json`.
- **Baisser le seuil de décision** : `phishing_threshold=0.5`
  (`src/common/config.py:53`) est trop conservateur pour un usage défensif où le
  coût d'un FN > coût d'un FP. Le tuner sur la validation (viser recall ≥ 0.85) ;
  il est déjà configurable via `PHISHING_THRESHOLD` — documenter une valeur
  recommandée (p. ex. 0.30-0.35) calibrée sur le **réel uniquement**.
- **Calibrer les probabilités** (`CalibratedClassifierCV`) car RandomForest
  produit des proba mal calibrées, ce qui rend le seuil peu interprétable.
- **Acquérir plus de phishing FR/CM RÉEL** : le seul corpus réel est de l'anglais
  (UCI SMS). C'est la limite structurelle ; le synthétique ne la comble pas.

---

### MINEUR-1 — Représentativité linguistique : FR/CM = 100 % synthétique
**Preuve :** croisement source × langue du dataset consolidé :
- `uci_sms_spam` : 1037 lignes, **0 français**.
- `synthetic` : 345 lignes dont **264 français**.

⇒ **Toute** la capacité FR/CM du modèle provient du synthétique. Combiné à
MAJEUR-1, la « bonne » détection FR observée est largement un artefact de fuite.
À documenter explicitement comme limitation de représentativité.

---

### MINEUR-2 — Sources du registre partiellement non vérifiables / périssables
**Fichier :** `src/bloc2_phishing/dataset_downloader.py:46-100` (`SOURCES`).
- URLs `raw.githubusercontent.com` (justmarkham, mohitgupta-omg, MariyaSha) :
  dépôts tiers, **susceptibles de disparaître** ; licences indiquées « à vérifier
  au téléchargement » (`phishing_emails_curated`).
- `phishtank_online_valid` pointe vers `http://` (non-TLS) et requiert en pratique
  une clé d'API (le feed anonyme est restreint) — risque de récupération vide.
- **Réseau bloqué en sandbox** : ces sources ne sont de toute façon pas
  téléchargeables ici ; seul `data/external/sms_spam_collection.csv` (UCI, déjà
  présent) alimente réellement l'entraînement.

**Correctif :** figer les licences exactes par source (l'UCI SMS Spam est
CC BY 4.0 — OK), préférer des miroirs pérennes/archivés, passer PhishTank en
`https` et documenter l'exigence de clé. Pas bloquant car le mode hors-ligne est
géré proprement (voir ci-dessous).

---

## POINTS 1-5 — CONFIRMÉS OK / KO AVEC PREUVES

### 1. Qualité & honnêteté de l'entraînement — **OK** (avec réserve MAJEUR-1)
- **Split stratifié réel** : `train.py:_stratified_split` (l.117-174) utilise
  `train_test_split(..., stratify=labels)` en deux temps (test puis val). Vérifié :
  support test seed=42 = {0:211, 1:66}, seed=7 = {0:211, 1:66} — stratification
  respectée.
- **Pas de fuite test→train sur le pipeline** : le `TfidfVectorizer` est **fit
  uniquement sur `train+val`** via `Pipeline.fit(fit_samples)`
  (`phishing_detector.py:141`, appelé sur `fit_samples = train + val` en
  `train.py:242-244`). Le test (`detector.predict(test)`) n'entre **jamais** dans
  le fit du vectoriseur. **Correct** — pas de fuite *classique* du vectoriseur.
- **Métriques sur test jamais vu** : `train.py:257` évalue sur `test`.
- **Reproductibilité inter-graines** :
  - seed=42 : acc 0.9495 / prec 1.00 / recall 0.7879 / f1 0.8814 / CM(tp52 fp0 tn211 fn14)
  - seed=7  : acc 0.9639 / prec 0.9828 / recall 0.8636 / f1 0.9194 / CM(tp57 fp1 tn210 fn9)
  ⇒ cohérent et stable.
- **Matrice de confusion exacte** : recalcul manuel sur CM seed=7 →
  acc 0.9639, prec 0.9828, recall 0.8636, f1 0.9194 — **identique** à
  `evaluation.py`. Formules `evaluation.py:75-82` correctes.

### 2. Datasets — **OK partiel**
- **Registre de sources** : structuré et correct dans la forme ; licences
  imprécises pour 2 sources (cf. MINEUR-2).
- **Mode hors-ligne** : `download_source` (l.119-173) attrape toutes les
  exceptions réseau et **retourne `None` sans lever** ; `load_external` lit ce qui
  est présent dans `data/external/`. **Robuste.**
- **Dédoublonnage** : présent (`_dedupe`, l.483-493) mais opère sur `raw_text`
  brut → **inefficace** contre les quasi-doublons synthétiques (cf. MAJEUR-1).
  Mesure : 0 doublon brut, mais 26 doublons après nettoyage. **KO sur ce point.**
- **Déséquilibre** : 1055 légit / 327 phishing (≈3,2:1). Géré par
  `class_weight="balanced"` (`phishing_detector.py:136`). Acceptable.
- **Ratio synthétique** : plafonné à 25 % (`max_synthetic_ratio=0.25`,
  `dataset_downloader.py:543`) — atteint exactement (345/1382 = 25 %).
  **Raisonnable et documenté**, mais la classe phishing est **53 % synthétique**
  (173/327), ce qui n'est pas plafonné par classe — d'où le biais.
- **Fuite synthétique→test** : **confirmée** (MAJEUR-1).

### 3. Représentativité / biais — **KO (à corriger/documenter)**
- Réel = anglais uniquement ; FR/CM = 100 % synthétique (MINEUR-1).
- recall 0.79 = 14 FN : **honnêtement reporté** dans le registre, **mais agrégat
  trompeur** (réel 0.56 vs synthétique 1.00) — MAJEUR-2.
- Recommandations concrètes : ventiler les métriques, baisser+calibrer le seuil,
  group-split anti-fuite, acquérir du phishing FR/CM réel (cf. MAJEUR-1/2).

### 4. Inférence temps réel — **OK**
- **Cohérence train/serve** : `inference.py:237` et `realtime.py` appellent le
  **même** `preprocess`/`clean_text` (bloc 2) qu'à l'entraînement. Le
  prétraitement est **stateless** (regex pures, aucun état fitté) ⇒ **aucun risque
  de skew train/serve**. Vérifié end-to-end : un SMS loterie FR donne
  `clean_text='felicitations vous avez gagne <MONEY> a la loterie mtn appelez
  <PHONE>'`, détecteur `tfidf_rf`, score 0.6331, `is_phishing=True`.
- **Modèle versionné bien chargé** : `phishing_detector.load()` (l.286-291)
  résout via `model_registry.load_current("tfidf_rf")` (alias `CURRENT.txt`,
  portable Windows), repli sur joblib historique. Vérifié : détecteur chargé =
  `tfidf_rf`, `is_trained=True`.
- **Seuil configurable** : `settings.phishing_threshold` (env `PHISHING_THRESHOLD`,
  `config.py:53`), appliqué à la prédiction (`phishing_detector.py:186`).
  *(Réserve : valeur 0.5 trop haute, cf. MAJEUR-2.)*

### 5. BERT — **OK**
- **Dégradation propre sans torch** : `bert_detector.py` importe torch/transformers
  paresseusement ; `is_available()` (l.83-86) renvoie `False` ici ; `train()` lève
  une `RuntimeError` actionnable (l.131-132) ; `predict()` renvoie des prédictions
  **neutres** (score 0.0, non-phishing) sans casser le pipeline (l.348-353).
- **Activation réaliste/documentée** : `get_detector("auto")`
  (`bloc3_ia/__init__.py:64-73`) ne sélectionne BERT que si deps **ET** poids
  présents, sinon repli TF-IDF/heuristique. `train.py:_train_bert` (l.317-323)
  sort proprement (code 0) avec hint d'installation si deps absentes. Cohérent et
  honnête : **aucun faux-semblant** de modèle BERT actif.

---

## SYNTHÈSE PRIORISÉE DES ACTIONS

| Prio | Action | Fichier |
|------|--------|---------|
| 1 (MAJEUR-1) | Dédoublonner sur `clean_text` OU group-split par template | `dataset_downloader.py:477-493`, `train.py:117-174` |
| 2 (MAJEUR-2) | Ventiler le rappel réel/synthétique + FR/EN ; baisser & calibrer le seuil | `evaluation.py`, `config.py:53` |
| 3 (MAJEUR-1) | Enrichir la diversité des templates (≥15-20/scénario) | `corpus_generator.py:169-410` |
| 4 (MINEUR-1) | Documenter la limite « FR/CM = 100 % synthétique » | `docs/`, `meta.json` |
| 5 (MINEUR-2) | Figer licences/miroirs pérennes ; PhishTank en https | `dataset_downloader.py:46-100` |

**En l'état, le système est un prototype défensif honnête et fonctionnel, mais sa
performance réelle sur le phishing FR/CM est surévaluée par la fuite synthétique
et doit être corrigée avant déploiement opérationnel.**
