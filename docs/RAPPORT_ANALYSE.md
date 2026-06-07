# Rapport d'analyse et d'améliorations — IA & Cybersécurité Cameroun

_Date : 7 juin 2026_

## 1. État initial du projet

Le dépôt ne contenait que la documentation : les 9 chapitres du mémoire (`.docx`)
et les diagrammes d'architecture (`.drawio`). **Aucun code** n'existait
(`README` et `requirements.txt` vides, pas de dossier `src/`). La plus grande
lacune était donc l'absence d'implémentation.

## 2. Ce qui a été construit

Implémentation complète et testée de l'architecture en 5 blocs :

- **Socle commun** (`src/common`) : contrats Pydantic partagés, configuration,
  base de données (SQLAlchemy), journalisation.
- **Bloc 1** — scan de vulnérabilités (Nmap, OWASP ZAP, enrichissement CVE/NVD) + mode démo.
- **Blocs 2–3** — collecte/prétraitement phishing + moteur IA (TF-IDF/RF, stub BERT,
  scoring vulnérabilités RF/XGBoost) avec repli heuristique.
- **Bloc 4** — corrélation (4 règles), score de risque composite, alertes.
- **Bloc 5** — API FastAPI (6 endpoints) + dashboard SOC (HTML/Chart.js).
- **`pipeline.py`** — orchestration end-to-end.
- **Tests** (`tests/`), `pytest.ini`, docs.

## 3. Vérifications réelles (exécutées)

- **32 tests pytest : 32 réussis (100 %).**
- **Pipeline démo** : 4 vulnérabilités, 10 messages, **3 alertes** générées et
  hiérarchisées (R1 CRITICAL 91,9 ; R3 HIGH 71,7 ; R2 LOW 30,8).
- **API** : tous les endpoints testés (health, run-demo, alerts, stats, filtre,
  PATCH statut, 404) — OK.
- **Modèle phishing** entraîné (TF-IDF + RandomForest), sérialisé et rechargé par
  le pipeline (exactitude indicative 0,90 sur le corpus de démo).

## 4. Bug corrigé

La sévérité d'une `Vulnerability` n'était pas dérivée de son score CVSS quand elle
était omise (les validateurs Pydantic v2 ne s'exécutent pas sur les valeurs par
défaut). Corrigé via un `model_validator(mode="after")`. Impact : la priorisation
des alertes dépend de cette dérivation.

## 5. Écarts mémoire ↔ code (décision : étendre le mémoire)

L'implémentation a fait évoluer la conception initiale. Plutôt que de brider le
code, ces évolutions sont documentées et justifiées dans le nouveau
**Chapitre 10 — Implémentation, tests et résultats** :

- Backend **FastAPI** au lieu de Flask (validation Pydantic, doc auto, async).
- **Schéma d'alertes enrichi** (listes d'IDs, `risk_score` numérique, `rationale`,
  actions recommandées).
- **Contrats de données typés** (Pydantic) matérialisant les interfaces JSON du ch. 3.

## 6. Travaux futurs prioritaires

1. Étendre le corpus camerounais (génération synthétique + collecte terrain).
2. Fine-tuner et activer le détecteur **BERT** multilingue.
3. Basculer la persistance sur **PostgreSQL** en production.
4. Éprouver les scans **Nmap/ZAP** sur un environnement de test autorisé.
