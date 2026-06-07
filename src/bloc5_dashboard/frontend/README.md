# Frontend Bloc 5 — Dashboard SOC & Console d'analyse

Deux pages autonomes (HTML + CSS + JS *inline*, sans outil de build). Seule
dépendance externe : **Chart.js** chargé depuis le CDN Cloudflare (connexion
Internet requise pour les graphiques). Les deux pages consomment l'API FastAPI
du bloc 5.

## Les deux pages

### 1. `index.html` — Dashboard SOC (analystes)

Vue de supervision destinée à l'équipe sécurité.

- **KPI** : total d'alertes, alertes critiques, risque moyen, et infos du modèle
  de détection (`GET /api/model` : type, entraîné ou repli heuristique, seuil,
  métriques).
- **Graphiques** (Chart.js) : donut de répartition par sévérité, barres par statut.
- **Tableau des alertes** avec filtres (sévérité, statut, risque minimum) et
  boutons **Acquitter** / **Résoudre**.
- Bouton **Lancer la démo** pour générer des alertes de démonstration.
- **Repli propre** : si l'API est injoignable, un bandeau d'avertissement
  s'affiche, l'indicateur d'état passe au rouge et les actions sont neutralisées
  (pas de page blanche). Rafraîchissement automatique toutes les 30 s.

Endpoints utilisés : `GET /health`, `GET /api/stats`, `GET /api/model`,
`GET /api/alerts` (avec filtres `severity`, `status`, `min_risk`),
`PATCH /api/alerts/{id}`, `POST /api/run-demo`.

### 2. `console.html` — Console d'analyse temps réel (usagers)

Outil d'analyse à la demande pour les usagers.

- **Analyse d'un message** : zone de saisie + canal (SMS / EMAIL / URL) →
  verdict (phishing / légitime) avec code couleur, score, indicateurs détectés et
  texte nettoyé (`POST /api/analyze`).
- **Upload de fichier** `.csv` (colonne `raw_text` obligatoire) ou `.txt`
  (un message par ligne) → synthèse (n, n_phishing, taux) + tableau des résultats
  par message (`POST /api/upload`).
- **Flux temps réel** : interrogation toutes les ~3 s de `GET /api/live/recent`
  et `GET /api/live/stats` pour afficher les derniers événements analysés et un
  mini-graphe des scores récents (case « Actualisation auto » pour activer/couper).
- Gestion explicite des erreurs **400 / 401 / 413 / 429** en français.

Endpoints utilisés : `GET /health`, `POST /api/analyze`, `POST /api/upload`,
`GET /api/live/recent`, `GET /api/live/stats`.

## Configurer l'adresse de l'API (`API_BASE`)

En haut du bloc `<script>` de **chaque** page :

```js
const API_BASE = "http://localhost:8000";
```

Modifier cette constante si l'API tourne sur un autre hôte/port.

## Clé API (en-tête `X-API-Key`)

Certains endpoints sensibles (`PATCH /api/alerts/{id}`, `POST /api/run-demo`,
`POST /api/upload`) peuvent exiger une clé d'API **si** une clé est configurée
côté serveur (variable d'environnement `API_KEY`). En mode développement, sans
clé configurée, ces endpoints sont ouverts.

Chaque page propose un champ **« Clé API »** : s'il est rempli, sa valeur est
envoyée dans l'en-tête HTTP `X-API-Key`. En cas de réponse **401**, un message
invite à renseigner ce champ. La réponse **429** (limite de débit) est aussi
gérée par un message clair.

## Lancer

1. Démarrer l'API du bloc 5 depuis la racine du projet :

   ```bash
   uvicorn src.bloc5_dashboard.api.main:app --reload --port 8000
   ```

2. Ouvrir les pages dans un navigateur :
   - double-clic sur `index.html` / `console.html`, **ou**
   - les servir en local (recommandé pour éviter d'éventuels soucis CORS) :

     ```bash
     # depuis src/bloc5_dashboard/frontend
     python -m http.server 5173
     # puis http://localhost:5173/index.html  et  /console.html
     ```

   Les origines `http://localhost:5173` et `http://localhost:3000` sont
   autorisées par défaut côté API (voir `settings.cors_origins`).

## Notes

- Aucune dépendance hors Chart.js (CDN). Aucun `localStorage` requis.
- Design SOC sombre, responsive (cartes et grilles s'adaptent au mobile).
</content>
</invoke>
