# Dashboard SOC — Frontend (Bloc 5)

Tableau de bord SOC autonome (un seul fichier `index.html`, sans build tool).
Affiche les KPI, deux graphiques (sévérité, statut) et le tableau des alertes
servies par l'API du bloc 5.

## Ouvrir le dashboard

1. Lancer l'API du bloc 5 (depuis la racine du projet) :

   ```bash
   uvicorn src.bloc5_dashboard.api.main:app --reload --port 8000
   ```

2. Ouvrir `index.html` dans un navigateur :
   - double-clic sur le fichier, **ou**
   - le servir en local pour éviter d'éventuels soucis CORS/navigateur :

     ```bash
     # depuis src/bloc5_dashboard/frontend
     python -m http.server 5173
     # puis ouvrir http://localhost:5173
     ```

   Les origines `http://localhost:5173` et `http://localhost:3000` sont
   autorisées par défaut côté API (voir `settings.cors_origins`).

## Configurer l'adresse de l'API

En haut du bloc `<script>` de `index.html` :

```js
const API_BASE = "http://localhost:8000";
```

Modifier cette constante si l'API tourne sur un autre hôte/port.

## Mode hors-ligne

Si l'API est injoignable, le dashboard affiche un bandeau d'avertissement et
bascule sur des **données de démonstration locales** afin que la page reste
lisible. Les boutons d'action (Acquitter / Résoudre) sont désactivés dans ce mode.

## Fonctionnalités

- Cartes KPI : total des alertes, alertes critiques, risque moyen.
- Graphique donut : répartition par sévérité.
- Graphique barres : alertes par statut.
- Tableau : titre, sévérité (code couleur), risque, statut, date.
- Boutons **Acquitter** (`ACKNOWLEDGED`) et **Résoudre** (`RESOLVED`) → `PATCH /api/alerts/{id}`.
- Bouton **Lancer la démo** → `POST /api/run-demo` puis rafraîchissement.

Chart.js est chargé depuis le CDN Cloudflare (connexion Internet requise pour les graphiques).
