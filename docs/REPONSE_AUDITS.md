# Réponse aux audits experts — corrections appliquées

_Date : 7 juin 2026._ Suite aux deux audits indépendants
([cybersécurité](AUDIT_CYBERSECURITE.md) & [IA](AUDIT_IA.md)), verdict initial
« Approuvé avec réserves ». Voici les correctifs appliqués et vérifiés.

## Cybersécurité & réseau

| Réf | Problème | Correctif appliqué | Vérifié |
|---|---|---|---|
| M1 | Auth « fail-open » si `API_KEY` vide | `enforce_production_security()` : démarrage **refusé** si `ENVIRONMENT=production` et `API_KEY` vide (dev reste permissif) | ✅ RuntimeError levé |
| M2 | Pas de rate limiting sur l'inférence | Middleware `ratelimit.py` (fenêtre glissante par IP) sur `/api/analyze*` et `/api/upload`, **429** au-delà du quota (`RATE_LIMIT_PER_MINUTE`, défaut 120) | ✅ 429 après quota |
| M3 | Upload lu entièrement en RAM avant contrôle de taille (DoS) | Lecture **bornée en flux** (coupure à 2 Mo sans charger le fichier entier) | ✅ 413 conservé |
| M4 | CORS `*` + `allow_credentials=True` | Jamais de wildcard avec credentials : liste blanche + creds, ou `*` sans creds ; méthodes/headers restreints | ✅ |
| mineur | En-têtes HTTP partiels | Ajout `Referrer-Policy`, `X-XSS-Protection` (+ `X-Content-Type-Options`, `X-Frame-Options` déjà présents) | ✅ |

Bons points confirmés par l'audit : contenu uploadé **jamais persisté** sur
disque (analyse en mémoire, pas de path traversal) ; **aucune** injection shell
(nmap/ZAP via libs Python) ; pas de fuite de PII/secret dans les logs ;
conteneur non-root.

## IA & données

| Réf | Problème | Correctif appliqué | Vérifié |
|---|---|---|---|
| MAJEUR-1 | Fuite synthétique → test (clean_text identiques) | **Déduplication par `clean_text`** avant le split (107 doublons retirés : 1382 → 1275) | ✅ métriques recalculées |
| MAJEUR-2 | Recall réel surévalué par l'agrégat | Métriques **honnêtes post-fuite** : Acc 0.94 / Prec 1.00 / Recall 0.71 / F1 0.83 (au lieu de 0.88 gonflé) | ✅ |

Bons points confirmés : pas de fuite du vectoriseur (fit sur train uniquement),
split réellement stratifié, matrice de confusion exacte, cohérence train/serve
parfaite (même `clean_text`), modèle versionné, BERT dégradé proprement.

## Limites assumées (travaux futurs)

- **Données FR/CM réelles** : le corpus réel téléchargeable est anglophone
  (UCI SMS Spam) ; le contexte camerounais reste couvert par le corpus
  synthétique. La performance réelle sur du phishing FR/CM est donc à confirmer
  avec des données terrain. Le `dataset_downloader` liste déjà des sources
  (PhishTank, OpenPhish, mirrors) téléchargeables sur une machine avec Internet.
- **Seuil de décision** : à 0.5 le modèle privilégie la précision (0 faux
  positif) au détriment du rappel ; `PHISHING_THRESHOLD` permet de l'abaisser
  pour capter plus de phishing selon la tolérance de l'entreprise.
- **CSV formula injection** : impact faible (aucun export tableur) ; à neutraliser
  si un export Excel est ajouté.
- **Mot de passe PostgreSQL** : changer `soc/soc` par défaut en production
  (voir `docs/DEPLOIEMENT.md`).
