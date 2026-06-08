# Démo live — Scan de vulnérabilités (Bloc 1 ↔ Bloc 5)

Ce guide explique comment faire une démonstration **crédible et réelle** du Bloc 1
(scan de vulnérabilités) connecté à l'API du Bloc 5 (`/api/scan`), avec ou sans
infrastructure.

> ⚠️ **Éthique & légalité.** Ne scannez **que** des cibles que vous contrôlez ou
> qui autorisent explicitement les scans (`scanme.nmap.org`, DVWA local). Scanner
> un tiers sans autorisation écrite est illégal (loi camerounaise n°2010/012 sur
> la cybersécurité). En cas de doute, utilisez le **mode démo** ci-dessous.

---

## 1. Mode démo (sans aucune infra)

Le plus simple pour une démo live : aucune cible réelle, aucun outil externe.
L'API renvoie un échantillon de vulnérabilités **réalistes** (vraies CVE).

```bash
# Démarrer l'API
make run-api    # http://localhost:8000

# Appeler /api/scan en mode demo
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://localhost:8080","engine":"demo"}' | jq
```

Réponse type (extrait) :

```json
{
  "target": "http://localhost:8080",
  "engine": "demo",
  "count": 6,
  "duration_sec": 0.0,
  "vulnerabilities": [
    {"id": "demo-log4shell", "cve_id": "CVE-2021-44228", "cvss_score": 10.0, "...": "..."},
    {"id": "demo-apache-2449", "cve_id": "CVE-2021-41773", "cvss_score": 9.8, "...": "..."}
  ]
}
```

Pour **injecter** ces vulnérabilités dans le moteur d'alertes du dashboard,
ajoutez `"inject": true` au corps de la requête.

---

## 2. Démo web réelle — OWASP ZAP + DVWA

`docker-compose.scan.yml` (fourni séparément) démarre **DVWA** (cible web
volontairement vulnérable) et **OWASP ZAP** (scanner web piloté par API).

```bash
# Démarrer la stack de démo scan (ZAP + DVWA)
make scan-demo-up
# équivaut à : docker compose -f docker-compose.scan.yml up -d

# DVWA est exposé (par défaut) sur http://localhost:8080
# ZAP expose son API (par défaut) sur http://localhost:8090

# Lancer un scan web réel via l'API (moteur ZAP, routage auto sur URL http)
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://dvwa","engine":"auto"}' | jq

# Arrêter la stack
make scan-demo-down
```

Notes :

- En `engine: "auto"`, une cible commençant par `http://`/`https://` est routée
  vers **ZAP** ; une IP/hôte vers **nmap**.
- ZAP révèle typiquement XSS, SQLi, CSRF et en-têtes de sécurité manquants sur DVWA.
- L'URL ZAP/clé API se configure via `ZAP_API_URL` / `ZAP_API_KEY` (voir `.env`).

---

## 3. Démo réseau réelle — Nmap sur scanme.nmap.org

`scanme.nmap.org` est l'hôte public **prévu par le projet Nmap** pour tester les
scans (autorisé). Il figure déjà dans la liste blanche
(`nmap_allowed_targets`).

```bash
# Scan réseau réel (moteur nmap, routage auto sur hôte non-URL)
curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","engine":"nmap"}' | jq
```

Les services détectés (SSH, HTTP…) sont mappés en `Vulnerability` et enrichis via
l'API **NVD** lorsqu'un produit/version est identifiable.

---

## 4. Enrichissement CVE/NVD

L'enrichissement interroge la base publique **NVD** (aucune attaque). Pour
augmenter le quota, définissez une clé :

```bash
export NVD_API_KEY="votre-cle"   # ~0.6 s entre requêtes (sinon ~6 s)
```

En **mode hors-ligne** (sandbox, pas de réseau), l'enrichissement renvoie les
données inchangées **sans jamais lever d'exception** : la démo reste fonctionnelle.

---

## 5. Paramètres de `/api/scan`

| Champ     | Type    | Défaut  | Description                                             |
|-----------|---------|---------|--------------------------------------------------------|
| `target`  | string  | —       | IP / hôte / URL à scanner (obligatoire).               |
| `engine`  | string  | `auto`  | `auto` \| `nmap` \| `zap` \| `demo`.                   |
| `inject`  | bool    | `false` | Injecte les vulns dans le moteur d'alertes (dashboard).|
| `demo`    | bool    | `false` | Alias hérité : équivaut à `engine="demo"`.             |

Sécurité : endpoint protégé par `X-API-Key` lorsque `API_KEY` est configurée.
