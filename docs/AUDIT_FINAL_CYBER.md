# AUDIT FINAL — CYBERSÉCURITÉ & RÉSEAU
## Projet « IA & Cybersécurité Cameroun »

- **Auditeur** : Expert indépendant Cybersécurité & Réseau
- **Date** : 2026-06-08
- **Commit audité** : `ed7993b` (HEAD)
- **Périmètre** : Bloc 1 (scan Nmap/ZAP/CVE), `/api/scan`, surface API générale, artefacts Docker/CI, gestion des secrets.
- **Méthode** : revue de code + exécution réelle (pytest, TestClient FastAPI, parsing YAML, recherche de secrets).

---

## VERDICT : **VALIDÉ POUR DÉMO**

Le projet est **prêt pour la présentation**. Aucun problème **BLOQUANT** ni **MAJEUR** détecté.
Les défenses anti-injection, la liste blanche, l'authentification, le rate limiting,
le CORS, la gestion des secrets et la robustesse hors-ligne sont **correctement implémentés
et vérifiés par exécution réelle**. Seules quelques remarques **MINEURES** (durcissement
optionnel, non bloquant) sont relevées.

| Point | Sujet | État | Preuve |
|------|-------|------|--------|
| 1 | Scan Nmap réel | **OK** | Tests d'injection/whitelist verts (ci-dessous) |
| 2 | Scan ZAP réel | **OK** | Imports paresseux, flux complet, exception-safe |
| 3 | `/api/scan` | **OK** | Demo offline 200 ; auth 401/200 vérifiée |
| 4 | Enrichissement CVE/NVD | **OK** | Lazy `requests`, rate-limit, cache, offline tolérant |
| 5 | Démo Docker / CI | **OK** | YAML valide, non-root, pas de secret en dur |
| 6 | Surface API générale | **OK** | Rate limit, upload borné, CORS, headers, fail-open dev only |

---

## 1. SCAN NMAP RÉEL — **OK**
Fichier : `src/bloc1_scan/nmap_scanner.py`

- **Pas de `shell=True`** : `subprocess.run(command, ..., shell=False)` (ligne 182-189), arguments
  construits en **liste** via `build_command` (ligne 125-139). Aucun `os.system`, `eval`, `exec` métier
  dans tout `src/` (les seules occurrences `eval` sont `model.eval()` de PyTorch — légitime).
- **Anti-injection** : regex `_TARGET_RE = ^[A-Za-z0-9._:\-/]+$` (ligne 42) appliquée
  **toujours**, y compris en mode `force=True` (ligne 156-161). Tout méta-caractère shell est rejeté.
- **Whitelist** : `settings.nmap_allowed_targets` (`127.0.0.1,localhost,scanme.nmap.org`),
  vérifiée par `is_target_allowed` (ligne 118-120), contournable seulement par `force=True` explicite
  (ligne 164-171).
- **Binaire absent / timeout / OSError** : gérés (lignes 190-206), renvoient `[]` sans exception.
- **Parsing XML** : `xml.etree` stdlib, import paresseux, `ParseError` capturée, filtre `state="open"`
  (lignes 226-282).

**Preuve d'exécution :**
```
whitelist: ['127.0.0.1', 'localhost', 'scanme.nmap.org']
Nmap hors-whitelist 8.8.8.8 (attendu []): []
valid('127.0.0.1; rm -rf') attendu False: False
Nmap injection (force=True, attendu []): []
  reject '127.0.0.1 && cat /etc/passwd': True
  reject '$(whoami)': True
  reject '`id`': True
  reject 'a|b': True
```
Tests dédiés présents : `tests/test_nmap_scanner.py`.

---

## 2. SCAN ZAP RÉEL — **OK**
Fichiers : `src/bloc1_scan/zap_scanner.py`, `src/bloc1_scan/scanner.py`

- **Import paresseux** de `zapv2` dans `_connect` (ligne 96-105) : `ImportError` → warning + `None`,
  jamais d'exception.
- **Flux complet** : `urlopen` → `spider` (poll borné) → `ascan` optionnel (poll borné) → `core.alerts`
  (lignes 61-91). Polling avec `max_wait` (anti-boucle infinie, ligne 138-162).
- **Robustesse ZAP injoignable** : `scan` enveloppe tout le flux dans `try/except Exception` → `[]`
  (ligne 79-87). Démon absent = échec propre.
- **Mapping vers `Vulnerability`** : `_map_alert` (ligne 167-184) puis `_zap_alert_to_vuln`
  (`scanner.py` ligne 148-199) — risque ZAP → CVSS/sévérité, enrichissement CVE si `cveid` présent,
  description structurée (param, méthode, CWE, remédiation).

Tests dédiés présents : `tests/test_zap_scanner.py`.

---

## 3. `/api/scan` — **OK**
Fichier : `src/bloc5_dashboard/api/scan.py`

- **Auth** : `dependencies=[Depends(require_api_key)]` sur la route (ligne 83).
- **Modes engine** `auto|nmap|zap|demo` via `Literal` + `_resolve_engine` (lignes 28, 57-80).
  `auto` route URL→ZAP / hôte→nmap.
- **Mode demo = aucun appel réseau** : import paresseux de `sample_data.demo_vulnerabilities`
  (ligne 106-110), aucune instanciation de scanner.
- **Gestion d'erreurs** : `try/except` → HTTP 400 propre (lignes 105-122) ; cible vide → 400 (ligne 99-100).
- **Injection optionnelle** tolérante aux pannes (lignes 127-134).

**Preuve d'exécution (demo + auth) :**
```
DEMO status: 200 count: 6 engine: demo        # demo offline, 6 vulns, 0 appel réseau
scan sans cle (attendu 401): 401
scan mauvaise cle (attendu 401): 401
scan bonne cle (attendu 200): 200
```
Tests dédiés présents : `tests/test_scan_api.py`.

---

## 4. ENRICHISSEMENT CVE / NVD — **OK**
Fichier : `src/bloc1_scan/cve_enrichment.py`

- **`requests` lazy** (ligne 87) : `ImportError` → warning + `[]`.
- **Rate-limit thread-safe** : verrou + horodatage, délai adapté à la présence d'une clé
  (`0.6 s` avec clé, `6.0 s` sans) — lignes 33-57.
- **Cache mémoire** `_CACHE` (lignes 30, 82-84, 118) + `clear_cache()`.
- **Mode hors-ligne tolérant** : toutes les erreurs réseau/quota/payload capturées → `[]` ou objet
  inchangé, **jamais d'exception** (lignes 108-116, 187-191).
- **Parsing CVSS** : priorité v3.1 → v3.0 → v2 (`_extract_cvss`, lignes 232-247), CWE et références
  taggées exploit/patch.

---

## 5. DÉMO DOCKER / CI — **OK**
Fichiers : `Dockerfile`, `docker-compose.yml`, `docker-compose.scan.yml`, `docker/nginx.conf`,
`deploy.ps1`, `deploy.sh`, `.github/workflows/ci.yml`

- **YAML valide** (les 3 fichiers chargés sans erreur) :
  ```
  YAML OK
  ```
- **Utilisateur non-root** : `Dockerfile` crée `appuser` (uid 10001) et `USER appuser` (lignes 37-40).
- **Pas de secret en dur** : compose et scripts utilisent des variables d'env avec valeurs par défaut
  documentées (`${API_KEY:-}`, `${POSTGRES_PASSWORD:-soc}`, `${ZAP_API_KEY:-changeme}`).
  Aucune vraie clé (`AIza…`/Gemini) dans `deploy.sh`/`deploy.ps1`.
- **Cohérence** : ports alignés (`api:8000`, `web:5173→80`), `db` healthcheck + `depends_on:
  condition: service_healthy`, réseaux bridge isolés, volumes persistants (`pgdata`, `models`).
- **nginx** : statique en lecture seule, en-têtes de sécurité (`nosniff`, `SAMEORIGIN`, `no-referrer`),
  `/healthz`.
- **DVWA/ZAP** : stack `docker-compose.scan.yml` correctement isolée (`scan-net`), avertissements
  éthiques explicites.
- **CI** : workflow `ci.yml` valide — checkout, Python 3.11, install requirements, `compileall src`, `pytest`.

---

## 6. SURFACE API GÉNÉRALE — **OK**
Fichiers : `src/bloc5_dashboard/api/main.py`, `security.py`, `ratelimit.py`, `inference.py`,
`src/common/config.py`

- **Auth / fail-open** : `require_api_key` (`security.py`) compare en **temps constant**
  (`secrets.compare_digest`). Fail-open **uniquement en dev** (clé vide → warning).
- **Garde production** : `enforce_production_security()` (security.py ligne 69-85) **bloque le démarrage**
  si `ENVIRONMENT=production` et `API_KEY` vide ; **câblée** dans le `lifespan` de l'app (main.py ligne 50).
- **Rate limiting** : middleware en mémoire (`ratelimit.py`), fenêtre glissante par IP, 120 req/min
  par défaut sur `/api/analyze*` et `/api/upload`, renvoie 429 + `Retry-After`.
- **Upload borné** : `inference.py` — 2 Mo max (lecture par chunks de 64 Ko → 413), 5000 lignes (400),
  batch 1000 items (400) — lignes 44-48, 386-427.
- **CORS** : pas de wildcard `*` combiné aux credentials (main.py lignes 65-78) — liste blanche + creds,
  ou `*` sans creds.
- **En-têtes de sécurité** : `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `X-XSS-Protection` (main.py lignes 84-96).
- **Secrets / clé Gemini** : `.env` **gitignoré** (`git check-ignore .env` → `.env`) et **non tracké**
  (`git ls-files .env` → vide). La vraie clé (53 caractères) **n'apparaît dans AUCUN fichier tracké** :
  ```
  git grep "AQ.Ab8RN6"          -> (rien, rc=1)
  git grep -E "AIza[...]{20,}"  -> (rien, rc=1)
  git grep -F "<clé .env>"      -> (rien, rc=1)
  ```
  Les `.env.example` / `.env.docker.example` ne contiennent que des placeholders vides.

---

## TESTS AUTOMATISÉS
```
python3 -m pytest -q -p no:cacheprovider
........................................................................ [ 74%]
.........................                                                [100%]
97 passed
```
Suite **verte** (97 tests), dont des tests dédiés Bloc 1 : `test_nmap_scanner.py`,
`test_zap_scanner.py`, `test_scan_api.py`.

---

## PROBLÈMES PAR GRAVITÉ

### BLOQUANT
*Aucun.*

### MAJEUR
*Aucun.*

### MINEUR (durcissement optionnel, non bloquant pour la démo)

1. **Démon ZAP exposé sans restriction d'adresses** — `docker-compose.scan.yml:52`
   `-config api.addrs.addr.regex=true` avec `addr.name=.*` autorise l'API ZAP depuis n'importe quelle
   adresse. Acceptable car le port n'est publié que sur l'hôte et la stack est explicitement « machine
   locale uniquement ». *Correctif* : restreindre à `addr.name=127\.0\.0\.1` pour un durcissement.

2. **Clé ZAP par défaut `changeme`** — `docker-compose.scan.yml:51`. Valeur de démo documentée.
   *Correctif* : définir `ZAP_API_KEY` via `.env` pour toute exécution hors poste local.

3. **`POSTGRES_PASSWORD` par défaut `soc`** — `docker-compose.yml:19`. Valeur de dev. La garde
   `enforce_production_security` ne couvre que l'`API_KEY`. *Correctif* : exiger un mot de passe non
   trivial en production (documenté dans `.env.docker.example`, à appliquer au déploiement réel).

4. **Rate limiting mono-processus** — `ratelimit.py`. En mémoire, donc non partagé en cluster.
   Suffisant pour la démo. *Correctif* (prod multi-instances) : Redis / slowapi.

5. **CVSS v2 sans normalisation explicite de sévérité textuelle** — `cve_enrichment.py:244`.
   Comportement correct (repli sur `baseSeverity` de l'entrée v2). Aucune action requise.

---

## CONCLUSION
Le Bloc 1 (Nmap/ZAP/CVE) et la surface API respectent les bonnes pratiques de sécurité :
exécution sous-processus sans shell, validation anti-injection systématique, liste blanche,
authentification à temps constant avec garde de production, rate limiting, upload borné,
CORS strict, en-têtes de sécurité, et gestion robuste du mode hors-ligne. Les secrets ne sont
pas committés. La suite de tests est verte et les artefacts Docker/CI sont valides.

**Décision finale : VALIDÉ POUR DÉMO.** Les points mineurs relèvent du durcissement d'un
déploiement de production réel et ne conditionnent pas la présentation.
