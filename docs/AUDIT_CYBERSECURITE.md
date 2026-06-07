# Audit de Cybersécurité — « IA & Cybersécurité Cameroun »

Auditeur : Expert indépendant Cybersécurité & Réseau (audit en lecture seule, aucune modification du code applicatif).
Date : 2026-06-07
Périmètre : sécurité applicative du produit de détection de phishing (API bloc 5, upload, auth, logs, secrets, bloc 1 scan).
Méthode : lecture de code + tests dynamiques via `TestClient` (FastAPI) + revue config/Docker.

---

## VERDICT : APPROUVÉ AVEC RÉSERVES

La posture de base est **solide** : limites de taille/lignes/batch présentes, validation d'extension, comparaison de clé en temps constant, en-têtes anti-clickjacking/sniffing, conteneur non-root, pas de secret en dur, pas d'injection shell, pas d'écriture de fichier arbitraire, pas de PII dans les logs. Aucun problème **BLOQUANT**.

Mise en production conditionnée à la correction des points **MAJEURS** ci-dessous (auth réellement activée, contrôle de taille en streaming, durcissement CORS).

---

## Problèmes par gravité

### MAJEUR

**M1 — Authentification désactivée par défaut (« fail-open »)**
`src/common/config.py:62` (`api_key = ""`) + `src/bloc5_dashboard/api/security.py:52-58`.
Si `API_KEY` est vide, `require_api_key` **laisse passer** toute requête (uniquement un warning). En production, un déploiement sans `API_KEY` exposerait `POST /api/upload`, `PATCH /api/alerts/{id}` et `POST /api/run-demo` au public.
*Preuve* : `POST /api/upload` sans en-tête `X-API-Key` => **200 OK**, `count=1` (clé non configurée).
*Correctif* : refuser le démarrage en mode non-dev si la clé est absente. Dans `security.py`, remplacer le repli silencieux par :
```python
if not expected:
    if settings.environment.lower() in {"production", "prod", "staging"}:
        raise HTTPException(status_code=503, detail="API_KEY non configurée (refus en production).")
    logger.warning("API_KEY non configurée : auth DÉSACTIVÉE (dev uniquement).")
    return
```

**M2 — Aucun rate limiting sur les endpoints publics et coûteux**
`src/bloc5_dashboard/api/inference.py:285` (`/api/analyze`), `:315` (`/api/analyze/batch`).
`/api/analyze` et `/api/analyze/batch` sont **publics** (pas de `Depends(require_api_key)`) et déclenchent prétraitement + inférence ML. Aucun throttling.
*Preuve* : 30 requêtes rapides sur `/api/analyze` => 30×200, aucun 429.
*Correctif* : ajouter `slowapi` (compatible sandbox PyPI) avec une limite par IP, ex. `@limiter.limit("60/minute")` sur `/api/analyze` et `/api/analyze/batch`, et une limite plus stricte sur `/api/upload`. À défaut, placer un reverse-proxy (nginx) avec `limit_req`.

**M3 — Contrôle de taille d'upload APRÈS lecture intégrale en mémoire (DoS mémoire)**
`src/bloc5_dashboard/api/inference.py:374-384`.
`raw = await file.read()` charge **tout** le corps en RAM **avant** le test `len(raw) > MAX_UPLOAD_BYTES`. La limite logique (413) fonctionne, mais un client peut forcer l'allocation de gigaoctets (Content-Length non borné par l'app) avant le rejet — vecteur de DoS si plusieurs requêtes concurrentes.
*Preuve* : `big.csv` (~2 Mo+) renvoie bien 413, mais seulement après lecture complète.
*Correctif* : lire en flux et couper dès dépassement :
```python
raw = bytearray()
while chunk := await file.read(64 * 1024):
    raw.extend(chunk)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Fichier trop volumineux.")
raw = bytes(raw)
```
Idéalement aussi rejeter en amont sur `request.headers["content-length"]`.

**M4 — CORS : `allow_origins=["*"]` combiné à `allow_credentials=True`**
`src/bloc5_dashboard/api/main.py:37-44`.
Si `CORS_ORIGINS` est vide, le repli est `["*"]` avec `allow_credentials=True` et `allow_methods=["*"]`. Cette combinaison est dangereuse (et non conforme : les navigateurs refusent `*`+credentials, mais la config révèle une intention trop permissive et peut être contournée selon la version). Origines, méthodes et en-têtes en wildcard exposent l'API à des requêtes cross-origin non maîtrisées.
*Correctif* : ne jamais retomber sur `["*"]`. Exiger une liste explicite ; si vide en production, lever une erreur. Restreindre `allow_methods` à `["GET","POST","PATCH"]` et `allow_headers` à `["Content-Type","X-API-Key"]`.

### MINEUR

**m1 — Injection de formules CSV (CSV/Formula Injection) non neutralisée**
`src/bloc5_dashboard/api/inference.py:450-497` (parsing) ; le `raw_text` est renvoyé tel quel dans `results[].clean_text`/echo.
Le contenu de cellules commençant par `= + - @` (ex. `=cmd|calc!A1`) est ingéré et restitué sans neutralisation.
*Preuve* : upload `inj.csv` contenant `=cmd|calc!A1`, `@SUM(1+1)`, `+1+2` => 200, contenu repris dans la réponse.
*Impact réel* : faible pour ce produit (les valeurs ne sont pas réécrites dans un fichier CSV/Excel téléchargeable, et le front doit échapper le HTML). Devient MAJEUR si une fonctionnalité d'export CSV/XLSX des résultats est ajoutée.
*Correctif* : si export tableur prévu, préfixer toute valeur commençant par `= + - @ \t \r` par une apostrophe `'` (ou un espace) à la génération du fichier exporté. Côté front, garantir l'échappement (textContent, pas innerHTML).

**m2 — Mot de passe Postgres faible « en dur » dans la config par défaut et Compose**
`src/common/config.py:41` (`soc:soc`), `docker-compose.yml` (`POSTGRES_PASSWORD: soc`).
Ce n'est pas un secret applicatif (pas de clé/API token), mais le couple `soc/soc` est un identifiant faible documenté comme valeur par défaut. Acceptable en dev local isolé ; à bannir en production.
*Correctif* : dans `docker-compose.yml`, lire `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set me}` et `DATABASE_URL` depuis l'environnement ; documenter une rotation forte. Le port 5432 n'est pas exposé hors réseau Compose (bon point).

**m3 — En-têtes de sécurité HTTP incomplets**
`src/bloc5_dashboard/api/main.py:47-57`.
Présents : `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (vérifié). Absents : `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`.
*Preuve* : sur `/health`, HSTS/CSP/Referrer-Policy = `None`.
*Correctif* : ajouter dans le middleware :
```python
response.headers["Referrer-Policy"] = "no-referrer"
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
response.headers["Content-Security-Policy"] = "default-src 'self'"
```

**m4 — `data/` (et potentiellement `models/`) copiés dans l'image Docker**
`Dockerfile` `COPY data/ ./data/`.
Risque d'embarquer la base SQLite de dev (`data/soc_dev.db`) ou des datasets dans l'image livrée.
*Correctif* : `.dockerignore` excluant `data/*.db`, `.env`, `models/registry/*` non nécessaires au runtime.

---

## Points 1 à 6 — Conclusions étayées

### 1. Upload de fichiers — OK avec réserves (M3, m1)
- Extension validée (`.csv`/`.txt` uniquement) — **OK**. Preuve : `evil.exe` => 400 « Extension non gérée ».
- Taille max 2 Mo (413), 5000 lignes max, batch 1000 — **OK** logiquement. Preuve : `big.csv` => 413. *Mais* lecture intégrale avant contrôle (M3).
- Fichier vide => 400, CSV sans colonne `raw_text` => 400 — **OK**.
- Encodage : `utf-8-sig` puis repli `latin-1`, sinon 400 propre — **OK**.
- Persistance : **le contenu uploadé n'est JAMAIS écrit sur disque** (analyse en mémoire). Aucune écriture de chemin arbitraire, pas de risque zip/path traversal. Grep `open(` dans l'API : aucune écriture. — **OK / bon point**.
- CSV bomb / formula injection : DictReader standard borné par la limite de lignes ; injection de formule non neutralisée (m1, impact faible sans export).

### 2. AuthN/AuthZ — KO partiel (M1, M2, M4)
- Endpoints modifiant l'état protégés par `Depends(require_api_key)` : `/api/upload` (inference.py:347-351), `/api/run-demo` (main.py:190-195), `PATCH /api/alerts/{id}` (main.py:131-136) — **OK structurellement**.
- Comparaison en temps constant via `secrets.compare_digest` — **OK** (security.py:61).
- **MAIS** clé vide par défaut => auth « fail-open » (M1). `/api/analyze` et `/api/analyze/batch` publics sans rate limiting (M2). CORS wildcard+credentials (M4).

### 3. En-têtes & surface HTTP — OK avec réserves (m3)
- 4xx/5xx propres : 400 (texte vide), 422 (enum invalide), 413 (trop gros), 404 (alerte absente). **Pas de fuite de stack trace ni de chemins** dans les messages d'erreur (vérifié). `run-demo` capture les exceptions et renvoie un message contrôlé (main.py:214-219) — **OK / bon point**.
- En-têtes sécurité partiels (m3).

### 4. Logs & données — OK (bon point)
- `logging_conf.py` : format simple, aucun handler exfiltrant.
- **Aucun logger n'émet `raw_text`, `clean_text`, `sender`, `source_ip` ni le contenu des messages analysés** (grep exhaustif : 0 correspondance). Les logs ne contiennent que des compteurs et des noms de classes/modèles. Pas de fuite de secret/PII. — **OK**.

### 5. Secrets & config — OK avec réserves (m2, m4)
- **Aucun secret applicatif en dur** : `nvd_api_key`, `zap_api_key`, `api_key` par défaut vides (config.py:47,50,62). `.env.example` ne contient que des placeholders vides. — **OK**.
- `.env` réel **absent du dépôt** et présent dans `.gitignore` (ligne 5). — **OK**.
- Conteneur **non-root** : `USER appuser` (uid 10001), `chown` appliqué (Dockerfile). — **OK / bon point**.
- Réserves : mot de passe Postgres faible par défaut (m2), `COPY data/` (m4).

### 6. Bloc 1 scan (nmap/ZAP) — OK (bon point)
- Avertissements éthiques/autorisation **présents et explicites** dans `scanner.py`, `nmap_scanner.py`, `zap_scanner.py` (« ne scannez que des cibles autorisées par écrit », mode `demo=True` sans réseau).
- **Aucune injection de commande shell** : nmap via `python-nmap` (`nmap.PortScanner().scan(hosts=..., arguments=...)`), ZAP via client `zapv2`. Pas de `subprocess`, `os.system`, `shell=True`, `eval`, `exec` dans la base de code. — **OK**.
- `joblib.load` (phishing_detector.py:302, vuln_scorer.py:287) : source **uniquement** issue du registre de modèles interne / chemin contrôlé par l'application, jamais d'un input utilisateur. Risque de désérialisation **non exploitable** par un attaquant externe. — **OK**.

---

## Synthèse priorisée des correctifs

| # | Gravité | Fichier:ligne | Action |
|---|---------|---------------|--------|
| M1 | MAJEUR | security.py:52 / config.py:62 | Refuser le démarrage sans `API_KEY` hors dev |
| M2 | MAJEUR | inference.py:285,315 | Rate limiting (slowapi) sur `/api/analyze*` et `/api/upload` |
| M3 | MAJEUR | inference.py:374 | Lecture en flux + coupure à la limite de taille |
| M4 | MAJEUR | main.py:37 | CORS : pas de wildcard, méthodes/headers restreints |
| m1 | MINEUR | inference.py:450 | Neutraliser l'injection de formule si export tableur |
| m2 | MINEUR | config.py:41 / compose | Mot de passe Postgres fort via env en prod |
| m3 | MINEUR | main.py:47 | Ajouter HSTS / CSP / Referrer-Policy |
| m4 | MINEUR | Dockerfile | `.dockerignore` pour `data/*.db`, `.env` |

Aucun problème BLOQUANT. Produit déployable après traitement des 4 points MAJEURS.
