# Commits thematiques de la passe de finition — a lancer sur ta machine Windows.
# Usage : ouvrir PowerShell dans le dossier du projet puis : .\scripts\commit_finition.ps1
$ErrorActionPreference = "Stop"

# 0) Nettoyage des fichiers parasites (au cas ou)
git rm -r --cached --ignore-unmatch tmp_audit.py "pytest-cache-files-*" data/soc_dev.db data/soc_dev.db-journal 2>$null
if (Test-Path tmp_audit.py) { Remove-Item -Force tmp_audit.py }
Get-ChildItem -Directory -Filter "pytest-cache-files-*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

# 1) Securite API (auth prod, rate limiting, CORS, upload borne, en-tetes)
git add -A -- src/bloc5_dashboard/api/main.py src/bloc5_dashboard/api/security.py src/bloc5_dashboard/api/ratelimit.py src/bloc5_dashboard/api/inference.py
git commit -m "feat(securite): garde prod sans cle, rate limiting, CORS strict, upload borne (audit cyber)"

# 2) IA : calibrage du seuil + metriques par source + exposition API
git add -A -- src/bloc3_ia/train.py src/bloc3_ia/phishing_detector.py src/bloc3_ia/evaluation.py src/bloc3_ia/model_registry.py
git commit -m "feat(ia): calibrage du seuil sur validation, anti-fuite, metriques par source"

# 3) Frontend 100% fonctionnel (dashboard + console temps reel + upload)
git add -A -- src/bloc5_dashboard/frontend/
git commit -m "feat(frontend): dashboard SOC et console temps reel/upload cables sur l'API"

# 4) Proprete & robustesse (lifespan, smoke test, Makefile, gitignore)
git add -A -- src/bloc5_dashboard/api/main.py scripts/smoke_test.py Makefile .gitignore tmp_audit.py
git commit -m "chore: migration lifespan, smoke-test end-to-end, Makefile, .gitignore durci"

# 5) Documentation : audits experts + reponse + analyses
git add -A -- docs/
git commit -m "docs: audits cybersecurite & IA, reponse aux audits, plans d'analyse"

# 6) Reste eventuel (datasets, modeles ignores, etc.)
git add -A
git commit -m "chore: divers (datasets consolides, ajustements)" 2>$null

# 7) Push
git push origin main
Write-Host "`n=== Termine. Verifie le depot : https://github.com/orly2001/cyber-ia-cameroun ==="
