<#
  run_all.ps1 — Lance TOUS les services pour tester le produit en local (Windows).
  - prepare l'environnement Python (venv + dependances)
  - entraine le modele s'il est absent
  - demarre l'API FastAPI (http://localhost:8000)
  - sert le frontend (http://localhost:5173) -> autorise par le CORS
  - attend que tout reponde puis ouvre le dashboard et la console
  Usage :  ouvrir PowerShell dans le dossier du projet, puis :  .\scripts\run_all.ps1
  Pour arreter : fermer les 2 fenetres "API" et "FRONTEND" ouvertes, ou Ctrl+C dedans.
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "== Projet : $root ==" -ForegroundColor Cyan

# 1) venv + dependances
if (-not (Test-Path ".\venv\Scripts\python.exe")) {
  Write-Host "Creation du venv..." -ForegroundColor Yellow
  python -m venv venv
}
$py = ".\venv\Scripts\python.exe"
Write-Host "Installation des dependances (peut prendre un moment)..." -ForegroundColor Yellow
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements.txt

# 2) Entrainement du modele si absent
if (-not (Test-Path ".\models\registry\tfidf_rf\CURRENT.txt") -and -not (Test-Path ".\models\phishing_tfidf_rf.joblib")) {
  Write-Host "Aucun modele detecte -> entrainement (donnees consolidees)..." -ForegroundColor Yellow
  & $py -m src.bloc3_ia.train --model tfidf --seed 42
} else {
  Write-Host "Modele existant detecte." -ForegroundColor Green
}

# 3) Demarrage de l'API (nouvelle fenetre)
Write-Host "Demarrage de l'API sur http://localhost:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "cd '$root'; .\venv\Scripts\Activate.ps1; `$host.UI.RawUI.WindowTitle='API SOC :8000'; uvicorn src.bloc5_dashboard.api.main:app --host 127.0.0.1 --port 8000"
)

# 4) Service du frontend (nouvelle fenetre) sur le port autorise par le CORS
Write-Host "Service du frontend sur http://localhost:5173 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
  "-NoExit","-Command",
  "cd '$root'; `$host.UI.RawUI.WindowTitle='FRONTEND :5173'; $py -m http.server 5173 --directory src/bloc5_dashboard/frontend"
)

# 5) Attente que l'API reponde (/health)
Write-Host "Attente de l'API..." -ForegroundColor Yellow
$ok = $false
for ($i=0; $i -lt 30; $i++) {
  try {
    $r = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 2
    if ($r.status -eq "ok") { $ok = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $ok) { Write-Host "L'API ne repond pas encore ; verifie la fenetre 'API SOC :8000'." -ForegroundColor Red }
else { Write-Host "API operationnelle." -ForegroundColor Green }

# 6) Jeu de donnees de demo (alertes) pour peupler le dashboard
try { Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/run-demo" -TimeoutSec 20 | Out-Null } catch {}

# 7) Ouverture du navigateur
Start-Process "http://localhost:5173/index.html"
Start-Sleep -Seconds 1
Start-Process "http://localhost:5173/console.html"

Write-Host ""
Write-Host "================ PRET A TESTER ================" -ForegroundColor Cyan
Write-Host " Dashboard SOC : http://localhost:5173/index.html"
Write-Host " Console live  : http://localhost:5173/console.html"
Write-Host " API + docs    : http://localhost:8000/docs"
Write-Host " Sante         : http://localhost:8000/health"
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Pour arreter : fermer les fenetres 'API SOC :8000' et 'FRONTEND :5173'."
