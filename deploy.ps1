<#
  deploy.ps1 -- Deploiement COMPLET et autonome de la stack (db + api + frontend) sous Windows.
  Prend en charge TOUT ce qui est necessaire, et n'installe que ce qui manque :
    - verifie Docker (CLI) ; tente une installation via winget si absent ;
    - DEMARRE Docker Desktop automatiquement si le moteur ne tourne pas, puis attend ;
    - construit l'image API et telecharge les images db/web seulement si absentes ;
    - demarre la stack, attend la sante de l'API, ouvre le navigateur.
  Usage :
    .\deploy.ps1            # ou up
    .\deploy.ps1 down|logs|status
#>
param([string]$Command = "up")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-DockerEngine {
  # Retourne $true si le moteur Docker repond.
  $oldPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  } finally {
    $ErrorActionPreference = $oldPreference
  }
}
function Test-DockerCli { [bool](Get-Command docker -ErrorAction SilentlyContinue) }

function Start-DockerDesktop {
  $candidates = @(
    "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
    "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
    "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
  )
  foreach ($p in $candidates) {
    if (Test-Path $p) { Write-Host "Demarrage de Docker Desktop..." -ForegroundColor Yellow; Start-Process -FilePath $p | Out-Null; return $true }
  }
  return $false
}

function Ensure-Docker {
  # 1) CLI present ?
  if (-not (Test-DockerCli)) {
    Write-Host "Docker n'est pas installe." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      Write-Host "Installation de Docker Desktop via winget (cela peut prendre plusieurs minutes)..." -ForegroundColor Yellow
      winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
      Write-Host "Docker Desktop installe. Un redemarrage de session Windows peut etre requis." -ForegroundColor Yellow
    } else {
      Write-Host "winget introuvable. Installe Docker Desktop manuellement : https://www.docker.com/products/docker-desktop/" -ForegroundColor Red
      exit 1
    }
  }
  # 2) Moteur en marche ?
  if (Test-DockerEngine) { return }
  Write-Host "Le moteur Docker ne tourne pas -- tentative de demarrage automatique." -ForegroundColor Yellow
  if (-not (Start-DockerDesktop)) {
    Write-Host "Impossible de localiser Docker Desktop.exe. Lance Docker Desktop manuellement puis relance ce script." -ForegroundColor Red
    exit 1
  }
  Write-Host "Attente du moteur Docker (jusqu'a 180 s)..." -ForegroundColor Yellow
  for ($i=0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    if (Test-DockerEngine) { Write-Host "Moteur Docker pret." -ForegroundColor Green; return }
  }
  Write-Host "Docker ne repond toujours pas. Ouvre Docker Desktop, attends qu'il soit 'Running', puis relance." -ForegroundColor Red
  exit 1
}

# Choix de la commande compose (v2 plugin de preference).
function Get-Compose {
  & docker compose version *> $null
  if ($LASTEXITCODE -eq 0) { return "docker compose" }
  if (Get-Command docker-compose -ErrorAction SilentlyContinue) { return "docker-compose" }
  Write-Host "docker compose introuvable (Docker Desktop l'inclut normalement)." -ForegroundColor Red; exit 1
}

# Lecture des ports depuis .env si present.
$ApiPort = "8000"; $WebPort = "5173"
if (Test-Path ".env") {
  Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*API_PORT\s*=\s*(.+)$') { $ApiPort = $Matches[1].Trim() }
    if ($_ -match '^\s*WEB_PORT\s*=\s*(.+)$') { $WebPort = $Matches[1].Trim() }
  }
}

# Commandes sans build prealable.
if ($Command -in @("down","logs","status")) {
  Ensure-Docker
  $DC = Get-Compose
  switch ($Command) {
    "down"   { Invoke-Expression "$DC down"; Write-Host "Stack arretee." }
    "logs"   { Invoke-Expression "$DC logs -f" }
    "status" { Invoke-Expression "$DC ps" }
  }
  exit 0
}
if ($Command -ne "up") { Write-Host "Commande inconnue: $Command (up|down|logs|status)" -ForegroundColor Red; exit 2 }

# ---- UP ----
Ensure-Docker
$DC = Get-Compose
if (-not (Test-Path ".env")) { Copy-Item ".env.docker.example" ".env"; Write-Host "[.env cree depuis .env.docker.example]" -ForegroundColor Yellow }

Write-Host "== Build de l'image API + recuperation des images db/web (si absentes) ==" -ForegroundColor Cyan
Invoke-Expression "$DC up -d --build"
if ($LASTEXITCODE -ne 0) { Write-Host "Echec du demarrage de la stack. Voir les logs : .\deploy.ps1 logs" -ForegroundColor Red; exit 1 }

Write-Host "== Attente de l'API (entrainement du modele au 1er demarrage, soyez patient) ==" -ForegroundColor Yellow
$ok = $false
for ($i=0; $i -lt 80; $i++) {
  try { 
    $r = Invoke-RestMethod -Uri "http://localhost:$ApiPort/health" -TimeoutSec 2
    if ($r.status -eq "ok") { $ok = $true; break } 
  } catch { 
    Start-Sleep -Seconds 3 
  }
}
if ($ok) { Write-Host "API operationnelle sur :$ApiPort." -ForegroundColor Green }
else { Write-Host "L'API ne repond pas encore. Logs :" -ForegroundColor Red; Invoke-Expression "$DC logs --tail=50 api" }

try { Invoke-RestMethod -Method Post -Uri "http://localhost:$ApiPort/api/run-demo" -TimeoutSec 30 | Out-Null } catch {}

Start-Process "http://localhost:$WebPort/index.html"
Start-Sleep -Seconds 1
Start-Process "http://localhost:$WebPort/console.html"

Write-Host ""
Write-Host "================ DEPLOIEMENT PRET ================" -ForegroundColor Cyan
Write-Host " Dashboard SOC : http://localhost:$WebPort/index.html"
Write-Host " Console live  : http://localhost:$WebPort/console.html"
Write-Host " API + docs    : http://localhost:$ApiPort/docs"
Write-Host "--------------------------------------------------"
Write-Host " Logs  : .\deploy.ps1 logs     Arret : .\deploy.ps1 down"
Write-Host "=================================================" -ForegroundColor Cyan
