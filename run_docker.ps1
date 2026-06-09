# ============================================================
# NIDS — Docker launcher for Windows
# ============================================================
# Requires: Docker Desktop running
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  ########  NIDS Docker Launcher  ########" -ForegroundColor Cyan
Write-Host ""

# Check Docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Docker not found. Install Docker Desktop from https://docker.com" -ForegroundColor Red
    pause; exit 1
}

$dockerStatus = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Docker daemon is not running. Start Docker Desktop first." -ForegroundColor Red
    pause; exit 1
}
Write-Host "[OK] Docker is running" -ForegroundColor Green

# Build
Write-Host "[INFO] Building NIDS image..." -ForegroundColor Yellow
docker-compose build

# Start
Write-Host "[LAUNCH] Starting NIDS container at http://localhost:8501" -ForegroundColor Cyan
Write-Host "         Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""
docker-compose up
