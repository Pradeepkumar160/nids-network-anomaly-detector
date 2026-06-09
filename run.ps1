# ============================================================
# NIDS — Network Intrusion Detector
# PowerShell launcher for Windows
# ============================================================
# Usage: Right-click → Run with PowerShell
#        OR from a PowerShell window: .\run.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  ########  NIDS Launcher  ########" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check Python ──────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python not found. Install Python 3.10+ from https://python.org" -ForegroundColor Red
    pause; exit 1
}
$pyVersion = python --version 2>&1
Write-Host "[OK] $pyVersion" -ForegroundColor Green

# ── 2. Create / activate virtual environment ─────────────────
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}
Write-Host "[INFO] Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# ── 3. Install / upgrade dependencies ────────────────────────
Write-Host "[INFO] Installing dependencies (this may take a minute the first time)..." -ForegroundColor Yellow
python -m pip install -q -r requirements.txt

# ── 4. Generate demo data if no datasets exist ────────────────
$datasets = Get-ChildItem "data\datasets\*.csv" -ErrorAction SilentlyContinue
if (-not $datasets) {
    Write-Host "[INFO] Generating demo dataset..." -ForegroundColor Yellow
    python generate_demo_data.py
}

# ── 5. Launch Streamlit ───────────────────────────────────────
Write-Host ""
Write-Host "[LAUNCH] Starting NIDS dashboard at http://localhost:8501" -ForegroundColor Cyan
Write-Host "         Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

streamlit run app.py `
    --server.port 8501 `
    --server.headless false `
    --browser.gatherUsageStats false
