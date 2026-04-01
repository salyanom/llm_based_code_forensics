$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

Write-Host "Starting Qdrant..."
docker compose -f docker-compose.qdrant.yml up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "Qdrant failed to start. The API will still run with local fallback search." -ForegroundColor Yellow
    Write-Host "Tip: run 'docker compose -f docker-compose.qdrant.yml pull' and retry." -ForegroundColor Yellow
}

Write-Host "Starting API server on http://localhost:8000 ..."
& ".\venv\Scripts\python.exe" -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
