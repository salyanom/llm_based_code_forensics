$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

function Test-DockerEngineAvailable {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        return $false
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $script:ErrorActionPreference = "Continue"
    try {
        & docker info *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $script:ErrorActionPreference = $previousErrorActionPreference
    }
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

 $dockerReady = Test-DockerEngineAvailable

if ($dockerReady) {
    Write-Host "Starting Qdrant..."
    $previousErrorActionPreference = $ErrorActionPreference
    $script:ErrorActionPreference = "Continue"
    try {
        & docker compose -f docker-compose.qdrant.yml up -d
    } finally {
        $script:ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Qdrant failed to start. The API will still run with local fallback search." -ForegroundColor Yellow
        Write-Host "Tip: run 'docker compose -f docker-compose.qdrant.yml pull' and retry." -ForegroundColor Yellow
    }
} else {
    Write-Host "Docker is not installed or not on PATH. Skipping Qdrant and using local fallback search." -ForegroundColor Yellow
}

Write-Host "Starting API server on http://localhost:8000 ..."
& ".\venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8000
