$ErrorActionPreference = "Continue"

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

Write-Host "Stopping API server processes..."
Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*Tree Sitter Demo*" } |
    Stop-Process -Force

Write-Host "Stopping Qdrant..."
$dockerReady = Test-DockerEngineAvailable

if ($dockerReady) {
    $previousErrorActionPreference = $ErrorActionPreference
    $script:ErrorActionPreference = "Continue"
    try {
        & docker compose -f docker-compose.qdrant.yml down
    } finally {
        $script:ErrorActionPreference = $previousErrorActionPreference
    }
} else {
    Write-Host "Docker is not available or the engine is not running. Skipping Qdrant shutdown." -ForegroundColor Yellow
}

Write-Host "Stopped."
