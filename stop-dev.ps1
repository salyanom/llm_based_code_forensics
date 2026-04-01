$ErrorActionPreference = "Continue"

Set-Location $PSScriptRoot

Write-Host "Stopping API server processes..."
Get-Process -Name python -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*Tree Sitter Demo*" } |
    Stop-Process -Force

Write-Host "Stopping Qdrant..."
docker compose -f docker-compose.qdrant.yml down

Write-Host "Stopped."
