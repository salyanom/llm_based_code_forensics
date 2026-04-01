param(
    [string]$ApiBase = "http://localhost:8000",
    [string]$DefaultFolder = "code_samples"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$ErrorActionPreference = "Stop"

function Convert-RestUtf8Text {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text -or $Text -eq "") {
        return $Text
    }

    # Fix common mojibake patterns when UTF-8 text was decoded as Windows-1252/Latin-1.
    if ($Text -match "[ðâÃ]") {
        try {
            $bytes = [System.Text.Encoding]::GetEncoding(1252).GetBytes($Text)
            $fixed = [System.Text.Encoding]::UTF8.GetString($bytes)
            if (-not [string]::IsNullOrWhiteSpace($fixed)) {
                return $fixed
            }
        }
        catch {
        }
    }

    return $Text
}

function Test-Api {
    param(
        [int]$MaxAttempts = 30,
        [int]$SleepSeconds = 2
    )

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            $null = Invoke-RestMethod -Method Get -Uri "$ApiBase/health" -TimeoutSec 5
            return $true
        }
        catch {
            if ($i -eq 1) {
                Write-Host "Waiting for API warm-up..." -ForegroundColor DarkGray
            }
            Start-Sleep -Seconds $SleepSeconds
        }
    }

    return $false
}

# Scan output formatting is handled by the Python backend.

if (-not (Test-Api)) {
    Write-Host "API is not reachable at $ApiBase" -ForegroundColor Red
    Write-Host "Start it first:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\start-dev.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Code Forensics Interactive Console" -ForegroundColor Cyan
Write-Host "Commands:" -ForegroundColor DarkGray
Write-Host "  scan [query]" -ForegroundColor DarkGray
Write-Host "  ask [question]" -ForegroundColor DarkGray
Write-Host "  refresh" -ForegroundColor DarkGray
Write-Host "  rescans" -ForegroundColor DarkGray
Write-Host "  use [scan_id]" -ForegroundColor DarkGray
Write-Host "  exit" -ForegroundColor DarkGray

$activeScanId = ""

while ($true) {
    $inputLine = Read-Host "forensics>>"
    if (-not $inputLine) { continue }

    $trimmed = $inputLine.Trim()
    if ($trimmed -eq "exit") { break }

    if ($trimmed -eq "refresh") {
        $refresh = Invoke-RestMethod -Method Post -Uri "$ApiBase/rag/refresh"
        Write-Host ("RAG refreshed. entries={0}" -f $refresh.stats.entries) -ForegroundColor Green
        continue
    }

    if ($trimmed -eq "rescans") {
        $scans = Invoke-RestMethod -Method Get -Uri "$ApiBase/scans"
        Write-Host "Recent scans:" -ForegroundColor Cyan
        foreach ($s in $scans) {
            Write-Host ("  {0}  {1}  {2}" -f $s.scan_id, $s.created_at, $s.query)
        }
        continue
    }

    if ($trimmed.StartsWith("use ")) {
        $candidate = $trimmed.Substring(4).Trim()
        if ($candidate) {
            $activeScanId = $candidate
            Write-Host ("Active scan set to: {0}" -f $activeScanId) -ForegroundColor Green
        }
        continue
    }

    if ($trimmed.StartsWith("scan")) {
        $query = "scan all"
        if ($trimmed.Length -gt 4) {
            $queryInput = $trimmed.Substring(4).Trim()
            if (-not $queryInput -or $queryInput.ToLower() -eq "all") {
                $query = "scan all"
            }
            else {
                $query = $queryInput
            }
        }

        $payload = @{
            folder = $DefaultFolder
            query = $query
            generate_patches = $true
        } | ConvertTo-Json -Depth 8

        $scanResponse = Invoke-RestMethod -Method Post -Uri "$ApiBase/scan" -ContentType "application/json" -Body $payload
        $activeScanId = [string]$scanResponse.scan_id
        if ($scanResponse.cli_report) {
            Write-Host ""
            Write-Host (Convert-RestUtf8Text -Text ([string]$scanResponse.cli_report))
        }
        else {
            Write-Host ("Scan completed. scan_id={0}" -f $activeScanId) -ForegroundColor Green
        }
        continue
    }

    if ($trimmed.StartsWith("ask ")) {
        $question = $trimmed.Substring(4).Trim()
        if (-not $question) {
            Write-Host "Please provide a question after ask." -ForegroundColor Yellow
            continue
        }

        $askPayload = @{
            prompt = $question
            scan_id = $(if ($activeScanId) { $activeScanId } else { $null })
            top_findings = 5
        } | ConvertTo-Json -Depth 8

        $askResponse = Invoke-RestMethod -Method Post -Uri "$ApiBase/assistant/ask" -ContentType "application/json" -Body $askPayload
        Write-Host ""
        Write-Host "=== ASSISTANT RESPONSE ===" -ForegroundColor Cyan
        if ($askResponse.scan_id) {
            Write-Host ("Using scan_id: {0}" -f $askResponse.scan_id) -ForegroundColor DarkGray
        }
        Write-Host $askResponse.answer
        continue
    }

    Write-Host "Unknown command. Use: scan [query], ask [question], refresh, rescans, use [scan_id], exit" -ForegroundColor Yellow
}
