param(
    [string]$Folder = "code_samples",
    [string]$Query = "scan all",
    [bool]$GeneratePatches = $true,
    [string]$ApiBase = "http://localhost:8000",
    [string]$SaveJsonPath = ""
)

$ErrorActionPreference = "Stop"

$healthUrl = "$ApiBase/health"
try {
    $null = Invoke-RestMethod -Method Get -Uri $healthUrl -TimeoutSec 5
}
catch {
    Write-Host "Cannot reach API at $ApiBase" -ForegroundColor Red
    Write-Host "Start it first:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\start-dev.ps1" -ForegroundColor Yellow
    exit 1
}

$payload = @{
    folder = $Folder
    query = $Query
    generate_patches = $GeneratePatches
} | ConvertTo-Json -Depth 8

$response = Invoke-RestMethod -Method Post -Uri "$ApiBase/scan" -ContentType "application/json" -Body $payload

if ($SaveJsonPath -ne "") {
    $response | ConvertTo-Json -Depth 25 | Out-File -FilePath $SaveJsonPath -Encoding utf8
    Write-Host "Saved full JSON report to: $SaveJsonPath" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "=== SCAN SUMMARY ===" -ForegroundColor Cyan
Write-Host ("Scan ID: {0}" -f $response.scan_id)
Write-Host ("Created: {0}" -f $response.created_at)
Write-Host ("Query:   {0}" -f $response.query)
Write-Host ("Files:   {0}" -f (($response.files_scanned -join ", ")))
Write-Host ("Totals:  functions={0} vulnerabilities={1}" -f $response.summary.total_functions, $response.summary.total_vulnerabilities)

if (-not $response.vulnerabilities -or $response.vulnerabilities.Count -eq 0) {
    Write-Host "No vulnerabilities found." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "=== FINDINGS ===" -ForegroundColor Cyan

$index = 1
foreach ($v in $response.vulnerabilities) {
    $sev = [string]$v.severity
    $sevColor = "White"
    if ($sev -eq "Critical") { $sevColor = "Red" }
    elseif ($sev -eq "High") { $sevColor = "DarkRed" }
    elseif ($sev -eq "Medium") { $sevColor = "Yellow" }
    elseif ($sev -eq "Low") { $sevColor = "Green" }

    Write-Host ("[{0}] {1} - {2}" -f $index, $sev, $v.type) -ForegroundColor $sevColor
    Write-Host ("    file={0}:{1} function={2}" -f $v.file, $v.line, $v.function_name)
    Write-Host ("    CWE={0} CVE={1} CVSS={2} Confidence={3}" -f $v.cwe, $v.cve, $v.cvss_score, $v.confidence)

    $why = [string]$v.explanation
    if ($why.Length -gt 180) {
        $why = $why.Substring(0, 177) + "..."
    }
    Write-Host ("    Analysis summary: {0}" -f $why)

    if ($v.patch_verification) {
        Write-Host ("    Patch verification: status={0} original_tainted_sinks={1} patched_tainted_sinks={2}" -f $v.patch_verification.status, $v.patch_verification.original_tainted_sinks, $v.patch_verification.patched_tainted_sinks) -ForegroundColor DarkGray
    }

    $index += 1
}
