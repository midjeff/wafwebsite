# Export only analysis data. Never write credentials or Authorization headers.
$ErrorActionPreference = 'Stop'
$base = 'http://localhost:9000'
$outputDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'reports\generated'
function Save-Json($Name, $Data) {
    $json = ConvertTo-Json -InputObject $Data -Depth 100
    [IO.File]::WriteAllText((Join-Path $outputDir $Name), $json, [Text.UTF8Encoding]::new($false))
}
try {
    if (-not $env:SONAR_TOKEN) { throw 'Missing SONAR_TOKEN.' }
    $headers = @{ Authorization = "Bearer $env:SONAR_TOKEN" }
    foreach ($variant in @('vulnerable','fixed')) {
        $taskFile = Join-Path $outputDir "sonar-$variant-report-task.txt"
        $properties = ConvertFrom-StringData ([IO.File]::ReadAllText($taskFile))
        $complete = $false
        for ($i=0; $i -lt 120; $i++) {
            $result = Invoke-RestMethod -Uri "$base/api/ce/task?id=$($properties.ceTaskId)" -Headers $headers -TimeoutSec 20
            if ($result.task.status -eq 'SUCCESS') { $complete = $true; break }
            if ($result.task.status -in @('FAILED','CANCELED')) { throw "Analysis $variant ended: $($result.task.status)" }
            Start-Sleep -Seconds 2
        }
        if (-not $complete) { throw "Analysis $variant is still pending; rerun export-sonar.ps1 later." }
        Save-Json "sonar-$variant-task.json" $result
        foreach ($kind in @('issues','hotspots')) {
            $all = @()
            $page = 1
            do {
                $filter = if ($kind -eq 'issues') { "componentKeys=nexus-$variant" } else { "project=nexus-$variant" }
                $data = Invoke-RestMethod -Uri "$base/api/$kind/search?$filter&ps=500&p=$page" -Headers $headers -TimeoutSec 30
                $all += @($data.$kind)
                $total = if ($data.paging) { $data.paging.total } else { $data.total }
                $page++
            } while ($all.Count -lt $total -and $page -le 20)
            if ($all.Count -lt $total) { throw 'API pagination limit reached; export is incomplete.' }
            Save-Json "sonar-$variant-$kind.json" @{ items=$all; total=$total; project="nexus-$variant" }
        }
        $gate = Invoke-RestMethod -Uri "$base/api/qualitygates/project_status?projectKey=nexus-$variant" -Headers $headers -TimeoutSec 20
        Save-Json "sonar-$variant-qualitygate.json" $gate
        Write-Host "PASS: $variant analyzed and exported; quality gate=$($gate.projectStatus.status)."
    }
    $server = Invoke-RestMethod -Uri "$base/api/server/version" -Headers $headers -TimeoutSec 20
    Save-Json 'sonar-server.json' @{version=$server; exportedAt=[DateTime]::UtcNow.ToString('o')}
    exit 0
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    $headers = $null
}
