param(
    [Parameter(Position=0)]
    [ValidateSet('start','stop','status','reset','clean-comments','logs','test','sonar','scan-semgrep','scan-sonar','scan')]
    [string]$Action = 'start'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot

function Invoke-Docker {
    param([string[]]$DockerArgs)
    & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed (exit $LASTEXITCODE)." }
}
function Clean-Comments {
    foreach ($service in @('vulnerable','fixed')) {
        Invoke-Docker -DockerArgs @('compose','exec','-T',$service,'flask','--app','portal.main:create_app','clean-comments')
    }
}
function Save-WafLogs {
    $lines = & docker compose logs --no-color --no-log-prefix waf 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Could not read WAF logs.' }
    $file = Join-Path $projectRoot 'logs\waf.log'
    [IO.File]::WriteAllLines($file, [string[]]$lines, [Text.UTF8Encoding]::new($false))
    Write-Host 'PASS: logs/waf.log saved (contains synthetic lab request data).'
}
function Scan-Semgrep {
    Invoke-Docker -DockerArgs @('compose','--profile','tools','run','--rm','--no-deps','semgrep')
    Write-Host 'PASS: Semgrep completed. Findings are not scanner failures. See reports/generated.'
}
function Scan-Sonar {
    if (-not $env:SONAR_TOKEN) { throw 'SONAR_TOKEN is missing. Follow reports/SONAR-SETUP.md; never put the token in a file.' }
    $status = Invoke-RestMethod -Uri 'http://localhost:9000/api/system/status' -TimeoutSec 10
    if ($status.status -ne 'UP') { throw 'SonarQube is not ready. Run lab.ps1 sonar first.' }
    foreach ($variant in @('vulnerable','fixed')) {
        Invoke-Docker -DockerArgs @('compose','--profile','tools','run','--rm','--no-deps','scanner',"-Dproject.settings=sast/sonar-$variant.properties")
    }
    & (Join-Path $PSScriptRoot 'export-sonar.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'SonarQube analysis/export failed.' }
}

try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI not found. Install/start Docker Desktop with Linux containers; see README.md.' }
    Invoke-Docker -DockerArgs @('info','--format','{{.OSType}}')
    $engine = & docker info --format '{{.OSType}}'
    if ($engine -ne 'linux') { throw 'Switch Docker Desktop to Linux containers.' }
    switch ($Action) {
        # nginx resolves its literal proxy_pass backend at startup. Recreate the
        # whole stand so WAF cannot retain an old backend IP after an app rebuild.
        'start' { Invoke-Docker -DockerArgs @('compose','up','--build','--force-recreate','-d','--wait','--wait-timeout','180') }
        'stop' { Invoke-Docker -DockerArgs @('compose','--profile','analysis','stop') }
        'status' { Invoke-Docker -DockerArgs @('compose','--profile','analysis','ps') }
        'reset' {
            foreach ($service in @('vulnerable','fixed')) {
                Invoke-Docker -DockerArgs @('compose','exec','-T',$service,'flask','--app','portal.main:create_app','reset-db')
            }
            Write-Host 'PASS: both synthetic databases reset; SonarQube data preserved.'
        }
        'clean-comments' { Clean-Comments }
        'logs' { Save-WafLogs; Get-Content -LiteralPath (Join-Path $projectRoot 'logs\waf.log') -Tail 100 -Encoding UTF8 }
        'test' {
            Invoke-Docker -DockerArgs @('compose','up','--build','--force-recreate','-d','--wait','--wait-timeout','180')
            Invoke-Docker -DockerArgs @('compose','--profile','checks','build','checks')
            $failed = $false
            foreach ($mode in @('vulnerable','waf','fixed')) {
                Clean-Comments
                & docker compose --profile checks run --rm checks --mode $mode
                if ($LASTEXITCODE -ne 0) { $failed = $true }
            }
            Clean-Comments
            Save-WafLogs
            & docker compose --profile checks run --rm --no-deps --entrypoint python checks check_waf_logs.py
            if ($LASTEXITCODE -ne 0) { $failed = $true }
            if ($failed) { throw 'One or more HTTP/audit checks failed. Inspect reports/generated and logs/waf.log.' }
            Write-Host 'PASS: normal operations, attacks, fixes, separate sessions and WAF audit correlation.'
        }
        'sonar' { Invoke-Docker -DockerArgs @('compose','--profile','analysis','up','-d','--wait','--wait-timeout','660','sonarqube') }
        'scan-semgrep' { Scan-Semgrep }
        'scan-sonar' { Scan-Sonar }
        'scan' { Scan-Semgrep; Scan-Sonar }
    }
    exit 0
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
