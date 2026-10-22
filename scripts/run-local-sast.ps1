[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('vulnerable', 'fixed')]
    [string]$Variant,

    [switch]$RecreateDatabase
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
function Get-RepoRelativePath([string]$Path) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the repository: $fullPath"
    }
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}
function Invoke-LoggedProcess([string]$Executable, [string[]]$Arguments, [string]$LogBase) {
    $stdoutPath = "$LogBase.stdout.tmp"
    $stderrPath = "$LogBase.stderr.tmp"
    $argumentLine = ($Arguments | ForEach-Object { '"' + ($_ -replace '"', '\\"') + '"' }) -join ' '
    $process = Start-Process -FilePath $Executable -ArgumentList $argumentLine -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $combined = @()
    if (Test-Path -LiteralPath $stdoutPath) { $combined += Get-Content -LiteralPath $stdoutPath }
    if (Test-Path -LiteralPath $stderrPath) { $combined += Get-Content -LiteralPath $stderrPath }
    $combined | Set-Content -LiteralPath "$LogBase.log" -Encoding utf8
    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    return $process.ExitCode
}
$sourceDir = Join-Path $root $(if ($Variant -eq 'fixed') { 'app-fixed' } else { 'app' })
$lock = Get-Content -LiteralPath (Join-Path $root 'sast/codeql-lock.json') -Raw | ConvertFrom-Json
$toolRoot = Join-Path $root '.runtime/tools/codeql-bundle-v2.27.2'
$codeql = Get-ChildItem -LiteralPath $toolRoot -Filter 'codeql.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $codeql) { throw "CodeQL 2.27.2 bundle not found below $toolRoot. See reports/TASK-2-SAST.md." }
$codeql = $codeql.FullName
$codeqlVersion = (& $codeql version 2>&1 | Out-String).Trim()
$actualCodeQLVersion = [regex]::Match($codeqlVersion, 'toolchain release\s+([0-9]+(?:\.[0-9]+)+)').Groups[1].Value
if ($actualCodeQLVersion -ne $lock.cliVersion) { throw "Expected CodeQL $($lock.cliVersion), found: $codeqlVersion" }
$python = Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Project virtualenv Python not found: $python" }

$packManifest = Get-ChildItem -LiteralPath $toolRoot -Filter 'qlpack.yml' -File -Recurse |
    Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match '(?m)^name:\s*codeql/python-queries\s*$' } |
    Select-Object -First 1
if (-not $packManifest) { throw 'The official codeql/python-queries pack was not found in the CodeQL bundle.' }
$packText = Get-Content -LiteralPath $packManifest.FullName -Raw
$packVersion = [regex]::Match($packText, '(?m)^version:\s*([^\s#]+)').Groups[1].Value
if ($packVersion -ne $lock.queryPackVersion) { throw "Expected $($lock.queryPack) $($lock.queryPackVersion), found $packVersion" }
$suite = Join-Path $packManifest.DirectoryName 'codeql-suites/python-security-extended.qls'
if (-not (Test-Path -LiteralPath $suite)) { throw "Official python-security-extended suite is missing: $suite" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $root "reports/generated/codeql-sast/$Variant-$stamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$databaseRoot = Join-Path $root '.runtime/codeql/databases'
$database = Join-Path $databaseRoot $Variant
New-Item -ItemType Directory -Path $databaseRoot -Force | Out-Null
if ((Test-Path -LiteralPath $database) -and -not $RecreateDatabase) {
    throw "CodeQL DB already exists at $database. Use -RecreateDatabase to rebuild this exact local DB."
}

$sourceFiles = @(Get-ChildItem -LiteralPath $sourceDir -Recurse -File | Where-Object { $_.Extension -eq '.py' } | Sort-Object FullName)
$allFiles = @(Get-ChildItem -LiteralPath $sourceDir -Recurse -File | Sort-Object FullName)
$fileInventory = [ordered]@{
    variant = $Variant
    sourceRoot = Get-RepoRelativePath $sourceDir
    discoveredFiles = @($allFiles | ForEach-Object { Get-RepoRelativePath $_.FullName })
    pythonFiles = @($sourceFiles | ForEach-Object { Get-RepoRelativePath $_.FullName })
    nonPythonFiles = @($allFiles | Where-Object { $_.Extension -notin @('.py', '.pyc') } | ForEach-Object { Get-RepoRelativePath $_.FullName })
    generatedArtifacts = @($allFiles | Where-Object { $_.Extension -eq '.pyc' } | ForEach-Object { Get-RepoRelativePath $_.FullName })
}
$fileInventory | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDir 'source-inventory.json') -Encoding utf8

$createLog = Join-Path $reportDir 'codeql-database-create.log'
$analyzeLog = Join-Path $reportDir 'codeql-analyze.log'
$sarif = Join-Path $reportDir 'codeql.sarif'
$banditJson = Join-Path $reportDir 'bandit.json'
$banditLog = Join-Path $reportDir 'bandit.log'
$metadataPath = Join-Path $reportDir 'metadata.json'

Write-Host "Variant: $Variant"
Write-Host "Source:  $sourceDir"
Write-Host "Python files discovered: $($sourceFiles.Count)"
Write-Host "Reports: $reportDir"
Write-Host "Creating CodeQL database (local only)..."
if (Test-Path -LiteralPath $database) {
    $resolvedDatabase = [IO.Path]::GetFullPath($database)
    $resolvedDatabaseRoot = [IO.Path]::GetFullPath($databaseRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedDatabase.StartsWith($resolvedDatabaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove DB outside $databaseRoot"
    }
    Remove-Item -LiteralPath $resolvedDatabase -Recurse -Force
}
$createExit = Invoke-LoggedProcess $codeql @('database', 'create', $database, '--language=python', "--source-root=$sourceDir", '--build-mode=none', '--no-run-unnecessary-builds', '--extractor-option=python.python_executable_name=python', '--overwrite', '--threads=0') ($createLog -replace '\.log$', '')
if ($createExit -ne 0) { Get-Content -LiteralPath $createLog; throw "CodeQL database creation failed (exit $createExit)." }

Write-Host "Running official codeql/python-queries@$packVersion python-security-extended suite..."
$analyzeExit = Invoke-LoggedProcess $codeql @('database', 'analyze', $database, $suite, '--format=sarif-latest', "--output=$sarif", '--threads=0') ($analyzeLog -replace '\.log$', '')
if ($analyzeExit -ne 0) { Get-Content -LiteralPath $analyzeLog; throw "CodeQL analysis failed (exit $analyzeExit)." }

Write-Host 'Running Bandit standard plugins with all severity/confidence levels...'
$banditExit = Invoke-LoggedProcess $python @('-m', 'bandit', '-r', $sourceDir, '--severity-level', 'all', '--confidence-level', 'all', '-f', 'json', '-o', $banditJson) ($banditLog -replace '\.log$', '')
if (-not (Test-Path -LiteralPath $banditJson)) { Get-Content -LiteralPath $banditLog; throw "Bandit did not produce JSON (exit $banditExit)." }

$packInfo = [ordered]@{
    variant = $Variant
    generatedAtLocal = (Get-Date).ToString('o')
    sourceDirectory = Get-RepoRelativePath $sourceDir
    codeqlVersion = $codeqlVersion
    codeqlPack = 'codeql/python-queries'
    codeqlPackVersion = $packVersion
    codeqlBundleSha256 = $lock.bundleSha256
    codeqlSuite = 'python-security-extended.qls (official suite from bundled codeql/python-queries pack)'
    codeqlDatabase = Get-RepoRelativePath $database
    codeqlDatabaseCreateLog = 'codeql-database-create.log'
    codeqlAnalysisLog = 'codeql-analyze.log'
    banditVersion = ((& $python -m bandit --version 2>&1 | Out-String).Trim())
    banditCommand = "python -m bandit -r $($fileInventory.sourceRoot) --severity-level all --confidence-level all -f json"
    banditExitCode = $banditExit
    outputs = @('codeql.sarif', 'bandit.json', 'source-inventory.json')
    codeqlDatabaseCommand = "codeql database create <db> --language=python --source-root=$($fileInventory.sourceRoot) --build-mode=none --no-run-unnecessary-builds --extractor-option=python.python_executable_name=python --threads=0"
    codeqlAnalyzeCommand = "codeql database analyze <db> codeql/python-queries/codeql-suites/python-security-extended.qls --format=sarif-latest --threads=0"
    noUpload = $true
}
$packInfo | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding utf8

$sarifDoc = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
$banditDoc = Get-Content -LiteralPath $banditJson -Raw | ConvertFrom-Json
$pythonSetupNotices = @(Select-String -LiteralPath $createLog -Pattern 'No installed Python found!').Count
$summary = [ordered]@{
    variant = $Variant
    reportDirectory = Get-RepoRelativePath $reportDir
    discoveredFiles = $allFiles.Count
    pythonFiles = $sourceFiles.Count
    nonPythonFiles = @($fileInventory.nonPythonFiles).Count
    codeqlResults = @($sarifDoc.runs[0].results).Count
    codeqlInvocationErrors = @($sarifDoc.runs[0].invocations[0].toolExecutionNotifications | Where-Object { $_.level -eq 'error' }).Count
    codeqlPythonLauncherNotices = $pythonSetupNotices
    banditResults = @($banditDoc.results).Count
    banditErrors = @($banditDoc.errors).Count
    banditExitCode = $banditExit
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $reportDir 'summary.json') -Encoding utf8
Write-Host ($summary | ConvertTo-Json -Depth 5)
if ($summary.codeqlInvocationErrors -gt 0 -or $summary.banditErrors -gt 0) { throw 'One or more scanners reported execution/parse errors; inspect report logs.' }
Write-Host 'Complete. No report was uploaded.'
