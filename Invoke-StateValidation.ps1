#Requires -Version 5.1
<#
.SYNOPSIS
    Audit the Group Enumerator SQLite state database for integrity / consistency.

.DESCRIPTION
    Read-only. Runs the state-DB consistency checks (Test-StateDbConsistency ->
    state_db.py validate) and prints a RAG-style report: SQLite integrity, foreign-key
    references, group/member identity, snapshot member-count agreement, and
    reuse-basis completeness (the incremental-reuse decay detector).

    Safe to schedule (e.g. a nightly integrity check). Exit code:
        0  no errors (clean, or warnings only)
        1  one or more errors  (or the validator could not run)
        2  the database file does not exist

.PARAMETER DbPath
    Path to the SQLite database. Defaults to the config's SqliteDbPath, else
    State\group-enumerator.db under the script root.

.PARAMETER ConfigPath
    Optional config file to read SqliteDbPath from.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-StateValidation.ps1
.EXAMPLE
    .\Invoke-StateValidation.ps1 -DbPath .\State\group-enumerator.db
#>
[CmdletBinding()]
param(
    [Parameter()][string]$DbPath,
    [Parameter()][string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

. (Join-Path $scriptRoot 'Modules\GroupEnumLogger.ps1')
. (Join-Path $scriptRoot 'Modules\StateDatabase.ps1')

# ---- Resolve the DB path (param > config > default) ----
if (-not $DbPath) {
    $cfgFile = if ($ConfigPath) { $ConfigPath } else { Join-Path $scriptRoot 'Config\group-enum-config.json' }
    $sqlitePath = $null
    if (Test-Path $cfgFile) {
        try { $sqlitePath = (Get-Content $cfgFile -Raw | ConvertFrom-Json).SqliteDbPath } catch { }
    }
    if ($sqlitePath) {
        $DbPath = if ([System.IO.Path]::IsPathRooted($sqlitePath)) { $sqlitePath } else { Join-Path $scriptRoot $sqlitePath }
    } else {
        $DbPath = Join-Path $scriptRoot (Join-Path 'State' 'group-enumerator.db')
    }
}

Write-Host ''
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator - State Consistency Audit' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host "Database: $DbPath" -ForegroundColor Gray

if (-not (Test-Path $DbPath)) {
    Write-Host "  [skip] database file does not exist yet (nothing to audit)." -ForegroundColor Yellow
    exit 2
}

$v = Test-StateDbConsistency -DbPath $DbPath
if ($null -eq $v -or -not $v.ContainsKey('Checks')) {
    Write-Host '  [ERROR] validator did not return a result (is Python available?).' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host ('Schema version: {0}' -f $(if ($null -ne $v.SchemaVersion) { $v.SchemaVersion } else { 'unknown' })) -ForegroundColor Gray
Write-Host ''
$pad = 26
foreach ($c in $v.Checks) {
    $sev = [string]$c.Severity
    $tag = switch ($sev) { 'ok' { '[ OK ]' } 'warn' { '[WARN]' } 'error' { '[FAIL]' } default { '[????]' } }
    $col = switch ($sev) { 'ok' { 'Green' } 'warn' { 'Yellow' } 'error' { 'Red' } default { 'Gray' } }
    Write-Host ('  {0} {1} {2}' -f $tag, ([string]$c.Name).PadRight($pad), $c.Detail) -ForegroundColor $col
}

Write-Host ''
$summaryCol = if ([int]$v.Errors -gt 0) { 'Red' } elseif ([int]$v.Warnings -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ('Result: {0}  ({1} error(s), {2} warning(s))' -f $(if ([bool]$v.Ok) { 'PASS' } else { 'FAIL' }), [int]$v.Errors, [int]$v.Warnings) -ForegroundColor $summaryCol
Write-Host ''

exit $(if ([int]$v.Errors -gt 0) { 1 } else { 0 })
