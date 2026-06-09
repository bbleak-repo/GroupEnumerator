#Requires -Version 5.1
<#
.SYNOPSIS
    Membership churn / re-grant ("access flapping") report over the change ledger.

.DESCRIPTION
    Reads the change ledger (SQLite or JSON backend) over a time window and flags accounts that
    were REMOVED then ADDED again (re-grants) -- repeated cycles ("was there, removed, re-added,
    removed, re-added") are a governance red flag, especially in privileged groups. Reuses the
    same change-window logic as the enumerator and the RC08 privileged-name classifier.

    Detects oscillation that crosses enumeration runs (run cadence bounds resolution -- an
    add+remove entirely between two runs is not in the ledger; frequent/business-hours runs
    catch more).

    Exit code (for gating): 0 = no re-grants, 2 = re-grants found, 1 = error.

.PARAMETER DbPath      SQLite DB (default: config SqliteDbPath, else State\group-enumerator.db).
.PARAMETER StatePath   State directory holding changelog.jsonl for the JSON backend (default State\).
.PARAMETER Backend     Auto (default) | Sqlite | Json.
.PARAMETER Days        Window size in days back (default 30). Used unless -Since or -Period is given.
.PARAMETER Since       Explicit window start date (overrides -Days / -Period).
.PARAMETER Period      Day | Week | Month | Quarter (overrides -Days).
.PARAMETER CsvName     Restrict to one CSV source's groups (SQLite only).
.PARAMETER MinReGrants Minimum re-grants to flag an account (default 1).
.PARAMETER PrivilegedOnly  Only report re-grants in privileged groups.
.PARAMETER ExportCsv   Also write the flagged rows to this CSV path.
.PARAMETER OutputHtml  Also write a self-contained HTML report to this path.
.PARAMETER Quiet       Print only the summary + verdict.

.EXAMPLE
    .\Invoke-MembershipChurn.ps1 -Days 30
.EXAMPLE
    .\Invoke-MembershipChurn.ps1 -Since 2026-05-01 -PrivilegedOnly -OutputHtml .\Output\churn.html
#>
[CmdletBinding()]
param(
    [string]$DbPath,
    [string]$StatePath,
    [ValidateSet('Auto', 'Sqlite', 'Json')][string]$Backend = 'Auto',
    [ValidateRange(1, 36500)][int]$Days = 30,
    [Nullable[datetime]]$Since = $null,
    [ValidateSet('Day', 'Week', 'Month', 'Quarter')][string]$Period,
    [string]$CsvName,
    [ValidateRange(1, 1000)][int]$MinReGrants = 1,
    [switch]$PrivilegedOnly,
    [switch]$AllPrivileged,
    [string[]]$PrivilegedPattern,
    [switch]$ReplacePrivilegedBuiltins,
    [string]$ExportCsv,
    [string]$OutputHtml,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

. (Join-Path $scriptRoot 'Modules\GroupEnumLogger.ps1')
. (Join-Path $scriptRoot 'Modules\StateDatabase.ps1')
. (Join-Path $scriptRoot 'Modules\MembershipState.ps1')
. (Join-Path $scriptRoot 'Modules\MembershipChurn.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC00-Framework.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC08-PrivilegedRisk.ps1')

function Write-Rag {
    param([string]$Level, [string]$Text)
    $map = @{ OK = 'Green'; RISK = 'Red'; WARN = 'Yellow'; INFO = 'Gray' }
    $tag = switch ($Level) { 'OK' { '[ OK ]' } 'RISK' { '[RISK]' } 'WARN' { '[WARN]' } default { '[INFO]' } }
    Write-Host ("{0} {1}" -f $tag, $Text) -ForegroundColor $map[$Level]
}

# ---- Resolve the change window (Since > Period > Days(default 30)) ----
$rw = if ($Since) { Resolve-ChangeWindow -ChangeSince $Since }
      elseif ($PSBoundParameters.ContainsKey('Period') -and $Period) { Resolve-ChangeWindow -ChangePeriod $Period }
      else { Resolve-ChangeWindow -ChangeDays $Days }
$sinceDate   = $rw.SinceDate
$windowLabel = $rw.Label

# ---- Resolve sources ----
if (-not $DbPath) {
    $cfgFile = Join-Path $scriptRoot 'Config\group-enum-config.json'
    $sq = $null
    if (Test-Path $cfgFile) { try { $sq = (Get-Content $cfgFile -Raw | ConvertFrom-Json).SqliteDbPath } catch { } }
    $DbPath = if ($sq) { if ([System.IO.Path]::IsPathRooted($sq)) { $sq } else { Join-Path $scriptRoot $sq } }
              else { Join-Path $scriptRoot (Join-Path 'State' 'group-enumerator.db') }
}
$stateDir = if ($StatePath) { if ([System.IO.Path]::IsPathRooted($StatePath)) { $StatePath } else { Join-Path $scriptRoot $StatePath } }
            else { Join-Path $scriptRoot 'State' }
$jsonLog = Join-Path $stateDir 'changelog.jsonl'

$useSqlite = switch ($Backend) {
    'Sqlite' { $true }
    'Json'   { $false }
    default  { (Test-Path -LiteralPath $DbPath) -and (Test-PythonAvailable) }
}

Write-Host ''
Write-Host '===============================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator - Membership Churn / Re-grant' -ForegroundColor Cyan
Write-Host '===============================================' -ForegroundColor Cyan

# ---- Read events ----
$events = @()
try {
    if ($useSqlite) {
        if (-not (Test-Path -LiteralPath $DbPath)) { Write-Rag 'RISK' "No SQLite DB at: $DbPath"; exit 1 }
        $qArgs = @()
        if ($sinceDate) { $qArgs += @('--since', $sinceDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')) }
        if ($CsvName) { $qArgs += @('--csv-name', $CsvName) }
        # Assign first (NOT inline @()): Read-ChangeLog/Invoke-StateDb return ,@(...) which
        # inline @() would collapse to a single wrapper element. Coerce to array after.
        $events = Invoke-StateDb -Command 'query-changes' -DbPath $DbPath -Arguments $qArgs
        Write-Host "Source: SQLite  $DbPath" -ForegroundColor Gray
    } else {
        if (-not (Test-Path -LiteralPath $jsonLog)) { Write-Rag 'RISK' "No changelog found at: $jsonLog"; Write-Host 'Run with -TrackChanges first, or pass -DbPath / -StatePath.' -ForegroundColor Yellow; exit 1 }
        $rcArgs = @{ Path = $jsonLog }
        if ($sinceDate) { $rcArgs['Since'] = $sinceDate.ToUniversalTime() }
        $events = Read-ChangeLog @rcArgs
        Write-Host "Source: JSON    $jsonLog" -ForegroundColor Gray
    }
} catch {
    Write-Rag 'RISK' "Could not read the change ledger: $_"
    exit 1
}
$events = @($events)   # normalise to an array (handles the ,@() return wrapper)
Write-Host ("Window: {0}   (events analyzed: {1})" -f $windowLabel, $events.Count) -ForegroundColor Gray

# ---- Privileged classification (params override config: AllGroupsPrivileged / PrivilegedPatterns /
#      ReplacePrivilegedBuiltins). Built-in admin/operator detection by default. ----
$cfgPriv = $null
$cfgFileP = Join-Path $scriptRoot 'Config\group-enum-config.json'
if (Test-Path $cfgFileP) { try { $cfgPriv = Get-Content $cfgFileP -Raw | ConvertFrom-Json } catch { $cfgPriv = $null } }
$allPriv  = if ($PSBoundParameters.ContainsKey('AllPrivileged')) { [bool]$AllPrivileged } else { [bool]($cfgPriv -and $cfgPriv.AllGroupsPrivileged -eq $true) }
$privPats = if ($PrivilegedPattern) { $PrivilegedPattern } elseif ($cfgPriv -and $cfgPriv.PrivilegedPatterns) { @($cfgPriv.PrivilegedPatterns) } else { @() }
$replPriv = $ReplacePrivilegedBuiltins.IsPresent -or ($cfgPriv -and $cfgPriv.ReplacePrivilegedBuiltins -eq $true)
$pred = New-RCPrivilegedPredicate -ExtraPatterns $privPats -All:$allPriv -ReplaceBuiltins:$replPriv

# ---- Analyse ----
$churn = Get-MembershipChurn -Events $events -MinReGrants $MinReGrants `
    -PrivilegedNamePredicate $pred -PrivilegedOnly:$PrivilegedOnly
$sum = $churn.Summary
$records = @($churn.Records)

Write-Host ''
Write-Host ("Accounts flagged     : {0}" -f $sum.AccountsFlagged) -ForegroundColor $(if ($sum.AccountsFlagged -gt 0) { 'Red' } else { 'Green' })
Write-Host ("Total re-grants      : {0}" -f $sum.TotalReGrants) -ForegroundColor $(if ($sum.TotalReGrants -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ("Privileged re-grants : {0}" -f $sum.PrivilegedReGrants) -ForegroundColor $(if ($sum.PrivilegedReGrants -gt 0) { 'Red' } else { 'Green' })
Write-Host ("Groups affected      : {0}" -f $sum.GroupsAffected) -ForegroundColor Gray
Write-Host ''

if (-not $Quiet) {
    foreach ($r in $records) {
        $cur = if ($r.CurrentlyIn) { 'in group' } else { 'removed' }
        $gap = if ($null -ne $r.MinReAddGapHours) { "; fastest re-add $($r.MinReAddGapHours)h" } else { '' }
        $tag = if ($r.Privileged) { 'RISK' } else { 'WARN' }
        $pv  = if ($r.Privileged) { ' [PRIV]' } else { '' }
        Write-Rag $tag ("{0,-22} {1,-16} re-grants={2} ({3}){4}{5}" -f $r.Group, $r.Sam, $r.ReGrants, $cur, $gap, $pv)
    }
    if ($records.Count -gt 0) { Write-Host '' }
}

if ($ExportCsv) {
    try {
        if ($records.Count -gt 0) {
            $records | Select-Object Domain, Group, Sam, DisplayName, ReGrants, Adds, Removes, CurrentlyIn, MinReAddGapHours, Privileged, FirstSeen, LastSeen |
                Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
        } else {
            Set-Content -LiteralPath $ExportCsv -Value '"Domain","Group","Sam","DisplayName","ReGrants","Adds","Removes","CurrentlyIn","MinReAddGapHours","Privileged","FirstSeen","LastSeen"' -Encoding UTF8
        }
        Write-Host ("  Exported CSV: {0} ({1} row(s))" -f $ExportCsv, $records.Count) -ForegroundColor Gray
    } catch { Write-Host "  [warn] -ExportCsv failed: $_" -ForegroundColor Yellow }
}
if ($OutputHtml) {
    try {
        $null = New-ChurnHtmlReport -Churn $churn -WindowLabel $windowLabel -OutputPath $OutputHtml
        Write-Host ("  HTML report: {0}" -f $OutputHtml) -ForegroundColor Gray
    } catch { Write-Host "  [warn] -OutputHtml failed: $_" -ForegroundColor Yellow }
}

if ($sum.AccountsFlagged -eq 0) {
    Write-Rag 'OK' 'No re-grant / flapping accounts in the window.'
    Write-Host ''
    exit 0
}
Write-Rag 'RISK' ("FAIL: {0} account(s) re-granted in the window ({1} re-grant(s), {2} privileged)." -f $sum.AccountsFlagged, $sum.TotalReGrants, $sum.PrivilegedReGrants)
Write-Host ''
exit 2
