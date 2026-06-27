#Requires -Version 5.1
<#
.SYNOPSIS
    Render a clean adds/removes report from an existing groups-isc-changes-both*.csv change feed.

.DESCRIPTION
    Reads the SailPoint-ready change feed (Export-ChangeFeedCsv columns:
    Change,Domain,GroupName,SamAccountName,DisplayName,Email; Change in {Added,Removed})
    and writes a self-contained, light, paste-friendly HTML report with two sections:

      * ADDED   - a per-USER list (one row per user with the groups they were added to),
      * REMOVED - a removal TABLE (one row per group/user removal),

    plus KPI summary cards. Visual style mirrors the SailPoint-GovernanceToolkit delta reports
    (green ADDED / red REMOVED badges, dark table headers). Purely a reader/renderer of an
    existing feed - it does NOT touch AD, the cache, or the state ledger.

    Exit code: 0 = report generated, 1 = error (feed missing / unreadable).

.PARAMETER CsvPath
    Path to the feed CSV. Accepts a literal file, a wildcard (e.g. .\Output\groups-isc-changes-both*.csv),
    or a directory (the newest groups-isc-changes-both*.csv inside it is used). When omitted, the newest
    groups-isc-changes-both*.csv found under Output\, then State\, then the tool root is used.
.PARAMETER OutputHtml
    Destination .html path. Default: Output\isc-change-diff-<yyyyMMdd-HHmmss>.html.
.PARAMETER ExportCsv
    Optional: also re-write the normalized feed rows (Change,Domain,GroupName,SamAccountName,
    DisplayName,Email) to this CSV path.
.PARAMETER Title
    Optional report title override (default 'ISC Membership Changes').
.PARAMETER AllPrivileged
    Treat every group as privileged for PRIV badge highlighting (else config / built-in detection).
.PARAMETER PrivilegedPattern
    Extra wildcard pattern(s) marking a group name privileged (adds PRIV badges).
.PARAMETER ReplacePrivilegedBuiltins
    Replace (don't augment) the built-in privileged-name detection with the supplied patterns.
.PARAMETER Quiet
    Print only the summary line, not the per-section console breakdown.

.EXAMPLE
    .\Invoke-IscChangeDiff.ps1 -CsvPath .\Output\groups-isc-changes-both-20260610.csv -OutputHtml .\Output\changes.html
.EXAMPLE
    .\Invoke-IscChangeDiff.ps1 -CsvPath .\Output\ -AllPrivileged
#>
[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$OutputHtml,
    [string]$ExportCsv,
    [string]$Title = 'ISC Membership Changes',
    [switch]$AllPrivileged,
    [string[]]$PrivilegedPattern,
    [switch]$ReplacePrivilegedBuiltins,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

. (Join-Path $scriptRoot 'Modules\IscChangeDiff.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC00-Framework.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC08-PrivilegedRisk.ps1')

function Write-Rag {
    param([string]$Level, [string]$Text)
    $map = @{ OK = 'Green'; RISK = 'Red'; WARN = 'Yellow'; INFO = 'Gray' }
    $tag = switch ($Level) { 'OK' { '[ OK ]' } 'RISK' { '[RISK]' } 'WARN' { '[WARN]' } default { '[INFO]' } }
    Write-Host ("{0} {1}" -f $tag, $Text) -ForegroundColor $map[$Level]
}

function Resolve-LocalPath {
    param([string]$P, [string]$Default)
    if (-not $P) { return $Default }
    if ([System.IO.Path]::IsPathRooted($P)) { return $P }
    return (Join-Path $scriptRoot $P)
}

# ---- Resolve the feed CSV (literal | wildcard | directory | auto-discover newest) ----
function Resolve-FeedCsv {
    param([string]$Spec)
    $pattern = 'groups-isc-changes-both*.csv'
    $candidates = @()

    if ($Spec) {
        $full = Resolve-LocalPath $Spec $null
        if (Test-Path -LiteralPath $full -PathType Leaf) { return $full }
        if (Test-Path -LiteralPath $full -PathType Container) {
            $candidates = @(Get-ChildItem -LiteralPath $full -Filter $pattern -File -ErrorAction SilentlyContinue)
        } elseif ($Spec -match '[\*\?]') {
            $candidates = @(Get-ChildItem -Path $full -File -ErrorAction SilentlyContinue)
        } else {
            return $full   # literal path that doesn't exist yet -> let caller report the miss
        }
    } else {
        foreach ($d in @('Output', 'State', '.')) {
            $dir = Join-Path $scriptRoot $d
            if (Test-Path -LiteralPath $dir) {
                $candidates += @(Get-ChildItem -LiteralPath $dir -Filter $pattern -File -ErrorAction SilentlyContinue)
            }
        }
    }
    if ($candidates.Count -eq 0) { return $null }
    return ($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

Write-Host ''
Write-Host '===============================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator - ISC Change Diff (adds/removes)' -ForegroundColor Cyan
Write-Host '===============================================' -ForegroundColor Cyan

$feed = Resolve-FeedCsv -Spec $CsvPath
if (-not $feed -or -not (Test-Path -LiteralPath $feed -PathType Leaf)) {
    Write-Rag 'RISK' ("No change feed found{0}. Expected a groups-isc-changes-both*.csv (Change,Domain,GroupName,SamAccountName,DisplayName,Email)." -f $(if ($CsvPath) { " at: $CsvPath" } else { ' under Output\, State\, or the tool root' }))
    exit 1
}
Write-Host ("Feed: {0}" -f $feed) -ForegroundColor Gray

# ---- Read + shape ----
try {
    $rows = Import-IscChangeFeed -Path $feed
} catch {
    Write-Rag 'RISK' "Could not read the feed: $_"
    exit 1
}

# ---- Privileged classification (params override config), same seam as the other reports ----
$cfgPriv = $null
$cfgFileP = Join-Path $scriptRoot 'Config\group-enum-config.json'
if (Test-Path $cfgFileP) { try { $cfgPriv = Get-Content $cfgFileP -Raw | ConvertFrom-Json } catch { $cfgPriv = $null } }
$allPriv  = if ($PSBoundParameters.ContainsKey('AllPrivileged')) { [bool]$AllPrivileged } else { [bool]($cfgPriv -and $cfgPriv.AllGroupsPrivileged -eq $true) }
$privPats = if ($PrivilegedPattern) { $PrivilegedPattern } elseif ($cfgPriv -and $cfgPriv.PrivilegedPatterns) { @($cfgPriv.PrivilegedPatterns) } else { @() }
$replPriv = $ReplacePrivilegedBuiltins.IsPresent -or ($cfgPriv -and $cfgPriv.ReplacePrivilegedBuiltins -eq $true)
$pred = New-RCPrivilegedPredicate -ExtraPatterns $privPats -All:$allPriv -ReplaceBuiltins:$replPriv

$diff = Get-IscChangeDiff -Rows $rows -PrivilegedNamePredicate $pred
$sum  = $diff.Summary

Write-Host ''
Write-Host ("Added events    : {0}  ({1} user(s))" -f $sum.AddEvents, $sum.UsersAdded) -ForegroundColor $(if ($sum.AddEvents -gt 0) { 'Green' } else { 'Gray' })
Write-Host ("Removed events  : {0}  ({1} user(s))" -f $sum.RemoveEvents, $sum.UsersRemoved) -ForegroundColor $(if ($sum.RemoveEvents -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ("Groups affected : {0}" -f $sum.GroupsAffected) -ForegroundColor Gray
Write-Host ("Net change      : {0}" -f $(if ($sum.NetChange -gt 0) { "+$($sum.NetChange)" } else { $sum.NetChange })) -ForegroundColor Gray
if (($sum.PrivilegedAddUsers + $sum.PrivilegedRemoveEvents) -gt 0) {
    Write-Host ("Privileged      : {0} add user(s), {1} removal(s)" -f $sum.PrivilegedAddUsers, $sum.PrivilegedRemoveEvents) -ForegroundColor Red
}
Write-Host ''

if (-not $Quiet) {
    foreach ($u in @($diff.Adds)) {
        $who = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
        $pv = if ($u.AnyPrivileged) { ' [PRIV]' } else { '' }
        Write-Rag 'OK' ("ADD  {0,-22} -> {1}{2}" -f $who, (@($u.Groups | ForEach-Object { $_.Name }) -join ', '), $pv)
    }
    foreach ($r in @($diff.Removes)) {
        $who = if ($r.DisplayName) { $r.DisplayName } else { $r.SamAccountName }
        $pv = if ($r.Privileged) { ' [PRIV]' } else { '' }
        Write-Rag 'WARN' ("REM  {0,-26} {1}{2}" -f $r.GroupName, $who, $pv)
    }
    if (@($diff.Adds).Count -gt 0 -or @($diff.Removes).Count -gt 0) { Write-Host '' }
}

# ---- Optional CSV re-export of the normalized rows ----
if ($ExportCsv) {
    $csvOut = Resolve-LocalPath $ExportCsv $null
    try {
        @($rows) | Select-Object @{ N = 'Change'; E = { $_.Change } }, Domain, GroupName, SamAccountName, DisplayName, Email |
            Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8
        Write-Host ("  Exported CSV: {0} ({1} row(s))" -f $csvOut, @($rows).Count) -ForegroundColor Gray
    } catch { Write-Host "  [warn] -ExportCsv failed: $_" -ForegroundColor Yellow }
}

# ---- HTML report ----
$htmlOut = if ($OutputHtml) { Resolve-LocalPath $OutputHtml $null }
           else { Join-Path $scriptRoot ('Output\isc-change-diff-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
try {
    $null = New-IscChangeDiffHtml -Diff $diff -OutputPath $htmlOut -Title $Title -SourceLabel (Split-Path -Leaf $feed)
    Write-Host ("  HTML report: {0}" -f $htmlOut) -ForegroundColor Gray
} catch {
    Write-Rag 'RISK' "Could not write the HTML report: $_"
    exit 1
}

Write-Rag 'OK' ('ISC change diff generated ({0} added, {1} removed).' -f $sum.AddEvents, $sum.RemoveEvents)
Write-Host ''
exit 0
