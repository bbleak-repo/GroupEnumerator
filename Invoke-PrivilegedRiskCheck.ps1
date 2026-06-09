#Requires -Version 5.1
<#
.SYNOPSIS
    Scriptable privileged-access governance gate: flag accounts that still hold privileged-
    group membership but are DISABLED (and, from a stale-enriched cache, never-logged-in /
    stale). Reads a JSON cache -- no DC required -- so it is safe to schedule (nightly /CI).

.DESCRIPTION
    Reuses the exact RC08 classification (Get-RCPrivilegedRiskData) so the gate and the HTML
    report never drift. Privileged groups are identified by name heuristic (admins / operators
    / domain controllers / protected users / etc.; underscores normalised so GG_IT_Admins
    matches). Reads the enumerated roster from a Group Enumerator JSON cache.

    A plain cache carries each member's Enabled flag, so DISABLED-in-privileged is always
    checked. Never-logged-in / stale require a -DetectStale run (live LDAP) and only appear if
    the cache's context already carries StaleResults; for those, run the full tool with
    -DetectStale -ReportComponents privileged-risk.

    Exit code (for gating):
        0  clean -- no at-risk accounts in privileged groups
        2  at-risk accounts found
        1  error (cache not found / unreadable)

.PARAMETER CachePath
    A Group Enumerator JSON cache FILE, or a DIRECTORY (the newest *.json in it is used).
    Defaults to the Cache\ directory under the script root.

.PARAMETER MaxList
    Cap the number of at-risk rows printed (default 50). The summary counts are always exact.

.PARAMETER Quiet
    Suppress the per-account listing; print only the summary + verdict.

.PARAMETER ExportCsv
    Also write the at-risk accounts (Group, Domain, Sam, Status) to this CSV path for
    remediation tracking. Written in both clean (header-only) and at-risk cases.

.EXAMPLE
    .\Invoke-PrivilegedRiskCheck.ps1 -CachePath .\Cache\groups-20260606-101500.json
.EXAMPLE
    # nightly gate over the newest cache; non-zero exit fails the scheduled job
    .\Invoke-PrivilegedRiskCheck.ps1 -CachePath .\Cache
#>
[CmdletBinding()]
param(
    [Parameter()][string]$CachePath,
    [Parameter()][int]$MaxList = 50,
    [Parameter()][switch]$Quiet,
    [Parameter()][string]$ExportCsv,
    [Parameter()][switch]$AllPrivileged,
    [Parameter()][string[]]$PrivilegedPattern,
    [Parameter()][switch]$ReplacePrivilegedBuiltins
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# RC00 framework first (registry + Get-RCProp + New-RCContext), then RC08 (the classifier).
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC00-Framework.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC08-PrivilegedRisk.ps1')

function Write-RagLine {
    param([string]$Level, [string]$Text)
    $map = @{ OK = 'Green'; RISK = 'Red'; INFO = 'Gray' }
    $tag = switch ($Level) { 'OK' { '[ OK ]' } 'RISK' { '[RISK]' } default { '[INFO]' } }
    Write-Host ("{0} {1}" -f $tag, $Text) -ForegroundColor $map[$Level]
}

# ---- Resolve the cache file (param file > newest in dir > default Cache dir) ----
if (-not $CachePath) { $CachePath = Join-Path $scriptRoot 'Cache' }
$cacheFile = $null
if (Test-Path -LiteralPath $CachePath -PathType Container) {
    $cacheFile = (Get-ChildItem -LiteralPath $CachePath -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if ($cacheFile) { $cacheFile = $cacheFile.FullName }
} elseif (Test-Path -LiteralPath $CachePath -PathType Leaf) {
    $cacheFile = $CachePath
}

Write-Host ''
Write-Host '===========================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator - Privileged-Access Gate' -ForegroundColor Cyan
Write-Host '===========================================' -ForegroundColor Cyan

if (-not $cacheFile -or -not (Test-Path -LiteralPath $cacheFile)) {
    Write-RagLine 'RISK' "No JSON cache found at: $CachePath"
    Write-Host 'Run the enumerator first (it writes a cache), or pass -CachePath <file>.' -ForegroundColor Yellow
    exit 1
}
Write-Host "Cache: $cacheFile" -ForegroundColor Gray

# ---- Load the cache + build an RC context ----
try {
    $cache  = [System.IO.File]::ReadAllText($cacheFile) | ConvertFrom-Json
    $groups = @($cache.Groups)
} catch {
    Write-RagLine 'RISK' "Could not read/parse the cache: $_"
    exit 1
}
if ($groups.Count -eq 0) {
    Write-RagLine 'INFO' 'Cache contains no groups.'
    exit 0
}

$ctx  = New-RCContext -GroupResults $groups
# Privileged classification: params override config (AllGroupsPrivileged / PrivilegedPatterns /
# ReplacePrivilegedBuiltins). Built-in admin/operator detection by default.
$cfgPriv = $null
$cfgFileP = Join-Path $scriptRoot 'Config\group-enum-config.json'
if (Test-Path $cfgFileP) { try { $cfgPriv = Get-Content $cfgFileP -Raw | ConvertFrom-Json } catch { $cfgPriv = $null } }
$allPriv  = if ($PSBoundParameters.ContainsKey('AllPrivileged')) { [bool]$AllPrivileged } else { [bool]($cfgPriv -and $cfgPriv.AllGroupsPrivileged -eq $true) }
$privPats = if ($PrivilegedPattern) { $PrivilegedPattern } elseif ($cfgPriv -and $cfgPriv.PrivilegedPatterns) { @($cfgPriv.PrivilegedPatterns) } else { @() }
$replPriv = $ReplacePrivilegedBuiltins.IsPresent -or ($cfgPriv -and $cfgPriv.ReplacePrivilegedBuiltins -eq $true)
$privPred = New-RCPrivilegedPredicate -ExtraPatterns $privPats -All:$allPriv -ReplaceBuiltins:$replPriv
$data = Get-RCPrivilegedRiskData -Context $ctx -PrivilegedNamePredicate $privPred

# ---- Report ----
Write-Host ''
Write-Host ("Privileged groups        : {0}" -f $data.PrivilegedGroups.Count) -ForegroundColor Gray
Write-Host ("Disabled in privileged   : {0}" -f $data.DisabledCount) -ForegroundColor $(if ($data.DisabledCount -gt 0) { 'Red' } else { 'Green' })
if ($data.HasStaleData) {
    Write-Host ("Never-logged-in in priv. : {0}" -f $data.NeverCount) -ForegroundColor $(if ($data.NeverCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host ("Stale in privileged      : {0}" -f $data.StaleCount) -ForegroundColor $(if ($data.StaleCount -gt 0) { 'Yellow' } else { 'Green' })
} else {
    Write-Host '(cache has no stale data; only Disabled-in-privileged is evaluated -- run with -DetectStale for never/stale)' -ForegroundColor DarkGray
}
Write-Host ("At-risk accounts (distinct): {0}" -f $data.DistinctAtRisk) -ForegroundColor $(if ($data.DistinctAtRisk -gt 0) { 'Red' } else { 'Green' })
Write-Host ''

$atRisk = @($data.AtRisk)

# Machine-readable remediation export (written in both clean and at-risk cases so a
# scheduled job always produces a stable artifact; header-only when clean).
if ($ExportCsv) {
    try {
        $rows = @($atRisk | Select-Object Group, Domain, Sam, Status)
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
        } else {
            Set-Content -LiteralPath $ExportCsv -Value '"Group","Domain","Sam","Status"' -Encoding UTF8
        }
        Write-Host ("  Exported at-risk CSV: {0} ({1} row(s))" -f $ExportCsv, $rows.Count) -ForegroundColor Gray
    } catch {
        Write-Host "  [warn] could not write -ExportCsv: $_" -ForegroundColor Yellow
    }
}

if ($atRisk.Count -eq 0) {
    Write-RagLine 'OK' 'No at-risk accounts in privileged groups.'
    Write-Host ''
    exit 0
}

if (-not $Quiet) {
    $sorted = @($atRisk | Sort-Object Group, Sam)
    $shown  = if ($sorted.Count -gt $MaxList) { $sorted[0..($MaxList - 1)] } else { $sorted }
    foreach ($r in $shown) {
        Write-RagLine 'RISK' ("{0,-22} {1,-18} {2}" -f $r.Group, $r.Sam, $r.Status)
    }
    if ($sorted.Count -gt $MaxList) {
        Write-Host ("  ... and {0} more (raise -MaxList to see all)" -f ($sorted.Count - $MaxList)) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-RagLine 'RISK' ("FAIL: {0} at-risk account(s) in privileged groups." -f $data.DistinctAtRisk)
Write-Host ''
exit 2
