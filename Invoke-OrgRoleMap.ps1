#Requires -Version 5.1
<#
.SYNOPSIS
    Org Role Map - manager -> group -> user COUNT map over an org tree, showing where privileged
    (or tracked) group roles concentrate in the business. Three modes: Full, Delta, Adhoc.

.DESCRIPTION
    Builds an org tree from AD's manager attribute and overlays tracked-group membership COUNTS
    (no user names). Renders a self-contained HTML (inline SVG spatial map + accessible/printable
    table; shared accessible light/dark theme). Privileged classification reuses the RC08 predicate.

      FULL   : build/refresh the org-tree cache (State\org-tree.json) and render from a full
               snapshot cache (-CachePath, produced by Invoke-GroupEnumerator -IncludeAttributes
               manager). Tree is built from the snapshot's manager edges (single-hop, DC-free);
               -BuildOrgTree requests the deep upward chain walk (needs a reachable DC).
      DELTA  : reuse the existing org-tree cache (no DC) + a baseline snapshot for node counts, and
               overlay changelog Added/Removed over a window (SQLite/JSON, auto-detected). Loud
               staleness banner when the cached tree is older than -MaxStaleDays.
      ADHOC  : render from a specific snapshot cache only; NO state writes (auditor "what did this
               snapshot look like" mode). Uses an existing org-tree cache if present, else single-hop.

    Exit code (for gating): 0 = ok/informational, 1 = error, 2 = a -FailOn threshold tripped.

.PARAMETER Mode        Full | Delta | Adhoc (default Adhoc).
.PARAMETER CachePath   Snapshot cache JSON (Full/Adhoc data source; Delta baseline counts).
.PARAMETER OrgTreePath Org-tree cache path (default State\org-tree.json).
.PARAMETER DbPath      SQLite DB for Delta (default config / State\group-enumerator.db).
.PARAMETER StatePath   State dir holding changelog.jsonl for the JSON backend (Delta).
.PARAMETER Backend     Auto (default) | Sqlite | Json (Delta).
.PARAMETER Days        Delta window in days (default 30). Used unless -Since/-Period given.
.PARAMETER Since        Explicit Delta window start (overrides -Days/-Period).
.PARAMETER Period       Day | Week | Month | Quarter (overrides -Days).
.PARAMETER Groups       Track only these group names (wildcards). Default: all (or privileged).
.PARAMETER PrivilegedOnly  Track only privileged groups (RC08 predicate).
.PARAMETER DepthCap     Max manager-chain depth for the deep walk (default 20).
.PARAMETER BuildOrgTree FULL only: deep upward manager-chain walk via LDAP (needs a DC).
.PARAMETER MaxStaleDays Org-tree staleness threshold for the banner / StaleCache gate (default 30).
.PARAMETER FailOn       Comma list raising exit 2: StaleCache, UnmanagedBucket, PrivConcentration.
.PARAMETER UnmanagedFailPct       UnmanagedBucket gate: unmanaged priv refs >= this % of total (default 25).
.PARAMETER PrivConcentrationPct   PrivConcentration gate: one top branch holds >= this % (default 60).
.PARAMETER ExportCsv    Also write the placement rows (org path, group, count) to this CSV.
.PARAMETER OutputHtml   Write the HTML report to this path.
.PARAMETER Quiet        Print only the summary + verdict.

.EXAMPLE
    .\Invoke-OrgRoleMap.ps1 -Mode Adhoc -CachePath .\Cache\groups-20260605-090000.json -OutputHtml .\Output\orgmap.html
.EXAMPLE
    .\Invoke-OrgRoleMap.ps1 -Mode Delta -Days 30 -PrivilegedOnly -OutputHtml .\Output\orgmap-delta.html -FailOn StaleCache,UnmanagedBucket
#>
[CmdletBinding()]
param(
    [ValidateSet('Full', 'Delta', 'Adhoc')][string]$Mode = 'Adhoc',
    [string]$CachePath,
    [string]$OrgTreePath,
    [string]$DbPath,
    [string]$StatePath,
    [ValidateSet('Auto', 'Sqlite', 'Json')][string]$Backend = 'Auto',
    [ValidateRange(1, 36500)][int]$Days = 30,
    [Nullable[datetime]]$Since = $null,
    [ValidateSet('Day', 'Week', 'Month', 'Quarter')][string]$Period,
    [string[]]$Groups,
    [switch]$PrivilegedOnly,
    [switch]$AllPrivileged,
    [string[]]$PrivilegedPattern,
    [switch]$ReplacePrivilegedBuiltins,
    [ValidateRange(1, 100)][int]$DepthCap = 20,
    [ValidateRange(0, 100)][int]$DefaultOpenDepth = 2,
    [switch]$BuildOrgTree,
    [string]$Server,
    [switch]$AllowInsecure,
    [ValidateRange(0, 36500)][int]$MaxStaleDays = 30,
    [ValidateSet('StaleCache', 'UnmanagedBucket', 'PrivConcentration')][string[]]$FailOn = @(),
    [ValidateRange(0, 100)][int]$UnmanagedFailPct = 25,
    [ValidateRange(0, 100)][int]$PrivConcentrationPct = 60,
    [string]$ExportCsv,
    [string]$OutputHtml,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

. (Join-Path $scriptRoot 'Modules\GroupEnumLogger.ps1')
. (Join-Path $scriptRoot 'Modules\StateDatabase.ps1')
. (Join-Path $scriptRoot 'Modules\MembershipState.ps1')
. (Join-Path $scriptRoot 'Modules\GroupReportGenerator.ps1')          # Import-GroupDataJson
. (Join-Path $scriptRoot 'Modules\ADLdap.ps1')                        # New-AdLdapConnection (deep walk)
. (Join-Path $scriptRoot 'Modules\OrgRoleMap.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC00-Framework.ps1')
. (Join-Path $scriptRoot 'Modules\ReportComponents\RC08-PrivilegedRisk.ps1')
. (Join-Path $scriptRoot 'Modules\BaselineReports\B00-report-theme.ps1')

function Write-Rag {
    param([string]$Level, [string]$Text)
    $map = @{ OK = 'Green'; RISK = 'Red'; WARN = 'Yellow'; INFO = 'Gray' }
    $tag = switch ($Level) { 'OK' { '[ OK ]' } 'RISK' { '[RISK]' } 'WARN' { '[WARN]' } default { '[INFO]' } }
    Write-Host ("{0} {1}" -f $tag, $Text) -ForegroundColor $map[$Level]
}
function Resolve-LocalPath { param([string]$P, [string]$Default)
    if (-not $P) { return $Default }
    if ([System.IO.Path]::IsPathRooted($P)) { return $P }
    return (Join-Path $scriptRoot $P)
}

# Privileged classification: params override config (Config\group-enum-config.json:
# AllGroupsPrivileged, PrivilegedPatterns, ReplacePrivilegedBuiltins). Built-in detection by default.
$cfgPriv = $null
$cfgFileP = Join-Path $scriptRoot 'Config\group-enum-config.json'
if (Test-Path $cfgFileP) { try { $cfgPriv = Get-Content $cfgFileP -Raw | ConvertFrom-Json } catch { $cfgPriv = $null } }
$allPriv  = if ($PSBoundParameters.ContainsKey('AllPrivileged')) { [bool]$AllPrivileged } else { [bool]($cfgPriv -and $cfgPriv.AllGroupsPrivileged -eq $true) }
$privPats = if ($PrivilegedPattern) { $PrivilegedPattern } elseif ($cfgPriv -and $cfgPriv.PrivilegedPatterns) { @($cfgPriv.PrivilegedPatterns) } else { @() }
$replPriv = $ReplacePrivilegedBuiltins.IsPresent -or ($cfgPriv -and $cfgPriv.ReplacePrivilegedBuiltins -eq $true)
$pred = New-RCPrivilegedPredicate -ExtraPatterns $privPats -All:$allPriv -ReplaceBuiltins:$replPriv
if ($allPriv) { Write-Host '  (privileged scope: ALL tracked groups)' -ForegroundColor DarkGray }
elseif ($privPats.Count -gt 0) { Write-Host ("  (privileged scope: built-ins{0} + custom [{1}])" -f $(if ($replPriv) { ' OFF' } else { '' }), ($privPats -join ', ')) -ForegroundColor DarkGray }
$orgTreeFile = Resolve-LocalPath $OrgTreePath (Join-Path $scriptRoot (Join-Path 'State' 'org-tree.json'))

Write-Host ''
Write-Host '===============================================' -ForegroundColor Cyan
Write-Host ("Group Enumerator - Org Role Map  [{0}]" -f $Mode) -ForegroundColor Cyan
Write-Host '===============================================' -ForegroundColor Cyan

# ---- Load the snapshot cache (Full/Adhoc data; Delta baseline) ----
$groupResults = @()
if ($Mode -in @('Full', 'Adhoc')) {
    if (-not $CachePath) { Write-Rag 'RISK' "-CachePath is required for $Mode (a snapshot enumerated with -IncludeAttributes manager)."; exit 1 }
    if (-not (Test-Path -LiteralPath $CachePath)) { Write-Rag 'RISK' "Cache not found: $CachePath"; exit 1 }
    try { $groupResults = @((Import-GroupDataJson -JsonPath $CachePath).Groups) }
    catch { Write-Rag 'RISK' "Could not read cache: $_"; exit 1 }
    Write-Host ("Snapshot: {0} ({1} group(s))" -f $CachePath, $groupResults.Count) -ForegroundColor Gray
} elseif ($Mode -eq 'Delta' -and $CachePath -and (Test-Path -LiteralPath $CachePath)) {
    try { $groupResults = @((Import-GroupDataJson -JsonPath $CachePath).Groups) } catch { $groupResults = @() }
}

# ---- Member refs (flatten + classify) ----
$refs = ConvertTo-OrgMemberRefs -GroupResults $groupResults -PrivilegedNamePredicate $pred -TrackedGroups $Groups -PrivilegedOnly:$PrivilegedOnly

# ---- Org tree ----
$orgTreeCache = $null
$builtUtc = ''
$staleWarn = ''
$staleTripped = $false

if ($Mode -eq 'Full') {
    # When asked to deep-walk without an explicit -Server, derive the DC target from the snapshot's
    # domain (DC-locator / serverless bind), mirroring how enumeration resolves it from the CSV. Lets
    # the GUI request a deep walk without needing a separate LDAP-server field.
    if ($BuildOrgTree -and -not $Server) {
        $domGuess = @($refs | ForEach-Object { $_.Domain } | Where-Object { $_ } | Select-Object -First 1)
        if (-not $domGuess) { foreach ($g in $groupResults) { $dd = Get-OrgProp (Get-OrgProp $g 'Data') 'Domain'; if ($dd) { $domGuess = [string]$dd; break } } }
        if ($domGuess) { $Server = [string]$domGuess; Write-Host "  (deep-walk DC derived from snapshot domain: $Server)" -ForegroundColor DarkGray }
    }
    if ($BuildOrgTree -and $Server) {
        # Live deep walk: resolve each member's manager chain UP to the top via LDAP. Memoised
        # per DN (each user + each manager looked up once), so it scales with DISTINCT identities,
        # not total member-refs. Single-domain lab/forest: one connection serves every base lookup.
        try {
            Write-Host ("Deep manager-chain walk against {0} (AllowInsecure={1}) ..." -f $Server, [bool]$AllowInsecure) -ForegroundColor Gray
            $conn = New-AdLdapConnection -Server $Server -AllowInsecure:$AllowInsecure
            Write-Host ("  Connected: tier {0}, port {1}" -f $conn.Tier, $conn.Port) -ForegroundColor DarkGray
            # Reference the connection via a script-scoped var (NOT GetNewClosure, which would try to
            # snapshot the [ValidateSet] param vars like $Period and throw).
            $script:OrgLiveConn = $conn
            $lookup = {
                param($Dn)
                try { $res = Invoke-AdLdapSearch -Context $script:OrgLiveConn -BaseDN $Dn -Scope Base -Filter '(objectClass=*)' -Attributes @('manager', 'sAMAccountName', 'displayName', 'userAccountControl') }
                catch { return $null }
                if (-not $res -or @($res).Count -eq 0) { return $null }
                $e = @($res)[0]
                $uac = 0; [void][int]::TryParse([string]$e['userAccountControl'], [ref]$uac)
                return @{ Dn = [string]$e['DistinguishedName']; Sam = [string]$e['sAMAccountName']; Display = [string]$e['displayName']; Domain = (Get-OrgDomainFromDn $Dn); Enabled = (-not ($uac -band 2)); ManagerDn = [string]$e['manager']; Resolved = $true }
            }
            $memberDns = @($refs | ForEach-Object { $_.Dn } | Where-Object { $_ } | Sort-Object -Unique)
            Write-Host ("  Walking chains for {0} distinct member DN(s) ..." -f $memberDns.Count) -ForegroundColor DarkGray
            $orgTreeCache = Build-OrgTreeCache -MemberDns $memberDns -LookupFn $lookup -DepthCap $DepthCap -BuiltByMode 'Full-DeepWalk'
            try { $conn.Connection.Dispose() } catch {}
            Write-Host ("  Deep walk complete: {0} org node(s); issues: {1}" -f $orgTreeCache.Nodes.Count, (($orgTreeCache.Metadata.Issues -join ', ') -replace '^$', 'none')) -ForegroundColor Gray
        } catch {
            Write-Rag 'WARN' "Deep walk failed ($_); falling back to single-hop tree from the snapshot."
            $orgTreeCache = ConvertTo-OrgTreeCacheFromRecords -GroupResults $groupResults
        }
    } else {
        if ($BuildOrgTree) { Write-Rag 'INFO' '-BuildOrgTree needs -Server <dc> [-AllowInsecure] for the live deep walk; building a single-hop tree from the snapshot manager edges instead.' }
        $orgTreeCache = ConvertTo-OrgTreeCacheFromRecords -GroupResults $groupResults
    }
    try { $null = Save-OrgTreeCache -Cache $orgTreeCache -Path $orgTreeFile; Write-Host ("Org-tree cache written: {0} ({1} node(s))" -f $orgTreeFile, $orgTreeCache.Nodes.Count) -ForegroundColor Gray }
    catch { Write-Host "  [warn] could not write org-tree cache: $_" -ForegroundColor Yellow }
    $builtUtc = $orgTreeCache.Metadata.BuiltUtc
} else {
    # Delta / Adhoc: prefer the persisted org-tree cache; fall back to single-hop from the snapshot.
    if (Test-Path -LiteralPath $orgTreeFile) {
        $orgTreeCache = Import-OrgTreeCache -Path $orgTreeFile
        $st = Get-OrgTreeStaleness -OrgTreeCache $orgTreeCache -MaxStaleDays $MaxStaleDays
        $builtUtc = [string](& { $m = $orgTreeCache.Metadata; if ($m) { $m.BuiltUtc } })
        if ($st.Stale) { $staleWarn = $st.Warning; $staleTripped = $true; Write-Rag 'WARN' $staleWarn }
        Write-Host ("Org-tree cache: {0} (age {1}d)" -f $orgTreeFile, $st.AgeDays) -ForegroundColor Gray
    } elseif (@($groupResults).Count -gt 0) {
        $orgTreeCache = ConvertTo-OrgTreeCacheFromRecords -GroupResults $groupResults
        $builtUtc = $orgTreeCache.Metadata.BuiltUtc
        Write-Rag 'INFO' 'No org-tree cache found; built a single-hop tree from the snapshot (limited depth). Run -Mode Full to persist a fuller tree.'
    } else {
        Write-Rag 'RISK' "No org-tree cache at $orgTreeFile and no snapshot to build from. Run -Mode Full first."; exit 1
    }
}

$tree = Build-OrgTree -OrgTreeCache $orgTreeCache
$agg  = Get-OrgRoleAggregate -OrgTree $tree -MemberRefs $refs

# ---- Delta overlay ----
$windowLabel = ''
if ($Mode -eq 'Delta') {
    $rw = if ($Since) { Resolve-ChangeWindow -ChangeSince $Since }
          elseif ($PSBoundParameters.ContainsKey('Period') -and $Period) { Resolve-ChangeWindow -ChangePeriod $Period }
          else { Resolve-ChangeWindow -ChangeDays $Days }
    $windowLabel = $rw.Label
    $DbPath   = Resolve-LocalPath $DbPath (Join-Path $scriptRoot (Join-Path 'State' 'group-enumerator.db'))
    $stateDir = Resolve-LocalPath $StatePath (Join-Path $scriptRoot 'State')
    $jsonLog  = Join-Path $stateDir 'changelog.jsonl'
    $useSqlite = switch ($Backend) { 'Sqlite' { $true } 'Json' { $false } default { (Test-Path -LiteralPath $DbPath) -and (Test-PythonAvailable) } }
    $events = @()
    try {
        if ($useSqlite) {
            if (-not (Test-Path -LiteralPath $DbPath)) { Write-Rag 'RISK' "No SQLite DB at: $DbPath"; exit 1 }
            $qa = @(); if ($rw.SinceDate) { $qa += @('--since', $rw.SinceDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')) }
            $events = Invoke-StateDb -Command 'query-changes' -DbPath $DbPath -Arguments $qa
            Write-Host "Change source: SQLite $DbPath" -ForegroundColor Gray
        } else {
            if (-not (Test-Path -LiteralPath $jsonLog)) { Write-Rag 'RISK' "No changelog at: $jsonLog"; exit 1 }
            $rcArgs = @{ Path = $jsonLog }; if ($rw.SinceDate) { $rcArgs['Since'] = $rw.SinceDate.ToUniversalTime() }
            $events = Read-ChangeLog @rcArgs
            Write-Host "Change source: JSON $jsonLog" -ForegroundColor Gray
        }
    } catch { Write-Rag 'RISK' "Could not read the change ledger: $_"; exit 1 }
    $events = @($events)
    $dres = Add-OrgDeltaToTree -Aggregate $agg -ChangeEvents $events -PrivilegedNamePredicate $pred
    Write-Host ("Window: {0}  (events {1}; matched {2}, unmatched {3})" -f $windowLabel, $events.Count, $dres.Matched, $dres.Unmatched) -ForegroundColor Gray
}

# ---- Summary ----
$S = $agg.Summary
Write-Host ''
Write-Host ("Privileged refs      : {0}" -f $S.TotalPrivRefs) -ForegroundColor $(if ($S.TotalPrivRefs -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ("Tracked refs         : {0}" -f $S.TotalMemberRefs) -ForegroundColor Gray
Write-Host ("Org nodes            : {0}" -f $S.NodeCount) -ForegroundColor Gray
Write-Host ("Unmanaged priv refs  : {0}" -f $S.UnmanagedPrivRefs) -ForegroundColor $(if ($S.UnmanagedPrivRefs -gt 0) { 'Red' } else { 'Green' })
if (-not $Quiet -and @($S.TopConcentratedNodes).Count -gt 0) {
    Write-Host ''
    Write-Host 'Top privileged concentration (subtree):' -ForegroundColor Gray
    foreach ($t in $S.TopConcentratedNodes) { Write-Host ("  {0,-28} priv={1} tracked={2}" -f $t.Display, $t.SubtreePrivRefs, $t.SubtreeGroupRefs) -ForegroundColor Gray }
}
Write-Host ''

# ---- Outputs ----
if ($ExportCsv) {
    try {
        $rows = New-Object System.Collections.Generic.List[object]
        $parentOf = @{}; foreach ($k in $agg.Nodes.Keys) { foreach ($c in $agg.Nodes[$k].ChildDns) { if (-not $parentOf.ContainsKey($c)) { $parentOf[$c] = $k } } }
        foreach ($k in $agg.Nodes.Keys) {
            $n = $agg.Nodes[$k]; if ($n.SubtreeGroupRefs -le 0) { continue }
            $names = New-Object System.Collections.Generic.List[string]; $cur = $k; $seen = @{}
            while ($cur -and $agg.Nodes.ContainsKey($cur) -and -not $seen.ContainsKey($cur)) { $seen[$cur] = $true; $d = $agg.Nodes[$cur].Display; [void]$names.Add($(if ($d) { $d } else { $agg.Nodes[$cur].Sam })); $cur = if ($parentOf.ContainsKey($cur)) { $parentOf[$cur] } else { $null } }
            $names.Reverse()
            $rows.Add([pscustomobject]@{ OrgPath = ($names -join ' > '); Sam = $n.Sam; SubtreePrivRefs = $n.SubtreePrivRefs; SubtreeGroupRefs = $n.SubtreeGroupRefs; SubtreeDistinctUsers = $n.SubtreeDistinctUsers; Depth = $n.Depth; Unmanaged = $n.IsUnmanaged }) | Out-Null
        }
        $rows | Sort-Object -Property @{Expression='SubtreePrivRefs';Descending=$true} | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host ("  Exported CSV: {0} ({1} node row(s))" -f $ExportCsv, $rows.Count) -ForegroundColor Gray
    } catch { Write-Host "  [warn] -ExportCsv failed: $_" -ForegroundColor Yellow }
}
if ($OutputHtml) {
    try { $null = New-OrgRoleMapHtml -Aggregate $agg -MemberRefs $refs -Mode $Mode -OutputPath $OutputHtml -WindowLabel $windowLabel -OrgTreeBuiltUtc $builtUtc -StaleWarning $staleWarn -DefaultOpenDepth $DefaultOpenDepth; Write-Host ("  HTML report: {0}" -f $OutputHtml) -ForegroundColor Gray }
    catch { Write-Host "  [warn] -OutputHtml failed: $_" -ForegroundColor Yellow }
}

# ---- Gate (-FailOn) ----
$fails = @()
if ($FailOn -contains 'StaleCache' -and $staleTripped) { $fails += "StaleCache ($staleWarn)" }
if ($FailOn -contains 'UnmanagedBucket') {
    $pct = if ($S.TotalPrivRefs -gt 0) { [int][math]::Round(100.0 * $S.UnmanagedPrivRefs / $S.TotalPrivRefs) } else { 0 }
    if ($pct -ge $UnmanagedFailPct) { $fails += "UnmanagedBucket ($pct% of privileged refs unmanaged >= $UnmanagedFailPct%)" }
}
if ($FailOn -contains 'PrivConcentration' -and $S.TotalPrivRefs -gt 0) {
    $topPct = 0
    foreach ($rk in @($agg.Roots)) { if ($agg.Nodes.ContainsKey($rk)) { $p = [int][math]::Round(100.0 * $agg.Nodes[$rk].SubtreePrivRefs / $S.TotalPrivRefs); if ($p -gt $topPct) { $topPct = $p } } }
    if ($topPct -ge $PrivConcentrationPct) { $fails += "PrivConcentration (one branch holds $topPct% of privileged refs >= $PrivConcentrationPct%)" }
}

if ($fails.Count -gt 0) {
    foreach ($f in $fails) { Write-Rag 'RISK' "FAIL: $f" }
    Write-Host ''
    exit 2
}
Write-Rag 'OK' 'Org role map generated.'
Write-Host ''
exit 0
