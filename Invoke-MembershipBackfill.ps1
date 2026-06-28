#Requires -Version 5.1
<#
.SYNOPSIS
    Retroactively reconstruct a tracked membership history by replaying the
    per-day cache snapshots an operator already keeps under Cache\.

.DESCRIPTION
    Thin CLI wrapper around Modules\MembershipBackfill.ps1. For an operator who
    did NOT run Group Enumerator with -TrackChanges, this replays the existing
    per-run cache snapshots (Cache\*.json, e.g. groups-<timestamp>.json or
    dc-live-test-groups-<timestamp>.json) in chronological order through GE's
    EXISTING change-tracking engine to synthesize, after the fact, the same
    State\group-enumerator-state.json and changelog.jsonl you would have had if
    -TrackChanges had run each day.

    Each replayed run's changelog events are stamped with THAT snapshot's
    historical date (Metadata.BuiltUtc / GeneratedTimestamp / filename token),
    NOT the current wall-clock time, so the reconstructed ledger carries true
    historical timestamps. The oldest snapshot is treated as a silent baseline
    (no change events), matching real first-run semantics.

    This script is a pure pass-through wrapper: it does NOT re-implement
    discovery or diffing and does NOT touch the off-limits change-tracking core.
    All replay logic lives in Invoke-MembershipBackfillCore (the module).

    LIVE-STATE GUARD: By default this refuses to write into a destination that
    already holds a state or changelog file, so it will not clobber a live
    State\ directory. You MUST pass an explicit isolated destination
    (-OutputDir or -StatePath); pointing at a populated dir without -Force exits
    non-zero. The core enforces the file-existence refusal; -Force allows a
    clean idempotent rebuild.

    Exit codes: 0 = backfill completed, 1 = error (no cache, no destination,
    live-dir refusal, or core failure).

.PARAMETER CachePath
    REQUIRED. Folder containing the per-run cache snapshots (or a glob/path).
    Snapshots are replayed in chronological (oldest-to-newest) order, resolved
    from each snapshot's metadata (Metadata.BuiltUtc, falling back to the
    filename timestamp); the oldest is the silent baseline.

.PARAMETER OutputDir
    Isolated destination directory for the reconstructed state + changelog.
    Relative paths resolve against the tool root; absolute paths pass through.

.PARAMETER StatePath
    Optional explicit override for the state JSON file path, passed through to
    the core. When given without -OutputDir, OutputDir is derived from its
    parent folder.

.PARAMETER Force
    Allow (re)writing into a destination that already holds a state/changelog
    file. Without it the run refuses, to protect a live State\ directory.

.PARAMETER Quiet
    Print only the summary line, not the per-path detail.

.PARAMETER EmitChangeFeed
    Optional, OFF by default. Additionally writes one SailPoint-ready change-feed
    CSV per NON-baseline replayed day (groups-isc-changes-both-<yyyyMMdd>.csv,
    stamped with that snapshot's historical date) via the engine's reused
    Export-ChangeFeedCsv, so the existing Invoke-IscChangeDiff.ps1 report can run
    over the reconstructed history.

.PARAMETER ChangeFeedDir
    Optional destination directory for the per-day change-feed CSVs. Defaults to
    -OutputDir when omitted. Only used with -EmitChangeFeed. Relative paths
    resolve against the tool root; absolute paths pass through.

.EXAMPLE
    .\Invoke-MembershipBackfill.ps1 -CachePath .\Cache -OutputDir .\Backfill-State

.EXAMPLE
    .\Invoke-MembershipBackfill.ps1 -CachePath C:\snapshots -StatePath C:\replay\state.json -Force

.NOTES
    No emoji in code (per project conventions). Windows PowerShell 5.1.

    AUTHORED live-acceptance note (DO NOT execute autonomously; for a human to
    run against a real environment):
      1. Copy (do not move) a real run's snapshots into a folder, or point
         -CachePath straight at the existing Cache\ (it is only read).
      2. Point -OutputDir at a brand-new throwaway directory, e.g.
         .\_backfill-acceptance, so nothing live is touched.
      3. Run:
           .\Invoke-MembershipBackfill.ps1 -CachePath .\Cache `
                                           -OutputDir .\_backfill-acceptance
         Confirm the RAG summary lists the expected snapshot count, that the
         oldest date is reported as the silent baseline, and that
         _backfill-acceptance\group-enumerator-state.json and changelog.jsonl
         were written.
      4. Open the changelog.jsonl and confirm event timestamps match the
         historical snapshot dates, NOT today's date.
      5. Do NOT aim -OutputDir / -StatePath at the live State\ directory without
         -Force; by default the run will (correctly) refuse and exit 1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CachePath,

    [string]$OutputDir,

    [string]$StatePath,

    [switch]$Force,

    [switch]$Quiet,

    [switch]$EmitChangeFeed,

    [string]$ChangeFeedDir
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# Dot-source ONLY the backfill module. It already loads the off-limits engine +
# bridge (GroupEnumLogger / MembershipDrift / MembershipState /
# GroupReportGenerator), so do NOT re-dot-source those here (avoid double-load).
. (Join-Path $scriptRoot 'Modules\MembershipBackfill.ps1')

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

Write-Host ''
Write-Host '====================================================' -ForegroundColor Cyan
Write-Host 'Group Enumerator - Membership Backfill / Replay' -ForegroundColor Cyan
Write-Host '====================================================' -ForegroundColor Cyan

# ---- Validate the cache snapshots folder ----
$cache = Resolve-LocalPath $CachePath $null
if (-not $cache -or -not (Test-Path -LiteralPath $cache)) {
    Write-Rag 'RISK' ("No cache snapshots folder found at: {0}" -f $CachePath)
    exit 1
}

# ---- Destination resolution + guard (CLI's own additive guard) ----
$resolvedState   = Resolve-LocalPath $StatePath $null
$resolvedOut     = Resolve-LocalPath $OutputDir $null
$resolvedFeedDir = Resolve-LocalPath $ChangeFeedDir $null

if (-not $resolvedOut -and -not $resolvedState) {
    Write-Rag 'RISK' 'No isolated destination given. Specify -OutputDir (or -StatePath) so a live State\ dir is never overwritten by default.'
    exit 1
}
if (-not $resolvedOut -and $resolvedState) {
    $resolvedOut = Split-Path $resolvedState -Parent
}

Write-Host ("Cache : {0}" -f $cache) -ForegroundColor Gray
Write-Host ("Output: {0}" -f $resolvedOut) -ForegroundColor Gray
if ($resolvedState) { Write-Host ("State : {0}" -f $resolvedState) -ForegroundColor Gray }

# ---- Build optional pass-throughs and call the core ----
$optional = @{}
if ($resolvedState)   { $optional['StatePath']      = $resolvedState }
if ($Force)           { $optional['Force']          = $true }
if ($EmitChangeFeed)  { $optional['EmitChangeFeed'] = $true }
if ($resolvedFeedDir) { $optional['ChangeFeedDir']  = $resolvedFeedDir }

try {
    $result = Invoke-MembershipBackfillCore -CachePath $cache -OutputDir $resolvedOut @optional
} catch {
    Write-Rag 'RISK' "Backfill failed: $_"
    exit 1
}

# ---- RAG summary from the returned hashtable ----
Write-Host ''
Write-Rag 'INFO' ("Snapshots replayed : {0}" -f $result.SnapshotsReplayed)
Write-Rag 'INFO' ("Baseline (silent)  : {0}" -f $result.BaselineDate)

$addLevel = if ($result.TotalAdded -gt 0)   { 'OK' }   else { 'INFO' }
$remLevel = if ($result.TotalRemoved -gt 0) { 'WARN' } else { 'INFO' }
Write-Rag $addLevel ("Total added        : {0}" -f $result.TotalAdded)
Write-Rag $remLevel ("Total removed      : {0}" -f $result.TotalRemoved)

if ($EmitChangeFeed -and $result.ChangeFeedPaths) {
    Write-Rag 'INFO' ("Change feeds       : {0} file(s) -> {1}" -f @($result.ChangeFeedPaths).Count, $result.ChangeFeedDir)
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host ("State file : {0}" -f $result.StatePath) -ForegroundColor Gray
    Write-Host ("Changelog  : {0}" -f $result.ChangeLogPath) -ForegroundColor Gray
}

Write-Host ''
Write-Rag 'OK' ('Backfill complete ({0} snapshot(s); {1} added, {2} removed).' -f $result.SnapshotsReplayed, $result.TotalAdded, $result.TotalRemoved)
Write-Host ''
exit 0
