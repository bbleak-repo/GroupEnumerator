<#
.SYNOPSIS
    Pure helpers for retroactive membership backfill / replay of cache snapshots.

.DESCRIPTION
    ADDITIVE companion module that lets an operator who did NOT run with
    -TrackChanges reconstruct a tracked history from the per-day cache snapshots
    they already keep under Cache/. This file (T-01) provides only the pure,
    side-effect-free discovery + ordering helpers:

      - Resolve-SnapshotDate : returns the historical [datetime] for one cache
                               file, using documented precedence
                               (Metadata.BuiltUtc -> Metadata.GeneratedTimestamp
                               -> filename timestamp -> file LastWriteTime).
      - Get-BackfillSnapshot : discovers Cache/*.json snapshots in a folder/glob
                               and returns them ordered chronologically ascending
                               as @{ Path; Date; DateSource } objects.

    The off-limits diff / change-tracking core (MembershipState.ps1,
    MembershipDrift.ps1, StateDatabase.ps1) is loaded/CALLED only -- never
    modified. These helpers do NOT invoke the diff engine; they read metadata
    cheaply with ConvertFrom-Json so discovery is fast and pure.

.NOTES
    No emoji in code (per project conventions).
    Windows PowerShell 5.1 compatible.
    Loads MembershipDrift.ps1, MembershipState.ps1, GroupReportGenerator.ps1 so
    the module is self-contained for later backfill items; ADDS NO behaviour to
    those files.
#>

# ---- Resolve module dir at load time (dot-source context has valid $PSScriptRoot) ----
$script:BackfillModuleDir = $PSScriptRoot

# ---- Load the engine + bridge dependencies (call-only; never modified) ----
# GroupEnumLogger.ps1 first: MembershipDrift.ps1's Compare-GroupMembership calls
# Write-GroupEnumLog UNGUARDED, so the logger must be in scope (it loads inert --
# Enabled=$false -- so every log call is a silent no-op until Initialize-GroupEnumLog).
# This mirrors Invoke-GroupEnumerator.ps1, which dot-sources the logger first.
foreach ($dep in @('GroupEnumLogger.ps1', 'MembershipDrift.ps1', 'MembershipState.ps1', 'GroupReportGenerator.ps1')) {
    $p = Join-Path $script:BackfillModuleDir $dep
    if (Test-Path $p) { . $p }
}

# ---------------------------------------------------------------------------
# Public: Resolve-SnapshotDate
# ---------------------------------------------------------------------------
function Resolve-SnapshotDate {
    <#
    .SYNOPSIS
        Resolves the historical date of a single cache snapshot file.

    .DESCRIPTION
        Reads the snapshot metadata cheaply (ConvertFrom-Json, no diff engine)
        and resolves a [datetime] using this precedence:
          1. Metadata.BuiltUtc          (ISO-8601 'o' with trailing Z; UTC)
          2. Metadata.GeneratedTimestamp ('yyyy-MM-dd HH:mm:ss', local, exact)
          3. Filename timestamp          (<yyyyMMdd>-<HHmmss> token in the leaf)
          4. File LastWriteTime          (additive safety net)

    .PARAMETER Path
        Full path to the cache snapshot .json file.

    .PARAMETER DateSource
        Optional [ref] that receives the label of the tier that resolved the
        date: 'BuiltUtc', 'GeneratedTimestamp', 'Filename', 'LastWriteTime', or
        'Unknown' if it could not be resolved.

    .OUTPUTS
        [datetime]
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ref]$DateSource
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ($DateSource) { $DateSource.Value = 'Unknown' }

    # Read metadata cheaply (-Raw handles BOM, mirroring Import-GroupDataJson).
    $meta = $null
    try {
        $meta = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json).Metadata
    } catch {
        $meta = $null
    }

    # Tier 1: Metadata.BuiltUtc (ISO-8601 round-trip, UTC -> local).
    if ($meta -and $meta.BuiltUtc) {
        try {
            $dto = [System.DateTimeOffset]::Parse([string]$meta.BuiltUtc, $invariant, [System.Globalization.DateTimeStyles]::RoundtripKind)
            if ($DateSource) { $DateSource.Value = 'BuiltUtc' }
            return $dto.LocalDateTime
        } catch { }
    }

    # Tier 2: Metadata.GeneratedTimestamp ('yyyy-MM-dd HH:mm:ss', exact, no tz shift).
    if ($meta -and $meta.GeneratedTimestamp) {
        try {
            $gen = [datetime]::ParseExact([string]$meta.GeneratedTimestamp, 'yyyy-MM-dd HH:mm:ss', $invariant)
            if ($DateSource) { $DateSource.Value = 'GeneratedTimestamp' }
            return $gen
        } catch { }
    }

    # Tier 3: Filename timestamp <yyyyMMdd>-<HHmmss> (covers groups-/dc-live-test-groups-/test-groups- prefixes).
    try {
        $leaf = [System.IO.Path]::GetFileName($Path)
        $m = [regex]::Match($leaf, '(\d{8})-(\d{6})')
        if ($m.Success) {
            $stamp = "$($m.Groups[1].Value)-$($m.Groups[2].Value)"
            $fromName = [datetime]::ParseExact($stamp, 'yyyyMMdd-HHmmss', $invariant)
            if ($DateSource) { $DateSource.Value = 'Filename' }
            return $fromName
        }
    } catch { }

    # Tier 4: LastWriteTime fallback (additive safety net; never crash on a non-timestamped snapshot).
    $mtime = (Get-Item -LiteralPath $Path).LastWriteTime
    if ($DateSource) { $DateSource.Value = 'LastWriteTime' }
    return $mtime
}

# ---------------------------------------------------------------------------
# Public: Get-BackfillSnapshot
# ---------------------------------------------------------------------------
function Get-BackfillSnapshot {
    <#
    .SYNOPSIS
        Discovers cache snapshots and returns them ordered chronologically.

    .DESCRIPTION
        Given a folder (or glob/path), discovers the *.json snapshots, resolves
        each one's historical date via Resolve-SnapshotDate, and returns them
        ordered ascending by Date (Path as deterministic tie-breaker). Pure /
        side-effect-free: reads metadata only, never invokes the diff engine.

    .PARAMETER CachePath
        A directory containing snapshot .json files, or a glob/path expression.

    .OUTPUTS
        [array] of [pscustomobject]@{ Path; Date; DateSource }, ascending by Date.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CachePath
    )

    # Discover the candidate .json files.
    $files = @()
    if (Test-Path -LiteralPath $CachePath -PathType Container) {
        $files = @(Get-ChildItem -Path (Join-Path $CachePath '*.json') -File -ErrorAction SilentlyContinue)
    } else {
        $files = @(Get-ChildItem -Path $CachePath -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.json' })
    }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $src = 'Unknown'
        $date = Resolve-SnapshotDate -Path $f.FullName -DateSource ([ref]$src)
        $items.Add([pscustomobject]@{
            Path       = $f.FullName
            Date       = $date
            DateSource = $src
        })
    }

    # Ascending chronological order; Path as deterministic tie-breaker.
    $ordered = @($items | Sort-Object Date, Path)

    # Leading comma preserves the array through the PS 5.1 pipeline
    # (mirrors Read-ChangeLog's ,@($events) in MembershipState.ps1).
    return ,$ordered
}

# ---------------------------------------------------------------------------
# Public: Invoke-MembershipBackfillCore
# ---------------------------------------------------------------------------
function Invoke-MembershipBackfillCore {
    <#
    .SYNOPSIS
        Replays ordered cache snapshots through GE's change-tracking engine to
        synthesize a post-hoc state file + historical changelog.

    .DESCRIPTION
        Reuses the off-limits diff / change-tracking core UNMODIFIED, by CALLING
        it only. For each chronological snapshot returned by Get-BackfillSnapshot
        it (1) bridges the cache to group-results via Import-GroupDataJson, just
        like the -FromCache path; (2) diffs against the loaded state with
        Update-MembershipState, stamping each run's events with THAT snapshot's
        historical date (ISO 'o'), not wall-clock time; (3) persists with
        Save-MembershipState and appends with Add-ChangeLogEntries.

        The oldest snapshot is a silent baseline: its iteration finds no state
        file, so Update-MembershipState seeds the groups (first-run semantics)
        and emits zero change events -- nothing carries the baseline date.

        Writes ONLY to the caller-specified output/state path and, by default,
        REFUSES to overwrite a pre-existing state/changelog (live-dir guard);
        pass -Force to rebuild. The rebuild wipes prior state/log so the
        append-only changelog never doubles, making re-runs idempotent and
        byte-identical (every written timestamp derives from snapshot dates).

        GUARDRAIL: MembershipState.ps1 / MembershipDrift.ps1 / StateDatabase.ps1
        are CALLED only, never modified.

    .PARAMETER CachePath
        Folder (or glob/path) of cache snapshots; passed to Get-BackfillSnapshot.

    .PARAMETER OutputDir
        Isolated output directory for the reconstructed state + changelog.

    .PARAMETER StatePath
        Optional explicit override for the state JSON file path. When omitted,
        the state file is <OutputDir>\group-enumerator-state.json and the
        changelog is changelog.jsonl beside it (mirrors the unified naming in
        Invoke-GroupEnumerator.ps1).

    .PARAMETER Force
        Required to (re)write into a target that already holds a state or
        changelog file. Without it the function refuses, to avoid clobbering a
        live State/ directory.

    .PARAMETER EmitChangeFeed
        Optional, OFF by default. When set, writes one SailPoint-ready change-feed
        CSV per NON-baseline replayed day via the engine's Export-ChangeFeedCsv
        (reused unmodified). Each file is named groups-isc-changes-both-<yyyyMMdd>.csv
        stamped with THAT snapshot's historical date, with the locked columns
        Change,Domain,GroupName,SamAccountName,DisplayName,Email so the existing
        Invoke-IscChangeDiff.ps1 report can run over the reconstructed history.
        The oldest (baseline) snapshot emits no feed.

    .PARAMETER ChangeFeedDir
        Optional destination directory for the per-day change-feed CSVs. Defaults
        to OutputDir when omitted. Only used when -EmitChangeFeed is set.

    .OUTPUTS
        Hashtable:
        @{
            SnapshotsReplayed; BaselineDate; TotalAdded; TotalRemoved;
            StatePath; ChangeLogPath; ChangeFeedDir; ChangeFeedPaths
        }
        ChangeFeedDir is $null and ChangeFeedPaths is an empty array unless
        -EmitChangeFeed was supplied.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CachePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir,

        [Parameter(Mandatory = $false)]
        [string]$StatePath,

        [switch]$Force,

        [switch]$EmitChangeFeed,

        [Parameter(Mandatory = $false)]
        [string]$ChangeFeedDir
    )

    # 1. Resolve state + changelog file paths (mirror unified naming).
    if ($StatePath) {
        $stateFile = $StatePath
    } else {
        $stateFile = Join-Path $OutputDir 'group-enumerator-state.json'
    }
    $logFile = Join-Path (Split-Path $stateFile -Parent) 'changelog.jsonl'

    $parentDir = Split-Path $stateFile -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        $null = New-Item -ItemType Directory -Path $parentDir -Force
    }

    # 2. Live-dir guard: never clobber an existing state/changelog without -Force.
    if (-not $Force) {
        if ((Test-Path -LiteralPath $stateFile) -or (Test-Path -LiteralPath $logFile)) {
            throw "refusing to overwrite existing state at '$stateFile'; use -Force or choose a clean -OutputDir"
        }
    }

    # 3. Idempotent rebuild: wipe prior state/log so the append-only changelog
    #    never doubles. Do NOT delete the whole dir (T-03 may stage CSVs there).
    Remove-Item -LiteralPath $stateFile, $logFile -Force -ErrorAction SilentlyContinue

    # 4. Discover + order snapshots chronologically.
    $ordered = Get-BackfillSnapshot -CachePath $CachePath
    if ($ordered.Count -eq 0) {
        throw "no cache snapshots found under '$CachePath'"
    }

    # 5. Oldest snapshot is the silent baseline.
    $baselineDate = $ordered[0].Date.ToString('o')
    $totalAdded   = 0
    $totalRemoved = 0

    # 5b. Resolve the change-feed dir ONLY when emitting (additive, off by default).
    #     Defaults to OutputDir; auto-create if it does not yet exist. We never
    #     pre-wipe feed files here -- filenames are deterministic per snapshot date
    #     and Export-ChangeFeedCsv overwrites via WriteAllText, so re-runs stay
    #     byte-identical without disturbing other staged CSVs in the dir.
    $feedDir   = $null
    $feedPaths = New-Object System.Collections.Generic.List[string]
    if ($EmitChangeFeed) {
        $feedDir = if ($ChangeFeedDir) { $ChangeFeedDir } else { $OutputDir }
        if ($feedDir -and -not (Test-Path -LiteralPath $feedDir)) {
            $null = New-Item -ItemType Directory -Path $feedDir -Force
        }
    }

    # 6. Replay each snapshot in ascending order, stamping the historical date.
    foreach ($snap in $ordered) {
        $iso    = $snap.Date.ToString('o')                 # historical stamp, NOT Get-Date
        $cache  = Import-GroupDataJson -JsonPath $snap.Path # same bridge as -FromCache
        $groups = @($cache.Groups)
        $state  = Import-MembershipState -Path $stateFile   # reload each iter -> recomputes IsFirstRun
        $update = Update-MembershipState -State $state -CurrentGroupResults $groups -Timestamp $iso
        # $null = ... : Save/Add return a path/int that must not leak onto the pipeline.
        $null   = Save-MembershipState -NewState $update.NewState -Path $stateFile
        $null   = Add-ChangeLogEntries -Changes $update.Changes -Path $logFile
        # Optional per-day SailPoint feed: emit only for NON-baseline days, using
        # the engine-authoritative first-run flag (mirrors how the loop trusts the
        # engine). The reused Export-ChangeFeedCsv locks the columns/header.
        if ($EmitChangeFeed -and -not $update.Summary.IsFirstRun) {
            # One snapshot per day is the norm, so the base name keeps the bare
            # yyyyMMdd token. If two snapshots resolve to the SAME calendar day,
            # suffix the later one(s) (-2, -3, ...) so neither per-day feed CSV is
            # silently overwritten and ChangeFeedPaths lists no duplicate. Ordering
            # is deterministic, so re-runs stay byte-identical.
            $dayToken = $snap.Date.ToString('yyyyMMdd')
            $feedName = 'groups-isc-changes-both-{0}.csv' -f $dayToken
            $feedPath = Join-Path $feedDir $feedName
            $dup = 2
            while ($feedPaths.Contains($feedPath)) {
                $feedName = 'groups-isc-changes-both-{0}-{1}.csv' -f $dayToken, $dup
                $feedPath = Join-Path $feedDir $feedName
                $dup++
            }
            $null = Export-ChangeFeedCsv -Changes @($update.Changes) -OutputPath $feedPath -ChangeType 'Both'
            $feedPaths.Add($feedPath)
        }
        $totalAdded   += $update.Summary.TotalAdded
        $totalRemoved += $update.Summary.TotalRemoved
    }

    # 7. Return the run summary.
    return @{
        SnapshotsReplayed = $ordered.Count
        BaselineDate      = $baselineDate
        TotalAdded        = $totalAdded
        TotalRemoved      = $totalRemoved
        StatePath         = $stateFile
        ChangeLogPath     = $logFile
        ChangeFeedDir     = $feedDir
        ChangeFeedPaths   = @($feedPaths)
    }
}
