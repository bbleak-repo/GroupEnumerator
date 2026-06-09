<#
.SYNOPSIS
    Persistent membership state ledger for daily change tracking.

.DESCRIPTION
    Maintains a single local JSON "database" of current group membership plus an
    append-only change log, so consecutive (e.g. daily) runs can report exactly
    which users were ADDED to or REMOVED from each tracked group over time.

    This is an ADDITIVE companion to MembershipDrift.ps1 (snapshot-vs-snapshot
    diffing). It does not modify or replace any existing drift behaviour. It reuses
    Compare-GroupMembership from MembershipDrift.ps1 for the set diff.

    Two artefacts are kept:
      - state.json      : the current known membership of every tracked group,
                          keyed by "DOMAIN|GroupName" (so one or many domains in a
                          single run are handled identically).
      - changelog.jsonl : one JSON object per line, one line per add/remove event,
                          appended (never rewritten) so full history is retained.

    First run (no prior state) SEEDS the baseline and emits NO change events -- the
    existing population is recorded, not reported as a flood of "adds". A group that
    first appears on a later run is likewise seeded silently (no false adds). Only
    groups already present in the prior state produce add/remove deltas.

.NOTES
    No emoji in code.
    Reuses Compare-GroupMembership (MembershipDrift.ps1) -- dot-source it first.
    Logging via Write-GroupEnumLog (GroupEnumLogger.ps1) is optional; guarded.
#>

# ---------------------------------------------------------------------------
# Private: optional structured logging (no-op if logger not loaded)
# ---------------------------------------------------------------------------
function Write-StateLog {
    param(
        [string]$Level = 'INFO',
        [string]$Operation = 'ChangeTracking',
        [string]$Message = '',
        [hashtable]$Context = @{}
    )
    if (Get-Command Write-GroupEnumLog -ErrorAction SilentlyContinue) {
        Write-GroupEnumLog -Level $Level -Operation $Operation -Message $Message -Context $Context
    }
}

# ---------------------------------------------------------------------------
# Private: always return an array (PS 5.1 ConvertFrom-Json unwraps 1-element arrays)
# ---------------------------------------------------------------------------
function ConvertTo-StateArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [array]) { return $Value }
    return @($Value)
}

# ---------------------------------------------------------------------------
# Public: Import-MembershipState
# ---------------------------------------------------------------------------
function Import-MembershipState {
    <#
    .SYNOPSIS
        Loads the membership state file, or returns an empty first-run state.

    .PARAMETER Path
        Path to state.json.

    .OUTPUTS
        Hashtable:
        @{
            Metadata    = @{ Version; FirstRun; LastRun; RunCount }
            GroupsByKey = @{ "DOMAIN|GroupName" = @{ Domain; GroupName; LastSeen; Members = @() } }
            IsFirstRun  = [bool]
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $empty = @{
        Metadata    = @{ Version = '2.0'; FirstRun = $null; LastRun = $null; RunCount = 0 }
        GroupsByKey = @{}
        CsvSources  = @{}
        IsFirstRun  = $true
    }

    if (-not (Test-Path $Path)) {
        Write-StateLog -Level 'INFO' -Message "No prior state at $Path -- first run (baseline seed)" -Context @{ path = $Path }
        return $empty
    }

    try {
        $raw  = [System.IO.File]::ReadAllText($Path)
        $data = $raw | ConvertFrom-Json
    } catch {
        Write-StateLog -Level 'WARN' -Message "Failed to read state ($Path); treating as first run: $_" -Context @{ path = $Path }
        return $empty
    }

    $groupsByKey = @{}
    foreach ($g in @(ConvertTo-StateArray $data.Groups)) {
        if (-not $g.Domain -or -not $g.GroupName) { continue }
        $key = "$($g.Domain)|$($g.GroupName)"
        $groupsByKey[$key] = @{
            Domain    = $g.Domain
            GroupName = $g.GroupName
            LastSeen  = $g.LastSeen
            Members   = @(ConvertTo-StateArray $g.Members)
        }
    }

    $csvSources = @{}
    if ($data.CsvSources) {
        foreach ($prop in $data.CsvSources.PSObject.Properties) {
            $csvSources[$prop.Name] = @{
                LastRun = $prop.Value.LastRun
                Groups  = @(ConvertTo-StateArray $prop.Value.Groups)
            }
        }
    }

    $meta = @{
        Version  = if ($data.Metadata.Version) { $data.Metadata.Version } else {
            if ($data.CsvSources) { '2.0' } else { '1.0' }
        }
        FirstRun = if ($data.Metadata.FirstRun) { $data.Metadata.FirstRun } else { $null }
        LastRun  = if ($data.Metadata.LastRun)  { $data.Metadata.LastRun }  else { $null }
        RunCount = if ($data.Metadata.RunCount) { [int]$data.Metadata.RunCount } else { 0 }
    }

    Write-StateLog -Level 'INFO' -Message "Loaded state: $($groupsByKey.Count) group(s), run #$($meta.RunCount)" `
        -Context @{ path = $Path; groups = $groupsByKey.Count; runCount = $meta.RunCount }

    return @{
        Metadata    = $meta
        GroupsByKey  = $groupsByKey
        CsvSources  = $csvSources
        IsFirstRun  = ($groupsByKey.Count -eq 0)
    }
}

# ---------------------------------------------------------------------------
# Public: Update-MembershipState
# ---------------------------------------------------------------------------
function Update-MembershipState {
    <#
    .SYNOPSIS
        Diffs current enumeration against the loaded state, producing change events
        and the next state to persist.

    .PARAMETER State
        The hashtable returned by Import-MembershipState.

    .PARAMETER CurrentGroupResults
        Array of current group result hashtables (each @{ Data = @{ Domain; GroupName; Members; Skipped } }).

    .PARAMETER Timestamp
        ISO-8601 timestamp string to stamp on this run's change events.

    .OUTPUTS
        Hashtable:
        @{
            NewState = @{ Metadata; GroupsByKey }   # ready for Save-MembershipState
            Changes  = @( @{ Timestamp; Domain; GroupName; SamAccountName; DisplayName; Email; Action } )
            Summary  = @{ TotalAdded; TotalRemoved; GroupsChanged; GroupsTracked; GroupsSeeded; IsFirstRun }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$CurrentGroupResults,

        [Parameter(Mandatory = $false)]
        [string]$Timestamp = (Get-Date).ToString('o'),

        [Parameter(Mandatory = $false)]
        [string]$CsvName = ''
    )

    $isFirstRun  = [bool]$State.IsFirstRun
    $groupsByKey = @{}
    foreach ($k in $State.GroupsByKey.Keys) { $groupsByKey[$k] = $State.GroupsByKey[$k] }

    $csvSources = @{}
    if ($State.CsvSources) {
        foreach ($k in $State.CsvSources.Keys) {
            $csvSources[$k] = @{
                LastRun = $State.CsvSources[$k].LastRun
                Groups  = @($State.CsvSources[$k].Groups)
            }
        }
    }

    $changes      = [System.Collections.Generic.List[hashtable]]::new()
    $totalAdded   = 0
    $totalRemoved = 0
    $groupsChanged = 0
    $groupsSeeded  = 0

    foreach ($gr in $CurrentGroupResults) {
        if (-not $gr.Data -or $gr.Data.Skipped) { continue }

        $domain    = $gr.Data.Domain
        $groupName = $gr.Data.GroupName
        if (-not $domain -or -not $groupName) { continue }
        $key = "$domain|$groupName"

        $currentMembers = @(ConvertTo-StateArray $gr.Data.Members)

        if ($groupsByKey.ContainsKey($key)) {
            # Known group -- compute real delta against last known membership.
            $baseline = @(ConvertTo-StateArray $groupsByKey[$key].Members)
            $diff = Compare-GroupMembership -CurrentMembers $currentMembers -BaselineMembers $baseline `
                -GroupName $groupName -Domain $domain

            foreach ($u in $diff.Added) {
                $changes.Add(@{
                    Timestamp = $Timestamp; Domain = $domain; GroupName = $groupName
                    SamAccountName = $u.SamAccountName; DisplayName = $u.DisplayName; Email = $u.Email
                    Action = 'Added'
                })
            }
            foreach ($u in $diff.Removed) {
                $changes.Add(@{
                    Timestamp = $Timestamp; Domain = $domain; GroupName = $groupName
                    SamAccountName = $u.SamAccountName; DisplayName = $u.DisplayName; Email = $u.Email
                    Action = 'Removed'
                })
            }

            $totalAdded   += $diff.Summary.AddedCount
            $totalRemoved += $diff.Summary.RemovedCount
            if ($diff.Summary.AddedCount -gt 0 -or $diff.Summary.RemovedCount -gt 0) { $groupsChanged++ }
        } else {
            # Newly tracked group (first run, or first time this group appears).
            # Seed silently -- do NOT emit the existing population as adds.
            $groupsSeeded++
        }

        # Record current membership as the new known state for this group.
        $groupsByKey[$key] = @{
            Domain    = $domain
            GroupName = $groupName
            LastSeen  = $Timestamp
            Members   = @($currentMembers | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    DisplayName    = if ($_.DisplayName) { $_.DisplayName } else { '' }
                    Email          = if ($_.Email)       { $_.Email }       else { '' }
                }
            })
        }
    }

    # Track which groups this CSV references (v2)
    if ($CsvName) {
        $groupKeysThisRun = @($CurrentGroupResults | Where-Object {
            $_.Data -and -not $_.Data.Skipped -and $_.Data.Domain -and $_.Data.GroupName
        } | ForEach-Object { "$($_.Data.Domain)|$($_.Data.GroupName)" })

        $csvSources[$CsvName] = @{
            LastRun = $Timestamp
            Groups  = @($groupKeysThisRun | Sort-Object -Unique)
        }
    }

    $meta = @{
        Version  = if ($CsvName) { '2.0' } elseif ($State.Metadata.Version) { $State.Metadata.Version } else { '1.0' }
        FirstRun = if ($State.Metadata.FirstRun) { $State.Metadata.FirstRun } else { $Timestamp }
        LastRun  = $Timestamp
        RunCount = [int]$State.Metadata.RunCount + 1
    }

    Write-StateLog -Level 'INFO' -Message "State updated: +$totalAdded added, -$totalRemoved removed across $groupsChanged group(s); $groupsSeeded seeded" `
        -Context @{ added = $totalAdded; removed = $totalRemoved; changed = $groupsChanged; seeded = $groupsSeeded; firstRun = $isFirstRun }

    return @{
        NewState = @{ Metadata = $meta; GroupsByKey = $groupsByKey; CsvSources = $csvSources }
        Changes  = @($changes)
        Summary  = @{
            TotalAdded    = $totalAdded
            TotalRemoved  = $totalRemoved
            GroupsChanged = $groupsChanged
            GroupsTracked = $groupsByKey.Count
            GroupsSeeded  = $groupsSeeded
            IsFirstRun    = $isFirstRun
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Save-MembershipState
# ---------------------------------------------------------------------------
function Save-MembershipState {
    <#
    .SYNOPSIS
        Atomically writes the new state to disk (UTF-8 without BOM).

    .PARAMETER NewState
        The NewState hashtable from Update-MembershipState (@{ Metadata; GroupsByKey }).

    .PARAMETER Path
        Destination path for state.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$NewState,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $outDir = Split-Path $Path -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        $null = New-Item -ItemType Directory -Path $outDir -Force
    }

    $groupsArr = foreach ($key in ($NewState.GroupsByKey.Keys | Sort-Object)) {
        $g = $NewState.GroupsByKey[$key]
        [ordered]@{
            Domain    = $g.Domain
            GroupName = $g.GroupName
            LastSeen  = $g.LastSeen
            Members   = @(ConvertTo-StateArray $g.Members)
        }
    }

    $out = [ordered]@{
        Metadata = [ordered]@{
            Version  = $NewState.Metadata.Version
            FirstRun = $NewState.Metadata.FirstRun
            LastRun  = $NewState.Metadata.LastRun
            RunCount = $NewState.Metadata.RunCount
        }
        Groups = @($groupsArr)
    }

    # v2: include CsvSources section if present
    if ($NewState.CsvSources -and $NewState.CsvSources.Count -gt 0) {
        $csvSourcesOut = [ordered]@{}
        foreach ($csvKey in ($NewState.CsvSources.Keys | Sort-Object)) {
            $csvSourcesOut[$csvKey] = [ordered]@{
                LastRun = $NewState.CsvSources[$csvKey].LastRun
                Groups  = @($NewState.CsvSources[$csvKey].Groups)
            }
        }
        $out['CsvSources'] = $csvSourcesOut
    }

    $json = $out | ConvertTo-Json -Depth 10
    $tmp  = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $Path -Force

    Write-StateLog -Level 'INFO' -Message "State saved: $Path ($($NewState.GroupsByKey.Count) groups)" `
        -Context @{ path = $Path; groups = $NewState.GroupsByKey.Count }
    return $Path
}

# ---------------------------------------------------------------------------
# Public: Add-ChangeLogEntries
# ---------------------------------------------------------------------------
function Add-ChangeLogEntries {
    <#
    .SYNOPSIS
        Appends change events to the JSONL change log (one compact JSON object per line).

    .PARAMETER Changes
        Array of change event hashtables from Update-MembershipState.

    .PARAMETER Path
        Path to changelog.jsonl.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Changes,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not $Changes -or $Changes.Count -eq 0) { return 0 }

    $outDir = Split-Path $Path -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        $null = New-Item -ItemType Directory -Path $outDir -Force
    }

    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $Changes) {
        $line = [ordered]@{
            Timestamp      = $c.Timestamp
            Domain         = $c.Domain
            GroupName      = $c.GroupName
            SamAccountName = $c.SamAccountName
            DisplayName    = $c.DisplayName
            Email          = $c.Email
            Action         = $c.Action
        } | ConvertTo-Json -Compress
        $null = $sb.Append($line).Append("`r`n")
    }

    [System.IO.File]::AppendAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

    Write-StateLog -Level 'INFO' -Message "Change log appended: $($Changes.Count) event(s) -> $Path" `
        -Context @{ path = $Path; events = $Changes.Count }
    return $Changes.Count
}

# ---------------------------------------------------------------------------
# Public: Invoke-ChangeLogRotation
# ---------------------------------------------------------------------------
function Invoke-ChangeLogRotation {
    <#
    .SYNOPSIS
        Rotates the changelog when it exceeds a configurable size threshold.

    .DESCRIPTION
        Checks the changelog file size against MaxSizeMB. When exceeded, the
        current changelog is archived as changelog-YYYY-MM.jsonl (using the
        current date), and the active changelog is replaced with a fresh file.

        Alternatively, when RetentionDays is specified, entries older than
        the retention period are trimmed and the file is rewritten in place.

        Size-based rotation (archive) takes priority. If both thresholds are
        set, size rotation runs first; retention trimming runs on the result.

    .PARAMETER Path
        Path to the changelog.jsonl file.

    .PARAMETER MaxSizeMB
        Maximum changelog size in megabytes before archiving. Default: 50.
        Set to 0 to disable size-based rotation.

    .PARAMETER RetentionDays
        Optional. When set, entries older than this many days are removed.
        Set to 0 to disable retention-based trimming.

    .OUTPUTS
        Hashtable: @{ Rotated = [bool]; Archived = [string]; TrimmedCount = [int]; RemainingCount = [int] }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, [double]::MaxValue)]
        [double]$MaxSizeMB = 50,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$RetentionDays = 0
    )

    $result = @{
        Rotated        = $false
        Archived       = ''
        TrimmedCount   = 0
        RemainingCount = 0
    }

    if (-not (Test-Path $Path)) {
        return $result
    }

    $fileInfo = Get-Item $Path -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $result }

    # ---- Size-based rotation: archive entire file ----
    if ($MaxSizeMB -gt 0) {
        $fileSizeMB = $fileInfo.Length / 1MB
        if ($fileSizeMB -ge $MaxSizeMB) {
            $archiveDir = Split-Path $Path -Parent
            $dateTag = (Get-Date).ToString('yyyy-MM')
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
            $archiveName = "${baseName}-${dateTag}.jsonl"
            $archivePath = Join-Path $archiveDir $archiveName

            # Avoid overwriting an existing archive for the same month
            if (Test-Path $archivePath) {
                $counter = 1
                do {
                    $archiveName = "${baseName}-${dateTag}-$counter.jsonl"
                    $archivePath = Join-Path $archiveDir $archiveName
                    $counter++
                } while (Test-Path $archivePath)
            }

            # Move current changelog to archive
            Move-Item -LiteralPath $Path -Destination $archivePath -Force

            # Create empty new changelog
            [System.IO.File]::WriteAllText($Path, '', [System.Text.UTF8Encoding]::new($false))

            $result.Rotated = $true
            $result.Archived = $archivePath

            Write-StateLog -Level 'INFO' -Message "Changelog rotated: archived to $archivePath (was $([Math]::Round($fileSizeMB, 2)) MB)" `
                -Context @{ path = $Path; archive = $archivePath; sizeMB = [Math]::Round($fileSizeMB, 2) }

            return $result
        }
    }

    # ---- Retention-based trimming: remove old entries ----
    if ($RetentionDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        $lines = [System.IO.File]::ReadAllLines($Path)
        $kept = [System.Collections.Generic.List[string]]::new()
        $trimmedCount = 0

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if (-not $trimmed) { continue }

            $keep = $true
            try {
                $evt = $trimmed | ConvertFrom-Json
                # Pre-type as [datetime]: PS 5.1 cannot bind [ref]$ts to TryParse's
                # 'out DateTime' overload when $ts is $null (untyped) -> "no overload, argc 2".
                [datetime]$ts = [datetime]::MinValue
                if ($evt.Timestamp -and [datetime]::TryParse([string]$evt.Timestamp, [ref]$ts)) {
                    if ($ts -lt $cutoff) {
                        $keep = $false
                        $trimmedCount++
                    }
                }
            } catch {
                # Unparseable lines are kept
            }

            if ($keep) {
                $kept.Add($trimmed)
            }
        }

        if ($trimmedCount -gt 0) {
            $content = if ($kept.Count -gt 0) {
                ($kept -join "`r`n") + "`r`n"
            } else {
                ''
            }
            [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))

            $result.TrimmedCount = $trimmedCount
            $result.RemainingCount = $kept.Count

            Write-StateLog -Level 'INFO' -Message "Changelog trimmed: removed $trimmedCount entries older than $RetentionDays days ($($kept.Count) remaining)" `
                -Context @{ path = $Path; trimmed = $trimmedCount; remaining = $kept.Count; retentionDays = $RetentionDays }
        } else {
            $result.RemainingCount = $kept.Count
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
# Public: Resolve-ChangeWindow
# ---------------------------------------------------------------------------
function Resolve-ChangeWindow {
    <#
    .SYNOPSIS
        Resolve a change-history time window from any of: a preset (Day/Week/Month/Quarter),
        a custom number of days back, or an explicit since-date. Precedence:
        ChangeSince > ChangeDays > ChangePeriod. Returns @{ SinceDate; Label; Active }.
    .NOTES
        Pure: pass -Now for deterministic testing (defaults to the current time).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$ChangePeriod,
        [int]$ChangeDays = 0,
        [Nullable[datetime]]$ChangeSince = $null,
        [Nullable[datetime]]$Now = $null
    )
    $ref = if ($Now) { [datetime]$Now } else { Get-Date }
    $since = $null
    $label = $null
    if ($ChangeSince) {
        $since = [datetime]$ChangeSince
        $label = "since $($since.ToString('yyyy-MM-dd'))"
    } elseif ($ChangeDays -gt 0) {
        $since = $ref.AddDays(-$ChangeDays)
        $label = "last $ChangeDays day(s)"
    } elseif ($ChangePeriod) {
        switch ($ChangePeriod) {
            'Day'     { $since = $ref.AddDays(-1);   $label = 'last Day' }
            'Week'    { $since = $ref.AddDays(-7);   $label = 'last Week' }
            'Month'   { $since = $ref.AddMonths(-1); $label = 'last Month' }
            'Quarter' { $since = $ref.AddMonths(-3); $label = 'last Quarter' }
        }
    }
    return @{ SinceDate = $since; Label = $label; Active = [bool]$since }
}

# ---------------------------------------------------------------------------
# Public: Read-ChangeLog
# ---------------------------------------------------------------------------
function Read-ChangeLog {
    <#
    .SYNOPSIS
        Reads change events from the JSONL change log, optionally filtered.

    .PARAMETER Path
        Path to changelog.jsonl.

    .PARAMETER ChangeType
        Added | Removed | Both (default Both).

    .PARAMETER Since
        Optional [datetime]; only events at or after this time are returned.

    .OUTPUTS
        Array of change event objects.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Added', 'Removed', 'Both')]
        [string]$ChangeType = 'Both',

        [Parameter(Mandatory = $false)]
        [Nullable[datetime]]$Since = $null,

        [Parameter(Mandatory = $false)]
        [switch]$LastDay,

        [Parameter(Mandatory = $false)]
        [switch]$LastWeek,

        [Parameter(Mandatory = $false)]
        [switch]$LastMonth,

        [Parameter(Mandatory = $false)]
        [switch]$LastQuarter,

        [Parameter(Mandatory = $false)]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [string]$CsvName,

        [Parameter(Mandatory = $false)]
        [string]$StatePath
    )

    # Time-period convenience switches -> $Since
    if ($LastDay -and -not $Since) { $Since = (Get-Date).AddDays(-1) }
    elseif ($LastWeek -and -not $Since) { $Since = (Get-Date).AddDays(-7) }
    elseif ($LastMonth -and -not $Since) { $Since = (Get-Date).AddMonths(-1) }
    elseif ($LastQuarter -and -not $Since) { $Since = (Get-Date).AddMonths(-3) }

    # CsvName filter: resolve which groups belong to this CSV
    $csvGroupFilter = $null
    if ($CsvName -and $StatePath -and (Test-Path $StatePath)) {
        try {
            $stateRaw = [System.IO.File]::ReadAllText($StatePath) | ConvertFrom-Json
            if ($stateRaw.CsvSources -and $stateRaw.CsvSources.$CsvName) {
                $csvGroupFilter = @(ConvertTo-StateArray $stateRaw.CsvSources.$CsvName.Groups)
            }
        } catch { }
    }

    if (-not (Test-Path $Path)) { return @() }

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($rawLine in [System.IO.File]::ReadAllLines($Path)) {
        $line = $rawLine.Trim()
        if (-not $line) { continue }
        try { $evt = $line | ConvertFrom-Json } catch { continue }

        if ($ChangeType -ne 'Both' -and $evt.Action -ne $ChangeType) { continue }
        if ($Since) {
            # Pre-type as [datetime]: PS 5.1 cannot bind [ref]$ts to TryParse's
            # 'out DateTime' overload when $ts is $null (untyped) -> "no overload, argc 2".
            [datetime]$ts = [datetime]::MinValue
            if ([datetime]::TryParse([string]$evt.Timestamp, [ref]$ts)) {
                if ($ts -lt $Since) { continue }
            } else {
                # An unparseable timestamp can't be shown to fall within the
                # requested window -- exclude it rather than leaking it through.
                continue
            }
        }

        # Group name filter
        if ($GroupName -and $evt.GroupName -ne $GroupName) { continue }

        # CSV source filter
        if ($csvGroupFilter) {
            $evtKey = "$($evt.Domain)|$($evt.GroupName)"
            if ($evtKey -notin $csvGroupFilter) { continue }
        }

        $events.Add($evt)
    }
    return ,@($events)
}

# ---------------------------------------------------------------------------
# Public: Merge-LegacyState
# ---------------------------------------------------------------------------
function Merge-LegacyState {
    <#
    .SYNOPSIS
        Merges per-CSV v1 state files into a single v2 unified state file.
    .DESCRIPTION
        Scans StateDir for *-membership-state.json files, merges all groups
        (deduplicating by DOMAIN|GroupName, keeping the most recent LastSeen),
        builds CsvSources from filenames, and merges all *-changelog.jsonl
        files sorted by timestamp.
    .PARAMETER StateDir
        Directory containing legacy state files.
    .PARAMETER OutputStateFile
        Path for the unified state file. Defaults to group-enumerator-state.json in StateDir.
    .PARAMETER OutputChangeLog
        Path for the unified changelog. Defaults to changelog.jsonl in StateDir.
    .PARAMETER Force
        Overwrite existing unified state/changelog files without prompting.
        Without -Force, the function will skip merge if output files already exist.
    .OUTPUTS
        Hashtable: @{ FilesProcessed; GroupsMerged; DuplicateGroups; ChangeLogEntries; OutputStateFile; OutputChangeLog; Skipped }
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StateDir,
        [Parameter(Mandatory = $false)]
        [string]$OutputStateFile,
        [Parameter(Mandatory = $false)]
        [string]$OutputChangeLog,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if (-not $OutputStateFile) { $OutputStateFile = Join-Path $StateDir 'group-enumerator-state.json' }
    if (-not $OutputChangeLog) { $OutputChangeLog = Join-Path $StateDir 'changelog.jsonl' }

    $emptyResult = @{ FilesProcessed = 0; GroupsMerged = 0; DuplicateGroups = 0; ChangeLogEntries = 0; OutputStateFile = $OutputStateFile; OutputChangeLog = $OutputChangeLog; Skipped = $false }

    # Guard: if output already exists and -Force not specified, skip
    if (-not $Force -and (Test-Path $OutputStateFile)) {
        Write-StateLog -Level 'WARN' -Message "Unified state file already exists: $OutputStateFile (use -Force to overwrite)" -Context @{ path = $OutputStateFile }
        $emptyResult.Skipped = $true
        return $emptyResult
    }

    $stateFiles = Get-ChildItem -Path $StateDir -Filter '*-membership-state.json' -File -ErrorAction SilentlyContinue
    if (-not $stateFiles -or $stateFiles.Count -eq 0) {
        return $emptyResult
    }

    # WhatIf support: show what would happen without writing
    if (-not $PSCmdlet.ShouldProcess("$($stateFiles.Count) legacy state file(s) in $StateDir", 'Merge into unified state')) {
        $emptyResult.Skipped = $true
        return $emptyResult
    }

    $allGroups = @{}
    $csvSources = @{}
    $duplicateCount = 0
    $earliestFirst = $null
    $latestLast = $null
    $totalRunCount = 0

    foreach ($file in $stateFiles) {
        $csvLeaf = $file.BaseName -replace '-membership-state$', ''
        $state = Import-MembershipState -Path $file.FullName

        # Track CSV source
        $groupKeys = @()
        foreach ($key in $state.GroupsByKey.Keys) {
            $groupKeys += $key
            $g = $state.GroupsByKey[$key]
            if ($allGroups.ContainsKey($key)) {
                # Duplicate: keep the entry with the latest LastSeen
                $duplicateCount++
                $existingLast = $allGroups[$key].LastSeen
                $newLast = $g.LastSeen
                if ($newLast -and $existingLast -and $newLast -gt $existingLast) {
                    $allGroups[$key] = $g
                }
            } else {
                $allGroups[$key] = $g
            }
        }

        $csvSources[$csvLeaf] = @{
            LastRun = $state.Metadata.LastRun
            Groups  = @($groupKeys | Sort-Object)
        }

        # Track metadata extremes
        if ($state.Metadata.FirstRun) {
            if (-not $earliestFirst -or $state.Metadata.FirstRun -lt $earliestFirst) {
                $earliestFirst = $state.Metadata.FirstRun
            }
        }
        if ($state.Metadata.LastRun) {
            if (-not $latestLast -or $state.Metadata.LastRun -gt $latestLast) {
                $latestLast = $state.Metadata.LastRun
            }
        }
        $totalRunCount += [int]$state.Metadata.RunCount
    }

    # Build unified state
    $newState = @{
        Metadata   = @{
            Version  = '2.0'
            FirstRun = $earliestFirst
            LastRun  = $latestLast
            RunCount = $totalRunCount
        }
        GroupsByKey = $allGroups
        CsvSources = $csvSources
    }

    # Suppress: Save-MembershipState returns $Path, which would otherwise leak into
    # this function's pipeline output alongside the result hashtable (callers index
    # the result by property, so a stray string makes it an array and breaks that).
    $null = Save-MembershipState -NewState $newState -Path $OutputStateFile

    # Merge changelogs
    $changeLogFiles = Get-ChildItem -Path $StateDir -Filter '*-changelog.jsonl' -File -ErrorAction SilentlyContinue
    $allEntries = [System.Collections.Generic.List[string]]::new()

    if ($changeLogFiles) {
        $seenEntries = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($clFile in $changeLogFiles) {
            foreach ($line in [System.IO.File]::ReadAllLines($clFile.FullName)) {
                $trimmed = $line.Trim()
                if (-not $trimmed) { continue }
                # Deduplicate by exact line content. This collapses ONLY byte-identical
                # events, which arise when the same change is present in more than one
                # legacy changelog being merged (overlap). It cannot drop a genuinely
                # distinct change: a changelog event is keyed by Timestamp+Domain+
                # GroupName+SamAccountName+Action, and a given account cannot repeat the
                # same action on the same group at the same timestamp -- so two identical
                # lines always denote one logical event. Distinct events (different
                # action, user, group, or timestamp) serialize to different lines and
                # are all preserved.
                if ($seenEntries.Add($trimmed)) {
                    $allEntries.Add($trimmed)
                }
            }
        }

        # Sort by timestamp (ISO-8601 sorts lexicographically)
        $sorted = $allEntries | Sort-Object {
            try { ($_ | ConvertFrom-Json).Timestamp } catch { '' }
        }

        if ($sorted.Count -gt 0) {
            $clContent = ($sorted -join "`r`n") + "`r`n"
            [System.IO.File]::WriteAllText($OutputChangeLog, $clContent, [System.Text.UTF8Encoding]::new($false))
        }
    }

    Write-StateLog -Level 'INFO' -Message "Merged $($stateFiles.Count) legacy state file(s): $($allGroups.Count) group(s), $($allEntries.Count) changelog entries" `
        -Context @{ files = $stateFiles.Count; groups = $allGroups.Count; duplicates = $duplicateCount; changelog = $allEntries.Count }

    return @{
        FilesProcessed  = $stateFiles.Count
        GroupsMerged     = $allGroups.Count
        DuplicateGroups  = $duplicateCount
        ChangeLogEntries = $allEntries.Count
        OutputStateFile  = $OutputStateFile
        OutputChangeLog  = $OutputChangeLog
        Skipped          = $false
    }
}

# ---------------------------------------------------------------------------
# Public: Export-ChangeFeedCsv
# ---------------------------------------------------------------------------
function Export-ChangeFeedCsv {
    <#
    .SYNOPSIS
        Writes a SailPoint-ready CSV of change events, keyed on sAMAccountName,
        filtered by change type.

    .DESCRIPTION
        Columns: Change,Domain,GroupName,SamAccountName,DisplayName,Email
        SailPoint correlates on SamAccountName. Default ChangeType 'Both' emits adds
        and removals; 'Removed' produces the removals-only feed. A header-only file
        is written when there are no matching events, so the daily feed always exists.

    .PARAMETER Changes
        Array of change event hashtables (from Update-MembershipState) or objects
        (from Read-ChangeLog).

    .PARAMETER OutputPath
        Destination CSV path.

    .PARAMETER ChangeType
        Added | Removed | Both (default Both).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Changes,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Added', 'Removed', 'Both')]
        [string]$ChangeType = 'Both'
    )

    # RFC 4180 field escaping: quote fields containing comma, quote, CR or LF and
    # double embedded quotes, so a DisplayName like 'Smith, "Bob"' cannot shift columns.
    function ConvertTo-FeedCsvField {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        if ($Value -match '[",\r\n]') { return '"' + ($Value -replace '"', '""') + '"' }
        return $Value
    }

    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add('Change,Domain,GroupName,SamAccountName,DisplayName,Email')

    foreach ($c in $Changes) {
        if ($ChangeType -ne 'Both' -and $c.Action -ne $ChangeType) { continue }
        $change = ConvertTo-FeedCsvField ([string]$c.Action)
        $domain = ConvertTo-FeedCsvField ([string]$c.Domain)
        $group  = ConvertTo-FeedCsvField ([string]$c.GroupName)
        $sam    = ConvertTo-FeedCsvField $(if ($c.SamAccountName) { [string]$c.SamAccountName } else { '' })
        $dn     = ConvertTo-FeedCsvField $(if ($c.DisplayName)    { [string]$c.DisplayName }    else { '' })
        $mail   = ConvertTo-FeedCsvField $(if ($c.Email)          { [string]$c.Email }          else { '' })
        $rows.Add("$change,$domain,$group,$sam,$dn,$mail")
    }

    $outDir = Split-Path $OutputPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        $null = New-Item -ItemType Directory -Path $outDir -Force
    }

    [System.IO.File]::WriteAllText($OutputPath, ($rows -join "`r`n"), [System.Text.UTF8Encoding]::new($false))

    Write-StateLog -Level 'INFO' -Message "Change-feed CSV exported: $OutputPath ($ChangeType)" `
        -Context @{ path = $OutputPath; changeType = $ChangeType; rows = ($rows.Count - 1) }
    return $OutputPath
}

# ---------------------------------------------------------------------------
# Public: Export-ChangeReportHtml
# ---------------------------------------------------------------------------
function Export-ChangeReportHtml {
    <#
    .SYNOPSIS
        Writes a self-contained HTML report of membership changes (adds/removals).

    .DESCRIPTION
        Standalone, dependency-free HTML (embedded CSS + a theme toggle) matching the
        project's dark/light palette. Summary cards plus per-group add/remove tables,
        honouring -ChangeType. All user-controlled text is HTML-escaped. This is an
        additive artefact -- it does not modify any existing report generator.

    .PARAMETER Changes
        Array of change events (from Update-MembershipState or Read-ChangeLog).

    .PARAMETER OutputPath
        Destination .html path.

    .PARAMETER ChangeType
        Added | Removed | Both (default Both).

    .PARAMETER Summary
        Optional summary hashtable from Update-MembershipState (for group counts).

    .PARAMETER Theme
        Initial theme: dark (default) or light. Toggleable in-browser.

    .PARAMETER Title
        Optional report title.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Changes,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Added', 'Removed', 'Both')]
        [string]$ChangeType = 'Both',

        [Parameter(Mandatory = $false)]
        [hashtable]$Summary,

        [Parameter(Mandatory = $false)]
        [ValidateSet('dark', 'light')]
        [string]$Theme = 'dark',

        [Parameter(Mandatory = $false)]
        [string]$Title = 'Membership Changes'
    )

    function ConvertTo-HtmlText {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        return ($Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;')
    }

    # Filter by change type and group by DOMAIN|GroupName.
    $filtered = @($Changes | Where-Object { $ChangeType -eq 'Both' -or $_.Action -eq $ChangeType })
    $byGroup = @{}
    foreach ($c in $filtered) {
        $key = "$($c.Domain)|$($c.GroupName)"
        if (-not $byGroup.ContainsKey($key)) { $byGroup[$key] = [System.Collections.Generic.List[object]]::new() }
        $byGroup[$key].Add($c)
    }

    $addedShown   = @($filtered | Where-Object { $_.Action -eq 'Added' }).Count
    $removedShown = @($filtered | Where-Object { $_.Action -eq 'Removed' }).Count
    $groupsTracked = if ($Summary -and $null -ne $Summary.GroupsTracked) { $Summary.GroupsTracked } else { $byGroup.Count }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine(('<html lang="en" class="theme-{0}">' -f $Theme))
    $null = $sb.AppendLine('<head>')
    $null = $sb.AppendLine('<meta charset="UTF-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    $null = $sb.AppendLine(('<title>{0}</title>' -f (ConvertTo-HtmlText $Title)))
    $null = $sb.AppendLine('<style>')
    $null = $sb.AppendLine('.theme-dark{--bg:#1a1a2e;--card-bg:#16213e;--card-inner:#0f1620;--text:#e0e0e0;--text-muted:#94a3b8;--accent:#3498db;--border:#2d3748;--th-bg:#2c3e50;--th-text:#fff;--row-alt:rgba(44,62,80,0.25);--header-grad:linear-gradient(135deg,#2c3e50 0%,#3498db 100%);--shadow:0 4px 6px rgba(0,0,0,0.35);}')
    $null = $sb.AppendLine('.theme-light{--bg:#f8f9fa;--card-bg:#fff;--card-inner:#f1f5f9;--text:#1a1a2e;--text-muted:#64748b;--accent:#2563eb;--border:#e2e8f0;--th-bg:#334155;--th-text:#fff;--row-alt:rgba(226,232,240,0.5);--header-grad:linear-gradient(135deg,#334155 0%,#2563eb 100%);--shadow:0 4px 6px rgba(0,0,0,0.1);}')
    $null = $sb.AppendLine(':root{--c-added:#52b788;--c-removed:#e63946;}')
    $null = $sb.AppendLine('*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}')
    $null = $sb.AppendLine('body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;line-height:1.6;}')
    $null = $sb.AppendLine('.container{max-width:1440px;margin:0 auto;}')
    $null = $sb.AppendLine('header{background:var(--header-grad);padding:28px 32px;border-radius:10px;margin-bottom:26px;box-shadow:var(--shadow);display:flex;justify-content:space-between;align-items:flex-start;gap:20px;}')
    $null = $sb.AppendLine('header h1{font-size:2em;color:#fff;margin-bottom:6px;}header .sub{color:rgba(255,255,255,0.85);font-size:0.95em;}')
    $null = $sb.AppendLine('.toggle{background:rgba(255,255,255,0.15);color:#fff;border:1px solid rgba(255,255,255,0.3);border-radius:6px;padding:8px 14px;cursor:pointer;font-size:0.9em;}')
    $null = $sb.AppendLine('.cards{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:26px;}')
    $null = $sb.AppendLine('.card{background:var(--card-bg);border:1px solid var(--border);border-radius:10px;padding:18px 22px;min-width:150px;box-shadow:var(--shadow);}')
    $null = $sb.AppendLine('.card .n{font-size:2em;font-weight:700;}.card .l{color:var(--text-muted);font-size:0.85em;text-transform:uppercase;letter-spacing:0.04em;}')
    $null = $sb.AppendLine('.n.add{color:var(--c-added);}.n.rem{color:var(--c-removed);}')
    $null = $sb.AppendLine('section.group{background:var(--card-bg);border:1px solid var(--border);border-radius:10px;margin-bottom:18px;box-shadow:var(--shadow);overflow:hidden;}')
    $null = $sb.AppendLine('section.group h2{font-size:1.1em;padding:14px 20px;background:var(--card-inner);border-bottom:1px solid var(--border);}')
    $null = $sb.AppendLine('table{width:100%;border-collapse:collapse;}th,td{text-align:left;padding:9px 20px;border-bottom:1px solid var(--border);font-size:0.92em;}')
    $null = $sb.AppendLine('th{background:var(--th-bg);color:var(--th-text);position:sticky;top:0;}tr:nth-child(even) td{background:var(--row-alt);}')
    $null = $sb.AppendLine('.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:600;color:#fff;}')
    $null = $sb.AppendLine('.badge.added{background:var(--c-added);}.badge.removed{background:var(--c-removed);}')
    $null = $sb.AppendLine('.empty{padding:30px;text-align:center;color:var(--text-muted);}')
    $null = $sb.AppendLine('footer{margin-top:26px;color:var(--text-muted);font-size:0.82em;text-align:center;}')
    $null = $sb.AppendLine('</style></head><body><div class="container">')
    $null = $sb.AppendLine('<header><div class="header-text">')
    $null = $sb.AppendLine(('<h1>{0}</h1>' -f (ConvertTo-HtmlText $Title)))
    $null = $sb.AppendLine(('<div class="sub">Generated {0} &middot; Change type: {1}</div>' -f (ConvertTo-HtmlText $generated), (ConvertTo-HtmlText $ChangeType)))
    $null = $sb.AppendLine('</div><button class="toggle" onclick="var h=document.documentElement;h.className=h.className===''theme-dark''?''theme-light'':''theme-dark'';">Toggle theme</button></header>')

    # Summary cards
    $null = $sb.AppendLine('<div class="cards">')
    if ($ChangeType -ne 'Removed') {
        $null = $sb.AppendLine(('<div class="card"><div class="n add">{0}</div><div class="l">Added</div></div>' -f $addedShown))
    }
    if ($ChangeType -ne 'Added') {
        $null = $sb.AppendLine(('<div class="card"><div class="n rem">{0}</div><div class="l">Removed</div></div>' -f $removedShown))
    }
    $null = $sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Net change</div></div>' -f ($addedShown - $removedShown)))
    $null = $sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Groups changed</div></div>' -f $byGroup.Count))
    $null = $sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">Groups tracked</div></div>' -f $groupsTracked))
    $null = $sb.AppendLine('</div>')

    if ($byGroup.Count -eq 0) {
        $null = $sb.AppendLine('<section class="group"><div class="empty">No membership changes for this run.</div></section>')
    } else {
        foreach ($key in ($byGroup.Keys | Sort-Object)) {
            $parts  = $key -split '\|', 2
            $domain = if ($parts.Count -ge 1) { $parts[0] } else { '' }
            $group  = if ($parts.Count -ge 2) { $parts[1] } else { '' }
            $null = $sb.AppendLine('<section class="group">')
            $null = $sb.AppendLine(('<h2>{0}\{1}</h2>' -f (ConvertTo-HtmlText $domain), (ConvertTo-HtmlText $group)))
            $null = $sb.AppendLine('<table><thead><tr><th>Change</th><th>SamAccountName</th><th>DisplayName</th><th>Email</th></tr></thead><tbody>')
            foreach ($c in ($byGroup[$key] | Sort-Object @{e={$_.Action}}, @{e={$_.SamAccountName}})) {
                $cls = if ($c.Action -eq 'Removed') { 'removed' } else { 'added' }
                $null = $sb.AppendLine(('<tr><td><span class="badge {0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f `
                    $cls, (ConvertTo-HtmlText ([string]$c.Action)), (ConvertTo-HtmlText ([string]$c.SamAccountName)), `
                    (ConvertTo-HtmlText ([string]$c.DisplayName)), (ConvertTo-HtmlText ([string]$c.Email))))
            }
            $null = $sb.AppendLine('</tbody></table></section>')
        }
    }

    $null = $sb.AppendLine('<footer>Membership change tracking &middot; self-contained report</footer>')
    $null = $sb.AppendLine('</div></body></html>')

    $outDir = Split-Path $OutputPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        $null = New-Item -ItemType Directory -Path $outDir -Force
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

    Write-StateLog -Level 'INFO' -Message "Change report HTML exported: $OutputPath ($ChangeType)" `
        -Context @{ path = $OutputPath; changeType = $ChangeType; groups = $byGroup.Count }
    return $OutputPath
}
