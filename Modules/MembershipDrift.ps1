<#
.SYNOPSIS
    Group membership drift detection across runs

.DESCRIPTION
    Compares current group membership data against previous run(s) to detect
    users added or removed from each group. Supports two comparison baselines:
      - Initial (first run) -- long-term drift from the original state
      - Previous (last run) -- incremental changes since the last execution

    Returns per-group delta details including the specific users added/removed,
    with summary counts for dashboard display.

.NOTES
    No emoji in code.
    Depends on Write-GroupEnumLog from GroupEnumLogger.ps1 (dot-sourced first).
    Depends on Import-GroupDataJson from GroupReportGenerator.ps1 (dot-sourced first).
#>

# ---------------------------------------------------------------------------
# Public: Get-LatestCacheFile
# ---------------------------------------------------------------------------
function Get-LatestCacheFile {
    <#
    .SYNOPSIS
        Finds the most recent JSON cache file in a directory, excluding a specific file.

    .PARAMETER CacheDirectory
        Directory to search for .json files

    .PARAMETER ExcludePath
        Optional file path to exclude (typically the current run's cache)

    .OUTPUTS
        String path to the latest cache file, or $null if none found
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheDirectory,

        [Parameter(Mandatory = $false)]
        [string]$ExcludePath
    )

    if (-not (Test-Path $CacheDirectory)) { return $null }

    $excludeLeaf = if ($ExcludePath) { [System.IO.Path]::GetFileName($ExcludePath) } else { '' }

    $jsonFiles = Get-ChildItem -Path $CacheDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $excludeLeaf } |
        Sort-Object LastWriteTime -Descending

    if ($jsonFiles -and $jsonFiles.Count -gt 0) {
        $latest = $jsonFiles[0].FullName
        Write-GroupEnumLog -Level 'DEBUG' -Operation 'DriftDetection' `
            -Message "Latest cache file found: $latest" -Context @{ path = $latest }
        return $latest
    }

    return $null
}

# ---------------------------------------------------------------------------
# Public: Compare-GroupMembership
# ---------------------------------------------------------------------------
function Compare-GroupMembership {
    <#
    .SYNOPSIS
        Compares current group members against a baseline set to find additions and removals.

    .PARAMETER CurrentMembers
        Array of current member hashtables (each must have SamAccountName)

    .PARAMETER BaselineMembers
        Array of baseline member hashtables from a previous run

    .PARAMETER GroupName
        Group name (for logging and display)

    .PARAMETER Domain
        Domain name (for logging)

    .OUTPUTS
        Hashtable:
        @{
            Added   = @( @{ SamAccountName; DisplayName; Email } )
            Removed = @( @{ SamAccountName; DisplayName; Email } )
            Unchanged = @( @{ SamAccountName; DisplayName; Email } )
            Summary = @{
                AddedCount    = [int]
                RemovedCount  = [int]
                UnchangedCount = [int]
                TotalCurrent  = [int]
                TotalBaseline = [int]
                NetChange     = [int]   # positive = growth, negative = shrink
            }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$CurrentMembers,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$BaselineMembers,

        [Parameter(Mandatory = $false)]
        [string]$GroupName = '',

        [Parameter(Mandatory = $false)]
        [string]$Domain = ''
    )

    # Build SAM sets for fast lookup (case-insensitive)
    $currentSams  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $baselineSams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $currentBySam  = @{}
    $baselineBySam = @{}

    foreach ($m in $CurrentMembers) {
        $sam = if ($m.SamAccountName) { $m.SamAccountName } else { continue }
        $null = $currentSams.Add($sam)
        $currentBySam[$sam.ToLower()] = $m
    }

    foreach ($m in $BaselineMembers) {
        $sam = if ($m.SamAccountName) { $m.SamAccountName } else { continue }
        $null = $baselineSams.Add($sam)
        $baselineBySam[$sam.ToLower()] = $m
    }

    # Added: in current but not in baseline
    $added = @()
    foreach ($sam in $currentSams) {
        if (-not $baselineSams.Contains($sam)) {
            $user = $currentBySam[$sam.ToLower()]
            $added += @{
                SamAccountName = $user.SamAccountName
                DisplayName    = if ($user.DisplayName) { $user.DisplayName } else { '' }
                Email          = if ($user.Email) { $user.Email } else { '' }
            }
        }
    }

    # Removed: in baseline but not in current
    $removed = @()
    foreach ($sam in $baselineSams) {
        if (-not $currentSams.Contains($sam)) {
            $user = $baselineBySam[$sam.ToLower()]
            $removed += @{
                SamAccountName = if ($user.SamAccountName) { $user.SamAccountName } else { $sam }
                DisplayName    = if ($user -and $user.DisplayName) { $user.DisplayName } else { '' }
                Email          = if ($user -and $user.Email) { $user.Email } else { '' }
            }
        }
    }

    # Unchanged: in both
    $unchanged = @()
    foreach ($sam in $currentSams) {
        if ($baselineSams.Contains($sam)) {
            $user = $currentBySam[$sam.ToLower()]
            $unchanged += @{
                SamAccountName = $user.SamAccountName
                DisplayName    = if ($user.DisplayName) { $user.DisplayName } else { '' }
                Email          = if ($user.Email) { $user.Email } else { '' }
            }
        }
    }

    $summary = @{
        AddedCount     = $added.Count
        RemovedCount   = $removed.Count
        UnchangedCount = $unchanged.Count
        TotalCurrent   = $currentSams.Count
        TotalBaseline  = $baselineSams.Count
        NetChange      = $added.Count - $removed.Count
    }

    if ($added.Count -gt 0 -or $removed.Count -gt 0) {
        Write-GroupEnumLog -Level 'INFO' -Operation 'DriftDetection' `
            -Message "Drift in $Domain\$GroupName : +$($added.Count) added, -$($removed.Count) removed" `
            -Context @{
                domain    = $Domain
                groupName = $GroupName
                added     = $added.Count
                removed   = $removed.Count
                unchanged = $unchanged.Count
            }
    }

    return @{
        Added     = $added
        Removed   = $removed
        Unchanged = $unchanged
        Summary   = $summary
    }
}

# ---------------------------------------------------------------------------
# Public: Get-MembershipDrift
# ---------------------------------------------------------------------------
function Get-MembershipDrift {
    <#
    .SYNOPSIS
        Compares current group results against baseline and/or previous run cache files.

    .PARAMETER CurrentGroupResults
        Array of current group result hashtables from enumeration

    .PARAMETER BaselinePath
        Path to the initial/first run JSON cache (long-term drift)

    .PARAMETER PreviousRunPath
        Path to the most recent previous run JSON cache (incremental drift)

    .OUTPUTS
        Hashtable:
        @{
            FromBaseline = @{
                "DOMAIN|GroupName" = @{ Added; Removed; Unchanged; Summary }
            }
            FromPrevious = @{
                "DOMAIN|GroupName" = @{ Added; Removed; Unchanged; Summary }
            }
            OverallSummary = @{
                BaselineComparison = @{ TotalAdded; TotalRemoved; GroupsWithChanges }
                PreviousComparison = @{ TotalAdded; TotalRemoved; GroupsWithChanges }
            }
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentGroupResults,

        [Parameter(Mandatory = $false)]
        [string]$BaselinePath,

        [Parameter(Mandatory = $false)]
        [string]$PreviousRunPath
    )

    $fromBaseline = @{}
    $fromPrevious = @{}
    $baselineTotalAdded = 0; $baselineTotalRemoved = 0; $baselineGroupsChanged = 0
    $previousTotalAdded = 0; $previousTotalRemoved = 0; $previousGroupsChanged = 0

    # Load baseline cache
    $baselineGroups = @{}
    if ($BaselinePath -and (Test-Path $BaselinePath)) {
        Write-GroupEnumLog -Level 'INFO' -Operation 'DriftDetection' `
            -Message "Loading baseline cache: $BaselinePath"
        try {
            $baselineData = Import-GroupDataJson -JsonPath $BaselinePath
            foreach ($g in $baselineData.Groups) {
                if ($g.Data -and $g.Data.Domain -and $g.Data.GroupName) {
                    $key = "$($g.Data.Domain)|$($g.Data.GroupName)"
                    $baselineGroups[$key] = $g
                }
            }
        } catch {
            Write-GroupEnumLog -Level 'WARN' -Operation 'DriftDetection' `
                -Message "Failed to load baseline cache: $_"
        }
    }

    # Load previous run cache
    $previousGroups = @{}
    if ($PreviousRunPath -and (Test-Path $PreviousRunPath)) {
        Write-GroupEnumLog -Level 'INFO' -Operation 'DriftDetection' `
            -Message "Loading previous run cache: $PreviousRunPath"
        try {
            $previousData = Import-GroupDataJson -JsonPath $PreviousRunPath
            foreach ($g in $previousData.Groups) {
                if ($g.Data -and $g.Data.Domain -and $g.Data.GroupName) {
                    $key = "$($g.Data.Domain)|$($g.Data.GroupName)"
                    $previousGroups[$key] = $g
                }
            }
        } catch {
            Write-GroupEnumLog -Level 'WARN' -Operation 'DriftDetection' `
                -Message "Failed to load previous run cache: $_"
        }
    }

    # Compare each current group against baselines
    foreach ($groupResult in $CurrentGroupResults) {
        if (-not $groupResult.Data -or $groupResult.Data.Skipped) { continue }

        $domain    = $groupResult.Data.Domain
        $groupName = $groupResult.Data.GroupName
        $key       = "$domain|$groupName"

        $currentMembers = if ($groupResult.Data.Members -is [array]) {
            $groupResult.Data.Members
        } elseif ($groupResult.Data.Members) {
            @(, $groupResult.Data.Members)
        } else { @() }

        # Compare against baseline
        if ($baselineGroups.ContainsKey($key)) {
            $blGroup = $baselineGroups[$key]
            $blMembers = if ($blGroup.Data.Members -is [array]) { $blGroup.Data.Members } elseif ($blGroup.Data.Members) { @(, $blGroup.Data.Members) } else { @() }

            $diff = Compare-GroupMembership -CurrentMembers $currentMembers -BaselineMembers $blMembers `
                -GroupName $groupName -Domain $domain
            $fromBaseline[$key] = $diff

            $baselineTotalAdded   += $diff.Summary.AddedCount
            $baselineTotalRemoved += $diff.Summary.RemovedCount
            if ($diff.Summary.AddedCount -gt 0 -or $diff.Summary.RemovedCount -gt 0) {
                $baselineGroupsChanged++
            }
        }

        # Compare against previous run
        if ($previousGroups.ContainsKey($key)) {
            $prGroup = $previousGroups[$key]
            $prMembers = if ($prGroup.Data.Members -is [array]) { $prGroup.Data.Members } elseif ($prGroup.Data.Members) { @(, $prGroup.Data.Members) } else { @() }

            $diff = Compare-GroupMembership -CurrentMembers $currentMembers -BaselineMembers $prMembers `
                -GroupName $groupName -Domain $domain
            $fromPrevious[$key] = $diff

            $previousTotalAdded   += $diff.Summary.AddedCount
            $previousTotalRemoved += $diff.Summary.RemovedCount
            if ($diff.Summary.AddedCount -gt 0 -or $diff.Summary.RemovedCount -gt 0) {
                $previousGroupsChanged++
            }
        }
    }

    Write-GroupEnumLog -Level 'INFO' -Operation 'DriftDetection' `
        -Message "Drift analysis complete" -Context @{
            baselineGroups  = $baselineGroups.Count
            previousGroups  = $previousGroups.Count
            baselineChanged = $baselineGroupsChanged
            previousChanged = $previousGroupsChanged
        }

    return @{
        FromBaseline   = $fromBaseline
        FromPrevious   = $fromPrevious
        OverallSummary = @{
            BaselineComparison = @{
                TotalAdded        = $baselineTotalAdded
                TotalRemoved      = $baselineTotalRemoved
                GroupsWithChanges = $baselineGroupsChanged
                GroupsCompared    = $baselineGroups.Count
            }
            PreviousComparison = @{
                TotalAdded        = $previousTotalAdded
                TotalRemoved      = $previousTotalRemoved
                GroupsWithChanges = $previousGroupsChanged
                GroupsCompared    = $previousGroups.Count
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Public: Export-DriftReportCsv
# ---------------------------------------------------------------------------
function Export-DriftReportCsv {
    <#
    .SYNOPSIS
        Exports membership drift to CSV showing all additions and removals.

    .PARAMETER DriftResult
        Output from Get-MembershipDrift

    .PARAMETER OutputPath
        Path for the output CSV

    .PARAMETER ComparisonType
        "Baseline" or "Previous" -- which comparison to export
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DriftResult,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Baseline', 'Previous')]
        [string]$ComparisonType = 'Previous'
    )

    $driftData = if ($ComparisonType -eq 'Baseline') { $DriftResult.FromBaseline } else { $DriftResult.FromPrevious }

    if (-not $driftData -or $driftData.Count -eq 0) {
        Write-GroupEnumLog -Level 'WARN' -Operation 'DriftExport' `
            -Message "No drift data for $ComparisonType comparison -- skipping CSV export"
        return $null
    }

    # RFC 4180 field escaping: quote any field containing a comma, quote, CR
    # or LF, doubling embedded quotes. Without this a DisplayName like
    # 'Smith, "Bob"' or an Email with a comma shifts every later column.
    function ConvertTo-CsvField {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        if ($Value -match '[",\r\n]') {
            return '"' + ($Value -replace '"', '""') + '"'
        }
        return $Value
    }

    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add('Change,Domain,GroupName,SamAccountName,DisplayName,Email')

    foreach ($key in ($driftData.Keys | Sort-Object)) {
        $diff = $driftData[$key]
        $parts = $key -split '\|', 2
        $domain    = if ($parts.Count -ge 1) { $parts[0] } else { '' }
        $groupName = if ($parts.Count -ge 2) { $parts[1] } else { '' }

        foreach ($user in $diff.Added) {
            $sam  = ConvertTo-CsvField $(if ($user.SamAccountName) { $user.SamAccountName } else { '' })
            $dn   = ConvertTo-CsvField $(if ($user.DisplayName)    { $user.DisplayName }    else { '' })
            $mail = ConvertTo-CsvField $(if ($user.Email)          { $user.Email }          else { '' })
            $rows.Add("Added,$(ConvertTo-CsvField $domain),$(ConvertTo-CsvField $groupName),$sam,$dn,$mail")
        }

        foreach ($user in $diff.Removed) {
            $sam  = ConvertTo-CsvField $(if ($user.SamAccountName) { $user.SamAccountName } else { '' })
            $dn   = ConvertTo-CsvField $(if ($user.DisplayName)    { $user.DisplayName }    else { '' })
            $mail = ConvertTo-CsvField $(if ($user.Email)          { $user.Email }          else { '' })
            $rows.Add("Removed,$(ConvertTo-CsvField $domain),$(ConvertTo-CsvField $groupName),$sam,$dn,$mail")
        }
    }

    $outDir = Split-Path $OutputPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) {
        $null = New-Item -ItemType Directory -Path $outDir -Force
    }

    $csvContent = $rows -join "`r`n"
    [System.IO.File]::WriteAllText($OutputPath, $csvContent, [System.Text.UTF8Encoding]::new($false))

    Write-GroupEnumLog -Level 'INFO' -Operation 'DriftExport' `
        -Message "Drift CSV exported: $OutputPath ($ComparisonType)" `
        -Context @{ path = $OutputPath; rows = ($rows.Count - 1) }

    return $OutputPath
}
